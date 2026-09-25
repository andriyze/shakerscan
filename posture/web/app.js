/* ShakerScan posture check page: DOM rendering and the check request.
 *
 * Every value from a check document, an opened file or the address bar is inserted as text
 * (textContent or setAttribute); nothing is ever parsed as HTML. Response values come from
 * DNS records, certificates and HTTP headers that the checked target controls.
 */
(function () {
  'use strict';

  const V = window.ShakerScanView;
  const DEFAULT_ENDPOINT = 'https://pub.shakerscan.com/v1/check';
  const TIMEOUT_MS = 30000;
  const MAX_FILE_BYTES = 1048576;
  const endpointMeta = document.querySelector('meta[name="shakerscan-check-endpoint"]');
  const endpoint = new URL((endpointMeta && endpointMeta.content.trim()) || DEFAULT_ENDPOINT, location.href).href;
  const service = V.serviceLabel(endpoint);

  const $ = id => document.getElementById(id);
  const form = $('check-form');
  const input = $('target');
  const selectorInput = $('selector');
  const submit = $('submit');
  const fieldError = $('target-error');
  const statusRegion = $('status');
  const output = $('output');
  const fileInput = $('file');
  let inflight = null;

  // --- DOM helpers ----------------------------------------------------------------------

  const ATTRIBUTES = new Set(['id', 'href', 'download', 'title', 'role', 'type', 'tabindex', 'datetime',
    'scope', 'hidden', 'open', 'rel', 'target', 'colspan', 'aria-label', 'aria-hidden', 'aria-live', 'aria-labelledby']);

  function el(tag, props, ...children) {
    const node = document.createElement(tag);
    for (const [name, value] of Object.entries(props || {})) {
      if (value === null || value === undefined || value === false) continue;
      if (name === 'class') node.className = value;
      else if (name === 'text') node.textContent = String(value);
      else if (ATTRIBUTES.has(name)) node.setAttribute(name, value === true ? '' : String(value));
      else throw new Error(`unsupported property ${name}`);
    }
    for (const child of children.flat(2)) {
      if (child === null || child === undefined || child === false || child === '') continue;
      node.append(child instanceof Node ? child : String(child));
    }
    return node;
  }

  // Static icon paths (24x24, stroked); never built from response data.
  const ICONS = {
    dns: ['M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18z', 'M3 12h18', 'M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z'],
    mail: ['M3 6.5h18v11H3z', 'M3.5 7l8.5 6.5L20.5 7'],
    http: ['M4 5h16v14H4z', 'M4 9h16', 'M7 7h.01', 'M9.5 7h.01'],
    tls: ['M6 11h12v9H6z', 'M8.5 11V8a3.5 3.5 0 0 1 7 0v3', 'M12 14.5v2.5'],
    ip: ['M12 4v4', 'M12 16v4', 'M4 12h4', 'M16 12h4', 'M9 9h6v6H9z'],
    alert: ['M12 3.5l9.5 16.5h-19z', 'M12 10v4.5', 'M12 17.5h.01'],
    copy: ['M9 9h11v11H9z', 'M5 15H4V4h11v1'],
    expand: ['M7 9l5-5 5 5', 'M7 15l5 5 5-5'],
    download: ['M12 4v11', 'M7.5 10.5L12 15l4.5-4.5', 'M5 19.5h14'],
    other: ['M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18z']
  };

  function icon(name) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('class', 'icon');
    for (const d of ICONS[name] || ICONS.other) {
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('d', d);
      svg.append(path);
    }
    return svg;
  }

  const slug = value => String(value).toLowerCase().replace(/[^a-z0-9_-]+/g, '-').slice(0, 64);

  function flash(button, text) {
    const label = button.querySelector('.label') || button;
    const original = label.dataset.label || label.textContent;
    label.dataset.label = original;
    label.textContent = text;
    setTimeout(() => { label.textContent = original; }, 1600);
  }

  async function copyText(text, button) {
    try {
      await navigator.clipboard.writeText(text);
      flash(button, 'Copied');
    } catch (error) {
      flash(button, 'Copy failed');
    }
  }

  function actionButton(iconName, label, onClick) {
    const button = el('button', { type: 'button', class: 'ghost' }, icon(iconName), el('span', { class: 'label', text: label }));
    button.addEventListener('click', () => onClick(button));
    return button;
  }

  // --- status and errors ----------------------------------------------------------------

  function setStatus(text, busy) {
    statusRegion.replaceChildren();
    if (!text) return;
    statusRegion.append(el('p', { class: busy ? 'status-line busy' : 'status-line' },
      busy ? el('span', { class: 'spinner', 'aria-hidden': 'true' }) : null, el('span', { text })));
  }

  function showFieldError(message) {
    fieldError.textContent = message || '';
    fieldError.hidden = !message;
    if (message) input.setAttribute('aria-invalid', 'true');
    else input.removeAttribute('aria-invalid');
  }

  function renderError(problem, target) {
    const titles = { network: 'Could not reach the check service', client_timeout: 'The check took too long',
      invalid_response: 'Unexpected answer from the service', file: 'That file could not be shown' };
    const title = titles[problem.code] || (problem.status === 429 ? 'Limit reached'
      : problem.status >= 500 ? 'The service could not complete the check' : 'The check was refused');
    const details = [problem.code, problem.status ? `HTTP ${problem.status}` : '',
      problem.retryAfter ? `retry in ${problem.retryAfter} s` : '', problem.requestId ? `request ${problem.requestId}` : ''].filter(Boolean);
    output.replaceChildren(el('section', { class: 'error-card', role: 'alert' },
      el('div', { class: 'error-icon' }, icon('alert')),
      el('div', { class: 'error-body' },
        el('h2', { text: title }),
        target ? el('p', { class: 'error-target mono', text: target }) : null,
        el('p', { text: problem.message }),
        problem.hint ? el('p', { class: 'muted', text: problem.hint }) : null,
        details.length ? el('p', { class: 'error-meta mono', text: details.join(' · ') }) : null)));
  }

  // --- result rendering -----------------------------------------------------------------

  function value(row) {
    if (row.chips) return el('ul', { class: 'chips' }, row.chips.map(item => el('li', { class: 'chip', text: item })));
    if (row.lines) return el('ul', { class: 'lines' }, row.lines.map(item => el('li', { text: item })));
    return el('span', { class: [row.mono ? 'mono' : '', row.muted ? 'muted' : ''].filter(Boolean).join(' ') || null, text: row.text });
  }

  function facts(rows) {
    if (!rows.length) return null;
    return el('dl', { class: 'facts' }, rows.map(row => el('div', { class: 'fact' },
      el('dt', { text: row.label }), el('dd', null, value(row)))));
  }

  function table(model) {
    return el('div', { class: 'table-wrap' }, el('table', null,
      el('caption', { class: 'sr-only', text: model.caption }),
      el('thead', null, el('tr', null, model.columns.map(column => el('th', { scope: 'col', text: column })))),
      el('tbody', null, model.rows.map(cells => el('tr', null, cells.map((cell, index) =>
        el('td', { class: index === 0 ? 'mono' : null, text: cell })))))));
  }

  // A card leads with its one-line headline; every fact, table and the probe scope sit
  // behind "Details" so a whole result reads at a glance.
  function card(observation) {
    const model = V.describe(observation);
    const count = model.rows.length + model.tables.reduce((sum, t) => sum + t.rows.length, 0) +
      model.sections.reduce((sum, s) => sum + s.rows.length, 0);
    return el('article', { class: model.hint ? 'card has-hint' : 'card', id: `obs-${slug(model.id)}` },
      el('header', { class: 'card-head' },
        el('h4', { text: model.name }),
        el('code', { class: 'obs-id', text: model.id })),
      el('p', { class: model.headline ? 'headline' : 'headline muted', text: model.headline || 'Observed; see details' }),
      model.hint ? el('p', { class: 'hint' }, icon('alert'), el('span', { text: model.hint })) : null,
      el('details', { class: 'more' },
        el('summary', null, el('span', { text: 'Details' }), el('span', { class: 'more-count', text: `${count} ${count === 1 ? 'fact' : 'facts'}` })),
        facts(model.rows),
        model.tables.map(table),
        model.sections.map(section => el('section', { class: 'sub' },
          el('h5', { class: 'mono', text: section.title }), facts(section.rows))),
        model.scope ? el('p', { class: 'scope' }, el('span', { class: 'scope-label', text: 'Scope' }), el('span', { text: model.scope })) : null));
  }

  function openCard(id) {
    const details = document.querySelector(`#obs-${slug(id)} details.more`);
    if (details) details.open = true;
  }

  function expandToggle() {
    return actionButton('expand', 'Expand all', button => {
      const all = Array.from(output.querySelectorAll('details.more'));
      const open = all.some(details => !details.open);
      for (const details of all) details.open = open;
      button.querySelector('.label').textContent = open ? 'Collapse all' : 'Expand all';
    });
  }

  function sourceLine(origin) {
    if (origin.source === 'sample') return 'Sample result · illustrative data, not a live observation';
    if (origin.source === 'file') return `Opened from ${origin.fileName || 'a file'} · shown on this device only`;
    return `Live result · ${service.host}`;
  }

  function download(doc, target) {
    const blob = new Blob([`${JSON.stringify(doc, null, 2)}\n`], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const day = (/^\d{4}-\d{2}-\d{2}/.exec(String(doc.checked_at)) || [new Date().toISOString().slice(0, 10)])[0];
    const link = el('a', { href: url, download: `shakerscan-check-${slug(target || 'result')}-${day}.json` });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  function renderDocument(doc, origin) {
    const observations = V.observationsOf(doc);
    const summary = V.summarize(doc);
    const hints = V.reviewHints(observations);
    const target = String(doc.target || (origin.request && origin.request.target) || '');
    const checked = typeof doc.checked_at === 'string' ? doc.checked_at : '';
    const cached = Boolean(doc.cache && doc.cache.hit === true);
    const json = JSON.stringify(doc, null, 2);

    const meta = [];
    if (checked) {
      const when = Date.parse(checked);
      meta.push(el('span', null, 'Checked ', el('time', { datetime: checked, title: checked,
        text: Number.isFinite(when) ? new Date(when).toLocaleString() : checked }),
      origin.source === 'live' ? ` (${V.relativeTime(checked)})` : ''));
    }
    if (cached) meta.push(el('span', { class: 'badge', text: 'cached answer' }));
    if (V.isIpTarget(target)) meta.push(el('span', { class: 'badge', text: 'IP address target' }));
    meta.push(el('span', { text: `${summary.observed} of ${summary.total} observations returned data` }));

    const heading = el('h2', { class: 'target mono', tabindex: '-1', text: target || 'Unknown target' });
    const head = el('header', { class: 'result-head' },
      el('div', { class: 'result-title' },
        el('p', { class: 'eyebrow', text: sourceLine(origin) }),
        heading,
        el('p', { class: 'meta' }, meta)),
      el('div', { class: 'result-actions' },
        expandToggle(),
        actionButton('copy', 'Copy JSON', button => copyText(json, button)),
        actionButton('download', 'Download', () => download(doc, target))));

    const pills = el('nav', { class: 'pills', 'aria-label': 'Observation groups' }, summary.groups.map(group =>
      el('a', { class: 'pill', href: `#group-${slug(group.id)}` }, icon(group.id), el('span', { text: group.label }),
        el('span', { class: 'pill-count mono', text: `${group.observed}/${group.total}` }))));

    const review = hints.length ? el('section', { class: 'review', 'aria-label': 'Review' },
      el('div', { class: 'review-head' }, icon('alert'), el('h3', { text: 'Review' }),
        el('p', { class: 'muted', text: 'Values that usually need attention. This is the page’s reading of the facts; the service makes no pass/fail judgment.' })),
      el('ul', null, hints.map(hint => {
        const link = el('a', { href: `#obs-${slug(hint.id)}`, text: hint.name });
        link.addEventListener('click', () => openCard(hint.id));
        return el('li', null, link, el('span', { text: ` — ${hint.text}` }));
      }))) : null;

    const groups = V.groupObservations(observations).map(group => el('section', { class: 'group', id: `group-${slug(group.id)}` },
      el('header', { class: 'group-head' },
        el('span', { class: `group-icon g-${slug(group.id)}` }, icon(group.id)),
        el('h3', { text: group.label }),
        el('span', { class: 'muted', text: `${group.observed.length} of ${group.total} with data` })),
      group.observed.length ? el('div', { class: 'cards' }, group.observed.map(card)) : null,
      group.empty.length ? el('p', { class: 'nodata' }, el('span', { class: 'nodata-label', text: 'No data' }),
        group.empty.map(o => el('span', { class: 'chip ghost-chip', title: typeof o.scope === 'string' ? o.scope : null,
          text: String(o.name || o.id) }))) : null));

    const limitations = (Array.isArray(doc.limitations) ? doc.limitations : []).filter(item => typeof item === 'string');
    const command = V.cliCommand(origin.request || V.requestOf(doc));
    const footer = el('div', { class: 'result-foot' },
      limitations.length ? el('section', { class: 'panel limits' }, el('h3', { text: 'Limits of this check' }),
        el('ul', null, limitations.map(item => el('li', { text: item })))) : null,
      command ? el('section', { class: 'panel cli' }, el('h3', { text: 'Same check from a terminal' }),
        el('div', { class: 'cli-row' }, el('code', { class: 'mono', text: command }),
          actionButton('copy', 'Copy', button => copyText(command, button)))) : null,
      el('details', { class: 'panel raw' }, el('summary', { text: 'Raw JSON' }), el('pre', { class: 'mono', text: json })),
      typeof doc.request_id === 'string' ? el('p', { class: 'request-id mono', text: `request ${doc.request_id}` }) : null);

    output.replaceChildren(el('article', { class: 'result' }, head, pills, review, groups, footer));
    heading.focus({ preventScroll: true });
    heading.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
  }

  // --- actions --------------------------------------------------------------------------

  function setAddress(params) {
    const url = new URL(location.href);
    url.search = '';
    for (const [key, val] of Object.entries(params)) if (val) url.searchParams.set(key, val);
    history.replaceState(null, '', url);
  }

  // Only the newest check may touch the page; an aborted or superseded one exits quietly.
  function cancelCheck() {
    if (!inflight) return;
    inflight.abort();
    inflight = null;
    submit.disabled = false;
    setStatus('');
  }

  async function runCheck() {
    let request;
    try {
      request = V.buildRequest(input.value, selectorInput.value);
    } catch (error) {
      showFieldError(error.message);
      input.focus();
      return;
    }
    showFieldError('');
    cancelCheck();
    const controller = new AbortController();
    inflight = controller;
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    submit.disabled = true;
    output.replaceChildren();
    setStatus(`Checking ${request.target}: DNS, email, HTTP and TLS. This usually takes under ten seconds.`, true);
    setAddress({ target: input.value.trim(), selector: request.dkim_selector });
    try {
      const response = await fetch(endpoint, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request),
        signal: controller.signal, credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer'
      });
      const text = await response.text();
      if (controller !== inflight) return;
      let body = null;
      try { body = JSON.parse(text); } catch (error) { body = null; }
      if (!response.ok) {
        renderError(V.describeError(response.status, body, response.headers.get('Retry-After')), request.target);
        return;
      }
      try {
        renderDocument(V.validateDocument(body), { source: 'live', request });
      } catch (error) {
        renderError(V.describeError(0, { error: { code: 'invalid_response', message: error.message } }), request.target);
      }
    } catch (error) {
      if (controller !== inflight) return;
      const code = error && error.name === 'AbortError' ? 'client_timeout' : 'network';
      renderError(V.describeError(0, { error: { code, message: code === 'network'
        ? `The request to ${service.host} did not complete.` : 'The request was stopped after 30 seconds.' } }), request.target);
    } finally {
      clearTimeout(timer);
      if (controller === inflight) {
        inflight = null;
        submit.disabled = false;
        setStatus('');
      }
    }
  }

  function showDocument(text, origin) {
    let doc;
    try {
      doc = V.validateDocument(JSON.parse(text));
    } catch (error) {
      renderError({ code: 'file', status: 0, message: error instanceof SyntaxError ? 'The file is not valid JSON.' : error.message,
        hint: 'Open the output of: shakerscan check example.com --json', retryAfter: null, requestId: '' });
      return;
    }
    cancelCheck();
    setAddress(origin.source === 'sample' ? { sample: '1' } : {});
    renderDocument(doc, origin);
  }

  async function openFile(file) {
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      renderError({ code: 'file', status: 0, message: 'The file is larger than 1 MB; a check result is much smaller.', hint: '', retryAfter: null, requestId: '' });
      return;
    }
    showDocument(await file.text(), { source: 'file', fileName: file.name });
  }

  async function loadSample() {
    try {
      const response = await fetch('sample.json', { cache: 'no-cache', credentials: 'omit' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      showDocument(await response.text(), { source: 'sample' });
    } catch (error) {
      renderError({ code: 'file', status: 0, message: 'The sample could not be loaded.',
        hint: 'Serve this page over http(s) to use the sample.', retryAfter: null, requestId: '' });
    }
  }

  // --- wiring ---------------------------------------------------------------------------

  $('service-note').textContent = service.hosted
    ? 'Checks run on the hosted ShakerScan service: public domains and global IP addresses only; 30 requests a minute, 25 new checks an hour and 100 a day per caller; answers are cached for 10 minutes.'
    : `Checks run on the ShakerScan instance at ${service.host}; its operator decides which targets it may reach.`;
  $('privacy-note').textContent = `The target you enter is sent to ${service.host}. This page sets no cookies and loads nothing from other sites.`;

  form.addEventListener('submit', event => {
    event.preventDefault();
    runCheck();
  });
  input.addEventListener('input', () => { if (!fieldError.hidden) showFieldError(''); });
  $('open-file').addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => {
    openFile(fileInput.files && fileInput.files[0]);
    fileInput.value = '';
  });
  $('load-sample').addEventListener('click', loadSample);

  const drop = $('drop');
  let dragDepth = 0;
  const carriesFile = event => Array.from((event.dataTransfer && event.dataTransfer.types) || []).includes('Files');
  window.addEventListener('dragenter', event => {
    if (!carriesFile(event)) return;
    dragDepth += 1;
    drop.hidden = false;
  });
  window.addEventListener('dragleave', () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) drop.hidden = true;
  });
  window.addEventListener('dragover', event => { if (carriesFile(event)) event.preventDefault(); });
  window.addEventListener('drop', event => {
    if (!carriesFile(event)) return;
    event.preventDefault();
    dragDepth = 0;
    drop.hidden = true;
    openFile(event.dataTransfer.files[0]);
  });

  const params = new URLSearchParams(location.search);
  if (params.get('target')) {
    input.value = params.get('target').slice(0, 300);
    if (params.get('selector')) {
      selectorInput.value = params.get('selector').slice(0, 63);
      $('options').open = true;
    }
    runCheck();
  } else if (params.has('sample')) {
    loadSample();
  }
})();
