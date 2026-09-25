/* ShakerScan posture check page: view logic shared by the page (app.js) and its tests.
 *
 * Nothing here touches the DOM. It turns a schema-2 check document into plain values that
 * app.js renders with textContent only. The service reports facts and makes no pass/fail
 * judgment; the only interpretation added here is the short "Review" list, which mirrors
 * `shakerscan check` so the page and the CLI say the same thing about the same document.
 */
(function (root) {
  'use strict';

  const HOSTED_SERVICE = 'pub.shakerscan.com';
  const GROUPS = [
    { id: 'dns', label: 'DNS' },
    { id: 'mail', label: 'Email' },
    { id: 'http', label: 'HTTP' },
    { id: 'tls', label: 'TLS' },
    { id: 'ip', label: 'IP network' }
  ];

  const isRecord = value => Boolean(value) && typeof value === 'object' && !Array.isArray(value);
  const has = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
  const plural = (count, word, many) => `${count} ${count === 1 ? word : many || `${word}s`}`;

  // --- request --------------------------------------------------------------------------

  // The request grammar the engine accepts (posture/src/request.ts). Target policy (public
  // names only, restricted zones) is the service's decision, so only syntax is checked here.
  const PATH = /^\/[A-Za-z0-9/_~.-]*$/;
  const SELECTOR = /^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$/i;
  const IPV4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const PORT_MESSAGE = 'Remove the port: the check always uses ports 80 and 443.';
  const EMPTY_MESSAGE = 'Enter a domain, IP address or URL, for example example.com.';

  function isIpTarget(target) {
    const value = String(target);
    return IPV4.test(value) || (value.includes(':') && /^[0-9a-f:.]+$/i.test(value));
  }

  /** Hostname, IP address or http(s) URL, as `shakerscan check` accepts it. A URL's path
   *  becomes the CORS probe path; its query and fragment are not sent. */
  function parseTarget(value) {
    const raw = String(value == null ? '' : value).trim();
    if (!raw) throw new Error(EMPTY_MESSAGE);
    let host;
    let path;
    if (raw.includes('://')) {
      let url;
      try { url = new URL(raw); } catch (error) { throw new Error('That URL could not be read. Try a domain such as example.com.'); }
      if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error('Only http and https URLs can be checked.');
      if (url.username || url.password) throw new Error('Remove the user name and password from the URL.');
      if (url.port) throw new Error(PORT_MESSAGE);
      host = url.hostname.replace(/^\[(.*)\]$/, '$1');
      if (url.pathname && url.pathname !== '/') path = url.pathname;
    } else {
      if (/[/?#@\s]/.test(raw)) throw new Error('Enter only a domain or IP address, or a full https:// URL to test a specific path.');
      host = raw.replace(/^\[(.*)\]$/, '$1');
      // One colon means name:port or IPv4:port; an IPv6 address always has at least two.
      if (/^[^:]+:\d*$/.test(host)) throw new Error(PORT_MESSAGE);
    }
    if (!isIpTarget(host)) host = host.toLowerCase().replace(/\.$/, '');
    if (!host) throw new Error(EMPTY_MESSAGE);
    if (path !== undefined && (path.length > 256 || !PATH.test(path) || path.includes('//') ||
        path.split('/').some(part => part === '.' || part === '..'))) {
      throw new Error('The URL path may contain only letters, digits and / _ ~ . - (up to 256 characters).');
    }
    return path === undefined ? { target: host } : { target: host, path };
  }

  /** The JSON body for POST /v1/check (hosted) or POST /public/check (instance). */
  function buildRequest(value, selectorValue) {
    const request = parseTarget(value);
    const selector = String(selectorValue == null ? '' : selectorValue).trim();
    if (selector) {
      if (isIpTarget(request.target)) throw new Error('A DKIM selector applies to domain names, not IP addresses.');
      if (!SELECTOR.test(selector)) throw new Error('A DKIM selector has letters, digits, "-" and "_" only, for example selector1.');
      request.dkim_selector = selector.toLowerCase();
    }
    return request;
  }

  /** The request a result answers, recovered from the document itself (file and sample views). */
  function requestOf(doc) {
    const request = { target: String(doc && doc.target || '') };
    for (const observation of observationsOf(doc)) {
      const result = isRecord(observation.result) ? observation.result : {};
      if (observation.id === 'http.cors' && typeof result.path === 'string' && result.path !== '/') request.path = result.path;
      if (observation.id === 'mail.dkim' && typeof result.selector === 'string') request.dkim_selector = result.selector;
    }
    return request;
  }

  /** The equivalent `shakerscan check` command, or '' when it cannot be shown safely: an opened
   *  file may carry any target, and the command must copy into a shell as plain words. */
  function cliCommand(request) {
    const target = String(request && request.target || '');
    if (!/^(?:[\p{L}\p{N}][\p{L}\p{N}._-]*|[0-9a-f]*:[0-9a-f:.]+)$/iu.test(target)) return '';
    const parts = ['shakerscan', 'check', target];
    if (request.path && PATH.test(request.path)) parts.push('--path', request.path);
    if (request.dkim_selector && SELECTOR.test(request.dkim_selector)) parts.push('--dkim-selector', request.dkim_selector);
    parts.push('--json');
    return parts.join(' ');
  }

  function serviceLabel(endpoint) {
    try {
      const url = new URL(endpoint);
      return { host: url.host, hosted: url.hostname === HOSTED_SERVICE };
    } catch (error) {
      return { host: String(endpoint), hosted: false };
    }
  }

  // --- documents ------------------------------------------------------------------------

  function validateDocument(doc) {
    if (!isRecord(doc)) throw new Error('The result is not a JSON object.');
    if (isRecord(doc.error)) throw new Error('This file holds an error response, not a check result.');
    if (doc.schema_version !== '2' || !Array.isArray(doc.observations)) {
      throw new Error('This is not a ShakerScan posture check result (schema 2). Save one with: shakerscan check example.com --json');
    }
    return doc;
  }

  function observationsOf(doc) {
    return (isRecord(doc) && Array.isArray(doc.observations) ? doc.observations : []).filter(isRecord);
  }

  // Keys that restate the request rather than report something observed.
  const CONTEXT_KEYS = new Set(['path', 'selector']);

  /** Whether the observation carries measured facts (null and request-only results do not). */
  function hasData(observation) {
    const result = observation && observation.result;
    return isRecord(result) && Object.keys(result).some(key => !CONTEXT_KEYS.has(key));
  }

  function groupObservations(observations) {
    const known = GROUPS.map(group => group.id);
    const others = [...new Set(observations.map(o => String(o.group || 'other')))].filter(id => !known.includes(id));
    return [...GROUPS, ...others.map(id => ({ id, label: id.toUpperCase() }))].map(group => {
      const members = observations.filter(o => String(o.group || 'other') === group.id);
      return { id: group.id, label: group.label, total: members.length,
        observed: members.filter(hasData), empty: members.filter(o => !hasData(o)) };
    }).filter(group => group.total > 0);
  }

  function summarize(doc) {
    const observations = observationsOf(doc);
    return { total: observations.length, observed: observations.filter(hasData).length,
      groups: groupObservations(observations).map(group => ({ id: group.id, label: group.label,
        total: group.total, observed: group.observed.length })) };
  }

  // --- review hints ---------------------------------------------------------------------

  /** The few risky values `shakerscan check` lists under "Review", worded the same way.
   *  One deliberate difference: an SPF record without an "all" term whose include/redirect
   *  tree was followed is not flagged, because a redirect= may supply the policy and the
   *  document cannot tell a redirect from an include-only record. */
  function reviewHint(observation) {
    const result = observation && observation.result;
    if (!isRecord(result)) return null;
    switch (observation.id) {
      case 'mail.spf': {
        const qualifier = String(result.all_qualifier);
        if (qualifier === '+') return 'SPF +all lets any server send as this domain';
        if (qualifier === '?') return 'SPF ends with neutral ?all, which authorizes nothing';
        const followed = Array.isArray(result.checked_domains) && result.checked_domains.length > 1;
        return qualifier === 'absent' && result.record_count === 1 && !followed ? 'SPF has no terminal all/redirect policy' : null;
      }
      case 'mail.dmarc':
        return result.applied_policy === 'none' ? 'DMARC policy is p=none (monitoring only)' : null;
      case 'dns.dnssec':
        return result.local_validation === 'bogus' ? 'DNSSEC validation failed' : null;
      case 'tls.handshake': {
        if (result.certificate_verified === false) return 'certificate was not verified';
        const days = result.certificate_days_remaining;
        return Number.isInteger(days) && days < 30 ? `certificate expires in ${days} days` : null;
      }
      default:
        return null;
    }
  }

  function reviewHints(observations) {
    return observations.map(o => ({ id: String(o.id), name: String(o.name || o.id), text: reviewHint(o) }))
      .filter(hint => hint.text);
  }

  // --- facts ----------------------------------------------------------------------------

  const LABELS = {
    a_count: 'IPv4 addresses (A)', aaaa_count: 'IPv6 addresses (AAAA)',
    zone: 'Zone', checked_names: 'Names checked', names: 'Name servers', count: 'Records',
    sampled_names: 'Queried directly', untested_names: 'Not queried', responding_names: 'Answered authoritatively',
    unresponsive_names: 'No authoritative answer', soa_serials: 'SOA serials', parent_names: 'Parent name servers',
    parent_sampled_names: 'Parent servers queried', parent_untested_names: 'Parent servers not queried',
    delegation_names: 'Delegated to', delegation_matches: 'Delegation matches zone NS',
    validated_queries: 'Resolver-authenticated answers', local_validation: 'Local validation (A record)',
    validation_reason: 'Validation stopped', validation_queries: 'Validation queries', parent_ds_count: 'DS records at parent',
    ds_algorithms: 'DS algorithms', dnskey_count: 'DNSKEY records', dnskey_algorithms: 'DNSKEY algorithms',
    policy_domain: 'Policy found at', records: 'Records',
    null_mx: 'Null MX', implicit_mx_fallback_applies: 'Implicit MX (A/AAAA) fallback', targets: 'MX targets',
    sampled_targets: 'Targets resolved (sample)', resolved_targets: 'Resolved', unresolved_targets: 'Did not resolve',
    record_count: 'Records', lookup_terms_in_record: 'DNS-lookup terms in record', all_qualifier: '"all" mechanism',
    recursive_evaluation: 'Sender authorization evaluated', checked_domains: 'Records retrieved for',
    expansion_complete: 'Include/redirect expansion complete', cycles: 'Include loops',
    referenced_lookup_terms: 'DNS-lookup terms in tree', missing_or_multiple_records: 'Missing or duplicate included records',
    effective_policy_evaluated: 'Policy discovery performed', no_applicable_policy: 'No applicable policy',
    inherited: 'Inherited from parent domain', declared_policy: 'Declared policy (p)', applied_policy: 'Applied policy',
    policy_tag: 'Policy tag applied', subdomain_policy: 'Subdomain policy (sp)', nonexistent_policy: 'Non-existent subdomain policy (np)',
    dkim_alignment: 'DKIM alignment', spf_alignment: 'SPF alignment', test_mode: 'Test mode (t)',
    rua_count: 'Report destinations', ruf_count: 'Failure report destinations',
    selector: 'Selector', key_type: 'Key type', key_bits: 'Key size',
    status_code: 'HTTP status', validated_address_count: 'Validated addresses', sampled_address_count: 'Addresses probed',
    sampled_families: 'Families probed', certificate_verified: 'Certificate verified',
    certificate_days_remaining: 'Certificate expires in', verified_addresses: 'Verified on',
    certificate_expiry_by_address: 'Days remaining by address', negotiated_ciphers: 'Negotiated ciphers',
    address_ciphers: 'Per address', negotiated_protocols: 'Negotiated protocols', address_protocol_probes: 'Protocol probes',
    present_headers: 'Present', absent_headers: 'Absent', hsts_max_age: 'HSTS max-age',
    hsts_include_subdomains: 'HSTS includeSubDomains', hsts_preload: 'HSTS preload',
    csp_script_source: 'CSP script directive', csp_script_values: 'CSP script sources', csp_directives: 'CSP directives',
    csp_selected_sources: 'CSP selected sources', x_content_type_options: 'X-Content-Type-Options',
    referrer_policy: 'Referrer-Policy', x_frame_options: 'X-Frame-Options',
    cross_origin_opener_policy: 'Cross-Origin-Opener-Policy', cross_origin_resource_policy: 'Cross-Origin-Resource-Policy',
    path: 'Path probed', allow_origin: 'Allow-Origin on GET', allow_origin_value: 'Allow-Origin value',
    allow_origin_value_omitted: 'Allow-Origin value omitted', allow_credentials: 'Allow-Credentials on GET',
    vary_origin: 'Vary: Origin', preflight_status_code: 'Preflight status', preflight_allow_origin: 'Allow-Origin on preflight',
    preflight_allow_origin_value: 'Preflight Allow-Origin value', preflight_allow_origin_value_omitted: 'Preflight value omitted',
    preflight_allow_credentials: 'Allow-Credentials on preflight', preflight_methods: 'Allow-Methods on preflight',
    redirect: 'HTTP root redirects', redirect_chain: 'Redirect chain', final_status_code: 'Final status',
    chain_complete: 'Chain followed to the end', total_address_count: 'Addresses observed', cname_chain: 'CNAME chain',
    enrichment: 'Ownership data', provider: 'Ownership source', reverse_dns: 'Reverse DNS (PTR)',
    reverse_dns_available: 'Reverse DNS answered', policy_status_code: 'Policy file status', mode: 'Mode',
    max_age: 'max_age', mx_patterns: 'MX patterns', policy_fetch: 'Policy file', destination_schemes: 'Destination schemes',
    content_type: 'Content-Type', charset: 'Charset', contact_count: 'Contact fields', contact_schemes: 'Contact schemes',
    canonical_count: 'Canonical fields', expires: 'Expires', format: 'Format'
  };
  // Facts that answer the card's main question are listed first.
  const LEAD = {
    'http.headers': ['present_headers', 'absent_headers'],
    'tls.handshake': ['certificate_verified', 'certificate_days_remaining'],
    'mail.dmarc': ['applied_policy', 'policy_domain', 'declared_policy']
  };
  // Lists whose entries are whole records or sentences, shown one per line.
  const LINE_KEYS = new Set(['records', 'targets', 'soa_serials', 'address_ciphers', 'address_protocol_probes',
    'certificate_expiry_by_address', 'csp_selected_sources', 'cname_chain', 'redirect_chain']);
  const ENUMS = {
    all_qualifier: { '-': '-all (fail)', '~': '~all (softfail)', '?': '?all (neutral)', '+': '+all (any sender)', absent: 'none in this record' },
    dkim_alignment: { r: 'relaxed', s: 'strict' },
    spf_alignment: { r: 'relaxed', s: 'strict' },
    test_mode: { y: 'yes (t=y)', n: 'no' },
    redirect: { same_host_https: 'to HTTPS, same host', same_host_http: 'to HTTP, same host', none: 'no redirect',
      missing: 'redirect without Location', refused: 'elsewhere (not followed)' },
    allow_origin: { none: 'no grant (header absent)', empty: 'empty header', wildcard: '* (any origin)',
      probe_origin: 'reflects the foreign probe origin', other: 'a different fixed origin' },
    enrichment: { available: 'available', partial: 'partial', unconfigured: 'not configured on this service',
      unavailable: 'unavailable', no_addresses: 'no addresses to look up' },
    format: { basic_valid: 'valid (Contact and Expires present)', invalid: 'published but invalid', absent: 'not published',
      html_fallback: 'an HTML page instead of a file', http_error: 'HTTP error' }
  };
  ENUMS.preflight_allow_origin = ENUMS.allow_origin;

  function humanize(key) {
    if (has(LABELS, key)) return LABELS[key];
    const text = String(key).replace(/_/g, ' ');
    return text.charAt(0).toUpperCase() + text.slice(1);
  }

  function duration(seconds) {
    for (const [size, name] of [[86400, 'day'], [3600, 'hour'], [60, 'minute']]) {
      if (seconds >= size && seconds % size === 0) return `${seconds} s (${plural(seconds / size, name)})`;
    }
    return `${seconds} s`;
  }

  /** A Node certificate date ("Oct 15 23:59:59 2026 GMT") or ISO time as "2026-10-15 23:59 UTC". */
  function formatDate(value) {
    const time = Date.parse(value);
    return Number.isFinite(time) ? new Date(time).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : String(value);
  }

  function scalar(key, value) {
    if (typeof value === 'boolean') return value ? 'yes' : 'no';
    if (typeof value === 'number') {
      if (key === 'hsts_max_age' || key === 'max_age') return duration(value);
      if (key === 'certificate_days_remaining') return plural(value, 'day');
      if (key === 'key_bits') return `${value} bits`;
      return String(value);
    }
    if (value === null || value === undefined) return '—';
    const text = String(value);
    if (has(ENUMS, key) && has(ENUMS[key], text)) return ENUMS[key][text];
    if (key === 'expires') return formatDate(text);
    return text;
  }

  function brief(record) {
    return Object.entries(record).filter(([, v]) => v !== null && v !== undefined && !isRecord(v) && !Array.isArray(v))
      .map(([k, v]) => `${k}=${scalar(k, v)}`).join(' ');
  }

  /** One fact row: { key, label } plus text (mono, muted), chips or lines. */
  function row(key, value) {
    const label = humanize(key);
    if (Array.isArray(value)) {
      let items = value.map(item => (isRecord(item) ? brief(item) : scalar(key, item)));
      if (!items.length) return { key, label, text: 'none', muted: true };
      if (key === 'redirect_chain') {
        items = items.map(item => {
          const [code, kind] = item.split(' ');
          return kind ? `${code} · ${ENUMS.redirect[kind] || kind}` : code;
        });
      }
      return LINE_KEYS.has(key) || items.some(item => item.length > 40 || /\s/.test(item))
        ? { key, label, lines: items } : { key, label, chips: items };
    }
    if (isRecord(value)) return { key, label, text: brief(value), mono: true };
    const text = scalar(key, value);
    // Identifiers (names, addresses, header values, algorithms) read best in monospace.
    return { key, label, text, mono: typeof value === 'number' || (text === value && /^\S+$/.test(text)) };
  }

  function certificateRows(cert) {
    const rows = [];
    const text = (key, label, value, mono) => {
      if (value !== undefined && value !== null && value !== '') rows.push({ key, label, text: String(value), mono: Boolean(mono) });
    };
    text('subject', 'Subject', cert.subject, true);
    text('issuer', 'Issuer', cert.issuer);
    if (cert.valid_from || cert.valid_to) {
      text('validity', 'Valid', `${cert.valid_from ? formatDate(cert.valid_from) : '?'} → ${cert.valid_to ? formatDate(cert.valid_to) : '?'}`);
    }
    if (typeof cert.ip_address_match === 'boolean') text('ip_address_match', 'Lists this IP address', cert.ip_address_match ? 'yes' : 'no');
    if (Array.isArray(cert.san_names)) {
      rows.push(cert.san_names.length ? { key: 'san_names', label: 'DNS names (SAN)', chips: cert.san_names.map(String) }
        : { key: 'san_names', label: 'DNS names (SAN)', text: 'none', muted: true });
    }
    text('public_key', 'Public key', [cert.public_key_type ? String(cert.public_key_type).toUpperCase() : '', cert.public_key_curve,
      Number.isInteger(cert.public_key_bits) ? `${cert.public_key_bits} bits` : ''].filter(Boolean).join(' · '));
    text('signature_algorithm', 'Signature', cert.signature_algorithm, true);
    text('alpn', 'ALPN', cert.alpn, true);
    if (cert.fingerprint256) rows.push({ key: 'fingerprint256', label: 'SHA-256 fingerprint', lines: [String(cert.fingerprint256)] });
    if (Array.isArray(cert.chain) && cert.chain.length) {
      rows.push({ key: 'chain', label: 'Chain', lines: cert.chain.filter(isRecord).map((entry, index) =>
        `${index}: ${entry.subject || '?'} ← ${entry.issuer || '?'}${entry.valid_to ? ` (until ${formatDate(entry.valid_to).slice(0, 10)})` : ''}`) });
    }
    return rows;
  }

  /** Everything a card shows for one observation: fact rows, plus tables or nested sections
   *  for the results that carry lists of records. */
  function describe(observation) {
    const result = isRecord(observation.result) ? observation.result : {};
    const id = String(observation.id);
    const card = { id, name: String(observation.name || id), group: String(observation.group || 'other'),
      scope: typeof observation.scope === 'string' ? observation.scope : '', headline: headline(observation),
      hint: reviewHint(observation), rows: [], tables: [], sections: [] };
    const skip = new Set();
    if (id === 'ip.network' && Array.isArray(result.addresses)) {
      skip.add('addresses');
      const addresses = result.addresses.filter(isRecord);
      if (addresses.length) {
        card.tables.push({ caption: 'Addresses', columns: ['Address', 'Network', 'Country', 'DNS TTL', 'Probed'],
          rows: addresses.map(a => [
            String(a.ip || '—'),
            ([a.asn, a.as_name].filter(Boolean).join(' ') || '—') + (a.anycast === true ? ' · anycast' : ''),
            a.country ? `${a.country}${a.country_code ? ` (${a.country_code})` : ''}` : String(a.country_code || '—'),
            Number.isInteger(a.dns_ttl) ? `${a.dns_ttl} s` : '—',
            a.sampled === true ? 'yes' : 'no'
          ]) });
      }
    }
    if (id === 'dns.https' && Array.isArray(result.records)) {
      skip.add('records');
      const records = result.records.filter(isRecord);
      if (records.length) {
        card.tables.push({ caption: 'HTTPS records', columns: ['Priority', 'Target', 'TTL', 'Parameters'],
          rows: records.map(r => [String(r.priority ?? '—'), String(r.target ?? '—'), Number.isInteger(r.ttl) ? `${r.ttl} s` : '—',
            Array.isArray(r.parameters) && r.parameters.length ? r.parameters.join(' ') : '—']) });
      }
    }
    if (id === 'http.connections' && Array.isArray(result.connections)) {
      skip.add('connections');
      for (const connection of result.connections.filter(isRecord)) {
        const facts = [];
        if (connection.status_code !== undefined) facts.push({ key: 'status_code', label: 'HTTP status', text: String(connection.status_code), mono: true });
        if (connection.tls_protocol) facts.push({ key: 'tls_protocol', label: 'Protocol', text: String(connection.tls_protocol), mono: true });
        if (connection.cipher) facts.push({ key: 'cipher', label: 'Cipher', text: String(connection.cipher), mono: true });
        card.sections.push({ title: String(connection.ip || 'Connection'),
          rows: [...facts, ...(isRecord(connection.certificate) ? certificateRows(connection.certificate) : [])] });
      }
      if (!result.connections.length) card.rows.push({ key: 'connections', label: 'Connections', text: 'none established', muted: true });
    }
    const lead = (LEAD[id] || []).filter(key => has(result, key));
    for (const key of [...lead, ...Object.keys(result).filter(key => !lead.includes(key))]) {
      if (!skip.has(key)) card.rows.push(row(key, result[key]));
    }
    return card;
  }

  /** One short line of the most telling facts, so a card can be read at a glance. */
  function headline(observation) {
    const r = observation && observation.result;
    if (!isRecord(r)) return '';
    const int = value => (Number.isInteger(value) ? value : null);
    const list = value => (Array.isArray(value) ? value : []);
    switch (observation.id) {
      case 'dns.addresses':
        return `${int(r.a_count) ?? 0} IPv4 · ${int(r.aaaa_count) ?? 0} IPv6`;
      case 'dns.nameservers':
        return list(r.names).length ? [plural(list(r.names).length, 'name server'),
          r.delegation_matches === true ? 'delegation matches' : r.delegation_matches === false ? 'delegation differs' : '',
          list(r.unresponsive_names).length ? `${list(r.unresponsive_names).length} without authoritative answer` : '']
          .filter(Boolean).join(' · ') : '';
      case 'dns.dnssec':
        return r.local_validation ? `local validation: ${r.local_validation}` : '';
      case 'dns.caa':
        return int(r.count) ? `${plural(r.count, 'record')} at ${r.policy_domain || 'the checked name'}` : int(r.count) === 0 ? 'no CAA records' : '';
      case 'dns.https':
        return int(r.count) ? plural(r.count, 'record') : 'no HTTPS records';
      case 'mail.mx':
        if (r.null_mx === true) return 'null MX: accepts no mail';
        if (r.implicit_mx_fallback_applies === true) return 'no MX; address records act as implicit MX';
        return int(r.count) === null ? '' : `${plural(r.count, 'MX target')}${int(r.sampled_targets)
          ? ` · ${list(r.resolved_targets).length} of ${r.sampled_targets} sampled resolve` : ''}`;
      case 'mail.spf': {
        if (int(r.record_count) === 0) return 'no SPF record';
        if (int(r.record_count) > 1) return 'multiple SPF records';
        const term = r.all_qualifier === 'absent' ? 'no "all" term' : ENUMS.all_qualifier[r.all_qualifier] || '';
        return [term, int(r.referenced_lookup_terms) === null ? '' : `${r.referenced_lookup_terms} DNS-lookup terms`].filter(Boolean).join(' · ');
      }
      case 'mail.dmarc':
        if (r.applied_policy) return `p=${r.applied_policy}${r.policy_domain ? ` at ${r.policy_domain}` : ''}${r.test_mode === 'y' ? ' · test mode' : ''}`;
        if (r.no_applicable_policy === true) return 'no applicable DMARC policy';
        return int(r.record_count) > 1 ? 'multiple DMARC records' : '';
      case 'mail.dkim':
        return r.key_type ? `${String(r.key_type).toUpperCase()}${int(r.key_bits) ? ` · ${r.key_bits} bits` : ''}` : '';
      case 'mail.mta_sts':
        if (int(r.record_count) === 0) return 'not published';
        return r.mode ? `mode ${r.mode}${int(r.max_age) !== null ? ` · max_age ${duration(r.max_age).replace(/^\d+ s \((.*)\)$/, '$1')}` : ''}` : 'record published';
      case 'mail.tls_rpt':
        return int(r.record_count) === 0 ? 'not published' : plural(int(r.rua_count) ?? 0, 'report destination');
      case 'http.response':
        return r.status_code === undefined ? '' : `HTTPS ${r.status_code}`;
      case 'http.redirect': {
        const hops = list(r.redirect_chain).map(item => String(item).split(' ')[0]);
        return hops.length ? `HTTP ${hops.join(' → ')}${r.redirect === 'same_host_https' ? ' (to HTTPS)' : ''}` : '';
      }
      case 'http.headers': {
        const present = list(r.present_headers).length, absent = list(r.absent_headers).length;
        return present + absent ? `${present} of ${present + absent} selected headers present` : '';
      }
      case 'http.cors':
        return r.allow_origin ? `${ENUMS.allow_origin[r.allow_origin] || r.allow_origin}${r.allow_credentials === true ? ', with credentials' : ''} on ${r.path || '/'}` : '';
      case 'http.security_txt':
        return r.format ? String(ENUMS.format[r.format] || r.format) : r.status_code === undefined ? '' : `HTTP ${r.status_code}`;
      case 'http.connections': {
        const connections = list(r.connections).filter(isRecord);
        const protocols = [...new Set(connections.map(c => c.tls_protocol).filter(Boolean))];
        return connections.length ? `${plural(connections.length, 'connection')}${protocols.length ? ` · ${protocols.join(', ')}` : ''}` : 'no connection established';
      }
      case 'tls.handshake':
        if (r.certificate_verified === false) return 'certificate not verified';
        return `certificate verified${int(r.certificate_days_remaining) === null ? '' : ` · expires in ${plural(r.certificate_days_remaining, 'day')}`}`;
      case 'tls.ciphers':
        return list(r.negotiated_protocols).join(', ');
      case 'ip.network': {
        const addresses = list(r.addresses).filter(isRecord);
        const networks = [...new Set(addresses.map(a => [a.asn, a.as_name].filter(Boolean).join(' ')).filter(Boolean))];
        const total = int(r.total_address_count) ?? addresses.length;
        if (!total) return 'no addresses';
        return `${plural(total, 'address', 'addresses')}${networks.length ? ` · ${networks.slice(0, 2).join(', ')}${networks.length > 2 ? ` +${networks.length - 2}` : ''}` : ''}`;
      }
      default:
        return '';
    }
  }

  // --- errors ---------------------------------------------------------------------------

  // Every code the engine can answer (posture/src/response.ts ERRORS), plus the page's own.
  const ERROR_HINTS = {
    invalid_request: 'Check the target and the optional DKIM selector.',
    target_not_allowed: 'The hosted service checks public DNS names and global IP addresses only. Internal names and private addresses need a self-hosted ShakerScan instance.',
    target_restricted: 'The hosted service does not check government or military targets. A self-hosted instance applies its own policy.',
    region_not_supported: 'The hosted service is not offered in your region. A self-hosted instance runs the same check.',
    route_not_found: 'This page is pointed at the wrong endpoint; its operator should check the endpoint setting.',
    method_not_allowed: 'This page is pointed at the wrong endpoint; its operator should check the endpoint setting.',
    body_too_large: 'The request was larger than the service accepts.',
    unsupported_media_type: 'The request was not sent as JSON.',
    rate_limited: 'The hosted service allows 30 requests a minute per caller.',
    hourly_quota_exceeded: 'The hosted service allows 25 uncached checks an hour per caller; answers cached in the last 10 minutes still work.',
    daily_quota_exceeded: 'The hosted service allows 100 uncached checks a day per caller.',
    dns_unavailable: 'DNS evidence could not be gathered right now; try again in a minute.',
    service_unavailable: 'The check service is temporarily unavailable; try again later.',
    timeout: 'The check did not finish in time; try again.',
    network: 'You may be offline, or the service does not accept requests from this page’s address (CORS).',
    client_timeout: 'No answer arrived within 30 seconds.',
    invalid_response: 'The service answered with something that is not a check result.'
  };

  function describeError(status, body, retryAfter) {
    const error = isRecord(body) && isRecord(body.error) ? body.error : {};
    const code = typeof error.code === 'string' && /^[a-z_]{1,64}$/.test(error.code) ? error.code : status ? `http_${status}` : 'network';
    const message = typeof error.message === 'string' && error.message ? error.message
      : isRecord(body) && typeof body.detail === 'string' && body.detail ? body.detail
        : status ? `The service answered HTTP ${status}.` : 'The request did not complete.';
    const seconds = Number.parseInt(String(retryAfter ?? ''), 10);
    return { code, status: status || 0, message, hint: has(ERROR_HINTS, code) ? ERROR_HINTS[code] : '',
      retryAfter: Number.isFinite(seconds) && seconds > 0 ? seconds : null,
      requestId: isRecord(body) && typeof body.request_id === 'string' ? body.request_id : '' };
  }

  function relativeTime(iso, now) {
    const then = Date.parse(iso);
    if (!Number.isFinite(then)) return '';
    const seconds = Math.round(((now === undefined ? Date.now() : now) - then) / 1000);
    if (seconds < 45) return 'just now';
    const minutes = Math.round(seconds / 60);
    if (minutes < 60) return `${plural(minutes, 'minute')} ago`;
    const hours = Math.round(minutes / 60);
    if (hours < 36) return `${plural(hours, 'hour')} ago`;
    return `${plural(Math.round(hours / 24), 'day')} ago`;
  }

  root.ShakerScanView = Object.freeze({
    HOSTED_SERVICE, GROUPS, ERROR_HINTS, parseTarget, buildRequest, requestOf, cliCommand, serviceLabel, isIpTarget,
    validateDocument, observationsOf, hasData, groupObservations, summarize, reviewHint, reviewHints,
    describe, headline, describeError, relativeTime, humanize, formatDate
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
