import type { Head } from '../http.ts';
import type { Check } from '../types.ts';

export const CORS_PROBE_ORIGIN = 'https://shakerscan-cors-probe.invalid';

export function headerCheck(head: Head): Check {
  const headers = head.headers;
  const issues: string[] = [];
  const required = ['strict-transport-security', 'content-security-policy', 'x-content-type-options', 'referrer-policy', 'permissions-policy'];
  const missing = required.filter(name => !headers.has(name));
  for (const name of missing) issues.push(`missing:${name}`);
  const evidence: NonNullable<Check['evidence']> = { missing_headers: missing };
  const hsts = headers.get('strict-transport-security');
  if (hsts != null) {
    const values = [...hsts.matchAll(/(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?=;|$)/gi)];
    if (values.length !== 1 || !Number.isSafeInteger(Number(values[0]![1]))) issues.push('invalid:hsts-max-age');
    else { const seconds = Number(values[0]![1]); evidence.hsts_max_age = seconds; if (seconds === 0) issues.push('disabled:hsts'); }
    evidence.hsts_include_subdomains = /(?:^|;)\s*includesubdomains\s*(?=;|$)/i.test(hsts);
    evidence.hsts_preload = /(?:^|;)\s*preload\s*(?=;|$)/i.test(hsts);
  }
  const csp = headers.get('content-security-policy');
  if (csp != null) {
    const directives = new Map<string, string[]>();
    for (const directive of csp.split(';').map(s => s.trim()).filter(Boolean)) {
      const [name, ...values] = directive.split(/\s+/);
      if (name && !directives.has(name.toLowerCase())) directives.set(name.toLowerCase(), values.map(v => v.toLowerCase()));
    }
    const source = directives.has('script-src') ? 'script-src' : directives.has('default-src') ? 'default-src' : 'none';
    evidence.csp_script_source = source;
    evidence.csp_directives = [...directives.keys()].filter(name => /^[a-z][a-z0-9-]{0,49}$/.test(name)).slice(0, 32);
    evidence.csp_selected_sources = ['default-src', 'connect-src', 'frame-ancestors', 'form-action', 'object-src', 'base-uri']
      .flatMap(name => (directives.get(name) ?? []).slice(0, 8).map(value => `${name} ${/^(?:'nonce-|\x27sha(?:256|384|512)-)/.test(value) ? '[nonce-or-hash]' : value}`))
      .filter(value => value.length <= 256 && /^[\x20-\x7e]+$/.test(value)).slice(0, 24);
    if (source === 'none') issues.push('missing:csp-script-source');
    else {
      const values = directives.get(source)!;
      evidence.csp_script_values = values.slice(0, 24).map(value =>
        /^'(?:nonce-|sha256-|sha384-|sha512-)/.test(value) ? '[nonce-or-hash]' : value).filter(value => value.length <= 128 && /^[\x20-\x7e]+$/.test(value));
      if (values.includes("'unsafe-eval'")) issues.push('weak:csp-unsafe-eval');
      if (values.includes("'unsafe-inline'") && !values.some(v => /^'(?:nonce-|sha256-|sha384-|sha512-|strict-dynamic)/.test(v))) issues.push('weak:csp-unsafe-inline');
      if (values.includes('*') || values.includes('http:')) issues.push('weak:csp-broad-script-source');
    }
  }
  const xcto = headers.get('x-content-type-options');
  if (xcto != null) evidence.x_content_type_options = xcto.trim().toLowerCase().slice(0, 64);
  if (xcto != null && xcto.trim().toLowerCase() !== 'nosniff') issues.push('invalid:x-content-type-options');
  const referrer = headers.get('referrer-policy');
  if (referrer != null) evidence.referrer_policy = referrer.trim().toLowerCase().slice(0, 128);
  if (referrer != null && /^(?:unsafe-url|no-referrer-when-downgrade)$/i.test(referrer.trim())) issues.push('weak:referrer-policy');
  evidence.issues = issues;
  const frame = headers.get('x-frame-options');
  if (frame != null) evidence.x_frame_options = frame.trim().toLowerCase().slice(0, 64);
  const coop = headers.get('cross-origin-opener-policy');
  if (coop != null) evidence.cross_origin_opener_policy = coop.trim().toLowerCase().slice(0, 64);
  const corp = headers.get('cross-origin-resource-policy');
  if (corp != null) evidence.cross_origin_resource_policy = corp.trim().toLowerCase().slice(0, 64);
  return { id: 'http.headers', name: 'HTTPS security headers', group: 'http', status: issues.length ? 'warn' : 'pass',
    detail: issues.length ? 'Selected HTTPS root headers are missing or have potentially weak values; policy effectiveness was not fully evaluated.' : 'Selected HTTPS root headers have basic valid values; policy effectiveness was not fully evaluated.', evidence };
}

export function corsCheck(head: Head, path = '/', preflight?: Head): Check {
  const origin = head.headers.get('access-control-allow-origin');
  const credentials = head.headers.get('access-control-allow-credentials')?.trim().toLowerCase() === 'true';
  const kind = origin == null ? 'none' : origin === '' ? 'empty' : origin === '*' ? 'wildcard' : origin === CORS_PROBE_ORIGIN ? 'probe_origin' : 'other';
  const preOrigin = preflight?.headers.get('access-control-allow-origin');
  const preKind = preOrigin === undefined || preOrigin === null ? 'none' : preOrigin === '' ? 'empty' : preOrigin === '*' ? 'wildcard' : preOrigin === CORS_PROBE_ORIGIN ? 'probe_origin' : 'other';
  const evidence: NonNullable<Check['evidence']> = { path, allow_origin: kind, allow_credentials: credentials,
    vary_origin: (head.headers.get('vary') ?? '').toLowerCase().split(',').some(value => value.trim() === 'origin') };
  if (origin && origin.length <= 256 && /^[\x20-\x7e]+$/.test(origin)) evidence.allow_origin_value = origin;
  if (origin && !evidence.allow_origin_value) evidence.allow_origin_value_omitted = true;
  if (preflight) {
    evidence.preflight_status_code = preflight.status;
    evidence.preflight_allow_origin = preKind;
    if (preOrigin && preOrigin.length <= 256 && /^[\x20-\x7e]+$/.test(preOrigin)) evidence.preflight_allow_origin_value = preOrigin;
    if (preOrigin && !evidence.preflight_allow_origin_value) evidence.preflight_allow_origin_value_omitted = true;
    evidence.preflight_allow_credentials = preflight.headers.get('access-control-allow-credentials')?.trim().toLowerCase() === 'true';
    evidence.preflight_methods = (preflight.headers.get('access-control-allow-methods') ?? '').slice(0, 128);
  }
  if (kind === 'probe_origin' && credentials) return { id: 'http.cors', name: 'CORS on HTTPS path', group: 'http', status: 'warn',
    detail: 'The requested HTTPS path allows a fixed foreign Origin with credentials on GET; exposure of sensitive data was not established.', evidence };
  if (kind === 'none' || kind === 'empty' || kind === 'other') return { id: 'http.cors', name: 'CORS on HTTPS path', group: 'http', status: 'pass',
    detail: 'No cross-origin read grant was observed for the fixed probe Origin on the requested HTTPS path.', evidence };
  return { id: 'http.cors', name: 'CORS on HTTPS path', group: 'http', status: 'unknown',
    detail: 'A cross-origin read grant was observed on the requested HTTPS path; authenticated behavior was not tested.', evidence };
}
