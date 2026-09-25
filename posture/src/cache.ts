import { abortable, Budget } from './budget.ts';
import type { Observation } from './types.ts';
export const CACHE_PREFIX = 'check:v1:posture-r4:';
const IDS = ['dns.addresses', 'dns.nameservers', 'dns.dnssec', 'dns.caa', 'mail.mx', 'mail.spf', 'mail.dmarc', 'mail.dkim'];
const WEB_IDS = ['http.response', 'tls.handshake', 'http.headers', 'http.redirect'];
const AWS_WEB_IDS = ['http.response', 'tls.handshake', 'tls.ciphers', 'http.headers', 'http.cors', 'http.redirect'];
const safeText = (v: unknown, limit: number): v is string => typeof v === 'string' && v.length <= limit && !/[\u0000-\u001f\u007f-\u009f]/u.test(v);
const keysOnly = (v: object, keys: string[]) => Object.keys(v).every(k => keys.includes(k));
function evidenceSafe(id: string, value: unknown): boolean {
  if (value === undefined) return true;
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const evidence = value as Record<string, unknown>;
  if (id === 'tls.ciphers') return keysOnly(evidence, ['negotiated_ciphers', 'address_ciphers', 'negotiated_protocols', 'address_protocol_probes']) &&
    Object.entries(evidence).every(([key, v]) => Array.isArray(v) && v.length <= (key === 'address_ciphers' ? 6 : key === 'address_protocol_probes' ? 4 : key === 'negotiated_protocols' ? 2 : 6) &&
      v.every(x => typeof x === 'string' && (key === 'address_ciphers' ?
        /^(?:\d{1,3}\.){3}\d{1,3} (?:TLSv1\.[23])\/[A-Za-z0-9_-]{1,100}$/.test(x) : key === 'negotiated_ciphers' ?
          /^(?:TLSv1\.[23])\/[A-Za-z0-9_-]{1,100}$/.test(x) : key === 'negotiated_protocols' ?
            /^(?:TLSv1\.[23])$/.test(x) :
            /^(?:\d{1,3}\.){3}\d{1,3} TLSv1\.[23] (?:negotiated|not_observed)$/.test(x))));
  if (id === 'tls.handshake') return keysOnly(evidence, ['certificate_days_remaining', 'verified_addresses', 'certificate_expiry_by_address']) && Object.entries(evidence).every(([key, v]) => {
    if (key === 'certificate_days_remaining') return Number.isInteger(v) && Number(v) >= -1 && Number(v) <= 36500;
    if (key === 'verified_addresses') return Array.isArray(v) && v.length <= 2 && v.every(x => typeof x === 'string' && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(x));
    return Array.isArray(v) && v.length <= 2 && v.every(x => typeof x === 'string' && /^(?:\d{1,3}\.){3}\d{1,3} -?\d{1,5}$/.test(x));
  });
  if (id === 'http.cors') return keysOnly(evidence, ['path', 'allow_origin', 'allow_origin_value', 'allow_origin_value_omitted', 'allow_credentials', 'vary_origin', 'preflight_status_code', 'preflight_allow_origin', 'preflight_allow_origin_value', 'preflight_allow_origin_value_omitted', 'preflight_allow_credentials', 'preflight_methods']) &&
    typeof evidence.path === 'string' && evidence.path.length <= 256 && /^\/[a-zA-Z0-9/_~.-]*$/.test(evidence.path) &&
    (evidence.allow_origin === undefined || ['none', 'empty', 'wildcard', 'probe_origin', 'other'].includes(String(evidence.allow_origin))) &&
    (evidence.allow_origin_value_omitted === undefined || typeof evidence.allow_origin_value_omitted === 'boolean') &&
    (evidence.allow_credentials === undefined || typeof evidence.allow_credentials === 'boolean') &&
    (evidence.vary_origin === undefined || typeof evidence.vary_origin === 'boolean') &&
    (evidence.preflight_status_code === undefined || Number.isInteger(evidence.preflight_status_code) && Number(evidence.preflight_status_code) >= 200 && Number(evidence.preflight_status_code) <= 599) &&
    (evidence.preflight_allow_origin === undefined || ['none', 'empty', 'wildcard', 'probe_origin', 'other'].includes(String(evidence.preflight_allow_origin))) &&
    (evidence.preflight_allow_origin_value_omitted === undefined || typeof evidence.preflight_allow_origin_value_omitted === 'boolean') &&
    (evidence.preflight_allow_credentials === undefined || typeof evidence.preflight_allow_credentials === 'boolean') &&
    (evidence.preflight_methods === undefined || safeText(evidence.preflight_methods, 128)) &&
    (evidence.allow_origin_value === undefined || safeText(evidence.allow_origin_value, 256)) &&
    (evidence.preflight_allow_origin_value === undefined || safeText(evidence.preflight_allow_origin_value, 256));
  if (id === 'http.headers') return keysOnly(evidence, ['missing_headers', 'issues', 'hsts_max_age', 'hsts_include_subdomains', 'hsts_preload', 'csp_script_source', 'csp_directives', 'csp_script_values', 'csp_selected_sources', 'x_content_type_options', 'referrer_policy', 'x_frame_options', 'cross_origin_opener_policy', 'cross_origin_resource_policy']) && Object.entries(evidence).every(([key, v]) => {
    if (key === 'hsts_max_age') return Number.isSafeInteger(v) && Number(v) >= 0;
    if (key === 'hsts_include_subdomains' || key === 'hsts_preload') return typeof v === 'boolean';
    if (key === 'csp_script_source') return ['script-src', 'default-src', 'none'].includes(String(v));
    if (key === 'csp_directives') return Array.isArray(v) && v.length <= 32 && v.every(x => typeof x === 'string' && /^[a-z][a-z0-9-]{0,49}$/.test(x));
    if (key === 'csp_script_values') return Array.isArray(v) && v.length <= 24 && v.every(x => safeText(x, 128));
    if (key === 'csp_selected_sources') return Array.isArray(v) && v.length <= 24 && v.every(x => safeText(x, 256));
    if (['x_content_type_options', 'referrer_policy', 'x_frame_options', 'cross_origin_opener_policy', 'cross_origin_resource_policy'].includes(key)) return safeText(v, 128);
    if (key === 'issues') return Array.isArray(v) && v.length <= 12 && v.every(x => typeof x === 'string' && /^(?:missing|invalid|weak|disabled):[a-z-]{1,50}$/.test(x));
    return Array.isArray(v) && v.length <= 5 && v.every(h => ['strict-transport-security', 'content-security-policy', 'x-content-type-options', 'referrer-policy', 'permissions-policy'].includes(h));
  });
  if (id === 'http.response' || id === 'http.redirect') return keysOnly(evidence, ['status_code', 'redirect', 'validated_address_count', 'sampled_address_count', 'sampled_families', 'redirect_chain', 'final_status_code', 'chain_complete']) && Object.entries(evidence).every(([key, v]) => {
    if (key === 'status_code' || key === 'final_status_code') return Number.isInteger(v) && Number(v) >= 200 && Number(v) <= 599;
    if (key === 'redirect_chain') return Array.isArray(v) && v.length <= 4 && v.every(x => typeof x === 'string' && /^[2-5]\d\d (?:none|missing|refused|same_host_http|same_host_https)$/.test(x));
    if (key === 'chain_complete') return typeof v === 'boolean';
    if (key === 'validated_address_count' || key === 'sampled_address_count') return Number.isInteger(v) && Number(v) >= 0 && Number(v) <= 128;
    if (key === 'sampled_families') return Array.isArray(v) && v.length <= 2 && v.every(x => x === 'IPv4' || x === 'IPv6');
    if (key === 'redirect') return ['none', 'missing', 'refused', 'same_host_http', 'same_host_https'].includes(v as string);
    return false;
  });
  if (id === 'dns.caa') return keysOnly(evidence, ['count', 'policy_domain', 'checked_names', 'records']) && Object.entries(evidence).every(([key, v]) => {
    if (key === 'count') return Number.isInteger(v) && Number(v) >= 0 && Number(v) <= 128;
    if (key === 'policy_domain') return typeof v === 'string' && v.length <= 253 && /^[a-z0-9.-]+$/.test(v);
    if (key === 'checked_names') return Array.isArray(v) && v.length <= 8 && v.every(x => typeof x === 'string' && x.length <= 253 && /^[a-z0-9.-]+$/.test(x));
    return Array.isArray(v) && v.length <= 16 && v.every(x => safeText(x, 580));
  });
  const numeric = id === 'dns.addresses' ? ['a_count', 'aaaa_count'] : id === 'mail.spf' ? ['record_count', 'lookup_terms_in_record', 'referenced_lookup_terms', 'missing_or_multiple_records'] : id === 'mail.dmarc' ? ['record_count', 'rua_count', 'ruf_count'] : id === 'mail.mx' ? ['count', 'sampled_targets'] : id === 'dns.dnssec' ? ['validation_queries'] : ['count'];
  const allowed = [...numeric, ...(id === 'dns.dnssec' ? ['validated_queries', 'local_validation', 'validation_reason', 'parent_ds_count', 'dnskey_count', 'ds_algorithms', 'dnskey_algorithms'] : []), ...(id === 'dns.nameservers' ? ['names', 'zone', 'checked_names', 'sampled_names', 'untested_names', 'responding_names', 'unresponsive_names', 'parent_names', 'parent_sampled_names', 'parent_untested_names', 'delegation_names', 'delegation_matches', 'soa_serials'] : []),
    ...(id === 'mail.mx' ? ['null_mx', 'implicit_mx_fallback_applies', 'targets', 'resolved_targets', 'unresolved_targets'] : []), ...(id === 'mail.spf' ? ['all_qualifier', 'recursive_evaluation', 'checked_domains', 'expansion_complete', 'cycles'] : []), ...(id === 'mail.dmarc' ? ['effective_policy_evaluated', 'declared_policy', 'subdomain_policy', 'nonexistent_policy', 'dkim_alignment', 'spf_alignment', 'test_mode', 'checked_names', 'policy_domain', 'inherited', 'applied_policy', 'policy_tag', 'no_applicable_policy'] : []),
    ...(id === 'mail.dkim' ? ['selector', 'key_type', 'key_bits'] : [])];
  return keysOnly(evidence, allowed) && Object.entries(evidence).every(([key, v]) => {
    if (numeric.includes(key)) return Number.isInteger(v) && (v as number) >= 0 && (v as number) <=
      (key === 'referenced_lookup_terms' ? 40960 : key === 'lookup_terms_in_record' ? 4096 : 128);
    if (['names', 'sampled_names', 'untested_names', 'responding_names', 'unresponsive_names', 'parent_names', 'parent_sampled_names', 'parent_untested_names', 'delegation_names'].includes(key)) return Array.isArray(v) && v.length <= 16 && v.every(n => typeof n === 'string' && n.length <= 253 && /^[a-z0-9_.-]+$/.test(n));
    if (key === 'zone') return typeof v === 'string' && v.length <= 253 && /^[a-z0-9.-]+$/.test(v);
    if (key === 'soa_serials') return Array.isArray(v) && v.length <= 2 && v.every(x => typeof x === 'string' && /^[a-z0-9.-]{1,253} \d{1,10}$/.test(x));
    if (key === 'parent_ds_count' || key === 'dnskey_count') return Number.isInteger(v) && Number(v) >= 0 && Number(v) <= 128;
    if (key === 'ds_algorithms' || key === 'dnskey_algorithms') return Array.isArray(v) && v.length <= 16 && v.every(x => typeof x === 'string' && /^\d{1,3}$/.test(x));
    if (key === 'delegation_matches') return typeof v === 'boolean';
    if (key === 'local_validation') return ['secure', 'insecure', 'bogus', 'indeterminate', 'unavailable'].includes(String(v));
    if (key === 'validation_reason') return ['deadline', 'query_limit', 'validator_unavailable'].includes(String(v));
    if (key === 'targets') return Array.isArray(v) && v.length <= 16 && v.every(x => typeof x === 'string' && /^\d{1,5} [a-z0-9.-]{1,253}$/.test(x));
    if (key === 'resolved_targets' || key === 'unresolved_targets') return Array.isArray(v) && v.length <= 3 && v.every(x => typeof x === 'string' && x.length <= 253 && /^[a-z0-9.-]+$/.test(x));
    if (key === 'checked_domains' || key === 'cycles') return Array.isArray(v) && v.length <= 10 && v.every(x => typeof x === 'string' && x.length <= 253 && /^[a-z0-9_.-]+$/.test(x));
    if (key === 'null_mx' || key === 'implicit_mx_fallback_applies') return typeof v === 'boolean';
    if (key === 'all_qualifier') return ['-', '~', '?', '+', 'absent'].includes(v as string);
    if (key === 'recursive_evaluation') return v === false;
    if (key === 'expansion_complete') return typeof v === 'boolean';
    if (key === 'effective_policy_evaluated' || key === 'inherited' || key === 'no_applicable_policy') return typeof v === 'boolean';
    if (key === 'checked_names') return Array.isArray(v) && v.length <= 8 && v.every(x => typeof x === 'string' && x.length <= 253 && /^[a-z0-9.-]+$/.test(x));
    if (key === 'policy_domain') return typeof v === 'string' && v.length <= 253 && /^[a-z0-9.-]+$/.test(v);
    if (key === 'policy_tag') return ['p', 'sp', 'np'].includes(v as string);
    if (key === 'applied_policy') return ['none', 'quarantine', 'reject'].includes(v as string);
    if (['declared_policy', 'subdomain_policy', 'nonexistent_policy'].includes(key)) return ['none', 'quarantine', 'reject'].includes(v as string);
    if (['dkim_alignment', 'spf_alignment'].includes(key)) return ['r', 's'].includes(v as string);
    if (key === 'test_mode') return ['y', 'n'].includes(v as string);
    if (key === 'selector') return typeof v === 'string' && /^[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$/.test(v);
    if (key === 'key_type') return typeof v === 'string' && /^[a-z0-9-]{1,40}$/.test(v);
    if (key === 'key_bits') return Number.isInteger(v) && Number(v) >= 0 && Number(v) <= 32768;
    return Array.isArray(v) && v.length <= 7 && v.every(q => ['A', 'AAAA', 'NS', 'CAA', 'MX', 'TXT', 'DMARC'].includes(q));
  });
}
export function isObservation(value: unknown, host: string): value is Observation {
  if (!value || typeof value !== 'object') return false;
  const o = value as Observation;
  const age = Date.now() - Date.parse(o.checked_at);
  const safeFactValue = (value: unknown, depth = 0): boolean => {
    if (depth > 8) return false;
    if (value === null || typeof value === 'boolean') return true;
    if (typeof value === 'number') return Number.isSafeInteger(value) || Number.isFinite(value) && Math.abs(value) < 1e12;
    if (typeof value === 'string') return safeText(value, 1024);
    if (Array.isArray(value)) return value.length <= 32 && value.every(item => safeFactValue(item, depth + 1));
    return !!value && typeof value === 'object' && Object.keys(value).length <= 32 &&
      Object.entries(value).every(([key, item]) => /^[a-z][a-z0-9_]{0,63}$/.test(key) && safeFactValue(item, depth + 1));
  };
  const extras = o.v2_extras;
  const extrasSafe = extras === undefined || Array.isArray(extras) && extras.length <= 6 &&
    extras.every((item, i) => !!item && typeof item === 'object' && !Array.isArray(item) &&
      item.id === ['ip.network', 'mail.mta_sts', 'mail.tls_rpt', 'http.security_txt', 'dns.https', 'http.connections'][i] &&
      keysOnly(item, ['id', 'name', 'group', 'scope', 'result']) && safeText(item.name, 100) &&
      safeText(item.scope, 300) && ['dns', 'mail', 'http', 'ip'].includes(item.group) && safeFactValue(item.result));
  return keysOnly(o, ['schema_version', 'target', 'checked_at', 'summary', 'checks', 'limitations', 'v2_extras']) && extrasSafe && o.schema_version === '1' && o.target === host && age >= -1000 && age < 600000 &&
    safeText(o.summary, 512) && Array.isArray(o.limitations) && o.limitations.length <= 4 && o.limitations.every(x => safeText(x, 512)) &&
    Array.isArray(o.checks) && [8, 12, 14].includes(o.checks.length) && o.checks.every((c, i) => c && c.id === (o.checks.length === 14 ? [...IDS, ...AWS_WEB_IDS] : [...IDS, ...WEB_IDS])[i] &&
      keysOnly(c, ['id', 'name', 'group', 'status', 'detail', 'evidence']) && evidenceSafe(c.id, c.evidence) &&
      ['pass', 'warn', 'fail', 'unknown'].includes(c.status) && ['dns', 'mail', 'http', 'tls'].includes(c.group) &&
      safeText(c.name, 100) && safeText(c.detail, 512));
}
