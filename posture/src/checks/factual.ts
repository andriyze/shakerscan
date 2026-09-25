import { isIP } from 'node:net';
import type { Check, Observation } from '../types.ts';

const scope: Record<string, string> = {
  'dns.addresses': 'A and AAAA answers from the configured recursive DNS resolver',
  'dns.nameservers': 'Enclosing zone NS answer, direct SOA queries including serials to up to two named servers, and parent delegation sampled from up to two parent servers; sampled and untested names are explicit',
  'dns.dnssec': 'Local positive A RRset DNSSEC validation against bundled root trust anchors, resolver authentication flags, and recursive DS/DNSKEY answers at the enclosing zone',
  'dns.caa': 'CAA answers from the requested name up the DNS name tree, bounded to eight names',
  'mail.mx': 'MX answer at the requested name, implicit address-record fallback when no MX exists, and A/AAAA resolution of up to three MX targets',
  'mail.spf': 'SPF TXT record and include/redirect expansion for up to ten domains; no sender IP evaluated',
  'mail.dmarc': 'DMARC TXT policy discovery from the requested name up the DNS name tree, bounded to eight names',
  'mail.dkim': 'TXT key at <selector>._domainkey.<target> when a selector was supplied',
  'http.response': 'HTTPS HEAD / on up to two validated IPv4 addresses',
  'tls.handshake': 'Certificate and TLS data from the sampled HTTPS connections',
  'tls.ciphers': 'Ciphers and protocol versions negotiated by bounded TLS 1.2, TLS 1.3 and default HTTPS handshakes on up to two IPv4 addresses; failed probes do not prove a version is unsupported',
  'http.headers': 'Selected headers from HTTPS HEAD / on one validated IPv4 address',
  'http.cors': 'HTTPS GET and OPTIONS on the result path with one fixed foreign Origin on one validated IPv4 address; absent, empty and returned origin values are distinguished',
  'http.redirect': 'HTTP HEAD / and up to three same-host redirect hops on one validated IPv4 address'
};

function measured(check: Check): Record<string, string | number | boolean | string[]> | null {
  if (!check.evidence) return null;
  // The legacy issues list is a policy judgment. Header presence is retained
  // as a measurement against the explicitly selected header names.
  const { issues: _issues, missing_headers: missing, ...facts } = check.evidence;
  if (check.id === 'http.headers' && Array.isArray(missing)) {
    const selected = ['strict-transport-security', 'content-security-policy', 'x-content-type-options', 'referrer-policy', 'permissions-policy'];
    facts.present_headers = selected.filter(name => !missing.includes(name));
    facts.absent_headers = missing;
  }
  if (check.id === 'tls.handshake') facts.certificate_verified = check.status === 'pass' || check.status === 'warn';
  return Object.keys(facts).length ? facts : null;
}

// DNS and mail observations describe hostnames; an IP-address target has none of them.
const HOSTNAME_ONLY = ['dns.nameservers', 'dns.dnssec', 'dns.caa', 'mail.mx', 'mail.spf', 'mail.dmarc', 'mail.dkim'];
function scopeFor(id: string, ipTarget: boolean): string | undefined {
  if (!ipTarget) return scope[id];
  if (id === 'dns.addresses') return 'The IP address target itself; no DNS lookup is made';
  return HOSTNAME_ONLY.includes(id) ? 'Not applicable to an IP address target' : scope[id];
}

export function factualResponse(data: Observation, hit: boolean, requestId: string) {
  const ipTarget = isIP(data.target) !== 0;
  return {
    schema_version: '2', target: data.target, checked_at: data.checked_at,
    observations: [...data.checks.map(check => ({ id: check.id, name: check.name, group: check.group,
      scope: scopeFor(check.id, ipTarget), result: measured(check) })), ...(data.v2_extras ?? [])],
    limitations: data.limitations, cache: { hit }, request_id: requestId
  };
}
