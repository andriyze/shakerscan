import { isIP } from 'node:net';
import ipaddr from 'ipaddr.js';
import { answers, query } from '../dns.ts';
import { PublicError } from '../response.ts';
import { isPublicAddress } from '../safety.ts';
import { TYPES } from '../wire.ts';
import type { Budget } from '../budget.ts';
import { summarize } from '../check.ts';
import type { Check, Fetcher, Observation } from '../types.ts';
import { securityTextFact } from './extra.ts';
import { webChecks, type WebFact } from './probe.ts';
import { isRestrictedTarget } from './restricted.ts';

// Only canonical literals are IP targets. Legacy numeric spellings (0x7f.1, 2130706433,
// octal, short forms) are never treated as addresses here; normalizeTarget rejects them.
const IPV4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/** Returns the canonical address for an IP-literal target, or null when the input is not one. */
export function parseIpTarget(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  let value = input.trim();
  if (value.startsWith('[') && value.endsWith(']')) value = value.slice(1, -1);
  if (IPV4.test(value)) {
    if (!isPublicAddress(value)) throw new PublicError('target_not_allowed');
    return value;
  }
  if (!value.includes(':')) return null;
  // Zone identifiers, embedded IPv4 and anything ipaddr.js would only accept loosely are refused.
  if (value.length > 45 || !/^[0-9a-fA-F:]+$/.test(value) || !ipaddr.IPv6.isValid(value)) throw new PublicError('target_not_allowed');
  const address = ipaddr.IPv6.parse(value).toString();
  if (!isPublicAddress(address)) throw new PublicError('target_not_allowed');
  return address;
}

export function reverseName(ip: string): string {
  const address = ipaddr.parse(ip);
  if (address.kind() === 'ipv4') return `${address.toByteArray().reverse().join('.')}.in-addr.arpa`;
  const hex = address.toByteArray().map(byte => byte.toString(16).padStart(2, '0')).join('');
  return `${[...hex].reverse().join('.')}.ip6.arpa`;
}

export async function reverseDns(ip: string, budget: Budget, fetcher: Fetcher): Promise<string[] | null> {
  const owner = reverseName(ip);
  const result = await query(owner, 'PTR', budget, fetcher);
  if (result.state !== 'ok') return null;
  try {
    return [...new Set(answers(result, owner, TYPES.PTR).map(record => (record.value ?? '').toLowerCase())
      .filter(name => name.length <= 253 && /^[a-z0-9_.-]+$/.test(name)))].slice(0, 8);
  } catch { return null; }
}

// Government and military networks are refused before any connection to the address.
const GOVERNMENT_NETWORK = /\b(?:DoD Network Information Center|Department of Defen[cs]e|Defense Information Systems Agency|Ministry of Defen[cs]e|Armed Forces|Government of|Federal Government|Government Offices|Ministerio de Defensa|Bundeswehr)\b/i;

// Legacy IPv4 /8 blocks the IANA registry lists as held by the US Department of Defense
// or the UK Ministry of Defence. Much of this space is unannounced, so ownership data is absent.
const MILITARY_BLOCKS = [6, 7, 11, 21, 22, 25, 26, 28, 29, 30, 33, 55, 214, 215];

export function restrictedNetwork(network: Record<string, unknown> | undefined, ptr: string[] | null): boolean {
  const ip = typeof network?.ip === 'string' ? network.ip : '';
  if (isIP(ip) === 4 && MILITARY_BLOCKS.includes(Number(ip.split('.')[0]))) return true;
  // Unrouted space has no ownership evidence to screen, and no public service to observe.
  if (typeof network?.asn !== 'string' || !network.asn) return true;
  const asDomain = typeof network?.as_domain === 'string' ? network.as_domain.toLowerCase() : '';
  const asName = typeof network?.as_name === 'string' ? network.as_name : '';
  return (asDomain !== '' && isRestrictedTarget(asDomain)) || GOVERNMENT_NETWORK.test(asName) ||
    (ptr ?? []).some(name => isRestrictedTarget(name));
}

type Extra = NonNullable<Observation['v2_extras']>[number];
const notApplicable = (id: string, name: string, group: Check['group']): Check =>
  ({ id, name, group, status: 'unknown', detail: 'Not applicable to an IP address target; no DNS lookup was made for this check.' });

// The same 14 checks and 6 extras as a hostname observation, so cache validation and the
// response schema are unchanged; DNS and mail observations are explicitly not applicable.
export async function ipObservation(ip: string, network: Record<string, unknown>, budget: Budget, path: string,
  web: typeof webChecks = webChecks, securityText: typeof securityTextFact = securityTextFact): Promise<Observation> {
  const v4 = isIP(ip) === 4;
  const checks: Check[] = [
    { id: 'dns.addresses', name: 'Address records', group: 'dns', status: 'pass',
      detail: v4 ? 'The target is a public IPv4 address; HTTP and HTTPS connect to it directly without DNS.' : 'The target is a public IPv6 address; this Lambda has no IPv6 egress, so it was not probed.',
      evidence: { a_count: v4 ? 1 : 0, aaaa_count: v4 ? 0 : 1 } },
    notApplicable('dns.nameservers', 'Name servers', 'dns'), notApplicable('dns.dnssec', 'DNSSEC', 'dns'),
    notApplicable('dns.caa', 'Certificate issuance policy', 'dns'), notApplicable('mail.mx', 'Mail routing', 'mail'),
    notApplicable('mail.spf', 'SPF', 'mail'), notApplicable('mail.dmarc', 'DMARC', 'mail'), notApplicable('mail.dkim', 'DKIM', 'mail')
  ];
  let connections: WebFact[] = [];
  const [probes, contact] = await Promise.all([
    web(ip, [ip], budget, path, facts => { connections = facts; }),
    securityText(ip, v4 ? ip : undefined, budget)
  ]);
  checks.push(...probes);
  const extras: Extra[] = [
    { id: 'ip.network', name: 'IP network', group: 'ip', scope: 'The target address; IPinfo Lite ASN and country enrichment and reverse DNS (PTR) names', result: network },
    { id: 'mail.mta_sts', name: 'MTA-STS', group: 'mail', scope: 'Not applicable to an IP address target', result: null },
    { id: 'mail.tls_rpt', name: 'SMTP TLS Reporting', group: 'mail', scope: 'Not applicable to an IP address target', result: null },
    contact,
    { id: 'dns.https', name: 'HTTPS DNS record', group: 'dns', scope: 'Not applicable to an IP address target', result: null },
    { id: 'http.connections', name: 'Sampled HTTPS connections', group: 'http',
      scope: 'Status, leaf key and signature, certificate chain and whether the certificate lists the IP address, from a pinned HTTPS connection sent without SNI',
      result: { connections } }
  ];
  return { schema_version: '1', target: ip, checked_at: new Date().toISOString(), summary: summarize(checks), checks,
    limitations: ['Up to seven HEAD requests, one GET and one OPTIONS CORS probe, a fixed-path security.txt GET and up to three same-address redirect hops. No SNI is sent; the certificate chain is verified and its IP identity is reported. IPv6 egress is unavailable.',
      'DNS and email-policy checks apply to hostnames and were not performed for an IP address target.'],
    v2_extras: JSON.parse(JSON.stringify(extras)) };
}
