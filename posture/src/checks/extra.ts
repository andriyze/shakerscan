import { answers, query, type Result } from '../dns.ts';
import { isPublicAddress } from '../safety.ts';
import { TYPES } from '../wire.ts';
import type { Budget } from '../budget.ts';
import type { Fetcher, Observation } from '../types.ts';
import { pinnedText } from './probe.ts';

type Fact = NonNullable<Observation['v2_extras']>[number];
const fact = (id: string, name: string, group: Fact['group'], scope: string, result: Fact['result']): Fact =>
  ({ id, name, group, scope, result });
function txt(result: Result, owner: string): string[] {
  if (result.state !== 'ok') return [];
  try { return answers(result, owner, TYPES.TXT).map(record => record.value ?? ''); }
  catch { return []; }
}
function tags(value: string): Map<string, string> {
  const fields = new Map<string, string>();
  for (const part of value.split(';')) {
    const match = /^\s*([a-z][a-z0-9_]*)\s*=\s*([\x20-\x7e]*)\s*$/.exec(part);
    if (match && !fields.has(match[1]!)) fields.set(match[1]!, match[2]!.trim());
  }
  return fields;
}

export async function mailTransportFacts(host: string, hasMail: boolean, budget: Budget, fetcher: Fetcher,
  getText: typeof pinnedText = pinnedText): Promise<[Fact, Fact]> {
  const mtaScope = 'TXT at _mta-sts.<target> and, when advertised, one pinned HTTPS GET of the fixed MTA-STS policy path';
  const rptScope = 'TXT at _smtp._tls.<target>; reporting destinations are counted, not contacted';
  if (!hasMail || `mta-sts.${host}`.length > 253) return [
    fact('mail.mta_sts', 'MTA-STS', 'mail', mtaScope, null),
    fact('mail.tls_rpt', 'SMTP TLS Reporting', 'mail', rptScope, null)
  ];
  const [mtaDns, rptDns] = await Promise.all([
    query(`_mta-sts.${host}`, 'TXT', budget, fetcher), query(`_smtp._tls.${host}`, 'TXT', budget, fetcher)
  ]);
  const mtaRecords = txt(mtaDns, `_mta-sts.${host}`).filter(value => /^v=STSv1(?:\s*;|\s*$)/i.test(value));
  const rptRecords = txt(rptDns, `_smtp._tls.${host}`).filter(value => /^v=TLSRPTv1(?:\s*;|\s*$)/i.test(value));
  const rptTags = rptRecords.length === 1 ? tags(rptRecords[0]!) : new Map<string, string>();
  const rpt = fact('mail.tls_rpt', 'SMTP TLS Reporting', 'mail', rptScope, rptDns.state === 'ok' ? {
    record_count: rptRecords.length, rua_count: (rptTags.get('rua') ?? '').split(',').filter(Boolean).length,
    destination_schemes: [...new Set((rptTags.get('rua') ?? '').split(',').map(uri => uri.split(':')[0]?.toLowerCase()).filter(uri => uri === 'mailto' || uri === 'https'))]
  } : null);
  if (mtaDns.state !== 'ok') return [fact('mail.mta_sts', 'MTA-STS', 'mail', mtaScope, null), rpt];
  const mtaResult: Record<string, unknown> = { record_count: mtaRecords.length };
  if (mtaRecords.length === 1) {
    const policyHost = `mta-sts.${host}`;
    try {
      const a = await query(policyHost, 'A', budget, fetcher);
      if (a.state !== 'ok') throw Error('dns_unavailable');
      const ips = answers(a, policyHost, TYPES.A).map(record => record.value!).filter(Boolean);
      if (!ips.length || ips.some(ip => !isPublicAddress(ip))) throw Error('unsafe_address');
      const response = await getText(policyHost, ips[0]!, '/.well-known/mta-sts.txt', budget);
      mtaResult.policy_status_code = response.status;
      if (response.status === 200) {
        const policy = new Map<string, string[]>();
        for (const line of response.body.split(/\r?\n/).slice(0, 100)) {
          const match = /^\s*(version|mode|mx|max_age):\s*([^\r\n]{0,255})\s*$/i.exec(line);
          if (match) policy.set(match[1]!.toLowerCase(), [...(policy.get(match[1]!.toLowerCase()) ?? []), match[2]!.trim()]);
        }
        if (policy.get('version')?.[0] === 'STSv1') {
          const mode = policy.get('mode')?.[0];
          if (mode && ['enforce', 'testing', 'none'].includes(mode)) mtaResult.mode = mode;
          const maxAge = Number(policy.get('max_age')?.[0]);
          if (Number.isSafeInteger(maxAge) && maxAge >= 0) mtaResult.max_age = maxAge;
          mtaResult.mx_patterns = (policy.get('mx') ?? []).filter(value => /^[*a-z0-9.-]{1,253}$/i.test(value)).slice(0, 16);
        }
      }
    } catch { mtaResult.policy_fetch = 'unavailable'; }
  }
  return [fact('mail.mta_sts', 'MTA-STS', 'mail', mtaScope, mtaResult), rpt];
}

export async function securityTextFact(host: string, ip: string | undefined, budget: Budget,
  getText: typeof pinnedText = pinnedText): Promise<Fact> {
  const scope = 'One pinned HTTPS GET of /.well-known/security.txt on a validated IPv4 address; HTTP status, content type and required Contact/Expires fields observed; no redirects followed';
  if (!ip) return fact('http.security_txt', 'Security contact', 'http', scope, null);
  try {
    const response = await getText(host, ip, '/.well-known/security.txt', budget);
    const result: Record<string, unknown> = { status_code: response.status };
    const contentType = response.content_type?.split(';')[0]?.trim().toLowerCase();
    if (contentType) result.content_type = contentType;
    const charset = /(?:^|;)\s*charset\s*=\s*"?([^";\s]+)"?/i.exec(response.content_type ?? '')?.[1]?.toLowerCase();
    if (charset) result.charset = charset.slice(0, 32);
    if (response.status === 200) {
      if (contentType === 'text/html' || /^\s*(?:<!doctype\s+html|<html\b)/i.test(response.body)) {
        result.format = 'html_fallback';
        return fact('http.security_txt', 'Security contact', 'http', scope, result);
      }
      const lines = response.body.split(/\r?\n/).slice(0, 256);
      const values = (key: string) => lines.filter(line => line.toLowerCase().startsWith(`${key.toLowerCase()}:`))
        .map(line => line.slice(key.length + 1).trim());
      const contacts = values('Contact');
      result.contact_count = contacts.length;
      result.contact_schemes = [...new Set(contacts.map(value => value.split(':')[0]?.toLowerCase())
        .filter(value => value === 'mailto' || value === 'https' || value === 'tel'))];
      result.canonical_count = values('Canonical').length;
      const expirations = values('Expires');
      const expires = expirations[0];
      const validExpiry = Boolean(expirations.length === 1 && expires && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$/i.test(expires) &&
        Number.isFinite(Date.parse(expires)) && Date.parse(expires) > Date.now());
      if (expires && Number.isFinite(Date.parse(expires))) result.expires = new Date(expires).toISOString();
      result.format = contentType === 'text/plain' && (!charset || charset === 'utf-8') &&
        contacts.some(value => /^(?:mailto|https|tel):\S+$/i.test(value)) && validExpiry ? 'basic_valid' : 'invalid';
    } else {
      result.format = response.status === 404 || response.status === 410 ? 'absent' : 'http_error';
    }
    return fact('http.security_txt', 'Security contact', 'http', scope, result);
  } catch { return fact('http.security_txt', 'Security contact', 'http', scope, null); }
}

export async function httpsDnsFact(host: string, budget: Budget, fetcher: Fetcher): Promise<Fact> {
  const scope = 'HTTPS resource records from the configured recursive DNS resolver; advertised parameters only';
  const response = await query(host, 'HTTPS', budget, fetcher);
  if (response.state !== 'ok') return fact('dns.https', 'HTTPS DNS records', 'dns', scope, null);
  let records;
  try { records = answers(response, host, TYPES.HTTPS).slice(0, 8)
    .map(record => ({ priority: record.preference, target: record.value, ttl: record.ttl, parameters: record.params ?? [] })); }
  catch { return fact('dns.https', 'HTTPS DNS records', 'dns', scope, null); }
  return fact('dns.https', 'HTTPS DNS records', 'dns', scope, { count: records.length, records });
}
