import { Budget } from './budget.ts';
import { answers, resolve, type Results } from './dns.ts';
import { mailChecks } from './mail.ts';
import { TYPES } from './wire.ts';
import type { Check, Fetcher, Observation } from './types.ts';

export function summarize(checks: Check[]): string {
  const warnings = checks.filter(c => c.status === 'warn' || c.status === 'fail').length;
  const unknown = checks.filter(c => c.status === 'unknown').length;
  return `${warnings} observation${warnings === 1 ? '' : 's'} worth reviewing; ${unknown} check${unknown === 1 ? '' : 's'} could not be determined.`;
}

export function observation(host: string, results: Results): Observation {
  const a = answers(results.A, host, TYPES.A), aaaa = answers(results.AAAA, host, TYPES.AAAA);
  const nxdomain = results.A.state === 'ok' && results.A.rcode === 3;
  const checks: Check[] = [{ id: 'dns.addresses', name: 'Address records', group: 'dns',
    status: nxdomain ? 'fail' : a.length + aaaa.length ? 'pass' : 'unknown',
    detail: nxdomain ? 'The resolver returned NXDOMAIN for this name.' : a.length + aaaa.length ? 'Public address records observed; no connection to these addresses was made.' : 'No A or AAAA records observed; the domain may still provide other services.',
    evidence: { a_count: a.length, aaaa_count: aaaa.length } }];
  for (const [key, type, id, name, present, absent] of [
    ['NS', TYPES.NS, 'dns.nameservers', 'Name servers', 'NS records observed at this name; delegation health was not tested.', 'No NS record observed at this name; parent delegation was not evaluated.'],
    ['CAA', TYPES.CAA, 'dns.caa', 'Certificate issuance policy', 'CAA records observed at this name; effective inherited policy was not evaluated.', 'No CAA record observed at this name; inherited policy may apply.']
  ] as const) {
    try {
      if (results[key].state !== 'ok') throw new Error();
      const records = answers(results[key], host, type);
      if (key === 'NS') {
        const names = [...new Set(records.map(r => r.value).filter((v): v is string => Boolean(v)))].sort();
        checks.push({ id, name, group: 'dns', status: names.length >= 2 ? 'pass' : names.length ? 'warn' : 'unknown',
          detail: names.length >= 2 ? `${names.length} name servers observed in the recursive answer; parent delegation and server reachability were not tested.` : names.length ? 'Only one name server was observed; parent delegation and reachability were not tested.' : absent,
          evidence: { count: names.length, names: names.slice(0, 16) } });
      } else checks.push({ id, name, group: 'dns', status: records.length ? 'pass' : 'unknown', detail: records.length ? present : absent, evidence: { count: records.length } });
    } catch { checks.push({ id, name, group: 'dns', status: 'unknown', detail: 'DNS evidence was unavailable or incomplete.' }); }
  }
  const validated = Object.entries(results).filter(([, r]) => r.state === 'ok' && r.ad).map(([key]) => key);
  checks.splice(2, 0, { id: 'dns.dnssec', name: 'DNSSEC', group: 'dns', status: validated.length ? 'pass' : 'unknown',
    detail: validated.length ? 'The resolver authenticated the listed DNS answer sets with DNSSEC.' : 'DNSSEC validation was not established; this does not prove DNSSEC is disabled.', evidence: { validated_queries: validated } });
  checks.push(...mailChecks(results, host));
  return { schema_version: '1', target: host, checked_at: new Date().toISOString(),
    summary: summarize(checks), checks,
    limitations: ['DNS and direct email-policy observations only; HTTP and TLS probing are not included.', 'SPF sender authorization, inherited CAA/DMARC policy and DKIM were not evaluated.'] };
}
