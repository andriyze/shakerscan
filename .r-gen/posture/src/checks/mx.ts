import { answers, query, type Result } from '../dns.ts';
import type { Budget } from '../budget.ts';
import { normalizeTarget } from '../target.ts';
import type { Check, Fetcher } from '../types.ts';
import { TYPES } from '../wire.ts';

export async function mxTargets(host: string, initial: Result, budget: Budget, fetcher: Fetcher): Promise<Check> {
  if (initial.state !== 'ok') return { id: 'mail.mx', name: 'Mail routing', group: 'mail', status: 'unknown', detail: 'MX DNS evidence was unavailable.' };
  let records;
  try { records = answers(initial, host, TYPES.MX); }
  catch { return { id: 'mail.mx', name: 'Mail routing', group: 'mail', status: 'unknown', detail: 'MX DNS evidence was unavailable.' }; }
  const nullRecords = records.filter(record => record.value === '').length;
  const nullMx = records.length === 1 && nullRecords === 1 && records[0]!.preference === 0;
  const targets = records.filter(record => record.value).slice(0, 16)
    .map(record => `${record.preference ?? 0} ${record.value}`);
  if (nullMx || !records.length) return { id: 'mail.mx', name: 'Mail routing', group: 'mail', status: records.length ? 'pass' : 'unknown',
    detail: nullMx ? 'An explicit null MX was observed.' : 'No explicit MX record was observed; SMTP senders may use A/AAAA address records as an implicit MX.',
    evidence: { count: records.length, null_mx: nullMx, implicit_mx_fallback_applies: !records.length,
      targets, sampled_targets: 0, resolved_targets: [], unresolved_targets: [] } };
  const resolved: string[] = [], unresolved: string[] = [];
  const sample = [...new Set(records.map(record => record.value).filter((value): value is string => Boolean(value)))].slice(0, 3);
  await Promise.all(sample.map(async target => {
    try {
      if (normalizeTarget(target) !== target) throw new Error();
      const a = await query(target, 'A', budget, fetcher);
      if (a.state === 'ok' && answers(a, target, TYPES.A).length) { resolved.push(target); return; }
      const aaaa = await query(target, 'AAAA', budget, fetcher);
      if (aaaa.state === 'ok' && answers(aaaa, target, TYPES.AAAA).length) { resolved.push(target); return; }
    } catch { /* A malformed or unavailable target remains unresolved. */ }
    unresolved.push(target);
  }));
  resolved.sort(); unresolved.sort();
  return { id: 'mail.mx', name: 'Mail routing', group: 'mail', status: unresolved.length || nullRecords ? 'warn' : 'pass',
    detail: nullRecords ? 'Null MX and other MX records were observed together; review the configuration.' : `Resolved ${resolved.length} of ${sample.length} sampled MX targets to an address; reachability was not tested.`,
    evidence: { count: records.length, null_mx: false, implicit_mx_fallback_applies: false, targets, sampled_targets: sample.length,
      resolved_targets: resolved, unresolved_targets: unresolved } };
}
