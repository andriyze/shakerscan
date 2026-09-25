import { answers, query, type Results } from '../dns.ts';
import type { Budget } from '../budget.ts';
import type { Check, Fetcher } from '../types.ts';
import { TYPES, type RecordData } from '../wire.ts';

function display(record: RecordData): string {
  const tag = record.tag ?? 'unknown';
  // iodef commonly carries a reporting mailbox. It is not needed to describe
  // certificate issuance and stays out of the public response.
  const value = tag === 'iodef' ? '[redacted]' : record.value ?? '[non-printable or too long]';
  return `${record.flags ?? 0} ${tag} ${value}`.slice(0, 580);
}

export async function caaPolicy(host: string, initial: Results['CAA'], budget: Budget, fetcher: Fetcher): Promise<Check> {
  const checked: string[] = [];
  let current = host;
  let result = initial;
  while (checked.length < 8) {
    checked.push(current);
    if (result.state !== 'ok') return { id: 'dns.caa', name: 'Certificate issuance policy', group: 'dns', status: 'unknown',
      detail: 'CAA lookup was incomplete.', evidence: { checked_names: checked } };
    let records: RecordData[];
    try { records = answers(result, current, TYPES.CAA); }
    catch { return { id: 'dns.caa', name: 'Certificate issuance policy', group: 'dns', status: 'unknown',
      detail: 'CAA lookup was incomplete.', evidence: { checked_names: checked } }; }
    if (records.length) return { id: 'dns.caa', name: 'Certificate issuance policy', group: 'dns', status: 'pass',
      detail: `CAA records were observed at ${current}; issuance authorization was not evaluated.`,
      evidence: { count: records.length, policy_domain: current, checked_names: checked,
        records: records.slice(0, 16).map(display) } };
    const parent = current === '.' ? '' : current.includes('.') ? current.slice(current.indexOf('.') + 1) : '.';
    if (!parent) return { id: 'dns.caa', name: 'Certificate issuance policy', group: 'dns', status: 'unknown',
      detail: 'No CAA records were observed from the requested name through the DNS root.',
      evidence: { count: 0, checked_names: checked, records: [] } };
    current = parent;
    result = await query(current, 'CAA', budget, fetcher);
  }
  return { id: 'dns.caa', name: 'Certificate issuance policy', group: 'dns', status: 'unknown',
    detail: 'CAA lookup stopped at its eight-name bound.', evidence: { checked_names: checked } };
}
