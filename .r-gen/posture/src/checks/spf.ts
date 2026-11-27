import { answers, query, type Result } from '../dns.ts';
import type { Budget } from '../budget.ts';
import type { Check, Fetcher } from '../types.ts';
import { TYPES } from '../wire.ts';

const terms = (record: string) => record.trim().split(/\s+/).slice(1);
const lookup = (term: string) => /^(?:[+?~-])?(?:include:|a(?:$|[:/])|mx(?:$|[:/])|ptr(?:$|[:/])|exists:|redirect=)/i.test(term);
function referenceName(value: string): string {
  const name = value.toLowerCase();
  if (name.length > 253 || !/^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$/.test(name) ||
      name.split('.').some(label => label.length > 63 || /^-|-$/.test(label)) ||
      /\.(?:local|localhost|internal|invalid|test|example)$/.test(name)) throw new Error('invalid');
  return name;
}
function policies(result: Result, host: string): string[] {
  if (result.state !== 'ok') throw new Error('unavailable');
  return answers(result, host, TYPES.TXT).map(record => record.value ?? '').filter(value => /^v=spf1(?:\s|$)/i.test(value));
}

export async function spfTree(host: string, initial: Result, budget: Budget, fetcher: Fetcher): Promise<Check> {
  const checked: string[] = [], cycles: string[] = [];
  let root: string[];
  try { root = policies(initial, host); }
  catch { return { id: 'mail.spf', name: 'SPF', group: 'mail', status: 'unknown', detail: 'SPF DNS evidence was unavailable.' }; }
  if (root.length !== 1) return { id: 'mail.spf', name: 'SPF', group: 'mail', status: root.length ? 'warn' : 'unknown',
    detail: root.length ? 'Multiple SPF records were observed.' : 'No SPF record was observed.',
    evidence: { record_count: root.length, lookup_terms_in_record: 0, all_qualifier: 'absent', recursive_evaluation: false,
      checked_domains: [host], expansion_complete: root.length === 0, cycles } };
  const rootTerms = terms(root[0]!);
  const allTerms = rootTerms.filter(term => /^[+?~-]?all$/i.test(term));
  const qualifier = allTerms.length ? /^[?~-]/.test(allTerms[0]!) ? allTerms[0]![0]! : '+' : 'absent';
  const policyIssue = allTerms.length > 1 ? 'Multiple all mechanisms appear in the SPF record.' :
    qualifier === '+' ? 'The SPF record permits all senders with +all.' :
    qualifier === '?' ? 'The SPF record ends with a neutral ?all policy.' :
    qualifier === 'absent' && !rootTerms.some(term => /^redirect=/i.test(term)) ? 'No all or redirect terminal policy was observed.' : undefined;
  // Receivers evaluate every include/redirect occurrence, so lookup terms are counted per
  // evaluation. Loops are detected against the current include path, not every prior visit.
  const fetched = new Map<string, Promise<string[] | null>>([[host, Promise.resolve(root)]]);
  const records = (domain: string) => {
    let pending = fetched.get(domain);
    if (!pending) {
      pending = query(domain, 'TXT', budget, fetcher).then(result => policies(result, domain)).catch(() => null);
      fetched.set(domain, pending);
    }
    return pending;
  };
  let incomplete = false, totalTerms = 0, dangling = 0, evaluations = 0;
  const walk = async (domain: string, ancestors: string[]): Promise<void> => {
    if (evaluations >= 10) { incomplete = true; return; }
    evaluations++;
    if (!checked.includes(domain)) checked.push(domain);
    const found = await records(domain);
    if (!found) { incomplete = true; return; }
    if (found.length !== 1) { dangling++; return; }
    const tokens = terms(found[0]!);
    totalTerms += tokens.filter(lookup).length;
    const children: string[] = [];
    for (const token of tokens) {
      const match = /^(?:[+?~-])?(?:include:|redirect=)([^\s]+)$/i.exec(token);
      if (!match) continue;
      try {
        const child = referenceName(match[1]!);
        if (child !== match[1]!.toLowerCase()) throw new Error('invalid');
        if (child === domain || ancestors.includes(child)) cycles.push(child);
        else children.push(child);
      } catch { incomplete = true; }
    }
    await Promise.all(children.slice(0, 10).map(records));
    for (const child of children) await walk(child, [...ancestors, domain]);
  };
  await walk(host, []);
  const issue = policyIssue ?? (totalTerms > 10 ? 'More than ten DNS-lookup terms were referenced across the include/redirect tree.' : undefined);
  return { id: 'mail.spf', name: 'SPF', group: 'mail', status: issue || incomplete || cycles.length || dangling ? 'warn' : 'pass',
    detail: policyIssue ?? (incomplete ? 'SPF include/redirect expansion was incomplete.' : undefined) ?? issue ?? 'SPF include/redirect records were retrieved; sender authorization was not evaluated.',
    evidence: { record_count: root.length, lookup_terms_in_record: rootTerms.filter(lookup).length,
      all_qualifier: qualifier, recursive_evaluation: false, checked_domains: checked,
      expansion_complete: !incomplete, cycles: [...new Set(cycles)].slice(0, 10),
      referenced_lookup_terms: totalTerms, missing_or_multiple_records: dangling } };
}
