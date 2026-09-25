import { answers, type Result, type Results } from './dns.ts';
import { TYPES } from './wire.ts';
import type { Check } from './types.ts';

function spfCheck(policies: string[]): Check {
  const evidence: NonNullable<Check['evidence']> = { record_count: policies.length };
  if (policies.length !== 1) return { id: 'mail.spf', name: 'SPF', group: 'mail', status: 'warn',
    detail: policies.length ? 'Multiple SPF records observed; receivers treat this as a permanent error.' : 'No SPF record observed at this name.', evidence };
  const terms = policies[0]!.trim().split(/ +/).slice(1);
  const lookupTerms = terms.filter(term => /^(?:[+?~-])?(?:include:|a(?:$|[:/])|mx(?:$|[:/])|ptr(?:$|[:/])|exists:|redirect=)/i.test(term)).length;
  const allTerms = terms.filter(term => /^(?:[+?~-])?all$/i.test(term));
  const all = allTerms.length === 1 ? allTerms[0]![0] : undefined;
  const qualifier = all === '-' || all === '~' || all === '?' ? all : allTerms.length ? '+' : 'absent';
  evidence.lookup_terms_in_record = lookupTerms;
  evidence.all_qualifier = qualifier;
  evidence.recursive_evaluation = false;
  const issue = lookupTerms > 10 ? 'More than ten DNS-lookup terms appear in this record alone.' :
    allTerms.length > 1 ? 'Multiple all mechanisms appear in the SPF record.' :
    qualifier === '+' ? 'The SPF record permits all senders with +all.' :
    qualifier === '?' ? 'The SPF record ends with a neutral ?all policy.' :
    qualifier === 'absent' && !terms.some(term => /^redirect=/i.test(term)) ? 'No all or redirect terminal policy was observed.' : undefined;
  return { id: 'mail.spf', name: 'SPF', group: 'mail', status: issue ? 'warn' : 'pass',
    detail: issue ?? `SPF declares ${qualifier === 'absent' ? 'a redirect' : `${qualifier}all`}; ${lookupTerms} DNS-lookup term${lookupTerms === 1 ? '' : 's'} in this record. Recursive evaluation and sender authorization were not tested.`, evidence };
}

function txt(result: Result, host: string): string[] { return answers(result, host, TYPES.TXT).map(r => r.value ?? ''); }
function unknown(id: string, name: string): Check {
  return { id, name, group: 'mail', status: 'unknown', detail: 'DNS evidence was unavailable or incomplete.' };
}
export function mailChecks(results: Results, host: string): Check[] {
  const checks: Check[] = [];
  try {
    if (results.MX.state !== 'ok') throw new Error();
    const records = answers(results.MX, host, TYPES.MX);
    const nullMx = records.filter(r => r.value === '' && r.preference === 0);
    checks.push({ id: 'mail.mx', name: 'Mail routing', group: 'mail',
      status: nullMx.length && records.length > 1 ? 'warn' : records.length ? 'pass' : 'unknown',
      detail: nullMx.length ? (records.length === 1 ? 'An explicit null MX declares that this domain does not accept mail.' : 'Null MX and other MX records were observed together; review the configuration.') : records.length ? 'MX records observed; mail-server reachability was not checked.' : 'No explicit MX record observed; implicit mail routing was not evaluated.',
      evidence: { count: records.length, null_mx: nullMx.length === 1 && records.length === 1 } });
  } catch { checks.push(unknown('mail.mx', 'Mail routing')); }
  try {
    if (results.TXT.state !== 'ok') throw new Error();
    const policies = txt(results.TXT, host).filter(value => /^v=spf1(?: |$)/i.test(value));
    checks.push(spfCheck(policies));
  } catch { checks.push(unknown('mail.spf', 'SPF')); }
  try {
    if (results.DMARC.state !== 'ok') throw new Error();
    const policies = txt(results.DMARC, `_dmarc.${host}`).filter(value => /^v=DMARC1(?:\s*;|\s*$)/.test(value));
    let detail = 'No direct DMARC record observed; inherited policy was not evaluated.';
    let status: Check['status'] = 'unknown';
    const evidence: NonNullable<Check['evidence']> = { record_count: policies.length, effective_policy_evaluated: false };
    if (policies.length > 1) { status = 'warn'; detail = 'Multiple direct DMARC records observed; review the configuration.'; }
    if (policies.length === 1) {
      const tags = policies[0]!.split(';').map(s => s.trim()).filter(Boolean);
      const names = new Set<string>();
      let malformed = false;
      for (const tag of tags) {
        const match = /^([a-z][a-z0-9_]*)\s*=\s*([\x20-\x7e]*)$/.exec(tag);
        if (!match || names.has(match[1]!)) { malformed = true; break; }
        names.add(match[1]!);
        if (match[1] === 'p') evidence.declared_policy = match[2]!.trim();
        if (match[1] === 'sp') evidence.subdomain_policy = match[2]!.trim();
        if (match[1] === 'np') evidence.nonexistent_policy = match[2]!.trim();
        if (match[1] === 'adkim') evidence.dkim_alignment = match[2]!.trim();
        if (match[1] === 'aspf') evidence.spf_alignment = match[2]!.trim();
        if (match[1] === 't') evidence.test_mode = match[2]!.trim();
      }
      const policy = String(evidence.declared_policy ?? 'none');
      if (!evidence.declared_policy) evidence.declared_policy = 'none';
      if (malformed || !['none', 'quarantine', 'reject'].includes(policy) ||
          (evidence.subdomain_policy !== undefined && !['none', 'quarantine', 'reject'].includes(String(evidence.subdomain_policy))) ||
          (evidence.nonexistent_policy !== undefined && !['none', 'quarantine', 'reject'].includes(String(evidence.nonexistent_policy))) ||
          (evidence.dkim_alignment !== undefined && !['r', 's'].includes(String(evidence.dkim_alignment))) ||
          (evidence.spf_alignment !== undefined && !['r', 's'].includes(String(evidence.spf_alignment))) ||
          (evidence.test_mode !== undefined && !['y', 'n'].includes(String(evidence.test_mode)))) {
        status = 'warn'; detail = 'The direct DMARC record has malformed or unrecognized policy tags.';
        for (const key of ['declared_policy', 'subdomain_policy', 'nonexistent_policy', 'dkim_alignment', 'spf_alignment', 'test_mode']) delete evidence[key];
      } else {
        evidence.dkim_alignment ??= 'r'; evidence.spf_alignment ??= 'r'; evidence.test_mode ??= 'n';
        status = policy === 'none' || evidence.test_mode === 'y' ? 'warn' : 'pass';
        detail = `The direct DMARC record requests p=${policy}${evidence.subdomain_policy ? `, sp=${evidence.subdomain_policy}` : ''}${evidence.test_mode === 'y' ? ' in test mode' : ''}; inherited policy and message authentication were not evaluated.`;
      }
    }
    checks.push({ id: 'mail.dmarc', name: 'DMARC', group: 'mail', status, detail, evidence });
  } catch { checks.push(unknown('mail.dmarc', 'DMARC')); }
  checks.push({ id: 'mail.dkim', name: 'DKIM', group: 'mail', status: 'unknown', detail: 'DKIM requires a selector and was not checked; selectors are not guessed.' });
  return checks;
}
