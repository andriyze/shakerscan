import { answers, query, type Result } from '../dns.ts';
import type { Budget } from '../budget.ts';
import type { Check, Fetcher } from '../types.ts';
import { TYPES } from '../wire.ts';

type Policy = { domain: string; tags: Map<string, string> };
const disposition = ['none', 'quarantine', 'reject'];

function parsePolicy(value: string, domain: string): Policy | null {
  const parts = value.split(';').map(part => part.trim()).filter(Boolean);
  if (parts[0] !== 'v=DMARC1') return null;
  const tags = new Map<string, string>();
  for (const part of parts) {
    const match = /^([a-z][a-z0-9_]*)\s*=\s*([\x20-\x7e]*)$/i.exec(part);
    if (!match) return null;
    const tag = match[1]!.toLowerCase();
    if (tags.has(tag)) return null;
    // Tag values other than URIs are case-insensitive (RFC 7489 §6.4).
    tags.set(tag, ['rua', 'ruf'].includes(tag) ? match[2]!.trim() : match[2]!.trim().toLowerCase());
  }
  if (!disposition.includes(tags.get('p') ?? '') ||
      (tags.has('sp') && !disposition.includes(tags.get('sp')!)) ||
      (tags.has('np') && !disposition.includes(tags.get('np')!)) ||
      (tags.has('psd') && !['y', 'n'].includes(tags.get('psd')!)) ||
      (tags.has('t') && !['y', 'n'].includes(tags.get('t')!)) ||
      (tags.has('adkim') && !['r', 's'].includes(tags.get('adkim')!)) ||
      (tags.has('aspf') && !['r', 's'].includes(tags.get('aspf')!))) return null;
  return { domain, tags };
}

function candidates(result: Result, domain: string): { count: number; policy: Policy | null } {
  if (result.state !== 'ok') throw new Error('unavailable');
  const records = answers(result, `_dmarc.${domain}`, TYPES.TXT).map(record => record.value ?? '')
    .filter(value => /^v=DMARC1(?:\s*;|\s*$)/.test(value));
  return { count: records.length, policy: records.length === 1 ? parsePolicy(records[0]!, domain) : null };
}

export async function dmarcPolicy(host: string, initial: Result, exists: boolean, budget: Budget, fetcher: Fetcher): Promise<Check> {
  const checked = [host];
  let direct: ReturnType<typeof candidates>;
  try { direct = candidates(initial, host); }
  catch { return { id: 'mail.dmarc', name: 'DMARC', group: 'mail', status: 'unknown', detail: 'DMARC DNS evidence was unavailable.',
    evidence: { record_count: 0, effective_policy_evaluated: false, checked_names: checked } }; }
  // RFC 7489 §6.6.3: records at the requested name end discovery even when unusable.
  if (direct.count > 1 || (direct.count === 1 && !direct.policy)) return { id: 'mail.dmarc', name: 'DMARC', group: 'mail', status: 'warn',
    detail: direct.count > 1 ? 'Multiple DMARC records were observed; receivers apply no policy from this name.' :
      'The DMARC record is malformed or uses unrecognized values; receivers may apply no policy.',
    evidence: { record_count: direct.count, effective_policy_evaluated: true, checked_names: checked } };
  const found: Policy[] = [];
  if (direct.policy) found.push(direct.policy);
  if (!direct.policy) {
    const labels = host.split('.');
    const start = Math.max(1, labels.length - 7);
    for (let index = start; index < labels.length && checked.length < 8; index++) {
      const domain = labels.slice(index).join('.');
      checked.push(domain);
      const result = await query(`_dmarc.${domain}`, 'TXT', budget, fetcher);
      try {
        const { policy } = candidates(result, domain);
        if (policy) {
          found.push(policy);
          if (policy.tags.has('psd')) break;
        }
      } catch { return { id: 'mail.dmarc', name: 'DMARC', group: 'mail', status: 'unknown', detail: 'DMARC policy walk was incomplete.',
        evidence: { record_count: direct.count, effective_policy_evaluated: false, checked_names: checked } }; }
    }
  }
  let selected = found[0];
  if (!direct.policy && found.length) {
    const explicitOrg = found.find(policy => policy.tags.get('psd') === 'n');
    const psd = found.find(policy => policy.tags.get('psd') === 'y');
    if (explicitOrg) selected = explicitOrg;
    else if (psd) {
      const org = checked[checked.indexOf(psd.domain) - 1];
      selected = found.find(policy => policy.domain === org) ?? psd;
    } else selected = found.at(-1);
  }
  if (!selected) return { id: 'mail.dmarc', name: 'DMARC', group: 'mail', status: 'unknown',
    detail: 'No applicable DMARC record was observed in the bounded DNS tree walk.',
    evidence: { record_count: direct.count, effective_policy_evaluated: true, checked_names: checked, no_applicable_policy: true } };
  const tags = selected.tags;
  const source = selected.domain === host ? 'p' : !exists && tags.has('np') ? 'np' : tags.has('sp') ? 'sp' : 'p';
  const applied = tags.get(source)!;
  const evidence: NonNullable<Check['evidence']> = {
    record_count: direct.count, effective_policy_evaluated: true, checked_names: checked,
    policy_domain: selected.domain, inherited: selected.domain !== host,
    declared_policy: tags.get('p')!, applied_policy: applied, policy_tag: source,
    dkim_alignment: tags.get('adkim') ?? 'r', spf_alignment: tags.get('aspf') ?? 'r', test_mode: tags.get('t') ?? 'n',
    rua_count: tags.get('rua')?.split(',').filter(Boolean).length ?? 0,
    ruf_count: tags.get('ruf')?.split(',').filter(Boolean).length ?? 0
  };
  if (tags.has('sp')) evidence.subdomain_policy = tags.get('sp')!;
  if (tags.has('np')) evidence.nonexistent_policy = tags.get('np')!;
  return { id: 'mail.dmarc', name: 'DMARC', group: 'mail', status: applied === 'none' || tags.get('t') === 'y' ? 'warn' : 'pass',
    detail: `The applicable DMARC policy was found at ${selected.domain}; message authentication was not evaluated.`, evidence };
}
