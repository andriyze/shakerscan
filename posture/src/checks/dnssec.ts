import { dnssecLookUp, Question, SecurityStatus } from '@relaycorp/dnssec';
import { boundedBody, type Budget } from '../budget.ts';
import { RESOLVER, query, type Results } from '../dns.ts';
import type { Check, Fetcher } from '../types.ts';
import { encodeQuery, TYPES as WIRE_TYPES, type QueryType } from '../wire.ts';

const TYPES = new Set(['A', 'DS', 'DNSKEY']);

export async function dnssecValidation(host: string, initial: Results, budget: Budget, fetcher: Fetcher): Promise<Check> {
  const validated = Object.entries(initial).filter(([, result]) => result.state === 'ok' && result.ad).map(([type]) => type).sort();
  let queryCount = 0;
  try {
    const result = await dnssecLookUp(new Question(host, 'A'), async question => {
      if (++queryCount > 16) throw new Error('dnssec_query_limit');
      const type = question.getTypeName();
      const name = question.name === '.' ? '.' : question.name.replace(/\.$/, '').toLowerCase();
      if (!TYPES.has(type) || (name !== '.' && (name.length > 253 || !/^[a-z0-9.-]+$/.test(name)))) throw new Error('unsupported_question');
      budget.reserve();
      const id = crypto.getRandomValues(new Uint16Array(1))[0]!;
      const wire = encodeQuery(name, type as QueryType, id);
      wire[3] = wire[3]! | 0x10; // CD: obtain signatures for local verification.
      const signal = AbortSignal.any([budget.signal, AbortSignal.timeout(1000)]);
      const response = await fetcher(RESOLVER, { method: 'POST', redirect: 'manual', signal,
        headers: { Accept: 'application/dns-message', 'Content-Type': 'application/dns-message', 'User-Agent': 'ShakerScan-Public/0.4' }, body: wire });
      if (response.status !== 200 || response.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase() !== 'application/dns-message') {
        void response.body?.cancel().catch(() => {}); throw new Error('dns_unavailable');
      }
      return Buffer.from(await boundedBody(response.body, 32768, signal, 'dns_unavailable'));
    });
    const status = result.status;
    return { id: 'dns.dnssec', name: 'DNSSEC', group: 'dns',
      status: status === SecurityStatus.SECURE ? 'pass' : status === SecurityStatus.BOGUS ? 'warn' : 'unknown',
      detail: `Local DNSSEC validation of the A RRset returned ${status.toLowerCase()}; signed denial of existence is outside this validator.`,
      evidence: { validated_queries: validated, local_validation: status.toLowerCase(), validation_queries: queryCount } };
  } catch {
    const reason = budget.signal.aborted ? 'deadline' : queryCount > 16 ? 'query_limit' : 'validator_unavailable';
    return { id: 'dns.dnssec', name: 'DNSSEC', group: 'dns', status: 'unknown',
      detail: 'Local DNSSEC validation of the A RRset was unavailable.',
      evidence: { validated_queries: validated, local_validation: 'unavailable', validation_reason: reason, validation_queries: queryCount } };
  }
}

export async function dnssecPublishedKeys(check: Check, zone: string, budget: Budget, fetcher: Fetcher): Promise<void> {
  if (!/^[a-z0-9.-]{1,253}$/.test(zone)) return;
  const [ds, keys] = await Promise.all([query(zone, 'DS', budget, fetcher), query(zone, 'DNSKEY', budget, fetcher)]);
  const evidence = check.evidence ?? (check.evidence = {});
  if (ds.state === 'ok' && ds.rcode === 0) {
    const records = ds.records.filter(record => record.section === 'answer' && record.name === zone && record.type === WIRE_TYPES.DS);
    evidence.parent_ds_count = records.length;
    evidence.ds_algorithms = [...new Set(records.map(record => String(record.algorithm)).filter(value => value !== 'undefined'))].slice(0, 16);
    // The validator cannot prove an insecure delegation; an authoritative empty DS answer
    // at the parent is settled evidence that the zone is unsigned, not a transient failure.
    if (!records.length && evidence.local_validation === 'unavailable' && evidence.validation_reason === 'validator_unavailable') {
      evidence.local_validation = 'insecure';
      delete evidence.validation_reason;
      check.detail = `No DS record was published at the parent for ${zone}; the zone is not DNSSEC-signed.`;
    }
  }
  if (keys.state === 'ok' && keys.rcode === 0) {
    const records = keys.records.filter(record => record.section === 'answer' && record.name === zone && record.type === WIRE_TYPES.DNSKEY);
    evidence.dnskey_count = records.length;
    evidence.dnskey_algorithms = [...new Set(records.map(record => String(record.algorithm)).filter(value => value !== 'undefined'))].slice(0, 16);
  }
}
