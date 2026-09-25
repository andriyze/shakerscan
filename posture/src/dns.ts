import { abortable, boundedBody, Budget } from './budget.ts';
import { PublicError } from './response.ts';
import { decodeAnswer, encodeQuery, TYPES, type DnsAnswer, type QueryType, type RecordData } from './wire.ts';
import { isPublicAddress } from './safety.ts';
import { normalizeTarget } from './target.ts';
import type { Fetcher } from './types.ts';

export const RESOLVER = 'https://cloudflare-dns.com/dns-query';
export type Result = DnsAnswer | { state: 'unavailable' | 'timeout' };
export type Results = Record<'A' | 'AAAA' | 'NS' | 'CAA' | 'MX' | 'TXT' | 'DMARC', Result>;
export async function query(host: string, type: QueryType, budget: Budget, fetcher: Fetcher): Promise<Result> {
  const controller = new AbortController();
  const abort = () => controller.abort();
  budget.signal.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(abort, Math.max(0, Math.min(3000, budget.deadline - Date.now())));
  try {
    budget.reserve();
    const id = crypto.getRandomValues(new Uint16Array(1))[0]!;
    const response = await abortable(fetcher(RESOLVER, {
      method: 'POST', redirect: 'manual', signal: controller.signal,
      headers: { Accept: 'application/dns-message', 'Content-Type': 'application/dns-message', 'User-Agent': 'ShakerScan-Public/0.1' },
      body: encodeQuery(host, type, id)
    }), controller.signal);
    if (response.status !== 200 || response.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase() !== 'application/dns-message') {
      void response.body?.cancel().catch(() => {});
      return { state: 'unavailable' };
    }
    const answer = decodeAnswer(await boundedBody(response.body, 32768, controller.signal, 'dns_unavailable'), { host, type, id });
    if (answer.rcode !== 0 && answer.rcode !== 3) return { state: 'unavailable' };
    return answer;
  } catch {
    return { state: controller.signal.aborted || budget.signal.aborted ? 'timeout' : 'unavailable' };
  } finally {
    clearTimeout(timer); controller.abort(); budget.signal.removeEventListener('abort', abort);
  }
}
export function answers(result: Result, host: string, type: number): RecordData[] {
  if (result.state !== 'ok') return [];
  let name = host === '.' ? '' : host;
  const visited = new Set<string>();
  for (let hop = 0; hop <= 8; hop++) {
    if (visited.has(name)) throw new PublicError('dns_unavailable');
    visited.add(name);
    const aliases = result.records.filter(r => r.section === 'answer' && r.name === name && r.type === TYPES.CNAME);
    const values = result.records.filter(r => r.section === 'answer' && r.name === name && r.type === type);
    if (aliases.length === 0) {
      // An alias-only reply is incomplete unless authenticated denial/SOA supplies negative evidence.
      if (values.length === 0 && !result.records.some(r => r.type === TYPES.SOA && r.section === 'authority')) throw new PublicError('dns_unavailable');
      return values;
    }
    if (aliases.length !== 1 || values.length || !aliases[0]?.value || hop === 8) throw new PublicError('dns_unavailable');
    name = aliases[0].value;
  }
  throw new PublicError('dns_unavailable');
}
export function validateAddressEvidence(results: Results, host: string): void {
  for (const result of Object.values(results)) {
    if (result.state !== 'ok') continue;
    for (const record of result.records) {
      if ((record.type === TYPES.A || record.type === TYPES.AAAA) && !isPublicAddress(record.value ?? '')) throw new PublicError('target_not_allowed');
    }
  }
  for (const type of ['A', 'AAAA'] as const) {
    const result = results[type];
    if (result.state !== 'ok') throw new PublicError(result.state === 'timeout' ? 'timeout' : 'dns_unavailable');
    const values = answers(result, host, TYPES[type]);
    for (const record of result.records.filter(r => r.type === TYPES.CNAME && r.section === 'answer')) {
      normalizeTarget(record.value);
    }
    if (result.rcode === 3 && values.length) throw new PublicError('dns_unavailable');
  }
  if (results.A.state === 'ok' && results.AAAA.state === 'ok' && results.A.rcode !== results.AAAA.rcode) throw new PublicError('dns_unavailable');
  if (results.A.state === 'ok' && results.AAAA.state === 'ok') {
    const chain = (r: DnsAnswer) => r.records.filter(record => record.type === TYPES.CNAME && record.section === 'answer').map(record => `${record.name}:${record.value}`).sort().join('|');
    if (chain(results.A) !== chain(results.AAAA)) throw new PublicError('dns_unavailable');
  }
}
export async function resolve(host: string, budget: Budget, fetcher: Fetcher): Promise<Results> {
  const tasks: [keyof Results, string, QueryType][] = [
    ['A', host, 'A'], ['AAAA', host, 'AAAA'], ['NS', host, 'NS'], ['CAA', host, 'CAA'],
    ['MX', host, 'MX'], ['TXT', host, 'TXT'], ['DMARC', `_dmarc.${host}`, 'TXT']
  ];
  const output = {} as Results;
  let next = 0;
  await Promise.all(Array.from({ length: 3 }, async () => {
    while (next < tasks.length) {
      const [key, name, type] = tasks[next++]!;
      output[key] = await query(name, type, budget, fetcher);
    }
  }));
  validateAddressEvidence(output, host);
  return output;
}
