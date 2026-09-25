import { encodeQuery, TYPES, type QueryType } from '../src/wire.ts';
import type { Fetcher } from '../src/types.ts';

export function name(value: string): number[] {
  return value ? [...value.split('.').flatMap(s => [s.length, ...Buffer.from(s)]), 0] : [0];
}
const word = (v: number) => [v >> 8, v & 255];
export function rr(type: number, data: number[], owner = 'example.com'): number[] {
  return [...name(owner), ...word(type), 0, 1, 0, 0, 0, 60, ...word(data.length), ...data];
}
export function soa(host = 'example.com'): number[] {
  return rr(TYPES.SOA, [...name('ns.example.com'), ...name('hostmaster.example.com'), ...new Array(20).fill(0)], host);
}
export function packet(host: string, type: QueryType, id: number, records: number[][] = [], flags = 0x81a0, authority: number[][] = []): Uint8Array {
  const query = encodeQuery(host, type, id);
  const question = query.slice(12, query.length - 11);
  return new Uint8Array([...word(id), ...word(flags), 0, 1, ...word(records.length), ...word(authority.length), 0, 0,
    ...question, ...records.flat(), ...authority.flat()]);
}
export function queryInfo(body: RequestInit['body']) {
  const bytes = body as Uint8Array;
  let pos = 12;
  const labels: string[] = [];
  while (bytes[pos]) { const size = bytes[pos++]!; labels.push(Buffer.from(bytes.slice(pos, pos + size)).toString()); pos += size; }
  pos++;
  const number = (bytes[pos]! << 8) | bytes[pos + 1]!;
  return { host: labels.join('.'), type: Object.entries(TYPES).find(([, v]) => v === number)![0] as QueryType,
    id: (bytes[0]! << 8) | bytes[1]! };
}
export function mockDns(overrides: Partial<Record<QueryType | 'DMARC', number[][]>> = {}, calls: { url: string; init: RequestInit }[] = []): Fetcher {
  return async (url, init) => {
    calls.push({ url, init });
    const { host, type, id } = queryInfo(init.body);
    const key = host.startsWith('_dmarc.') ? 'DMARC' : type;
    const defaults: Partial<Record<QueryType | 'DMARC', number[][]>> = {
      A: [rr(TYPES.A, [93, 184, 216, 34], host)],
      NS: [rr(TYPES.NS, name('ns.example.com'), host)],
      MX: [rr(TYPES.MX, [0, 10, ...name('mx.example.com')], host)],
      TXT: [rr(TYPES.TXT, [10, ...Buffer.from('v=spf1 -all')], host)]
    };
    const records = overrides[key] ?? defaults[key] ?? [];
    return new Response(packet(host, type, id, records, 0x81a0, records.length ? [] : [soa(host)]), { headers: { 'Content-Type': 'application/dns-message' } });
  };
}
