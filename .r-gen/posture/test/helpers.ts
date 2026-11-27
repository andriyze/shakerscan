import { encodeQuery, TYPES, type QueryType } from '../src/wire.ts';
import { isObservation } from '../src/cache.ts';
import type { Check, Fetcher, Observation } from '../src/types.ts';

// Property-test run counts; POSTURE_FUZZ_SCALE=50 (for example) fuzzes longer locally.
export const runs = (count: number) => Math.max(1, Math.round(count * (Number(process.env.POSTURE_FUZZ_SCALE) || 1)));
// isObservation is the engine's schema for a cached observation. Evidence derived from any
// network response must satisfy it, or that target's result is never reusable.
type Fact = NonNullable<Observation['v2_extras']>[number];
const CHECK_IDS = ['dns.addresses', 'dns.nameservers', 'dns.dnssec', 'dns.caa', 'mail.mx', 'mail.spf', 'mail.dmarc', 'mail.dkim',
  'http.response', 'tls.handshake', 'tls.ciphers', 'http.headers', 'http.cors', 'http.redirect'];
const FACT_IDS = ['ip.network', 'mail.mta_sts', 'mail.tls_rpt', 'http.security_txt', 'dns.https', 'http.connections'];
/** Whether isObservation accepts an otherwise minimal observation carrying this check or fact. */
export function cacheAccepts(item: Check | Fact, host = 'example.com'): boolean {
  const checks = CHECK_IDS.map(id => id === item.id && !('scope' in item) ? item : { id, name: id, group: id.split('.')[0] as Check['group'], status: 'unknown' as const, detail: 'stub' });
  const extras = FACT_IDS.map(id => id === item.id && 'scope' in item ? item : { id, name: id, group: id.split('.')[0] as Fact['group'], scope: 'stub', result: null });
  return isObservation({ schema_version: '1', target: host, checked_at: new Date().toISOString(), summary: 'stub', checks, limitations: [], v2_extras: extras }, host);
}
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
