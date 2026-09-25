import { isIP } from 'node:net';
import ipaddr from 'ipaddr.js';
import { boundedBody, type Budget } from '../budget.ts';
import { isPublicAddress } from '../safety.ts';
import type { Fetcher } from '../types.ts';

type Network = { ip: string; family: 'IPv4' | 'IPv6'; sampled: boolean; dns_ttl?: number; asn?: string; as_name?: string;
  as_domain?: string; country_code?: string; country?: string; continent_code?: string; continent?: string; anycast?: boolean };
export interface IpinfoCache {
  get(ips: string[], budget: Budget): Promise<Record<string, Record<string, unknown>>>;
  put(records: Record<string, Record<string, unknown>>, budget: Budget): Promise<void>;
}
// The DNS decoder emits uncompressed IPv6; IPinfo returns the RFC 5952 form.
export const canonicalIp = (ip: string) => ipaddr.isValid(ip) ? ipaddr.parse(ip).toString() : ip;
const field = (value: unknown, max: number) => typeof value === 'string' && value.length <= max &&
  /^[\x20-\x7e]+$/.test(value) ? value : undefined;

export async function ipNetworks(addresses: string[], sampled: string[], ttls: Record<string, number>, aliases: string[], token: string, budget: Budget,
  fetcher: Fetcher = fetch, cache?: IpinfoCache): Promise<Record<string, unknown>> {
  const unique = [...new Set(addresses.map(canonicalIp))].filter(ip => isIP(ip) !== 0 && isPublicAddress(ip));
  const selected = unique.slice(0, 8);
  const networks: Network[] = selected.map(ip => ({ ip, family: isIP(ip) === 4 ? 'IPv4' : 'IPv6', sampled: sampled.map(canonicalIp).includes(ip),
    ...(Number.isInteger(ttls[ip]) ? { dns_ttl: ttls[ip] } : {}) }));
  let enrichment = !selected.length ? 'no_addresses' : token ? 'unavailable' : 'unconfigured';
  if (token && selected.length) {
    try {
      const cached = cache ? await cache.get(selected, budget) : {};
      const missing = selected.filter(ip => !cached[ip]);
      let data: Record<string, unknown> = cached;
      if (missing.length) {
        try {
        budget.reserve();
        const signal = AbortSignal.any([budget.signal, AbortSignal.timeout(Math.max(1, Math.min(1500, budget.deadline - Date.now())))]);
        const response = await fetcher('https://api.ipinfo.io/batch/lite', { method: 'POST', redirect: 'manual', signal,
          headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify(missing) });
        if (response.status !== 200 || response.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json') {
          void response.body?.cancel().catch(() => {}); throw Error('ipinfo_unavailable');
        }
        const fresh = JSON.parse(new TextDecoder().decode(await boundedBody(response.body, 8192, signal, 'dns_unavailable')));
        if (!fresh || typeof fresh !== 'object' || Array.isArray(fresh)) throw Error('ipinfo_invalid');
        data = { ...cached, ...fresh };
        } catch { /* A failed batch does not discard cached IP facts. */ }
      }
      let found = 0;
      const toCache: Record<string, Record<string, unknown>> = {};
      for (const item of networks) {
        const record = data[item.ip] as Record<string, unknown> | undefined;
        if (!record || typeof record !== 'object' || typeof record.ip !== 'string' || canonicalIp(record.ip) !== item.ip) continue;
        const safe: Record<string, unknown> = { ip: item.ip };
        for (const key of ['asn', 'as_name', 'as_domain', 'country_code', 'country', 'continent_code', 'continent'] as const) {
          const value = field(record[key], key === 'as_name' ? 200 : 100);
          if (value !== undefined) { item[key] = value; safe[key] = value; }
        }
        if (typeof record.anycast === 'boolean') { item.anycast = record.anycast; safe.anycast = record.anycast; }
        if (!cached[item.ip]) toCache[item.ip] = safe;
        found++;
      }
      if (cache && Object.keys(toCache).length) { try { await cache.put(toCache, budget); } catch { /* Disposable cache. */ } }
      if (found) enrichment = found === networks.length ? 'available' : 'partial';
    } catch { /* Third-party enrichment must never block a domain observation. */ }
  }
  return { addresses: networks, total_address_count: unique.length, cname_chain: aliases.slice(0, 8), enrichment, provider: 'ipinfo_lite' };
}
