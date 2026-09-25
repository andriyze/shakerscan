import { isIP } from 'node:net';
import ipaddr from 'ipaddr.js';
import { boundedBody, type Budget } from '../budget.ts';
import { PublicError } from '../response.ts';
import type { Fetcher } from '../types.ts';

export const BLOCKED_COUNTRIES = new Set(['CN', 'RU', 'KP', 'HK', 'IN', 'BR', 'ID', 'PK', 'NG', 'IR']);

export interface CallerCountryCache {
  get(key: string, budget: Budget): Promise<string | null>;
  put(key: string, country: string, budget: Budget): Promise<void>;
}

export async function checkCallerCountry(ip: string, identity: string, token: string, budget: Budget,
  fetcher: Fetcher = fetch, cache?: CallerCountryCache): Promise<void> {
  if (!token || !isIP(ip)) throw new PublicError('service_unavailable');
  const key = `geo:country:${identity}`;
  let country: string | null = null;
  try { country = await cache?.get(key, budget) ?? null; } catch { budget.assert(); }
  if (!country) {
    try {
      budget.reserve();
      const signal = AbortSignal.any([budget.signal, AbortSignal.timeout(Math.max(1, Math.min(1500, budget.deadline - Date.now())))]);
      const response = await fetcher(`https://api.ipinfo.io/lite/${encodeURIComponent(ip)}`, {
        method: 'GET', redirect: 'manual', signal,
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' }
      });
      if (response.status !== 200 || response.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase() !== 'application/json') {
        void response.body?.cancel().catch(() => {});
        throw Error('geo_unavailable');
      }
      const data: unknown = JSON.parse(new TextDecoder().decode(await boundedBody(response.body, 2048, signal, 'dns_unavailable')));
      if (!data || typeof data !== 'object' || Array.isArray(data)) throw Error('geo_invalid');
      const record = data as Record<string, unknown>;
      const returnedIp = record.ip;
      const returnedCountry = record.country_code;
      if (typeof returnedIp !== 'string' || !isIP(returnedIp) ||
          ipaddr.parse(returnedIp).toNormalizedString() !== ipaddr.parse(ip).toNormalizedString() ||
          typeof returnedCountry !== 'string' || !/^[A-Z]{2}$/.test(returnedCountry))
        throw Error('geo_invalid');
      country = returnedCountry;
      try { await cache?.put(key, country, budget); } catch { budget.assert(); }
    } catch {
      budget.assert();
      throw new PublicError('service_unavailable');
    }
  }
  if (!country) throw new PublicError('service_unavailable');
  if (BLOCKED_COUNTRIES.has(country)) throw new PublicError('region_not_supported');
}
