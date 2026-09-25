import type { Budget } from '../budget.ts';
import type { Observation } from '../types.ts';
import type { IpinfoCache } from './ipinfo.ts';
import type { CallerCountryCache } from './geo.ts';

export interface Store {
  consume(key: string, limit: number, expires: number, budget: Budget): Promise<boolean>;
  get(host: string, selector: string | undefined, budget: Budget, path?: string): Promise<Observation | null>;
  put(data: Observation, selector: string | undefined, budget: Budget, path?: string, transient?: boolean): Promise<void>;
  ipinfo?: IpinfoCache;
  callerCountry?: CallerCountryCache;
}
// Unavailable or incomplete evidence is cached for 60 seconds; settled results for 10 minutes.
const TRANSIENT_DETAIL = /evidence was unavailable|was incomplete|validation of the A RRset was unavailable/;
export function transientResult(data: Observation): boolean {
  return data.checks.some(c => (c.id === 'http.response' && c.status === 'unknown') || TRANSIENT_DETAIL.test(c.detail)) ||
    data.v2_extras?.[0]?.result?.enrichment === 'unavailable';
}
// Result cache key; hosted stores and the in-process store share it.
export const resultCacheKey = (host: string, selector?: string, path = '/') => `cache:v2:deep-r17:${host}:${selector ?? '-'}:${path}`;

/** A store with no admission limits and no cache: every call is a fresh, unlimited check. */
export function unlimitedStore(): Store {
  return { async consume() { return true; }, async get() { return null; }, async put() {} };
}
