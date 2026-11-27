export type Status = 'pass' | 'warn' | 'fail' | 'unknown';
export interface Check {
  id: string;
  name: string;
  group: 'dns' | 'mail' | 'http' | 'tls';
  status: Status;
  detail: string;
  evidence?: Record<string, string | number | boolean | string[]>;
}
export interface Observation {
  schema_version: '1';
  target: string;
  checked_at: string;
  summary: string;
  checks: Check[];
  limitations: string[];
  v2_extras?: Array<{ id: string; name: string; group: 'dns' | 'mail' | 'http' | 'ip'; scope: string; result: Record<string, unknown> | null }>;
}
export type Fetcher = (url: string, init: RequestInit) => Promise<Response>;
