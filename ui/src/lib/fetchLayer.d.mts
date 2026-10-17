export class ApiError extends Error {
  constructor(message: string, options?: { status?: number; retryAfter?: number | null; detail?: unknown })
  status: number
  /** Seconds the server asked to wait (429/503), when it said. */
  retryAfter: number | null
  detail: unknown
}
export function isAbortError(error: unknown): boolean

export interface GetJsonOptions {
  signal?: AbortSignal
  heavy?: boolean
  maxAgeMs?: number
  dedupe?: boolean
  label?: string
  init?: RequestInit
  onBusy?: (seconds: number | null) => void
}

export interface FetchLayer {
  getJson<T = any>(url: string, options?: GetJsonOptions): Promise<T>
  peek<T = any>(url: string): { body: T; ageMs: number; etag: string | null } | null
  invalidate(prefix?: string): void
  stats: { network: number; deduped: number; notModified: number; cached: number }
}

export function createFetchLayer(options?: {
  fetchImpl?: (input: string, init?: RequestInit) => Promise<Response>
  now?: () => number
  maxEntries?: number
  sleep?: (ms: number) => Promise<void>
}): FetchLayer

export const fetchLayer: FetchLayer
export function getJson<T = any>(url: string, options?: GetJsonOptions): Promise<T>
export function peekJson<T = any>(url: string): { body: T; ageMs: number; etag: string | null } | null
export function invalidateJson(prefix?: string): void
