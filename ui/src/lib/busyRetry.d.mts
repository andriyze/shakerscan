export const BUSY_RETRY_ATTEMPTS: number
export const BUSY_RETRY_DEFAULT_SECONDS: number
export const BUSY_RETRY_MAX_SECONDS: number
export const BUSY_STATUSES: ReadonlySet<number>
export const HEAVY_READ_MAX_WAIT_SECONDS: number
export function isBusyAnswer(response: { status?: number; headers?: { get(name: string): string | null } } | null | undefined): boolean
export function retryAfterSeconds(response: { headers?: { get(name: string): string | null } } | null | undefined): number
export function busyNotice(seconds: number | null): string | null
export function fetchRetryingBusy(
  input: RequestInfo | URL,
  init?: RequestInit,
  options?: {
    onBusy?: (seconds: number | null) => void
    attempts?: number
    sleep?: (ms: number, signal?: AbortSignal | null) => Promise<void>
    fetchImpl?: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
    maxWaitSeconds?: number | null
  },
): Promise<Response>
export function fetchHeavyRead(
  input: RequestInfo | URL,
  init?: RequestInit,
  options?: Parameters<typeof fetchRetryingBusy>[2],
): Promise<Response>
