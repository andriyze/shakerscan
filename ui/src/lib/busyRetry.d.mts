export const BUSY_RETRY_ATTEMPTS: number
export const BUSY_RETRY_DEFAULT_SECONDS: number
export const BUSY_RETRY_MAX_SECONDS: number
export function retryAfterSeconds(response: { headers?: { get(name: string): string | null } } | null | undefined): number
export function busyNotice(seconds: number | null): string | null
export function fetchRetryingBusy(
  input: RequestInfo | URL,
  init?: RequestInit,
  options?: {
    onBusy?: (seconds: number | null) => void
    attempts?: number
    sleep?: (ms: number) => Promise<void>
    fetchImpl?: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
  },
): Promise<Response>
