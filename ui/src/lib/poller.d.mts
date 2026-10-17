export const DEFAULT_MAX_BACKOFF_MS: number
export interface PollVisibility {
  hidden(): boolean
  subscribe(listener: () => void): () => void
}
export function documentVisibility(doc?: Document | null): PollVisibility
export function backoffDelay(baseMs: number, failures: number, options?: { maxBackoffMs?: number; retryAfterSeconds?: number | null }): number
export interface Poller {
  start(): void
  stop(): void
  trigger(): void
  reschedule(): void
  state(): { running: boolean; stopped: boolean; failures: number; scheduled: boolean; dueWhileHidden: boolean }
}
export function createPoller(options: {
  run: (signal: AbortSignal) => Promise<unknown>
  intervalMs: number
  idleIntervalMs?: number | null
  isLive?: () => boolean
  maxBackoffMs?: number
  onError?: (error: unknown, failures: number) => void
  onSchedule?: (state: { failures: number; nextDelayMs: number | null }) => void
  visibility?: PollVisibility
  timers?: { set(fn: () => void, ms: number): unknown; clear(id: unknown): void }
}): Poller
