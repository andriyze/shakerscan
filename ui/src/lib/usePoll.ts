'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { createPoller, type Poller } from './poller.mjs'

export interface UsePollOptions {
  /** Wait between ticks while `live` (ms). */
  intervalMs: number
  /** Wait while not live (ms); null (the default) stops polling until `refresh()` or `live` turns true. */
  idleIntervalMs?: number | null
  /** Whether something on the page is changing (a running scan, an active Hunt). Default true. */
  live?: boolean
  /** False keeps the loop off entirely (feature disabled, nothing selected). Default true. */
  enabled?: boolean
  /** Restart the loop (with an immediate tick) when any of these change. */
  deps?: ReadonlyArray<unknown>
  maxBackoffMs?: number
}

export interface PollState {
  /** Run a tick now (resets the wait; queued behind a tick in flight). */
  refresh: () => void
  /** Consecutive failed ticks; 0 after a success. */
  failures: number
  /** The last tick's error, cleared by the next success. */
  error: unknown
}

/**
 * Poll `tick` with the shared rules (lib/poller.mjs): no overlap, paused while the tab is hidden,
 * exponential backoff on errors and on 429/503 Retry-After, and a slower or stopped loop while
 * nothing is live. `tick` receives an AbortSignal that aborts when the component unmounts or the
 * deps change, so a late answer can never land on the wrong page.
 */
export function usePoll(tick: (signal: AbortSignal) => Promise<unknown>, {
  intervalMs, idleIntervalMs = null, live = true, enabled = true, deps = [], maxBackoffMs,
}: UsePollOptions): PollState {
  const tickRef = useRef(tick)
  tickRef.current = tick
  const liveRef = useRef(live)
  liveRef.current = live
  const pollerRef = useRef<Poller | null>(null)
  const [failures, setFailures] = useState(0)
  const [error, setError] = useState<unknown>(null)

  useEffect(() => {
    if (!enabled) return
    const poller = createPoller({
      run: async (signal) => {
        await tickRef.current(signal)
        if (!signal.aborted) {
          setFailures(0)
          setError(null)
        }
      },
      intervalMs,
      idleIntervalMs,
      isLive: () => liveRef.current,
      maxBackoffMs,
      onError: (cause, count) => {
        setFailures(count)
        setError(cause)
      },
    })
    pollerRef.current = poller
    poller.start()
    return () => {
      poller.stop()
      if (pollerRef.current === poller) pollerRef.current = null
    }
    // `deps` is the caller's restart key.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, intervalMs, idleIntervalMs, maxBackoffMs, ...deps])

  // Live changed: the next tick comes at the live (or idle) pace, counted from now.
  useEffect(() => {
    pollerRef.current?.reschedule()
  }, [live])

  const refresh = useCallback(() => pollerRef.current?.trigger(), [])
  return { refresh, failures, error }
}
