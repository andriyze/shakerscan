/**
 * A framework-free poll loop (the engine behind `usePoll`).
 *
 * - One tick at a time: a tick never overlaps the previous one; `trigger()` during a tick runs
 *   one more right after it.
 * - Hidden tabs do not poll: a due tick waits until the document is visible again, then runs.
 * - Live or idle: while `isLive()` the loop waits `intervalMs`; otherwise `idleIntervalMs`, and
 *   `null` there means it stops until `trigger()` (or `isLive()` turning true on the next trigger).
 * - Errors back off exponentially (interval x 2^failures, capped at `maxBackoffMs`), and a busy
 *   answer's Retry-After (error.retryAfter, seconds) is a floor on the wait.
 * - `stop()` aborts the tick in flight (its AbortSignal) and clears every timer and listener.
 */

export const DEFAULT_MAX_BACKOFF_MS = 120_000

export function documentVisibility(doc = typeof document === 'undefined' ? null : document) {
  return {
    hidden: () => Boolean(doc && doc.visibilityState === 'hidden'),
    subscribe(listener) {
      if (!doc) return () => {}
      doc.addEventListener('visibilitychange', listener)
      return () => doc.removeEventListener('visibilitychange', listener)
    },
  }
}

const realTimers = {
  set: (fn, ms) => setTimeout(fn, ms),
  clear: (id) => clearTimeout(id),
}

/** The wait after `failures` consecutive failed ticks. */
export function backoffDelay(baseMs, failures, { maxBackoffMs = DEFAULT_MAX_BACKOFF_MS, retryAfterSeconds = null } = {}) {
  const exponent = Math.min(Math.max(0, failures), 16)
  let delay = Math.min(maxBackoffMs, baseMs * 2 ** exponent)
  if (Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0) delay = Math.max(delay, retryAfterSeconds * 1000)
  return delay
}

/**
 * @param {object} options
 * @param {(signal: AbortSignal) => Promise<unknown>} options.run one tick
 * @param {number} options.intervalMs wait between ticks while live
 * @param {number | null} [options.idleIntervalMs] wait while not live; null stops until trigger()
 * @param {() => boolean} [options.isLive]
 * @param {number} [options.maxBackoffMs]
 * @param {(error: unknown, failures: number) => void} [options.onError]
 * @param {(state: { failures: number, nextDelayMs: number | null }) => void} [options.onSchedule]
 * @param {{ hidden(): boolean, subscribe(listener: () => void): () => void }} [options.visibility]
 * @param {{ set(fn: () => void, ms: number): unknown, clear(id: unknown): void }} [options.timers]
 */
export function createPoller({
  run, intervalMs, idleIntervalMs = null, isLive = () => true, maxBackoffMs = DEFAULT_MAX_BACKOFF_MS,
  onError = () => {}, onSchedule = () => {}, visibility = documentVisibility(), timers = realTimers,
}) {
  let timer = null
  let running = false
  let rerun = false
  let stopped = true
  let dueWhileHidden = false
  let failures = 0
  let controller = null
  let generation = 0
  let unsubscribe = () => {}

  function clearTimer() {
    if (timer !== null) timers.clear(timer)
    timer = null
  }

  function schedule(delay) {
    clearTimer()
    onSchedule({ failures, nextDelayMs: delay })
    if (stopped || delay == null) return
    timer = timers.set(() => {
      timer = null
      tick()
    }, delay)
  }

  function nextDelay(error) {
    if (error !== undefined) {
      return backoffDelay(intervalMs, failures, { maxBackoffMs, retryAfterSeconds: error?.retryAfter ?? null })
    }
    return isLive() ? intervalMs : idleIntervalMs
  }

  async function tick() {
    if (stopped) return
    if (visibility.hidden()) {
      dueWhileHidden = true
      return
    }
    if (running) {
      rerun = true
      return
    }
    running = true
    dueWhileHidden = false
    const mine = generation
    controller = new AbortController()
    const signal = controller.signal
    let failure
    try {
      await run(signal)
      if (mine !== generation) return
      failures = 0
    } catch (error) {
      // A tick stopped (or superseded by a restart) while it ran leaves no trace.
      if (mine !== generation || signal.aborted) return
      failures += 1
      failure = error
      onError(error, failures)
    }
    running = false
    controller = null
    if (stopped) return
    if (rerun) {
      rerun = false
      schedule(0)
      return
    }
    schedule(nextDelay(failure))
  }

  function onVisibility() {
    if (stopped || visibility.hidden()) return
    if (dueWhileHidden) tick()
  }

  return {
    start() {
      if (!stopped) return
      stopped = false
      failures = 0
      unsubscribe = visibility.subscribe(onVisibility)
      tick()
    },
    stop() {
      stopped = true
      generation += 1
      rerun = false
      dueWhileHidden = false
      clearTimer()
      unsubscribe()
      unsubscribe = () => {}
      controller?.abort()
      controller = null
      running = false
    },
    /** Run a tick now (or right after the one in flight), resetting the wait. */
    trigger() {
      if (stopped) return
      clearTimer()
      tick()
    },
    /** Recompute the wait (after `isLive()` changed) without running a tick now. */
    reschedule() {
      if (stopped || running || dueWhileHidden || failures > 0) return
      schedule(isLive() ? intervalMs : idleIntervalMs)
    },
    state() {
      return { running, stopped, failures, scheduled: timer !== null, dueWhileHidden }
    },
  }
}
