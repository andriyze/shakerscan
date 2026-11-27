/**
 * Archive exports answer 503 with Retry-After while every export slot is busy, and heavy reads
 * (dashboard, exposure, grouped targets and inventory facets, exports) answer 429 with
 * Retry-After while their admission slots are full. Either request is worth repeating, not
 * failing: wait as told (bounded), say so, and try again a few times.
 *
 * Only a busy answer is repeated: a 429, or a 503 that carries Retry-After. A bare 503 means
 * "not ready / unavailable" (a database still starting, a dependency down), and waiting it out
 * only hides the server's message from the operator, so it is returned at once.
 *
 * A heavy page read also has a total wait budget (HEAVY_READ_MAX_WAIT_SECONDS), well under the
 * time an operator (or an acceptance check) waits for a page to show its state. A refusal whose
 * wait would exceed the budget is returned with its Retry-After, and the poll loop backs off by it.
 */
export const BUSY_RETRY_ATTEMPTS = 4
export const BUSY_RETRY_DEFAULT_SECONDS = 5
export const BUSY_RETRY_MAX_SECONDS = 30
export const BUSY_STATUSES = new Set([429, 503])
export const HEAVY_READ_MAX_WAIT_SECONDS = 6

function hasRetryAfter(response) {
  const raw = response?.headers?.get?.('retry-after')
  return raw != null && String(raw).trim() !== ''
}

/** True when the server said "busy, come back later" rather than "unavailable". */
export function isBusyAnswer(response) {
  const status = response?.status
  if (status === 429) return true
  return status === 503 && hasRetryAfter(response)
}

export function retryAfterSeconds(response) {
  const raw = response?.headers?.get?.('retry-after')
  const seconds = raw == null || raw === '' ? NaN : Number(raw)
  if (!Number.isFinite(seconds) || seconds < 0) return BUSY_RETRY_DEFAULT_SECONDS
  return Math.min(Math.ceil(seconds), BUSY_RETRY_MAX_SECONDS)
}

export function busyNotice(seconds) {
  return seconds == null ? null : `Archive exports are busy; retrying in ${seconds} s…`
}

function abortError() {
  try {
    return new DOMException('The read was aborted', 'AbortError')
  } catch {
    const error = new Error('The read was aborted')
    error.name = 'AbortError'
    return error
  }
}

/** Wait `ms`, ending early (rejecting) when `signal` aborts: a caller that left stops waiting. */
const pause = (ms, signal) => new Promise((resolve, reject) => {
  if (signal?.aborted) { reject(abortError()); return }
  const timer = setTimeout(() => { signal?.removeEventListener?.('abort', onAbort); resolve() }, ms)
  function onAbort() { clearTimeout(timer); reject(abortError()) }
  signal?.addEventListener?.('abort', onAbort, { once: true })
})

/**
 * @param {object} [options]
 * @param {number | null} [options.maxWaitSeconds] total wait across retries; a busy answer whose
 *   wait would go past it is returned instead (null: no budget beyond `attempts`)
 */
export async function fetchRetryingBusy(input, init, {
  onBusy = () => {}, attempts = BUSY_RETRY_ATTEMPTS, sleep = pause, fetchImpl = (...args) => fetch(...args),
  maxWaitSeconds = null,
} = {}) {
  let waited = 0
  for (let attempt = 1; ; attempt += 1) {
    const response = await fetchImpl(input, init)
    if (!isBusyAnswer(response) || attempt >= attempts) {
      onBusy(null)
      return response
    }
    const seconds = retryAfterSeconds(response)
    if (maxWaitSeconds != null && waited + seconds > maxWaitSeconds) {
      onBusy(null)
      return response
    }
    onBusy(seconds)
    waited += seconds
    await sleep(seconds * 1000, init?.signal)
  }
}

/**
 * ``fetch`` for a heavy page read: retried while the server answers busy, within
 * HEAVY_READ_MAX_WAIT_SECONDS in total; anything else (a bare 503 included) is returned at once.
 */
export function fetchHeavyRead(input, init, options = {}) {
  return fetchRetryingBusy(input, init, { maxWaitSeconds: HEAVY_READ_MAX_WAIT_SECONDS, ...options })
}
