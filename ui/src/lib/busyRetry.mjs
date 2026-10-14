/**
 * Archive exports answer 503 with Retry-After while every export slot is busy, and heavy reads
 * (dashboard, exposure, grouped targets and inventory facets, exports) answer 429 with
 * Retry-After while their admission slots are full. Either request is worth repeating, not
 * failing: wait as told (bounded), say so, and try again a few times.
 */
export const BUSY_RETRY_ATTEMPTS = 4
export const BUSY_RETRY_DEFAULT_SECONDS = 5
export const BUSY_RETRY_MAX_SECONDS = 30
export const BUSY_STATUSES = new Set([429, 503])

export function retryAfterSeconds(response) {
  const raw = response?.headers?.get?.('retry-after')
  const seconds = raw == null || raw === '' ? NaN : Number(raw)
  if (!Number.isFinite(seconds) || seconds < 0) return BUSY_RETRY_DEFAULT_SECONDS
  return Math.min(Math.ceil(seconds), BUSY_RETRY_MAX_SECONDS)
}

export function busyNotice(seconds) {
  return seconds == null ? null : `Archive exports are busy; retrying in ${seconds} s…`
}

const pause = (ms) => new Promise(resolve => setTimeout(resolve, ms))

export async function fetchRetryingBusy(input, init, {
  onBusy = () => {}, attempts = BUSY_RETRY_ATTEMPTS, sleep = pause, fetchImpl = (...args) => fetch(...args),
} = {}) {
  for (let attempt = 1; ; attempt += 1) {
    const response = await fetchImpl(input, init)
    if (!BUSY_STATUSES.has(response.status) || attempt >= attempts) {
      onBusy(null)
      return response
    }
    const seconds = retryAfterSeconds(response)
    onBusy(seconds)
    await sleep(seconds * 1000)
  }
}

/** ``fetch`` for a heavy read: retried while the server answers busy (429/503 + Retry-After). */
export function fetchHeavyRead(input, init) {
  return fetchRetryingBusy(input, init)
}
