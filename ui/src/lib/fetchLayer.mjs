/**
 * The UI's shared read layer: one place that decides how a GET reaches the API.
 *
 * - Abort: every read takes an AbortSignal; a caller that goes away stops waiting at once.
 * - Dedupe: identical GETs in flight share one request. The shared request is aborted only when
 *   every caller waiting on it has aborted, so one unmounting panel cannot fail another's read.
 * - ETag/304: when the server sent an ETag, the next read sends If-None-Match and a 304 answers
 *   from the cached body. Endpoints without ETags behave exactly as before.
 * - Stale-while-revalidate: `peek(url)` returns the last body (and its age) so a page can paint
 *   it at once while `getJson` revalidates; `maxAgeMs` answers from the cache without a request
 *   while the entry is younger than that. Bodies are retained only where they are reused (an
 *   ETag was sent, or the read asked for `maxAgeMs`), so plain reads hold no memory.
 * - Busy: heavy reads wait out 429/503 + Retry-After (busyRetry.mjs); a refusal that survives
 *   the retries is an `ApiError` carrying `retryAfter`, which the poller turns into backoff.
 */
import { fetchRetryingBusy, retryAfterSeconds } from './busyRetry.mjs'

export class ApiError extends Error {
  constructor(message, { status = 0, retryAfter = null, detail = null } = {}) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.retryAfter = retryAfter
    this.detail = detail
  }
}

export function isAbortError(error) {
  return Boolean(error) && (error.name === 'AbortError' || error.code === 20)
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

function detailMessage(body) {
  const detail = body && typeof body === 'object' ? body.detail : null
  if (typeof detail === 'string') return detail
  if (detail && typeof detail === 'object' && typeof detail.message === 'string') return detail.message
  if (Array.isArray(detail) && detail.length && typeof detail[0]?.msg === 'string') return detail[0].msg
  return null
}

async function failure(response, fallback) {
  let body = null
  try { body = await response.json() } catch { body = null }
  const busy = response.status === 429 || response.status === 503
  return new ApiError(detailMessage(body) || `${fallback} (${response.status})`, {
    status: response.status,
    retryAfter: busy ? retryAfterSeconds(response) : null,
    detail: body && typeof body === 'object' ? body.detail ?? null : null,
  })
}

/**
 * @param {object} [options]
 * @param {(input: string, init?: RequestInit) => Promise<Response>} [options.fetchImpl]
 * @param {() => number} [options.now]
 * @param {number} [options.maxEntries] bounded cache of bodies kept for ETag and peek
 * @param {(ms: number) => Promise<void>} [options.sleep] busy-retry wait (tests)
 */
export function createFetchLayer({
  fetchImpl = (input, init) => fetch(input, init), now = () => Date.now(), maxEntries = 100, sleep,
} = {}) {
  /** url -> { body, etag, at } in least-recently-used order (Map iteration order). */
  const cache = new Map()
  /** url -> { promise, controller, waiters } */
  const inflight = new Map()
  const stats = { network: 0, deduped: 0, notModified: 0, cached: 0 }
  // Bumped by invalidate(): a read that started before it never writes its answer to the cache.
  let epoch = 0

  function remember(url, entry) {
    cache.delete(url)
    cache.set(url, entry)
    while (cache.size > maxEntries) cache.delete(cache.keys().next().value)
  }

  function peek(url) {
    const entry = cache.get(url)
    if (!entry) return null
    return { body: entry.body, ageMs: Math.max(0, now() - entry.at), etag: entry.etag || null }
  }

  async function request(url, { heavy, init, label, controller, onBusy, retain }) {
    const started = epoch
    const entry = cache.get(url)
    const headers = new Headers(init?.headers || undefined)
    if (entry?.etag) headers.set('If-None-Match', entry.etag)
    const requestInit = { cache: 'no-store', ...init, headers, signal: controller.signal }
    stats.network += 1
    const response = heavy
      ? await fetchRetryingBusy(url, requestInit, { fetchImpl, onBusy, ...(sleep ? { sleep } : {}) })
      : await fetchImpl(url, requestInit)
    if (response.status === 304 && entry) {
      stats.notModified += 1
      // An entry invalidated while this read was out stays gone (the 304 answered the old ETag).
      if (started === epoch && cache.get(url) === entry) remember(url, { ...entry, at: now() })
      return entry.body
    }
    if (!response.ok) throw await failure(response, label)
    const body = await response.json()
    const etag = response.headers?.get?.('etag') || null
    // Bodies are kept only where they are reused: for If-None-Match, or a caller's maxAgeMs.
    if (started === epoch && (etag || retain)) remember(url, { body, etag, at: now() })
    else if (started === epoch) cache.delete(url)
    return body
  }

  /**
   * GET `url` as JSON.
   * @param {string} url
   * @param {object} [options]
   * @param {AbortSignal} [options.signal]
   * @param {boolean} [options.heavy] wait out 429/503 + Retry-After before failing
   * @param {number} [options.maxAgeMs] answer from the cache while the entry is this fresh
   * @param {boolean} [options.dedupe] share an identical in-flight GET (default true)
   * @param {string} [options.label] failure message prefix
   * @param {RequestInit} [options.init] extra request options (headers)
   * @param {(seconds: number | null) => void} [options.onBusy]
   */
  function getJson(url, { signal, heavy = false, maxAgeMs = 0, dedupe = true, label = 'Request failed', init, onBusy } = {}) {
    if (signal?.aborted) return Promise.reject(abortError())
    if (maxAgeMs > 0) {
      const entry = cache.get(url)
      if (entry && now() - entry.at < maxAgeMs) {
        stats.cached += 1
        return Promise.resolve(entry.body)
      }
    }
    let shared = dedupe ? inflight.get(url) : undefined
    if (shared) {
      stats.deduped += 1
    } else {
      const controller = new AbortController()
      shared = { controller, waiters: 0, promise: null }
      const current = shared
      current.promise = request(url, { heavy, init, label, controller, onBusy, retain: maxAgeMs > 0 }).finally(() => {
        if (inflight.get(url) === current) inflight.delete(url)
      })
      // A shared read nobody waits for any more must not surface as an unhandled rejection.
      current.promise.catch(() => undefined)
      if (dedupe) inflight.set(url, current)
    }
    const owner = shared
    owner.waiters += 1
    return new Promise((resolve, reject) => {
      let settled = false
      const onAbort = () => {
        if (settled) return
        settled = true
        owner.waiters -= 1
        if (owner.waiters <= 0) {
          if (inflight.get(url) === owner) inflight.delete(url)
          owner.controller.abort()
        }
        reject(abortError())
      }
      signal?.addEventListener('abort', onAbort, { once: true })
      owner.promise.then(
        (body) => { if (!settled) { settled = true; owner.waiters -= 1; signal?.removeEventListener('abort', onAbort); resolve(body) } },
        (error) => { if (!settled) { settled = true; owner.waiters -= 1; signal?.removeEventListener('abort', onAbort); reject(error) } },
      )
    })
  }

  /** Forget cached bodies whose URL starts with `prefix` (all when omitted), e.g. after a write. */
  function invalidate(prefix = '') {
    epoch += 1
    for (const url of [...cache.keys()]) if (url.startsWith(prefix)) cache.delete(url)
    // A read already in flight answers its own callers but is not joined by later ones.
    for (const url of [...inflight.keys()]) if (url.startsWith(prefix)) inflight.delete(url)
  }

  return { getJson, peek, invalidate, stats }
}

/** The page's shared instance. */
export const fetchLayer = createFetchLayer()
export const getJson = (url, options) => fetchLayer.getJson(url, options)
export const peekJson = (url) => fetchLayer.peek(url)
export const invalidateJson = (prefix) => fetchLayer.invalidate(prefix)
