import assert from 'node:assert/strict'
import test from 'node:test'

import { ApiError, createFetchLayer, isAbortError } from './fetchLayer.mjs'
import { isListV1, isUnknownListParamError, listV1Params, mergeSinceDelta, totalLabel } from './listPage.mjs'

function reply(status, body, headers = {}) {
  const lower = Object.fromEntries(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]))
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (name) => lower[name.toLowerCase()] ?? null },
    json: async () => body,
  }
}

/** A fetch whose answers the test releases one by one. */
function controlledFetch() {
  const calls = []
  const fetchImpl = (url, init) => new Promise((resolve, reject) => {
    const call = { url, init, resolve, reject }
    calls.push(call)
    init?.signal?.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })))
  })
  return { calls, fetchImpl }
}

test('identical reads in flight share one request', async () => {
  const { calls, fetchImpl } = controlledFetch()
  const layer = createFetchLayer({ fetchImpl })
  const first = layer.getJson('/dashboard')
  const second = layer.getJson('/dashboard')
  assert.equal(calls.length, 1)
  calls[0].resolve(reply(200, { ok: 1 }))
  assert.deepEqual(await first, { ok: 1 })
  assert.deepEqual(await second, { ok: 1 })
  assert.equal(layer.stats.deduped, 1)
  // Once settled, the next read is a new request.
  const third = layer.getJson('/dashboard')
  assert.equal(calls.length, 2)
  calls[1].resolve(reply(200, { ok: 2 }))
  assert.deepEqual(await third, { ok: 2 })
})

test('one caller aborting does not fail the others; the last one out aborts the request', async () => {
  const { calls, fetchImpl } = controlledFetch()
  const layer = createFetchLayer({ fetchImpl })
  const a = new AbortController()
  const b = new AbortController()
  const first = layer.getJson('/scans', { signal: a.signal })
  const second = layer.getJson('/scans', { signal: b.signal })
  a.abort()
  await assert.rejects(first, (error) => isAbortError(error))
  assert.equal(calls[0].init.signal.aborted, false, 'still wanted by the second caller')
  b.abort()
  await assert.rejects(second, (error) => isAbortError(error))
  assert.equal(calls[0].init.signal.aborted, true, 'nobody waits any more: the request is aborted')
  // A fresh read after that is not handed the aborted request.
  const third = layer.getJson('/scans')
  assert.equal(calls.length, 2)
  calls[1].resolve(reply(200, []))
  assert.deepEqual(await third, [])
})

test('an already aborted signal never reaches the network', async () => {
  const { calls, fetchImpl } = controlledFetch()
  const layer = createFetchLayer({ fetchImpl })
  const controller = new AbortController()
  controller.abort()
  await assert.rejects(layer.getJson('/x', { signal: controller.signal }), (error) => isAbortError(error))
  assert.equal(calls.length, 0)
})

test('an ETag is revalidated with If-None-Match and a 304 answers from the cache', async () => {
  const seen = []
  const answers = [reply(200, { rows: [1] }, { ETag: 'W/"v1"' }), reply(304, null)]
  const layer = createFetchLayer({ fetchImpl: async (url, init) => { seen.push(init.headers.get('If-None-Match')); return answers.shift() } })
  assert.deepEqual(await layer.getJson('/targets/grouped'), { rows: [1] })
  assert.deepEqual(await layer.getJson('/targets/grouped'), { rows: [1] })
  assert.deepEqual(seen, [null, 'W/"v1"'])
  assert.equal(layer.stats.notModified, 1)
})

test('without an ETag no conditional header is sent', async () => {
  const seen = []
  const layer = createFetchLayer({ fetchImpl: async (url, init) => { seen.push(init.headers.get('If-None-Match')); return reply(200, { n: seen.length }) } })
  await layer.getJson('/queue/stats')
  await layer.getJson('/queue/stats')
  assert.deepEqual(seen, [null, null])
})

test('stale-while-revalidate: peek shows the last body and its age; maxAgeMs skips the network', async () => {
  let clock = 1_000
  let calls = 0
  const layer = createFetchLayer({ now: () => clock, fetchImpl: async () => { calls += 1; return reply(200, { calls }) } })
  assert.equal(layer.peek('/workers'), null)
  await layer.getJson('/workers', { maxAgeMs: 5_000 })
  clock += 4_000
  assert.deepEqual(layer.peek('/workers'), { body: { calls: 1 }, ageMs: 4_000, etag: null })
  assert.deepEqual(await layer.getJson('/workers', { maxAgeMs: 5_000 }), { calls: 1 })
  assert.equal(calls, 1, 'fresh enough: no request')
  clock += 2_000
  assert.deepEqual(await layer.getJson('/workers', { maxAgeMs: 5_000 }), { calls: 2 })
  layer.invalidate('/work')
  assert.equal(layer.peek('/workers'), null)
})

test('a refusal becomes an ApiError with the server message and Retry-After', async () => {
  const layer = createFetchLayer({ fetchImpl: async () => reply(429, { detail: 'busy' }, { 'Retry-After': '7' }) })
  await assert.rejects(layer.getJson('/exposure/assets'), (error) => {
    assert.ok(error instanceof ApiError)
    assert.equal(error.status, 429)
    assert.equal(error.retryAfter, 7)
    assert.equal(error.message, 'busy')
    return true
  })
})

test('a heavy read waits out busy answers before failing', async () => {
  const answers = [reply(429, null, { 'Retry-After': '1' }), reply(200, { done: true })]
  const waits = []
  const layer = createFetchLayer({ fetchImpl: async () => answers.shift(), sleep: async (ms) => { waits.push(ms) } })
  assert.deepEqual(await layer.getJson('/dashboard', { heavy: true }), { done: true })
  assert.deepEqual(waits, [1000])
})

test('a heavy read answered 503 without Retry-After fails at once with the server message', async () => {
  let calls = 0
  const layer = createFetchLayer({
    fetchImpl: async () => { calls += 1; return reply(503, { detail: 'Database is not ready' }) },
    sleep: async () => { throw new Error('a bare 503 must not be waited out') },
  })
  await assert.rejects(layer.getJson('/exposure/assets', { heavy: true }), (error) => {
    assert.ok(error instanceof ApiError)
    assert.equal(error.status, 503)
    assert.equal(error.message, 'Database is not ready')
    assert.equal(error.retryAfter, null, 'not busy: the poller does not treat it as Retry-After')
    return true
  })
  assert.equal(calls, 1)
})

test('a heavy read gives up within its wait budget and keeps the Retry-After for backoff', async () => {
  const waits = []
  const layer = createFetchLayer({
    fetchImpl: async () => reply(429, { detail: 'busy' }, { 'Retry-After': '5' }),
    sleep: async (ms) => { waits.push(ms) },
  })
  await assert.rejects(layer.getJson('/dashboard', { heavy: true }), (error) => error.status === 429 && error.retryAfter === 5)
  assert.deepEqual(waits, [5000])
})

test('a plain read (no ETag, no maxAgeMs) keeps no body', async () => {
  const layer = createFetchLayer({ fetchImpl: async () => reply(200, { big: true }) })
  await layer.getJson('/scans')
  assert.equal(layer.peek('/scans'), null)
})

test('invalidate: an in-flight read neither repopulates the cache nor is joined afterwards', async () => {
  const { calls, fetchImpl } = controlledFetch()
  const layer = createFetchLayer({ fetchImpl })
  const before = layer.getJson('/targets/inventory?q', { maxAgeMs: 60_000 })
  layer.invalidate('/targets')
  const after = layer.getJson('/targets/inventory?q', { maxAgeMs: 60_000 })
  assert.equal(calls.length, 2, 'the read after invalidate is a new request')
  calls[0].resolve(reply(200, { old: true }))
  assert.deepEqual(await before, { old: true })
  assert.equal(layer.peek('/targets/inventory?q'), null, 'the stale answer is not cached')
  calls[1].resolve(reply(200, { fresh: true }))
  assert.deepEqual(await after, { fresh: true })
  assert.deepEqual(layer.peek('/targets/inventory?q').body, { fresh: true })
})

test('a 304 does not resurrect an entry invalidated while it was out', async () => {
  const { calls, fetchImpl } = controlledFetch()
  const layer = createFetchLayer({ fetchImpl })
  const first = layer.getJson('/g')
  calls[0].resolve(reply(200, { v: 1 }, { ETag: '"1"' }))
  await first
  const second = layer.getJson('/g')
  layer.invalidate()
  calls[1].resolve(reply(304, null))
  assert.deepEqual(await second, { v: 1 })
  assert.equal(layer.peek('/g'), null)
})

test('the body cache is bounded', async () => {
  const layer = createFetchLayer({ maxEntries: 2, fetchImpl: async (url) => reply(200, { url }, { ETag: '"x"' }) })
  await layer.getJson('/a')
  await layer.getJson('/b')
  await layer.getJson('/c')
  assert.equal(layer.peek('/a'), null)
  assert.ok(layer.peek('/b'))
  assert.ok(layer.peek('/c'))
})

test('list/v1 is detected by its envelope; the legacy shape is not', () => {
  assert.equal(isListV1({ items: [], has_more: false, next_cursor: null, total_kind: 'none' }), true)
  assert.equal(isListV1({ findings: [], total: 0 }), false)
  assert.equal(isListV1(null), false)
})

test('list/v1 parameters: count on the first page only, the limit bounded', () => {
  assert.deepEqual(listV1Params({ limit: 50, sort: '-severity' }), { limit: '50', sort: '-severity', count: 'none' })
  assert.deepEqual(listV1Params({ limit: 500, cursor: 'abc', count: 'exact' }), { limit: '200', cursor: 'abc' })
  assert.deepEqual(listV1Params({ count: 'exact', since: '2026-10-14T00:00:00Z' }), { count: 'exact', since: '2026-10-14T00:00:00Z' })
})

test('an engine that rejects the list parameters is recognised, other 400s are not', () => {
  assert.equal(isUnknownListParamError(new ApiError('Unknown query parameter(s): count, sort. Allowed: …', { status: 400 })), true)
  assert.equal(isUnknownListParamError(new ApiError('severity must be one of …', { status: 400 })), false)
  assert.equal(isUnknownListParamError(new ApiError('Unknown query parameter(s): count', { status: 500 })), false)
})

test('totals: exact, capped, estimated, absent', () => {
  assert.equal(totalLabel({ total: 1234, total_kind: 'exact' }, 'en-US'), '1,234')
  assert.equal(totalLabel({ total: 10000, total_kind: 'at_least' }, 'en-US'), '10,000+')
  assert.equal(totalLabel({ total: 52000, total_kind: 'estimate' }, 'en-US'), 'about 52,000')
  assert.equal(totalLabel({ total_kind: 'none' }), null)
})

test('a since= delta replaces changed rows in place and puts new rows first', () => {
  const rows = [{ id: 'b', v: 1 }, { id: 'a', v: 1 }]
  const merged = mergeSinceDelta(rows, [{ id: 'a', v: 2 }, { id: 'c', v: 1 }])
  assert.deepEqual(merged, [{ id: 'c', v: 1 }, { id: 'b', v: 1 }, { id: 'a', v: 2 }])
  assert.equal(mergeSinceDelta(rows, []), rows, 'an empty delta keeps the same array (no re-render)')
  assert.deepEqual(mergeSinceDelta(rows, [{ id: 'd' }], { limit: 2 }).map((row) => row.id), ['d', 'b'])
})
