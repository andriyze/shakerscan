import assert from 'node:assert/strict'
import test from 'node:test'

import {
  BUSY_RETRY_ATTEMPTS, BUSY_STATUSES, HEAVY_READ_MAX_WAIT_SECONDS, busyNotice, fetchHeavyRead, fetchRetryingBusy, isBusyAnswer,
  retryAfterSeconds,
} from './busyRetry.mjs'

// R2 review: a download holding the archive export slots made the UI's own browse pages fail with
// "Export failed (503)". A 503 is now retried after Retry-After, with a notice while waiting.
const reply = (status, retryAfter) => ({ status, headers: { get: (name) => (name === 'retry-after' ? retryAfter : null) } })

test('Retry-After is honoured, bounded, and defaulted', () => {
  assert.equal(retryAfterSeconds(reply(503, '10')), 10)
  assert.equal(retryAfterSeconds(reply(503, '600')), 30)
  assert.equal(retryAfterSeconds(reply(503, 'Wed, 21 Oct 2026 07:28:00 GMT')), 5)
  assert.equal(retryAfterSeconds(reply(503, null)), 5)
  assert.equal(busyNotice(10), 'Archive exports are busy; retrying in 10 s…')
  assert.equal(busyNotice(null), null)
})

test('a busy archive is retried until it answers, with a notice while waiting', async () => {
  const answers = [reply(503, '2'), reply(503, '3'), reply(200, null)]
  const waits = []
  const notices = []
  const response = await fetchRetryingBusy('/scans/s/http-transactions', undefined, {
    fetchImpl: async () => answers.shift(), sleep: async (ms) => { waits.push(ms) }, onBusy: (s) => notices.push(s),
  })
  assert.equal(response.status, 200)
  assert.deepEqual(waits, [2000, 3000])
  assert.deepEqual(notices, [2, 3, null])
})

test('it gives up after a few attempts and returns the refusal to show', async () => {
  let calls = 0
  const response = await fetchRetryingBusy('/x', undefined, {
    fetchImpl: async () => { calls += 1; return reply(503, '1') }, sleep: async () => {},
  })
  assert.equal(response.status, 503)
  assert.equal(calls, BUSY_RETRY_ATTEMPTS)
})

test('other failures are returned at once', async () => {
  let calls = 0
  const response = await fetchRetryingBusy('/x', undefined, { fetchImpl: async () => { calls += 1; return reply(404, null) } })
  assert.equal(response.status, 404)
  assert.equal(calls, 1)
})

// Heavy reads (dashboard, exposure, inventory facets, exports) are admission-controlled: a full
// group answers 429 with Retry-After, which is waited out exactly like a busy archive's 503.
test('a 429 from heavy-read admission is retried after its Retry-After', async () => {
  assert.ok(BUSY_STATUSES.has(429) && BUSY_STATUSES.has(503))
  const answers = [reply(429, '5'), reply(200, null)]
  const waits = []
  const response = await fetchRetryingBusy('/dashboard', undefined, {
    fetchImpl: async () => answers.shift(), sleep: async (ms) => { waits.push(ms) },
  })
  assert.equal(response.status, 200)
  assert.deepEqual(waits, [5000])
})

// 2.11: a heavy read answered 503 "Database is not ready" kept retrying for ~15 s, so the
// Exposure page never showed the failure. Only a busy answer (429, or 503 with Retry-After) is
// repeated, and a heavy page read waits at most HEAVY_READ_MAX_WAIT_SECONDS in total.
test('a bare 503 is "unavailable", not busy: returned at once with its message intact', async () => {
  assert.equal(isBusyAnswer(reply(503, null)), false)
  assert.equal(isBusyAnswer(reply(503, '')), false)
  assert.equal(isBusyAnswer(reply(503, '5')), true)
  assert.equal(isBusyAnswer(reply(429, null)), true)
  let calls = 0
  const waits = []
  const response = await fetchHeavyRead('/exposure/services', undefined, {
    fetchImpl: async () => { calls += 1; return reply(503, null) }, sleep: async (ms) => { waits.push(ms) },
  })
  assert.equal(response.status, 503)
  assert.equal(calls, 1)
  assert.deepEqual(waits, [])
})

test('a heavy read stops waiting at its total budget and hands back the refusal', async () => {
  assert.ok(HEAVY_READ_MAX_WAIT_SECONDS > 0 && HEAVY_READ_MAX_WAIT_SECONDS < 10)
  const waits = []
  let calls = 0
  const response = await fetchHeavyRead('/dashboard', undefined, {
    fetchImpl: async () => { calls += 1; return reply(429, '5') }, sleep: async (ms) => { waits.push(ms) },
  })
  assert.equal(response.status, 429)
  assert.deepEqual(waits, [5000], 'one 5 s wait fits; a second would pass the budget')
  assert.equal(calls, 2)
  assert.ok(waits.reduce((sum, ms) => sum + ms, 0) <= HEAVY_READ_MAX_WAIT_SECONDS * 1000)

  // A wait longer than the whole budget is not started at all.
  let longCalls = 0
  const long = await fetchHeavyRead('/dashboard', undefined, {
    fetchImpl: async () => { longCalls += 1; return reply(503, '30') }, sleep: async () => { throw new Error('must not wait') },
  })
  assert.equal(long.status, 503)
  assert.equal(longCalls, 1)
})

test('an export (no budget) still waits out a busy 503 with Retry-After', async () => {
  const answers = [reply(503, '10'), reply(503, '10'), reply(200, null)]
  const waits = []
  const response = await fetchRetryingBusy('/hunts/h/record', undefined, {
    fetchImpl: async () => answers.shift(), sleep: async (ms) => { waits.push(ms) },
  })
  assert.equal(response.status, 200)
  assert.deepEqual(waits, [10000, 10000])
})

test('a caller that aborts stops waiting at once', async () => {
  const controller = new AbortController()
  const started = Date.now()
  const pending = fetchRetryingBusy('/x', { signal: controller.signal }, { fetchImpl: async () => reply(429, '20') })
  setTimeout(() => controller.abort(), 20)
  await assert.rejects(pending, (error) => error.name === 'AbortError')
  assert.ok(Date.now() - started < 2000)
})
