import assert from 'node:assert/strict'
import test from 'node:test'

import { BUSY_RETRY_ATTEMPTS, busyNotice, fetchRetryingBusy, retryAfterSeconds } from './busyRetry.mjs'

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
