import assert from 'node:assert/strict'
import test from 'node:test'

import { backoffDelay, createPoller } from './poller.mjs'

/** Manual timers and visibility: the test decides when time passes and whether the tab shows. */
function harness() {
  let now = 0
  let nextId = 1
  const pending = new Map()
  const listeners = new Set()
  const page = { hidden: false }
  const timers = {
    set(fn, ms) { const id = nextId++; pending.set(id, { fn, at: now + ms }); return id },
    clear(id) { pending.delete(id) },
  }
  const visibility = {
    hidden: () => page.hidden,
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener) },
  }
  const flush = () => new Promise((resolve) => setImmediate(resolve))
  async function advance(ms) {
    const until = now + ms
    for (;;) {
      const due = [...pending.entries()].filter(([, timer]) => timer.at <= until).sort((a, b) => a[1].at - b[1].at)[0]
      if (!due) break
      pending.delete(due[0])
      now = due[1].at
      due[1].fn()
      await flush()
    }
    now = until
    await flush()
  }
  async function setHidden(hidden) {
    page.hidden = hidden
    for (const listener of [...listeners]) listener()
    await flush()
  }
  const nextDelay = () => {
    const at = [...pending.values()].map((timer) => timer.at - now).sort((a, b) => a - b)[0]
    return at === undefined ? null : at
  }
  return { timers, visibility, advance, setHidden, flush, nextDelay, listeners, pending }
}

test('ticks at the live interval and never overlaps a slow tick', async () => {
  const h = harness()
  let calls = 0
  let release
  const poller = createPoller({
    intervalMs: 5000, timers: h.timers, visibility: h.visibility,
    run: () => { calls += 1; return calls === 2 ? new Promise((resolve) => { release = resolve }) : Promise.resolve() },
  })
  poller.start()
  await h.flush()
  assert.equal(calls, 1)
  await h.advance(5000)
  assert.equal(calls, 2)
  poller.trigger()
  await h.advance(20000)
  assert.equal(calls, 2, 'the second tick is still running: nothing overlaps it')
  release()
  await h.flush()
  assert.equal(calls, 2)
  await h.advance(0)
  assert.equal(calls, 3, 'the trigger queued behind it runs right after')
  poller.stop()
})

test('a hidden tab does not poll; showing it runs the due tick at once', async () => {
  const h = harness()
  let calls = 0
  const poller = createPoller({ intervalMs: 5000, timers: h.timers, visibility: h.visibility, run: async () => { calls += 1 } })
  poller.start()
  await h.flush()
  assert.equal(calls, 1)
  await h.setHidden(true)
  await h.advance(60_000)
  assert.equal(calls, 1, 'no requests while hidden')
  assert.equal(h.nextDelay(), null, 'and no timer spinning either')
  await h.setHidden(false)
  assert.equal(calls, 2, 'visible again: one catch-up tick')
  await h.advance(5000)
  assert.equal(calls, 3)
  poller.stop()
})

test('a tab hidden from the start waits for the first view', async () => {
  const h = harness()
  await h.setHidden(true)
  let calls = 0
  const poller = createPoller({ intervalMs: 5000, timers: h.timers, visibility: h.visibility, run: async () => { calls += 1 } })
  poller.start()
  await h.flush()
  assert.equal(calls, 0)
  await h.setHidden(false)
  assert.equal(calls, 1)
  poller.stop()
})

test('errors back off exponentially, capped, and a success resets the pace', async () => {
  const h = harness()
  const delays = []
  let fail = true
  const poller = createPoller({
    intervalMs: 5000, maxBackoffMs: 30_000, timers: h.timers, visibility: h.visibility,
    run: async () => { if (fail) throw new Error('down') },
    onSchedule: ({ nextDelayMs }) => delays.push(nextDelayMs),
  })
  poller.start()
  await h.flush()
  await h.advance(10_000)
  await h.advance(20_000)
  await h.advance(30_000)
  assert.deepEqual(delays, [10_000, 20_000, 30_000, 30_000])
  fail = false
  await h.advance(30_000)
  assert.equal(delays.at(-1), 5000)
  poller.stop()
})

test('a busy answer waits at least its Retry-After', async () => {
  const h = harness()
  const delays = []
  const poller = createPoller({
    intervalMs: 2000, timers: h.timers, visibility: h.visibility,
    run: async () => { throw Object.assign(new Error('busy'), { status: 429, retryAfter: 25 }) },
    onSchedule: ({ nextDelayMs }) => delays.push(nextDelayMs),
  })
  poller.start()
  await h.flush()
  assert.equal(delays[0], 25_000)
  poller.stop()
  assert.equal(backoffDelay(2000, 3), 16_000)
  assert.equal(backoffDelay(2000, 3, { retryAfterSeconds: 30 }), 30_000)
  assert.equal(backoffDelay(60_000, 5), 120_000)
})

test('polls only while something is live; idle null stops until live again', async () => {
  const h = harness()
  let live = true
  let calls = 0
  const poller = createPoller({
    intervalMs: 3000, idleIntervalMs: null, isLive: () => live, timers: h.timers, visibility: h.visibility,
    run: async () => { calls += 1 },
  })
  poller.start()
  await h.flush()
  live = false
  await h.advance(3000)
  assert.equal(calls, 2, 'this tick saw the scan finish')
  await h.advance(120_000)
  assert.equal(calls, 2, 'nothing live: no polling')
  live = true
  poller.reschedule()
  await h.advance(2999)
  assert.equal(calls, 2)
  await h.advance(1)
  assert.equal(calls, 3, 'live again: back to the live pace without an extra immediate request')
  poller.stop()
})

test('idle pace is slower, not zero, when given', async () => {
  const h = harness()
  let calls = 0
  const poller = createPoller({
    intervalMs: 5000, idleIntervalMs: 60_000, isLive: () => false, timers: h.timers, visibility: h.visibility,
    run: async () => { calls += 1 },
  })
  poller.start()
  await h.flush()
  await h.advance(59_000)
  assert.equal(calls, 1)
  await h.advance(1000)
  assert.equal(calls, 2)
  poller.stop()
})

test('stop aborts the tick in flight and leaves no timer or listener behind', async () => {
  const h = harness()
  let signal
  const errors = []
  const poller = createPoller({
    intervalMs: 5000, timers: h.timers, visibility: h.visibility,
    run: (s) => { signal = s; return new Promise((resolve, reject) => s.addEventListener('abort', () => reject(new Error('aborted')))) },
    onError: (error) => errors.push(error),
  })
  poller.start()
  await h.flush()
  assert.equal(h.listeners.size, 1)
  poller.stop()
  await h.flush()
  assert.equal(signal.aborted, true)
  assert.deepEqual(errors, [], 'an abort is not a failure')
  assert.equal(h.pending.size, 0)
  assert.equal(h.listeners.size, 0)
})

test('a restart is not disturbed by the stopped tick finishing late', async () => {
  const h = harness()
  const releases = []
  let calls = 0
  const poller = createPoller({
    intervalMs: 5000, timers: h.timers, visibility: h.visibility,
    run: () => { calls += 1; return new Promise((resolve) => releases.push(resolve)) },
  })
  poller.start()
  await h.flush()
  poller.stop()
  poller.start()
  await h.flush()
  assert.equal(calls, 2)
  releases[0]()
  await h.flush()
  assert.equal(poller.state().running, true, 'the new tick is still the one running')
  releases[1]()
  await h.flush()
  assert.equal(h.nextDelay(), 5000)
  poller.stop()
})
