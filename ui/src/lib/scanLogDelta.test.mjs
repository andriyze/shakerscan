import assert from 'node:assert/strict'
import test from 'node:test'
import { emptyScanLogState, mergeScanLogReply } from './scanLogDelta.mjs'

const reply = (lines, next, extras = {}) => ({
  lines, next_seq: next, first_seq: next - lines.length + 1, seq_supported: true, ...extras,
})

test('numbered logs append only new lines and idle polls keep the current window', () => {
  let state = mergeScanLogReply(emptyScanLogState(), reply(['a', 'b'], 2))
  state = mergeScanLogReply(state, reply(['c'], 3))
  assert.deepEqual(state, { lines: ['a', 'b', 'c'], nextSeq: 3, partial: false })
  assert.equal(mergeScanLogReply(state, reply([], 3)), state)
  assert.equal(mergeScanLogReply(state, reply(['b', 'c'], 3)), state)
})

test('a missed window and a counter reset replace the tail without joining unrelated lines', () => {
  const old = mergeScanLogReply(emptyScanLogState(), reply(['old'], 10))
  const truncated = mergeScanLogReply(old, reply(['new'], 20, { truncated: true }))
  assert.deepEqual(truncated, { lines: ['new'], nextSeq: 20, partial: true })
  const reset = mergeScanLogReply(truncated, reply(['fresh'], 1, { truncated: true }))
  assert.deepEqual(reset, { lines: ['fresh'], nextSeq: 1, partial: true })
  assert.equal(mergeScanLogReply(truncated, reply(['late'], 5)), truncated)
})

test('the browser keeps a bounded window and records known omitted history', () => {
  let state = mergeScanLogReply(emptyScanLogState(), reply(['a', 'b'], 2), 2)
  state = mergeScanLogReply(state, reply(['c', 'd'], 4), 2)
  assert.deepEqual(state, { lines: ['c', 'd'], nextSeq: 4, partial: true })
  const gap = mergeScanLogReply(state, reply(['gap'], 10), 2)
  assert.deepEqual(gap, { lines: ['gap'], nextSeq: 10, partial: true })
})

test('legacy or aggregated feeds replace the window and clear a previous cursor', () => {
  const old = mergeScanLogReply(emptyScanLogState(), reply(['old'], 2))
  const legacy = mergeScanLogReply(old, { lines: ['parent child a', 'parent child b'] })
  assert.deepEqual(legacy, { lines: ['parent child a', 'parent child b'], nextSeq: null, partial: false })
  assert.deepEqual(mergeScanLogReply(legacy, reply(['new writer'], 1)), {
    lines: ['new writer'], nextSeq: 1, partial: false,
  })
})

test('malformed sequence metadata is an error, never a successful empty log', () => {
  for (const body of [null, {}, { lines: [null] }, reply(['bad'], -1),
    { ...reply(['bad'], 2), first_seq: 1 }, reply([], Number.MAX_SAFE_INTEGER + 1)]) {
    assert.throws(() => mergeScanLogReply(emptyScanLogState(), body), /malformed/)
  }
})
