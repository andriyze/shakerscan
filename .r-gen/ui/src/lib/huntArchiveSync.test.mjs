import assert from 'node:assert/strict'
import test from 'node:test'

import { ARCHIVE_MAX_ROWS, planPageMerge, resyncWindows } from './huntArchiveSync.mjs'

const rows = (...ids) => ids.map((id) => ({ id }))

test('new rows at the tail are appended', () => {
  const plan = planPageMerge({ held: rows('a', 'b'), page: rows('c', 'd'), limit: 250, total: 4 })
  assert.deepEqual(plan, { action: 'append', rows: rows('c', 'd') })
})

test('a row inserted mid-list is detected: the total grew more than the tail returned', () => {
  // Held a,b; the server now has a,x,b,c (x archived late). Offset 2 returns b,c: b is known.
  assert.deepEqual(planPageMerge({ held: rows('a', 'b'), page: rows('b', 'c'), limit: 250, total: 4 }), { action: 'resync' })
  // Held a,b; the server has a,x,b: offset 2 returns only b.
  assert.deepEqual(planPageMerge({ held: rows('a', 'b'), page: rows('b'), limit: 250, total: 3 }), { action: 'resync' })
})

test('a tail read of only known ids resyncs instead of appending nothing forever', () => {
  assert.deepEqual(planPageMerge({ held: rows('a', 'b', 'c'), page: rows('c'), limit: 250, total: 4 }), { action: 'resync' })
})

test('a short tail page that does not account for the total resyncs', () => {
  // Total says 5 but held 2 + page 2 = 4: one row went in before the offset (ids all new by chance).
  assert.deepEqual(planPageMerge({ held: rows('a', 'b'), page: rows('c', 'd'), limit: 250, total: 5 }), { action: 'resync' })
})

test('a full page with more to come appends', () => {
  const page = Array.from({ length: 3 }, (_, i) => ({ id: `n${i}` }))
  assert.equal(planPageMerge({ held: rows('a'), page, limit: 3, total: 100 }).action, 'append')
})

test('a purge (total below the rows held) reloads the first page', () => {
  assert.deepEqual(planPageMerge({ held: rows('a', 'b', 'c'), page: [], limit: 250, total: 1 }), { action: 'reload' })
})

test('Load more with no progress resyncs; an empty page at the true end is a no-op append', () => {
  assert.deepEqual(planPageMerge({ held: rows('a', 'b'), page: [], limit: 250, total: 3 }), { action: 'resync' })
  assert.deepEqual(planPageMerge({ held: rows('a', 'b'), page: [], limit: 250, total: 2 }), { action: 'append', rows: [] })
})

test('the resync re-reads what was held, at least one page, within the server ceiling', () => {
  assert.deepEqual(resyncWindows(10), [{ offset: 0, limit: 250 }])
  assert.deepEqual(resyncWindows(600), [{ offset: 0, limit: 600 }])
  assert.deepEqual(resyncWindows(ARCHIVE_MAX_ROWS + 5), [{ offset: 0, limit: ARCHIVE_MAX_ROWS }, { offset: ARCHIVE_MAX_ROWS, limit: 5 }])
})
