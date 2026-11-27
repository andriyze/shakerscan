import assert from 'node:assert/strict'
import test from 'node:test'

import { reconcileReviewSelection } from './huntReviewModel.ts'

test('history replacement removes a selection from a discarded page', () => {
  assert.equal(reconcileReviewSelection('later-page', ['first-page']), 'first-page')
})
test('empty history clears selection', () => {
  assert.equal(reconcileReviewSelection('old', []), '')
})
test('refresh retains an existing visible selection', () => {
  assert.equal(reconcileReviewSelection('second', ['first', 'second']), 'second')
})
test('appending history preserves a later-page selection', () => {
  assert.equal(reconcileReviewSelection('second', ['first', 'second', 'third']), 'second')
})
