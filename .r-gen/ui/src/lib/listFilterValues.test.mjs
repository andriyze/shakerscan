import assert from 'node:assert/strict'
import test from 'node:test'

import { listFilterValues, toggleListFilterValue } from './listFilterValues.ts'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

test('severity pills add and remove values in a fixed order', () => {
  assert.equal(toggleListFilterValue(undefined, 'high', SEVERITIES), 'high')
  assert.equal(toggleListFilterValue('high', 'critical', SEVERITIES), 'critical,high')
  assert.equal(toggleListFilterValue('critical,high', 'critical', SEVERITIES), 'high')
  // Clearing the last value removes the filter from the URL.
  assert.equal(toggleListFilterValue('high', 'high', SEVERITIES), undefined)
})

test('a single value from an older link still reads as one selection', () => {
  assert.deepEqual(listFilterValues('critical'), ['critical'])
  assert.deepEqual(listFilterValues(' critical , high ,'), ['critical', 'high'])
  assert.deepEqual(listFilterValues(undefined), [])
})
