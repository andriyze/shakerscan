import assert from 'node:assert/strict'
import test from 'node:test'
import { countActiveSecondaryFilters, triageOutcomeMessage } from '../src/app/findings/triage.ts'

test('triage toast names the verdict the button promised and reports missing ids', () => {
  assert.equal(triageOutcomeMessage(1, 'resolved'), '1 finding marked resolved')
  assert.equal(triageOutcomeMessage(3, 'false_positive'), '3 findings marked false positive')
  assert.equal(triageOutcomeMessage(2, 'accepted_risk', 0), '2 findings marked accepted risk')
  assert.equal(triageOutcomeMessage(4, 'active', 1), '4 findings reactivated · 1 no longer exists')
  assert.equal(triageOutcomeMessage(4, 'active', 2), '4 findings reactivated · 2 no longer exist')
})

test('the Filters badge counts only filters that narrow the list', () => {
  assert.equal(countActiveSecondaryFilters(['', '', 0, '', '', false]), 0)
  assert.equal(countActiveSecondaryFilters(['dast', '', 30, '', undefined, true]), 3)
  assert.equal(countActiveSecondaryFilters([null, 'example.com', 0, 'exploited', 'deterministic', false]), 3)
})
