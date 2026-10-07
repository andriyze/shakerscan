import assert from 'node:assert/strict'
import test from 'node:test'

import { ANALYST_VERDICTS, statusForVerdict, verdictChangeMessage, verdictOptionLabel } from './analystVerdict.ts'

const verdict = (value) => ANALYST_VERDICTS.find((item) => item.value === value)

test('a verdict changes the status only where the two would contradict', () => {
  assert.equal(statusForVerdict('false_positive', 'true_positive'), 'active')
  assert.equal(statusForVerdict('resolved', 'true_positive'), 'resolved')
  assert.equal(statusForVerdict('accepted_risk', 'retest_needed'), 'accepted_risk')
  assert.equal(statusForVerdict('active', 'duplicate'), 'false_positive')
  assert.equal(statusForVerdict('active', 'accepted_risk'), 'accepted_risk')
  // Clearing the verdict never touches the status.
  assert.equal(statusForVerdict('false_positive', null), 'false_positive')
})

test('the option names the status change before it is chosen', () => {
  assert.equal(
    verdictOptionLabel('false_positive', verdict('true_positive')),
    'True positive (status becomes Active)',
  )
  assert.equal(verdictOptionLabel('active', verdict('true_positive')), 'True positive')
})

test('the confirmation reports what the server stored, including a status change', () => {
  assert.equal(
    verdictChangeMessage({ analyst_verdict: 'true_positive', status: 'active', previous_status: 'false_positive' }),
    'Analyst verdict set to true positive; status changed from False positive to Active',
  )
  assert.equal(
    verdictChangeMessage({ analyst_verdict: null, status: 'active', previous_status: 'active' }),
    'Analyst verdict cleared',
  )
})
