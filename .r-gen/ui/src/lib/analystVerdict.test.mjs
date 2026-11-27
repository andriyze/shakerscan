import assert from 'node:assert/strict'
import test from 'node:test'

import { ANALYST_VERDICTS, statusForVerdict, verdictChangeMessage, verdictOptionLabel, verdictRequestStatus } from './analystVerdict.ts'

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

test('a verdict that keeps the status sends none, so a status changed elsewhere is not reverted', () => {
  assert.equal(verdictRequestStatus('active', null), undefined)
  assert.equal(verdictRequestStatus('resolved', 'true_positive'), undefined)
  assert.equal(verdictRequestStatus('false_positive', 'duplicate'), undefined)
  // A change the verdict makes is sent, and named by the option beforehand.
  assert.equal(verdictRequestStatus('false_positive', 'true_positive'), 'active')
  assert.equal(verdictRequestStatus('active', 'accepted_risk'), 'accepted_risk')
})

test('the confirmation names a status changed since the page loaded', () => {
  assert.equal(
    verdictChangeMessage({ analyst_verdict: null, status: 'false_positive', previous_status: 'false_positive' }, 'active'),
    'Analyst verdict cleared; status is False positive, changed since this page loaded',
  )
  assert.equal(
    verdictChangeMessage({ analyst_verdict: null, status: 'active', previous_status: 'active' }, 'active'),
    'Analyst verdict cleared',
  )
})
