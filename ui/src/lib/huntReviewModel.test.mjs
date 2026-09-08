import test from 'node:test'
import assert from 'node:assert/strict'
import { assessmentText, candidateHistoryText, isReviewId } from './huntReviewModel.ts'

test('historical candidates are neither erased nor described as freshly reproduced', () => {
  assert.match(candidateHistoryText('historical_only'), /Earlier lead retained/)
  assert.match(candidateHistoryText('historical_only'), /latest attempt did not reproduce/)
  assert.match(candidateHistoryText('current_attempt'), /not proof/)
})

test('ambiguous and unknown server assessments are not translated into safe or verified', () => {
  assert.match(assessmentText('inconclusive'), /no boundary conclusion/)
  assert.match(assessmentText('potential_violation'), /review required/)
  assert.match(assessmentText('access_denied'), /this tested object/)
  assert.equal(assessmentText('new_server_state'), 'Server assessment: new_server_state')
  assert.equal(assessmentText('constructor'), 'Server assessment: constructor')
  assert.equal(assessmentText(undefined), 'Not examined')
})

test('review URL references reject malformed and path-shaped identifiers', () => {
  assert.equal(isReviewId('00000000-0000-0000-0000-000000000001'), true)
  for (const value of ['', '../capabilities/test', null, {}, 'not-an-id']) assert.equal(isReviewId(value), false)
})
