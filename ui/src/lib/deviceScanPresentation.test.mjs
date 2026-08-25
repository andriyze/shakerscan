import assert from 'node:assert/strict'
import test from 'node:test'

import { deviceScorePresentation } from './deviceScanPresentation.mjs'


function deviceScan({ reachability = 'online', complete = true, decision = 'allow' } = {}) {
  return {
    run_kind: 'device_posture',
    grade: 'A',
    score: 100,
    result: {
      result: { grade: 'A', score: 100 },
      device_posture: {
        reachability: { status: reachability },
        completeness: { complete },
        decision: { decision },
      },
    },
  }
}


test('complete device posture retains its final score', () => {
  assert.deepEqual(deviceScorePresentation(deviceScan()), {
    isDevice: true,
    status: 'final',
    grade: 'A',
    score: 100,
    note: null,
  })
})


test('incomplete device posture is explicitly provisional', () => {
  const presentation = deviceScorePresentation(deviceScan({ complete: false, decision: 'needs_review' }))
  assert.equal(presentation.status, 'provisional')
  assert.equal(presentation.grade, 'A')
  assert.equal(presentation.score, 100)
  assert.match(presentation.note, /not a pass verdict/)
})


test('unconfirmed device reachability never presents a stored score', () => {
  const presentation = deviceScorePresentation(deviceScan({ reachability: 'inconclusive', complete: false, decision: 'needs_review' }))
  assert.equal(presentation.status, 'unavailable')
  assert.equal(presentation.grade, null)
  assert.equal(presentation.score, null)
  assert.match(presentation.note, /reachability was not confirmed/)
})


test('non-device score presentation is unchanged', () => {
  assert.deepEqual(deviceScorePresentation({ run_kind: 'web_dast', grade: 'B', score: 88 }), {
    isDevice: false,
    status: 'final',
    grade: 'B',
    score: 88,
    note: null,
  })
})
