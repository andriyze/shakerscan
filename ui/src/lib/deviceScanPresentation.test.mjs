import assert from 'node:assert/strict'
import test from 'node:test'

import { deviceActivityLogLines, deviceScorePresentation } from './deviceScanPresentation.mjs'


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


test('device activity becomes readable content-free report logs', () => {
  assert.deepEqual(deviceActivityLogLines({ events: [
    {
      phase: 'tcp_scope',
      progress: 40,
      message: 'Checking common and device-specific TCP ports',
      details: { hidden_command: 'must not be copied' },
    },
    { phase: 'complete', progress: 100, message: 'Device scan completed' },
    { phase: 'ignored', progress: 100, message: '' },
  ] }), [
    '[device] 40% · tcp scope · Checking common and device-specific TCP ports',
    '[device] 100% · complete · Device scan completed',
  ])
})
