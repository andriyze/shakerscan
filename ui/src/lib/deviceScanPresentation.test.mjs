import assert from 'node:assert/strict'
import test from 'node:test'

import { deviceActivityLogLines, deviceReachabilityServiceSummary, deviceScorePresentation, deviceTargetScorePresentation } from './deviceScanPresentation.mjs'


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


test('device summaries preserve the latest scan provisional state', () => {
  const presentation = deviceTargetScorePresentation({
    last_grade: 'A',
    last_score: 100,
    last_posture_complete: false,
    last_posture_decision: 'needs_review',
    last_reachability: { status: 'online', checked_at: '2026-08-28T00:00:00Z' },
  }, { nowMs: Date.parse('2026-08-29T00:00:00Z') })
  assert.equal(presentation.status, 'provisional')
  assert.equal(presentation.grade, 'A')
  assert.equal(presentation.score, 100)
  assert.match(presentation.note, /not a pass verdict/)
})


test('device summaries withhold a retained A when latest reachability is inconclusive', () => {
  const presentation = deviceTargetScorePresentation({
    last_grade: 'A',
    last_score: 100,
    last_posture_complete: true,
    last_posture_decision: 'allow',
    last_reachability: { status: 'inconclusive', checked_at: '2026-08-29T00:00:00Z' },
  }, { nowMs: Date.parse('2026-08-29T01:00:00Z') })
  assert.equal(presentation.status, 'unavailable')
  assert.equal(presentation.grade, null)
  assert.equal(presentation.score, null)
  assert.match(presentation.note, /not current proof/)
})


test('device summaries qualify stale positive evidence', () => {
  const presentation = deviceTargetScorePresentation({
    last_grade: 'A',
    last_score: 100,
    last_posture_complete: true,
    last_posture_decision: 'allow',
    last_reachability: { status: 'online', checked_at: '2026-08-15T00:00:00Z' },
  }, { nowMs: Date.parse('2026-08-29T00:00:00Z') })
  assert.equal(presentation.status, 'provisional')
  assert.equal(presentation.grade, 'A')
  assert.match(presentation.note, /older than 7 days/)
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


test('non-device detail prefers current-policy result projection over legacy row score', () => {
  assert.deepEqual(deviceScorePresentation({
    run_kind: 'web_dast',
    grade: 'A',
    score: 100,
    result: {
      result: {
        risk_grade: 'B',
        risk_score: 86,
        score_policy: 'risk_and_assurance/v5',
      },
    },
  }), {
    isDevice: false,
    status: 'final',
    grade: 'B',
    score: 86,
    note: null,
  })
})


test('unreliable DAST grade is explicitly provisional and never displayed as A star', () => {
  const presentation = deviceScorePresentation({
    run_kind: 'web_dast',
    grade: 'A*',
    score: 100,
    result: {
      result: { grade: 'A*', score: 100, grade_reliable: false },
      coverage: { status: 'partial', grade_reliability: { reliable: false } },
    },
  })

  assert.equal(presentation.status, 'provisional')
  assert.equal(presentation.grade, 'A')
  assert.equal(presentation.score, 100)
  assert.match(presentation.note, /not a pass verdict/)
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


test('latest device reachability is not confused with retained service history', () => {
  assert.equal(deviceReachabilityServiceSummary({
    serviceAccessible: false,
    retainedServiceCount: 3,
  }), 'latest check found no currently responding TCP service; 3 previously confirmed services retained below')
  assert.equal(deviceReachabilityServiceSummary({
    serviceAccessible: false,
    selectedScan: true,
    retainedServiceCount: 3,
  }), 'this scan found no currently responding TCP service with complete visibility')
  assert.equal(deviceReachabilityServiceSummary({ serviceAccessible: true }), 'at least one service responded')
  assert.equal(deviceReachabilityServiceSummary({ serviceAccessible: null }), 'service accessibility still being assessed')
})
