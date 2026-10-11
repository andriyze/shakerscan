import assert from 'node:assert/strict'
import test from 'node:test'

import { authorizationStopNotice, failedScanHeadline, retestAuthorizationStopNotice } from './authorizationStop.ts'

// Fixture data in the shape the worker writes (api/scan/action_authority_guard.py annotate).
const stopped = {
  status: 'partial',
  partial: true,
  stop_reason: 'authorization_withdrawn',
  authority_stop: {
    stop_reason: 'authorization_withdrawn',
    reason_code: 'authorization_revoked',
    observed_at: '2026-10-09T20:00:00+00:00',
    interrupted_actions: ['templates.active'],
    not_run_actions: ['templates.followup', 'verify.xss'],
  },
}

test('a withdrawn authorization yields a banner naming the cause and what did not run', () => {
  const notice = authorizationStopNotice(stopped)
  assert.equal(notice.title, 'Scan stopped: authorization withdrawn')
  assert.match(notice.detail, /authorization was revoked while this Scan was running/)
  assert.match(notice.detail, /2 actions did not run/)
  assert.deepEqual(notice.notRunActions, ['templates.followup', 'verify.xss'])
  assert.deepEqual(notice.interruptedActions, ['templates.active'])
  assert.equal(notice.observedAt, '2026-10-09T20:00:00+00:00')
})

test('expiry and scope reasons are named, and an unknown reason stays generic', () => {
  const expired = { ...stopped, authority_stop: { ...stopped.authority_stop, reason_code: 'authorization_expired' } }
  assert.match(authorizationStopNotice(expired).detail, /approval expired/)
  const scope = { ...stopped, authority_stop: { reason_code: 'scope_invalid' } }
  assert.match(authorizationStopNotice(scope).detail, /deactivated or no longer matched/)
  assert.deepEqual(authorizationStopNotice(scope).notRunActions, [])
  const other = { stop_reason: 'authorization_withdrawn' }
  assert.match(authorizationStopNotice(other).detail, /authorization was withdrawn/)
})

test('no banner for a scan that was not stopped by authorization', () => {
  assert.equal(authorizationStopNotice(undefined), null)
  assert.equal(authorizationStopNotice({ partial: true, status: 'partial' }), null)
  assert.equal(authorizationStopNotice({ stop_reason: 'cancelled' }), null)
})

test('an unverified stop is named as unconfirmed, never as a revoke', () => {
  const notice = authorizationStopNotice({ stop_reason: 'authorization_unverified',
    authority_stop: { stop_reason: 'authorization_unverified', reason_code: 'authorization_unverified' } })
  assert.equal(notice.title, 'Scan stopped: authorization could not be confirmed')
  assert.match(notice.detail, /not found revoked/)
  assert.doesNotMatch(notice.detail, /was revoked/)
})

// The retest row shape GET /retests/finding/{id} returns (api/retest_routes/router.py).
const stoppedRetest = {
  status: 'failed',
  verdict: 'error',
  stop_reason: 'authorization_withdrawn',
  authority_stop: {
    stop_reason: 'authorization_withdrawn',
    reason_code: 'authorization_revoked',
    observed_at: '2026-10-10T10:00:00+00:00',
    interrupted_actions: ['finding.retest'],
    not_run_actions: [],
  },
}

test('a retest stopped by a revoke says so and that no verdict was recorded', () => {
  const notice = retestAuthorizationStopNotice(stoppedRetest)
  assert.equal(notice.title, 'Retest stopped: authorization withdrawn')
  assert.match(notice.detail, /authorization was revoked while this retest was running/)
  assert.match(notice.detail, /No verdict was recorded/)
  assert.doesNotMatch(notice.detail, /coverage is partial/)
  assert.equal(notice.observedAt, '2026-10-10T10:00:00+00:00')
  const unverified = retestAuthorizationStopNotice({ stop_reason: 'authorization_unverified',
    authority_stop: { reason_code: 'authorization_unverified' } })
  assert.equal(unverified.title, 'Retest stopped: authorization could not be confirmed')
  assert.equal(retestAuthorizationStopNotice({ status: 'completed', verdict: 'likely_fixed' }), null)
  assert.equal(retestAuthorizationStopNotice(null), null)
})

test('a failed scan stopped by its authorization says why, not "during the failed phase"', () => {
  const revoked = {
    status: 'failed',
    current_phase: 'failed',
    error_message: 'Scan stopped while it ran: target authorization check returned authorization_revoked',
    result: { scan_metadata: { stop_reason: 'authorization_withdrawn',
      authority_stop: { reason_code: 'authorization_revoked' } } },
  }
  assert.equal(failedScanHeadline(revoked), 'This scan was stopped because the target’s authorization was revoked.')
  assert.doesNotMatch(failedScanHeadline(revoked), /failed phase/)
  // The error text alone (no annotated metadata) is enough.
  const fromError = { current_phase: 'failed',
    error_message: 'Scan stopped before it started: target authorization check returned scope_invalid' }
  assert.match(failedScanHeadline(fromError), /stopped because the target was deactivated/)
  const unverified = { current_phase: 'failed',
    result: { scan_metadata: { stop_reason: 'authorization_unverified' } } }
  assert.match(failedScanHeadline(unverified, 'shard'), /^This shard was stopped because its target’s authorization could not be confirmed/)
})

test('other failed scans name a real phase and never a terminal status', () => {
  assert.equal(failedScanHeadline({ current_phase: 'active_testing' }),
    'This scan stopped during the active testing phase and did not finish.')
  assert.equal(failedScanHeadline({ current_phase: 'failed' }), 'This scan stopped before it finished.')
  assert.equal(failedScanHeadline({ result: { scan_metadata: { terminated_at_phase: 'discovery' } }, current_phase: 'failed' }),
    'This scan stopped during the discovery phase and did not finish.')
  assert.equal(failedScanHeadline(undefined), 'This scan stopped before it finished.')
})

test('a retest refused before it started says so, and names its own scope cause', () => {
  const before = retestAuthorizationStopNotice({ stop_reason: 'authorization_withdrawn',
    authority_stop: { reason_code: 'authorization_revoked', before_start: true } })
  assert.match(before.detail, /revoked before this retest started/)
  const scope = retestAuthorizationStopNotice({ stop_reason: 'authorization_withdrawn',
    authority_stop: { reason_code: 'scope_invalid' } })
  assert.match(scope.detail, /does not cover it or the replayed URL while this retest was running/)
})
