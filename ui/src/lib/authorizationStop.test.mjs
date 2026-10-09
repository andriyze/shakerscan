import assert from 'node:assert/strict'
import test from 'node:test'

import { authorizationStopNotice } from './authorizationStop.ts'

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
