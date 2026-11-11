import assert from 'node:assert/strict'
import test from 'node:test'

import { releaseProfileReason } from './releaseProfile.mjs'

test('the release profile says what selected it', () => {
  assert.equal(releaseProfileReason({ policy_profile: 'production', policy_profile_basis: 'target_environment', target_environment: 'production' }),
    "from the target's environment")
  assert.equal(releaseProfileReason({ policy_profile: 'staging', policy_profile_basis: 'scan' }), 'set for this run')
  assert.equal(releaseProfileReason({ policy_profile: 'staging', policy_profile_basis: 'default', target_environment: 'lab' }),
    'default: no profile is defined for the target\'s environment "lab"')
  assert.equal(releaseProfileReason({ policy_profile: 'staging', policy_profile_basis: 'default' }),
    'default: the run names no environment')
})

test('a decision that does not say what selected its profile gets no reason', () => {
  assert.equal(releaseProfileReason({ policy_profile: 'staging' }), null)
  assert.equal(releaseProfileReason(null), null)
})
