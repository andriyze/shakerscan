import assert from 'node:assert/strict'
import test from 'node:test'

import { canonicalFindingProofVerified } from './findingProof.ts'

test('canonical proof requires the authoritative boolean and matching state', () => {
  assert.equal(canonicalFindingProofVerified({ is_verified: true, proof_state: 'verified' }), true)
  assert.equal(canonicalFindingProofVerified({ is_verified: true, proof_state: 'suspected' }), false)
  assert.equal(canonicalFindingProofVerified({ is_verified: false, proof_state: 'verified' }), false)
  assert.equal(canonicalFindingProofVerified({ proof_state: 'verified' }), false)
})
