import assert from 'node:assert/strict'
import test from 'node:test'

import { boundaryBaseFromTarget, boundaryCandidateIds, boundaryScanMessage, savedArtifactMatchesSource } from './aiBoundaryPresentation.ts'

test('saved fixture base omits execution fragments and credentials', () => {
  const identity = { path: '/identity', subject_field: 'subject', tenant_field: 'tenant' }
  const metadata = {
    boundary_contract: {
      version: 1, name: 'agent', owner: { role: 'owner' }, attacker: { role: 'attacker' },
      identity, resource: { path: '/records/{{resource_id}}' }, response_path: 'answer',
      action: { prompt: 'refund' }, credential: { secret: 'must-not-copy' },
    },
  }
  assert.deepEqual(boundaryBaseFromTarget(metadata), {
    version: 1, name: 'agent', owner: { role: 'owner' }, attacker: { role: 'attacker' },
    identity, resource: { path: '/records/{{resource_id}}' }, response_path: 'answer',
  })
  assert.equal(boundaryBaseFromTarget({ boundary_contract: { version: 1 } }), null)
})

test('candidate choices combine run summary and action receipts without duplicates', () => {
  assert.deepEqual(boundaryCandidateIds({
    outcome_summary: { candidate_ids: ['candidate-a', 'candidate-b'] },
    actions: [{ result: { reference_ids: { candidate_ids: ['candidate-b', 'candidate-c'] } } }],
  }), ['candidate-a', 'candidate-b', 'candidate-c'])
})

test('queued and failed scans do not appear ready for regression export', () => {
  assert.match(boundaryScanMessage('queued'), /still queued or running/)
  assert.match(boundaryScanMessage('failed'), /Review its result/)
  assert.match(boundaryScanMessage('completed'), /ready for regression export/)
})

test('a pasted artifact must match the source-bound server reconstruction', () => {
  const source = { artifact_sha256: 'sha256:one', ai_target_id: 'target-a', source_scan_id: 'scan-a' }
  assert.equal(savedArtifactMatchesSource(source, { ...source }), true)
  assert.equal(savedArtifactMatchesSource(source, { ...source, artifact_sha256: 'sha256:tampered' }), false)
  assert.equal(savedArtifactMatchesSource(source, { ...source, ai_target_id: 'target-b' }), false)
})
