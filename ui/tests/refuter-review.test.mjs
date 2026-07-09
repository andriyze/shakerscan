import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'
import test from 'node:test'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const out = mkdtempSync(path.join(tmpdir(), 'refuter-review-'))
execFileSync('npx', ['tsc', 'src/lib/refuterReview.ts', '--module', 'commonjs', '--target', 'es2022', '--outDir', out, '--skipLibCheck'], { cwd: root })
const require = createRequire(import.meta.url)
const { buildRefuterReviewPlanView, buildRefuterAnnotationPayload } = require(path.join(out, 'refuterReview.js'))
test.after(() => rmSync(out, { recursive: true, force: true }))

test('normalizes counterevidence questions, steps, refs, and verdict paths', () => {
  const view = buildRefuterReviewPlanView({ automation_plan: {
    steps: [{ id: 'retest', label: 'Retest', command: 'finding.retest', mode: 'planned_not_executed' }],
    counterevidence_bundle: {
      review_questions: ['Does it reproduce?'],
      benign_explanations_to_test: ['Stale object'],
      required_evidence_refs: ['verification_id_after_replay'],
      verdict_paths: { supported: 'Reproduced', refuted: 'Benign response' },
    },
  } })
  assert.equal(view.available, true)
  assert.equal(view.steps[0].command, 'finding.retest')
  assert.deepEqual(view.reviewQuestions, ['Does it reproduce?'])
  assert.deepEqual(view.requiredEvidenceRefs, ['verification_id_after_replay'])
  assert.deepEqual(view.verdictPaths.map((item) => item.verdict), ['supported', 'refuted'])
})

test('keeps analyst notes signal-only unless human verdict mode is explicit', () => {
  const review = { id: 'review-1', subject_type: 'finding', finding_id: 'finding-1' }
  const signal = buildRefuterAnnotationPayload(review, {
    mode: 'signal', signal: 'weaken', observedBehavior: 'non_reproducible', notes: 'Stale object',
    evidenceObjectIds: ['evidence-1'], toolReceiptIds: [], createdBy: 'analyst',
  })
  assert.equal(signal.verdict_basis, 'signal_only')
  assert.equal(signal.refuter_verdict, undefined)
  assert.equal(signal.refuter_signal, 'weaken')

  const verdict = buildRefuterAnnotationPayload(review, {
    mode: 'human_verdict', signal: 'question', verdict: 'refuted', observedBehavior: 'benign_explanation', notes: '',
    evidenceObjectIds: [], toolReceiptIds: ['receipt-1'], createdBy: 'analyst',
  })
  assert.equal(verdict.verdict_basis, 'human_approved_review')
  assert.equal(verdict.refuter_verdict, 'refuted')
  assert.equal(verdict.refuter_signal, 'refute')
})
