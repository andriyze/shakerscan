import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'
import test from 'node:test'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const uiRoot = path.resolve(__dirname, '..')
const outDir = mkdtempSync(path.join(tmpdir(), 'authz-replay-'))

execFileSync(
  'npx',
  [
    'tsc',
    'src/lib/authzReplay.ts',
    '--module',
    'commonjs',
    '--target',
    'es2022',
    '--outDir',
    outDir,
    '--skipLibCheck',
  ],
  { cwd: uiRoot, stdio: 'pipe' }
)

const require = createRequire(import.meta.url)
const { buildAuthzReplayReview, sessionMatchesTarget } = require(path.join(outDir, 'authzReplay.js'))

test.after(() => {
  rmSync(outDir, { recursive: true, force: true })
})

test('summarizes replay proof and promotion state', () => {
  const review = buildAuthzReplayReview({
    authz_replay_plan: { method: 'GET', path: '/api/orders/{id}' },
    authz_replay: {
      plan: { method: 'GET', path: '/api/orders/{id}' },
      observations: [{}, {}],
      violation_count: 1,
      mismatch_count: 1,
      proof_state: 'replayed_violation_observed',
      proof_bundle: {
        authenticated_principal_count: 2,
        access_granted_count: 1,
        soft_200_denial_count: 0,
        denial_redirect_count: 1,
        differential_observed: true,
      },
    },
    authz_replay_promotion: { finding_ids: ['finding-1'] },
  })

  assert.equal(review.available, true)
  assert.equal(review.path, '/api/orders/{id}')
  assert.equal(review.observationCount, 2)
  assert.equal(review.violationCount, 1)
  assert.equal(review.authenticatedPrincipalCount, 2)
  assert.equal(review.differentialObserved, true)
  assert.deepEqual(review.promotedFindingIds, ['finding-1'])
})

test('matches interactive sessions by origin', () => {
  assert.equal(sessionMatchesTarget('https://app.example.test/login', 'https://app.example.test'), true)
  assert.equal(sessionMatchesTarget('https://other.example.test', 'https://app.example.test'), false)
})
