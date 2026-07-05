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
const outDir = mkdtempSync(path.join(tmpdir(), 'ai-gate-campaign-'))

execFileSync(
  'npx',
  [
    'tsc',
    'src/lib/aiGateCampaign.ts',
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
const { buildAiGateCampaignReview } = require(path.join(outDir, 'aiGateCampaign.js'))

test.after(() => {
  rmSync(outDir, { recursive: true, force: true })
})

test('summarizes AI Gate campaign matrix, skipped reasons, evidence hashes, and replayable findings', () => {
  const review = buildAiGateCampaignReview({
    findings: [
      {
        id: 'finding-1',
        source: 'ai_gate',
        title: 'Cross-tenant RAG leakage',
        severity: 'high',
        evidence: { probe_id: 'rag-cross-tenant', probe_family: 'rag' },
      },
    ],
    ai_gate: {
      target_name: 'Secure RAG',
      target_type: 'rag',
      probe_pack: 'shaker-rag-lite',
      scan_profile: 'standard',
      coverage_matrix: {
        summary: {
          planned: 4,
          executed: 2,
          with_transcripts: 2,
          with_findings: 1,
          errors: 1,
          skipped: 2,
          request_budget: 2,
          stopped_by_rate_limit: false,
        },
        by_family: {
          rag: { planned: 3, executed: 2, with_transcript: 2, with_findings: 1, errors: 0 },
          mcp: { planned: 1, executed: 0, with_transcript: 0, with_findings: 0, errors: 1 },
        },
        skipped: [
          { probe_id: 'rag-stale-canary', family: 'rag', reason: 'request_budget' },
          { probe_id: 'mcp-scope', family: 'mcp', reason: 'request_budget' },
        ],
      },
      execution_plan: {
        semantic_judge: { status: 'completed', reviewed_probe_count: 1 },
        judging_quality_gate: { status: 'judging_completed' },
      },
      evidence_manifest: {
        manifest_hash: 'manifest-hash',
        probe_catalog: { planned_hash: 'planned-hash', executed_hash: 'executed-hash' },
        evidence: { transcripts_hash: 'transcripts-hash', execution_plan_hash: 'plan-hash' },
      },
      usage: { stopped_by_request_budget: true },
      decision: { decision: 'needs_review', environment: 'staging', rationale: 'Review RAG leakage.' },
    },
  })

  assert.equal(review.available, true)
  assert.equal(review.target_name, 'Secure RAG')
  assert.equal(review.planned, 4)
  assert.equal(review.executed, 2)
  assert.equal(review.stopped_by_request_budget, true)
  assert.equal(review.families[0].family, 'rag')
  assert.equal(review.families[0].skipped, 1)
  assert.deepEqual(review.skipped_reasons, [{ reason: 'request_budget', count: 2, families: ['mcp', 'rag'] }])
  assert.equal(review.planned_hash, 'planned-hash')
  assert.equal(review.transcripts_hash, 'transcripts-hash')
  assert.equal(review.semantic_judge_status, 'completed')
  assert.equal(review.findings[0].id, 'finding-1')
  assert.equal(review.findings[0].probe_family, 'rag')
})

test('returns unavailable review for non AI Gate results', () => {
  const review = buildAiGateCampaignReview({ result: { score: 90 } })

  assert.equal(review.available, false)
  assert.equal(review.families.length, 0)
  assert.equal(review.findings.length, 0)
})
