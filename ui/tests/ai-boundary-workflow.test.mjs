import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'
import test from 'node:test'

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const outDir = mkdtempSync(path.join(tmpdir(), 'ai-boundary-workflow-'))
execFileSync('npx', [
  'tsc', 'src/lib/aiBoundary.ts', 'src/lib/apiConfig.ts', '--module', 'commonjs',
  '--target', 'es2022', '--outDir', outDir, '--skipLibCheck', '--ignoreConfig',
], { cwd: uiRoot, stdio: 'pipe' })
const require = createRequire(import.meta.url)
const boundary = require(path.join(outDir, 'aiBoundary.js'))
test.after(() => rmSync(outDir, { recursive: true, force: true }))

test('candidate compilation and verification use bound IDs and explicit operator facts', async () => {
  const original = global.fetch
  const calls = []
  global.fetch = async (url, options) => {
    calls.push({ url, options })
    return { ok: true, json: async () => ({ status: 'ready', scan_id: 'scan-1' }) }
  }
  try {
    const principal = { role: 'attacker', subject: 'user-b', tenant: 'tenant-b', resource_id: 'doc-b' }
    await boundary.compileBoundaryCandidate('hunt/1', 'candidate/2', {
      owner: { ...principal, role: 'owner' }, attacker: principal,
      expected_rule: 'Cross-tenant read forbidden',
    })
    await boundary.queueBoundaryVerification('target/3', { status: 'ready' }, { version: 1 }, 'staging', 'standard')
    assert.match(calls[0].url, /hunts\/hunt%2F1\/candidates\/candidate%2F2\/boundary-proposal$/)
    assert.equal(calls[0].options.method, 'POST')
    assert.equal(JSON.parse(calls[0].options.body).expected_rule, 'Cross-tenant read forbidden')
    assert.match(calls[1].url, /ai\/targets\/target%2F3\/boundary\/verify$/)
    assert.deepEqual(JSON.parse(calls[1].options.body), {
      proposal: { status: 'ready' }, boundary_base: { version: 1 },
      environment: 'staging', scan_profile: 'standard',
    })
  } finally { global.fetch = original }
})

test('regression export and evaluation carry artifact unchanged for server validation', async () => {
  const original = global.fetch
  const calls = []
  global.fetch = async (url, options) => {
    calls.push({ url, body: JSON.parse(options.body) })
    return { ok: true, json: async () => ({ status: 'pass' }) }
  }
  try {
    const artifact = { schema_version: 'ai-boundary-regression/v1', artifact_sha256: 'sha256:abc' }
    await boundary.exportBoundaryRegression('target-a', 'source-scan', { status: 'ready' }, { version: 1 })
    await boundary.evaluateBoundaryRegression('target-a', artifact, 'later-scan')
    assert.equal(calls[0].body.source_scan_id, 'source-scan')
    assert.equal(calls[0].body.boundary_base.version, 1)
    assert.deepEqual(calls[1].body, { artifact, scan_id: 'later-scan' })
  } finally { global.fetch = original }
})

test('server refusal is surfaced instead of presenting a queued scan', async () => {
  const original = global.fetch
  global.fetch = async () => ({ ok: false, status: 422, json: async () => ({ detail: 'authorization required' }) })
  try {
    await assert.rejects(
      boundary.queueBoundaryVerification('target-a', {}, {}, 'preview', 'standard'),
      /authorization required/,
    )
  } finally { global.fetch = original }
})
