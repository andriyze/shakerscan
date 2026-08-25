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
const outDir = mkdtempSync(path.join(tmpdir(), 'deferred-work-contracts-'))

execFileSync(
  'npx',
  [
    'tsc',
    'src/lib/deferredWorkContracts.ts',
    '--module', 'commonjs',
    '--target', 'es2022',
    '--outDir', outDir,
    '--skipLibCheck',
  ],
  { cwd: uiRoot, stdio: 'pipe' },
)

const require = createRequire(import.meta.url)
const contracts = require(path.join(outDir, 'deferredWorkContracts.js'))

test.after(() => rmSync(outDir, { recursive: true, force: true }))

test('ASM schedule create and edit share one bounded option contract', () => {
  const options = contracts.buildAsmScheduleOptions({
    batchSize: 5000,
    staleDays: -4,
    endpointFilter: 'api',
    family: 'bola',
    exploitDepth: true,
  })
  assert.deepEqual(options, {
    batch_size: 1000,
    stale_days: 0,
    endpoint_filter: 'api',
    check_family: 'bola',
    exploit_depth: true,
  })
  assert.deepEqual(contracts.readAsmScheduleOptions(options), {
    batchSize: 1000,
    staleDays: 0,
    endpointFilter: 'api',
    family: 'bola',
    exploitDepth: true,
  })

  const mutation = contracts.buildScheduleMutation({
    name: 'BOLA wave',
    frequency: 'weekly',
    dayOfWeek: 3,
    timeOfDay: '02:00',
    kind: 'asm_improve',
    scanOptions: options,
  })
  assert.equal(mutation.schedule_kind, 'asm_improve')
  assert.equal(mutation.scan_type, undefined)
  assert.equal(mutation.day_of_week, 3)
  assert.deepEqual(mutation.scan_options, options)
})

test('skip reasons never render object coercions and stay bounded', () => {
  const normalized = contracts.normalizeSkipReasons([
    { module: 'nuclei', reason: 'request_budget_exhausted' },
    'browser',
    {},
  ], 2)

  assert.deepEqual(normalized.items, [
    { key: 'nuclei-0', label: 'nuclei', reason: 'request_budget_exhausted' },
    { key: 'browser-1', label: 'browser', reason: null },
  ])
  assert.equal(normalized.remaining, 1)
})

test('remediation links allow internal routes and reject unsafe destinations', () => {
  assert.equal(contracts.safeRemediationHref('/settings/policy-profiles'), '/settings/policy-profiles')
  assert.equal(contracts.safeRemediationHref('//evil.test/path'), null)
  assert.equal(contracts.safeRemediationHref('javascript:alert(1)'), null)
  assert.equal(contracts.safeRemediationHref('https://external.test'), null)
})

test('parent and family coverage preserve attempted, completed, and proof facts', () => {
  assert.deepEqual(contracts.normalizeParentCoverage({
    assigned_endpoints: 10,
    attempted_endpoints: 7,
    active_endpoints_selected: 8,
    telemetry_shards: 2,
    shards_with_contribution: 3,
  }), {
    assigned: 10,
    attempted: 7,
    selected: 8,
    tested: 7,
    telemetryShards: 2,
    contributingShards: 3,
    complete: false,
  })

  assert.deepEqual(contracts.normalizeFamilyCoverage({
    attempted: 9,
    attempts: 99,
    completed: 5,
    proved: 2,
    blocked: 1,
    cancelled: 1,
    partial: 2,
    failed: 0,
  }), {
    attempted: 9,
    completed: 5,
    proved: 2,
    blocked: 1,
    cancelled: 1,
    partial: 2,
    failed: 0,
    label: '2 proved / 5 completed / 9 attempted',
  })
})
