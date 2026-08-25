import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const detail = fs.readFileSync(path.join(root, 'src/app/scans/[id]/page.tsx'), 'utf8')
const experiment = fs.readFileSync(path.join(root, 'src/app/deep-hunt/experiment/page.tsx'), 'utf8')

test('scan detail explains stages, placement, budgets, evidence, and grade reliability', () => {
  assert.match(detail, /function ExecutionPlanCard/)
  assert.match(detail, /What this scan ran/)
  assert.match(detail, /Same local \/ fleet contract/)
  assert.match(detail, /Grade is provisional/)
  assert.match(detail, /Reserved:/)
  assert.match(detail, /Used:/)
  assert.match(detail, /Evidence observations:/)
  assert.match(detail, /Open execution record/)
})

test('execution explanation remains visible while running and after terminal outcomes', () => {
  assert.equal((detail.match(/<ExecutionPlanCard scan=\{scan\} \/>/g) || []).length, 4)
  assert.match(detail, /complete_with_gaps/)
})

test('direct shard pages identify the parent as the authoritative Scan', () => {
  assert.match(detail, /function ShardContextBanner/)
  assert.match(detail, /Parallel work unit · shard/)
  assert.match(detail, /This page is one child execution, not the final Scan verdict/)
  assert.match(detail, /Open parent Scan/)
  assert.match(detail, /isShard \? 'Shard failed' : 'Scan failed'/)
  assert.match(detail, /Review parent Scan/)
})

test('terminal shard rollups never render stale queued or running phases', () => {
  assert.match(detail, /const terminal = \['completed', 'failed', 'cancelled'\]\.includes\(shardStatus\)/)
  assert.match(detail, /const staleTerminalPhases = new Set\(\['pending', 'queued', 'running'\]\)/)
  assert.match(detail, /<span>\{phaseLabel\}<\/span>/)
})

test('bounded experiment timeout has an accessible name', () => {
  assert.match(experiment, /id="experiment-timeout-label"/)
  assert.match(experiment, /aria-labelledby="experiment-timeout-label"/)
})
