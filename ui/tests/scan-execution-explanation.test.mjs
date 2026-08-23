import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const detail = fs.readFileSync(path.join(root, 'src/app/scans/[id]/page.tsx'), 'utf8')

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
