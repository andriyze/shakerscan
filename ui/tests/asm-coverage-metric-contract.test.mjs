import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const page = fs.readFileSync(path.join(root, 'src/app/asm/page.tsx'), 'utf8')
const api = fs.readFileSync(path.join(root, 'src/lib/api.ts'), 'utf8')

test('ASM surfaces use one explicit route/variant/attempt coverage contract', () => {
  assert.match(api, /schema_version: 'asm_coverage_metrics\/v2'/)
  assert.match(api, /canonical_routes: number/)
  assert.match(api, /route_variants: number/)
  assert.match(api, /variants_ever_completed: number/)
  assert.match(api, /proof_bearing_variants: number/)
  assert.match(page, /Completed \/ Route variants/)
  assert.match(page, /Synthetic variants are never called endpoints/)
  assert.match(page, /snapshot \{coverage\.metric_contract\?\.snapshot_at/)
  assert.match(page, /proved \/ completed \/ attempted/)
})
