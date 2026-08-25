import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const api = fs.readFileSync(path.join(root, 'src/lib/api.ts'), 'utf8')
const page = fs.readFileSync(path.join(root, 'src/app/evidence/page.tsx'), 'utf8')

test('evidence browse loads bounded rows and expands one full proof on demand', () => {
  assert.match(page, /summary_only: true/)
  assert.match(page, /getEvidenceInstance\(inst\.id\)/)
  assert.match(api, /searchParams\.set\('summary_only', 'true'\)/)
  assert.match(api, /evidence\/instances\/\$\{encodeURIComponent\(id\)\}/)
})

test('evidence labels both nested family proofs and root proof contracts', () => {
  assert.match(page, /const nested = asObject\(po\.family_proof\)/)
  assert.match(page, /Object\.keys\(nested\)\.length \? nested : po/)
})

test('evidence detail treats canonical deterministic proof contracts as usable proof', () => {
  assert.match(page, /schema_version\) === 'proof-contract\/v2'/)
  assert.match(page, /predicate\.satisfied === true/)
  assert.match(page, /reexecution\.performed === true/)
  assert.match(page, /Boolean\(text\(reexecution\.verifier_build\)\)/)
  assert.match(page, /hasValidProofContract \|\| hasRequestComparisonProof/)
  assert.match(page, /hasValidProofContract \? 'Deterministic proof'/)
  assert.match(page, /!isProofContract \? \(/)
})
