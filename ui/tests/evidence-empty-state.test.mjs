import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const page = fs.readFileSync(path.join(root, 'src/app/evidence/page.tsx'), 'utf8')

test('an empty autonomous-evidence list does not claim that no evidence exists', () => {
  // Soak N14: the page said "No evidence yet" while 200 scan evidence objects were stored; the
  // list holds autonomous-test evidence instances only.
  assert.doesNotMatch(page, /message="No evidence yet"/)
  assert.match(page, /message="No autonomous test evidence yet"/)
  assert.match(page, /Scan findings keep their evidence on each finding/)
})
