import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const detail = readFileSync(path.join(root, 'src/app/scans/[id]/page.tsx'), 'utf8')
const presentation = readFileSync(path.join(root, 'src/lib/scanDetailPresentation.mjs'), 'utf8')

test('completed scans lead with an evidence-based conclusion instead of a grade', () => {
  assert.match(detail, /Run conclusion/)
  assert.match(detail, /resultPresentation\.headline/)
  assert.match(presentation, /No material vulnerability confirmed in this run/)
  assert.match(presentation, /this is not a clean bill of health/)
})

test('risk, examination strength, and release status are kept distinct', () => {
  assert.match(detail, /Observed risk from this run/)
  assert.match(detail, /This is not an overall safety or release score/)
  assert.match(detail, /Examination strength/)
  assert.match(detail, /Overall release decision/)
  assert.match(detail, /const observedRiskColor = weakAssurance \? 'text-gray-200'/)
  assert.match(detail, /historical scoring policy may exclude posture deductions/)
})

test('result scope and deterministic posture weaknesses are visible', () => {
  assert.match(detail, /Identity coverage/)
  assert.match(detail, /HTTP requests used/)
  assert.match(detail, /Check families run/)
  assert.match(detail, /Baseline posture needs attention/)
  assert.match(detail, /historical score predates posture-aware scoring/)
})
