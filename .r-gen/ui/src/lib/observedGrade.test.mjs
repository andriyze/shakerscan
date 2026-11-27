import assert from 'node:assert/strict'
import test from 'node:test'

import { deviceScorePresentation } from './deviceScanPresentation.mjs'
import { observedGrade } from './observedGrade.mjs'

test('a list shows the letter the Scan page shows and says provisional in words', () => {
  assert.deepEqual(observedGrade('F*'), { letter: 'F', provisional: true })
  assert.deepEqual(observedGrade('A'), { letter: 'A', provisional: false })
  assert.deepEqual(observedGrade(' B+* '), { letter: 'B+', provisional: true })
  assert.equal(observedGrade(''), null)
  assert.equal(observedGrade(null), null)
  assert.equal(observedGrade('*'), null)
  // The Scan page's own presentation of the same stored grade.
  const page = deviceScorePresentation({ run_kind: 'web_dast', grade: 'F*', score: 0, result: { result: { grade: 'F*', score: 0 } } })
  assert.equal(observedGrade('F*').letter, page.grade)
})
