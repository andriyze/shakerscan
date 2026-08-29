import assert from 'node:assert/strict'
import test from 'node:test'

import { assuranceBand, assuranceGapLabels, scanAssurance } from './assurance.mjs'

test('bands describe coverage, not risk', () => {
  assert.equal(assuranceBand(100).band, 'strong')
  assert.equal(assuranceBand(85).band, 'strong')
  assert.equal(assuranceBand(70).band, 'adequate')
  assert.equal(assuranceBand(50).band, 'limited')
  assert.equal(assuranceBand(1).band, 'weak')
  assert.equal(assuranceBand(0).band, 'none')
})

test('a missing score is absent, not zero', () => {
  // Zero means "we examined nothing", which is a real claim. An older scan with no value
  // recorded must not make that claim on the scan's behalf.
  assert.equal(assuranceBand(undefined), null)
  assert.equal(scanAssurance({}), null)
  assert.equal(scanAssurance(null), null)
})

test('the scan row is preferred over the report body', () => {
  const scan = { assurance_score: 90, result: { assurance_score: 10 } }
  assert.equal(scanAssurance(scan).score, 90)
})

test('a report-only score is still read for scans stored before the column existed', () => {
  assert.equal(scanAssurance({ result: { assurance_score: 42 } }).score, 42)
  assert.equal(scanAssurance({ result: { result: { assurance_score: 42 } } }).score, 42)
})

test('gaps are rendered as readable phrases', () => {
  assert.deepEqual(
    assuranceGapLabels(['authenticated_coverage', 'candidates_attempted']),
    ['only anonymous traffic', 'planned candidates were not attempted'],
  )
  assert.deepEqual(assuranceGapLabels(['something_new']), ['something new'])
  assert.deepEqual(assuranceGapLabels(undefined), [])
})

test('zero reports that nothing was examined', () => {
  const result = scanAssurance({ assurance_score: 0, result: { assurance_gaps: ['no_examination_recorded'] } })
  assert.equal(result.band, 'none')
  assert.deepEqual(result.gaps, ['no examination recorded'])
})
