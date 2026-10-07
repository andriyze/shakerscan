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

test('the current detail projection is preferred over the stored scan row', () => {
  const scan = { assurance_score: 90, result: { assurance_score: 10 } }
  assert.equal(scanAssurance(scan).score, 10)
})

test('a report-only score is still read for scans stored before the column existed', () => {
  assert.equal(scanAssurance({ result: { assurance_score: 42 } }).score, 42)
  assert.equal(scanAssurance({ result: { result: { assurance_score: 42 } } }).score, 42)
})

test('gaps are rendered as readable phrases', () => {
  assert.deepEqual(
    assuranceGapLabels(['authenticated_coverage', 'candidates_attempted', 'examination_breadth']),
    ['only anonymous traffic', 'some planned candidates were not attempted', 'the examination was narrow'],
  )
  assert.deepEqual(assuranceGapLabels(['something_new']), ['something new'])
  assert.deepEqual(assuranceGapLabels(undefined), [])
})

test('zero reports that nothing was examined', () => {
  const result = scanAssurance({ assurance_score: 0, result: { assurance_gaps: ['no_examination_recorded'] } })
  assert.equal(result.band, 'none')
  assert.deepEqual(result.gaps, ['no examination recorded'])
})

test('active verification is named only when no active verifier attempted a candidate', () => {
  // 146b6c03: XSS attempted its candidate and SQLi ran for 22 minutes, yet the Coverage tab
  // read "active verification never ran". The gap now names what it measures.
  assert.deepEqual(assuranceGapLabels(['active_verification_attempted']), ['no active verifier attempted a candidate'])
  assert.ok(!assuranceGapLabels(['active_verification_attempted'])[0].includes('never ran'))
})

test('a run that never examined the application shows no examination strength from planned work', () => {
  // A not-examined run kept 64/100 beside "Not examined". Historical reports still carry it.
  const legacy = scanAssurance({
    assurance_score: 64,
    result: { result: { assurance_score: 64, application_observed: false, risk_assessment_state: 'not_examined', assurance_gaps: ['authenticated_coverage'] } },
  })
  assert.equal(legacy.score, 0)
  assert.equal(legacy.band, 'none')
  assert.equal(legacy.label, 'Application not examined')
  assert.deepEqual(legacy.gaps, ['only anonymous traffic', 'the application was not examined'])
  // A list row carries the projected assessment state beside the stored column.
  const row = scanAssurance({ assurance_score: 64, application_observed: false })
  assert.equal(row.score, 0)
  // An observed application keeps its score.
  assert.equal(scanAssurance({ assurance_score: 64, application_observed: true }).score, 64)
})
