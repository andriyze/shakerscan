import assert from 'node:assert/strict'
import test from 'node:test'

import { findingObservation, hasObservation, hostOf, humanizeToken, pathOf, verificationSource } from './findingObservation.ts'

test('an exposure proof reads as what was exposed, how it answered, and the redacted excerpt', () => {
  const observation = findingObservation(JSON.stringify({
    exposure_class: 'private_key_material',
    response_status: 200,
    content_type: 'application/octet-stream',
    discovered_via: 'seed_path',
    evidence_type: 'deterministic_response_signature',
    matched_signature: '-----BEGIN (?:RSA )?PRIVATE KEY-----',
    redacted_excerpt: '[private_key_material detected — content withheld]',
    response_body_sha256: 'abc',
  }))
  assert.deepEqual(observation.facts.map((fact) => `${fact.label}: ${fact.value}`), [
    'Exposed: Private key material',
    'HTTP status: 200',
    'Content type: application/octet-stream',
    'Found via: Seed path',
    'Evidence: Deterministic response signature',
  ])
  // The excerpt is the server's redacted text verbatim.
  assert.equal(observation.excerpt, '[private_key_material detected — content withheld]')
  assert.deepEqual(observation.signatures, ['-----BEGIN (?:RSA )?PRIVATE KEY-----'])
  assert.equal(hasObservation(observation), true)
})

test('an injection proof shows the parameter, technique, repetitions and control/payload statuses', () => {
  const observation = findingObservation({
    method: 'GET',
    field_path: 'q',
    technique: 'error_based_repeated',
    repetitions: 2,
    database_error_signatures: ['sqlite(?:3)?[ _-]?(?:error|exception)'],
    response_pairs: [{ control_status: 200, payload_status: 500 }, { control_status: 200, payload_status: 500 }],
    evidence: ['SQL error detected (postgresql)'],
    extraction_evidence: ['Found 15 tables', 'SQL error detected (postgresql)'],
  })
  assert.deepEqual(observation.facts.map((fact) => fact.label), ['Technique', 'Method', 'Parameter', 'Confirmed'])
  assert.equal(observation.facts.find((fact) => fact.label === 'Confirmed')?.value, '2 independent repetitions')
  assert.deepEqual(observation.responsePairs, [{ control: '200', payload: '500' }, { control: '200', payload: '500' }])
  // Signals are de-duplicated across the two lists.
  assert.deepEqual(observation.signals, ['SQL error detected (postgresql)', 'Found 15 tables'])
})

test('missing or malformed evidence yields an empty observation', () => {
  for (const value of [null, undefined, '', 'not json', '[1,2]', 42]) {
    const observation = findingObservation(value)
    assert.equal(hasObservation(observation), false, String(value))
  }
})

test('a scan-time verdict is not presented as a replay', () => {
  assert.equal(verificationSource({ retestRuns: 0, latestRetestStatus: null, verificationCount: 0 }), 'scan_time')
  assert.equal(verificationSource({ retestRuns: 0, latestRetestStatus: 'completed', verificationCount: 0 }), 'retest')
  assert.equal(verificationSource({ retestRuns: 2 }), 'retest')
  assert.equal(verificationSource({ retestRuns: 0, verificationCount: 1 }), 'retest')
})

test('locations show the host and the path with query names only', () => {
  assert.equal(hostOf('https://honey.example.test/id_rsa'), 'honey.example.test')
  assert.equal(pathOf('https://app.example.test/search?q=secret&page=2&q=x'), '/search?q&page')
  assert.equal(pathOf('/rest/products/search'), '/rest/products/search')
  assert.equal(hostOf('/relative'), '')
  assert.equal(humanizeToken('error_based_repeated'), 'Error based repeated')
})
