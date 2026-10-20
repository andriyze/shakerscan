import assert from 'node:assert/strict'
import test from 'node:test'
import { findingDetailEvidence, hasDetailEvidence } from './findingDetailEvidence.ts'

test('certificate and verifier facts are readable without changing proof or severity', () => {
  const input = { requested_host: 'app.fixture.invalid', trust: { result: 'untrusted', failure: 'issuer_not_found', error_code: 20 },
    certificate: { issuer: 'CN=Fixture CA', dns_names: ['other.fixture.invalid'], not_after: '2026-01-01', public_key_bits: 2048 },
    chain: [{ subject: 'CN=other.fixture.invalid', issuer: 'CN=Fixture CA' }],
    severity_basis: { schema: 'severity-basis/v1', reason: 'The issuer was not trusted.' },
    verified: false, arbitrary_private_value: 'must-not-render', extracted_results: ['secret-not-for-this-view'] }
  const before = JSON.stringify(input)
  const result = findingDetailEvidence(input)
  assert.equal(hasDetailEvidence(result), true)
  assert.equal(result.severityReason, 'The issuer was not trusted.')
  const facts = result.groups.flatMap(group => group.facts)
  assert.ok(facts.some(fact => fact.label === 'Verifier code' && fact.value === '20'))
  assert.ok(facts.some(fact => fact.label === 'Issuer' && fact.value === 'CN=Fixture CA'))
  assert.ok(facts.some(fact => fact.label === 'DNS names (up to 25)' && fact.value === 'other.fixture.invalid'))
  assert.ok(!JSON.stringify(result).includes('must-not-render'))
  assert.ok(!JSON.stringify(result).includes('secret-not-for-this-view'))
  assert.equal(JSON.stringify(input), before)
})

test('legacy records stay honest and hostile or oversized data is bounded', () => {
  for (const value of [null, [], 1, '{invalid', { unknown: 'value' }]) {
    assert.equal(hasDetailEvidence(findingDetailEvidence(value)), false)
  }
  const result = findingDetailEvidence(JSON.stringify({
    certificate: { subject: '<img src=x onerror=alert(1)>', dns_names: Array(100).fill('x'.repeat(1000)) },
    chain: Array(100).fill({ issuer: 'issuer' }), severity_basis: { schema: 'unknown', reason: 'ignored' },
  }))
  assert.equal(result.groups.filter(group => group.title.startsWith('Presented chain')).length, 6)
  assert.equal(result.severityReason, null)
  assert.ok(JSON.stringify(result).length < 12000)
  assert.equal(result.groups[0].facts[0].value, '<img src=x onerror=alert(1)>')
})

test('finite template metadata displays as metadata even without certificate evidence', () => {
  const result = findingDetailEvidence({ template_id: 'fixture', cve_ids: ['CVE-2026-12345'], cvss_score: 7.5, epss_score: Infinity })
  assert.deepEqual(result.groups.map(group => group.title), ['Template metadata'])
  assert.ok(result.groups[0].facts.some(fact => fact.label === 'Template CVSS' && fact.value === '7.5'))
  assert.ok(!result.groups[0].facts.some(fact => fact.label === 'EPSS'))
})

test('a weak-cipher finding shows the negotiated suite apart from the weak suites it accepts', () => {
  // Unit fixture shaped like a stored weak-cipher finding: the weak suite the finding is about is
  // `cipher`; the suite a normal handshake negotiates is `negotiated_cipher`.
  const facts = findingDetailEvidence({
    protocol: 'TLSv1.2', cipher: 'ECDHE-RSA-RC4-SHA', negotiated_cipher: 'ECDHE-RSA-AES256-GCM-SHA384',
    weak_ciphers_supported: ['ECDHE-RSA-RC4-SHA', 'ECDHE-RSA-DES-CBC3-SHA'], supported_protocols: ['TLSv1', 'TLSv1.2'],
  }).groups.flatMap(group => group.facts)
  const value = label => facts.find(fact => fact.label === label)?.value
  assert.equal(value('Negotiated cipher'), 'ECDHE-RSA-AES256-GCM-SHA384')
  assert.equal(value('Weak suites accepted'), 'ECDHE-RSA-RC4-SHA, ECDHE-RSA-DES-CBC3-SHA')
  assert.equal(value('Protocols observed'), 'TLSv1, TLSv1.2')
  // Any other TLS finding keeps its negotiated suite under `cipher`.
  const other = findingDetailEvidence({ cipher: 'TLS_AES_256_GCM_SHA384' }).groups.flatMap(group => group.facts)
  assert.ok(other.some(fact => fact.label === 'Negotiated cipher' && fact.value === 'TLS_AES_256_GCM_SHA384'))
})
