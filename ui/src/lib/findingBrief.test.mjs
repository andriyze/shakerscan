import assert from 'node:assert/strict'
import test from 'node:test'
import { parseFindingBrief, parseRelatedFindings, secretLink, severityLine } from './findingBrief.ts'

const REF = 'secret://12345678-1234-1234-1234-123456789abc'

test('a brief is parsed only for its schema and keeps every section bounded', () => {
  assert.equal(parseFindingBrief({ class: 'tls.x' }), null)
  assert.equal(parseFindingBrief('nope'), null)
  const brief = parseFindingBrief({
    schema: 'finding-detail/v1', class: 'exposure.environment_secret_file', class_label: 'Environment file with secrets',
    summary: 'x'.repeat(5000), where: [{ label: 'URL', value: 'http://a.invalid/.env', mono: true }, { label: '', value: 'dropped' }],
    secrets: [{ field: 'DB_PASSWORD', category: 'password', length: 9, ref: REF }, { field: 'X', ref: 'javascript:alert(1)' }],
    secret_refs: [REF, 'secret://not-a-uuid'], references: ['https://ok.invalid', 'javascript:alert(1)'],
    cves: [{ id: 'CVE-2021-41773', nvd: 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773', known_exploited: { date_added: '2021-11-03', ransomware: true }, epss: { score: 0.97 } }, { id: 'not-a-cve' }],
    reproduce: { command: 'curl -sS http://a.invalid/.env', expect: '200' }, verify: { expect: 'no command' },
    severity: { severity: 'high', reason: 'Anyone can download it. More text.', current_rule: { severity: 'medium', reason: 'r' } },
    confidence: { level: 'confirmed', reason: 'signature' },
  })
  assert.ok(brief)
  assert.equal(brief.summary.length, 1500)
  assert.deepEqual(brief.where, [{ label: 'URL', value: 'http://a.invalid/.env', mono: true }])
  assert.equal(brief.secrets[0].ref, REF)
  assert.equal(brief.secrets[1].ref, '')
  assert.deepEqual(brief.secretRefs, [REF])
  assert.deepEqual(brief.references, ['https://ok.invalid'])
  assert.equal(brief.cves.length, 1)
  assert.equal(brief.cves[0].kev?.ransomware, true)
  assert.equal(brief.verify, null)
  assert.equal(brief.severity?.currentRule?.severity, 'medium')
  assert.equal(severityLine(brief), 'Anyone can download it.')
})

test('secret links point at the target inventory, never at a raw value', () => {
  assert.equal(secretLink('t-1', REF), '/targets/t-1/asset#discovered-secrets')
  assert.equal(secretLink(undefined, REF), '')
  assert.equal(secretLink('t-1', 'secret://x'), '')
})

test('related findings require an id and a title', () => {
  const rows = parseRelatedFindings([
    { id: '00000000-0000-4000-8000-000000000001', title: 'Same cert', severity: 'medium', relation: 'Same certificate' },
    { id: '../../admin', title: 'bad id' }, { id: '00000000-0000-4000-8000-000000000002' },
  ])
  assert.deepEqual(rows.map(row => row.title), ['Same cert'])
})

test('redacted query values are masked for display and emptied for copy, other values kept', async () => {
  const { maskedUrl, displayTitle } = await import('./findingBrief.ts')
  const result = maskedUrl('https://shop.invalid/rest/products/search?q=%3Credacted%3E&page=2')
  assert.equal(result.masked, true)
  assert.equal(result.display, 'https://shop.invalid/rest/products/search?q=•••&page=2')
  assert.equal(result.usable, 'https://shop.invalid/rest/products/search?q=&page=2')
  assert.ok(!result.display.includes('redacted') && !result.usable.includes('redacted'))
  assert.deepEqual(maskedUrl('https://a.invalid/x?y=1'), { display: 'https://a.invalid/x?y=1', usable: 'https://a.invalid/x?y=1', masked: false })
  assert.equal(maskedUrl('not a url').usable, 'not a url')
  assert.equal(displayTitle('Potential SQL injection', true), 'SQL injection')
  assert.equal(displayTitle('Potential SQL injection', false), 'Potential SQL injection')
  assert.equal(displayTitle('Verified SQL injection', true), 'Verified SQL injection')
})
