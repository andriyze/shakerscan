import { expect, test } from '@playwright/test'

import { mockPageApi } from './mock-page-api'

// Browser contract fixture: one completed scan and its target posture, as the API answers them.
// Synthetic: nothing is stored and nothing runs.
const SCAN = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaa0010'
const TARGET = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbb0010'
const SHA256 = '7d014389784591926cd325f346dbea20a17e81513ccb74c6c63e5d2e3687f9de'
const DS = 'key tag 2371, algorithm 13, digest type 2, digest 2CDA41A2F000036A2539D4386CE231A0ECA14092386B4CB5B2AEF3B7BD2AC78C'
const SOA = 'primary ns1.fixture.example, mailbox dns.fixture.example, serial 2419478529, refresh 10000, retry 2400, expire 604800, minimum 1800'

const certificate = {
  subject: 'shop.fixture.example', issuer: 'CN=Fixture CA,O=Fixture Trust,C=US',
  not_before: '2026-10-24T04:03:18+00:00', not_after: '2027-01-22T04:03:17+00:00', days_remaining: 72,
  key_algo: 'ECPublicKey', key_size: 256, sig_algo: 'sha384', signature_hash: 'sha384',
  signature_algorithm: '1.2.840.10045.4.3.3', sans: ['shop.fixture.example'], fingerprints: { sha256: SHA256 },
}

test('POSTURE-001 the posture tab names the signature once, shows DNS answers as fields and the certificate in one place', async ({ page }) => {
  await mockPageApi(page, {
    'GET /health': () => ({ status: 'healthy', scanner_version: 'fixture' }),
    [`GET /scans/${SCAN}`]: () => ({
      id: SCAN, target_id: TARGET, target_url: 'https://shop.fixture.example', status: 'completed', scan_type: 'standard',
      created_at: '2026-09-15T00:00:00Z', completed_at: '2026-09-15T00:01:00Z', options: {},
      result: {
        result: { risk_score: 90, risk_grade: 'A', assurance_score: 80, assurance_band: 'adequate', grade_reliable: true },
        findings: [],
        tls: { certificate },
        dns: { a: ['192.0.2.10'], dnssec: { status: 'unsigned' } },
        infrastructure: {
          canonical_host: 'shop.fixture.example',
          dns: { nameservers: ['ns1.fixture.example'], soa: { primary_nameserver: 'ns1.fixture.example' } },
          certificate: { subject: 'shop.fixture.example', issuer: certificate.issuer, not_after: certificate.not_after, sans: certificate.sans, fingerprints: certificate.fingerprints },
        },
      },
    }),
    [`GET /targets/${TARGET}/posture`]: () => ({
      schema_version: 'target-posture/v1', target_id: TARGET,
      sections: {
        http_headers: null,
        tls: { scan_id: SCAN, observed_at: '2026-09-15T00:01:00Z', payload: {
          certificate: { subject: 'shop.fixture.example', issuer: certificate.issuer, not_after: certificate.not_after, key_algorithm: null, key_bits: 256, signature_algorithm: '1.2.840.10045.4.3.3', san_count: 1, self_signed: false, expired: false },
          protocols: [], cipher_suites: {}, weak: [], ocsp_stapled: null, grade: null, sources: [],
        } },
        dns: { scan_id: SCAN, observed_at: '2026-09-15T00:01:00Z', payload: {
          records: { host_a: ['192.0.2.10'], root_ds: [DS], root_soa: [SOA] },
          dnssec: 'unsigned', dmarc_present: false, mta_sts_enabled: false, tls_rpt_present: false, caa_present: false,
        } },
        network: null,
      },
    }),
  })
  await page.goto(`/scans/${SCAN}?tab=posture`, { waitUntil: 'domcontentloaded' })
  const panel = page.locator('main')
  await expect(panel.getByRole('heading', { name: 'TLS/SSL Configuration' })).toBeVisible()

  // One name for the signature algorithm in the summary and in the TLS section; no bare OID, no bare hash.
  await expect(panel.getByText('ECDSA with SHA-384', { exact: true })).toHaveCount(2)
  await expect(panel.getByText('1.2.840.10045.4.3.3')).toHaveCount(0)
  await expect(panel.getByText('sha384', { exact: true })).toHaveCount(0)

  // Structured DNS answers are read in full as named fields.
  const posture = panel.getByTestId('target-posture')
  await expect(posture.getByText(DS, { exact: true })).toBeVisible()
  await expect(posture.getByText(SOA, { exact: true })).toBeVisible()
  await expect(posture.getByText(/\{'|'\}|': /)).toHaveCount(0)
  expect(await posture.getByText(DS, { exact: true }).evaluate((node) => node.scrollWidth <= node.clientWidth + 1)).toBe(true)

  // The certificate is shown in full once (TLS section), not a second time under infrastructure.
  await expect(panel.getByRole('heading', { name: 'Target infrastructure' })).toBeVisible()
  await expect(panel.getByRole('heading', { name: 'DNS topology' })).toBeVisible()
  await expect(panel.getByRole('heading', { name: 'Certificate identity' })).toHaveCount(0)
  await expect(panel.getByText(SHA256, { exact: true })).toHaveCount(1)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true)
})

test('POSTURE-002 without a TLS section the infrastructure block still shows the certificate it knows', async ({ page }) => {
  await mockPageApi(page, {
    'GET /health': () => ({ status: 'healthy', scanner_version: 'fixture' }),
    [`GET /scans/${SCAN}`]: () => ({
      id: SCAN, target_id: TARGET, target_url: 'https://shop.fixture.example', status: 'completed', scan_type: 'standard',
      created_at: '2026-09-15T00:00:00Z', completed_at: '2026-09-15T00:01:00Z', options: {},
      result: {
        result: { risk_score: 90, risk_grade: 'A' }, findings: [],
        infrastructure: {
          canonical_host: 'shop.fixture.example', dns: { nameservers: ['ns1.fixture.example'] },
          certificate: { subject: 'shop.fixture.example', issuer: certificate.issuer, not_after: certificate.not_after, sans: certificate.sans },
        },
      },
    }),
    [`GET /targets/${TARGET}/posture`]: () => ({ schema_version: 'target-posture/v1', target_id: TARGET, sections: { http_headers: null, tls: null, dns: null, network: null } }),
  })
  await page.goto(`/scans/${SCAN}?tab=posture`, { waitUntil: 'domcontentloaded' })
  await expect(page.locator('main').getByRole('heading', { name: 'Certificate identity' })).toBeVisible()
  await expect(page.locator('main').getByRole('heading', { name: 'TLS/SSL Configuration' })).toHaveCount(0)
})
