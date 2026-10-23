import { expect, test, type Page } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

const TARGET = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const REF = 'secret://12345678-1234-1234-1234-123456789abc'

async function mockFinding(page: Page, id: string, finding: Record<string, unknown>) {
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, route => route.fulfill({ json: { items: [], findings: [], total: 0 } }))
  await page.route(`${MOCK_API_ORIGIN}/findings/${id}`, route => route.fulfill({ json: {
    id, status: 'active', target_id: TARGET, target_url: 'https://app.fixture.invalid',
    first_seen_at: '2026-10-15T00:00:00Z', last_seen_at: '2026-10-16T00:00:00Z', ...finding,
  } }))
}

test('certificate mismatch leads with the names, a reproduce command and why it is medium', async ({ page }) => {
  const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
  let external = 0
  page.on('request', request => { if (request.url().includes('onerror') || request.url().endsWith('/x')) external++ })
  await mockFinding(page, id, {
    title: 'TLS certificate hostname mismatch', severity: 'high', tool: 'tls.inspect', proof_state: 'verified', verified: true,
    url: 'https://app.fixture.invalid:8444',
    evidence: { check: 'tls_certificate_hostname_mismatch', certificate: { dns_names: ['other.fixture.invalid'] } },
    detail: {
      schema: 'finding-detail/v1', class: 'tls.certificate_hostname_mismatch', class_label: 'Certificate hostname mismatch',
      summary: 'https://app.fixture.invalid:8444 presented a certificate for other.fixture.invalid, which does not include app.fixture.invalid.',
      where: [{ label: 'Origin', value: 'https://app.fixture.invalid:8444', mono: true }],
      observed: [{ label: 'Certificate names', value: '<img src=x onerror=alert(1)>', mono: true }],
      expected: ['A subjectAltName entry that matches app.fixture.invalid.'],
      context: ['The chain itself is trusted; only the name is wrong.'],
      confidence: { level: 'confirmed', reason: 'Read directly from the TLS handshake.' },
      reproduce: { command: "openssl s_client -connect 10.0.0.5:8444 -servername app.fixture.invalid </dev/null" },
      verify: { command: 'openssl s_client -verify_return_error', expect: 'Verify return code: 0 (ok)' },
      fix: ['Issue a certificate whose subjectAltName includes app.fixture.invalid.'],
      severity: { severity: 'high', reason: 'Browsers refuse a certificate issued for another name. Users see an error.', source: 'current_rule',
        current_rule: { severity: 'medium', reason: 'Browsers refuse it.' }, policy: 'Stored findings keep their severity until the next Scan.' },
    },
    related_findings: [{ id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2', title: 'TLS certificate chain is not trusted', severity: 'medium', relation: 'Same certificate' }],
  })
  await page.goto(`/findings/${id}`)
  await expect(page.getByTestId('finding-brief-summary')).toContainText('other.fixture.invalid')
  await expect(page.getByTestId('finding-why-severity')).toContainText('Browsers refuse a certificate issued for another name.')
  await expect(page.getByText('<img src=x onerror=alert(1)>', { exact: true })).toBeVisible()
  await expect(page.getByTestId('finding-brief-reproduce')).toContainText('-servername app.fixture.invalid')
  await expect(page.getByText('the current rule rates this medium', { exact: false })).toBeVisible()
  await expect(page.getByTestId('finding-fix-specific')).toContainText('subjectAltName includes app.fixture.invalid')
  await expect(page.getByTestId('finding-fix-verify')).toContainText('Verify return code: 0 (ok)')
  await expect(page.getByRole('link', { name: 'TLS certificate chain is not trusted' })).toHaveAttribute('href', /aaaaaaa2/)
  expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false)
  expect(external).toBe(0)
  await page.screenshot({ path: `test-results/finding-brief-tls-${test.info().project.name}.png`, fullPage: true })
})

test('exposed secrets show field names and stored references, never values', async ({ page }) => {
  const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3'
  await mockFinding(page, id, {
    title: 'Sensitive exposure: environment secret file', severity: 'high', tool: 'shakerscan_exposure_probe', proof_state: 'verified',
    url: 'http://app.fixture.invalid/.env', evidence: { exposure_class: 'environment_secret_file' },
    detail: {
      schema: 'finding-detail/v1', class: 'exposure.environment_secret_file', class_label: 'Environment file with secrets',
      summary: 'http://app.fixture.invalid/.env served an environment file to an anonymous request (HTTP 200). It contained 2 secret values: AWS_ACCESS_KEY_ID, DB_PASSWORD.',
      secrets: [{ field: 'AWS_ACCESS_KEY_ID', category: 'aws access key', length: 20, ref: REF }, { field: 'DB_PASSWORD', category: 'password', length: 9 }],
      secret_refs: [REF], excerpt: { label: 'Response excerpt (masked by the scanner)', text: '[environment_secret_file detected - content withheld]' },
      reproduce: { command: "curl -sS -o /dev/null -w '%{http_code}' http://app.fixture.invalid/.env", note: 'Prints only status, type and size, never the content.' },
      fix: ['Rotate every credential named below.'], confidence: { level: 'confirmed', reason: 'Content signature matched.' },
      severity: { severity: 'high', reason: 'Secret material is exposed.', source: 'producer' },
    },
  })
  await page.goto(`/findings/${id}`)
  await expect(page.getByText('AWS_ACCESS_KEY_ID', { exact: true })).toBeVisible()
  await expect(page.getByRole('link', { name: REF })).toHaveAttribute('href', `/targets/${TARGET}/asset#discovered-secrets`)
  await expect(page.getByText('values never stored or shown', { exact: false })).toBeVisible()
  await expect(page.getByText('The scanner stored no structured evidence', { exact: false })).toHaveCount(0)
  expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false)
  await page.screenshot({ path: `test-results/finding-brief-exposure-${test.info().project.name}.png`, fullPage: true })
})

test('a finding without a brief keeps the existing page', async ({ page }) => {
  const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4'
  await mockFinding(page, id, { title: 'Legacy finding', severity: 'low', tool: 'legacy', evidence: {} })
  await page.goto(`/findings/${id}`)
  await expect(page.getByRole('heading', { name: 'Legacy finding', exact: true })).toBeVisible()
  await expect(page.getByTestId('finding-brief')).toHaveCount(0)
  await expect(page.getByTestId('finding-why-severity')).toHaveCount(0)
})

test('a proven candidate-titled finding reads as proven, masks redacted values and keeps the verdict select in its card', async ({ page }) => {
  const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa5'
  await page.setViewportSize({ width: 1440, height: 900 })
  await mockFinding(page, id, {
    title: 'Potential SQL injection', severity: 'high', tool: 'sqlmap', proof_state: 'verified', verified: true,
    is_verified: true, url: 'https://shop.fixture.invalid/rest/products/search?q=%3Credacted%3E',
    evidence: { url: 'https://shop.fixture.invalid/rest/products/search?q=%3Credacted%3E', param: 'q' },
    retest_supported: false, retest_unsupported_reason: 'no_prover',
  })
  await page.goto(`/findings/${id}`)
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('SQL injection')
  await expect(page.getByText('<redacted>', { exact: false })).toHaveCount(0)
  await expect(page.getByText('/rest/products/search?q=•••', { exact: true })).toBeVisible()
  await expect(page.locator('a[title="Open in new tab"]').first()).toHaveAttribute('href', 'https://shop.fixture.invalid/rest/products/search?q=')
  // A proven finding without a replay says its proof stands, not that it needs a new Scan.
  await expect(page.getByText('has no single-request retest', { exact: false })).toHaveCount(0)
  await expect(page.getByText('the scan-time proof above still stands', { exact: false })).toBeVisible()
  const select = page.getByLabel('Analyst verdict')
  const card = page.locator('#triage')
  const [selectBox, cardBox] = [await select.boundingBox(), await card.boundingBox()]
  expect(selectBox && cardBox && selectBox.x + selectBox.width <= cardBox.x + cardBox.width).toBe(true)
})
