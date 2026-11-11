import { expect, test } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

test('certificate finding explains its evidence and severity on a populated page', async ({ page }) => {
  const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
  const target = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
  let external = 0
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, route => route.fulfill({ json: { items: [], findings: [], total: 0 } }))
  await page.route(`${MOCK_API_ORIGIN}/findings/${id}`, route => route.fulfill({ json: {
    id, title: 'TLS certificate hostname mismatch', severity: 'medium', status: 'active',
    target_id: target, target_url: 'https://app.fixture.invalid', url: 'https://app.fixture.invalid',
    tool: 'tls.inspect', proof_state: 'verified', verified: true, first_seen_at: '2026-10-15T00:00:00Z',
    last_seen_at: '2026-10-15T00:00:00Z', evidence: {
      check: 'tls_certificate_hostname_mismatch', requested_host: 'app.fixture.invalid',
      trust: { result: 'trusted' }, certificate: { subject: '<img src=x onerror=alert(1)>',
        issuer: 'CN=Fixture Issuer', dns_names: ['other.fixture.invalid'],
        not_after: '2026-12-31', public_key_type: 'RSA', public_key_bits: 2048 },
      chain: [{ subject: 'CN=other.fixture.invalid', issuer: 'CN=Fixture Issuer' }],
      severity_basis: { schema: 'severity-basis/v1', reason: 'The certificate names another service.' },
    },
  } }))
  page.on('request', request => { if (request.url().includes('onerror') || request.url().endsWith('/x')) external++ })
  await page.goto(`/findings/${id}`)
  await expect(page.getByRole('heading', { name: 'TLS certificate hostname mismatch', exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Certificate presented' })).toBeVisible()
  await expect(page.getByText('CN=Fixture Issuer', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('other.fixture.invalid', { exact: true })).toBeVisible()
  await expect(page.getByText('<img src=x onerror=alert(1)>', { exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Why this severity' })).toBeVisible()
  await expect(page.getByText('The certificate names another service.', { exact: true })).toBeVisible()
  await expect(page.getByText('The scanner stored no structured evidence', { exact: false })).toHaveCount(0)
  expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false)
  expect(external).toBe(0)
  await page.screenshot({ path: `test-results/finding-detail-${test.info().project.name}.png`, fullPage: true })
})

test('recorded evidence wraps prose between words and still wraps a long unbroken value', async ({ page }) => {
  const id = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
  const description = 'The service port answers the cluster pods interface without authentication, so anyone '
    + 'who can reach it can list every running workload and execute commands inside its containers.'
  const digest = 'f0'.repeat(120)
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, route => route.fulfill({ json: { items: [], findings: [], total: 0 } }))
  await page.route(`${MOCK_API_ORIGIN}/findings/${id}`, route => route.fulfill({ json: {
    id, title: 'Cluster pods interface exposed', severity: 'high', status: 'active',
    target_url: 'https://app.fixture.invalid', url: 'https://app.fixture.invalid/pods', tool: 'nuclei',
    first_seen_at: '2026-10-15T00:00:00Z', last_seen_at: '2026-10-15T00:00:00Z',
    evidence: { template_id: 'fixture-pods-interface', template_description: description, cvss_metrics: digest },
  } }))
  await page.goto(`/findings/${id}`)
  const prose = page.getByText(description, { exact: true })
  await expect(prose).toBeVisible()
  // A word that fits on a line is drawn on one line: no break in the middle of it.
  const brokenWords = await prose.evaluate((element) => {
    const text = element.firstChild as Text
    const broken: string[] = []
    for (const word of (text.textContent || '').matchAll(/\S+/g)) {
      const range = document.createRange()
      range.setStart(text, word.index)
      range.setEnd(text, word.index + word[0].length)
      if (new Set([...range.getClientRects()].map((box) => Math.round(box.top))).size > 1) broken.push(word[0])
    }
    return broken
  })
  expect(brokenWords).toEqual([])
  expect(await prose.evaluate((element) => element.getBoundingClientRect().height
    > 2 * parseFloat(getComputedStyle(element).lineHeight))).toBe(true)

  // A value with nowhere to break still wraps inside its column instead of widening the page.
  const unbroken = page.getByText(digest, { exact: true })
  await expect(unbroken).toBeVisible()
  expect(await unbroken.evaluate((element) => element.scrollWidth <= element.clientWidth
    && element.getBoundingClientRect().height > 2 * parseFloat(getComputedStyle(element).lineHeight))).toBe(true)
  expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false)
})
