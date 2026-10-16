import { expect, test, type Page } from '@playwright/test'
import fixture from './fixtures/service-intelligence.json'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

async function mockServices(page: Page, fail = false) {
  const writes: string[] = []
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    if (!['GET', 'OPTIONS'].includes(request.method())) writes.push(url.pathname)
    if (url.pathname === '/exposure/services') {
      // 500, not 503: a 503/429 is a busy answer the page retries (busyRetry.mjs) before failing.
      if (fail) return route.fulfill({ status: 500, json: { detail: 'Database is not ready' } })
      if (url.searchParams.get('search')) return route.fulfill({ json: { ...fixture, targets: [], total_targets: 0 } })
      return route.fulfill({ json: fixture })
    }
    if (url.pathname === '/domains') return route.fulfill({ json: { domains: ['example.test'] } })
    return route.fulfill({ json: { status: 'healthy', workers: [], targets: [], devices: [], total: 0 } })
  })
  return writes
}

test('service evidence, candidates and activities are separate and never execute on navigation', async ({ page }) => {
  const writes = await mockServices(page)
  await page.goto('/exposure')
  await expect(page.getByRole('heading', { name: 'Exposure', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Inspect tcp/443 on Fixture app' }).click()
  const details = page.getByTestId('service-details')
  await expect(details).toContainText('Observation relationship—not a proven attack path')
  await details.getByRole('tab', { name: 'Weaknesses' }).click()
  await expect(details.getByRole('link', { name: 'CVE-2017-17562', exact: true })).toBeVisible()
  await expect(details).toContainText('Candidate')
  await details.getByRole('tab', { name: 'Activities' }).click()
  await expect(details).toContainText('Assess common passwords')
  await expect(details).toContainText('Not implemented')
  const href = await details.getByRole('link', { name: 'Prepare investigation in Hunt' }).getAttribute('href')
  expect(href).toContain('/hunt?target=')
  expect(href).not.toContain('active_testing=true')
  await details.getByRole('tab', { name: 'Evidence / history' }).click()
  await expect(details).toContainText('test-runner')
  await expect(details).toContainText('SHA-256:')
  expect(writes).toEqual([])
  expect(await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth)).toBe(false)
})

test('search and browser history preserve the Services lens without stale details', async ({ page }) => {
  await mockServices(page)
  await page.goto('/exposure')
  await page.getByRole('button', { name: 'Inspect tcp/443 on Fixture app' }).click()
  await page.getByRole('textbox', { name: 'Search service targets' }).fill('missing')
  await page.getByRole('button', { name: 'Search', exact: true }).click()
  await expect(page).toHaveURL(/service_query=missing/)
  await expect(page.getByTestId('service-details')).toHaveCount(0)
  await expect(page.getByText('No targets on this page', { exact: true })).toBeVisible()
  await page.goBack()
  await expect(page.getByTestId('service-details')).toBeVisible()
})

test('source failure remains visible, not a clean empty inventory', async ({ page }) => {
  await mockServices(page, true)
  await page.goto('/exposure')
  await expect(page.getByText('Database is not ready', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: /Retry/i })).toBeVisible()
  await expect(page.getByText('No targets on this page', { exact: true })).toHaveCount(0)
})

test('an old lens link lands on the service view; the removed views are gone', async ({ page }) => {
  await mockServices(page)
  for (const lens of ['triage', 'map', 'paths', 'services']) {
    await page.goto(`/exposure?lens=${lens}`)
    await expect(page.getByRole('button', { name: 'Inspect tcp/443 on Fixture app' })).toBeVisible()
    await expect(page.getByRole('tab', { name: /Triage|Map|Attack paths/ })).toHaveCount(0)
  }
})

test('a candidate shows known exploitation, likelihood and the checks that exist; inconclusive listeners fold away', async ({ page }) => {
  await mockServices(page)
  await page.goto('/exposure')
  // The UDP listener with no answer is folded by default and can be shown.
  await expect(page.getByRole('button', { name: 'Inspect udp/161 on Fixture app' })).toHaveCount(0)
  await page.getByRole('button', { name: 'show 1 inconclusive' }).click()
  await expect(page.getByRole('button', { name: 'Inspect udp/161 on Fixture app' })).toBeVisible()
  await expect(page.getByText('1 known exploited')).toBeVisible()
  await page.getByRole('button', { name: 'Inspect tcp/443 on Fixture app' }).click()
  const details = page.getByTestId('service-details')
  await details.getByRole('tab', { name: 'Weaknesses' }).click()
  await expect(details).toContainText('Known exploited (CISA KEV, added 2022-03-25) · used in ransomware')
  await expect(details).toContainText('EPSS 94.3% (top 0.1%)')
  await expect(details).toContainText('CVSS 9.8')
  await expect(details).toContainText('they run only as part of an authorized Scan')
})

test('verify runs the named check as an ordinary Scan only after the person confirms', async ({ page }) => {
  const writes = await mockServices(page)
  const posted: unknown[] = []
  await page.route(`${MOCK_API_ORIGIN}/scans`, async (route) => {
    if (route.request().method() !== 'POST') return route.fallback()
    posted.push(route.request().postDataJSON())
    return route.fulfill({ json: { scan_id: '99999999-9999-4999-8999-999999999999', status: 'queued' } })
  })
  await page.goto('/exposure')
  // One row per listener, with its severity and the check that exists.
  await expect(page.getByTestId('listener-row')).toHaveCount(1)
  await expect(page.getByText('1 with a check')).toBeVisible()
  await page.getByRole('button', { name: 'Inspect tcp/443 on Fixture app' }).click()
  const details = page.getByTestId('service-details')
  await details.getByRole('tab', { name: 'Weaknesses' }).click()
  const verification = details.getByTestId('candidate-verification')
  await expect(verification).toContainText('Check available')
  await verification.getByRole('button', { name: 'Verify with this check' }).click()
  await expect(verification).toContainText('runs only cve-2017-17562 against https://app.example.test')
  expect(posted).toEqual([])
  await verification.getByRole('button', { name: 'Start verify Scan' }).click()
  await expect(verification.getByRole('status')).toContainText('Verify Scan queued')
  expect(posted).toEqual([{
    target: 'https://app.example.test', budget_profile: 'fast', verify_templates: ['cve-2017-17562'],
    policy: { active_testing: true, preset: 'custom', include_families: ['nuclei_active'] },
  }])
  expect(writes).toEqual([])
})
