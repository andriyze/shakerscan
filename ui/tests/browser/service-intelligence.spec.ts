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
      if (fail) return route.fulfill({ status: 503, json: { detail: 'Database is not ready' } })
      if (url.searchParams.get('search')) return route.fulfill({ json: { ...fixture, targets: [], total_targets: 0 } })
      return route.fulfill({ json: fixture })
    }
    if (url.pathname === '/domains') return route.fulfill({ json: { domains: ['example.test'] } })
    if (url.pathname === '/exposure/assets') return route.fulfill({ json: { assets: [], total: 0, metrics: null } })
    if (url.pathname === '/exposure/nodes') return route.fulfill({ json: { nodes: [] } })
    return route.fulfill({ json: { status: 'healthy', workers: [], targets: [], devices: [], total: 0 } })
  })
  return writes
}

test('service evidence, candidates and activities are separate and never execute on navigation', async ({ page }) => {
  const writes = await mockServices(page)
  await page.goto('/exposure?lens=services')
  await expect(page.getByRole('tab', { name: 'Services', exact: true })).toHaveAttribute('aria-selected', 'true')
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
  await page.goto('/exposure?lens=services')
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
  await page.goto('/exposure?lens=services')
  await expect(page.getByText('Database is not ready', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: /Retry/i })).toBeVisible()
  await expect(page.getByText('No targets on this page', { exact: true })).toHaveCount(0)
})
