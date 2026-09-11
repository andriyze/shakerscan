import { expect, test, type Page } from '@playwright/test'

import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

const alphaId = '55555555-5555-4555-8555-555555555555'
const betaId = '66666666-6666-4666-8666-666666666666'

type Policy = {
  schema: string
  mode: string
  features: Record<string, { state: string }>
  navigation: Record<string, string>
  ui_routes: string[]
}

// Managed workspace where deletion is licensed but the operator is not an engine admin:
// the dock must show triage only, with no More menu and no Advanced cleanup.
const nonAdminPolicy: Policy = {
  schema: 'shakerscan.workspace-capabilities/v1',
  mode: 'managed',
  features: { findings: { state: 'enabled' }, record_deletion: { state: 'enabled' } },
  navigation: { '/findings': 'findings' },
  ui_routes: ['/findings', '/findings/[^/]+'],
}

async function mockApi(page: Page, options: { policy?: Policy } = {}) {
  const writes: { path: string; body: Record<string, unknown> }[] = []
  let status = 'active'
  await pinMockApiOrigin(page)
  await page.addInitScript((policy) => {
    if (policy) window.__SHAKERSCAN_CAPABILITIES__ = policy as never
  }, options.policy ?? null)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const body = request.method() === 'POST' && request.postData() ? request.postDataJSON() : {}
    if (request.method() !== 'GET' && request.method() !== 'OPTIONS') writes.push({ path, body })
    if (path === '/findings') {
      const seen = { first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-02T00:00:00Z' }
      return route.fulfill({ json: { total: 2, findings: [
        { id: alphaId, title: 'Alpha finding', severity: 'high', status, tool: 'nuclei', cvss_score: 7.5, ...seen },
        { id: betaId, title: 'Beta finding', severity: 'low', status, ...seen },
      ] } })
    }
    if (path === '/findings/bulk') {
      status = String(body.status)
      return route.fulfill({ json: { updated: 2, requested: 2, unique_requested: 2, not_found: 0, status } })
    }
    if (path === '/domains') return route.fulfill({ json: { domains: [] } })
    return route.fulfill({ json: { status: 'healthy', workers: [], total: 0 } })
  })
  return writes
}

test('initial load shows no selection or deletion controls', async ({ page }) => {
  await mockApi(page)
  await page.goto('/findings')
  await expect(page.getByText('Alpha finding')).toBeVisible()
  await expect(page.getByRole('checkbox')).toHaveCount(0)
  await expect(page.getByRole('region', { name: 'Selection actions' })).toHaveCount(0)
  await expect(page.getByRole('menuitem', { name: 'Delete selected findings' })).toHaveCount(0)
  await expect(page.getByRole('button', { name: /delete/i })).toHaveCount(0)
})

test('bulk triage posts the selected IDs and dismisses the dock', async ({ page }) => {
  const writes = await mockApi(page)
  await page.goto('/findings')
  await page.getByRole('button', { name: 'Select', exact: true }).click()
  await page.getByRole('checkbox', { name: 'Select finding Alpha finding', exact: true }).check()
  await page.getByRole('checkbox', { name: 'Select finding Beta finding', exact: true }).check()
  const dock = page.getByRole('region', { name: 'Selection actions' })
  await expect(dock).toContainText('2 selected')
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth)
  expect(overflow, 'dock must not cause horizontal overflow').toBe(false)
  await dock.getByRole('button', { name: 'Mark resolved', exact: true }).click()
  const bulk = writes.find(w => w.path === '/findings/bulk')!
  expect([...(bulk.body.finding_ids as string[])].sort()).toEqual([alphaId, betaId].sort())
  expect(bulk.body.status).toBe('resolved')
  await expect(page.getByText('2 findings marked resolved')).toBeVisible()
  await expect(dock).toHaveCount(0)
  // Selection mode persists for the next batch; the selection itself is cleared.
  await expect(page.getByRole('checkbox', { name: 'Select finding Alpha finding', exact: true })).not.toBeChecked()
})

test('the active status filter is never offered as a no-op verdict', async ({ page }) => {
  await mockApi(page)
  await page.goto('/findings?status=resolved')
  await page.getByRole('button', { name: 'Select', exact: true }).click()
  await page.getByRole('checkbox', { name: 'Select finding Alpha finding', exact: true }).check()
  const dock = page.getByRole('region', { name: 'Selection actions' })
  await expect(dock.getByRole('button', { name: 'Mark resolved', exact: true })).toHaveCount(0)
  await expect(dock.getByRole('button', { name: 'Reactivate', exact: true })).toBeVisible()
})

test('managed workspace without engine admin gets triage but no record deletion', async ({ page }) => {
  await mockApi(page, { policy: nonAdminPolicy })
  await page.goto('/findings')
  await expect(page.getByText('Alpha finding')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Advanced cleanup' })).toHaveCount(0)
  await page.getByRole('button', { name: 'Select', exact: true }).click()
  await page.getByRole('checkbox', { name: 'Select finding Alpha finding', exact: true }).check()
  const dock = page.getByRole('region', { name: 'Selection actions' })
  await expect(dock.getByRole('button', { name: 'Mark resolved', exact: true })).toBeVisible()
  await expect(dock.getByRole('button', { name: 'More actions' })).toHaveCount(0)
  await expect(page.getByRole('menuitem', { name: 'Delete selected findings' })).toHaveCount(0)
})

test('secondary filters fold behind a counted Filters button', async ({ page }) => {
  await mockApi(page)
  await page.goto('/findings?source_type=dast&verified_only=true')
  const filters = page.getByRole('button', { name: /^Filters/ })
  await expect(filters).toContainText('2')
  await expect(page.getByRole('group', { name: 'Filter by source' })).toHaveCount(0)
  await filters.click()
  await expect(page.getByRole('group', { name: 'Filter by source' })).toBeVisible()
})
