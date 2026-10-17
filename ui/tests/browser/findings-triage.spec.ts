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

test('on an engine without server grouping, repeats group in the browser into one expandable row', async ({ page }) => {
  const requests: URL[] = []
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const url = new URL(route.request().url())
    if (url.pathname === '/findings') {
      requests.push(url)
      const base = {
        title: 'Exposed secret', severity: 'critical', status: 'active', proof_state: 'verified', target_id: 't-app',
        first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-02T00:00:00Z',
      }
      return route.fulfill({ json: { total: 2, findings: [
        { ...base, id: alphaId, url: 'https://app.example.test/.env' },
        { ...base, id: betaId, url: 'https://app.example.test/.git/config' },
      ] } })
    }
    if (url.pathname === '/domains') return route.fulfill({ json: { domains: [] } })
    return route.fulfill({ json: { status: 'healthy', workers: [], total: 0 } })
  })
  await page.goto('/findings')
  await expect(page.getByText('2 open findings in 1 group')).toBeVisible()
  // The engine is asked to group first; it answers rows (an older engine), so the page loads the
  // whole result set and groups it, so no group is cut between pages.
  expect(requests[0].searchParams.get('group_by')).toBe('issue')
  const rows = requests.find((url) => !url.searchParams.has('group_by'))!
  expect(rows.searchParams.get('status')).toBe('active')
  expect(rows.searchParams.get('limit')).toBe('500')
  const group = page.getByRole('button', { name: /Exposed secret/ })
  await expect(group).toHaveAttribute('aria-expanded', 'false')
  await group.click()
  await expect(group).toHaveAttribute('aria-expanded', 'true')
  await expect(page.getByRole('link', { name: /\/\.git\/config/ })).toHaveAttribute('href', new RegExp(betaId))
  await page.getByRole('button', { name: 'All', exact: true }).click()
  await expect.poll(() => requests.at(-1)?.searchParams.get('status')).toBeNull()
})

test('the engine groups every match: counts are whole groups and pages follow its cursor', async ({ page }) => {
  const requests: URL[] = []
  const lead = {
    id: alphaId, title: 'Exposed secret', severity: 'critical', status: 'active', proof_state: 'verified',
    target_id: 't-app', url: 'https://app.example.test/.env',
    first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-02T00:00:00Z',
  }
  const group = (overrides: Record<string, unknown> = {}) => ({
    title_key: 'exposed secret', severity: 'critical', subject: 't-app', proof_state: 'verified', status: 'active',
    count: 120, first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-03T00:00:00Z', lead,
    member_ids: [alphaId, betaId], member_ids_truncated: true,
    members: [
      { id: alphaId, url: lead.url, last_seen_at: lead.last_seen_at, latest_retest_verdict: null },
      { id: betaId, url: 'https://app.example.test/.git/config', last_seen_at: '2026-01-03T00:00:00Z', latest_retest_verdict: null },
    ],
    ...overrides,
  })
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const url = new URL(route.request().url())
    if (url.pathname === '/findings' && url.searchParams.get('group_by') === 'issue') {
      requests.push(url)
      const second = url.searchParams.get('cursor') === 'page-2'
      return route.fulfill({ json: {
        items: second ? [group({ lead: { ...lead, id: 'ffffffff-ffff-4fff-8fff-ffffffffffff', title: 'Open redirect' }, count: 1, member_ids: ['ffffffff-ffff-4fff-8fff-ffffffffffff'], member_ids_truncated: false, members: [] })] : [group()],
        next_cursor: second ? null : 'page-2', has_more: !second, total: 51, total_kind: 'exact',
        findings_total: 170, generated_at: '2026-01-04T00:00:00Z',
      } })
    }
    if (url.pathname === '/findings') return route.fulfill({ json: { total: 0, findings: [] } })
    if (url.pathname === '/domains') return route.fulfill({ json: { domains: [] } })
    return route.fulfill({ json: { status: 'healthy', workers: [], total: 0 } })
  })
  await page.goto('/findings')
  await expect(page.getByText('170 open findings in 51 groups · showing groups 1–1')).toBeVisible()
  expect(requests[0].searchParams.get('status')).toBe('active')
  expect(requests[0].searchParams.get('count')).toBe('exact')
  expect(requests[0].searchParams.get('sort')).toBe('-severity')
  expect(requests[0].searchParams.has('offset')).toBe(false)
  const row = page.getByRole('button', { name: /Exposed secret/ })
  await expect(row).toContainText('×120')
  await row.click()
  await expect(page.getByRole('link', { name: /\/\.git\/config/ })).toHaveAttribute('href', new RegExp(betaId))
  await expect(page.getByText('118 more not listed here. Narrow the filters to list them.')).toBeVisible()
  // The next page continues from the engine's cursor.
  await page.getByRole('button', { name: 'Next' }).first().click()
  await expect(page.getByText('Open redirect')).toBeVisible()
  expect(requests.at(-1)?.searchParams.get('cursor')).toBe('page-2')
})
