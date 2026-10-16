import { expect, test, type Page } from '@playwright/test'

import { mockPageApi, queryNames, serverError, type MockHandler } from './mock-page-api'

// Browser contract fixture for the 2.11 lab UI audit fixes: the real pages, a scripted API; no
// scan, Hunt or discovery runs. Hosts are RFC 6761 `.invalid`, as in the scale seed.
const now = '2026-10-15T10:00:00Z'
const facets = (total: number) => ({ total, environment: { production: total }, authorization: { authorized: 0, unauthorized: total },
  findings: { any: 0, critical_high: 0, none: total }, activity: { scanned: 0, never: total, scanning: 0 }, asset_type: { web: total, network: 0 } })
const asset = (i: number) => {
  const host = `app-${String(i).padStart(5, '0')}.scale-seed.invalid`
  return { id: `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`, asset_id: `a-${i}`, name: null, url: `https://${host}`, locator: host,
    root_domain: 'scale-seed.invalid', is_active: true, environment: 'production', connected_device: false, origin_count: 1,
    origins: [{ id: `o-${i}`, url: `https://${host}`, name: null, is_active: true }], created_at: now, updated_at: now }
}

async function targets(page: Page, members: number, memberCount: number) {
  return mockPageApi(page, {
    '/health': () => ({ status: 'healthy' }),
    '/targets/inventory': (url) => ({
      items: [{ root_domain: 'scale-seed.invalid', discoverable: false, targets: Array.from({ length: members }, (_, i) => asset(i + 1)),
        member_count: memberCount, members_truncated: memberCount > members }],
      has_more: url.searchParams.has('cursor') ? false : true, next_cursor: url.searchParams.has('cursor') ? null : 'page-2',
      total: 2, total_kind: 'exact', generated_at: now, facets: facets(memberCount),
    }),
  })
}

test('#2 a 10k-target domain opens New Scan by reference, and the page reads list/v1 group pages', async ({ page }) => {
  const api = await targets(page, 200, 10_000)
  await page.goto('/targets')
  const group = page.getByTestId('target-domain-group').first()
  await expect(group).toContainText('10,000 targets')
  const batch = group.getByRole('link', { name: /Customize batch/ })
  await expect(batch).toHaveAttribute('href', '/scan/new?domain=scale-seed.invalid')
  // Bounded request: a member cap, an exact group count on the first page, never offset paging.
  const first = api.requests.find(entry => entry.startsWith('GET /targets/inventory'))!
  const params = new URL(first.split(' ')[1], 'http://x').searchParams
  expect(params.get('member_limit')).toBe('200')
  expect(params.get('count')).toBe('exact')
  expect(params.get('group_by')).toBe('domain')
  expect(params.has('offset')).toBe(false)
  await page.getByRole('button', { name: 'Next', exact: true }).click()
  await expect.poll(() => api.requests.some(entry => entry.includes('cursor=page-2'))).toBe(true)
  await page.getByRole('button', { name: 'Previous', exact: true }).click()
  expect(queryNames(api, '/targets/inventory')).toEqual(['count', 'cursor', 'group_by', 'include_facets', 'limit', 'member_limit', 'sort'])
})

test('#13 one target reads "1 Target"', async ({ page }) => {
  await targets(page, 1, 1)
  await page.goto('/targets')
  await expect(page.getByRole('button', { name: /^1 Target$/ })).toBeVisible()
})

test('#2 New Scan resolves a domain reference into one capped batch and says why', async ({ page }) => {
  const api = await mockPageApi(page, {
    '/health': () => ({ status: 'healthy' }),
    '/targets/inventory': () => ({
      items: [{ root_domain: 'scale-seed.invalid', targets: Array.from({ length: 200 }, (_, i) => asset(i + 1)), member_count: 10_000, members_truncated: true }],
      has_more: false, next_cursor: null, generated_at: now,
    }),
  })
  await page.goto('/scan/new?domain=scale-seed.invalid')
  const box = page.getByRole('textbox', { name: /Target URLs/ })
  await expect(box).toHaveValue(/app-00001\.scale-seed\.invalid/)
  const lines = (await box.inputValue()).split('\n').filter(Boolean)
  expect(lines).toHaveLength(50)
  await expect(page.getByTestId('batch-notice')).toHaveText(
    'scale-seed.invalid has 10,000 targets; a batch scans at most 50 at once. The first 50 are filled in below; queue the rest in further batches.')
  const domainRead = api.requests.find(entry => entry.startsWith('GET /targets/inventory') && entry.includes('group_by=domain'))!
  expect([...new URL(domainRead.split(' ')[1], 'http://x').searchParams.keys()].sort()).toEqual(['count', 'group_by', 'limit', 'member_limit', 'search'])
})

function dashboardRoutes(view: string): Record<string, MockHandler> {
  return {
    '/health': () => ({ status: 'healthy' }),
    '/dashboard': () => ({ metrics: { total_targets: 5, total_scans: 10, running_scans: 0, active_findings: 75, critical_findings: 8,
      high_findings: 19, avg_score: 40 }, recent_scans: [], recent_findings: [], action_center: [] }),
    '/queue/stats': () => ({ pending: 0, queued: 0, running: 0, completed: 10, failed: 0 }),
    '/workers': () => ({ count: 4, current_count: 4, max_allowed: 8, workers: [] }),
    '/gungnir/status': () => ({ running: false, domains_monitored: 0, subdomains_found: 0, session_found: 0, last_discovery: null, started_at: null, uptime_seconds: 0 }),
    '/exposure/assets': (url) => url.searchParams.get('cohort') === view && view !== 'operational'
      ? { assets: [], count: 5, total: 5, new_count: 0, cohort: view, cohort_counts: { lab: 5 },
        metrics: { asset_count: 5, active_critical: 8, active_high: 19, ai_surfaces: 0, active_verified: 56, active_needs_verification: 19 } }
      : { assets: [], count: 0, total: 0, new_count: 0, cohort: url.searchParams.get('cohort'), cohort_counts: { lab: 5 },
        metrics: { asset_count: 0, active_critical: 0, active_high: 0, ai_surfaces: 0 } },
    '/targets/grouped': () => ({ items: [], next_cursor: null, has_more: false, total: 0, total_kind: 'exact', generated_at: now }),
    '/timeline': () => ({ events: [], upcoming: [] }),
  }
}

test('#4 an empty default scope says where the data is, never "Add a target", and the scope is in the URL', async ({ page }) => {
  await mockPageApi(page, dashboardRoutes('all'))
  await page.goto('/')
  const banner = page.getByTestId('dashboard-out-of-scope')
  await expect(banner).toHaveText(/Nothing in this scope yet\. 5 targets and 75 open findings are in other cohorts \(5 lab\)\./)
  await expect(page.getByText('No scan results yet. Add a target and run the first scan.')).toHaveCount(0)
  await expect(page.getByRole('link', { name: /Add a target/ })).toHaveCount(0)
  await expect(page.getByText('No scan results in this scope. Results for the other cohorts show under All cohorts.')).toBeVisible()
  await banner.getByRole('button', { name: 'Show all cohorts' }).click()
  await expect(page).toHaveURL(/\?cohort=all$/)
  await expect(page.getByRole('combobox', { name: 'Dashboard cohort scope' })).toHaveValue('all')
  await expect(banner).toHaveCount(0)
  await page.reload()
  await expect(page.getByRole('combobox', { name: 'Dashboard cohort scope' })).toHaveValue('all')
  await page.getByRole('combobox', { name: 'Dashboard cohort scope' }).selectOption('operational')
  await expect(page).not.toHaveURL(/cohort=/)
})

test('#4 a truly empty install keeps the first-run prompt', async ({ page }) => {
  const routes = dashboardRoutes('all')
  routes['/exposure/assets'] = (url) => ({ assets: [], count: 0, total: 0, new_count: 0, cohort: url.searchParams.get('cohort'), cohort_counts: {},
    metrics: { asset_count: 0, active_critical: 0, active_high: 0, ai_surfaces: 0 } })
  await mockPageApi(page, routes)
  await page.goto('/')
  await expect(page.getByText('No scan results yet. Add a target and run the first scan.')).toBeVisible()
  await expect(page.getByTestId('dashboard-out-of-scope')).toHaveCount(0)
})

test('#7 Refresh on /deep-hunt/leads makes a request and says when', async ({ page }) => {
  let contractReads = 0
  const api = await mockPageApi(page, {
    '/health': () => ({ status: 'healthy' }),
    '/arsenal/family-proof/contracts': () => { contractReads += 1; return { contracts: {}, aliases: {} } },
    '/targets/inventory': () => ({ items: [], has_more: false, next_cursor: null, generated_at: now }),
  })
  await page.goto('/deep-hunt/leads')
  await expect.poll(() => contractReads).toBe(1)
  // No target chosen: Refresh still re-reads the proof contracts and says so (it was inert).
  await page.getByRole('button', { name: 'Refresh', exact: true }).click()
  await expect(page.getByTestId('leads-refreshed')).toContainText('Proof contracts updated')
  expect(contractReads).toBe(2)
  expect(api.unhandled).toEqual([])
})

// Review of the audit fixes: the count read the facets' total (the search scope only), so a
// narrowed page said "1,200 targets in 3 groups" for three small groups.
test('the Targets count applies the filters, not the facets\' search-scope total', async ({ page }) => {
  await mockPageApi(page, {
    '/health': () => ({ status: 'healthy' }),
    '/targets/inventory': () => ({
      items: ['a', 'b', 'c'].map((name, index) => ({ root_domain: `${name}.invalid`, discoverable: true,
        targets: [{ ...asset(index + 1), root_domain: `${name}.invalid` }], member_count: 1, members_truncated: false })),
      has_more: false, next_cursor: null, total: 3, total_kind: 'exact', target_total: 3, target_total_kind: 'exact',
      generated_at: now, facets: facets(1200),
    }),
  })
  await page.goto('/targets?authorization=unauthorized')
  await expect(page.getByText('3 targets in 3 groups', { exact: true })).toBeVisible()
  await expect(page.getByText(/1,200 targets/)).toHaveCount(0)
})

// Review of the audit fixes: Next clicked while a typed search was settling sent the old query's
// cursor with the new search, and the server refused it (cursor_mismatch).
test('Next while a search is settling never pairs the old cursor with the new search', async ({ page }) => {
  // A cursor names the search it was issued for; like the server, the fixture refuses a mismatch.
  const refused: string[] = []
  const api = await mockPageApi(page, {
    '/health': () => ({ status: 'healthy' }),
    '/targets/inventory': (url) => {
      const search = url.searchParams.get('search') || ''
      const cursor = url.searchParams.get('cursor')
      if (cursor && cursor !== `page-2:${search}`) {
        refused.push(url.search)
        return { status: 400, json: { detail: { error: 'cursor_mismatch' } } }
      }
      return {
        items: [{ root_domain: 'scale-seed.invalid', discoverable: false, targets: [asset(1)], member_count: 1, members_truncated: false }],
        has_more: !cursor, next_cursor: cursor ? null : `page-2:${search}`,
        total: 2, total_kind: 'exact', generated_at: now, facets: facets(2),
      }
    },
  })
  await page.goto('/targets')
  const next = page.getByRole('button', { name: 'Next', exact: true })
  await expect(next).toBeEnabled()
  await page.getByRole('textbox', { name: 'Search targets by URL or domain' }).fill('app')
  await expect(next).toBeDisabled()
  await next.click({ force: true, timeout: 1000 }).catch(() => undefined)
  await expect.poll(() => api.requests.some(entry => entry.includes('search=app'))).toBe(true)
  await expect(next).toBeEnabled()
  await next.click()
  await expect.poll(() => api.requests.some(entry => entry.includes('cursor=page-2%3Aapp'))).toBe(true)
  expect(refused).toEqual([])
})

// Review of the audit fixes: a failed Refresh still said "updated", and the time outlived a
// target change.
test('a failed Refresh on /deep-hunt/leads says so, and a target change clears the time', async ({ page }) => {
  let contractReads = 0
  let failContracts = false
  const target = { ...asset(1), name: 'Leads app' }
  await mockPageApi(page, {
    '/health': () => ({ status: 'healthy' }),
    '/arsenal/family-proof/contracts': () => { contractReads += 1; return failContracts ? serverError() : { contracts: {}, aliases: {} } },
    '/targets/inventory': () => ({ items: [target], has_more: false, next_cursor: null, generated_at: now }),
    '/arsenal/hypotheses/schedule': () => ({ version: '1', scheduled: [], deferred: [], excluded: [],
      counts: { scheduled: 0, deferred: 0, excluded: 0 }, execution_enabled: false }),
  })
  await page.goto('/deep-hunt/leads')
  await expect.poll(() => contractReads).toBeGreaterThan(0)
  const refresh = page.getByRole('button', { name: 'Refresh', exact: true })
  await refresh.click()
  await expect(page.getByTestId('leads-refreshed')).toContainText('Proof contracts updated')
  failContracts = true
  await refresh.click()
  await expect(page.getByTestId('leads-refresh-failed')).toContainText('Refresh failed at')
  await expect(page.getByTestId('leads-refreshed')).toHaveCount(0)
  failContracts = false
  await refresh.click()
  await expect(page.getByTestId('leads-refreshed')).toBeVisible()
  // Choosing a target: the earlier Refresh time was for no target, so it goes.
  await page.locator('#leads-target').click()
  await page.getByRole('combobox', { name: /Search targets/ }).fill('app')
  await page.getByRole('option', { name: /app-00001/ }).click()
  await expect(page.getByTestId('leads-refreshed')).toHaveCount(0)
  await expect(page.getByTestId('leads-refresh-failed')).toHaveCount(0)
})
