import { expect, test, type Page } from '@playwright/test'

import { mockPageApi, queryNames, serverError, type MockHandler } from './mock-page-api'
import { visitAndAuditPage } from './page-quality'

// Browser contract fixture: the real dashboard and its polling hooks, a scripted API; no scan runs.
const targetId = '11111111-1111-4111-8111-111111111111'
const scanId = '22222222-2222-4222-8222-222222222222'
const now = '2026-10-15T10:00:00Z'

const target = {
  id: targetId, url: 'https://app.example.test', name: 'Fixture app', root_domain: 'example.test', is_root: false,
  discovery_source: 'manual', is_active: true, last_score: 72, last_grade: 'C', last_scanned_at: now,
  total_scans: 3, active_findings_count: 4, created_at: now, cohort: 'production',
}

function populated(): Record<string, MockHandler> {
  return {
    '/health': () => ({ status: 'healthy' }),
    '/dashboard': () => ({
      metrics: { total_targets: 1, total_scans: 3, running_scans: 0, active_findings: 4, critical_findings: 1, high_findings: 2, avg_score: 72 },
      recent_scans: [{ id: scanId, target_id: targetId, target_url: target.url, status: 'completed', scan_type: 'standard',
        created_at: now, completed_at: now, score: 72, grade: 'C', progress: 100 }],
      recent_findings: [],
      action_center: [{ id: 'fixture-action', priority: 'high', category: 'Evidence', title: 'Fixture verify critical finding',
        detail: 'One critical finding still needs deterministic verification.', href: '/findings?severity=critical',
        action_label: 'Review findings', count: 1 }],
    }),
    '/queue/stats': () => ({ pending: 2, queued: 2, running: 1, completed: 9, failed: 0 }),
    '/workers': () => ({ count: 2, current_count: 2, max_allowed: 8, workers: [] }),
    '/gungnir/status': () => ({ running: false, domains_monitored: 0, subdomains_found: 0, session_found: 0,
      last_discovery: null, started_at: null, uptime_seconds: 0 }),
    '/exposure/assets': () => ({
      assets: [{ id: targetId, node_id: `target:${targetId}`, kind: 'web_target', label: 'Fixture app', url: target.url,
        root_domain: 'example.test', cohort: 'production', active_total: 4, active_critical: 1, active_high: 2,
        active_verified: 1, active_needs_verification: 3, last_scanned_at: now, coverage_posture: 'fresh' }],
      count: 1, total: 1, new_count: 0, cohort: 'operational', cohort_counts: { production: 1 },
      metrics: { asset_count: 1, active_critical: 1, active_high: 2, active_verified: 1, active_needs_verification: 3,
        ai_surfaces: 0, verified_assets: 1, unverified_high_assets: 1, fresh_scans: 1, p1_count: 1 },
    }),
    '/targets/grouped': () => ({
      items: [{ root_domain: 'example.test', root_target: null, subdomains: [target], subdomain_count: 1, total_count: 1 }],
      next_cursor: null, has_more: false, total: 1, total_kind: 'exact', generated_at: now,
    }),
    '/timeline': () => ({
      events: [{ event_id: 'event-1', kind: 'scan', status: 'completed', target_id: targetId, target_url: target.url,
        scan_id: scanId, title: 'Fixture scan completed', occurred_at: now, created_at: now }],
      upcoming: [],
    }),
  }
}

function empty(): Record<string, MockHandler> {
  return {
    ...populated(),
    '/dashboard': () => ({
      metrics: { total_targets: 0, total_scans: 0, running_scans: 0, active_findings: 0, critical_findings: 0, high_findings: 0, avg_score: 0 },
      recent_scans: [], recent_findings: [], action_center: [],
    }),
    '/queue/stats': () => ({ pending: 0, queued: 0, running: 0, completed: 0, failed: 0 }),
    '/exposure/assets': () => ({ assets: [], count: 0, total: 0, new_count: 0, cohort: 'operational', cohort_counts: {},
      metrics: { asset_count: 0, active_critical: 0, active_high: 0, ai_surfaces: 0 } }),
    '/targets/grouped': () => ({ items: [], next_cursor: null, has_more: false, total: 0, total_kind: 'exact', generated_at: now }),
    '/timeline': () => ({ events: [], upcoming: [] }),
  }
}

const latestResult = (page: Page) => page.getByRole('link', { name: /app\.example\.test/ }).first()

test('populated dashboard shows queue, posture, latest results and activity', async ({ page }) => {
  const api = await mockPageApi(page, populated())
  await visitAndAuditPage(page, '/', 800)
  await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible()
  await expect(page.getByText('scans pending', { exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Security posture' })).toBeVisible()
  await expect(page.getByText('Proven active risk', { exact: true })).toBeVisible()
  // One asset is "1 asset", not "1 assets".
  for (const text of ['1 affected asset', '1 high-impact asset', 'of 1 known asset', '1 asset']) {
    await expect(page.getByText(text, { exact: true })).toBeVisible()
  }
  await expect(latestResult(page)).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Recent activity' })).toBeVisible()
  await expect(page.getByText('No scan results yet. Add a target and run the first scan.')).toHaveCount(0)
  expect(api.unhandled).toEqual([])
  // The gateway's query allowlist must accept exactly what the dashboard sends.
  expect(queryNames(api, '/exposure/assets')).toEqual(['cohort', 'count', 'limit'])
  expect(queryNames(api, '/targets/grouped')).toEqual(['count', 'limit', 'member_limit', 'sort', 'sort_by', 'sort_order'])
  expect(queryNames(api, '/timeline')).toEqual(['limit'])
})

test('empty dashboard says there is nothing yet instead of showing zeros as results', async ({ page }) => {
  const api = await mockPageApi(page, empty())
  await visitAndAuditPage(page, '/', 800)
  await expect(page.getByText('No scan results yet. Add a target and run the first scan.')).toBeVisible()
  await expect(page.getByText('No meaningful activity has been recorded yet.')).toBeVisible()
  expect(api.unhandled).toEqual([])
})

test('an unavailable API shows the dashboard error and recovers on retry', async ({ page }) => {
  let down = true
  const routes = populated()
  const healthy = routes['/dashboard']
  routes['/dashboard'] = (url, request) => down ? serverError() : healthy(url, request)
  routes['/queue/stats'] = () => serverError()
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await mockPageApi(page, routes)
  await page.goto('/')
  await expect(page.getByText('Failed to load dashboard. Is the API running?')).toBeVisible()
  await expect(page.getByText('Queue unavailable', { exact: true })).toBeVisible()
  down = false
  await page.getByRole('button', { name: /Retry|Try again/ }).first().click()
  await expect(page.getByText('Failed to load dashboard. Is the API running?')).toHaveCount(0)
  await expect(latestResult(page)).toBeVisible()
  expect(errors).toEqual([])
})

test('the dashboard fits a phone viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockPageApi(page, populated())
  await visitAndAuditPage(page, '/', 800)
  await expect(page.getByRole('heading', { name: 'Latest target results' })).toBeVisible()
})

test('a latest result shows the whole host name and the grade the Scan page shows', async ({ page }, testInfo) => {
  const routes = populated()
  const healthy = routes['/dashboard']
  const host = 'checkout.staging.example.test'
  routes['/dashboard'] = (url, request) => {
    const body = healthy(url, request) as { recent_scans: Array<Record<string, unknown>> }
    // The stored grade of an incomplete run ends in an asterisk.
    body.recent_scans = [{ ...body.recent_scans[0], target_url: `https://${host}`, grade: 'F*', score: 0, findings_count: 44,
      assurance_score: 83, assurance_band: 'adequate', assurance_label: 'Adequate' }]
    return body
  }
  await mockPageApi(page, routes)
  await page.goto('/')
  const row = page.getByTestId('latest-result-row')
  await expect(row).toHaveCount(1)
  await expect(row).toContainText('44 findings')
  await expect(row).toContainText('Observed posture F (provisional)')
  // The examination strength the API sends for the run, as the Scans list shows it.
  await expect(row).toContainText('83/100')
  await expect(row).not.toContainText('Examination strength unavailable')
  await expect(row).not.toContainText('F*')
  const name = row.getByText(host, { exact: true })
  await expect(name).toBeVisible()
  if (testInfo.project.name === 'chromium') {
    // On a desktop the name is not cut while the card has room for it.
    expect(await name.evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true)
  }
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true)
})

// 2.12.1: Scans that finished on lab targets are not "no results yet" in the default cohort: the
// card says the filter hides them, and one click shows every cohort.
function labOnly(): Record<string, MockHandler> {
  const labTarget = { ...target, cohort: 'lab' }
  const labAsset = { id: targetId, node_id: `target:${targetId}`, kind: 'web_target', label: 'Fixture app', url: target.url,
    root_domain: 'example.test', cohort: 'lab', active_total: 4, active_critical: 1, active_high: 2,
    active_verified: 1, active_needs_verification: 3, last_scanned_at: now, coverage_posture: 'fresh' }
  const otherId = '33333333-3333-4333-8333-333333333333'
  const otherAsset = { ...labAsset, id: otherId, node_id: `target:${otherId}`, url: 'https://other.example.test', label: 'Other',
    cohort: 'unclassified', active_total: 0, active_critical: 0, active_high: 0, active_verified: 0, active_needs_verification: 0 }
  return {
    ...populated(),
    '/exposure/assets': (url) => {
      const all = url.searchParams.get('cohort') === 'all'
      const assets = all ? [labAsset, otherAsset] : [otherAsset]
      return { assets, count: assets.length, total: assets.length, new_count: 0, cohort: url.searchParams.get('cohort') || 'operational',
        cohort_counts: { lab: 1, unclassified: 1 },
        metrics: { asset_count: assets.length, active_critical: all ? 1 : 0, active_high: all ? 2 : 0, ai_surfaces: 0 } }
    },
    '/targets/grouped': () => ({
      items: [{ root_domain: 'example.test', root_target: null, subdomains: [labTarget], subdomain_count: 1, total_count: 1 }],
      next_cursor: null, has_more: false, total: 1, total_kind: 'exact', generated_at: now,
    }),
  }
}

for (const width of [390, 1440]) {
  test(`DASHBOARD-COHORT at ${width} px: the cohort filter says what it hides and "Show all cohorts" shows it`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 })
    await mockPageApi(page, labOnly())
    await page.goto('/')
    const hidden = page.getByTestId('latest-results-hidden')
    await expect(hidden).toContainText('The Operational + unclassified filter hides 1 result.')
    await expect(page.getByText('No scan results yet. Add a target and run the first scan.')).toHaveCount(0)
    await hidden.getByRole('button', { name: 'Show all cohorts' }).click()
    await expect(page.getByLabel('Dashboard cohort scope')).toHaveValue('all')
    await expect(latestResult(page)).toBeVisible()
    await expect(hidden).toHaveCount(0)
  })
}
