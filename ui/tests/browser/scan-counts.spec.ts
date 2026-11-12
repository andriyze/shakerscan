import { expect, test } from '@playwright/test'

import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'
import { mockPageApi } from './mock-page-api'

// Synthetic fixtures: one application Scan and one discovery run of the same target. No scan runs.
const TARGET_ID = '00000000-0000-4000-8000-0000000000a1'
const APPLICATION_SCAN = '00000000-0000-4000-8000-0000000000b1'
const DISCOVERY_RUN = '00000000-0000-4000-8000-0000000000b2'

function scanRow(id: string, role: string, grade: string, score: number, findings: number) {
  return {
    id, target_id: TARGET_ID, target_url: 'https://counts.example.test', status: 'completed', progress: 100,
    scan_type: 'scan', run_kind: 'web_dast', scan_role: role, grade, score, findings_count: findings,
    assurance_score: 60, assurance_band: 'moderate', assurance_label: 'Moderate',
    created_at: '2026-10-01T10:00:00Z', started_at: '2026-10-01T10:00:05Z', completed_at: '2026-10-01T10:10:00Z',
    duration_seconds: 595, options: { scan_generation: 'v2', budget_profile: 'balanced' },
  }
}

test.describe('Scans list and discovery runs', () => {
  test('the list says how many discovery runs it leaves out and shows them from the same line', async ({ page }) => {
    const application = scanRow(APPLICATION_SCAN, 'standalone', 'F', 0, 44)
    const discovery = scanRow(DISCOVERY_RUN, 'asm_recon', 'D', 68, 4)
    const api = await mockPageApi(page, {
      '/scans': (url) => (url.searchParams.get('include_internal') === 'true'
        ? { scans: [discovery, application], total: 2, hidden_internal: 0, limit: 50, offset: 0 }
        : { scans: [application], total: 1, hidden_internal: 1, limit: 50, offset: 0 }),
      '/domains': () => ({ domains: [] }),
      '/campaigns': () => ({ campaigns: [], total: 0 }),
    })
    await page.goto('/scans')
    const count = page.getByTestId('scans-count')
    await expect(count).toContainText('Showing 1 scan')
    await expect(page.getByTestId('scans-hidden-note')).toHaveText('1 discovery or internal run not shown')
    await expect(page.getByRole('link', { name: 'https://counts.example.test' }).locator('visible=true')).toHaveCount(1)

    await count.getByRole('button', { name: 'Show them' }).click()
    await expect(page).toHaveURL(/include_internal=true/)
    await expect(count).toContainText('Showing 2 scans')
    await expect(page.getByTestId('scans-hidden-note')).toHaveCount(0)
    await expect(page.getByLabel('Show ASM and internal scans', { exact: true })).toBeChecked()
    await expect(page.getByRole('link', { name: 'https://counts.example.test' }).locator('visible=true')).toHaveCount(2)
    // The discovery run is listed as one, not as another Scan of the target.
    await expect(page.getByText('Discovery run', { exact: true }).locator('visible=true')).toHaveCount(1)
    expect(api.requests.some((entry) => entry.startsWith('GET /scans?') && entry.includes('include_internal=true'))).toBe(true)
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true)
  })

  test('a discovery run\'s page is headed as a discovery run', async ({ page }) => {
    await pinMockApiOrigin(page)
    await page.route(`${MOCK_API_ORIGIN}/**`, route => route.fulfill({ status: 503, json: { detail: 'fixture_unavailable' } }))
    const detail = (id: string, role: string) => ({
      ...scanRow(id, role, 'D', 68, 0),
      result: { result: { risk_score: 68, risk_grade: 'D', assurance_score: 32, assurance_band: 'limited' }, findings: [] },
    })
    await page.route(`${MOCK_API_ORIGIN}/scans/${DISCOVERY_RUN}`, route => route.fulfill({ json: detail(DISCOVERY_RUN, 'asm_recon') }))
    await page.route(`${MOCK_API_ORIGIN}/scans/${APPLICATION_SCAN}`, route => route.fulfill({ json: detail(APPLICATION_SCAN, 'standalone') }))

    await page.goto(`/scans/${DISCOVERY_RUN}`)
    await expect(page.getByTestId('scan-kind')).toHaveText('Discovery run')
    await expect(page.getByText('Discovery run conclusion', { exact: true })).toBeVisible()
    await expect(page.getByText('DAST scan', { exact: true })).toHaveCount(0)

    await page.goto(`/scans/${APPLICATION_SCAN}`)
    await expect(page.getByTestId('scan-kind')).toHaveText('DAST scan')
    await expect(page.getByText('Run conclusion', { exact: true })).toBeVisible()
  })
})

test('the Scans list names the posture column once, counts once and shows the grade the Scan page shows', async ({ page }) => {
  // The stored grade of an incomplete run ends in an asterisk.
  const application = scanRow(APPLICATION_SCAN, 'standalone', 'F*', 0, 44)
  await mockPageApi(page, {
    '/scans': () => ({ scans: [application], total: 1, hidden_internal: 0, limit: 50, offset: 0 }),
    '/domains': () => ({ domains: [] }),
    '/campaigns': () => ({ campaigns: [], total: 0 }),
  })
  await page.goto('/scans')
  await expect(page.getByTestId('scans-count')).toContainText('Showing 1 scan')
  // One page of scans is counted once, not again under the list.
  await expect(page.getByText(/Showing 1 scan/)).toHaveCount(1)
  await expect(page.getByTestId('scans-count-bottom')).toHaveCount(0)
  // The column header (or, on a narrow screen, the card) names the value once.
  await expect(page.getByText('Observed posture', { exact: true }).locator('visible=true')).toHaveCount(1)
  const posture = page.getByTestId('observed-posture').locator('visible=true')
  await expect(posture).toHaveCount(1)
  await expect(posture).toContainText('F')
  await expect(posture).toContainText('0/100')
  await expect(posture).toContainText('provisional')
  await expect(posture).not.toContainText('*')
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true)
})

test('one line on the Scan page relates its totals', async ({ page }) => {
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, route => route.fulfill({ status: 503, json: { detail: 'fixture_unavailable' } }))
  const finding = (severity: string, proven: boolean, index: number) => ({
    title: `Fixture ${severity} finding ${index}`, severity, tool: 'fixture', verified: proven,
    proof_state: proven ? 'verified' : 'suspected', url: `https://counts.example.test/item/${severity}/${index}`,
  })
  // 8 findings: 3 critical and 1 high proven, 1 high and 1 medium not yet verified, 1 low and 1 informational proven.
  const findings = [
    finding('critical', true, 1), finding('critical', true, 2), finding('critical', true, 3),
    finding('high', true, 1), finding('high', false, 2), finding('medium', false, 1),
    finding('low', true, 1), finding('info', true, 1),
  ]
  await page.route(`${MOCK_API_ORIGIN}/scans/${APPLICATION_SCAN}`, route => route.fulfill({ json: {
    ...scanRow(APPLICATION_SCAN, 'standalone', 'F', 0, findings.length),
    result: { result: { risk_score: 0, risk_grade: 'F', assurance_score: 60, assurance_band: 'moderate' }, findings },
  } }))
  await page.goto(`/scans/${APPLICATION_SCAN}`)
  // The headline counts proven findings at medium or higher; the tab counts all of them.
  await expect(page.getByRole('heading', { name: '4 confirmed material issues require action' })).toBeVisible()
  await expect(page.getByTestId('scan-count-line')).toHaveText(
    '8 findings in this run: 6 proven, 2 awaiting verification. Critical or high: 5. Proven at medium or higher: 4.')
  await expect(page.getByTestId('scan-findings-counts')).toHaveText('6 proven (4 medium or higher) · 2 need verification')
  await expect(page.getByText('8 observed in this scan', { exact: true })).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true)
})

test('a target row counts every open finding, informational ones included', async ({ page }) => {
  await pinMockApiOrigin(page)
  const row = (id: string, locator: string, severity_counts: Record<string, number>) => ({
    id, asset_id: id, locator, name: locator, url: `https://${locator}`, is_active: true, environment: 'production',
    connected_device: false, origin_count: 1, severity_counts,
  })
  const targets = [
    row('00000000-0000-4000-8000-0000000000c1', 'counts.example.test', { critical: 21, high: 17, low: 2, info: 4 }),
    row('00000000-0000-4000-8000-0000000000c2', 'notes.example.test', { info: 3 }),
  ]
  await page.route(`${MOCK_API_ORIGIN}/**`, route => {
    const url = new URL(route.request().url())
    if (url.pathname === '/targets/inventory') {
      return route.fulfill({ json: { targets, total: 2, total_groups: 1,
        groups: [{ root_domain: 'example.test', discoverable: true, targets }] } })
    }
    return route.fulfill({ json: { skill: null, revision: 0 } })
  })
  await page.goto('/targets')
  const rows = page.getByTestId('target-asset-row')
  const first = rows.filter({ hasText: 'counts.example.test' }).getByTestId('severity-pills')
  await expect(first).toHaveText('21C17H2L4I', { ignoreCase: true })
  await expect(first.getByTitle('4 info')).toBeVisible()
  // Informational findings are open findings: the row no longer reads "No open findings".
  const second = rows.filter({ hasText: 'notes.example.test' })
  await expect(second.getByTestId('severity-pills')).toHaveText('3I', { ignoreCase: true })
  await expect(second.getByText('No open findings')).toHaveCount(0)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true)
})

