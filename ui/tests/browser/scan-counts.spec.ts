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
