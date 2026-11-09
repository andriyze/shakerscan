import { expect, test } from '@playwright/test'

import { SCAN_PUBLIC_CONTRACT_SNAPSHOT } from '../../src/lib/scanContract.generated'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

// New Scan in plain words (2.12.1): build hashes and schema ids sit in a collapsed "Technical
// details" disclosure, coverage names the checks by their labels, and a disabled option says why
// in visible text (a tooltip never shows on a touch screen). Mocked API; nothing is queued.
for (const width of [390, 1440]) {
  test(`NEWSCAN-WORDS-001 New Scan speaks plainly at ${width} px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 })
    await pinMockApiOrigin(page)
    await page.route(`${MOCK_API_ORIGIN}/**`, async (route) => {
      const url = new URL(route.request().url())
      if (url.pathname === '/scan/contracts') return route.fulfill({ json: SCAN_PUBLIC_CONTRACT_SNAPSHOT })
      if (url.pathname === '/scan/contracts/preview') {
        return route.fulfill({ json: { preset: 'passive', requested_families: [], resolved_families: ['recon', 'nuclei_passive', 'sensitive_exposure'],
          derived_prerequisites: [], active_permissions: { active_testing: false, state_changing_http: false, network_discovery: false },
          minimum_family_quotas: {}, execution_topology: 'single', ai_used: false } })
      }
      if (url.pathname === '/workers') {
        return route.fulfill({ json: { count: 1, current_count: 1, stale_count: 0, pending_count: 0, fleet_uniform: true, stale_workers: [],
          expected_build_fingerprint: 'c8947ceb0123456789', distinct_fingerprints: ['c8947ceb0123456789'] } })
      }
      if (url.pathname === '/targets/inventory') return route.fulfill({ json: { items: [], next_cursor: null, has_more: false } })
      return route.fulfill({ json: {} })
    })
    await page.goto('/scan/new')
    await expect(page.getByRole('heading', { name: 'Where the Scan runs' })).toBeVisible()
    await expect(page.getByText(/Checks this Scan runs:.*Recon/)).toBeVisible()
    const body = page.locator('main')
    await expect(body).not.toContainText('Execution topology')
    await expect(body).not.toContainText('Release-authoritative')
    await expect(body).not.toContainText('Resolved families')
    // Identifiers are kept, out of sight until asked for.
    const details = page.getByTestId('scan-technical-details')
    await expect(details.getByText('c8947ceb0123456789').first()).toBeHidden()
    await details.getByText('Technical details').click()
    await expect(details.getByText(/Expected build:/)).toBeVisible()
    await expect(details.getByText('scan-action-plan/v1')).toBeVisible()
    // A disabled option names its reason in visible text.
    const network = page.getByTestId('network-discovery-needs-active')
    await expect(network).toBeVisible()
    await page.getByLabel('Allow active testing').check()
    await expect(network).toHaveCount(0)
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
    expect(overflow).toBeLessThanOrEqual(0)
  })
}

// 2026-11 evaluation: a Balanced "Standard active" Scan with state-changing requests allowed never
// tried the Hub's default login, though the checkbox says it includes default-login attempts: those
// are active templates (nuclei_active), which that preset runs only on Thorough and Deep.
test('NEWSCAN-WORDS-002 state-changing requests say when the default-login templates will not run', async ({ page }) => {
  let families = ['recon', 'nuclei_passive', 'xss', 'sqli', 'sensitive_exposure']
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async (route) => {
    const url = new URL(route.request().url())
    if (url.pathname === '/scan/contracts') return route.fulfill({ json: SCAN_PUBLIC_CONTRACT_SNAPSHOT })
    if (url.pathname === '/scan/contracts/preview') {
      return route.fulfill({ json: { preset: 'standard_active', requested_families: [], resolved_families: families,
        derived_prerequisites: [], active_permissions: { active_testing: true, state_changing_http: true, network_discovery: false },
        minimum_family_quotas: {}, execution_topology: 'single', ai_used: false } })
    }
    if (url.pathname === '/workers') {
      return route.fulfill({ json: { count: 1, current_count: 1, stale_count: 0, pending_count: 0, fleet_uniform: true, stale_workers: [],
        expected_build_fingerprint: 'c8947ceb0123456789', distinct_fingerprints: ['c8947ceb0123456789'] } })
    }
    if (url.pathname === '/targets/inventory') return route.fulfill({ json: { items: [], next_cursor: null, has_more: false } })
    return route.fulfill({ json: {} })
  })
  await page.goto('/scan/new')
  await expect(page.getByRole('heading', { name: 'Where the Scan runs' })).toBeVisible()
  await page.getByLabel('Allow active testing').check()
  await page.getByLabel(/Allow explicitly selected state-changing HTTP requests/).check()
  await expect(page.getByTestId('state-changing-templates-note')).toBeVisible()
  families = [...families, 'nuclei_active']
  await page.getByText('Thorough', { exact: true }).first().click()
  await expect(page.getByTestId('state-changing-templates-note')).toHaveCount(0)
})
