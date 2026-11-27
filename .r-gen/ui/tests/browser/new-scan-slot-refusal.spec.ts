import { expect, test, type Page } from '@playwright/test'

import { SCAN_PUBLIC_CONTRACT_SNAPSHOT } from '../../src/lib/scanContract.generated'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

// New Scan (2.12.1): a refused submission shows where the person is looking, beside Run Scan, in
// view and focused; a refusal because every scan slot is taken says so plainly with a way to the
// Scans page. Mocked API; nothing is queued.
const target = { id: '11111111-1111-4111-8111-111111111113', url: 'https://app.example.test', name: 'App',
  root_domain: 'example.test', is_root: true, discovery_source: 'manual', is_active: true, total_scans: 0,
  active_findings_count: 0, created_at: '2026-08-25T00:00:00Z' }
const SLOT_REFUSAL = 'concurrent scan limit reached: 2 of 2 licensed slots in use (2 network scans); wait for one to finish or cancel it'

async function mock(page: Page, refusal: { status: number; detail: string }) {
  const posts: string[] = []
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    if (url.pathname === '/scan/contracts') return route.fulfill({ json: SCAN_PUBLIC_CONTRACT_SNAPSHOT })
    if (url.pathname === '/scan/contracts/preview') {
      return route.fulfill({ json: { preset: 'passive', requested_families: [], resolved_families: ['recon', 'nuclei_passive', 'sensitive_exposure'],
        derived_prerequisites: [], active_permissions: { active_testing: false, state_changing_http: false, network_discovery: false },
        minimum_family_quotas: {}, execution_topology: 'single', ai_used: false } })
    }
    if (url.pathname === '/workers') return route.fulfill({ json: { count: 1, current_count: 1, stale_count: 0, pending_count: 0, fleet_uniform: true, stale_workers: [] } })
    if (url.pathname === '/targets/inventory') return route.fulfill({ json: { items: [target], next_cursor: null, has_more: false } })
    if (url.pathname === '/credential-profiles') return route.fulfill({ json: { profiles: [], count: 0 } })
    if (url.pathname === '/request-collections') return route.fulfill({ json: { collections: [], count: 0 } })
    if (url.pathname === `/targets/${target.id}/authorization`) return route.fulfill({ status: 404, json: { detail: 'not authorized' } })
    if (url.pathname === '/scans' && request.method() === 'POST') {
      posts.push(url.pathname)
      return route.fulfill({ status: refusal.status, json: { detail: refusal.detail } })
    }
    return route.fulfill({ json: {} })
  })
  return posts
}

for (const width of [390, 1440]) {
  test(`NEWSCAN-REFUSAL-001 a busy-slot refusal shows beside Run Scan, in view, at ${width} px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 800 })
    const posts = await mock(page, { status: 429, detail: SLOT_REFUSAL })
    await page.goto('/scan/new')
    await page.getByLabel('Target URL or hostname').fill(target.url)
    const submit = page.getByRole('button', { name: 'Run Scan' })
    await expect(submit).toBeEnabled()
    await page.evaluate(() => window.scrollTo(0, 0))
    await submit.click()
    await expect.poll(() => posts.length).toBe(1)
    const alert = page.getByTestId('scan-submit-error')
    await expect(alert).toContainText('concurrent scan limit reached')
    await expect(alert).toContainText('Scans already running or queued hold the available slots. This Scan was not queued')
    await expect(alert).toBeInViewport()
    await expect(alert).toBeFocused()
    await alert.getByRole('link', { name: 'Scans page' }).click()
    await expect(page).toHaveURL(/\/scans$/)
  })

  test(`NEWSCAN-REFUSAL-002 another refusal shows in view without the slot line at ${width} px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 800 })
    await mock(page, { status: 422, detail: 'target is not registered' })
    await page.goto('/scan/new')
    await page.getByLabel('Target URL or hostname').fill(target.url)
    await page.getByRole('button', { name: 'Run Scan' }).click()
    const alert = page.getByTestId('scan-submit-error')
    await expect(alert).toContainText('target is not registered')
    await expect(alert).toBeInViewport()
    await expect(alert).not.toContainText('hold the available slots')
  })
}
