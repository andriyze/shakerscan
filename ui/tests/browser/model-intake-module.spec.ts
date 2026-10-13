import { expect, test, type Page } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

// Model Intake is an optional module (2.10). With it off the page explains how to install it and
// makes no Model Intake request; the sidebar shows it only under the advanced switch.
async function mock(page: Page, enabled: boolean | undefined) {
  const intakeRequests: string[] = []
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async (route) => {
    const url = new URL(route.request().url())
    if (url.pathname.startsWith('/model-intake')) intakeRequests.push(`${route.request().method()} ${url.pathname}`)
    if (url.pathname === '/health') {
      const worker = enabled === undefined ? { status: 'ready' } : enabled ? { enabled: true, status: 'ready' } : { enabled: false, status: 'disabled', reason: 'module_not_installed' }
      return route.fulfill({ json: { status: 'healthy', scanner_version: '2.10.0', model_intake_worker: worker } })
    }
    return route.fulfill({ json: { status: 'healthy', workers: [], targets: [], devices: [], total: 0, items: [] } })
  })
  return intakeRequests
}

test('MODULE-001 with Model Intake off the page shows how to install it and runs nothing', async ({ page }) => {
  const intakeRequests = await mock(page, false)
  await page.goto('/model-intake')
  await expect(page.getByText('Optional module: not installed on this instance.')).toBeVisible()
  await expect(page.getByText('shakerscan model-intake enable', { exact: true })).toBeVisible()
  await expect(page.getByText(/about 4\.8 GB/)).toBeVisible()
  expect(intakeRequests).toEqual([])
})

test('MODULE-002 with Model Intake on (or an engine that predates the setting) the page loads', async ({ page }) => {
  for (const enabled of [true, undefined]) {
    const intakeRequests = await mock(page, enabled)
    await page.goto('/model-intake')
    await expect(page.getByText('Optional module: not installed on this instance.')).toHaveCount(0)
    await expect.poll(() => intakeRequests.length).toBeGreaterThan(0)
    await page.unrouteAll({ behavior: 'ignoreErrors' })
  }
})

test('MODULE-003 the sidebar lists Model Intake only under the advanced switch', async ({ page }) => {
  await page.setViewportSize({ width: 1400, height: 900 })
  await mock(page, false)
  await page.goto('/model-intake')
  const visibleLink = (name: string) => page.locator('aside:visible a[href], nav:visible a[href]').filter({ hasText: name })
  await expect(visibleLink('AI Gate')).not.toHaveCount(0)
  await expect(visibleLink('Model Intake')).toHaveCount(0)
  await page.getByRole('switch', { name: 'Show all sidebar sections' }).first().click()
  await expect(visibleLink('Model Intake')).not.toHaveCount(0)
})

test('MODULE-004 in a managed deployment the page says it is not available and names no host command', async ({ page }) => {
  const intakeRequests = await mock(page, false)
  await page.addInitScript(() => {
    window.__SHAKERSCAN_CAPABILITIES__ = {
      schema: 'shakerscan.workspace-capabilities/v1', mode: 'managed', features: { model_intake: { state: 'enabled' } }, navigation: { '/model-intake': 'model_intake' }, ui_routes: ['/model-intake'],
      edition: 'Enterprise Edition',
    }
  })
  await page.goto('/model-intake')
  await expect(page.getByText('Not available in this deployment.')).toBeVisible()
  await expect(page.getByText('shakerscan model-intake enable')).toHaveCount(0)
  expect(intakeRequests).toEqual([])
})
