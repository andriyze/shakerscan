import { expect, test, type Page } from '@playwright/test'

import { mockPageApi } from './mock-page-api'

// The managed workspace guide (/docs) over a scripted API, with a workspace policy injected the
// way a gateway publishes one. Nothing here is a real deployment, and nothing runs.
const policy = (navigation: Record<string, string>, routes: string[]) => ({
  schema: 'shakerscan.workspace-capabilities/v1',
  mode: 'managed',
  features: {
    dashboard: { state: 'enabled' }, docs: { state: 'enabled' }, scans: { state: 'enabled' },
    findings: { state: 'enabled' }, targets: { state: 'enabled' },
  },
  navigation: { '/': 'dashboard', '/docs': 'docs', '/scans': 'scans', '/findings': 'findings', '/targets': 'targets', ...navigation },
  ui_routes: ['/', '/docs', '/scans', '/findings', '/targets', ...routes],
})

async function guide(page: Page, value: unknown) {
  await page.addInitScript((injected) => { window.__SHAKERSCAN_CAPABILITIES__ = injected as never }, value)
  await mockPageApi(page, { '/health': () => ({ status: 'healthy', scanner_version: 'fixture' }) })
  await page.goto('/docs')
  await expect(page.getByRole('heading', { name: 'Workspace guide' })).toBeVisible()
  return page.locator('ol').first().locator('li')
}

test('GUIDE-001 a workspace that offers New Scan links it from the second step', async ({ page }) => {
  const steps = await guide(page, policy({ '/scan': 'scans' }, ['/scan/new']))
  await expect(steps).toHaveCount(4)
  await expect(steps.nth(1)).toContainText('Open New Scan, select the target')
  await expect(steps.nth(1).getByRole('link', { name: 'New Scan' })).toHaveAttribute('href', '/scan/new')
})

test('GUIDE-002 without New Scan the second step says so instead of a sentence with a hole in it', async ({ page }) => {
  const steps = await guide(page, policy({}, []))
  await expect(steps).toHaveCount(4)
  await expect(steps.nth(1)).toContainText('Starting a scan is not available to your account in this workspace.')
  await expect(steps.nth(1).getByRole('link')).toHaveCount(0)
  // No step is a sentence around a link that was not rendered.
  for (const text of await steps.allInnerTexts()) expect(text).not.toMatch(/Open\s*,|\s{2,},/)
})
