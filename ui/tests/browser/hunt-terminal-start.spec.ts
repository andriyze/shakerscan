import { expect, test, type Page } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

// Browser contract fixture: the Hunts page over a scripted API with one target and no Hunts.
// A managed (Enterprise) workspace starts Hunts from the terminal; the open-source edition keeps
// the browser launcher. Nothing runs.
const id = '5c7c3dee-a91b-4de7-82c6-fc2353ac8c7d'
const target = { id, asset_id: id, name: 'Shop', url: 'https://shop.example.test', locator: 'shop.example.test',
  environment: 'production', is_active: true, connected_device: false, origin_count: 1, service_count: 0 }

const managedPolicy = {
  schema: 'shakerscan.workspace-capabilities/v1',
  mode: 'managed',
  edition: 'Enterprise Edition',
  features: { hunt: { state: 'enabled' }, targets: { state: 'enabled' } },
  navigation: { '/hunt': 'hunt', '/targets': 'targets' },
  ui_routes: ['/hunt', '/targets', '/targets/[^/]+/asset'],
}

async function fixture(page: Page, managed: boolean) {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  if (managed) await page.addInitScript((policy) => { window.__SHAKERSCAN_CAPABILITIES__ = policy as never }, managedPolicy)
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const path = new URL(route.request().url()).pathname
    if (path === '/hunts') return route.fulfill({ json: { hunts: [], total: 0 } })
    if (path === '/targets/inventory') return route.fulfill({ json: { targets: [target], total: 1, offset: 0, limit: 500 } })
    return route.fulfill({ json: { status: 'healthy', rows: [], profiles: [], total: 0, has_more: false } })
  })
  return errors
}

// A managed workspace's first render differs from the server's (the server cannot see the
// client-injected navigation list, so it renders every link), and React reports that one
// recoverable hydration mismatch (#418) on every managed page, this one included. Any other page
// error still fails the test.
const MANAGED_HYDRATION = /Minified React error #418\b/

test('HUNT-TERM-001 a managed workspace starts Hunts from the terminal, not the browser', async ({ page }) => {
  const allErrors = await fixture(page, true)
  const unexpectedErrors = () => allErrors.filter(message => !MANAGED_HYDRATION.test(message))
  await page.goto('/hunt', { waitUntil: 'domcontentloaded' })
  const hint = page.getByTestId('terminal-hunt-start')
  await expect(hint).toBeVisible()
  await expect(hint).toHaveText('Start Hunts from your terminal: shakerscan agent')
  await expect(page.getByRole('button', { name: 'New Hunt' })).toHaveCount(0)

  // A link that preselects a target opens no browser launcher either.
  await page.goto(`/hunt?target=${id}`, { waitUntil: 'domcontentloaded' })
  await expect(page.getByTestId('terminal-hunt-start')).toBeVisible()
  await expect(page.getByRole('heading', { name: 'New Hunt' })).toHaveCount(0)
  expect(unexpectedErrors()).toEqual([])
})

test('HUNT-TERM-002 the open-source edition keeps the browser launcher', async ({ page }) => {
  const errors = await fixture(page, false)
  await page.goto('/hunt', { waitUntil: 'domcontentloaded' })
  await expect(page.getByRole('button', { name: 'New Hunt' })).toBeVisible()
  await expect(page.getByTestId('terminal-hunt-start')).toHaveCount(0)
  await page.goto(`/hunt?target=${id}`, { waitUntil: 'domcontentloaded' })
  await expect(page.getByRole('heading', { name: 'New Hunt' })).toBeVisible()
  expect(errors).toEqual([])
})
