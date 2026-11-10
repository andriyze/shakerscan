import { expect, test, type Page } from '@playwright/test'

import { SCAN_PUBLIC_CONTRACT_SNAPSHOT } from '../../src/lib/scanContract.generated'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

// New Scan opened from a target with two live web addresses. Where batch submission is not
// offered (a managed deployment that does not list batch_scan) the target field was left empty.
// Mocked API; nothing is queued.
const SEVERAL = '/scan/new?targets=' + encodeURIComponent('http://app.example.test:443\nhttps://app.example.test')

const managedWithoutBatch = {
  schema: 'shakerscan.workspace-capabilities/v1',
  mode: 'managed',
  edition: 'Enterprise Edition',
  features: { scan: { state: 'enabled' }, targets: { state: 'enabled' } },
  navigation: { '/scan': 'scan', '/targets': 'targets' },
  ui_routes: ['/scan/new', '/targets'],
}

async function mock(page: Page) {
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async (route) => {
    const url = new URL(route.request().url())
    if (url.pathname === '/scan/contracts') return route.fulfill({ json: SCAN_PUBLIC_CONTRACT_SNAPSHOT })
    if (url.pathname === '/workers') return route.fulfill({ json: { count: 1, current_count: 1, stale_count: 0, pending_count: 0, fleet_uniform: true, stale_workers: [] } })
    if (url.pathname === '/targets/inventory') return route.fulfill({ json: { items: [], next_cursor: null, has_more: false } })
    if (url.pathname === '/credential-profiles') return route.fulfill({ json: { profiles: [], count: 0 } })
    if (url.pathname === '/request-collections') return route.fulfill({ json: { collections: [], count: 0 } })
    return route.fulfill({ json: {} })
  })
}

test('NEWSCAN-PREFILL-001 without batch submission a several-address link prefills one address', async ({ page }) => {
  await page.addInitScript((policy) => { window.__SHAKERSCAN_CAPABILITIES__ = policy as never }, managedWithoutBatch)
  await mock(page)
  await page.goto(SEVERAL)
  const field = page.getByLabel('Target URL or hostname')
  await expect(field).toHaveValue('https://app.example.test')
  await expect(page.getByLabel('Multiple targets')).toHaveCount(0)
  const notice = page.getByTestId('other-addresses-notice')
  await expect(notice).toContainText('2 web addresses')
  await expect(notice).toContainText('http://app.example.test:443')
  await field.fill('https://other.example.test')
  await expect(notice).toHaveCount(0)
})

test('NEWSCAN-PREFILL-002 with batch submission the same link opens the batch list', async ({ page }) => {
  await mock(page)
  await page.goto(SEVERAL)
  await expect(page.getByLabel('Target URLs (one per line)')).toHaveValue('http://app.example.test:443\nhttps://app.example.test')
  await expect(page.getByTestId('other-addresses-notice')).toHaveCount(0)
})
