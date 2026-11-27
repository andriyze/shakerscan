import { expect, test, type Page } from '@playwright/test'

import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

// Browser contract fixture (synthetic, empty lists; nothing runs): list pages start their title
// at the same place, with the same shared header.
async function emptyApi(page: Page) {
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, (route) => route.fulfill({ json: {
    status: 'healthy', enabled: true, worker_count: 1, targets: [], devices: [], profiles: [], collections: [], policies: [],
    schedules: [], scans: [], total: 0, count: 0, offset: 0, limit: 25,
  } }))
}

async function titleBox(page: Page, path: string, title: string) {
  await page.goto(path, { waitUntil: 'domcontentloaded' })
  const heading = page.locator('main').getByRole('heading', { level: 1, name: title, exact: true })
  await expect(heading).toBeVisible()
  const main = (await page.locator('main').boundingBox())!
  const box = (await heading.boundingBox())!
  return { left: Math.round(box.x - main.x), top: Math.round(box.y - main.y) }
}

test('HEADER-001 Credentials, Request Collections and Connected Devices start their title where other list pages do', async ({ page }) => {
  await emptyApi(page)
  const reference = await titleBox(page, '/schedules', 'Schedules')
  for (const [path, title] of [['/credentials', 'Credentials'], ['/request-collections', 'Request Collections'], ['/devices', 'Connected Devices']]) {
    const box = await titleBox(page, path, title)
    expect(box, path).toEqual(reference)
  }
})
