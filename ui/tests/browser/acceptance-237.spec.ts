import { expect, test, type Page } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

const id = '10000000-0000-4000-8000-000000000001'
const device = { id, name: 'Acceptance printer', primary_locator: '192.168.1.50', device_class: 'printer',
  identity_confidence: 'low', environment: 'internal', active_findings_count: 0, is_active: true,
  created_at: '2026-09-19T00:00:00Z', updated_at: '2026-09-19T00:00:00Z' }

async function deviceApi(page: Page, failure = false) {
  const deletes: string[] = []
  let retired = false
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    if (path === `/devices/${id}` && request.method() === 'DELETE') {
      deletes.push(path)
      if (failure) return route.fulfill({ status: 409, json: { detail: 'Retirement could not be saved' } })
      retired = true
      return route.fulfill({ json: { status: 'deactivated', device_id: id } })
    }
    if (path === '/devices') return route.fulfill({ json: { devices: retired ? [] : [device], total: retired ? 0 : 1 } })
    if (path === `/devices/${id}`) return route.fulfill({ json: { device, interfaces: [], locator_history: [], services: [], scans: [] } })
    if (path === '/devices/readiness') return route.fulfill({ json: { enabled: true, status: 'paused', reason: 'No device worker', remedy: './scanner.sh devices start' } })
    return route.fulfill({ json: { status: 'healthy', workers: [], policies: [], profiles: [], collections: [], runs: [], sessions: [], total: 0 } })
  })
  return deletes
}

test('retirement is available while scanning is paused and requires confirmation', async ({ page }) => {
  const deletes = await deviceApi(page)
  await page.goto('/devices')
  await page.getByRole('button', { name: `Retire ${device.name}`, exact: true }).click()
  const dialog = page.getByRole('dialog', { name: 'Retire connected device?' })
  await expect(dialog).toContainText('Existing scan results and evidence are kept')
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click()
  expect(deletes).toEqual([])
  await page.getByRole('button', { name: `Retire ${device.name}`, exact: true }).click()
  await dialog.getByRole('button', { name: 'Retire device', exact: true }).click()
  await expect(dialog).not.toBeVisible()
  await expect(page.getByRole('button', { name: `Retire ${device.name}`, exact: true })).toHaveCount(0)
  expect(deletes).toEqual([`/devices/${id}`])
})

test('failed retirement remains visible and does not remove the device', async ({ page }) => {
  const deletes = await deviceApi(page, true)
  await page.goto(`/devices/${id}`)
  await page.getByRole('button', { name: `Retire ${device.name}`, exact: true }).click()
  const dialog = page.getByRole('dialog', { name: 'Retire connected device?' })
  await dialog.getByRole('button', { name: 'Retire device', exact: true }).click()
  await expect(dialog.getByRole('alert')).toHaveText('Retirement could not be saved')
  expect(deletes).toEqual([`/devices/${id}`])
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click()
  await expect(page.getByRole('heading', { name: device.name, exact: true })).toBeVisible()
})

test('successful detail-page retirement returns to the active inventory', async ({ page }) => {
  await deviceApi(page)
  await page.goto(`/devices/${id}`)
  await page.getByRole('button', { name: `Retire ${device.name}`, exact: true }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Retire device', exact: true }).click()
  await expect(page).toHaveURL(/\/devices$/)
  await expect(page.getByRole('button', { name: `Retire ${device.name}`, exact: true })).toHaveCount(0)
})

for (const [status, message] of [['already_exists', 'Target already present'], ['created', 'Target added']]) {
  test(`target creation reports ${status} honestly`, async ({ page }) => {
    await pinMockApiOrigin(page)
    await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
      const path = new URL(route.request().url()).pathname
      if (path === '/targets' && route.request().method() === 'POST') return route.fulfill({ json: { status, id, url: 'https://example.test' } })
      if (path === '/targets/grouped') return route.fulfill({ json: { domains: [], total_targets: 0, total_root_domains: 0 } })
      return route.fulfill({ json: { status: 'healthy', workers: [], domains: [], targets: [], total: 0 } })
    })
    await page.goto('/targets')
    await page.getByRole('button', { name: 'Add Target', exact: true }).click()
    const dialog = page.getByRole('dialog', { name: 'Add Target' })
    await dialog.getByPlaceholder('https://example.com').fill('https://example.test')
    await dialog.getByRole('button', { name: 'Add Target', exact: true }).click()
    await expect(page.getByText(message, { exact: true })).toBeVisible()
  })
}
