import { expect, test, type Page } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

const id = '00000000-0000-4000-8000-000000000391'
const device = { id, name: 'Living room TV', primary_locator: 'tv.example.test',
  device_class: 'media', is_active: true, metadata_json: {}, active_findings_count: 0 }

async function mock(page: Page, initial: string) {
  let status = initial
  let writes = 0
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const request = route.request(), path = new URL(request.url()).pathname
    if (!['GET', 'OPTIONS'].includes(request.method())) writes++
    if (path === '/devices/readiness') return route.fulfill({ json: {
      enabled: true, status, worker_count: status === 'ready' ? 1 : 0,
      remedy: status === 'not_ready' ? 'Run shakerscan devices start. Check shakerscan devices logs if startup fails.' : null,
    } })
    if (path === '/devices') return route.fulfill({ json: { devices: [device], total: 1 } })
    if (path === `/devices/${id}`) return route.fulfill({ json: {
      device, interfaces: [], services: [], scans: [], locator_history: [],
    } })
    return route.fulfill({ json: { status: 'healthy', profiles: [], collections: [], policies: [], runs: [], total: 0 } })
  })
  return { ready: () => { status = 'ready' }, writes: () => writes }
}

for (const view of ['list', 'detail']) {
  test(`NETWORK-001 ${view} startup is informational and automatically enables scans`, async ({ page }) => {
    const fixture = await mock(page, 'starting')
    await page.goto(view === 'list' ? '/devices' : `/devices/${id}`)
    await expect(page.getByText(/Network scanning is starting/)).toBeVisible()
    await expect(page.getByText(/Network scanning is starting/).locator('..').locator('..')).toHaveAttribute('role', 'status')
    await expect(page.getByText('Troubleshooting', { exact: true })).toHaveCount(0)
    const scan = page.getByRole('button', { name: view === 'list' ? 'Scan' : 'Start network scan', exact: true })
    await expect(scan).toBeDisabled()
    fixture.ready()
    await expect(scan).toBeEnabled({ timeout: 15_000 })
    await expect(page.getByText(/Network scanning is starting/)).toHaveCount(0)
    expect(fixture.writes()).toBe(0)
  })

  test(`NETWORK-002 ${view} unavailable capacity shows concise copy with installed CLI diagnostics`, async ({ page }) => {
    const fixture = await mock(page, 'not_ready')
    await page.goto(view === 'list' ? '/devices' : `/devices/${id}`)
    const banner = page.getByRole('alert').filter({ hasText: 'Network scanning is unavailable' })
    await expect(banner).toBeVisible()
    await expect(page.getByText('Run shakerscan devices start.', { exact: false })).toBeHidden()
    await banner.getByText('Troubleshooting', { exact: true }).click()
    await expect(banner.getByText(/Run shakerscan devices start/)).toBeVisible()
    await expect(banner).not.toContainText('./scanner.sh')
    await expect(banner).not.toContainText('Nmap')
    expect(fixture.writes()).toBe(0)
  })
}
