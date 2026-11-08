// Browser contract fixture: the Schedules page names targets (2.12.1). Scripted API; no schedule
// or scan ever runs.
import { expect, test } from '@playwright/test'

import { mockPageApi } from './mock-page-api'

const juice = { id: '55555555-5555-4555-8555-555555555555', name: 'Juice Shop (lab)', url: 'http://10.0.0.4:3000',
  is_active: true, root_domain: null, discovery_source: 'manual' }
const port = { id: '66666666-6666-4666-8666-666666666666', name: 'http://shop.example.test:2052', url: 'http://shop.example.test:2052',
  is_active: true, root_domain: 'example.test', discovery_source: 'network_discovery' }
const existing = {
  id: '11111111-1111-4111-8111-111111111111', target_id: juice.id, target_url: juice.url, target_name: juice.name,
  name: 'Nightly', frequency: 'daily', time_of_day: '02:00', timezone: 'UTC', jitter_minutes: 15,
  schedule_kind: 'normal_scan', scan_type: 'scan', scan_options: {}, is_active: true,
  next_run_at: '2099-01-01T02:00:00Z', schedule_health: { status: 'ok' },
  created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
}

for (const width of [390, 1440]) {
  test(`SCHEDULE-NAMES-001 schedules and the target picker show names at ${width} px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 })
    await mockPageApi(page, {
      'GET /health': () => ({ status: 'healthy' }),
      'GET /schedules': () => ({ schedules: [existing], total: 1 }),
      'GET /targets/inventory': (url) => {
        const term = (url.searchParams.get('search') || '').toLowerCase()
        const items = [juice, port].filter((target) => !term || `${target.name} ${target.url}`.toLowerCase().includes(term))
        return { items, next_cursor: null, has_more: false }
      },
      'GET /targets/assets': () => ({ items: [], next_cursor: null, has_more: false }),
    })
    await page.goto('/schedules')
    // The schedule row leads with the target's name, not its origin URL.
    await expect(page.getByText('Juice Shop (lab)', { exact: true })).toBeVisible()
    await page.getByRole('button', { name: /New Schedule/i }).first().click()
    await page.locator('#schedule-target').click()
    const listbox = page.getByRole('listbox')
    await expect(listbox.getByRole('option', { name: /Juice Shop \(lab\)/ })).toBeVisible()
    // A target whose name only repeats its URL shows the host, with the URL underneath.
    await expect(listbox.getByRole('option', { name: /^shop\.example\.test:2052/ })).toBeVisible()
    // Searchable by name.
    await page.getByPlaceholder('Search targets by name or host…').fill('juice')
    await expect(listbox.getByRole('option', { name: /shop\.example\.test:2052/ })).toHaveCount(0)
    await listbox.getByRole('option', { name: /Juice Shop \(lab\)/ }).click()
    await expect(page.locator('#schedule-target')).toContainText('Juice Shop (lab)')
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
    expect(overflow).toBeLessThanOrEqual(0)
  })
}
