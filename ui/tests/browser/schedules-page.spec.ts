// Browser contract fixture: the real /schedules page, a scripted API; no schedule or scan ever runs.
import { expect, test, type Page } from '@playwright/test'

import type { Schedule } from '../../src/lib/api'
import { mockPageApi, queryNames, unavailable, type MockedApi } from './mock-page-api'
import { visitAndAuditPage } from './page-quality'

const health = () => ({ status: 'healthy' })

function schedule(overrides: Partial<Schedule> = {}): Schedule {
  return {
    id: '11111111-1111-4111-8111-111111111111',
    target_id: '22222222-2222-4222-8222-222222222222',
    target_url: 'https://app.example.test',
    name: 'Nightly baseline',
    frequency: 'daily',
    time_of_day: '02:00',
    timezone: 'UTC',
    jitter_minutes: 15,
    schedule_kind: 'normal_scan',
    scan_type: 'scan',
    scan_options: { budget_profile: 'balanced' },
    is_active: true,
    next_run_at: '2099-01-01T02:00:00Z',
    schedule_health: { status: 'ok' },
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  }
}

const enabledDaily = schedule()
const pausedWeekly = schedule({
  id: '33333333-3333-4333-8333-333333333333',
  target_url: 'https://portal.example.test',
  name: 'Weekly portal',
  frequency: 'weekly',
  day_of_week: 2,
  is_active: false,
  last_run_at: '2026-01-02T02:00:00Z',
  schedule_health: {
    status: 'attention', recent_failed_count: 2, lookback_days: 7,
    latest_error: 'Synthetic fixture timeout.', latest_failed_scan_id: '44444444-4444-4444-8444-444444444444',
    recommendation: 'Use a smaller budget.',
  },
})

async function mockSchedules(page: Page, schedules: Schedule[] | (() => unknown)): Promise<MockedApi> {
  return mockPageApi(page, {
    'GET /health': health,
    'GET /schedules': typeof schedules === 'function' ? schedules : () => ({ schedules, total: schedules.length }),
  })
}

const scheduleReads = (api: MockedApi) => api.requests.filter((entry) => entry.startsWith('GET /schedules')).length

async function expectNoHorizontalOverflow(page: Page) {
  const layout = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }))
  expect(layout.scrollWidth, 'horizontal page overflow').toBeLessThanOrEqual(layout.clientWidth)
}

test('populated schedules list renders each schedule, its health and its pause state', async ({ page }) => {
  const api = await mockSchedules(page, [enabledDaily, pausedWeekly])
  await visitAndAuditPage(page, '/schedules')
  await expect(page.getByRole('heading', { name: 'Schedules' })).toBeVisible()
  await expect(page.getByText('app.example.test', { exact: true })).toBeVisible()
  await expect(page.getByText('(Nightly baseline)')).toBeVisible()
  await expect(page.getByText('portal.example.test', { exact: true })).toBeVisible()
  await expect(page.getByText('Weekly Wednesday')).toBeVisible()
  await expect(page.getByText('Paused — no next run')).toBeVisible()
  await expect(page.getByText('Schedule needs attention')).toBeVisible()
  await expect(page.getByText(/Synthetic fixture timeout\./)).toBeVisible()
  await expect(page.getByRole('link', { name: 'Failed scan' })).toHaveAttribute('href', '/scans/44444444-4444-4444-8444-444444444444')
  const switches = page.getByRole('switch', { name: 'Schedule enabled' })
  await expect(switches).toHaveCount(2)
  await expect(switches.nth(0)).toHaveAttribute('aria-checked', 'true')
  await expect(switches.nth(1)).toHaveAttribute('aria-checked', 'false')
  await expect(page.getByRole('button', { name: 'Needs attention (1)' })).toBeVisible()

  // The status filter is sent as is_active.
  await page.getByLabel('Filter schedules by status').selectOption('active')
  await expect.poll(() => api.requests.some((entry) => entry.includes('is_active=true'))).toBe(true)
  expect(api.unhandled).toEqual([])
  expect(queryNames(api, '/schedules')).toEqual(['is_active'])
})

test('empty schedules list offers to create the first one', async ({ page }) => {
  const api = await mockSchedules(page, [])
  await visitAndAuditPage(page, '/schedules')
  await expect(page.getByText('No schedules yet. Create one to automate your scans.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Create schedule' })).toBeVisible()
  expect(api.unhandled).toEqual([])
  expect(queryNames(api, '/schedules')).toEqual([])
})

test('a failed schedules read shows the error state and retry recovers', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  let fail = true
  await mockSchedules(page, () => (fail ? unavailable() : { schedules: [enabledDaily], total: 1 }))
  await page.goto('/schedules')
  await expect(page.getByText('Failed to load schedules. Is the API running?')).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Schedules' })).toBeVisible()
  await expect(page.locator('body')).not.toContainText('Application error')
  fail = false
  await page.getByRole('button', { name: /retry/i }).click()
  await expect(page.getByText('app.example.test', { exact: true })).toBeVisible()
  expect(errors).toEqual([])
})

test('schedules refresh every 30 s while one is enabled', async ({ page }) => {
  await page.clock.install()
  const api = await mockSchedules(page, [enabledDaily, pausedWeekly])
  await page.goto('/schedules')
  await expect(page.getByText('app.example.test', { exact: true })).toBeVisible()
  const before = scheduleReads(api)
  await page.clock.fastForward(31_000)
  await expect.poll(() => scheduleReads(api)).toBeGreaterThan(before)
  expect(api.unhandled).toEqual([])
})

test('schedules stop refreshing when every listed schedule is paused', async ({ page }) => {
  await page.clock.install()
  const api = await mockSchedules(page, [pausedWeekly])
  await page.goto('/schedules')
  await expect(page.getByText('portal.example.test', { exact: true })).toBeVisible()
  const before = scheduleReads(api)
  await page.clock.fastForward(95_000)
  await page.waitForTimeout(300)
  expect(scheduleReads(api)).toBe(before)
  expect(api.unhandled).toEqual([])
})

test('schedules fit a phone viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const api = await mockSchedules(page, [enabledDaily, pausedWeekly])
  await page.goto('/schedules')
  await expect(page.getByText('app.example.test', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'New Schedule' })).toBeVisible()
  await expect(page.getByText('Schedule needs attention')).toBeVisible()
  await expectNoHorizontalOverflow(page)
  expect(api.unhandled).toEqual([])
})
