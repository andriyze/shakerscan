// Browser contract fixture: the real /timeline page, a scripted API; no scan, schedule or Hunt ever runs.
import { expect, test, type Page } from '@playwright/test'

import type { TimelineEvent, TimelineResponse } from '../../src/lib/api'
import { mockPageApi, queryNames, unavailable, type MockAnswer, type MockedApi } from './mock-page-api'
import { visitAndAuditPage } from './page-quality'

const TARGET = '22222222-2222-4222-8222-222222222222'

function event(overrides: Partial<TimelineEvent> & Pick<TimelineEvent, 'event_id' | 'kind' | 'status'>): TimelineEvent {
  return { target_id: TARGET, target_url: 'https://app.example.test', created_at: '2026-01-02T03:04:05Z', ...overrides }
}

const completedScan = event({
  event_id: 'scan:11111111-1111-4111-8111-111111111111', kind: 'scan', command: 'scan.submit', status: 'completed',
  scan_id: '11111111-1111-4111-8111-111111111111', finding_ids: ['f-1', 'f-2'],
  operator_message: 'Synthetic fixture scan finished.',
})
const blockedAction = event({
  event_id: 'action:33333333-3333-4333-8333-333333333333', kind: 'campaign_action', action_name: 'Asm.improve',
  status: 'blocked', blocked_by: ['scope_receipt'], campaign_id: '44444444-4444-4444-8444-444444444444', risk_tier: 'low',
})
const runningScan = event({
  event_id: 'scan:55555555-5555-4555-8555-555555555555', kind: 'scan', command: 'scan.submit', status: 'running',
  scan_id: '55555555-5555-4555-8555-555555555555',
})
const upcomingSchedule = event({
  event_id: 'schedule:66666666-6666-4666-8666-666666666666', kind: 'schedule', status: 'scheduled',
  name: 'Nightly baseline', frequency: 'daily', time_of_day: '02:00', timezone: 'UTC', jitter_minutes: 15,
  next_eligible_at: '2099-01-01T02:00:00Z', schedule_id: '66666666-6666-4666-8666-666666666666',
})

function timeline(events: TimelineEvent[], upcoming: TimelineEvent[] = []): TimelineResponse {
  return { events, upcoming, count: events.length, statuses: [], execution_enabled: false }
}

// The target picker reads one list/v1 page of the inventory.
const inventory = () => ({ items: [], has_more: false, next_cursor: null, total_kind: 'none', generated_at: '2026-01-01T00:00:00Z' })

async function mockTimeline(page: Page, answer: () => MockAnswer): Promise<MockedApi> {
  return mockPageApi(page, {
    'GET /health': () => ({ status: 'healthy' }),
    'GET /targets/inventory': inventory,
    'GET /timeline': answer,
  })
}

const timelineReads = (api: MockedApi) => api.requests.filter((entry) => entry.startsWith('GET /timeline')).length

async function expectNoHorizontalOverflow(page: Page) {
  const layout = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }))
  expect(layout.scrollWidth, 'horizontal page overflow').toBeLessThanOrEqual(layout.clientWidth)
}

test('populated timeline lists recent activity and upcoming work with links', async ({ page }) => {
  const api = await mockTimeline(page, () => timeline([completedScan, blockedAction], [upcomingSchedule]))
  await visitAndAuditPage(page, '/timeline')
  await expect(page.getByRole('heading', { name: 'Timeline', level: 1 })).toBeVisible()
  await expect(page.getByText('Recent activity (2)')).toBeVisible()
  await expect(page.getByText('Upcoming (1)')).toBeVisible()
  await expect(page.getByText('Scan completed')).toBeVisible()
  await expect(page.getByText('Synthetic fixture scan finished.')).toBeVisible()
  await expect(page.getByText('2 findings')).toBeVisible()
  await expect(page.getByText('Coverage work queued')).toBeVisible()
  await expect(page.getByText('blocked by: scope_receipt')).toBeVisible()
  await expect(page.getByText('Scheduled rule: daily · 02:00 UTC')).toBeVisible()
  await expect(page.getByText('Dispatch jitter: ±15 min')).toBeVisible()
  const opens = page.getByRole('link', { name: 'Open →' })
  await expect(opens).toHaveCount(2)
  await expect(page.locator('a[href="/scans/11111111-1111-4111-8111-111111111111"]')).toBeVisible()
  await expect(page.locator('a[href="/deep-hunt/runs/44444444-4444-4444-8444-444444444444"]')).toBeVisible()

  // A category toggle turned off is sent as include_<kind>=false.
  await page.getByRole('button', { name: 'Scans', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Scans', exact: true })).toHaveAttribute('aria-pressed', 'false')
  await expect.poll(() => api.requests.some((entry) => entry.includes('include_scans=false'))).toBe(true)
  expect(api.unhandled).toEqual([])
  expect(queryNames(api, '/timeline')).toEqual(['include_scans', 'limit'])
  expect(queryNames(api, '/targets/inventory')).toEqual(['count', 'include_services', 'limit'])
})

test('empty timeline explains what will appear', async ({ page }) => {
  const api = await mockTimeline(page, () => timeline([]))
  await visitAndAuditPage(page, '/timeline')
  await expect(page.getByText('Recent activity (0)')).toBeVisible()
  await expect(page.getByText('No timeline events')).toBeVisible()
  await expect(page.getByText(/Upcoming \(/)).toHaveCount(0)
  expect(api.unhandled).toEqual([])
  expect(queryNames(api, '/timeline')).toEqual(['limit'])
})

test('a failed timeline read shows the error state and retry recovers', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  let fail = true
  await mockTimeline(page, () => (fail ? unavailable() : timeline([completedScan])))
  await page.goto('/timeline')
  await expect(page.getByRole('alert').filter({ hasText: 'Failed to load the mission timeline.' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Timeline', level: 1 })).toBeVisible()
  await expect(page.locator('body')).not.toContainText('Application error')
  fail = false
  await page.getByRole('button', { name: 'Retry' }).click()
  await expect(page.getByText('Scan completed')).toBeVisible()
  expect(errors).toEqual([])
})

test('timeline refreshes every 15 s while an event is in flight', async ({ page }) => {
  await page.clock.install()
  const api = await mockTimeline(page, () => timeline([runningScan, completedScan]))
  await page.goto('/timeline')
  await expect(page.getByText('Scan running')).toBeVisible()
  const before = timelineReads(api)
  await page.clock.fastForward(16_000)
  await expect.poll(() => timelineReads(api)).toBeGreaterThan(before)
  expect(api.unhandled).toEqual([])
})

test('a settled timeline only refreshes on the slow 60 s pace', async ({ page }) => {
  await page.clock.install()
  const api = await mockTimeline(page, () => timeline([completedScan, blockedAction]))
  await page.goto('/timeline')
  await expect(page.getByText('Scan completed')).toBeVisible()
  const before = timelineReads(api)
  await page.clock.fastForward(20_000)
  await page.waitForTimeout(300)
  expect(timelineReads(api)).toBe(before)
  await page.clock.fastForward(45_000)
  await expect.poll(() => timelineReads(api)).toBeGreaterThan(before)
  expect(api.unhandled).toEqual([])
})

test('timeline fits a phone viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  const api = await mockTimeline(page, () => timeline([completedScan, blockedAction], [upcomingSchedule]))
  await page.goto('/timeline')
  await expect(page.getByText('Scan completed')).toBeVisible()
  await expect(page.getByText('Upcoming (1)')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Hunt activity' })).toBeVisible()
  await expectNoHorizontalOverflow(page)
  expect(api.unhandled).toEqual([])
})
