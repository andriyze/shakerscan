import { expect, test } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

// Browser contract fixture: the real page and polling hook, a scripted API, no scan execution.
test('scan activity requests deltas and keeps the final cancellation lines', async ({ page }) => {
  const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
  let status = 'running'
  const cursors: Array<string | null> = []
  await pinMockApiOrigin(page)
  await page.clock.install()
  await page.route(`${MOCK_API_ORIGIN}/**`, route => route.fulfill({
    status: 503, json: { detail: 'fixture_unavailable' },
  }))
  await page.route(`${MOCK_API_ORIGIN}/scans/${id}`, route => route.fulfill({ json: {
    id, target_url: 'https://fixture.example.test', status, progress: 40,
    created_at: '2026-10-15T00:00:00Z', started_at: '2026-10-15T00:00:01Z',
    options: {}, result: { findings: [], risk_assessment_state: 'not_examined',
      application_observed: false, grade_reliable: false },
  } }))
  await page.route(`${MOCK_API_ORIGIN}/scans/${id}/logs?*`, route => {
    const cursor = new URL(route.request().url()).searchParams.get('after_seq')
    cursors.push(cursor)
    const next = status === 'cancelled' ? 3 : cursor === null ? 1 : 2
    const lines = next === 3 ? ['[scan] final settled activity']
      : next === 2 ? ['[scan] second activity'] : ['[scan] first activity']
    return route.fulfill({ json: { lines, seq_supported: true, next_seq: next,
      first_seq: next, truncated: false } })
  })
  await page.goto(`/scans/${id}`)
  await page.getByRole('button', { name: 'All logs', exact: true }).click()
  await expect(page.getByText('first activity', { exact: true })).toBeVisible()
  expect(cursors[0]).toBeNull()
  await page.clock.fastForward(5500)
  await expect(page.getByText('second activity', { exact: true })).toBeVisible()
  await expect(page.getByText('first activity', { exact: true })).toBeVisible()
  expect(cursors).toContain('1')
  status = 'cancelled'
  await page.clock.fastForward(5500)
  await expect(page.getByText('Scan cancelled', { exact: true })).toBeVisible()
  await page.getByRole('tab', { name: 'Activity', exact: true }).click()
  await expect(page.getByText('final settled activity', { exact: true })).toBeVisible()
  await expect(page.getByText('first activity', { exact: true })).toBeVisible()
  expect(cursors).toContain('2')
  const polls = cursors.length
  await page.clock.fastForward(120000)
  expect(cursors.length).toBe(polls)
})
