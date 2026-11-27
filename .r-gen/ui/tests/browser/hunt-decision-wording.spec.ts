import { expect, test, type Page } from '@playwright/test'
import type { HuntV2 } from '../../src/lib/huntV2'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

// The Hunt page (2.12.1): the capability-call card states a count with its limit underneath, and a
// pending permission request names whose decision it is (the person running the Hunt, in their
// terminal) with a copy button for the command. Mocked API; nothing runs.
const id = '11111111-1111-4111-8111-111111111112'
const run = {
  hunt_id: id, target_id: '22222222-2222-4222-8222-222222222222', target_kind: 'web',
  objective: 'Find stored XSS on the support portal', status: 'active', budget_profile: 'balanced',
  policy: { active_testing: true }, budget: { max_capability_calls: 14400, max_http_requests: 20000 },
  budget_used: { agent_actions: 23, http_requests: 120 }, capabilities: [], actions: [],
  created_at: '2026-11-07T00:00:00Z',
  pending_permission_requests: [{ id: 'req-1', kind: 'active.http_write', title: 'Send a POST to /support/ticket' }],
} as unknown as HuntV2

async function fixture(page: Page) {
  await pinMockApiOrigin(page)
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write'])
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const path = new URL(route.request().url()).pathname
    if (path === `/hunts/${id}`) return route.fulfill({ json: run })
    if (path === `/hunts/${id}/http-transactions`) return route.fulfill({ json: {
      fidelity: 'complete', fidelity_detail: 'Synthetic empty archive', total: 0, archive_total: 0, transactions: [] } })
    if (path === `/hunts/${id}/permission-requests`) return route.fulfill({ json: { requests: [], count: 0 } })
    if (path === `/hunts/${id}/query`) return route.fulfill({ json: { rows: [], has_more: false, next_cursor: null, supported: true } })
    return route.fulfill({ status: 404, json: { detail: 'No fixture for this unrelated route' } })
  })
}

for (const width of [390, 1440]) {
  test(`HUNT-WORDS-001 capability calls and a terminal decision read plainly at ${width} px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 })
    await fixture(page)
    await page.goto(`/hunt?run=${id}`)
    const calls = page.getByRole('button', { name: /Capability calls/ })
    await expect(calls).toContainText('23')
    await expect(calls).toContainText('limit 14,400')
    await expect(calls).not.toContainText('/')
    const decision = page.getByRole('region', { name: 'Waiting for a decision in the terminal' })
    await expect(decision).toBeVisible()
    await expect(decision.getByTestId('permission-decision-owner')).toContainText('the person running this Hunt from their terminal')
    await expect(page.getByRole('region', { name: 'Needs your decision' })).toHaveCount(0)
    await decision.getByRole('button', { name: 'Copy command' }).click()
    await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe('shakerscan approve req-1')
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
    expect(overflow).toBeLessThanOrEqual(0)
  })
}
