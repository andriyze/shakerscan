import { expect, test, type Page } from '@playwright/test'
import type { HuntV2 } from '../../src/lib/huntV2'

import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

const hunt = '11111111-1111-4111-8111-111111111111'
const first = '22222222-2222-4222-8222-222222222222'
const later = '33333333-3333-4333-8333-333333333333'
const savedRun: HuntV2 = {
  hunt_id: hunt, target_id: '44444444-4444-4444-8444-444444444444',
  target_kind: 'web', objective: 'Review synthetic saved evidence', status: 'completed',
  budget_profile: 'fast', policy: { active_testing: false }, budget: {}, budget_used: {},
  actions: [], capabilities: [],
}

async function mockHistory(page: Page) {
  let empty = false
  const reads: string[] = []
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const path = new URL(route.request().url()).pathname
    // The page also reads its parent run. A health response here crashes the
    // surrounding page before the investigation component can be exercised.
    if (path === `/hunts/${hunt}`) return route.fulfill({ json: savedRun })
    if (path === `/hunts/${hunt}/http-transactions`) return route.fulfill({ json: {
      fidelity: 'complete', fidelity_detail: 'Synthetic empty archive',
      total: 0, archive_total: 0, transactions: [],
    } })
    if (path === `/hunts/${hunt}/query`) {
      const next = route.request().postDataJSON().cursor
      const ids = empty ? [] : next ? [later] : [first]
      return route.fulfill({ json: { hunt_id: hunt, supported: true,
        rows: ids.map(id => ({ node_type: 'authorization_proposal', attributes: { hunt_id: hunt, proposal_id: id } })),
        has_more: !empty && !next, next_cursor: !empty && !next ? 'page-two' : null } })
    }
    if (path.startsWith(`/hunts/${hunt}/authorization-investigations/`)) {
      const id = path.split('/').at(-1)!
      reads.push(id)
      return route.fulfill({ json: { hunt_id: hunt, proposal_id: id, route: `/saved/${id}`,
        explanation: `Saved evidence ${id}`, attempts: [], evidence_needed: [], limitations: [],
        deferral_recorded: false, selected_request_examined: false } })
    }
    // Unrelated widgets may report unavailable, but must never receive a fake
    // successful payload that violates their own response contract.
    return route.fulfill({ status: 404, json: { detail: 'No fixture for this read-only route' } })
  })
  return { reads, clear: () => { empty = true } }
}

test('history refresh reconciles later-page selection and clears empty evidence', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  const state = await mockHistory(page)
  await page.goto(`/hunt?run=${hunt}`)
  const panel = page.getByRole('region', { name: 'Investigation review' })
  const selector = panel.getByLabel('Saved investigation')
  await expect(panel.getByText(`Saved evidence ${first}`, { exact: true })).toBeVisible()
  await panel.getByRole('button', { name: /Load more investigations/ }).click()
  await selector.selectOption(later)
  await expect(panel.getByText(`Saved evidence ${later}`, { exact: true })).toBeVisible()
  await panel.getByRole('button', { name: 'Refresh history', exact: true }).click()
  await expect(selector).toHaveValue(first)
  await expect(panel.getByText(`Saved evidence ${first}`, { exact: true })).toBeVisible()
  await expect(panel.getByText(`Saved evidence ${later}`, { exact: true })).toHaveCount(0)
  const readsBefore = state.reads.length
  await panel.getByRole('button', { name: 'Refresh history', exact: true }).click()
  await expect.poll(() => state.reads.length).toBeGreaterThan(readsBefore)
  state.clear()
  await panel.getByRole('button', { name: 'Refresh history', exact: true }).click()
  await expect(panel.getByText(/No saved authorization proposals/)).toBeVisible()
  await expect(panel.getByText('Latest assessment', { exact: true })).toHaveCount(0)
  await expect(panel.getByText('Reading saved evidence…', { exact: true })).toHaveCount(0)
  expect(errors).toEqual([])
})
