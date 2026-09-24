import { expect, test, type Page } from '@playwright/test'
import type { HuntV2 } from '../../src/lib/huntV2'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

const id = '11111111-1111-4111-8111-111111111111'
const initial: HuntV2 = {
  hunt_id: id, target_id: '22222222-2222-4222-8222-222222222222', target_kind: 'network',
  objective: 'Investigate all ports on the authorized asset', status: 'budget_exhausted',
  stop_reason: 'budget_exhausted:tcp_ports_attempted', budget_profile: 'thorough',
  budget_revision: 0, budget_amendable_dimensions: ['max_tcp_ports', 'max_http_requests'],
  policy: { active_testing: true, network_discovery: true },
  budget: { max_tcp_ports: 10000, max_http_requests: 20000 },
  budget_used: { tcp_ports_attempted: 10000, http_requests: 7 }, capabilities: [], actions: [],
}

async function fixture(page: Page, mode: 'success' | 'lost-response' | 'conflict' = 'success') {
  let run = structuredClone(initial)
  const writes: Record<string, unknown>[] = []
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    if (path === `/hunts/${id}`) return route.fulfill({ json: run })
    if (path === `/hunts/${id}/resume`) {
      run = { ...run, status: 'active', stop_reason: null }
      return route.fulfill({ json: run })
    }
    if (path === `/hunts/${id}/budget-amendments`) {
      writes.push(request.postDataJSON())
      if (mode === 'conflict') {
        run = { ...run, budget_revision: 1, budget: { ...run.budget, max_tcp_ports: 12000 } }
        return route.fulfill({ status: 409, json: { detail: { message: 'Hunt budget changed; refresh before extending' } } })
      }
      run = { ...run, budget_revision: 1, budget: { ...run.budget, max_tcp_ports: 65535 },
        status: request.postDataJSON().resume ? 'awaiting_planner' : 'budget_exhausted',
        stop_reason: request.postDataJSON().resume ? null : initial.stop_reason }
      // The server committed, but the first response did not reach the operator.
      if (mode === 'lost-response' && writes.length === 1) return route.abort('failed')
      return route.fulfill({ json: { budget_revision: 1, status: run.status,
        replayed: writes.length > 1, device_traffic_frozen: false } })
    }
    if (path === `/hunts/${id}/http-transactions`) return route.fulfill({ json: {
      fidelity: 'complete', fidelity_detail: 'Synthetic empty archive', total: 0, archive_total: 0, transactions: [],
    } })
    if (path === `/hunts/${id}/query`) return route.fulfill({ json: { rows: [], has_more: false, next_cursor: null, supported: true } })
    if (path === `/hunts/${id}/skills/suggestions`) return route.fulfill({ json: { suggestions: [], count: 0 } })
    return route.fulfill({ status: 404, json: { detail: 'No fixture for this unrelated route' } })
  })
  await page.goto(`/hunt?run=${id}`)
  const panel = page.getByRole('region', { name: 'Hunt budget extension' })
  await expect(panel).toBeVisible()
  expect(writes).toHaveLength(0)
  await panel.getByLabel('Budget dimension', { exact: true }).selectOption('max_tcp_ports')
  await panel.getByLabel('New total budget').fill('65535')
  return { panel, writes, errors, current: () => run }
}

test('operator extends a total and resumes the same Hunt without resetting usage', async ({ page }) => {
  const state = await fixture(page)
  await state.panel.getByRole('button', { name: 'Extend budget', exact: true }).click()
  await expect(state.panel.getByRole('status', { name: 'Budget result', exact: true })).toContainText('Budget updated')
  expect(state.writes).toHaveLength(1)
  expect(state.writes[0]).toMatchObject({ schema_version: 'hunt-budget-amendment/v1',
    expected_revision: 0, limits: { max_tcp_ports: 65535 }, operator_confirmed: true, resume: true })
  expect(state.writes[0].idempotency_key).toEqual(expect.any(String))
  expect(state.current().budget_used).toEqual(initial.budget_used)
  await expect(page.getByText('thorough (amended)', { exact: true })).toBeVisible()
  expect(state.errors).toEqual([])
})

test('a lost response retries with the same key rather than applying a second increase', async ({ page }) => {
  const state = await fixture(page, 'lost-response')
  await state.panel.getByRole('button', { name: 'Extend budget', exact: true }).click()
  await expect(state.panel.getByRole('alert')).toBeVisible()
  expect(state.writes).toHaveLength(1)
  await state.panel.getByRole('button', { name: 'Extend budget', exact: true }).click()
  await expect(state.panel.getByRole('status', { name: 'Budget result', exact: true })).toContainText('Budget updated')
  expect(state.writes).toHaveLength(2)
  expect(state.writes[1]).toEqual(state.writes[0])
  expect(state.current().budget_revision).toBe(1)
  expect(state.errors).toEqual([])
})

test('conflicting revision is visible and never triggers an automatic budget increase', async ({ page }) => {
  const state = await fixture(page, 'conflict')
  await state.panel.getByRole('button', { name: 'Extend budget', exact: true }).click()
  await expect(state.panel.getByRole('alert')).toContainText('Hunt budget changed')
  await state.panel.getByRole('button', { name: 'Refresh budget', exact: true }).click()
  await expect(state.panel.getByText(/Budget revision 1/)).toBeVisible()
  expect(state.writes).toHaveLength(1)
  expect(state.errors).toEqual([])
})


test('operator can extend first and resume later without increasing twice', async ({ page }) => {
  const state = await fixture(page)
  await state.panel.getByRole('checkbox').uncheck()
  await state.panel.getByRole('button', { name: 'Extend budget', exact: true }).click()
  await expect(state.panel.getByRole('status', { name: 'Budget result', exact: true })).toContainText('Resume this Hunt when you are ready')
  expect(state.current().status).toBe('budget_exhausted')
  await state.panel.getByRole('button', { name: 'Resume with current budget', exact: true }).click()
  await expect(state.panel.getByRole('status', { name: 'Budget result', exact: true })).toContainText('Hunt resumed')
  expect(state.current().status).toBe('active')
  expect(state.writes).toHaveLength(1)
  expect(state.current().budget_revision).toBe(1)
  expect(state.current().budget_used).toEqual(initial.budget_used)
  expect(state.errors).toEqual([])
})
