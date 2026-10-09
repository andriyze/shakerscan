import { expect, test, type Page } from '@playwright/test'

import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

// External release audit, 2026-10-09 (R2): a masked export leaves a body out past its budget or
// size limit, or when it cannot be masked safely, and sends null for it. Both archive views must
// say which, never "No body recorded". The archive below is a fixture.
const hunt = '55555555-5555-4555-8555-555555555555'
const scan = '66666666-6666-4666-8666-666666666666'
const BUDGET = 'Body withheld from this export (size/budget limit)'
const UNMASKABLE = 'Body withheld: it could not be masked safely'

const archive = {
  fidelity: 'partial',
  fidelity_detail: 'Fixture: bodies left out of this export',
  total: 3,
  archive_total: 3,
  capture_stats: {},
  raw_har: { available: false, reason: 'Fixture deployment' },
  transactions: [
    {
      id: 'fixture-budget', method: 'GET', url: 'https://fixture.example.test/over-budget', status_code: 200,
      capability_name: 'http.request', request: { headers: {}, body: 'q=1', bytes: 3 },
      response: { headers: {}, body: null, bytes: 4096, sha256: null },
      payload_omitted: ['response_body'], payload_omitted_reasons: { response_body: 'masking_budget' },
    },
    {
      id: 'fixture-unmaskable', method: 'POST', url: 'https://fixture.example.test/unmaskable', status_code: 201,
      capability_name: 'http.request', request: { headers: {}, body: null, bytes: 12, sha256: null },
      response: { headers: {}, body: 'created', bytes: 7 },
      payload_omitted: ['request_body'], payload_omitted_reasons: { request_body: 'masking_failed' },
    },
    {
      id: 'fixture-empty', method: 'GET', url: 'https://fixture.example.test/no-content', status_code: 204,
      capability_name: 'http.request', request: { headers: {}, body: null, bytes: 0 },
      response: { headers: {}, body: null, bytes: 0 },
      payload_omitted: [], payload_omitted_reasons: {},
    },
  ],
}

async function mockApi(page: Page) {
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, route => {
    const path = new URL(route.request().url()).pathname
    if (path === `/hunts/${hunt}`) return route.fulfill({ json: {
      hunt_id: hunt, target_id: '77777777-7777-4777-8777-777777777777', target_kind: 'web',
      objective: 'Fixture run with withheld bodies', status: 'completed', budget_profile: 'fast',
      policy: { active_testing: false }, budget: {}, budget_used: {}, actions: [], capabilities: [],
    } })
    if (path === `/scans/${scan}`) return route.fulfill({ json: {
      id: scan, target_url: 'https://fixture.example.test', status: 'completed',
      created_at: '2026-10-09T00:00:00Z', completed_at: '2026-10-09T00:01:00Z', options: {}, result: {},
    } })
    if (path === `/hunts/${hunt}/http-transactions` || path === `/scans/${scan}/http-transactions`) {
      return route.fulfill({ json: archive })
    }
    return route.fulfill({ status: 404, json: { detail: 'No fixture for this read-only route' } })
  })
}

test('the Hunt request panel says why a body is missing', async ({ page }) => {
  await mockApi(page)
  await page.goto(`/hunt?run=${hunt}#requests`)

  await page.getByRole('button', { name: /\/over-budget/ }).click()
  await expect(page.getByText(BUDGET, { exact: true })).toBeVisible()

  await page.getByRole('button', { name: /\/unmaskable/ }).click()
  await expect(page.getByText(UNMASKABLE, { exact: true })).toBeVisible()

  // Only a body nobody left out reads as absent: the empty 204 and nothing else.
  await page.getByRole('button', { name: /\/no-content/ }).click()
  await expect(page.getByText('No body recorded', { exact: true })).toHaveCount(2)
  await expect(page.getByText(BUDGET, { exact: true })).toHaveCount(1)
  await expect(page.getByText(UNMASKABLE, { exact: true })).toHaveCount(1)
})

test('the scan archive browser marks a withheld body beside its size', async ({ page }) => {
  await mockApi(page)
  await page.goto(`/scans/${scan}`)
  await page.getByRole('tab', { name: /activity/i }).click()
  await page.getByText('Browse recorded calls', { exact: true }).click()

  await page.locator('summary', { hasText: '/over-budget' }).click()
  await expect(page.getByText(`4096 bytes · ${BUDGET}`, { exact: true })).toBeVisible()

  await page.locator('summary', { hasText: '/unmaskable' }).click()
  await expect(page.getByText(`12 bytes · ${UNMASKABLE}`, { exact: true })).toBeVisible()

  await page.locator('summary', { hasText: '/no-content' }).click()
  await expect(page.getByText(/Body withheld/)).toHaveCount(2)
})
