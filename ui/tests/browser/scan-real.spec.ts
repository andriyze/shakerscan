import { expect, test } from '@playwright/test'


const REAL_STACK = process.env.PLAYWRIGHT_REAL_STACK === '1'
const API_URL = process.env.SHAKERSCAN_API_URL || 'http://localhost:8080'
const FIXTURE_TARGET = process.env.SHAKERSCAN_E2E_SCAN_TARGET
  || process.env.SHAKERSCAN_E2E_HUNT_TARGET
  || 'http://host.docker.internal:18099'


test('production scan UI submits canonical V2 Scan contract', async ({ page, request }) => {
  test.skip(!REAL_STACK, 'release-only real-stack Scan UI acceptance')

  await page.goto('/scan/new')
  await page.getByLabel('Target URL or hostname').fill(FIXTURE_TARGET)
  await page.getByRole('button', { name: /Fast/ }).click()

  const [response] = await Promise.all([
    page.waitForResponse((candidate) => (
      candidate.url() === `${API_URL}/scans` && candidate.request().method() === 'POST'
    )),
    page.getByRole('button', { name: 'Run Scan' }).click(),
  ])
  expect(response.ok()).toBeTruthy()
  const payload = response.request().postDataJSON()
  expect(payload).toMatchObject({
    target: FIXTURE_TARGET,
    target_kind: 'web',
    budget_profile: 'fast',
    policy: {
      active_testing: false,
      allow_state_changing_http: false,
      subdomain_discovery: false,
      network_discovery: false,
    },
    request_collections: [],
    credential_profile_ids: [],
    advanced: {},
    options: { require_current_workers: false },
  })

  const scan = await response.json()
  expect(scan.scan_id).toBeTruthy()
  await expect(page).toHaveURL(new RegExp(`/scans/${scan.scan_id}$`))

  const cancelled = await request.post(`${API_URL}/scans/${scan.scan_id}/cancel`)
  expect(cancelled.ok()).toBeTruthy()
})
