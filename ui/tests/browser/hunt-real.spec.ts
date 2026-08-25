import { expect, test } from '@playwright/test'

import { HUNT_BUDGET_DIMENSIONS } from '../../src/lib/huntContract.generated'
import { isApiResponse } from './real-stack-api'


const REAL_STACK = process.env.PLAYWRIGHT_REAL_STACK === '1'
const API_URL = process.env.SHAKERSCAN_API_URL || 'http://localhost:8080'
const FIXTURE_TARGET = process.env.SHAKERSCAN_E2E_HUNT_TARGET
  || 'http://host.docker.internal:18099'


test('production Hunt UI submits canonical passive V2 authority', async ({ page, request }) => {
  test.skip(!REAL_STACK, 'release-only real-stack Hunt UI acceptance')

  const createdTarget = await request.post(`${API_URL}/targets`, {
    data: {
      url: FIXTURE_TARGET,
      name: `Playwright Hunt release fixture ${Date.now()}`,
    },
  })
  expect(createdTarget.ok()).toBeTruthy()
  const target = await createdTarget.json()
  expect(target.id).toBeTruthy()

  await page.goto(`/hunt?target=${encodeURIComponent(target.id)}`)
  await expect(page.getByLabel('Target', { exact: true })).toHaveValue(target.id)
  await page.getByLabel('Objective').fill('Production UI real-stack Hunt acceptance.')
  await page.getByLabel('Budget profile').selectOption('fast')
  await page.getByText('Optional hard ceilings (zero disables a dimension)').click()
  for (const definition of HUNT_BUDGET_DIMENSIONS.filter((item) => item.zeroable)) {
    await page.getByLabel(definition.label).fill('0')
  }

  const [response] = await Promise.all([
    page.waitForResponse((candidate) => isApiResponse(candidate, API_URL, '/hunts')),
    page.getByRole('button', { name: 'Start Hunt' }).click(),
  ])
  expect(response.ok()).toBeTruthy()
  expect(response.headers()['x-shakerscan-hunt-contract']).toBe('v2')
  const payload = response.request().postDataJSON()
  expect(payload).toMatchObject({
    schema_version: 'hunt-start/v2',
    target_id: target.id,
    target_kind: 'web',
    goal: 'Production UI real-stack Hunt acceptance.',
    budget_profile: 'fast',
    policy: {
      active_testing: false,
      allow_state_changing_http: false,
      network_discovery: false,
      allow_oob_interactions: false,
      authorization_confirmed: false,
    },
    credential_refs: {},
    capabilities: [],
    request_collection_ids: [],
  })
  for (const definition of HUNT_BUDGET_DIMENSIONS.filter((item) => item.zeroable)) {
    expect(payload.budgets[definition.name]).toBe(0)
  }

  const hunt = await response.json()
  expect(hunt.hunt_id).toBeTruthy()
  await expect(page.getByText('Production UI real-stack Hunt acceptance.')).toBeVisible()
  const finished = await request.post(`${API_URL}/hunts/${hunt.hunt_id}/finish`, {
    data: {
      summary: 'Production UI acceptance completed.',
      next_actions: [],
    },
  })
  expect(finished.ok()).toBeTruthy()
})
