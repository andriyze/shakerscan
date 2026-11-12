import { expect, test, type Page } from '@playwright/test'

import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

// Mocked spec (fixture data, not a live stack): the finding page's Accept risk dialog against
// the API shapes of GET /findings/{id}, GET /policy-profiles and POST /finding-exceptions.
const findingId = '7d1f2c3b-4a5e-4f60-8b7c-9d0e1f2a3b4c'
const targetId = '8e2a3b4c-5d6e-4f70-9a8b-0c1d2e3f4a5b'
const profileId = '9f3b4c5d-6e7f-4a81-8b9c-1d2e3f4a5b6c'

async function mockApi(page: Page, profiles: Record<string, unknown>[]) {
  const posts: Record<string, unknown>[] = []
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    if (path === `/findings/${findingId}`) {
      return route.fulfill({ json: {
        id: findingId, title: 'Exposed environment file', severity: 'high', status: 'active', tool: 'exposure',
        url: 'http://accept.fixture.test/.env', target_url: 'http://accept.fixture.test', target_id: targetId,
        fingerprint: 'fp-accept', first_seen_at: '2026-10-01T00:00:00Z', last_seen_at: '2026-10-10T00:00:00Z',
      } })
    }
    if (path === '/policy-profiles') return route.fulfill({ json: { policy_profiles: profiles } })
    if (path === '/finding-exceptions' && request.method() === 'POST') {
      const body = request.postDataJSON() as Record<string, unknown>
      posts.push(body)
      return route.fulfill({ json: { id: 'a0b1c2d3-e4f5-4a67-8b89-0c1d2e3f4a5b', ...body } })
    }
    if (path === '/finding-exceptions') return route.fulfill({ json: { finding_exceptions: [] } })
    return route.fulfill({ status: 503, json: { detail: 'fixture_unavailable' } })
  })
  return posts
}

async function fillDialog(page: Page) {
  await page.getByRole('button', { name: 'Accept risk…' }).click()
  const dialog = page.getByRole('dialog')
  await dialog.getByLabel('Owner').fill('payments team')
  await dialog.getByLabel('Approver').fill('security lead')
  await dialog.getByLabel('Reason').fill('Decommissioned host, removed next sprint')
  await dialog.getByLabel('Compensating controls').fill('Blocked at the edge')
  return dialog
}

test('with no policy profile configured, Accept risk creates an exception under the default policy', async ({ page }) => {
  const posts = await mockApi(page, [])
  await page.goto(`/findings/${findingId}`)
  const dialog = await fillDialog(page)
  await expect(dialog.getByTestId('exception-default-policy')).toContainText('default release policy')
  await expect(dialog.getByRole('combobox')).toHaveCount(0)
  const create = dialog.getByRole('button', { name: 'Create Exception' })
  await expect(create).toBeEnabled()
  await create.click()
  await expect(page.getByText('Policy exception created')).toBeVisible()
  expect(posts).toHaveLength(1)
  expect(posts[0].policy_id).toBeNull()
  expect(posts[0]).toMatchObject({ finding_id: findingId, target_id: targetId, owner: 'payments team', status: 'active' })
  expect(Date.parse(String(posts[0].expires_at))).toBeGreaterThan(Date.now())
})

test('with a policy profile configured, the exception must name it', async ({ page }) => {
  const posts = await mockApi(page, [{ id: profileId, name: 'Release gate', environment: 'production', is_active: true }])
  await page.goto(`/findings/${findingId}`)
  const dialog = await fillDialog(page)
  const create = dialog.getByRole('button', { name: 'Create Exception' })
  await expect(create).toBeDisabled()
  await dialog.getByLabel('Policy').selectOption(profileId)
  await create.click()
  await expect(page.getByText('Policy exception created')).toBeVisible()
  expect(posts[0].policy_id).toBe(profileId)
})

test('Create Exception stays off until every required field is filled', async ({ page }) => {
  const posts = await mockApi(page, [])
  await page.goto(`/findings/${findingId}`)
  await page.getByRole('button', { name: 'Accept risk…' }).click()
  const dialog = page.getByRole('dialog')
  const create = dialog.getByRole('button', { name: 'Create Exception' })
  await expect(create).toBeDisabled()
  await expect(dialog.getByTestId('exception-incomplete')).toBeVisible()
  await dialog.getByLabel('Owner').fill('payments team')
  await dialog.getByLabel('Approver').fill('security lead')
  await dialog.getByLabel('Reason').fill('Decommissioned host')
  await expect(create).toBeDisabled()
  // Blank text does not count as filled.
  await dialog.getByLabel('Compensating controls').fill('   ')
  await expect(create).toBeDisabled()
  await dialog.getByLabel('Compensating controls').fill('Blocked at the edge')
  await expect(create).toBeEnabled()
  await expect(dialog.getByTestId('exception-incomplete')).toHaveCount(0)
  await dialog.getByLabel('Expires in days').fill('0')
  await expect(create).toBeDisabled()
  await dialog.getByLabel('Expires in days').fill('14')
  await expect(create).toBeEnabled()
  expect(posts).toEqual([])
})
