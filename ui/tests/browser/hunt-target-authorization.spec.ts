import { expect, test, type Page } from '@playwright/test'
import { MOCK_API_ORIGIN, pinMockApiOrigin } from './mock-api-origin'

const id = '5c7c3dee-a91b-4de7-82c6-fc2353ac8c7d'
const otherId = '11111111-1111-4111-8111-111111111111'
const runId = '22222222-2222-4222-8222-222222222222'
const target = { id, asset_id: id, name: 'LG TV', url: 'host://192.168.1.187', locator: '192.168.1.187',
  environment: 'production', is_active: true, connected_device: false, origin_count: 0, service_count: 0 }
const standing = { approval_receipt_id: '33333333-3333-4333-8333-333333333333', scope_receipt_id: 'host-scope',
  standing: true, expires_at: null, approved_by: 'interactive-ui' }
const run = { hunt_id: runId, target_id: id, target_kind: 'network', target_name: 'LG TV',
  objective: 'Investigate TV ports', status: 'completed', budget_profile: 'balanced', policy: {},
  budget: {}, budget_used: {}, actions: [], capabilities: [] }

async function fixture(page: Page, options: { existing?: boolean; failRead?: boolean; failWrite?: boolean; credentials?: boolean; revokedOnStart?: boolean } = {}) {
  let saved = options.existing ? standing : null
  let reads = 0
  let failRead = options.failRead ?? false
  const writes: Array<{ path: string; body: Record<string, unknown> }> = []
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const request = route.request(), path = new URL(request.url()).pathname
    if (path === '/findings') return route.fulfill({ json: { findings: [], total: 0 } })
    if (path === `/hunts/${runId}`) return route.fulfill({ json: run })
    if (path === `/hunts/${runId}/http-transactions`) return route.fulfill({ json: { transactions: [], total: 0, archive_total: 0, fidelity: 'complete' } })
    // The run's review panel uses POST for a read-only evidence query.
    if (path === `/hunts/${runId}/query`) return route.fulfill({ json: { rows: [], has_more: false, supported: true } })
    if (request.method() === 'POST') writes.push({ path, body: request.postDataJSON() })
    if (path === '/targets/inventory') return route.fulfill({ json: { targets: [target, { ...target, id: otherId, asset_id: otherId, name: 'Other TV', locator: '192.168.1.188', url: 'host://192.168.1.188' }], total: 2, offset: 0, limit: 500 } })
    if (path === `/targets/${id}/authorization`) {
      if (request.method() === 'GET') {
        reads++
        if (failRead) { failRead = false; return route.fulfill({ status: 503, json: { detail: 'Authorization store unavailable' } }) }
        if (options.revokedOnStart && reads > 1) saved = null
      } else if (options.failWrite) return route.fulfill({ status: 409, json: { detail: 'Target scope changed; reload the target' } })
      else saved = standing
      return route.fulfill({ json: { target_id: id, authorization: saved } })
    }
    if (path === `/targets/${otherId}/authorization`) return route.fulfill({ json: { target_id: otherId, authorization: null } })
    if (path.endsWith('/skill')) return route.fulfill({ json: { target_id: path.split('/')[2], revision: 0,
      skill: null, operator_skill: null, knowledge: null, trust: 'none', max_characters: 12000 } })
    if (path === '/credential-profiles') return route.fulfill({ json: { profiles: options.credentials ? [{
      id: '44444444-4444-4444-8444-444444444444', name: 'Stored TV identity', target_id: id, target_kind: 'network',
      auth_kind: 'ssh_password', principal_slot: 'ssh', execution_compatible: true, is_active: true, configuration: {}, version: 1,
    }] : [] } })
    if (path === '/hunts') {
      if (request.method() === 'GET') return route.fulfill({ json: { hunts: [], total: 0 } })
      return route.fulfill({ headers: { 'x-shakerscan-hunt-contract': 'v2', 'access-control-expose-headers': 'x-shakerscan-hunt-contract' }, json: run })
    }
    return route.fulfill({ json: { status: 'healthy', rows: [], profiles: [], collections: [], requests: [], total: 0, has_more: false, revision: 0, skill: null, operator_skill: null, knowledge: null } })
  })
  await page.goto(`/hunt?target=${id}`)
  await page.getByLabel('Allow bounded active testing').check()
  return { writes, errors }
}

test('first Hunt saves one standing authorization for an owned production-cohort private host without manual receipts', async ({ page }) => {
  const state = await fixture(page)
  const submit = page.getByRole('button', { name: 'Open agent session' })
  await expect(submit).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Create approval for this target' })).toHaveCount(0)
  await expect(page.getByLabel('Approval receipt ID (optional override)')).toBeHidden()
  await expect(page.getByText('Production blocks private and loopback destinations.')).toHaveCount(0)
  await page.getByLabel(/I own or have explicit authorization/).check()
  await expect(submit).toBeEnabled()
  expect(state.writes).toEqual([])
  await submit.click()
  await expect(page).toHaveURL(new RegExp(`run=${runId}`))
  expect(state.writes.map(item => item.path)).toEqual([`/targets/${id}/authorization`, '/hunts'])
  expect(state.writes[0].body).toEqual({ approved_by: 'interactive-ui' })
  expect(state.writes[1].body).toMatchObject({ target_id: id, target_kind: 'network', policy: { active_testing: true, authorization_confirmed: true } })
  expect(state.writes[1].body.policy).not.toHaveProperty('approval_receipt_id')
  await page.goto(`/hunt?target=${id}`)
  await page.getByLabel('Allow bounded active testing').check()
  await expect(page.getByText('Testing is authorized for this target. Hunts and scans reuse its saved authorization.')).toBeVisible()
  await expect(page.getByLabel(/I own or have explicit authorization/)).toHaveCount(0)
  await page.getByRole('button', { name: 'Open agent session' }).click()
  await expect(page).toHaveURL(new RegExp(`run=${runId}`))
  expect(state.writes.filter(item => item.path.endsWith('/authorization'))).toHaveLength(1)
  expect(state.errors).toEqual([])
})

test('saved authorization covers selected SSH credentials without another prompt', async ({ page }) => {
  const state = await fixture(page, { existing: true, credentials: true })
  await expect(page.getByText('Testing is authorized for this target. Hunts and scans reuse its saved authorization.')).toBeVisible()
  await expect(page.getByLabel(/I own or have explicit authorization/)).toHaveCount(0)
  await page.getByRole('button', { name: 'SSH identity (optional)', exact: true }).click()
  await page.getByRole('option', { name: /Stored TV identity/ }).click()
  await page.getByRole('button', { name: 'Open agent session' }).click()
  await expect(page).toHaveURL(new RegExp(`run=${runId}`))
  expect(state.writes).toHaveLength(1)
  expect(state.writes[0].body.credential_refs).toMatchObject({ ssh_credential_profile_id: '44444444-4444-4444-8444-444444444444' })
  expect(state.errors).toEqual([])
})

test('failed authorization read is retried explicitly and cannot trigger a Hunt', async ({ page }) => {
  const state = await fixture(page, { failRead: true })
  await expect(page.getByRole('alert').filter({ hasText: 'Authorization store unavailable' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Open agent session' })).toBeDisabled()
  expect(state.writes).toEqual([])
  await page.getByRole('button', { name: 'Retry authorization check' }).click()
  await page.getByLabel(/I own or have explicit authorization/).check()
  await expect(page.getByRole('button', { name: 'Open agent session' })).toBeEnabled()
  expect(state.writes).toEqual([])
})

test('a refused authorization carries the server reason and never submits the Hunt', async ({ page }) => {
  const state = await fixture(page, { failWrite: true })
  await page.getByLabel(/I own or have explicit authorization/).check()
  await page.getByRole('button', { name: 'Open agent session' }).click()
  await expect(page.getByRole('alert').filter({ hasText: 'Target scope changed; reload the target' }).first()).toBeVisible()
  expect(state.writes.map(item => item.path)).toEqual([`/targets/${id}/authorization`])
})

test('revoked authorization is not silently granted again at Hunt submission', async ({ page }) => {
  const state = await fixture(page, { existing: true, revokedOnStart: true })
  await expect(page.getByText('Testing is authorized for this target. Hunts and scans reuse its saved authorization.')).toBeVisible()
  await page.getByRole('button', { name: 'Open agent session' }).click()
  await expect(page.getByRole('alert').filter({ hasText: 'authorization changed' }).first()).toBeVisible()
  await expect(page.getByLabel(/I own or have explicit authorization/)).not.toBeChecked()
  expect(state.writes).toEqual([])
})

test('changing targets clears confirmation and advanced receipt overrides', async ({ page }) => {
  const state = await fixture(page)
  await page.getByLabel(/I own or have explicit authorization/).check()
  await page.getByText('Advanced: limits, scope receipt and capability allowlist', { exact: true }).click()
  await page.getByLabel('Approval receipt ID (optional override)').fill(standing.approval_receipt_id)
  await page.getByLabel('Scope receipt ID (optional)').fill(standing.scope_receipt_id)
  await page.locator(`button[data-value="${id}"][aria-haspopup="listbox"]`).click()
  await page.getByRole('option', { name: /Other TV/ }).click()
  await expect(page.getByLabel(/I own or have explicit authorization/)).not.toBeChecked()
  await expect(page.getByLabel('Approval receipt ID (optional override)')).toHaveValue('')
  await expect(page.getByLabel('Scope receipt ID (optional)')).toHaveValue('')
  await expect(page.getByRole('button', { name: 'Open agent session' })).toBeDisabled()
  expect(state.writes).toEqual([])
})

test('invalid Hunt limits do not record authorization before validation', async ({ page }) => {
  const state = await fixture(page)
  await page.getByLabel(/I own or have explicit authorization/).check()
  await page.getByText('Advanced: limits, scope receipt and capability allowlist', { exact: true }).click()
  await page.getByLabel('Optional maximum duration (seconds)').fill('-1')
  await page.getByRole('button', { name: 'Open agent session' }).click()
  await expect(page.getByRole('alert').filter({ hasText: 'Maximum duration must be a positive whole number' }).first()).toBeVisible()
  expect(state.writes).toEqual([])
})

test('a saved run page does not issue the launcher authorization and credential reads', async ({ page }) => {
  // Opening a run selects its target for a later "New Hunt", but the launcher is not shown.
  // Its reads were still issued, and a viewer role is refused both (Enterprise soak D14).
  const launcherReads: string[] = []
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await pinMockApiOrigin(page)
  await page.route(`${MOCK_API_ORIGIN}/**`, async route => {
    const request = route.request(), path = new URL(request.url()).pathname
    if (path === `/targets/${id}/authorization` || path === '/credential-profiles') launcherReads.push(path)
    if (path === `/hunts/${runId}`) return route.fulfill({ json: run })
    if (path === `/hunts/${runId}/http-transactions`) return route.fulfill({ json: { transactions: [], total: 0, archive_total: 0, fidelity: 'complete' } })
    if (path === `/hunts/${runId}/query`) return route.fulfill({ json: { hunt_id: runId, rows: [], has_more: false, supported: true } })
    if (path === '/targets/inventory') return route.fulfill({ json: { targets: [target], total: 1, offset: 0, limit: 500 } })
    if (path === `/targets/${id}/authorization`) return route.fulfill({ json: { target_id: id, authorization: standing } })
    if (path === '/credential-profiles') return route.fulfill({ json: { profiles: [] } })
    return route.fulfill({ json: { status: 'healthy', rows: [], profiles: [], collections: [], requests: [], total: 0, has_more: false, revision: 0, skill: null, operator_skill: null, knowledge: null } })
  })
  const inventory = page.waitForRequest(request => new URL(request.url()).pathname === '/targets/inventory')
  await page.goto(`/hunt?run=${runId}`)
  await inventory
  await expect(page.getByText('Investigate TV ports').first()).toBeVisible()
  // Give the selection effects a render after the target list resolves.
  await page.waitForTimeout(500)
  expect(launcherReads).toEqual([])
  // The launcher itself still reads both for the same target.
  await page.goto(`/hunt?target=${id}`)
  await expect.poll(() => launcherReads.slice().sort()).toEqual(['/credential-profiles', `/targets/${id}/authorization`])
  expect(errors).toEqual([])
})
