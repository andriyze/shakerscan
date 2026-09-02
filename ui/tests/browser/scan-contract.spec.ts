import { expect, test } from '@playwright/test'

import { SCAN_PUBLIC_CONTRACT_SNAPSHOT } from '../../src/lib/scanContract.generated'


const target = {
  id: '11111111-1111-4111-8111-111111111111',
  url: 'https://juice-shop.example.test',
  name: 'Juice Shop',
  root_domain: 'example.test',
  is_root: true,
  discovery_source: 'manual',
  is_active: true,
  total_scans: 3,
  active_findings_count: 1,
  created_at: '2026-08-25T00:00:00Z',
}

const credential = {
  id: '22222222-2222-4222-8222-222222222222',
  target_kind: 'web',
  target_id: target.id,
  name: 'Migrated primary user',
  auth_kind: 'authorization_header',
  principal_slot: 'primary',
  principal_label: 'primary-user',
  configuration: {},
  current_version: 2,
  record_version: 2,
  is_active: true,
  allowed_capabilities: ['auth.session.establish', 'http.request', 'web.probe'],
  secret_values_visible: false,
  status: 'active',
  refresh_required: false,
  execution_compatible: true,
  storage_encrypted: true,
  encryption_available: true,
}


test.beforeEach(async ({ page }) => {
  await page.route('**/scan/contracts', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(SCAN_PUBLIC_CONTRACT_SNAPSHOT),
  }))
  await page.route('**/targets?*', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ targets: [target], total: 1 }),
  }))
  await page.route('**/workers', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ count: 1, current_count: 1, stale_count: 0, pending_count: 0, fleet_uniform: true, stale_workers: [] }),
  }))
  await page.route('**/scan/contracts/preview', async (route) => {
    const request = route.request().postDataJSON()
    const active = request.active_testing === true
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        preset: request.preset,
        requested_families: request.include_families || [],
        resolved_families: active ? ['recon', 'nuclei_passive', 'xss', 'sqli'] : ['recon', 'nuclei_passive'],
        derived_prerequisites: [],
        active_permissions: {
          active_testing: active,
          state_changing_http: request.allow_state_changing_http === true,
          network_discovery: request.network_discovery === true,
        },
        minimum_family_quotas: {},
        execution_topology: request.execution_topology,
        ai_used: false,
      }),
    })
  })
  await page.route('**/credential-profiles?*', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ profiles: [credential], count: 1 }),
  }))
  await page.route('**/request-collections?*', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ collections: [], count: 0 }),
  }))
})


test('Scan contract drives budget, zero ceilings, and migrated credential selection', async ({ page }) => {
  await page.goto('/scan/new')
  await page.getByLabel('Target URL or hostname').fill(target.url)

  const thorough = page.getByRole('button', { name: /Thorough/ })
  await thorough.click()
  await expect(thorough).toHaveAttribute('aria-pressed', 'true')

  const advanced = page.getByRole('button', { name: /Advanced/ })
  await advanced.click()
  await expect(advanced).toHaveAttribute('aria-expanded', 'true')

  const primary = page.getByLabel('Primary identity')
  await expect(primary.locator(`option[value="${credential.id}"]`)).toBeEnabled()
  await primary.selectOption(credential.id)
  await expect(primary).toHaveValue(credential.id)

  const stateChanging = page.getByLabel('Maximum state-changing requests')
  await expect(stateChanging).toHaveAttribute('min', '0')
  await stateChanging.fill('0')
  await expect(stateChanging).toHaveValue('0')
  await expect(page.getByText('zero allowed', { exact: false }).first()).toBeVisible()
})

test('authorized active Scan creates a target-bound approval and submits it in one flow', async ({ page }) => {
  const approvalId = '33333333-3333-4333-8333-333333333333'
  const scopeId = '44444444-4444-4444-8444-444444444444'
  let submittedPayload: any = null

  await page.route('**/arsenal/scope/preview', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ scope_receipt: { receipt_id: scopeId, verdict: 'allowed', blocked_by: [] } }),
  }))
  await page.route('**/arsenal/approvals', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ approval_receipt: { id: approvalId } }),
  }))
  await page.route('**/scans', async (route) => {
    submittedPayload = route.request().postDataJSON()
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ scan_id: '55555555-5555-4555-8555-555555555555' }),
    })
  })

  await page.goto('/scan/new')
  await page.getByLabel('Target URL or hostname').fill(target.url)
  await page.getByLabel('Allow active testing').check()
  const submit = page.getByRole('button', { name: 'Run Scan' })
  await expect(submit).toBeDisabled()
  await page.getByLabel(/I own or have explicit authorization/).check()
  await expect(page.getByText(/Resolved families:.*xss/)).toBeVisible()
  await expect(page.getByText(/Approval receipt/i)).toHaveCount(0)

  await expect(submit).toBeEnabled()
  await submit.click()

  await expect(page).toHaveURL(/\/scans\/55555555-5555-4555-8555-555555555555$/)
  expect(submittedPayload).toMatchObject({
    target: target.url,
    approval_receipt_id: approvalId,
    policy: { preset: 'standard_active', active_testing: true },
    options: { require_current_workers: false },
  })
})
