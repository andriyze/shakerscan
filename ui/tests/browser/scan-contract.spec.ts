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
    body: JSON.stringify({ count: 1, current_count: 1, stale_workers: [] }),
  }))
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
