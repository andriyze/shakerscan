import { expect, test } from '@playwright/test'

const targetId = '11111111-1111-4111-8111-111111111111'
const credentialId = '22222222-2222-4222-8222-222222222222'

test('reviewed metadata stays separate from secrets and failed saves preserve input', async ({ page }, testInfo) => {
  await page.route('http://localhost:8080/**', route => route.fulfill({ json: {} }))
  await page.route('**/targets?*', route => route.fulfill({ json: { targets: [{
    id: targetId, url: 'https://fixture.example.test', name: 'Fixture', is_active: true, total_scans: 0,
  }] } }))
  await page.route('**/devices?*', route => route.fulfill({ json: { devices: [] } }))
  await page.route('**/credential-profiles?*', route => route.fulfill({ json: { profiles: [{
    id: credentialId, target_kind: 'web', target_id: targetId, name: 'Test identity',
    auth_kind: 'bearer_token', principal_slot: 'primary', configuration: {}, is_active: true,
    current_version: 1, record_version: 1, allowed_capabilities: [], status: 'active',
    secret_values_visible: false, storage_encrypted: true,
  }] } }))
  await page.route('**/authenticated-scan-profiles/contract', route => route.fulfill({ json: {
    enabled: true, schema_version: 'authenticated-scan-profile/v1',
  } }))
  await page.route('**/authenticated-scan-profiles?*', route => route.fulfill({ json: { profiles: [] } }))
  let submitted: any = null
  await page.route('**/authenticated-scan-profiles', async route => {
    submitted = route.request().postDataJSON()
    await route.fulfill({ status: 409, json: { detail: 'profile_changed' } })
  })
  await page.goto(`/credentials?target_id=${targetId}`)
  const section = page.getByRole('region', { name: 'Authentication profiles' })
  await expect(section).toContainText('Scan selection is not supported')
  await section.getByRole('button', { name: 'New authentication profile' }).click()
  await section.getByLabel('Name', { exact: true }).fill('Staging user')
  await section.getByLabel('Environment', { exact: true }).fill('staging')
  await section.getByLabel('Exact credential destination', { exact: false }).fill('https://fixture.example.test')
  await section.getByLabel('Expected non-secret identity label').fill('test-user')
  await section.getByText('Advanced validation: role, timeout, and freshness', { exact: true }).click()
  await section.getByLabel('Optional JSON role field').fill('role')
  await section.getByLabel('Expected non-secret role value').fill('member')
  await section.getByLabel('Health request timeout (seconds)').fill('4')
  await section.getByLabel('Validation freshness (seconds)').fill('120')
  const save = section.getByRole('button', { name: 'Save reviewed revision' })
  await expect(save).toBeDisabled()
  await section.getByRole('checkbox').check()
  await expect(save).toBeEnabled()
  await save.focus()
  await page.keyboard.press('Enter')
  await expect(section.getByRole('alert')).toContainText('profile or credential changed')
  await expect(section.getByLabel('Name', { exact: true })).toHaveValue('Staging user')
  expect(submitted.configuration.credential_reference).toBe(credentialId)
  expect(submitted.reviewed).toBe(true)
  expect(submitted.expected_revision).toBe(0)
  expect(submitted.configuration.validation_policy).toMatchObject({ role_field: 'role', expected_role: 'member', timeout_seconds: 4, freshness_seconds: 120 })
  expect(submitted).not.toHaveProperty('secret')
  expect(submitted.configuration).not.toHaveProperty('active_testing')
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('assurance-form.png'), fullPage: true })
})

test('identity validation requires review and reports uncertainty after completion', async ({ page }, testInfo) => {
  const approvalId = '33333333-3333-4333-8333-333333333333'
  const requestId = '44444444-4444-4444-8444-444444444444'
  let finished = false
  let submitted: any = null
  let approval: any = null
  await page.route('http://localhost:8080/**', route => route.fulfill({ json: {} }))
  await page.route('**/targets?*', route => route.fulfill({ json: { targets: [{ id: targetId,
    url: 'http://fixture.example.test', name: 'Fixture', is_active: true, total_scans: 0 }] } }))
  await page.route('**/devices?*', route => route.fulfill({ json: { devices: [] } }))
  await page.route('**/credential-profiles?*', route => route.fulfill({ json: { profiles: [{
    id: credentialId, target_kind: 'web', target_id: targetId, name: 'Test identity',
    auth_kind: 'bearer_token', principal_slot: 'primary', configuration: {}, is_active: true,
    current_version: 1, record_version: 1, allowed_capabilities: ['http.request'], status: 'active',
    secret_values_visible: false, storage_encrypted: true,
  }] } }))
  await page.route('**/authenticated-scan-profiles/contract', route => route.fulfill({ json: {
    enabled: true, schema_version: 'authenticated-scan-profile/v1',
    validation_execution: 'queued_read_only', supported_validation_methods: ['bearer_token'],
    validation_history: true,
  } }))
  await page.route('**/authenticated-scan-profiles?*', route => route.fulfill({ json: { profiles: [{
    profile_id: credentialId, revision: 2, credential_version: 1,
    configuration: { display_name: 'Staging user', environment_label: 'lab', lifecycle_state: 'ready',
      credential_destinations: ['http://fixture.example.test'], validation_policy: { path: '/me' } },
    assurance: { state: 'unknown', reason_code: finished ? 'validation_timeout' : 'not_validated', last_validated_at: null },
  }] } }))
  await page.route('**/arsenal/scope/preview', route => route.fulfill({ json: {
    scope_receipt: { receipt_id: approvalId, verdict: 'allowed' },
  } }))
  await page.route('**/arsenal/approvals', async route => {
    approval = route.request().postDataJSON()
    await route.fulfill({ json: { approval_receipt: { id: approvalId } } })
  })
  await page.route(`**/authenticated-scan-profiles/${credentialId}/validate`, async route => {
    submitted = route.request().postDataJSON()
    await route.fulfill({ status: 202, json: { request_id: requestId, status: 'queued' } })
  })
  await page.route(`**/authenticated-scan-profiles/validations/${requestId}`, async route => {
    finished = true
    await route.fulfill({ json: { request_id: requestId, status: 'failed', reason_code: 'validation_timeout',
      budget_reserved: { http_requests: 1, hosts_attempted: 1, tool_wall_seconds: 6 },
      budget_consumed: { http_requests: 1, hosts_attempted: 1, tool_wall_seconds: 5 },
      receipt: { receipt_hash: 'a'.repeat(64) } } })
  })
  await page.route(`**/authenticated-scan-profiles/${credentialId}/history`, route => route.fulfill({ json: {
    records: [
      { validation_id: requestId, request_id: requestId, revision: 2, checked_at: '2026-09-15T01:00:00Z',
        state: 'unknown', reason_code: 'validation_timeout', identity_matched: false, role_matched: null },
      { validation_id: approvalId, request_id: null, revision: 1, checked_at: '2026-09-14T01:00:00Z',
        state: 'valid', reason_code: 'identity_confirmed', identity_matched: true, role_matched: true },
    ], next_cursor: null,
  } }))
  await page.goto(`/credentials?target_id=${targetId}`)
  const section = page.getByRole('region', { name: 'Authentication profiles' })
  await section.getByRole('button', { name: 'Validate identity', exact: true }).click()
  const run = section.getByRole('button', { name: 'Run reviewed identity check' })
  await expect(run).toBeDisabled()
  await section.getByLabel('I authorize this identity check', { exact: false }).check()
  await expect(run).toBeDisabled()
  await section.getByLabel('I approve sending this test credential', { exact: false }).check()
  await expect(run).toBeEnabled()
  expect(submitted).toBeNull()
  await run.focus()
  await page.keyboard.press('Enter')
  await expect(section).toContainText('failed: validation timeout')
  await expect(section).toContainText('Identity: unknown · validation timeout')
  expect(approval.action_name).toBe('authentication.validate')
  expect(approval.risk_tier).toBe('credential')
  expect(submitted).toEqual({ expected_revision: 2, approval_receipt_id: approvalId,
    reviewed: true, allow_insecure_transport: true })
  await section.getByRole('button', { name: 'Validation history', exact: true }).click()
  await expect(section).toContainText('Valid at this check · identity confirmed')
  await expect(section).toContainText('Identity: unknown · validation timeout')
  await section.getByRole('button', { name: 'Execution receipt', exact: true }).click()
  await expect(section).toContainText('reserved 6; consumed 5')
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('assurance-validation.png'), fullPage: true })
})
