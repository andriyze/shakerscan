import { expect, test } from '@playwright/test'

const huntId = '00000000-0000-0000-0000-000000000001'
const candidateId = '00000000-0000-0000-0000-000000000002'
const prefill = {
  version: 1, name: 'discovered-read-boundary', owner: { resource_id: 'owner-record' },
  attacker: { resource_id: 'attacker-record' }, response_path: 'answer',
  identity: { path: '/identity', subject_field: 'subject', tenant_field: 'tenant' },
  resource: { path: '/records/{{resource_id}}', id_field: 'id', owner_field: 'owner', tenant_field: 'tenant', marker_field: 'marker' },
}
const discovery = {
  status: 'drafts_available', execution_enabled: false,
  coverage: { captures_read: 5, captures_truncated: false, structure_unavailable: 0, drafts_truncated: false },
  drafts: [{
    draft_id: 'read-pair', origin: 'https://app.test:8443', kind: 'cross_tenant_read', agent_paths: ['/chat'],
    fixture_prefill: prefill, missing_facts: ['distinct_principals', 'owner.subject'],
    field_provenance: { 'resource.path': [{ capture_id: 'capture-1', action_id: 'action-1' }] },
    candidate_request: { family: 'cross_tenant_retrieval', locus: { url: 'https://app.test:8443/records/{{resource_id}}' }, evidence_refs: ['capture-1'] },
  }],
}

test('discovery prepares an unverified candidate and keeps confirmed principal facts in the fixture', async ({ page }) => {
  const errors: string[] = []
  const writes: string[] = []
  page.on('pageerror', (error) => errors.push(error.message))
  await page.route('**/ai/targets?*', (route) => route.fulfill({ json: { total: 2, targets: [
    { id: 'target-1', name: 'Observed agent', target_type: 'api_chat', endpoint_url: 'https://app.test:8443/chat', is_active: true, production_mode: false },
    { id: 'target-2', name: 'Other port', target_type: 'api_chat', endpoint_url: 'https://app.test/chat', is_active: true, production_mode: false },
  ] } }))
  await page.route(`**/hunts/${huntId}`, (route) => route.fulfill({ json: { id: huntId, status: 'active', actions: [], target_url: 'https://app.test:8443' } }))
  await page.route(`**/hunts/${huntId}/boundary-discovery`, (route) => {
    writes.push('discovery')
    return route.fulfill({ json: discovery })
  })
  await page.route(`**/hunts/${huntId}/candidates`, (route) => {
    writes.push('candidate')
    expect(route.request().postDataJSON()).toEqual(discovery.drafts[0].candidate_request)
    return route.fulfill({ json: { candidate: { id: candidateId }, verified: false } })
  })
  await page.route('**/boundary/verify', (route) => {
    writes.push('verification')
    return route.fulfill({ status: 500, json: { detail: 'Verification must be explicit' } })
  })
  await page.goto('/ai-gate/boundary')
  await page.getByRole('combobox', { name: /^AI target/ }).selectOption('target-2')
  await page.getByPlaceholder('Hunt UUID').fill(huntId)
  await page.getByRole('button', { name: 'Load', exact: true }).click()
  await page.getByRole('button', { name: 'Discover boundary drafts' }).click()
  await expect(page.getByRole('button', { name: 'Prepare candidate and fixture' })).toBeDisabled()
  // Same hostname is insufficient: the configured service must match the capture.
  await page.getByRole('combobox', { name: /^AI target/ }).selectOption('target-1')
  await page.getByRole('button', { name: 'Discover boundary drafts' }).click()
  await page.getByRole('button', { name: 'Prepare candidate and fixture' }).click()
  await expect(page.getByPlaceholder('Candidate UUID')).toHaveValue(candidateId)
  await expect(page.getByRole('button', { name: 'Queue verification' })).toBeDisabled()
  await page.getByLabel('Subject', { exact: true }).nth(0).fill('owner-subject')
  const fixture = JSON.parse(await page.getByLabel('Boundary fixture base · JSON, no credentials').inputValue())
  expect(fixture.owner.subject).toBe('owner-subject')
  expect(fixture.owner.resource_id).toBe('owner-record')
  expect(fixture.attacker.subject).toBe('')
  expect(writes).toEqual(['discovery', 'discovery', 'candidate'])
  expect(errors).toEqual([])
  const width = await page.evaluate(() => [document.documentElement.scrollWidth, document.documentElement.clientWidth])
  expect(width[0]).toBeLessThanOrEqual(width[1])
})
