import { expect, test, type Page } from '@playwright/test'

const targetId = '11111111-1111-4111-8111-111111111111'
const findingId = '22222222-2222-4222-8222-222222222222'
const previewId = '33333333-3333-4333-8333-333333333333'
const receiptId = '44444444-4444-4444-8444-444444444444'
const targetUrl = 'https://target.example.invalid'

async function mockApi(page: Page, options: { blocked?: boolean; retry?: boolean } = {}) {
  const writes: { path: string; body: Record<string, unknown> }[] = []
  let deleted = false
  let executions = 0
  const finding = { id: findingId, title: 'Synthetic lifecycle finding', severity: 'low', status: 'active',
    first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-01T00:00:00Z', target_id: targetId }
  await page.addInitScript(() => { window.__SHAKERSCAN_API_URL__ = 'http://localhost:8080' })
  await page.route('http://localhost:8080/**', async route => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    const body = request.method() === 'POST' && request.postData() ? request.postDataJSON() : {}
    if (request.method() !== 'GET' && request.method() !== 'OPTIONS') writes.push({ path, body })
    if (path === '/targets/grouped') return route.fulfill({ json: {
      domains: deleted ? [] : [{ root_domain: 'example.invalid', root_target: { id: targetId, url: targetUrl,
        root_domain: 'example.invalid', is_root: true, is_active: true, total_scans: 0, active_findings_count: 1 },
        subdomains: [], subdomain_count: 0, total_count: 1 }], total_targets: deleted ? 0 : 1, total_root_domains: deleted ? 0 : 1,
    } })
    if (path === '/findings') return route.fulfill({ json: { findings: deleted ? [] : [finding], total: deleted ? 0 : 1 } })
    if (path === '/domains') return route.fulfill({ json: { domains: ['example.invalid'] } })
    if (path === '/data-deletion/preview') return route.fulfill({ json: {
      schema: 'shakerscan.record-deletion/v1', kind: body.kind, preview_id: previewId, preview_hash: 'a'.repeat(64),
      scope_receipt_id: `record-delete:${previewId}`, expires_at: new Date(Date.now() + 600000).toISOString(),
      root_ids: body.kind === 'target' ? [targetId] : [findingId], would_delete: 1, dry_run: true,
      external_files_deleted: false,
      records: { delete: { ...(body.kind === 'target' ? { targets: { count: 1 } } : {}), findings: { count: 1 } }, detach: {}, retain: {}, restrict: {} },
      blockers: options.blocked ? ['scans: 1 active record; finish or cancel it first'] : [],
      retained: ['Historical scans and external evidence files are retained.'],
    } })
    if (path === '/arsenal/approvals') return route.fulfill({ json: { approval_receipt: { id: receiptId } } })
    if (path === `/targets/${targetId}/archive`) {
      deleted = true // Hidden from active inventory, not deleted from storage.
      return route.fulfill({ json: { id: targetId, status: 'archived', records_deleted: false, schedules_paused: 1 } })
    }
    if (path === '/data-deletion/execute') {
      executions += 1
      if (options.retry && executions === 1) return route.abort('failed')
      deleted = true
      return route.fulfill({ json: { status: 'deleted', deleted: 1, deleted_ids: [targetId], external_files_deleted: false, retained: [], operation_id: previewId } })
    }
    return route.fulfill({ json: { status: 'healthy', workers: [], total: 0 } })
  })
  return writes
}

test('target cancellation only previews; confirmed deletion uses the exact approval and refreshes', async ({ page }) => {
  const writes = await mockApi(page)
  await page.goto('/targets')
  await page.getByRole('button', { name: `Delete ${targetUrl}`, exact: true }).click()
  const dialog = page.getByRole('dialog', { name: `Delete ${targetUrl}` })
  await expect(dialog.getByText('Not a complete data erasure')).toBeVisible()
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click()
  expect(writes.map(w => w.path)).toEqual(['/data-deletion/preview'])
  await page.getByRole('button', { name: `Delete ${targetUrl}`, exact: true }).click()
  await dialog.getByRole('button', { name: 'Approve and delete records' }).click()
  await expect(dialog).not.toBeVisible()
  await expect(page.getByRole('button', { name: `Delete ${targetUrl}`, exact: true })).toHaveCount(0)
  const approval = writes.find(w => w.path === '/arsenal/approvals')!
  expect(approval.body.action_context).toEqual({ preview_id: previewId, preview_hash: 'a'.repeat(64) })
  expect(approval.body.confirmations).toContain('confirm_delete_records')
  expect(writes.find(w => w.path === '/data-deletion/execute')!.body).toEqual({ preview_id: previewId, preview_hash: 'a'.repeat(64), approval_receipt_id: receiptId })
})

test('active-work blocker disables destructive confirmation without trapping cancellation', async ({ page }) => {
  const writes = await mockApi(page, { blocked: true })
  await page.goto('/targets')
  await page.getByRole('button', { name: `Delete ${targetUrl}`, exact: true }).click()
  const dialog = page.getByRole('dialog')
  await expect(dialog.getByRole('alert')).toContainText('active record')
  await expect(dialog.getByRole('button', { name: 'Approve and delete records' })).toBeDisabled()
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click()
  expect(writes).toHaveLength(1)
})

test('network retry reuses its receipt instead of creating another approval', async ({ page }) => {
  const writes = await mockApi(page, { retry: true })
  await page.goto('/targets')
  await page.getByRole('button', { name: `Delete ${targetUrl}`, exact: true }).click()
  const dialog = page.getByRole('dialog')
  await dialog.getByRole('button', { name: 'Approve and delete records' }).click()
  await expect(dialog.getByRole('alert')).toBeVisible()
  await dialog.getByRole('button', { name: 'Approve and delete records' }).click()
  await expect(dialog).not.toBeVisible()
  expect(writes.filter(w => w.path === '/arsenal/approvals')).toHaveLength(1)
  const executions = writes.filter(w => w.path === '/data-deletion/execute')
  expect(executions).toHaveLength(2)
  expect(executions[0].body).toEqual(executions[1].body)
})

test('findings page deletes only the selected record IDs', async ({ page }) => {
  const writes = await mockApi(page)
  await page.goto('/findings')
  await page.getByRole('checkbox', { name: 'Select finding Synthetic lifecycle finding', exact: true }).check()
  await page.getByRole('button', { name: 'Delete selected findings', exact: true }).click()
  expect(writes[0].body).toEqual({ kind: 'findings', finding_ids: [findingId] })
  await page.getByRole('dialog').getByRole('button', { name: 'Approve and delete records' }).click()
  await expect(page.getByRole('checkbox', { name: 'Select finding Synthetic lifecycle finding', exact: true })).toHaveCount(0)
})


test('protected target offers a separately confirmed archive, never a deletion approval', async ({ page }) => {
  const writes = await mockApi(page, { blocked: true })
  await page.goto('/targets')
  await page.getByRole('button', { name: `Delete ${targetUrl}`, exact: true }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Archive target instead', exact: true }).click()
  const dialog = page.getByRole('dialog', { name: `Archive ${targetUrl}`, exact: true })
  await expect(dialog.getByText(/Already-admitted or running work is not cancelled/)).toBeVisible()
  expect(writes.map(w => w.path)).toEqual(['/data-deletion/preview'])
  await dialog.getByRole('button', { name: 'Archive target', exact: true }).click()
  await expect(dialog).not.toBeVisible()
  expect(writes.map(w => w.path)).toEqual(['/data-deletion/preview', `/targets/${targetId}/archive`])
  await expect(page.getByRole('button', { name: `Delete ${targetUrl}`, exact: true })).toHaveCount(0)
})
