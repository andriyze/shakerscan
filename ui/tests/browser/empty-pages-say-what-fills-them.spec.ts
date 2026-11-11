import { expect, test } from '@playwright/test'

import { mockPageApi, type MockHandler } from './mock-page-api'

// Browser contract fixture: the Evidence and Coverage pages as they are straight after a first
// scan, with a scripted API. Synthetic: nothing is stored and nothing runs.
const now = '2026-10-15T10:00:00Z'
const health: Record<string, MockHandler> = { 'GET /health': () => ({ status: 'healthy', scanner_version: 'fixture' }) }
const target = {
  id: '11111111-1111-4111-8111-111111111111', url: 'https://shop.fixture.example', name: 'Fixture shop', root_domain: 'fixture.example',
  is_root: true, discovery_source: 'manual', is_active: true, total_scans: 1, active_findings_count: 28, created_at: now,
}
const grouped = (coverage: unknown) => () => ({
  items: [{ root_domain: 'fixture.example', root_target: { ...target, asm_coverage: coverage }, subdomains: [], subdomain_count: 0, total_count: 1 }],
  next_cursor: null, has_more: false, total: 1, total_kind: 'exact', generated_at: now,
})

test('FILL-001 an empty evidence list says what fills it and where scan evidence is', async ({ page }) => {
  await mockPageApi(page, { ...health, 'GET /evidence/instances': () => ({ evidence_instances: [], count: 0, execution_enabled: true }) })
  await page.goto('/evidence', { waitUntil: 'domcontentloaded' })
  const main = page.locator('main')
  await expect(main.getByText('No autonomous test evidence yet', { exact: true })).toBeVisible()
  await expect(main.getByText(/This list fills when a Hunt records evidence\. Scan findings keep their evidence on each finding/)).toBeVisible()
  await expect(main.getByRole('link', { name: 'Open findings', exact: true })).toHaveAttribute('href', '/findings')
  // Nothing to filter: no row of proof states at zero, no search box. The finding filter stays.
  await expect(main.getByRole('button', { name: /^Proven/ })).toHaveCount(0)
  await expect(main.getByRole('textbox', { name: 'Search evidence' })).toHaveCount(0)
  await expect(main.getByText('Advanced: filter by finding ID / fingerprint', { exact: true })).toBeVisible()
})

test('FILL-002 an evidence list with records keeps its proof states and search', async ({ page }) => {
  await mockPageApi(page, {
    ...health,
    'GET /evidence/instances': () => ({
      count: 1, execution_enabled: true,
      evidence_instances: [{
        id: 'e1111111-1111-4111-8111-111111111111', proof_state: 'verified', concrete_url: 'https://shop.fixture.example/search',
        metadata_json: { family: 'sqli', objective: 'Fixture objective', source: 'research_http_experiment' }, created_at: now,
      }],
    }),
  })
  await page.goto('/evidence', { waitUntil: 'domcontentloaded' })
  const main = page.locator('main')
  await expect(main.getByRole('button', { name: /^Proven/ })).toBeVisible()
  await expect(main.getByRole('textbox', { name: 'Search evidence' })).toBeVisible()
  await expect(main.getByText('No autonomous test evidence yet')).toHaveCount(0)
})

test('FILL-003 a coverage inventory with nothing completed says what completes a route', async ({ page }) => {
  await mockPageApi(page, {
    ...health,
    'GET /domains': () => ({ domains: ['fixture.example'] }),
    'GET /targets/grouped': grouped({ total: 56, tested: 0, untested: 56, denominator: 56, coverage: 0, coverage_basis: 'endpoint_status' }),
  })
  await page.goto('/asm', { waitUntil: 'domcontentloaded' })
  const main = page.locator('main')
  await expect(main.getByRole('row').filter({ hasText: '0 / 56' })).toHaveCount(1)
  const note = main.getByTestId('asm-nothing-tested')
  await expect(note).toContainText('A scan adds the routes it discovers to a target’s inventory')
  await expect(note).toContainText('counts as completed once a coverage test batch has tested it')
  await expect(note).toContainText('choose “Improve coverage”')
})

test('FILL-004 a coverage inventory with completed routes carries no such note', async ({ page }) => {
  await mockPageApi(page, {
    ...health,
    'GET /domains': () => ({ domains: ['fixture.example'] }),
    'GET /targets/grouped': grouped({ total: 56, tested: 4, untested: 52, denominator: 56, coverage: 0.071, coverage_basis: 'endpoint_status' }),
  })
  await page.goto('/asm', { waitUntil: 'domcontentloaded' })
  await expect(page.locator('main').getByRole('row').filter({ hasText: '4 / 56' })).toHaveCount(1)
  await expect(page.getByTestId('asm-nothing-tested')).toHaveCount(0)
})
