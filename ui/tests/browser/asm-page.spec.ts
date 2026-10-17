import { expect, test } from '@playwright/test'

import { mockPageApi, queryNames, serverError, type MockHandler } from './mock-page-api'
import { visitAndAuditPage } from './page-quality'

// Browser contract fixture: the real Coverage (/asm) rollup, a scripted API; no discovery or scan runs.
const now = '2026-10-15T10:00:00Z'
const covered = {
  id: '11111111-1111-4111-8111-111111111111', url: 'https://api.example.test', name: 'Fixture API', root_domain: 'example.test',
  is_root: false, discovery_source: 'manual', is_active: true, total_scans: 2, active_findings_count: 3, created_at: now,
  asm_coverage: { total: 10, tested: 4, untested: 6, denominator: 10, coverage: 0.4, coverage_basis: 'endpoint_status' },
}
const uninventoried = { ...covered, id: '22222222-2222-4222-8222-222222222222', url: 'https://www.example.test',
  name: 'Fixture site', asm_coverage: null }

function page(items: unknown[], total = items.length) {
  return { items, next_cursor: null, has_more: false, total, total_kind: 'exact', generated_at: now }
}

function routes(groups: unknown[]): Record<string, MockHandler> {
  return {
    '/health': () => ({ status: 'healthy' }),
    '/domains': () => ({ domains: groups.length ? ['example.test'] : [] }),
    '/targets/grouped': () => page(groups),
  }
}

const populated = [{ root_domain: 'example.test', root_target: null, subdomains: [covered, uninventoried], subdomain_count: 2, total_count: 2 }]

test('populated coverage lists only targets with a persistent inventory, least covered first', async ({ page: browser }) => {
  const api = await mockPageApi(browser, routes(populated))
  await visitAndAuditPage(browser, '/asm', 600)
  await expect(browser.getByRole('heading', { name: 'Coverage', exact: true })).toBeVisible()
  await expect(browser.getByText('1 target with a persistent inventory', { exact: true })).toBeVisible()
  await expect(browser.getByTestId('asm-rollup-scope')).toContainText('1 of 1 domain loaded')
  const row = browser.getByRole('row').filter({ hasText: 'example.test' }).filter({ has: browser.getByRole('button', { name: 'View' }) })
  await expect(row).toHaveCount(1)
  await expect(row).toContainText('40.0%')
  await expect(row).toContainText('4 / 10')
  await expect(row).toContainText('6')
  await expect(browser.getByRole('combobox', { name: 'Filter endpoints by domain' })).toContainText('example.test')
  expect(api.unhandled).toEqual([])
  expect(queryNames(api, '/targets/grouped')).toEqual(['count', 'limit', 'member_limit', 'sort', 'sort_by', 'sort_order'])
})

test('no inventory yet explains how to build one', async ({ page: browser }) => {
  const api = await mockPageApi(browser, routes([]))
  await visitAndAuditPage(browser, '/asm', 600)
  await expect(browser.getByText('No attack-surface inventory yet', { exact: true })).toBeVisible()
  await expect(browser.getByText(/Run a coverage scan on a target/)).toBeVisible()
  expect(api.unhandled).toEqual([])
})

test('a failed inventory read shows the error and retries', async ({ page: browser }) => {
  let fail = true
  const ok = routes(populated)
  const errors: string[] = []
  browser.on('pageerror', error => errors.push(error.message))
  await mockPageApi(browser, { ...ok, '/targets/grouped': (url, request) => fail ? serverError() : ok['/targets/grouped'](url, request) })
  await browser.goto('/asm')
  await expect(browser.getByText('Failed to load attack-surface inventory.', { exact: true })).toBeVisible()
  fail = false
  await browser.getByRole('button', { name: /Retry|Try again/ }).first().click()
  await expect(browser.getByText('1 target with a persistent inventory', { exact: true })).toBeVisible()
  expect(errors).toEqual([])
})

test('the coverage rollup fits a phone viewport', async ({ page: browser }) => {
  await browser.setViewportSize({ width: 390, height: 844 })
  await mockPageApi(browser, routes(populated))
  await visitAndAuditPage(browser, '/asm', 600)
  await expect(browser.getByRole('button', { name: 'View' })).toBeVisible()
})
