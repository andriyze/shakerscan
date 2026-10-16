import { expect, test } from '@playwright/test'

import { mockPageApi, queryNames, serverError, type MockHandler } from './mock-page-api'
import { visitAndAuditPage } from './page-quality'

// Browser contract fixture: the real Request Collections page, a scripted API; nothing is replayed.
const now = '2026-10-15T10:00:00Z'
const targetId = '11111111-1111-4111-8111-111111111111'
const collectionId = '33333333-3333-4333-8333-333333333333'
const asset = {
  id: targetId, asset_id: targetId, name: 'Fixture API', url: 'https://api.example.test', locator: 'api.example.test',
  root_domain: 'example.test', is_active: true, environment: 'staging', connected_device: false, origin_count: 0,
  service_count: 0, active_findings_count: 0, created_at: now, updated_at: now,
}
const collection = {
  id: collectionId, target_id: targetId, name: 'Fixture orders API', format: 'openapi', schema_version: 'v1',
  payload_sha256: 'a'.repeat(64), request_count: 3, safe_request_count: 2, potentially_mutating_request_count: 1,
  is_active: true, created_at: now, updated_at: now, storage_encrypted: true,
}

function routes({ collections = [collection] as unknown[] } = {}): Record<string, MockHandler> {
  return {
    '/health': () => ({ status: 'healthy' }),
    '/targets/inventory': () => ({ targets: [asset], total: 1, offset: 0, limit: 25 }),
    [`/targets/${targetId}/asset`]: () => ({
      target: asset, requested_target_id: targetId, origins: [], services: [], credentials: [],
      request_collections: [], active_findings: {}, history: { kind: 'scans', items: [], total: 0, offset: 0, limit: 25 },
    }),
    '/request-collections': (url) => url.searchParams.has('target_id')
      ? { collections, count: collections.length }
      : { collections: collections.map(item => ({ ...item as object, owner_name: 'Fixture API', owner_locator: 'api.example.test',
        binding_count: 0, selection_count: 0 })), count: collections.length, total: collections.length, limit: 25, offset: 0 },
    [`/request-collections/${collectionId}`]: () => ({
      collection, environments: [], bindings: [], selections: [], secret_values_visible: false,
    }),
    [`/request-collections/${collectionId}/requests`]: () => ({
      requests: [
        { request_id: 'req-1', ordinal: 1, name: 'List orders', method: 'GET', redacted_url: 'https://api.example.test/orders', normalized_path: '/orders', tags: [], safe_method: true, supported: true },
        { request_id: 'req-2', ordinal: 2, name: 'Create order', method: 'POST', redacted_url: 'https://api.example.test/orders', normalized_path: '/orders', tags: [], safe_method: false, supported: true },
      ],
      count: 2, total: 2, offset: 0, limit: 100, next_offset: null, secret_values_visible: false,
    }),
  }
}

test('the library lists every collection and Manage opens its owner', async ({ page }) => {
  const api = await mockPageApi(page, routes())
  await visitAndAuditPage(page, '/request-collections', 800)
  const library = page.getByRole('list', { name: 'All request collections' })
  await expect(library).toContainText('Fixture orders API')
  await expect(library).toContainText('api.example.test')
  await library.getByRole('button', { name: 'Manage', exact: true }).click()
  await expect(page).toHaveURL(new RegExp(`target_id=${targetId}`))
  await expect(page.getByRole('heading', { name: 'Fixture orders API', level: 2 })).toBeVisible()
  await expect(page.getByText('3 requests · 2 safe · 1 potentially state-changing')).toBeVisible()
  expect(api.unhandled).toEqual([])
  expect(queryNames(api, '/request-collections')).toEqual(['limit', 'offset', 'target_id'])
  expect(queryNames(api, `/request-collections/${collectionId}/requests`)).toEqual(['limit', 'offset'])
})

test('no collections: the library and a target say how to start', async ({ page }) => {
  const api = await mockPageApi(page, routes({ collections: [] }))
  await visitAndAuditPage(page, '/request-collections', 800)
  await expect(page.getByText('No request collections yet', { exact: true })).toBeVisible()
  await page.goto(`/request-collections?target_id=${targetId}`)
  await expect(page.getByText('No shared request collections for this target', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Upload collection' })).toBeVisible()
  expect(api.unhandled).toEqual([])
})

test('a failed collection read is reported, not shown as an empty target', async ({ page }) => {
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  const ok = routes()
  await mockPageApi(page, { ...ok, '/request-collections': (url, request) => url.searchParams.has('target_id')
    ? serverError('collections store unavailable') : ok['/request-collections'](url, request) })
  await page.goto(`/request-collections?target_id=${targetId}`)
  await expect(page.getByText('collections store unavailable')).toBeVisible()
  await expect(page.getByText('Fixture orders API')).toHaveCount(0)
  await expect(page.getByText('No shared request collections for this target', { exact: true })).toHaveCount(0)
  expect(errors).toEqual([])
})

test('a failed library read shows the error state', async ({ page }) => {
  const ok = routes()
  await mockPageApi(page, { ...ok, '/request-collections': () => serverError('library unavailable') })
  await page.goto('/request-collections')
  await expect(page.getByText('library unavailable')).toBeVisible()
})

test('request collections fit a phone viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await mockPageApi(page, routes())
  await visitAndAuditPage(page, `/request-collections?target_id=${targetId}`, 800)
  await expect(page.getByRole('heading', { name: 'Fixture orders API', level: 2 })).toBeVisible()
})
