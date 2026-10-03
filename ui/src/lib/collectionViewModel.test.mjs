import assert from 'node:assert/strict'
import test from 'node:test'

import { boundApis, filterRequests, methodCounts, originOf } from './collectionViewModel.mjs'

const requests = [
  { request_id: 'a', method: 'GET', name: 'List orders', normalized_path: '/api/orders', folder: 'Orders', tags: ['read'] },
  { request_id: 'b', method: 'POST', name: 'Create order', normalized_path: '/api/orders', folder: 'Orders', tags: [] },
  { request_id: 'c', method: 'delete', name: 'Remove user', normalized_path: '/api/users/{id}', folder: 'Admin', tags: ['danger'] },
  { request_id: 'd', method: 'GET', name: null, redacted_url: 'https://api.example.test/health', tags: [] },
]

test('requests filter by every query word across name, path, folder and tags, and by method', () => {
  assert.deepEqual(filterRequests(requests, { query: 'orders' }).map(item => item.request_id), ['a', 'b'])
  assert.deepEqual(filterRequests(requests, { query: 'admin danger' }).map(item => item.request_id), ['c'])
  assert.deepEqual(filterRequests(requests, { query: 'health' }).map(item => item.request_id), ['d'])
  assert.deepEqual(filterRequests(requests, { method: 'GET' }).map(item => item.request_id), ['a', 'd'])
  assert.deepEqual(filterRequests(requests, { query: 'orders', method: 'POST' }).map(item => item.request_id), ['b'])
  assert.deepEqual(filterRequests(requests, {}).length, 4)
})

test('method counts follow the conventional order', () => {
  assert.deepEqual(methodCounts(requests), [{ method: 'GET', count: 2 }, { method: 'POST', count: 1 }, { method: 'DELETE', count: 1 }])
})

test('origins drop paths and keep explicit ports', () => {
  assert.equal(originOf('https://api.example.test:8443/v1/orders?x=1'), 'https://api.example.test:8443')
  assert.equal(originOf('not a url'), 'not a url')
})

test('each API of an asset reports whether the collection is bound to it', () => {
  const apis = [{ id: 'host', url: 'host://example.test', label: 'example.test', kind: 'host' },
    { id: 'web', url: 'https://example.test', label: 'https://example.test', kind: 'origin' },
    { id: 'api', url: 'https://example.test:8443', label: 'https://example.test:8443', kind: 'origin' }]
  const bindings = [{ id: 'b1', target_id: 'api', is_active: true, allowed_origins: ['https://example.test:8443'] },
    { id: 'b2', target_id: 'web', is_active: false, allowed_origins: ['https://example.test'] }]
  assert.deepEqual(boundApis(bindings, apis).map(api => [api.id, api.bound]), [['host', false], ['web', false], ['api', true]])
})
