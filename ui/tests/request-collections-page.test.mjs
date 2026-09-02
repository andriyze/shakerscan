import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const page = fs.readFileSync(path.join(root, 'src/app/request-collections/page.tsx'), 'utf8')
const picker = fs.readFileSync(path.join(root, 'src/components/RequestCollectionPicker.tsx'), 'utf8')
const scan = fs.readFileSync(path.join(root, 'src/app/scan/new/page.tsx'), 'utf8')
const hunt = fs.readFileSync(path.join(root, 'src/app/hunt/page.tsx'), 'utf8')
const api = fs.readFileSync(path.join(root, 'src/lib/api.ts'), 'utf8')
const collectionApi = fs.readFileSync(path.join(root, 'src/lib/requestCollectionApi.ts'), 'utf8')
const sidebar = fs.readFileSync(path.join(root, 'src/components/Sidebar.tsx'), 'utf8')

test('shared collection UI supports upload, environment, binding, inventory, and selection', () => {
  assert.match(sidebar, /href: '\/request-collections'/)
  assert.match(page, /Validate and upload/)
  assert.match(page, /upsertRequestCollectionEnvironment/)
  assert.match(page, /upsertRequestCollectionBinding/)
  assert.match(page, /upsertRequestCollectionSelection/)
  assert.match(page, /Redacted request inventory/)
  assert.match(page, /\.slice\(0, 240\)/)
  for (const format of ['postman_collection', 'har', 'openapi']) {
    assert.match(page, new RegExp(`<option value="${format}">`))
  }
  for (const policy of ['discovery_only', 'safe_reads', 'confirmed_active']) {
    assert.match(page, new RegExp(`<option value="${policy}">`))
  }
})

test('collection presentation stays metadata-only after upload', () => {
  assert.match(collectionApi, /secret_values_visible: false/)
  assert.match(collectionApi, /storage_encrypted: true/)
  assert.doesNotMatch(api, /export async function listRequestCollections/)
  assert.doesNotMatch(page, /detail\.collection\.(encrypted_payload|document|environment)/)
  assert.doesNotMatch(picker, /encrypted_payload/)
  assert.match(page, /never reads secret-bearing content back/)
})

test('Scan and Hunt attach exact saved selection IDs without manual UUID entry', () => {
  assert.match(scan, /<RequestCollectionPicker/)
  assert.match(scan, /request_collections: requestCollectionIds\.map\(\(id\) => \(\{/)
  assert.match(scan, /replay_policy: requestCollectionMetadata\[id\]\.replayPolicy/)
  assert.match(scan, /allow_state_changing_http: allowStateChanging/)
  assert.match(hunt, /<RequestCollectionPicker/)
  assert.match(hunt, /requestCollectionIds,/)
  assert.doesNotMatch(hunt, /UUIDs separated by commas/)
  assert.match(picker, /selection\.id/)
  assert.match(picker, /selection\.selection_digest\.slice/)
  assert.match(picker, /active testing and state-changing HTTP/)
})

test('saved selections expose an explicit immutable revision lifecycle', () => {
  assert.match(page, /Ownership is exact target ID/)
  assert.match(page, /exact scheme \+ hostname \+ port/)
  assert.match(page, /Replace/)
  assert.match(page, /Clone/)
  assert.match(page, /Deactivate/)
  assert.match(collectionApi, /method: 'DELETE'/)
  assert.match(page, /Historical scan bindings remain immutable/)
})
