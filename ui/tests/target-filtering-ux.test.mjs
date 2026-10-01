import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const read = (file) => readFileSync(path.join(root, file), 'utf8')
const credentials = read('src/app/credentials/page.tsx')
const collections = read('src/app/request-collections/page.tsx')
const hunts = read('src/app/hunts/page.tsx')
const scans = read('src/app/scans/page.tsx')
const device = read('src/app/devices/[id]/page.tsx')
const api = read('src/lib/api.ts')

test('the credential and collection target lives in the URL', () => {
  for (const page of [credentials, collections]) {
    assert.match(page, /useUrlFilters<\{ target_kind\?: string; target_id\?: string/)
    assert.match(page, /const targetId = filters\.target_id \|\| ''/)
    assert.match(page, /<Suspense/)
  }
})

test('a slow answer for a target no longer selected never fills the list', () => {
  assert.match(credentials, /const request = \+\+latestProfileRequest\.current/)
  assert.match(credentials, /if \(request !== latestProfileRequest\.current\) return\n      setProfiles\(result\.profiles/)
  assert.match(collections, /const request = \+\+latestCollectionsRequest\.current/)
  assert.match(collections, /if \(request !== latestCollectionsRequest\.current\) return\n      setCollections\(result\.collections/)
  // A failed load clears the previous target's collections.
  assert.match(collections, /setCollections\(\[\]\)\n      setSelectedId\(''\)\n      setError\(cause instanceof Error/)
})

test('a linked credential target outside the loaded list is fetched, or reported', () => {
  assert.match(credentials, /getTarget\(targetId\)/)
  assert.match(credentials, /was not found among active targets that can hold credentials/)
  // An unknown ID is never sent to the profiles API.
  assert.match(credentials, /if \(!targetId \|\| !choices\.some\(\(item\) => item\.id === targetId\)\) \{\n      setProfiles\(\[\]\)/)
})

test('Hunts and Scans filter by an exact target', () => {
  assert.match(hunts, /targetId: targetId \|\| undefined,/)
  assert.match(hunts, /data-testid="hunts-target-filter"/)
  assert.match(scans, /target_id: targetIdFilter \|\| undefined,/)
  assert.match(scans, /data-testid="scans-target-filter"/)
  assert.match(api, /if \(params\?\.target_id\) searchParams\.set\('target_id', params\.target_id\)/)
})

test('a device lists its findings from every source, Hunt included', () => {
  assert.match(device, /href=\{`\/findings\?device_target_id=\$\{device\.id\}&freshness=all`\}/)
  assert.doesNotMatch(device, /source_type=device&device_target_id/)
})
