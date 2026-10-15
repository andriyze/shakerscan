import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const panel = readFileSync(path.join(root, 'src/components/hunt/HuntRequestsPanel.tsx'), 'utf8')

// 2.11 scale: a live Hunt used to re-read up to 1000 archived requests (bodies included) on every
// new action or request. Now the first page loads once and later reads fetch only what is new.
test('the archive loads one page, never an automatic 1000-row loop', () => {
  assert.doesNotMatch(panel, /AUTO_LOAD/)
  assert.match(panel, /const PAGE = 250/)
  assert.match(panel, /fetchPage\(0, PAGE, signal\)/)
  assert.doesNotMatch(panel, /while \(/)
})

test('a version change reads only the new tail, or one row for the total', () => {
  assert.match(panel, /const atTail = held\.length >= totalRef\.current/)
  assert.match(panel, /fetchPage\(atTail \? held\.length : 0, atTail \? PAGE : 1, signal\)/)
  // New rows are appended without duplicates; a purge (total below the rows held) reloads.
  assert.match(panel, /filter\(row => !seen\.has\(row\.id\)\)/)
  assert.match(panel, /if \(nextTotal < rowsRef\.current\.length\) \{\s*await loadFirst\(signal\)/)
})

test('version-driven reads are throttled, skipped while hidden and aborted on unmount', () => {
  assert.match(panel, /export const ARCHIVE_REFRESH_MIN_MS = 5000/)
  assert.match(panel, /lastRefreshAt\.current \+ ARCHIVE_REFRESH_MIN_MS - Date\.now\(\)/)
  assert.match(panel, /document\.visibilityState === 'hidden'/)
  assert.match(panel, /addEventListener\('visibilitychange', run\)/)
  assert.match(panel, /for \(const controller of live\) controller\.abort\(\)/)
  assert.match(panel, /\{ cache: 'no-store', signal \}/)
})

test('request rows skip layout and paint off screen (dependency-free virtualization)', () => {
  assert.match(panel, /<li className="\[content-visibility:auto\] \[contain-intrinsic-size:auto_44px\]">/)
})
