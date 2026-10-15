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
  assert.match(panel, /if \(rowsRef\.current\.length >= totalRef\.current\) \{\s*\/\/ At the tail[^\n]*\n\s*await readTail\(signal\)/)
  assert.match(panel, /fetchPage\(held\.length, PAGE, signal\)/)
  assert.match(panel, /fetchPage\(0, 1, signal\)/)
  // A purge (total below the rows held) reloads.
  assert.match(panel, /if \(nextTotal < rowsRef\.current\.length\) \{ await loadFirst\(signal\); return \}/)
})

// Review: rows archived out of order land mid-list, so an offset read at the tail could miss them
// and Load more could re-fetch only rows it already held. Both now go through planPageMerge
// (lib/huntArchiveSync.mjs, unit-tested there) and resync the held window when counts disagree.
test('tail reads and Load more follow the merge plan and resync instead of appending blindly', () => {
  assert.match(panel, /planPageMerge\(\{ held: rowsRef\.current, page: archive\.transactions \|\| \[\], limit: PAGE, total: nextTotal \}\)/)
  assert.match(panel, /if \(plan\.action === 'resync'\) \{ await resync\(signal\); return \}/)
  assert.match(panel, /if \(plan\.action === 'reload'\) \{ await loadFirst\(signal\); return \}/)
  assert.match(panel, /for \(const span of resyncWindows\(rowsRef\.current\.length, \{ page: PAGE \}\)\)/)
  const loadMore = panel.slice(panel.indexOf('const loadMore = useCallback'))
  assert.match(loadMore.slice(0, 400), /await readTail\(signal\)/)
})

test('version-driven reads are throttled, skipped while hidden and aborted on unmount', () => {
  assert.match(panel, /export const ARCHIVE_REFRESH_MIN_MS = 5000/)
  assert.match(panel, /lastRefreshAt\.current \+ ARCHIVE_REFRESH_MIN_MS - Date\.now\(\)/)
  assert.match(panel, /document\.visibilityState === 'hidden'/)
  assert.match(panel, /addEventListener\('visibilitychange', run\)/)
  // Review: a throttle timer that fires while the tab is hidden re-arms on visibilitychange instead
  // of dropping the refresh (the final requests and total used to stay unread).
  assert.match(panel, /if \(document\.visibilityState === 'hidden'\) \{ document\.addEventListener\('visibilitychange', run\); return \}/)
  assert.doesNotMatch(panel, /if \(document\.visibilityState === 'hidden'\) return\n/)
  assert.match(panel, /for \(const controller of live\) controller\.abort\(\)/)
  assert.match(panel, /\{ cache: 'no-store', signal \}/)
})

test('request rows skip layout and paint off screen (dependency-free virtualization)', () => {
  assert.match(panel, /<li className="\[content-visibility:auto\] \[contain-intrinsic-size:auto_44px\]">/)
})
