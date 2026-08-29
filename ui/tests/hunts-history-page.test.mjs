import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const page = readFileSync(path.join(root, 'src/app/hunts/page.tsx'), 'utf8')
const launcher = readFileSync(path.join(root, 'src/app/hunt/page.tsx'), 'utf8')
const sidebar = readFileSync(path.join(root, 'src/components/Sidebar.tsx'), 'utf8')
const client = readFileSync(path.join(root, 'src/lib/huntV2.ts'), 'utf8')

test('hunt history is reachable from the sidebar', () => {
  assert.match(sidebar, /href: '\/hunts'/)
})

test('history filter state lives in the URL so a view survives reload and back', () => {
  assert.match(page, /useUrlFilters<HuntFilters>/)
})

test('search is debounced rather than firing per keystroke', () => {
  assert.match(page, /SEARCH_DEBOUNCE_MS/)
  assert.match(page, /clearTimeout\(debounce\.current\)/)
})

test('paging is server-side and reports the true total', () => {
  assert.match(page, /offset: \(page - 1\) \* PAGE_SIZE/)
  assert.match(page, /Showing \$\{first\}-\$\{last\} of \$\{total\}/)
})

test('sorting and filtering cover target, status and kind', () => {
  for (const field of ['created_at', 'updated_at', 'completed_at', 'target_url', 'status']) {
    assert.ok(page.includes(`'${field}'`), `sort option ${field} missing`)
  }
  assert.match(page, /setFilter\('status'/)
  assert.match(page, /setFilter\('kind'/)
})

test('a background refresh failure does not blank the rows being read', () => {
  assert.match(page, /if \(!isPolling\) setLoadError/)
})

test('the page distinguishes loading, empty and error', () => {
  assert.match(page, /TableSkeleton/)
  assert.match(page, /EmptyState/)
  assert.match(page, /ErrorState/)
})

test('the launcher no longer renders a failed history fetch as "no hunts"', () => {
  // It swallowed the error and set an empty list, which is a different and far more
  // reassuring claim than "we could not load them".
  assert.doesNotMatch(launcher, /\.catch\(\(\) => \{ if \(!cancelled\) setHuntHistory\(\[\]\) \}\)/)
  assert.match(launcher, /setHuntHistoryError\(/)
  assert.match(launcher, /error \? \(/)
})

test('the launcher links to the full history instead of capping silently', () => {
  assert.match(launcher, /href=\{`\/hunts\?search=/)
  assert.match(launcher, /View all \$\{total\}/)
})

test('the client sends every supported filter and reads the total', () => {
  for (const param of ['target_id', 'status', 'target_kind', 'search', 'sort_by', 'sort_order', 'offset']) {
    assert.ok(client.includes(`'${param}'`), `client does not send ${param}`)
  }
  assert.match(client, /total: payload\.total/)
})

test('the assurance chip is actually rendered, not just defined', () => {
  const scans = readFileSync(path.join(root, 'src/app/scans/page.tsx'), 'utf8')
  const postureUses = scans.match(/<ObservedPosture scan=\{scan\}/g) || []
  assert.equal(postureUses.length, 2, 'both the card and table views must render observed posture')
  assert.match(scans, /<AssuranceChip scan=\{scan\} \/>/, 'observed posture must include assurance')
})
