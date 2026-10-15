import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const detail = readFileSync(path.join(root, 'src/app/scans/[id]/page.tsx'), 'utf8')

test('scan result fetches durable finding history for its exact target: one bounded page, once', () => {
  assert.match(detail, /getFindingsPage\(\s*\{ target_id: historyTargetId, status: 'active' \}/)
  // One page, newest observation first (this run's re-observed rows are on it), with an exact count.
  assert.match(detail, /limit: HISTORY_PAGE_SIZE, sort: '-last_seen', count: 'exact'/)
  assert.match(detail, /const HISTORY_PAGE_SIZE = 200/)
  // No loop over every active row any more.
  assert.doesNotMatch(detail, /HISTORY_ROW_CAP/)
  assert.doesNotMatch(detail, /for \(let offset = 0; offset </)
  // More rows than the page (or a capped count) is a partial history, not an all-clear.
  assert.match(detail, /setTargetFindingsPartial\(page\.has_more \|\| page\.total_kind === 'at_least' \|\| rows\.length < total\)/)
  assert.match(detail, /not an all-clear/)
  // Read once per terminal scan, not on every poll tick.
  assert.match(detail, /\}, \[scanTerminal, historyTargetId, scanId, retryNonce\]\)/)
})

test('scan detail polls through usePoll: 5 s while live, stopped when terminal, logs backing off', () => {
  assert.doesNotMatch(detail, /setInterval\(/)
  assert.match(detail, /intervalMs: SCAN_REFRESH_MS, idleIntervalMs: null, live: scan === null \|\| scanLive/)
  assert.match(detail, /const SCAN_REFRESH_MS = 5000/)
  assert.match(detail, /const LOG_MAX_SKIP = 6/)
  assert.match(detail, /logSkipRef\.current\.every = Math\.min\(LOG_MAX_SKIP, logSkipRef\.current\.every \* 2\)/)
  assert.match(detail, /live: scanLive, enabled: scan !== null/)
  // One final tail read on the live -> terminal transition.
  assert.match(detail, /scanTerminal && \(before === 'running' \|\| before === 'pending'\)/)
  assert.match(detail, /\[content-visibility:auto\]/)
})

test('scans list polls only while work is live and keeps its total on count=none polls', () => {
  const list = readFileSync(path.join(root, 'src/app/scans/page.tsx'), 'utf8')
  assert.doesNotMatch(list, /setInterval\(\(\) => \{\s*fetchScans/)
  assert.match(list, /count: isPolling \? 'none' : 'exact'/)
  assert.match(list, /if \(typeof data\.total === 'number'\)/)
  assert.match(list, /!isPolling && rawPage > maxPage/)
  assert.match(list, /intervalMs: SCANS_LIVE_REFRESH_MS,\s*idleIntervalMs: SCANS_IDLE_REFRESH_MS,\s*live,/)
  assert.match(list, /scan\.status === 'pending' \|\| scan\.status === 'running'\) \|\| activeHunts\.length > 0/)
})

test('scan result reconciles report evidence with durable IDs from the scan payload', () => {
  assert.match(detail, /reconciledScanFindings\(scan, targetFindings\)/)
})

test('scan result separates observations from findings not observed by this run', () => {
  assert.match(detail, /Findings observed in this scan/)
  assert.match(detail, /observed in this scan/)
  assert.match(detail, /not observed in this scan/)
  assert.match(detail, /Open all target findings/)
  assert.match(detail, /reconciledScanFindings\(scan, targetFindings\)/)
})

test('scan result does not bury the current run under historical target rows', () => {
  // Only this run's observations are listed, grouped (proven, needs verification, then the
  // informational rest folded away); earlier target findings stay a count and a link.
  assert.match(detail, /const groups = groupScanFindings\(current\)/)
  assert.match(detail, /group\.key === 'informational' \? \(\s*<details/)
  assert.match(detail, /Math\.max\(0, targetFindingsTotal - persistedCurrentCount\)/)
  assert.doesNotMatch(detail, /targetFindings\.map\(\(finding: any\)/)
  assert.doesNotMatch(detail, /rows\.map\(\(finding: any\)/)
  assert.match(detail, /use the link above to review them/)
  // The count matches the release gate's carried-over number when the gate supplies one.
  assert.match(detail, /carriedCount=\{carriedOverFromDecision\(deploymentDecision\)\?\.count \?\? null\}/)
})
