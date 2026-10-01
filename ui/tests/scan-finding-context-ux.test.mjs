import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const detail = readFileSync(path.join(root, 'src/app/scans/[id]/page.tsx'), 'utf8')

test('scan result fetches durable finding history for its exact target', () => {
  assert.match(detail, /getFindings\(\{/)
  assert.match(detail, /target_id: data\.target_id/)
  // Every active row is paged in; a cap that cannot be reached is a partial history, not an all-clear.
  assert.match(detail, /limit: pageSize/)
  assert.match(detail, /offset < HISTORY_ROW_CAP/)
  assert.match(detail, /setTargetFindingsPartial\(rows\.length < total\)/)
  assert.match(detail, /not an all-clear/)
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
