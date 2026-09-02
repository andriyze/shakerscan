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
  assert.match(detail, /limit: 100/)
})

test('scan result reconciles report evidence with durable IDs from the scan payload', () => {
  assert.match(detail, /const scanPersistedCurrent = Array\.isArray\(scan\?\.findings\)/)
  assert.match(detail, /const persistedByKey = new Map/)
  assert.match(detail, /_persisted: Boolean\(persisted\?\.id \|\| finding\.id\)/)
})

test('scan result separates observations from findings not observed by this run', () => {
  assert.match(detail, /Findings observed in this scan/)
  assert.match(detail, /observed in this scan/)
  assert.match(detail, /not observed in this scan/)
  assert.match(detail, /Open all target findings/)
  assert.match(detail, /const rawCurrent = Array\.isArray\(scan\?\.result\?\.findings\)/)
})

test('scan result does not bury the current run under historical target rows', () => {
  assert.match(detail, /const existingTotal = Math\.max/)
  assert.match(detail, /current\.slice\(0, 6\)\.map\(\(finding: any\)/)
  assert.match(detail, /Show \{current\.length - 6\} more findings observed in this scan/)
  assert.doesNotMatch(detail, /rows\.map\(\(finding: any\)/)
  assert.match(detail, /use the link above to review them/)
})
