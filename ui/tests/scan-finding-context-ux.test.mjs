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

test('scan result separates current signals from earlier target findings', () => {
  assert.match(detail, /Findings from this scan and earlier scans/)
  assert.match(detail, /from this scan/)
  assert.match(detail, /already on target/)
  assert.match(detail, /Open all target findings/)
  assert.match(detail, /const rawCurrent = Array\.isArray\(scan\?\.result\?\.findings\)/)
})
