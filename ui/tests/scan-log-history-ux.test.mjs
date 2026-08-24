import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const detail = readFileSync(path.join(root, 'src/app/scans/[id]/page.tsx'), 'utf8')

test('scan details load log history after a scan reaches a terminal state', () => {
  assert.match(detail, /const logData = await getScanLogs\(scanId, 200\)/)
  assert.doesNotMatch(detail, /data\?\.status === 'running' \|\| data\?\.status === 'pending' \|\| isModelIntake/)
})

test('completed and failed DAST views retain a readable execution log', () => {
  assert.match(detail, /Scan execution log \(\{logs\.length\} lines\)/)
  assert.match(detail, /\{renderStoredScanLogs\(true\)\}/)
  assert.match(detail, /\{renderStoredScanLogs\(\)\}/)
})
