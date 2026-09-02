import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const detail = readFileSync(path.join(root, 'src/app/scans/[id]/page.tsx'), 'utf8')

test('scan details load log history after a scan reaches a terminal state', () => {
  assert.match(detail, /const logData = await getScanLogs\(scanId, 500\)/)
  assert.doesNotMatch(detail, /data\?\.status === 'running' \|\| data\?\.status === 'pending' \|\| isModelIntake/)
})

test('completed and failed DAST views retain a readable execution log', () => {
  assert.match(detail, /Scan execution log \(\{logs\.length\} lines\)/)
  assert.match(detail, /\{renderStoredScanLogs\(true\)\}/)
  assert.match(detail, /\{renderStoredScanLogs\(\)\}/)
})

test('running scans lead with readable progress and searchable live activity', () => {
  assert.match(detail, /Live scan activity/)
  assert.match(detail, /Updates every 3 seconds/)
  assert.match(detail, /Key activity/)
  assert.match(detail, /Warnings & errors/)
  assert.match(detail, /Finding signals/)
  assert.match(detail, /placeholder="Search logs"/)
  assert.match(detail, /Following latest/)
  assert.match(detail, /role="progressbar"/)
  assert.match(detail, /You can leave this page/)
})
