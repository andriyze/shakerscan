import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const detail = readFileSync(path.join(root, 'src/app/scans/[id]/page.tsx'), 'utf8')

test('scan details load log history after a scan reaches a terminal state', () => {
  assert.match(detail, /let logData = await getScanLogs\(scanId, 500, signal, logDeltaRef\.current\.nextSeq\)/)
  // A terminal scan (opened fresh or just finished) still gets its log read.
  assert.match(detail, /logForceRef\.current = true\s*\n\s*logsPoll\.refresh\(\)/)
  // A new scan or retry resets the log loop during render, before usePoll's first tick reads it.
  const reset = detail.indexOf('if (logLoopKeyRef.current !== logLoopKey)')
  assert.ok(reset > 0 && reset < detail.indexOf('const logsPoll = usePoll('))
  assert.doesNotMatch(detail, /data\?\.status === 'running' \|\| data\?\.status === 'pending' \|\| isModelIntake/)
})

test('completed and failed DAST views retain a readable execution log', () => {
  assert.match(detail, /Scan execution log \(\{logs\.length\} lines\)/)
  assert.match(detail, /\{renderStoredScanLogs\(true\)\}/)
  // A completed scan keeps its log on the Activity tab, open: it is that tab's content.
  assert.match(detail, /tab="activity" active=\{reportTab\}>[\s\S]*?\{renderStoredScanLogs\(true\)\}/)
})

test('running scans lead with readable progress and searchable live activity', () => {
  assert.match(detail, /Live scan activity/)
  assert.match(detail, /Updates every 5–30 seconds \(slower while quiet\)/)
  assert.match(detail, /Key activity/)
  assert.match(detail, /Warnings & errors/)
  assert.match(detail, /Finding signals/)
  assert.match(detail, /placeholder="Search logs"/)
  assert.match(detail, /Following latest/)
  assert.match(detail, /role="progressbar"/)
  assert.match(detail, /You can leave this page/)
})
