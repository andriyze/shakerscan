import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

const page = fs.readFileSync(new URL('../src/app/fleet/page.tsx', import.meta.url), 'utf8')
const dashboard = fs.readFileSync(new URL('../src/app/page.tsx', import.meta.url), 'utf8')
const newScan = fs.readFileSync(new URL('../src/app/scan/new/page.tsx', import.meta.url), 'utf8')
const scanDetail = fs.readFileSync(new URL('../src/app/scans/[id]/page.tsx', import.meta.url), 'utf8')

test('fleet access failure does not render an empty fleet as authoritative state', () => {
  assert.match(page, /Enter the fleet operator token to load remote nodes and controls\./)
  assert.match(page, /if \(!loading && error && nodes\.length === 0\)/)
  assert.match(page, /<OperatorAccessCard/)
  assert.match(page, /<ErrorState message=\{error\}/)
  assert.match(page, /catch \(err\) \{[\s\S]*setNodes\(\[\]\)[\s\S]*setSummary\(EMPTY_SUMMARY\)/)
})

test('worker labels stay grammatical and completed shards show useful attribution', () => {
  assert.match(dashboard, /=== 1 \? 'worker' : 'workers'/)
  assert.match(newScan, /active_worker_count === 1 \? 'worker' : 'workers'/)
  assert.match(scanDetail, /const phaseLabel = terminal/)
  assert.match(scanDetail, /rawPhase \|\| \(shard\.executing_node_id/)
  assert.match(scanDetail, /`node \$\{String\(shard\.executing_node_id\)\.slice\(0, 8\)\}`/)
})
