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

test('worker labels stay grammatical and completed shards show useful attribution', async () => {
  // Behaviour over real counts, not the exact ternary a page happens to use:
  // rewording the copy must not fail this, but bad grammar must.
  const { workerCountLabel, placementPreviewLabel } = await import(
    '../src/lib/labels.ts'
  )
  assert.equal(workerCountLabel(0), '0 local workers running')
  assert.equal(workerCountLabel(1), '1 local worker running')
  assert.equal(workerCountLabel(2), '2 local workers running')
  assert.equal(placementPreviewLabel('single', 3), 'one compatible current worker')
  assert.equal(placementPreviewLabel('parallel', 1), 'up to 1 compatible current worker')
  assert.equal(placementPreviewLabel('parallel', 4), 'up to 4 compatible current workers')
  // Both pages must render through the shared helper rather than re-deriving it.
  assert.match(dashboard, /workerCountLabel\(/)
  assert.match(newScan, /placementPreviewLabel\(/)
  assert.match(scanDetail, /const phaseLabel = terminal/)
  assert.match(scanDetail, /rawPhase \|\| \(shard\.executing_node_id/)
})

test('dashboard distinguishes logical scans, worker jobs, and worker processes', () => {
  assert.match(dashboard, /Scan and work queue/)
  assert.match(dashboard, /work unit\{workRunning === 1 \? '' : 's'\} running/)
  assert.match(dashboard, /workers · limit/)
  assert.doesNotMatch(dashboard, /\{workerCount\} running · max/)
})
