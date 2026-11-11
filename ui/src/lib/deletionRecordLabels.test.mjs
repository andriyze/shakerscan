import assert from 'node:assert/strict'
import test from 'node:test'

import { deletionRecordRows } from './deletionRecordLabels.mjs'

test('record kinds people know are named, in a fixed order; working records are gathered with one total', () => {
  const rows = deletionRecordRows({
    scan_work_manifests: { count: 7 }, findings: { count: 44 }, http_transactions: { count: 1255 },
    targets: { count: 2 }, scan_action_plan_revisions: { count: 6 }, scans: { count: 2 },
  })
  assert.deepEqual(rows.named.map((row) => [row.label, row.count]), [
    ['Targets', 2], ['Scans', 2], ['Findings', 44], ['Recorded requests and responses', 1255],
  ])
  assert.deepEqual(rows.other.map((row) => [row.label, row.count]), [['Scan work manifests', 7], ['Scan action plan revisions', 6]])
  assert.equal(rows.otherTotal, 13)
})

test('every counted kind is kept: nothing in the preview is dropped from the dialog', () => {
  const input = { findings: { count: 1 }, something_new: { count: 3 }, odd: {} }
  const rows = deletionRecordRows(input)
  assert.equal(rows.named.length + rows.other.length, Object.keys(input).length)
  assert.deepEqual(deletionRecordRows(null), { named: [], other: [], otherTotal: 0 })
})
