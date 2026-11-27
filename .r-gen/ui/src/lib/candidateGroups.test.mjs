import assert from 'node:assert/strict'
import test from 'node:test'

import { candidatePageRange, candidateTargetLabel, groupCandidatesByTarget } from './candidateGroups.mjs'

test('a candidate names its target by name, then address, never only by id when either exists', () => {
  assert.equal(candidateTargetLabel({ target_id: 'a', target_name: 'Shop', target_url: 'https://shop.test' }), 'Shop')
  assert.equal(candidateTargetLabel({ device_target_id: 'b', target_name: '', target_url: 'host://10.0.0.5' }), '10.0.0.5')
  assert.equal(candidateTargetLabel({ device_target_id: '0123456789abcdef' }), 'Target 01234567')
  assert.equal(candidateTargetLabel({}), 'Unknown target')
})

test('candidates are grouped per target in first-seen order, web and device ids alike', () => {
  const rows = [
    { id: 1, target_id: 'web', target_name: 'Shop' },
    { id: 2, device_target_id: 'host', target_name: 'Edge' },
    { id: 3, target_id: 'web', target_name: 'Shop' },
  ]
  const groups = groupCandidatesByTarget(rows)
  assert.deepEqual(groups.map(g => [g.label, g.candidates.map(c => c.id)]), [['Shop', [1, 3]], ['Edge', [2]]])
})

test('the page range counts what is listed', () => {
  assert.equal(candidatePageRange({ offset: 50, count: 50, total: 312 }), 'Showing 51–100 of 312')
  assert.equal(candidatePageRange({ offset: 0, count: 0, total: 0 }), 'Showing 0 of 0')
})
