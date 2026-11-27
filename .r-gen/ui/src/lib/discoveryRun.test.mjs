import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

import { DISCOVERY_SCAN_ROLES, hiddenRunsNote, isDiscoveryRun, scansShownText } from './discoveryRun.mjs'

test('a discovery run is told apart from an application Scan by its role', () => {
  assert.equal(isDiscoveryRun({ scan_role: 'asm_recon', scan_type: 'scan', run_kind: 'web_dast' }), true)
  assert.equal(isDiscoveryRun({ scan_role: 'parallel_discovery' }), true)
  for (const role of ['standalone', 'parent', 'shard', 'asm_batch', '', null, undefined]) {
    assert.equal(isDiscoveryRun({ scan_role: role, scan_type: 'scan', run_kind: 'web_dast' }), false, String(role))
  }
  assert.equal(isDiscoveryRun(null), false)
})

test('the roles are the ones the API keeps out of a target\'s latest result', () => {
  const source = readFileSync(new URL('../../../api/scan/discovery_runs.py', import.meta.url), 'utf8')
  const declared = source.match(/^DISCOVERY_SCAN_ROLES = \(([^)]*)\)/m)
  assert.ok(declared)
  assert.deepEqual([...declared[1].matchAll(/"([a-z_]+)"/g)].map((match) => match[1]), DISCOVERY_SCAN_ROLES)
})

test('the Scans list says how many runs it leaves out, and nothing when it hides none', () => {
  assert.equal(hiddenRunsNote(1), '1 discovery or internal run not shown')
  assert.equal(hiddenRunsNote(12), '12 discovery or internal runs not shown')
  for (const none of [0, undefined, null, -1, 'x']) assert.equal(hiddenRunsNote(none), null)
})

test('the list count names the rows shown', () => {
  assert.equal(scansShownText(1, 1, 20), 'Showing 1 scan')
  assert.equal(scansShownText(0, 1, 20), 'Showing 0 scans')
  assert.equal(scansShownText(20, 1, 20), 'Showing 20 scans')
  assert.equal(scansShownText(45, 3, 20), 'Showing 41-45 of 45')
})
