import assert from 'node:assert/strict'
import test from 'node:test'

import { scanCountLine, scanCountSummary } from './scanCountLine.mjs'
import { scanFindingCounts, scanFindingCountsText, scanResultPresentation } from './scanDetailPresentation.mjs'

function findings(spec) {
  const rows = []
  for (const [severity, proven, unproven] of spec) {
    for (let index = 0; index < proven; index += 1) rows.push({ title: `${severity} proven ${index}`, severity, proof_state: 'verified' })
    for (let index = 0; index < unproven; index += 1) rows.push({ title: `${severity} open ${index}`, severity, proof_state: 'suspected' })
  }
  return rows
}

// 44 findings: 21 critical, 17 high, 2 low, 4 informational; 28 proven, of which 22 are medium or higher.
const RUN = { id: 's', result: { findings: findings([['critical', 12, 9], ['high', 10, 7], ['low', 2, 0], ['info', 4, 0]]), result: {} } }

test('one line relates the totals the Scan page shows', () => {
  assert.equal(scanCountLine(RUN),
    '44 findings in this run: 28 proven, 16 awaiting verification. Critical or high: 38. Proven at medium or higher: 22.')
})

test('the line uses the numbers of the headline, the severity chips and the Findings tab', () => {
  const summary = scanCountSummary(RUN)
  // The headline's "confirmed material issues".
  assert.equal(summary.provenMaterial, scanResultPresentation(RUN, null).confirmedCount)
  // The Findings tab's own summary.
  const tab = scanFindingCounts(RUN.result.findings)
  assert.deepEqual({ total: summary.total, proven: summary.proven, verify: summary.verify }, { total: tab.total, proven: tab.proven, verify: tab.verify })
  assert.equal(scanFindingCountsText(tab), '28 proven (22 medium or higher) · 16 need verification')
  // The critical and high chips.
  assert.equal(summary.criticalOrHigh, 21 + 17)
  assert.equal(summary.proven + summary.verify + summary.informational, summary.total)
})

test('unproven low and informational findings are named, and a run without findings has no line', () => {
  const run = { result: { findings: findings([['medium', 1, 0], ['low', 0, 2], ['info', 0, 1]]) } }
  assert.equal(scanCountLine(run),
    '4 findings in this run: 1 proven, 3 informational. Critical or high: 0. Proven at medium or higher: 1.')
  assert.equal(scanCountLine({ findings: findings([['high', 0, 1]]) }),
    '1 finding in this run: 0 proven, 1 awaiting verification. Critical or high: 1. Proven at medium or higher: 0.')
  assert.equal(scanCountLine({ result: { findings: [] } }), null)
  assert.equal(scanCountLine(null), null)
})
