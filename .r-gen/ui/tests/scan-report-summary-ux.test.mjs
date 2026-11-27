import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const report = readFileSync(path.join(root, 'src/components/ReportView.tsx'), 'utf8')

test('canonical DAST summary uses the persisted budget and permission names', () => {
  assert.match(report, /\? 'DAST Scan'/)
  assert.match(report, />Workflow</)
  assert.match(report, /'Budget & permissions'/)
  assert.match(report, /scanBudgetAndPolicyLabel/)
  assert.doesNotMatch(report, /scan\.options\?\.quick \? 'Quick' : 'Thorough'/)
})

test('HTTP usage falls back to canonical finalizer budget usage', () => {
  assert.match(report, /scanData\.scan_metadata\?\.budget_used/)
  assert.match(report, /canonicalBudgetUsed\.http_requests/)
  assert.match(report, /canonicalBudgetLimit\.max_http_requests/)
  assert.match(report, /scan\.execution_explanation\?\.budget/)
  assert.match(report, /scanData\.parallel && executionHttpRequests !== undefined/)
  assert.match(report, /\{attemptedHttpRequests\}\/\{httpRequestLimit\} requests used/)
})

test('parallel reports render canonical action gaps and partial status', () => {
  assert.match(report, /coverageActionRows/)
  assert.match(report, /coverageGapIssues/)
  assert.match(report, /Completed with partial coverage/)
})
