import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const report = readFileSync(path.join(root, 'src/components/ReportView.tsx'), 'utf8')
const coverage = readFileSync(path.join(root, 'src/components/report/ScanCoverageSection.tsx'), 'utf8')

test('scan coverage is a bounded report component with canonical language', () => {
  assert.match(report, /<ScanCoverageSection coverage=\{smart_coverage\} \/>/)
  assert.doesNotMatch(report, /Templates by Category/)
  assert.match(coverage, /aria-labelledby="scan-coverage-heading"/)
  assert.match(coverage, />Scan Coverage</)
  assert.match(coverage, /no parameters inventoried/)
  assert.match(coverage, /run_approximate/)
  assert.match(coverage, /\sestimated\s/)
})

test('coverage bars clamp malformed persisted percentages', () => {
  assert.match(coverage, /Math\.max\(0, Math\.min\(normalized \* 100, 100\)\)/)
})
