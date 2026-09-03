import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import { scanAssurance } from '../src/lib/assurance.mjs'
import { scanResultPresentation } from '../src/lib/scanDetailPresentation.mjs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const detail = readFileSync(path.join(root, 'src/app/scans/[id]/page.tsx'), 'utf8')

function scanWith({ reasons = [], gaps = [], families = [], gradeReliable = true, score = 93 }) {
  return {
    id: 'scan-1',
    result: {
      findings: [
        { title: 'A', severity: 'high', verified: true, proof_state: 'verified', url: 'http://t/a?x=1' },
        { title: 'B', severity: 'high', verified: false, proof_state: 'likely_vulnerable', url: 'http://t/b' },
      ],
      coverage: { reasons, selected_family_gaps: families },
      result: { assurance_score: score, assurance_gaps: gaps, grade_reliable: gradeReliable, risk_score: 14, risk_grade: 'F' },
    },
  }
}

test('a strong examination that finished everything endorses the conclusion', () => {
  const scan = scanWith({})
  const presentation = scanResultPresentation(scan, scanAssurance(scan))
  assert.equal(presentation.confidenceTone, 'supporting')
  assert.equal(presentation.coverageIncomplete, false)
  assert.match(presentation.confidence, /supports this run-level conclusion/)
  assert.equal(presentation.observedCount, 2)
  assert.equal(presentation.confirmedCount, 1)
  assert.equal(presentation.candidateCount, 1)
})

test('a strong score over an unfinished run is qualified, never endorsed, and names the families', () => {
  const scan = scanWith({
    reasons: ['timed_out'],
    gaps: ['required_actions_complete', 'selected_families_complete'],
    families: ['nuclei_passive', 'xss'],
    gradeReliable: false,
  })
  const presentation = scanResultPresentation(scan, scanAssurance(scan))
  assert.equal(presentation.confidenceTone, 'qualified')
  assert.equal(presentation.coverageIncomplete, true)
  assert.match(presentation.confidence, /did not finish everything it planned/)
  assert.doesNotMatch(presentation.confidence, /supports this run-level conclusion/)
  assert.deepEqual(presentation.incompleteFamilies, ['nuclei passive', 'xss'])
  assert.deepEqual(presentation.coverageGapReasons, ['A planned step ran out of its time allowance before it finished'])
})

test('coverage gap reasons read as what happened to the planned work, not as codes', () => {
  const scan = scanWith({
    reasons: ['insufficient_plan_budget', 'not_applicable', 'some_future_code'],
    gaps: [],
    families: ['sqli'],
    gradeReliable: false,
  })
  const presentation = scanResultPresentation(scan, scanAssurance(scan))
  assert.deepEqual(presentation.coverageGapReasons, [
    'Planned steps were skipped because the admitted budget did not reach them',
    'A planned proof step had no candidate left to prove',
    'some future code',
  ])
})

test('an unreliable grade alone is enough to qualify the conclusion', () => {
  const scan = scanWith({ gradeReliable: false })
  const presentation = scanResultPresentation(scan, scanAssurance(scan))
  assert.equal(presentation.confidenceTone, 'qualified')
})

test('a weak examination keeps the not-a-clean-bill wording', () => {
  const scan = scanWith({ score: 40 })
  const presentation = scanResultPresentation(scan, scanAssurance(scan))
  assert.equal(presentation.confidenceTone, 'weak')
  assert.match(presentation.confidence, /not a clean bill of health/)
})

test('the page renders one coverage-gaps panel and colours a qualified conclusion amber', () => {
  assert.match(detail, /data-testid="coverage-gaps"/)
  assert.match(detail, /resultPresentation\.confidenceTone === 'qualified' \? 'text-amber-200'/)
  assert.match(detail, /that did not finish:/)
  assert.doesNotMatch(detail, /What was not established<\/p>/)
  assert.match(detail, /absence of a finding in an unfinished family is not evidence of safety/)
})

test('finding rows show a route, a proof label, and survive narrow screens', () => {
  assert.match(detail, /function ScanFindingRow\(/)
  assert.match(detail, /function findingLocation\(/)
  assert.match(detail, /sm:grid-cols-\[auto_minmax\(0,1fr\)_auto\]/)
  assert.match(detail, /block truncate font-mono text-xs text-gray-500/)
  assert.match(detail, /\{provenCount\} proven/)
  // The redundant per-row origin pill is gone; origin lives in the section heading.
  assert.doesNotMatch(detail, /\{finding\._origin\}<\/span>/)
})

test('the release decision labels its chips and folds the blocking list', () => {
  assert.match(detail, /<span className="text-gray-500">profile<\/span>/)
  assert.match(detail, /<span className="text-gray-500">policy<\/span>/)
  assert.match(detail, /unresolved on this target from earlier scans/)
  assert.match(detail, /<details className="mt-3 border-t border-gray-800 pt-3">/)
})
