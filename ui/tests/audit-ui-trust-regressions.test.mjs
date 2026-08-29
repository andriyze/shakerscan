import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8')

test('query filter history preserves the App Router route identity', () => {
  const source = read('src/lib/useUrlFilters.ts')
  assert.match(source, /\.\.\.\(window\.history\.state \|\| \{\}\)/)
  assert.doesNotMatch(source, /pushState\(null/)
  assert.doesNotMatch(source, /replaceState\(null/)
})

test('exposure filters drive metrics, map, and priorities with one asset set', () => {
  const page = read('src/app/exposure/page.tsx')
  const paths = read('src/app/exposure/AttackPaths.tsx')
  assert.match(page, /const filteredAssets = useMemo/)
  assert.match(page, /filteredAssets\.filter\(\(a\) => a\.needs_action\)/)
  assert.match(page, /nodes=\{graphView\?\.nodes/)
  assert.match(page, /metrics=\{displayedMetrics\}/)
  assert.match(page, /Active critical findings/)
  assert.doesNotMatch(paths, /smart or full scans/i)
})

test('target groups distinguish domains from hosts and internal identities', () => {
  const page = read('src/app/targets/page.tsx')
  assert.match(page, /registrable_domain/)
  assert.match(page, /internal_service/)
  assert.match(page, /identity\.canDiscoverSubdomains/)
  assert.match(page, /runtime destination policy is checked before execution/)
  assert.doesNotMatch(page, /always show for root domains/)
})

test('finding copy failures and empty presentation have visible fallbacks', () => {
  const detail = read('src/app/findings/[id]/page.tsx')
  const candidates = read('src/app/findings/candidates/page.tsx')
  assert.match(detail, /Clipboard access failed/)
  assert.match(detail, /select text/)
  assert.match(detail, /cvss_score !== null/)
  assert.match(detail, /Canonical lifecycle/)
  assert.match(detail, /summaryDescription\.trim\(\)\.toLowerCase\(\) !== String\(finding\?\.title/)
  assert.match(candidates, /candidate\.claim\.trim\(\)\.toLowerCase\(\) !== candidate\.title/)
})

test('finding evidence names original, latest-observation, and producing scans separately', () => {
  const detail = read('src/app/findings/[id]/page.tsx')
  assert.match(detail, /Original finding scan:/)
  assert.match(detail, /Latest observation scan:/)
  assert.match(detail, /evidence-producing scan/)
  assert.doesNotMatch(detail, /<span>Scan:<\/span>/)
})

test('docs and mobile operations expose truthful accessible labels', () => {
  const docs = read('src/app/docs/page.tsx')
  const dashboard = read('src/app/page.tsx')
  const sidebar = read('src/components/Sidebar.tsx')
  assert.match(docs, /h1: \(\{ children \}\) => \(\s*<h2/)
  assert.match(dashboard, />Emergency clear<\/span>/)
  assert.match(dashboard, /current workers/)
  assert.match(sidebar, /Show advanced sections \(Records, Governance, Developer\)/)
  assert.doesNotMatch(sidebar, /Interactive Testing, Leads/)
})

test('executive posture defaults to an explicit operational cohort scope', () => {
  const dashboard = read('src/app/page.tsx')
  const targets = read('src/app/targets/page.tsx')
  const triage = read('src/app/exposure/TriageTable.tsx')
  assert.match(dashboard, /useState<CohortView>\('operational'\)/)
  assert.match(dashboard, /Lab data is never silently mixed into it/)
  assert.match(dashboard, /buildCohortActions\(scopedExposure\)/)
  assert.match(targets, /<option value="calibration">Calibration<\/option>/)
  assert.match(triage, /Executive cohort/)
})

test('scan submission titles follow the live execution status', () => {
  const timeline = read('src/app/timeline/page.tsx')
  assert.match(timeline, /completed: 'Scan completed'/)
  assert.match(timeline, /blocked: 'Scan blocked'/)
  assert.doesNotMatch(timeline, /'Scan\.submit': 'Scan queued'/)
})

test('scoped dashboard refuses unbound and unscoped historical rows', () => {
  const dashboard = read('src/app/page.tsx')
  const targets = read('src/app/targets/page.tsx')
  assert.match(dashboard, /rowMatchesCohort\(scan\.target_id, scan\.target_url/)
  assert.match(dashboard, /What changed is hidden in scoped mode/)
  assert.match(dashboard, /Observed posture \{scan\.grade\}/)
  assert.match(dashboard, /assurance\.label.*assurance\.score/)
  assert.match(targets, /Observed \{domain\.root_target\.last_grade\} · review coverage/)
  assert.doesNotMatch(targets, /hidden text-xl font-bold sm:inline/)
  const scans = read('src/app/scans/page.tsx')
  assert.match(scans, />Observed posture</)
  assert.match(scans, /Examination strength \$\{assurance\.score\}\/100/)
  assert.match(scans, /scan\.status !== 'completed'/)
  assert.match(scans, /asterisk marks assurance limitations/)
  assert.doesNotMatch(dashboard, /text-lg font-semibold[^\n]+scan\.grade/)
})

test('scan failure summaries do not contradict terminal result state', () => {
  const detail = read('src/app/scans/[id]/page.tsx')
  const scans = read('src/app/scans/page.tsx')
  assert.match(detail, /split\(\/\\s\+Last logs:/)
  assert.match(detail, /Execution coverage is incomplete/)
  assert.match(detail, /No score or grade was produced/)
  assert.doesNotMatch(detail, />Grade is provisional</)
  assert.match(scans, /Examination strength unavailable/)
})
