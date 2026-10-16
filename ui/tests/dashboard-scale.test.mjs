import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'

const dashboard = readFileSync(new URL('../src/app/page.tsx', import.meta.url), 'utf8')
const asm = readFileSync(new URL('../src/app/asm/page.tsx', import.meta.url), 'utf8')

test('a dashboard exposure failure belongs to its cohort and renders as unavailable, never zeros', () => {
  // The failure is keyed by cohort, so switching cohorts cannot carry it over or hide it.
  assert.match(dashboard, /useState<CohortView \| null>\(null\)/)
  assert.match(dashboard, /setExposureFailedView\(view\)/)
  assert.match(dashboard, /failed: exposureFailedView === cohortView/)
  assert.doesNotMatch(dashboard, /setExposureFailed\(/)
  // Posture, coverage freshness and cohort actions all render the explicit state with a retry.
  assert.match(dashboard, /state === 'unavailable' \? <ExposureUnavailable onRetry=\{onRetry\} \/>/)
  assert.match(dashboard, /exposureState === 'unavailable' \? <ExposureUnavailable onRetry=\{onRetry\} compact \/>/)
  assert.match(dashboard, /unavailable=\{cohortView !== 'all' && posture === 'unavailable' \? exposurePoll\.refresh : null\}/)
  // No primary call to action ("Add a target") is offered from missing data.
  assert.match(dashboard, /\) : state === 'ready' \? \(\s*<Link href=\{primary\.href\}/)
  // An empty scope on a populated install offers "Show all cohorts", never "Add a target".
  assert.match(dashboard, /state === 'ready' && outOfScope && onShowAll \? \(/)
})

test('the dashboard says when coverage or cohort matching covers only part of the estate', () => {
  assert.match(dashboard, /describeCoverageScope\(\{\s*groups: groupedTargets, hasMore: Boolean\(groupsPage\?\.has_more\)/)
  assert.match(dashboard, /\{scope\.show \? \(/)
  assert.match(dashboard, /cohortScopingNote\(\{ view: cohortView, exposure: scopedExposure \}\)/)
  assert.match(dashboard, /data-testid="cohort-scoping-note"/)
})

test('a failed ASM "Load more" keeps the loaded rows and offers a retry', () => {
  const loadMore = asm.slice(asm.indexOf('const loadMore = useCallback'), asm.indexOf('const rows = useMemo'))
  assert.ok(loadMore.length > 0)
  assert.doesNotMatch(loadMore, /setError\(true\)/, 'a later page failing must not replace the table with an error')
  assert.doesNotMatch(loadMore, /setGroups\(\[\]\)/)
  assert.match(loadMore, /setLoadMoreError\(/)
  assert.match(asm, /data-testid="asm-load-more-error"/)
  assert.match(asm, /Retry loading more domains/)
})
