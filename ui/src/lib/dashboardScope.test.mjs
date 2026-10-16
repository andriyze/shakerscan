import assert from 'node:assert/strict'
import test from 'node:test'

import { cohortScopingNote, coverageScope, postureState } from './dashboardScope.mjs'

test('a failed exposure read is unavailable, never an empty (all-clear) posture', () => {
  assert.equal(postureState({ enabled: true, exposure: null, failed: true }), 'unavailable')
  assert.equal(postureState({ enabled: true, exposure: null, failed: false }), 'loading')
  assert.equal(postureState({ enabled: true, exposure: { metrics: { asset_count: 0 } }, failed: false }), 'ready')
  // A later refresh failing keeps the numbers read for this cohort.
  assert.equal(postureState({ enabled: true, exposure: { metrics: {} }, failed: true }), 'ready')
  assert.equal(postureState({ enabled: true, exposure: {}, failed: true }), 'unavailable', 'a body without metrics is not data')
  assert.equal(postureState({ enabled: false, exposure: null, failed: true }), 'disabled')
})

test('coverage scope speaks when the domain page or a group member list was cut', () => {
  const full = { subdomains: [{}, {}], subdomain_count: 2 }
  assert.equal(coverageScope({ groups: [full], hasMore: false, total: '1' }).show, false)

  const cut = coverageScope({ groups: [full, { subdomains: new Array(20).fill({}), subdomain_count: 57 }], hasMore: false, total: null })
  assert.equal(cut.show, true)
  assert.equal(cut.truncatedGroups, 1)
  assert.match(cut.text, /1 domain has more subdomains than counted here/)

  const flagged = coverageScope({ groups: [{ subdomains: [], subdomains_truncated: true }], hasMore: false, total: null })
  assert.equal(flagged.truncatedGroups, 1)

  const paged = coverageScope({ groups: [full, full], hasMore: true, total: '10,000+' })
  assert.equal(paged.show, true)
  assert.match(paged.text, /Across the 2 domains with the most findings, of 10,000\+/)
})

test('cohort scoping of recent rows is labelled once the cohort outgrows the exposure page', () => {
  const assets = new Array(200).fill({})
  assert.equal(cohortScopingNote({ view: 'all', exposure: { assets, total: 5000 } }), null)
  assert.equal(cohortScopingNote({ view: 'production', exposure: { assets, total: 200 } }), null)
  assert.equal(cohortScopingNote({ view: 'production', exposure: null }), null)
  assert.match(cohortScopingNote({ view: 'production', exposure: { assets, total: 5000 } }), /200 highest-ranked of 5,000 assets/)
  assert.match(cohortScopingNote({ view: 'staging', exposure: { assets, metrics: { asset_count: 900 } } }), /of 900 assets/)
})

// UI audit 2.11 #4: with every target in the lab cohort the default scope showed zeros and the
// empty-install "Add a target" prompt. An empty scope on a populated install says where data is.
test('an empty scope with data in other cohorts says so; the scope comes from the URL', async () => {
  const { outOfScopeSummary, parseCohortView } = await import('./dashboardScope.mjs')
  assert.equal(parseCohortView(undefined), 'operational')
  assert.equal(parseCohortView('all'), 'all')
  assert.equal(parseCohortView('non_operational'), 'non_operational')
  assert.equal(parseCohortView('nonsense'), 'operational')

  const lab = { total: 0, metrics: { asset_count: 0 }, cohort_counts: { lab: 5 } }
  const summary = outOfScopeSummary({ view: 'operational', exposure: lab, installFindings: 75 })
  assert.deepEqual({ assets: summary.assets, findings: summary.findings, where: summary.where }, { assets: 5, findings: 75, where: '5 lab' })
  assert.equal(summary.text, 'Nothing in this scope yet. 5 targets and 75 open findings are in other cohorts (5 lab).')
  assert.equal(outOfScopeSummary({ view: 'production', exposure: { metrics: { asset_count: 0 }, cohort_counts: { staging: 1 } }, installFindings: 0 }).text,
    'Nothing in this scope yet. 1 target is in other cohorts (1 staging).')

  // Not for a scope with assets, an empty install, "all", or before exposure loaded.
  assert.equal(outOfScopeSummary({ view: 'operational', exposure: { metrics: { asset_count: 2 }, cohort_counts: { lab: 5, production: 2 } }, installFindings: 9 }), null)
  assert.equal(outOfScopeSummary({ view: 'operational', exposure: { metrics: { asset_count: 0 }, cohort_counts: {} }, installFindings: 0 }), null)
  assert.equal(outOfScopeSummary({ view: 'all', exposure: lab, installFindings: 75 }), null)
  assert.equal(outOfScopeSummary({ view: 'operational', exposure: null, installFindings: 75 }), null)
  // Members of the chosen scope never count as "elsewhere".
  assert.equal(outOfScopeSummary({ view: 'operational', exposure: { metrics: { asset_count: 0 }, cohort_counts: { unclassified: 0, lab: 2 } }, installFindings: 0 }).where, '2 lab')
})
