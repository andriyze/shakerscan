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
