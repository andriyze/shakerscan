import assert from 'node:assert/strict'
import test from 'node:test'
import { featureEnabled, navigationAllowed } from '../src/lib/workspaceCapabilities.ts'

const policy = {
  schema: 'shakerscan.workspace-capabilities/v1', mode: 'managed',
  features: { targets: { state: 'enabled' }, hunt: { state: 'unavailable' },
    fleet: { state: 'excluded' } },
  navigation: { '/targets': 'targets', '/hunt': 'hunt', '/fleet': 'fleet' },
  ui_routes: ['/targets', '/hunt', '/fleet'],
}

test('standalone retains features; managed deployments hide unavailable and excluded routes', () => {
  global.window = {}
  assert.equal(featureEnabled('hunt'), true)
  window.__SHAKERSCAN_CAPABILITIES__ = policy
  assert.equal(featureEnabled('hunt'), false)
  assert.equal(navigationAllowed('/targets?cohort=staging'), true)
  assert.equal(navigationAllowed('/targets/unreviewed/subroute'), false)
  assert.equal(navigationAllowed('/hunt'), false)
  assert.equal(navigationAllowed('/fleet'), false)
  assert.equal(navigationAllowed('/targets-evil'), false)
  assert.equal(navigationAllowed('/new-unreviewed-feature'), false)
  delete global.window
})

test('unknown capability contracts fail closed', () => {
  global.window = { __SHAKERSCAN_CAPABILITIES__: { ...policy, schema: 'future' } }
  assert.equal(featureEnabled('targets'), false)
  assert.equal(navigationAllowed('/targets'), false)
  delete global.window
})
