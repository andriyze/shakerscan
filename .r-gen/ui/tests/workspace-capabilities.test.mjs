import assert from 'node:assert/strict'
import test from 'node:test'
import { DEFAULT_EDITION_LABEL, featureEnabled, navigationAllowed, workspaceEdition, workspaceScanCeiling } from '../src/lib/workspaceCapabilities.ts'

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

test('server render without window matches the standalone client so nav does not hydrate-mismatch', () => {
  delete global.window
  assert.equal(typeof globalThis.window, 'undefined')
  // The server has no client-injected policy; it must render the same full surface a
  // standalone client (window defined, no policy) renders, or the nav flips on hydration.
  assert.equal(featureEnabled('hunt'), true)
  assert.equal(navigationAllowed('/targets'), true)
  assert.equal(navigationAllowed('/hunt'), true)
  assert.equal(navigationAllowed('/anything-at-all'), true)
})

test('unknown capability contracts fail closed', () => {
  global.window = { __SHAKERSCAN_CAPABILITIES__: { ...policy, schema: 'future' } }
  assert.equal(featureEnabled('targets'), false)
  assert.equal(navigationAllowed('/targets'), false)
  delete global.window
})

test('workspace limits narrow engine limits without changing standalone ceilings', () => {
  global.window = {}
  assert.equal(workspaceScanCeiling('max_workers', 4), 4)
  window.__SHAKERSCAN_CAPABILITIES__ = { ...policy, scan_limits: { max_workers: 1, max_http_requests: 9000 } }
  assert.equal(workspaceScanCeiling('max_workers', 4), 1)
  assert.equal(workspaceScanCeiling('max_workers'), 1)
  assert.equal(workspaceScanCeiling('max_http_requests', 5000), 5000)
  assert.equal(workspaceScanCeiling('max_http_requests', 60000), 9000)
  delete global.window
})


test('the edition label comes from a managed manifest and defaults to Open Source Edition', () => {
  delete global.window
  assert.equal(workspaceEdition(), undefined, 'server render has no label to show')
  assert.equal(DEFAULT_EDITION_LABEL, 'Open Source Edition')
  global.window = {}
  assert.equal(workspaceEdition(), undefined, 'standalone client keeps the default')
  window.__SHAKERSCAN_CAPABILITIES__ = {
    schema: 'shakerscan.workspace-capabilities/v1', mode: 'managed', features: {}, navigation: {}, ui_routes: [],
    edition: '  Enterprise Edition ',
  }
  assert.equal(workspaceEdition(), 'Enterprise Edition')
  window.__SHAKERSCAN_CAPABILITIES__.edition = 'x'.repeat(61)
  assert.equal(workspaceEdition(), undefined, 'an oversized label is ignored')
  window.__SHAKERSCAN_CAPABILITIES__ = { schema: 'other', mode: 'managed', edition: 'Enterprise Edition' }
  assert.equal(workspaceEdition(), undefined, 'unknown contracts fail closed')
  delete global.window
})

test('the session answer is loaded once, and allows everything until it arrives', async () => {
  const { sessionActionAllowed, sessionPageAllowed, sessionCapabilities, subscribeSessionCapabilities } =
    await import('../src/lib/workspaceCapabilities.ts')
  global.window = {}
  assert.equal(sessionActionAllowed('targets.add'), true)
  let loads = 0
  let resolve
  const load = () => { loads += 1; return new Promise(done => { resolve = done }) }
  let notified = 0
  const stopA = subscribeSessionCapabilities(() => { notified += 1 }, load)
  const stopB = subscribeSessionCapabilities(() => { notified += 1 }, load)
  assert.equal(loads, 1)
  assert.equal(sessionPageAllowed('/devices'), true)
  resolve({ default: 'deny', actions: { 'secrets.read': false }, pages: { '/devices': false }, reasons: {}, role: 'viewer' })
  await new Promise(done => setImmediate(done))
  assert.equal(notified, 2)
  assert.equal(sessionCapabilities().role, 'viewer')
  assert.equal(sessionActionAllowed('targets.add'), false)
  assert.equal(sessionPageAllowed('/devices/x'), false)
  assert.equal(sessionPageAllowed('/targets'), true)
  stopA(); stopB()
})

test('extensions are read from a managed policy only, and validated', async () => {
  const { workspaceExtensions } = await import('../src/lib/workspaceCapabilities.ts')
  const extensions = {
    schema: 'shakerscan.ui-extensions/v1',
    pages: [{ id: 'reports', title: 'Reports', src: '/deployment/embed/reports' }],
    nav: [{ label: 'Reports', page: 'reports' }, { label: 'Elsewhere', href: 'https://elsewhere.example/' }],
  }
  delete global.window
  assert.deepEqual(workspaceExtensions().nav, [], 'the server render has none')
  global.window = {}
  assert.deepEqual(workspaceExtensions().nav, [], 'a standalone UI has none')
  window.__SHAKERSCAN_CAPABILITIES__ = { ...policy, extensions }
  assert.deepEqual(workspaceExtensions().nav.map(entry => entry.href), ['/ext/reports'])
  assert.equal(workspaceExtensions(), workspaceExtensions(), 'one validation per declared block')
  window.__SHAKERSCAN_CAPABILITIES__ = { ...policy }
  assert.deepEqual(workspaceExtensions().nav, [], 'a policy without the member is the UI as it was')
  window.__SHAKERSCAN_CAPABILITIES__ = { ...policy, schema: 'future', extensions }
  assert.deepEqual(workspaceExtensions().nav, [], 'unknown capability contracts fail closed')
  window.__SHAKERSCAN_CAPABILITIES__ = { ...policy, mode: 'standalone', extensions }
  assert.deepEqual(workspaceExtensions().nav, [])
  // A hosted page is a route like any other: the policy lists it or the UI does not open it.
  window.__SHAKERSCAN_CAPABILITIES__ = { ...policy, extensions }
  assert.equal(navigationAllowed('/ext/reports'), false)
  window.__SHAKERSCAN_CAPABILITIES__ = {
    ...policy, extensions,
    features: { ...policy.features, extensions: { state: 'enabled' } },
    navigation: { ...policy.navigation, '/ext': 'extensions' },
    ui_routes: [...policy.ui_routes, '/ext/reports'],
  }
  assert.equal(navigationAllowed('/ext/reports'), true)
  assert.equal(navigationAllowed('/ext/other'), false)
  delete global.window
})
