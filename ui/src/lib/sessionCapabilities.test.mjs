import assert from 'node:assert/strict'
import test from 'node:test'
import {
  ALL_ALLOWED, actionAllowed, capabilityReason, fetchSessionCapabilities, pageAllowed,
  parseSessionCapabilities,
} from './sessionCapabilities.mjs'

const viewer = parseSessionCapabilities({
  schema_version: 'session-capabilities/v1', source: 'gateway', role: 'viewer', default: 'deny',
  actions: { 'secrets.read': false, 'findings.retest': 'yes' },
  pages: { '/devices': false, '/scan/new': false, '/scan': true },
  reasons: { 'targets.add': 'this action needs the operator role', bad: 3 },
})

test('a viewer answer denies unlisted actions and listed pages, longest prefix first', () => {
  assert.equal(actionAllowed(viewer, 'targets.add'), false)
  assert.equal(actionAllowed(viewer, 'findings.retest'), false) // a non-boolean is ignored, default applies
  assert.equal(pageAllowed(viewer, '/devices'), false)
  assert.equal(pageAllowed(viewer, '/devices/abc?x=1'), false)
  assert.equal(pageAllowed(viewer, '/devices-other'), true)
  assert.equal(pageAllowed(viewer, '/scan/new'), false)
  assert.equal(pageAllowed(viewer, '/scans/1'), true)
  assert.equal(pageAllowed(viewer, '/targets'), true)
  assert.equal(capabilityReason(viewer, 'targets.add'), 'this action needs the operator role')
  assert.equal(capabilityReason(viewer, 'bad'), undefined)
  assert.equal(viewer.role, 'viewer')
})

test('anything that is not the contract allows everything', () => {
  for (const body of [null, {}, { status: 'healthy' }, { schema_version: 'session-capabilities/v2', default: 'deny' }, []]) {
    const caps = parseSessionCapabilities(body)
    assert.equal(caps, ALL_ALLOWED)
    assert.equal(actionAllowed(caps, 'scans.start'), true)
    assert.equal(pageAllowed(caps, '/devices'), true)
  }
  assert.equal(actionAllowed(undefined, 'hunts.manage'), true)
})

test('the engine answer allows everything', () => {
  const caps = parseSessionCapabilities({ schema_version: 'session-capabilities/v1', default: 'allow',
    actions: { 'scans.start': true }, pages: {}, reasons: {} })
  assert.equal(actionAllowed(caps, 'scans.start'), true)
  assert.equal(actionAllowed(caps, 'secrets.decide'), true)
})

test('fetch failures, refusals and a missing endpoint allow everything', async () => {
  const answer = (status, body) => async () => ({ status, json: async () => body })
  assert.equal(await fetchSessionCapabilities('http://api/session/capabilities', answer(404, { detail: 'Not Found' })), ALL_ALLOWED)
  assert.equal(await fetchSessionCapabilities('http://api/session/capabilities', answer(500, null)), ALL_ALLOWED)
  assert.equal(await fetchSessionCapabilities('http://api/session/capabilities', async () => { throw new TypeError('offline') }), ALL_ALLOWED)
  assert.equal(await fetchSessionCapabilities('http://api/session/capabilities', async () => ({ status: 200, json: async () => { throw new SyntaxError('html') } })), ALL_ALLOWED)
  let url = ''
  const caps = await fetchSessionCapabilities('http://api/session/capabilities', async (u) => { url = u; return { status: 200, json: async () => ({ schema_version: 'session-capabilities/v1', default: 'deny', actions: {}, pages: {} }) } })
  assert.equal(url, 'http://api/session/capabilities')
  assert.equal(actionAllowed(caps, 'targets.add'), false)
})

test('a request that never answers allows everything after the timeout', async () => {
  const hang = (_url, init) => new Promise((_resolve, reject) => init.signal.addEventListener('abort', () => reject(new Error('aborted'))))
  assert.equal(await fetchSessionCapabilities('http://api/session/capabilities', hang, 20), ALL_ALLOWED)
})
