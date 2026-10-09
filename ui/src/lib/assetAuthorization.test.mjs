import assert from 'node:assert/strict'
import test from 'node:test'

import { assetAuthorizationStatus } from './assetAuthorization.mjs'

const origin = (authorized, is_active = true) => ({ id: 'o', url: 'https://app.test', is_active, authorized })

test('a web address with its own standing authorization is not shown as not authorized', () => {
  // The home-lab honey row: host has no receipt, its web origin does, and scans run under it.
  const status = assetAuthorizationStatus({ authorized: false, authorized_origin_count: 1, origin_count: 1, origins: [origin(true)] })
  assert.equal(status.state, 'web_apps')
  assert.equal(status.label, 'Web app authorized')
  assert.doesNotMatch(status.label, /Not authorized/)
})

test('host authority inherited by every web app reads as authorized', () => {
  const status = assetAuthorizationStatus({ authorized: true, authorized_origin_count: 1, origin_count: 1, origins: [origin(true)] })
  assert.deepEqual([status.state, status.label], ['authorized', 'Authorized'])
  assert.equal(assetAuthorizationStatus({ authorized: true, authorized_origin_count: 0, origin_count: 0 }).state, 'authorized')
})

test('a web app withdrawn from host authority is called out', () => {
  const status = assetAuthorizationStatus({ authorized: true, authorized_origin_count: 1, origin_count: 2, origins: [origin(true), origin(false)] })
  assert.equal(status.state, 'partial')
  assert.equal(status.label, 'Authorized · 1 of 2 web apps')
})

test('some but not all web apps authorized on an unauthorized host', () => {
  const status = assetAuthorizationStatus({ authorized: false, authorized_origin_count: 1, origin_count: 3 })
  assert.equal(status.state, 'web_apps')
  assert.equal(status.label, '1 of 3 web apps authorized')
})

test('nothing authorized, and an older API without the count, fall back safely', () => {
  assert.equal(assetAuthorizationStatus({ authorized: false, authorized_origin_count: 0, origin_count: 1 }).label, 'Not authorized')
  assert.equal(assetAuthorizationStatus({ authorized: false, origins: [origin(undefined)] }).state, 'none')
  assert.equal(assetAuthorizationStatus({ authorized: false, origins: [origin(true)] }).state, 'web_apps')
  assert.equal(assetAuthorizationStatus({ authorized: true }).state, 'authorized')
  assert.equal(assetAuthorizationStatus(null).state, 'none')
})
