import assert from 'node:assert/strict'
import test from 'node:test'

import { buildVersionsMatch, deriveBuildIdentity, formatBuildIdentity } from './buildIdentity.ts'

const uniformHealth = {
  scanner_version: 'abc1234',
  build_fingerprint: 'fingerprint-a',
  worker_build: {
    available: true,
    expected_count: 4,
    reported_count: 4,
    stale_count: 0,
    pending_count: 0,
    fleet_uniform: true,
    scanner_version: 'abc1234',
  },
  agent_tool_worker: { status: 'ready', worker_count: 1 },
  device_worker: { enabled: false, status: 'disabled', worker_count: 0 },
}

test('matching component identities collapse to one version', () => {
  assert.equal(formatBuildIdentity(deriveBuildIdentity('abc1234', uniformHealth)), 'Version abc1234')
})

test('different Git abbreviation lengths for the same commit do not create false skew', () => {
  const identity = deriveBuildIdentity('0fdfe57c', {
    ...uniformHealth,
    scanner_version: '0fdfe57',
    worker_build: { ...uniformHealth.worker_build, scanner_version: '0fdfe57' },
  })
  assert.equal(identity.skew, false)
  assert.equal(formatBuildIdentity(identity), 'Version 0fdfe57')
  assert.equal(buildVersionsMatch('0fdfe57c-dirty', '0fdfe57'), true)
})

test('short prefixes and non-Git version labels still require exact equality', () => {
  assert.equal(buildVersionsMatch('abc123', 'abc1234'), false)
  assert.equal(buildVersionsMatch('v0.7.0', 'v0.7'), false)
})

test('dirty UI retains its useful local-checkout marker without causing skew', () => {
  assert.equal(formatBuildIdentity(deriveBuildIdentity('abc1234-dirty', uniformHealth)), 'Version abc1234-dirty')
})

test('raw compose dev placeholder is unknown rather than a false mismatch', () => {
  const identity = deriveBuildIdentity('dev', uniformHealth)
  assert.equal(identity.skew, false)
  assert.equal(formatBuildIdentity(identity), 'Version abc1234')
})

test('scoped UI build uses API source fingerprint instead of unrelated Git revision', () => {
  const identity = deriveBuildIdentity('ui56789', uniformHealth, 'fingerprint-a')
  assert.equal(identity.skew, false)
  assert.equal(formatBuildIdentity(identity), 'UI ui56789 · API abc1234 · Workers abc1234')
})

test('scoped UI build still reports actual backend source skew', () => {
  const identity = deriveBuildIdentity('abc1234', uniformHealth, 'fingerprint-old')
  assert.equal(identity.skew, true)
})

test('fingerprint-authoritative stale workers produce an explicit mismatch', () => {
  const identity = deriveBuildIdentity('abc1234', {
    ...uniformHealth,
    worker_build: {
      available: true,
      expected_count: 4,
      reported_count: 4,
      stale_count: 1,
      pending_count: 1,
      fleet_uniform: false,
      scanner_version: null,
    },
  })
  assert.equal(identity.skew, true)
  assert.equal(formatBuildIdentity(identity), 'UI abc1234 · API abc1234 · Workers mixed/stale (2)')
})

test('missing worker heartbeats do not invent a worker version or mismatch', () => {
  const identity = deriveBuildIdentity('abc1234', {
    scanner_version: 'abc1234',
    worker_build: { available: false, reported_count: 0, fleet_uniform: false },
  })
  assert.equal(identity.skew, false)
  assert.equal(formatBuildIdentity(identity), 'Version abc1234')
})

test('worker reports without an expected denominator are visibly unverified', () => {
  const identity = deriveBuildIdentity('abc1234', {
    scanner_version: 'abc1234',
    worker_build: {
      available: true,
      expected_count: null,
      reported_count: 3,
      stale_count: 0,
      pending_count: 0,
      fleet_uniform: false,
    },
  })
  assert.equal(identity.skew, true)
  assert.equal(formatBuildIdentity(identity), 'UI abc1234 · API abc1234 · Workers unverified (3 reported)')
})

test('specialized scanner workers participate in build mismatch reporting', () => {
  const identity = deriveBuildIdentity('abc1234', {
    ...uniformHealth,
    agent_tool_worker: { status: 'not_ready', worker_count: 1 },
  })
  assert.equal(identity.skew, true)
  assert.equal(
    formatBuildIdentity(identity),
    'UI abc1234 · API abc1234 · Workers mixed/stale (1 specialized)',
  )
})

test('optional specialized pools with no running workers do not invent build skew', () => {
  const identity = deriveBuildIdentity('abc1234', {
    ...uniformHealth,
    agent_tool_worker: { status: 'not_ready', worker_count: 0 },
    device_worker: { enabled: true, status: 'not_ready', worker_count: 0 },
  })
  assert.equal(identity.skew, false)
  assert.equal(formatBuildIdentity(identity), 'Version abc1234')
})
