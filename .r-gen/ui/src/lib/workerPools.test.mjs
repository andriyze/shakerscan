import assert from 'node:assert/strict'
import { test } from 'node:test'
import { poolBadge, poolDetail } from './workerPools.mjs'

test('an opt-in pool with no worker reads as not started, not as a fault', () => {
  const pool = { status: 'not_ready', count: 0, current: 0, stale: 0, pending: 0, reason: 'no_fresh_device_worker' }
  assert.equal(poolBadge(pool, true).text, 'not started')
  assert.equal(poolBadge(pool, false).text, 'not ready')
})

test('a pool that has workers it cannot use stays a readiness fault', () => {
  const pool = { status: 'not_ready', count: 1, current: 0, stale: 1, pending: 0, reason: 'device_worker_build_stale' }
  assert.equal(poolBadge(pool, true).text, 'not ready')
  assert.equal(poolDetail(pool), 'device worker build stale')
})

test('the server remedy wins over the reason token', () => {
  const pool = { status: 'not_ready', count: 0, reason: 'no_fresh_device_worker', remedy: 'Start it with: shakerscan devices start' }
  assert.equal(poolDetail(pool), 'Start it with: shakerscan devices start')
  assert.equal(poolDetail({ status: 'ready', count: 2 }), 'All reported workers are current and capable.')
})
