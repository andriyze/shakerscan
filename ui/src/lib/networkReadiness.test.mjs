import assert from 'node:assert/strict'
import test from 'node:test'
import { networkReadinessPresentation } from './networkReadiness.mjs'
import { poolBadge } from './workerPools.mjs'

test('ready capacity hides the banner', () => {
  assert.equal(networkReadinessPresentation({ status: 'ready' }), null)
})

test('startup is informational and never asks the operator to run commands', () => {
  const result = networkReadinessPresentation({ status: 'starting', remedy: 'stale command' })
  assert.equal(result.role, 'status')
  assert.equal(result.remedy, null)
  assert.match(result.message, /starting/)
  assert.equal(poolBadge({ status: 'starting', count: 0 }).text, 'starting')
})

test('disabled capacity differs from a fault, which retains operator diagnostics', () => {
  assert.equal(networkReadinessPresentation({ status: 'disabled' }).role, 'status')
  const result = networkReadinessPresentation({ status: 'not_ready', remedy: 'shakerscan devices logs' })
  assert.equal(result.role, 'alert')
  assert.match(result.message, /saved targets and results/)
  assert.equal(result.remedy, 'shakerscan devices logs')
  assert.doesNotMatch(result.message, /Nmap|Naabu|container|worker/)
})
