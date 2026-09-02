import assert from 'node:assert/strict'
import test from 'node:test'

import { scanFailureRecommendation } from './scanFailureRecommendation.ts'

test('heartbeat timeout is treated as an execution failure, not target reachability', () => {
  const result = scanFailureRecommendation('No heartbeat for 5.8 minutes (timeout 5 min)')
  assert.match(result, /worker and queue health/)
  assert.match(result, /does not by itself mean the target was unreachable/)
})

test('DNS and connection failures still recommend a target reachability check', () => {
  assert.match(scanFailureRecommendation('DNS resolution failed'), /target address/)
  assert.match(scanFailureRecommendation('connection refused'), /target address/)
})

test('shards direct the operator to the authoritative parent', () => {
  assert.match(scanFailureRecommendation('anything', true), /parent Scan/)
})
