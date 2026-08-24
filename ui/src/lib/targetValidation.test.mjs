import assert from 'node:assert/strict'
import test from 'node:test'

import { validateScanTarget } from './targetValidation.ts'

test('accepts public and local-lab HTTP targets', () => {
  for (const target of [
    'https://example.com',
    'example.com',
    'http://localhost:3000',
    'http://172.19.0.4:3000',
    'http://shakerscan-fleet-juice-shop:3000',
    'juice-shop',
    'http://[fd00::10]:8080',
  ]) {
    assert.equal(validateScanTarget(target), null, target)
  }
})

test('rejects malformed and unsupported targets', () => {
  assert.equal(validateScanTarget(''), 'Please enter a target URL')
  assert.equal(
    validateScanTarget(`https://${'a'.repeat(2048)}.example`),
    'Target URL must be 2,048 characters or fewer',
  )
  assert.equal(validateScanTarget('not a host'), 'Target cannot contain spaces')
  assert.equal(validateScanTarget('file:///etc/passwd'), 'Only http(s) targets are supported')
  assert.match(validateScanTarget('http://bad_host') ?? '', /valid URL or domain/)
})
