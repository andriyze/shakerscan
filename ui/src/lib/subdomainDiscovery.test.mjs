import assert from 'node:assert/strict'
import test from 'node:test'

import { subdomainDiscoverySummary } from './subdomainDiscovery.ts'

test('the scan says which subdomains it found and how many became targets', () => {
  assert.equal(
    subdomainDiscoverySummary({
      root_domain: 'shakerscan.com', hosts: ['a.shakerscan.com', 'b.shakerscan.com'], count: 2, source: 'subfinder',
      targets: { status: 'recorded', added: 1, scannable: 2, unresolved_count: 1 },
    }),
    '2 subdomains of shakerscan.com found by subfinder · 1 new target added · 1 without an address record, not added',
  )
  assert.equal(
    subdomainDiscoverySummary({ hosts: ['a.example.com'], targets: { status: 'failed', error: 'PostgresError' } }),
    '1 subdomain found · not added as targets (PostgresError)',
  )
  assert.equal(subdomainDiscoverySummary({ hosts: [] }), null)
  assert.equal(subdomainDiscoverySummary(undefined), null)
})
