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

test('a partial recording names every cap: the listed limit, the DNS window and the target limit', () => {
  assert.equal(
    subdomainDiscoverySummary({
      root_domain: 'example.com', hosts: ['a.example.com'], count: 1000, total: 1500, truncated: true, source: 'subfinder',
      targets: {
        status: 'recorded', added: 100, scannable: 290, unresolved_count: 10, found: 1500, checked: 300,
        target_limit: 100, over_target_limit: 190, insert_failed: 2, partial: true,
      },
    }),
    '1500 subdomains of example.com found by subfinder; the first 1000 are listed · 300 of 1500 checked in DNS'
      + ' · 100 new targets added · 190 resolving names not added (at most 100 per run)'
      + ' · 10 without an address record, not added · 2 could not be stored',
  )
  // A complete run keeps the short sentence.
  assert.equal(
    subdomainDiscoverySummary({
      root_domain: 'example.com', hosts: ['a.example.com'], count: 1, total: 1, truncated: false, source: 'subfinder',
      targets: { status: 'recorded', added: 1, scannable: 1, unresolved_count: 0, found: 1, checked: 1, over_target_limit: 0 },
    }),
    '1 subdomain of example.com found by subfinder · 1 new target added',
  )
})
