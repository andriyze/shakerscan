import assert from 'node:assert/strict'
import test from 'node:test'

import { currentCompletedVariantCount, resolvedCoverage } from './asmCoverage.ts'

test('stale historical examinations do not inflate current ASM coverage', () => {
  const coverage = {
    total: 4,
    tested: 0,
    untested: 0,
    stale: 4,
    gone: 0,
    coverage: 0,
    metric_contract: {
      inventory: { canonical_routes: 2, route_variants: 4, retired_variants: 0 },
      examination: {
        canonical_routes_ever_completed: 2,
        variants_ever_completed: 4,
        current_fresh_variants: 0,
        stale_variants: 4,
        never_attempted_variants: 0,
      },
    },
  }

  assert.equal(currentCompletedVariantCount(coverage), 0)
  assert.equal(resolvedCoverage(coverage), 0)
})
