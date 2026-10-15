import assert from 'node:assert/strict'
import test from 'node:test'

import { exposureAssetsFromBody, exposureAssetsParams } from './exposureAssets.mjs'

test('the dashboard asks for one bounded list/v1 page', () => {
  assert.deepEqual(exposureAssetsParams({ limit: 200, cohort: 'operational' }), { limit: '200', count: 'none', cohort: 'operational' })
  assert.deepEqual(exposureAssetsParams({ limit: 1000 }), { limit: '200', count: 'none' })
  assert.deepEqual(exposureAssetsParams({ kind: 'ai', root_domain: 'example.com' }), {
    limit: '50', count: 'none', kind: 'ai', root_domain: 'example.com',
  })
})

test('a list/v1 page reads as the legacy shape, totals from the summary', () => {
  const metrics = { asset_count: 412, active_critical: 3, p1_count: 2 }
  const page = exposureAssetsFromBody({
    items: [{ id: 'a' }, { id: 'b' }], next_cursor: 'c1', has_more: true, total_kind: 'none',
    generated_at: '2026-10-15T00:00:00Z',
    summary: { metrics, new_count: 7, cohort: 'all', cohort_counts: { production: 400, lab: 12 } },
  })
  assert.deepEqual(page, {
    assets: [{ id: 'a' }, { id: 'b' }], count: 2, total: 412, offset: 0, new_count: 7, metrics,
    cohort: 'all', cohort_counts: { production: 400, lab: 12 }, truncated: true,
  })
  const counted = exposureAssetsFromBody({
    items: [], next_cursor: null, has_more: false, total_kind: 'exact', total: 0, summary: { metrics: { asset_count: 0 } },
  })
  assert.equal(counted.total, 0)
  assert.equal(counted.truncated, false)
})

test('a page without a summary never invents metrics', () => {
  const page = exposureAssetsFromBody({ items: [{ id: 'a' }], has_more: false, total_kind: 'none' })
  assert.equal(page.metrics, undefined)
  assert.equal(page.total, 1)
})

test('the legacy answer of an older engine passes through unchanged', () => {
  const legacy = { assets: [{ id: 'a' }], count: 1, total: 9, metrics: { asset_count: 9 }, new_count: 0 }
  assert.equal(exposureAssetsFromBody(legacy), legacy)
})
