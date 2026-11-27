/**
 * GET /exposure/assets as the dashboard reads it.
 *
 * An engine with list/v1 on this path answers a bounded page `{items, has_more, next_cursor, …}`
 * with the headline numbers over every matching asset under `summary` (metrics, cohort counts,
 * new count). An older engine ignores the opt-in and answers the legacy shape `{assets, total,
 * metrics, cohort_counts, …}`. Both become the legacy shape here, so the views read one shape.
 */
import { LIST_V1_MAX_LIMIT, isListV1, listV1Params } from './listPage.mjs'

/** Query values for the first page of the risk-ranked list (list/v1 opt-in, at most 200). */
export function exposureAssetsParams({ limit, root_domain, kind, cohort } = {}) {
  const params = listV1Params({ limit: Math.min(LIST_V1_MAX_LIMIT, limit || 50), count: 'none' })
  if (root_domain) params.root_domain = root_domain
  if (kind) params.kind = kind
  if (cohort) params.cohort = cohort
  return params
}

/** The legacy response shape from either answer. */
export function exposureAssetsFromBody(body) {
  if (!isListV1(body)) return body
  const summary = body.summary && typeof body.summary === 'object' ? body.summary : {}
  const metrics = summary.metrics && typeof summary.metrics === 'object' ? summary.metrics : undefined
  const assets = body.items
  const total = body.total_kind && body.total_kind !== 'none' && body.total != null
    ? Number(body.total)
    : Number(metrics?.asset_count ?? assets.length)
  return {
    assets,
    count: assets.length,
    total,
    offset: 0,
    new_count: Number(summary.new_count || 0),
    metrics,
    cohort: summary.cohort,
    cohort_counts: summary.cohort_counts || {},
    truncated: Boolean(body.has_more),
  }
}
