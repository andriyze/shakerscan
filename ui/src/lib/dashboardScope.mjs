/**
 * Dashboard decisions that must never turn missing data into an all-clear.
 *
 * - postureState: exposure for the selected cohort is shown only when it was read for that
 *   cohort; a failed read with nothing to show is "unavailable", never zeros.
 * - coverageScope: the coverage card sums one page of domains with a bounded number of members
 *   each; whenever either bound cut something off, the card says what it covers.
 * - cohortScopingNote: recent scans and activity are matched to a cohort through the bounded
 *   exposure page; above that page the match is approximate and the card says so.
 */

/**
 * @param {{ enabled: boolean, exposure: object | null | undefined, failed: boolean }} input
 * @returns {'disabled' | 'loading' | 'unavailable' | 'ready'}
 */
export function postureState({ enabled, exposure, failed }) {
  if (!enabled) return 'disabled'
  if (exposure && exposure.metrics) return 'ready'
  return failed ? 'unavailable' : 'loading'
}

/** Members a group returned versus the members it has. */
function groupTruncated(group) {
  if (!group || typeof group !== 'object') return false
  if (group.subdomains_truncated === true) return true
  const shown = Array.isArray(group.subdomains) ? group.subdomains.length : 0
  const count = Number(group.subdomain_count)
  return Number.isFinite(count) && count > shown
}

/**
 * @param {{ groups: object[], hasMore: boolean, total: string | null }} input
 * @returns {{ show: boolean, domains: number, hasMore: boolean, truncatedGroups: number, total: string | null, text: string | null }}
 */
export function coverageScope({ groups, hasMore, total }) {
  const list = Array.isArray(groups) ? groups : []
  const truncatedGroups = list.filter(groupTruncated).length
  const parts = []
  if (hasMore) parts.push(`Across the ${list.length.toLocaleString()} domains with the most findings${total ? `, of ${total}` : ''}.`)
  if (truncatedGroups) {
    parts.push(`${truncatedGroups.toLocaleString()} domain${truncatedGroups === 1 ? ' has' : 's have'} more subdomains than counted here.`)
  }
  return {
    show: parts.length > 0, domains: list.length, hasMore: Boolean(hasMore), truncatedGroups, total: total || null,
    text: parts.length ? parts.join(' ') : null,
  }
}

/**
 * @param {{ view: string, exposure: { assets?: unknown[], total?: number, metrics?: { asset_count?: number } } | null | undefined }} input
 * @returns {string | null}
 */
export function cohortScopingNote({ view, exposure }) {
  if (view === 'all' || !exposure) return null
  const shown = Array.isArray(exposure.assets) ? exposure.assets.length : 0
  const total = Number(exposure.total ?? exposure.metrics?.asset_count ?? 0)
  if (!Number.isFinite(total) || total <= shown) return null
  return `Cohort matching uses the ${shown.toLocaleString()} highest-ranked of ${total.toLocaleString()} assets; rows for other assets in this cohort may be missing. All cohorts shows everything.`
}
