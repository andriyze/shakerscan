// Pure logic behind the server-side target typeahead (useTargetSearch). No React.

const TARGET_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/**
 * Whether `id` can name a target (targets and their web origins are UUIDs). A link parameter
 * that cannot is not looked up: the API answers it with 400, never with an asset.
 */
export function isTargetId(id) {
  return typeof id === 'string' && TARGET_ID.test(id)
}

/** Pages a picker reads at most for one query while its filter keeps rejecting rows. */
export const TARGET_SEARCH_MAX_PAGES = 4

/**
 * Read inventory pages for one query until the picker's `accept` filter has `limit` rows, the
 * inventory has no more, or `maxPages` pages were read. The inventory has no parameter that says
 * exactly "a launchable web target", so the filter runs here; reading on keeps a page of rejected
 * rows from looking like "no targets".
 *
 * `fetchPage(position)` answers `{targets, hasMore, next}`; `next` is the position of the page
 * after it (a list/v1 cursor or a legacy offset), `null` at the end.
 */
export async function collectAcceptedTargets({ fetchPage, accept, limit, maxPages = TARGET_SEARCH_MAX_PAGES }) {
  const matches = []
  const seen = new Set()
  let position = null
  let scanned = 0
  let pages = 0
  let hasMore = false
  for (;;) {
    const page = await fetchPage(position)
    pages += 1
    const rows = Array.isArray(page?.targets) ? page.targets : []
    scanned += rows.length
    for (const row of rows) {
      if (!row || seen.has(row.id)) continue
      seen.add(row.id)
      if (!accept || accept(row)) matches.push(row)
    }
    hasMore = Boolean(page?.hasMore) && page?.next != null
    if (!hasMore || matches.length >= limit || pages >= maxPages || !rows.length) break
    position = page.next
  }
  return { matches: matches.slice(0, limit), hasMore: hasMore || matches.length > limit, scanned, pages, filtered: Boolean(accept) }
}

/**
 * The line under a server-searched picker. It never claims that no target exists when it only
 * read part of the inventory: a filtered, unfinished search says how far it looked.
 */
export function targetSearchNoteText({ assets, hasMore, error, query, scanned = 0, filtered = false, loading = false }) {
  const count = Array.isArray(assets) ? assets.length : 0
  if (error) return `Search failed: ${error}`
  if (loading) return 'Searching…'
  if (!count && hasMore) return `No matches on the first ${scanned} targets searched; type to narrow`
  if (hasMore) return `Showing the first ${count} matches; type to narrow`
  if (!count) {
    if (String(query || '').trim()) return filtered ? 'No matching target of this kind' : 'No matching targets'
    return filtered ? 'No target of this kind yet' : 'No targets yet'
  }
  return `${count} match${count === 1 ? '' : 'es'}`
}

/**
 * Whether the picker may say the inventory holds no usable target (and hide itself in favour of
 * an empty state): only after a complete, unfiltered-by-text answer that found nothing. A typed
 * query, a search still running or failing, or more unread pages all keep the search box.
 */
export function targetSearchProvesEmpty({ ready, loading, error, query, hasMore, assets }) {
  return Boolean(ready) && !loading && !error && !String(query || '').trim() && !hasMore
    && !(Array.isArray(assets) && assets.length)
}
