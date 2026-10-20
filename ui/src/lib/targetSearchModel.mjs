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

/** Pages a link that names a target by URL reads at most (200-row pages: about 2000 matches). */
export const TARGET_LINK_MAX_PAGES = 10

function httpOrigin(value) {
  if (typeof value !== 'string' || !/^https?:\/\//i.test(value)) return null
  try { return new URL(value).origin } catch { return null }
}

function abortError() {
  const error = new Error('The read was aborted')
  error.name = 'AbortError'
  return error
}

/** Why a search read failed, as a phrase for a notice (no trailing full stop). */
export function readFailureText(error) {
  const message = error instanceof Error ? error.message.trim().replace(/[.\s]+$/, '') : ''
  return message || 'the search could not be completed'
}

/**
 * The target a link names by URL: the first http(s) row with the same origin. A host search
 * matches by substring and sorts by name, so the exact origin can sit after many other matches
 * (an apex domain behind its subdomains); pages are read on until it is found, the inventory has
 * no more, or `maxPages` were read. `status` is `found`, `missing` (every matching page was read),
 * `unconfirmed` (the bound was reached with pages left) or `failed` (a page read failed, with
 * `error` saying why). Only `missing` says the target does not exist; `unconfirmed` and `failed`
 * prove nothing about it.
 *
 * `fetchPage(position)` is as for collectAcceptedTargets. An aborted `signal` stops before the
 * next page and rejects with an AbortError, also when a read in flight fails because of it.
 */
export async function resolveTargetByOrigin({ fetchPage, url, maxPages = TARGET_LINK_MAX_PAGES, signal }) {
  const origin = httpOrigin(url)
  if (!origin) return { status: 'missing', target: null, scanned: 0 }
  let read = 0
  let result
  try {
    result = await collectAcceptedTargets({
      fetchPage: async (position) => {
        if (signal?.aborted) throw abortError()
        const page = await fetchPage(position)
        read += Array.isArray(page?.targets) ? page.targets.length : 0
        return page
      },
      accept: (row) => httpOrigin(row?.url) === origin,
      limit: 1,
      maxPages,
    })
  } catch (error) {
    if (signal?.aborted) throw abortError()
    return { status: 'failed', target: null, scanned: read, error: readFailureText(error) }
  }
  if (signal?.aborted) throw abortError()
  if (result.matches.length) return { status: 'found', target: result.matches[0], scanned: result.scanned }
  return { status: result.hasMore ? 'unconfirmed' : 'missing', target: null, scanned: result.scanned }
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
