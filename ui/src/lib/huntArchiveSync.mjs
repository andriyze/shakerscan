/**
 * Keeping a Hunt's request archive in step with the server without re-reading all of it.
 *
 * The archive is ordered by (started_at, sequence, id), not by insertion: an action that overlapped
 * others archives its requests late, and they land in the middle of the list. A read by offset
 * (offset = rows held) therefore cannot be trusted blindly. `planPageMerge` checks what a page at
 * the tail returned against what was held: only when every returned row is new and the counts add
 * up is it appended; anything else (a known id at the tail, fewer new rows than the total grew)
 * means rows moved, and the window the operator holds is re-read from the start (`resyncWindows`).
 *
 * The proper fix is a server-side insertion-order cursor (after_seq) on
 * /hunts/{id}/http-transactions; until then this keeps the list correct at the cost of a re-read
 * when rows arrive out of order.
 */

export const ARCHIVE_PAGE = 250
/** The server's per-request ceiling (api/runtime/http_archive_reader.py MAX_EXPORT_ROWS). */
export const ARCHIVE_MAX_ROWS = 10_000

/**
 * @param {object} input
 * @param {Array<{id: string}>} input.held rows on screen, server order
 * @param {Array<{id: string}>} input.page rows the read at offset = held.length returned
 * @param {number} input.limit the read's limit
 * @param {number} input.total the total that read reported
 * @returns {{ action: 'append', rows: Array<{id: string}> } | { action: 'resync' } | { action: 'reload' }}
 */
export function planPageMerge({ held, page, limit, total }) {
  const rows = Array.isArray(page) ? page : []
  const current = Array.isArray(held) ? held : []
  // A purge (or a shorter archive than what is on screen): start over from the first page.
  if (total < current.length) return { action: 'reload' }
  const known = new Set(current.map((row) => String(row.id)))
  const fresh = rows.filter((row) => !known.has(String(row.id)))
  // A row the page already holds came back at the tail: something was inserted before it.
  if (fresh.length !== rows.length) return { action: 'resync' }
  // A short page is the end of the archive, so held + page must be the whole of it.
  if (rows.length < limit && current.length + rows.length !== total) return { action: 'resync' }
  // A full page cannot run past the total.
  if (current.length + rows.length > total) return { action: 'resync' }
  return { action: 'append', rows: fresh }
}

/**
 * The reads that re-fetch the first `held` rows (at least one page), each within the server's
 * per-request ceiling.
 */
export function resyncWindows(heldCount, { page = ARCHIVE_PAGE, max = ARCHIVE_MAX_ROWS } = {}) {
  const want = Math.max(page, Math.floor(heldCount) || 0)
  const windows = []
  for (let offset = 0; offset < want; offset += max) windows.push({ offset, limit: Math.min(max, want - offset) })
  return windows
}
