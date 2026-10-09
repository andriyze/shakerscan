// The "Requests JSON" export of a run's HTTP archive.
//
// The archive endpoint pages its rows. The export used to send the browser's page size (25)
// and save that one page, so a 92-call scan downloaded 25 calls and only the file's
// `truncated_export` said so. The export now pages through every call matching the filters
// (up to EXPORT_MAX_CALLS) and saves them as one document whose counts and capture fidelity
// describe everything it holds, not just its first page.

/** Rows asked for per request while exporting; the server accepts up to 10,000. */
export const EXPORT_PAGE_SIZE = 1000
/** Calls one browser export holds. Past this the file would strain the tab's memory (and a
 *  JSON string past the engine's limit fails as "Invalid string length"), so the export stops
 *  here and says so before and after the download. The HAR exports hold up to 10,000. */
export const EXPORT_MAX_CALLS = 20000

// Worst first: a document is only as complete as its least complete page.
const FIDELITY_RANK = { complete: 0, partial: 1, unknown: 2, unavailable: 3 }

function worstFidelity(values) {
  return values.reduce((worst, value) => (
    (FIDELITY_RANK[value] ?? FIDELITY_RANK.unknown) > (FIDELITY_RANK[worst] ?? FIDELITY_RANK.unknown) ? value : worst
  ), 'complete')
}

/** Archive-wide capture counters merged across pages: lists unioned, counts at their largest. */
function mergeCaptureStats(pages) {
  const merged = {}
  for (const stats of pages) {
    if (!stats || typeof stats !== 'object') continue
    for (const [key, value] of Object.entries(stats)) {
      const current = merged[key]
      if (Array.isArray(value)) merged[key] = [...new Set([...(Array.isArray(current) ? current : []), ...value])]
      else if (typeof value === 'number') merged[key] = typeof current === 'number' ? Math.max(current, value) : value
      else if (!(key in merged)) merged[key] = value
    }
  }
  return merged
}

/**
 * Collect every matching call into one export document.
 *
 * `fetchPage(offset, limit)` resolves to one archive envelope. Owner and redaction come from
 * the first page; fidelity is the worst any page reported, with every page's notes; capture
 * stats are merged; rows are de-duplicated by id, because a call archived mid-export shifts the
 * offsets of the pages after it. Paging stops at the declared total, at `maxCalls`, or when a
 * page comes back empty, and the result says honestly how many calls it holds.
 */
export async function collectArchiveExport(fetchPage, { pageSize = EXPORT_PAGE_SIZE, maxCalls = EXPORT_MAX_CALLS } = {}) {
  const pages = []
  const seen = new Set()
  const transactions = []
  const add = (rows) => {
    let added = 0
    for (const row of Array.isArray(rows) ? rows : []) {
      if (transactions.length >= maxCalls) break
      const id = row && typeof row === 'object' && row.id != null ? String(row.id) : null
      if (id !== null) {
        if (seen.has(id)) continue
        seen.add(id)
      }
      transactions.push(row)
      added += 1
    }
    return added
  }
  let offset = 0
  let total = 0
  for (;;) {
    const page = await fetchPage(offset, Math.min(pageSize, Math.max(1, maxCalls - transactions.length)))
    pages.push(page || {})
    const rows = Array.isArray(page?.transactions) ? page.transactions : []
    if (Number.isFinite(Number(page?.total))) total = Math.max(total, Number(page.total))
    add(rows)
    offset += rows.length
    if (rows.length === 0 || offset >= total || transactions.length >= maxCalls) break
  }
  total = Math.max(total, transactions.length)
  const first = pages[0]
  const notes = [...new Set(pages.map((page) => String(page?.fidelity_detail || '').trim()).filter(Boolean))]
  const capped = transactions.length >= maxCalls && total > transactions.length
  return {
    ...first,
    fidelity: worstFidelity(pages.map((page) => page?.fidelity || 'unknown')),
    fidelity_detail: notes.join('; '),
    capture_stats: mergeCaptureStats(pages.map((page) => page?.capture_stats)),
    exported: transactions.length,
    total,
    truncated_export: transactions.length < total,
    ...(capped ? { export_cap: maxCalls } : {}),
    transactions,
  }
}

/** What the page says before an export when it cannot hold every matching call. */
export function exportCapNotice(total, maxCalls = EXPORT_MAX_CALLS) {
  const count = Number(total) || 0
  return count > maxCalls
    ? `${count.toLocaleString('en-US')} calls match; Requests JSON holds the first ${maxCalls.toLocaleString('en-US')}. Narrow the filters to export the rest.`
    : null
}

/** What the page says about a finished export: null when it holds every matching call. */
export function exportShortfallMessage(document) {
  const exported = Number(document?.exported) || 0
  const total = Number(document?.total) || 0
  if (exported >= total) return null
  if (document?.export_cap) {
    return `The export holds the first ${exported.toLocaleString('en-US')} of ${total.toLocaleString('en-US')} matching calls, the most one browser export holds. Narrow the filters to export the rest.`
  }
  return `The export holds ${exported} of ${total} matching calls; the archive changed while it was being read. Export again to include the rest.`
}
