/**
 * The list/v1 contract as the UI reads it.
 *
 * A reworked list answers `{items, next_cursor, has_more, total?, total_kind, generated_at}` when
 * the request opts in (any of cursor, count, fields or since; a first page sends `count=`). An
 * engine without list/v1 on that path answers its legacy shape, recognised by the missing `items`
 * key, or (on /findings, which rejects unknown parameters) a 400 naming the unknown parameter.
 * Both are feature detection, never an error shown to the operator.
 */

export const LIST_V1_MAX_LIMIT = 200

export function isListV1(body) {
  return Boolean(body) && typeof body === 'object' && Array.isArray(body.items) && 'has_more' in body
}

/** Query values for one list/v1 page. `count` only on the first page; later pages carry the cursor. */
export function listV1Params({ limit, cursor, sort, count = 'none', since } = {}) {
  const params = {}
  if (limit) params.limit = String(Math.min(LIST_V1_MAX_LIMIT, Math.max(1, Math.floor(limit))))
  if (sort) params.sort = sort
  if (cursor) params.cursor = cursor
  else params.count = count || 'none'
  if (since) params.since = since
  return params
}

/** True for the 400 an engine without list/v1 on /findings gives for the new parameters. */
export function isUnknownListParamError(error) {
  if (!error || Number(error.status) !== 400) return false
  const text = `${error.message || ''} ${typeof error.detail === 'string' ? error.detail : ''}`
  return /unknown query parameter/i.test(text)
}

/**
 * How to show a list/v1 total: exact numbers as they are, `at_least` as "10,000+", estimates as
 * "about N", and nothing when the request asked for no count.
 */
export function totalLabel(page, locale) {
  if (!page || page.total == null || page.total_kind === 'none') return null
  const value = Number(page.total)
  if (!Number.isFinite(value)) return null
  const text = value.toLocaleString(locale)
  if (page.total_kind === 'at_least') return `${text}+`
  if (page.total_kind === 'estimate') return `about ${text}`
  return text
}

/**
 * Apply a `since=` delta to rows already on screen: changed rows replace theirs in place, new
 * rows go first (newest-first lists), and nothing else moves. `key` names the identity field.
 */
export function mergeSinceDelta(rows, delta, { key = 'id', limit = Infinity } = {}) {
  const current = Array.isArray(rows) ? rows : []
  const changes = Array.isArray(delta) ? delta : []
  if (!changes.length) return current
  const byId = new Map(changes.map((row) => [String(row?.[key]), row]))
  const merged = current.map((row) => {
    const id = String(row?.[key])
    if (!byId.has(id)) return row
    const next = byId.get(id)
    byId.delete(id)
    return next
  })
  const added = changes.filter((row) => byId.has(String(row?.[key])))
  const result = [...added, ...merged]
  return Number.isFinite(limit) ? result.slice(0, limit) : result
}
