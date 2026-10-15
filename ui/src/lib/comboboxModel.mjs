// Pure search and keyboard logic for the searchable picker (Combobox). No React.

/** Lower-case, accent-free text for matching. */
export function normalize(value) {
  return String(value ?? '').normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase()
}

/** Every word of the query must appear in the option's label, description, meta or keywords. */
export function matches(option, query) {
  const words = normalize(query).split(/\s+/).filter(Boolean)
  if (!words.length) return true
  const haystack = normalize([option.label, option.description, option.meta, option.keywords, option.group].filter(Boolean).join(' '))
  return words.every(word => haystack.includes(word))
}

/** Options that match, label matches first (prefix before substring), original order otherwise. */
export function filterOptions(options, query) {
  const list = (options || []).filter(option => matches(option, query))
  const words = normalize(query).split(/\s+/).filter(Boolean)
  if (!words.length) return list
  const rank = option => {
    const label = normalize(option.label)
    if (label.startsWith(words[0])) return 0
    if (words.every(word => label.includes(word))) return 1
    return 2
  }
  return list.map((option, index) => ({ option, index, rank: rank(option) }))
    .sort((left, right) => left.rank - right.rank || left.index - right.index)
    .map(item => item.option)
}

/** Next enabled index when moving through the list with the arrow keys (wraps around). */
export function moveActive(options, current, step) {
  const count = options.length
  if (!count) return -1
  for (let offset = 1; offset <= count; offset++) {
    const index = ((current < 0 ? (step > 0 ? -1 : 0) : current) + step * offset + count * count) % count
    if (!options[index]?.disabled) return index
  }
  return -1
}

/** Options split into ordered groups, keeping the first-seen group order. */
export function groupOptions(options) {
  const groups = []
  const byName = new Map()
  for (const option of options || []) {
    const name = option.group || ''
    if (!byName.has(name)) {
      const group = { name, options: [] }
      byName.set(name, group)
      groups.push(group)
    }
    byName.get(name).options.push(option)
  }
  return groups
}

/**
 * The highlighted index for a freshly shown list: the selected value when it is there and enabled,
 * otherwise the first enabled option, otherwise -1. Recomputed whenever the visible options
 * change, so an index from an earlier result list can never point at a different (or no) option.
 */
export function initialActive(options, value) {
  const list = options || []
  const selected = list.findIndex(option => option.value === value && !option.disabled)
  return selected >= 0 ? selected : moveActive(list, -1, 1)
}

/** An index that is valid for `options` (enabled and in range), or -1. */
export function clampActive(options, active) {
  const list = options || []
  return Number.isInteger(active) && active >= 0 && active < list.length && !list[active]?.disabled ? active : -1
}

/**
 * Whether Enter may choose the highlighted option. In server-search mode the options must answer
 * the text in the box: not while a search is due or running, and not while they belong to an
 * older query. A local list always answers its own filter.
 */
export function canChooseActive({ remote, loading, query, optionsQuery }) {
  if (!remote) return true
  if (loading) return false
  if (optionsQuery === undefined) return true
  return optionsQuery !== null && String(optionsQuery).trim() === String(query ?? '').trim()
}
