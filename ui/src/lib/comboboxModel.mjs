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
