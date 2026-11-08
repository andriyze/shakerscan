// Investigation candidates grouped by the target they concern, in the order the page lists them.

/** The name a person knows the target by: its display name, else its address, else a short id. */
export function candidateTargetLabel(candidate) {
  const name = String(candidate?.target_name || '').trim()
  if (name) return name
  const url = String(candidate?.target_url || '').trim()
  if (url) return url.replace(/^host:\/\//, '')
  const id = String(candidate?.target_id || candidate?.device_target_id || '')
  return id ? `Target ${id.slice(0, 8)}` : 'Unknown target'
}

/** Consecutive-order groups: one per target, first appearance first, candidates kept in order. */
export function groupCandidatesByTarget(candidates) {
  const groups = new Map()
  for (const candidate of candidates || []) {
    const key = String(candidate?.target_id || candidate?.device_target_id || '')
    let group = groups.get(key)
    if (!group) {
      group = { key, label: candidateTargetLabel(candidate), url: candidate?.target_url || null, candidates: [] }
      groups.set(key, group)
    }
    group.candidates.push(candidate)
  }
  return [...groups.values()]
}

/** "Showing 51–100 of 312" for an offset page. */
export function candidatePageRange({ offset, count, total }) {
  if (!total || !count) return `Showing 0 of ${total || 0}`
  return `Showing ${offset + 1}–${offset + count} of ${total}`
}
