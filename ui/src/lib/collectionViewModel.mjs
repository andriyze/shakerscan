// Pure helpers for viewing a request collection: filtering its requests and naming its APIs.

const METHOD_ORDER = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']

/** Requests matching a text query (name, path, URL, folder, tags) and an optional method. */
export function filterRequests(items, { query = '', method = '' } = {}) {
  const words = String(query).toLowerCase().split(/\s+/).filter(Boolean)
  return (items || []).filter(item => {
    if (method && String(item.method).toUpperCase() !== method) return false
    if (!words.length) return true
    const text = [item.name, item.normalized_path, item.redacted_url, item.folder, ...(item.tags || []), item.method]
      .filter(Boolean).join(' ').toLowerCase()
    return words.every(word => text.includes(word))
  })
}

/** How many loaded requests use each method, in a conventional order. */
export function methodCounts(items) {
  const counts = new Map()
  for (const item of items || []) {
    const method = String(item.method || 'GET').toUpperCase()
    counts.set(method, (counts.get(method) || 0) + 1)
  }
  return [...counts.entries()]
    .sort(([left], [right]) => {
      const a = METHOD_ORDER.indexOf(left), b = METHOD_ORDER.indexOf(right)
      return (a < 0 ? 99 : a) - (b < 0 ? 99 : b) || left.localeCompare(right)
    })
    .map(([method, count]) => ({ method, count }))
}

/** The origin a request binding admits, as scheme://host[:port]. */
export function originOf(url) {
  try {
    const parsed = new URL(String(url))
    return `${parsed.protocol}//${parsed.host}`
  } catch {
    return String(url || '')
  }
}

/** Which of an asset's APIs (host plus application origins) a collection is bound to. */
export function boundApis(bindings, apis) {
  const active = (bindings || []).filter(binding => binding.is_active)
  return (apis || []).map(api => {
    const binding = active.find(item => item.target_id === api.id)
    return { ...api, binding: binding || null, bound: Boolean(binding) }
  })
}
