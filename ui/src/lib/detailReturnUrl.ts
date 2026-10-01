// A list's filters travel to a detail page as return_<key>, so its back link restores the same
// scope. Every filter in effect is carried: a hand-kept subset dropped the device, campaign,
// freshness and grouping scope of the findings list.

export type FilterValues = Record<string, string | number | undefined>

export function detailUrlWithReturn(path: string, filters: FilterValues, defaults: FilterValues = {}): string {
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(filters)) {
    if (value === undefined || value === '' || value === defaults[key]) continue
    params.set(`return_${key}`, String(value))
  }
  const query = params.toString()
  return query ? `${path}?${query}` : path
}
