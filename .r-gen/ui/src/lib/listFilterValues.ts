// A multi-value URL filter kept as a comma list in a fixed order (severity=critical,high), which
// GET /findings accepts as is.

export function listFilterValues(value: string | null | undefined): string[] {
  return String(value || '').split(',').map((part) => part.trim()).filter(Boolean)
}

export function toggleListFilterValue(
  current: string | null | undefined,
  value: string,
  order: readonly string[],
): string | undefined {
  const selected = new Set(listFilterValues(current))
  if (selected.has(value)) selected.delete(value)
  else selected.add(value)
  const next = order.filter((item) => selected.has(item))
  return next.length ? next.join(',') : undefined
}
