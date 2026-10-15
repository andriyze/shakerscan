export function isFilterName(name: unknown): boolean
export function parseFilterParams(
  searchParams: URLSearchParams,
  defaults?: Record<string, string | number | undefined>,
): Record<string, string | number | undefined>
export function parseReturnParams(searchParams: URLSearchParams): Record<string, string>
