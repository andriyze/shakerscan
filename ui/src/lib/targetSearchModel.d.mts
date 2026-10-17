export function isTargetId(id: unknown): id is string
export const TARGET_SEARCH_MAX_PAGES: number
export function collectAcceptedTargets<T extends { id: string }, P = unknown>(options: {
  fetchPage: (position: P | null) => Promise<{ targets: T[]; hasMore: boolean; next: P | null }>
  accept?: (row: T) => boolean
  limit: number
  maxPages?: number
}): Promise<{ matches: T[]; hasMore: boolean; scanned: number; pages: number; filtered: boolean }>
export function targetSearchNoteText(search: {
  assets: unknown[]; hasMore: boolean; error: string | null; query: string
  scanned?: number; filtered?: boolean; loading?: boolean
}): string
export function targetSearchProvesEmpty(search: {
  ready: boolean; loading: boolean; error: string | null; query: string; hasMore: boolean; assets: unknown[]
}): boolean
