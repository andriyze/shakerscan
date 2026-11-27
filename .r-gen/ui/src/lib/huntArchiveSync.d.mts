export const ARCHIVE_PAGE: number
export const ARCHIVE_MAX_ROWS: number
export type PageMergePlan<T> = { action: 'append'; rows: T[] } | { action: 'resync' } | { action: 'reload' }
export function planPageMerge<T extends { id: string }>(input: { held: T[]; page: T[]; limit: number; total: number }): PageMergePlan<T>
export function resyncWindows(heldCount: number, options?: { page?: number; max?: number }): Array<{ offset: number; limit: number }>
