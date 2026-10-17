export type TotalKind = 'none' | 'estimate' | 'exact' | 'at_least'
export interface ListV1Page<T> {
  items: T[]
  next_cursor: string | null
  has_more: boolean
  total?: number
  total_kind: TotalKind
  generated_at: string
}
export const LIST_V1_MAX_LIMIT: number
export function isListV1<T = unknown>(body: unknown): body is ListV1Page<T>
export function listV1Params(options?: {
  limit?: number; cursor?: string | null; sort?: string; count?: 'none' | 'estimate' | 'exact'; since?: string | null
}): Record<string, string>
export function isUnknownListParamError(error: unknown): boolean
export function totalLabel(page: { total?: number | null; total_kind?: TotalKind } | null | undefined, locale?: string): string | null
export function mergeSinceDelta<T extends Record<string, any>>(rows: T[], delta: T[], options?: { key?: string; limit?: number }): T[]
