export type PostureState = 'disabled' | 'loading' | 'unavailable' | 'ready'
export function postureState(input: { enabled: boolean; exposure: { metrics?: unknown } | null | undefined; failed: boolean }): PostureState
export interface CoverageScope {
  show: boolean
  domains: number
  hasMore: boolean
  truncatedGroups: number
  total: string | null
  text: string | null
}
export function coverageScope(input: {
  groups: ReadonlyArray<{ subdomains?: unknown[]; subdomain_count?: number; subdomains_truncated?: boolean }>
  hasMore: boolean
  total: string | null
}): CoverageScope
export function cohortScopingNote(input: {
  view: string
  exposure: { assets?: unknown[]; total?: number; metrics?: { asset_count?: number } } | null | undefined
}): string | null
export type CohortView = 'operational' | 'production' | 'staging' | 'non_operational' | 'all'
export const COHORT_VIEWS: ReadonlyArray<CohortView>
export function parseCohortView(value: unknown): CohortView
export interface OutOfScopeSummary { assets: number; findings: number; where: string; text: string }
export function outOfScopeSummary(input: {
  view: string
  exposure: { total?: number; metrics?: { asset_count?: number }; cohort_counts?: Record<string, number> } | null | undefined
  installFindings: number | null | undefined
}): OutOfScopeSummary | null
