export function cleanTargetLocator(url: unknown): string
export function targetRetired(url: unknown): boolean
export function huntTargetTitle(hunt: { target_name?: string | null; target_url?: string | null; target_id?: string | null } | null | undefined): string
export function huntActivity(hunt: { budget_used?: Record<string, number | undefined> | null } | null | undefined): {
  requests: number; actions: number; candidates: number; browser: number; ports: number
}
