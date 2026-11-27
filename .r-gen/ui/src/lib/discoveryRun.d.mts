export const DISCOVERY_SCAN_ROLES: string[]
export function isDiscoveryRun(scan: { scan_role?: string | null } | null | undefined): boolean
export function hiddenRunsNote(hidden: unknown): string | null
export function scansShownText(total: number, page: number, pageSize: number): string
