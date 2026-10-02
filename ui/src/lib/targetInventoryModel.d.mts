export type TargetInputKind = 'domain' | 'ipv4' | 'ipv6' | 'local'

export interface ParsedTarget {
  ok: true
  input: string
  host: string
  kind: TargetInputKind
  scheme: 'http' | 'https' | null
  port: number | null
  pathIgnored: boolean
  webUrl: string
  webLabel: string
  webDefault: boolean
}
export interface InvalidTarget { ok: false; input?: string; error: string }

export function parseTargetInput(raw: unknown): ParsedTarget | InvalidTarget
export function parseTargetLines(raw: unknown): { entries: Array<ParsedTarget | (InvalidTarget & { input: string })>; truncated: boolean }
export function parsePortList(raw: unknown): { ports: number[]; error: string | null }
export function originLabel(url: unknown): { scheme: 'http' | 'https' | null; secure: boolean; port: number | null; host: string; label: string }
export const SEVERITY_ORDER: readonly string[]
export function severitySummary(counts: unknown): Array<{ severity: string; count: number }>
export function relativeTime(value: unknown, now?: number): string | null
export function isDomainGroup(rootDomain: unknown): boolean
export function groupSections<U>(groups: Array<{ root_domain: string; targets: U[] }>): { domains: Array<{ root_domain: string; targets: U[] }>; network: U[] }
export function latestGrade(asset: {
  network_grade?: string | null; network_last_scanned_at?: string | null
  origins?: Array<{ last_grade?: string | null; last_scanned_at?: string | null }>
} | null | undefined): string | null

export interface TargetFilters {
  search: string
  environment: string
  authorization: '' | 'authorized' | 'unauthorized' | string
  findings: '' | 'any' | 'critical_high' | 'none' | string
  activity: '' | 'never' | 'scanned' | 'scanning' | string
  asset_type: '' | 'web' | 'network' | string
  sort: 'name' | 'risk' | 'recent' | 'created' | string
  archived: boolean
}
export const FILTER_KEYS: ReadonlyArray<keyof TargetFilters>
export const FILTER_DEFAULTS: TargetFilters
export function filtersFromQuery(params: { get(key: string): string | null } | null | undefined): TargetFilters
export function queryFromFilters(filters: TargetFilters): string
export function inventoryParams(filters: TargetFilters, offset: number, limit: number): Record<string, string | number | boolean>
export function activeFilterCount(filters: TargetFilters): number
export function scanUrls(asset: { locator?: string | null; origins?: Array<{ url: string; is_active: boolean }> } | null | undefined): string[]
export function configureScanHref(targets: string[], forceBatch?: boolean): string
