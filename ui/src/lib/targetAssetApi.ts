import { API_URL, getApiErrorMessage } from './apiConfig'
import type { CredentialProfile } from './credentialApi'
import type { SharedServiceKnowledge } from '@/components/targets/SharedServicePorts'

export interface TargetAsset {
  id: string
  asset_id: string
  name: string | null
  url: string
  locator: string
  root_domain?: string
  is_active: boolean
  environment: string
  port_hints?: number[]
  has_target_skill?: boolean
  connected_device: boolean
  device_class?: string | null
  manufacturer?: string | null
  model?: string | null
  firmware_version?: string | null
  origin_count?: number
  service_count?: number
  active_findings_count?: number
  network_score?: number | null
  network_grade?: string | null
  network_last_scan_id?: string | null
  network_last_scanned_at?: string | null
  /** Inventory listing only: linked web apps, newest scan, findings and authorization. */
  origins?: InventoryOrigin[]
  severity_counts?: Partial<Record<'critical' | 'high' | 'medium' | 'low' | 'info', number>>
  last_scanned_at?: string | null
  scanning?: boolean
  /** The host asset's own standing authorization, which its linked web apps inherit. */
  authorized?: boolean
  /** Active linked web apps the scan path treats as authorized (inherited or their own receipt). */
  authorized_origin_count?: number
  created_at: string
  updated_at: string
}

export interface InventoryOrigin {
  id: string
  url: string
  name: string | null
  is_active: boolean
  last_scanned_at?: string | null
  last_grade?: string | null
  last_score?: number | null
  active_findings_count?: number | null
  /** Whether a scan of this web app runs under a standing authorization. */
  authorized?: boolean
}

/** Counts for each filter value over the current search, before the other filters apply. */
export interface InventoryFacets {
  total: number
  environment: Record<string, number>
  authorization: {authorized: number; unauthorized: number}
  findings: {any: number; critical_high: number; none: number}
  activity: {scanned: number; never: number; scanning: number}
  asset_type: {web: number; network: number}
}

export interface AssetOrigin {
  id: string
  url: string
  name: string | null
  is_active: boolean
  current_membership: boolean
  authorized?: boolean
  last_scanned_at?: string | null
  last_score?: number | null
  last_grade?: string | null
  active_findings_count: number
}
export interface AssetHistoryItem {
  id: string
  target_id: string
  target_url?: string
  title?: string
  status?: string | null
  severity?: string
  scan_type?: string
  run_kind?: string
  score?: number | null
  grade?: string | null
  created_at: string
}
export type AssetHistoryKind = 'scans' | 'findings' | 'hunts'
export interface AssetHistory {
  asset_id: string
  kind: AssetHistoryKind
  items: AssetHistoryItem[]
  total: number
  limit: number
  offset: number
}
export interface AssetDetail {
  service_intelligence?: SharedServiceKnowledge
  target: TargetAsset
  requested_target_id: string
  origins: AssetOrigin[]
  services: Array<{id: string; transport: string; port: number; state: string; service_name: string; product?: string | null; version?: string | null; web_origin?: string | null; last_seen_at?: string | null}>
  credentials: CredentialProfile[]
  request_collections: Array<{id: string; name: string; format: string; home_target_id: string; request_count: number; safe_request_count: number; potentially_mutating_request_count: number; is_active: boolean; updated_at?: string}>
  active_findings: Record<string, number>
  history: AssetHistory
  authorization?: {approval_receipt_id: string; approved_by: string; inherited?: boolean; authority_target_id?: string} | null
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, { cache: 'no-store', ...init })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Target request failed'))
  return response.json() as Promise<T>
}
const json = (method: string, body: unknown): RequestInit => ({ method, headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body) })

export interface TargetAssetGroup { root_domain: string; targets: TargetAsset[] }

export interface InventoryQuery {
  search?: string; offset?: number; limit?: number; connected_only?: boolean; include_inactive?: boolean
  include_services?: boolean; group_by?: 'domain'; asset_type?: 'web' | 'network'; environment?: string
  authorization?: 'authorized' | 'unauthorized'; findings?: 'any' | 'critical_high' | 'none'
  activity?: 'never' | 'scanned' | 'scanning'; sort?: 'name' | 'risk' | 'recent' | 'created'; include_facets?: boolean
}
export interface InventoryPage {
  targets: TargetAsset[]; groups?: TargetAssetGroup[]; total_groups?: number; total: number
  offset: number; limit: number; facets?: InventoryFacets
}

export function getTargetAssets(params: InventoryQuery = {}, signal?: AbortSignal): Promise<InventoryPage> {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) if (value !== undefined && value !== '') search.set(key, String(value))
  return request(`/targets/inventory?${search}`, { signal })
}
export const getTargetAsset = (id: string, signal?: AbortSignal) => request<AssetDetail>(`/targets/${encodeURIComponent(id)}/asset`, { signal })
export const getTargetAssetHistory = (id: string, kind: AssetHistoryKind, offset = 0, signal?: AbortSignal) => request<AssetHistory>(`/targets/${encodeURIComponent(id)}/history?${new URLSearchParams({kind,offset:String(offset),limit:'25'})}`, { signal })
export const enableTargetNetworkView = (id: string, deviceClass = 'generic') => request<{asset_id: string; device_id: string}>(`/targets/${encodeURIComponent(id)}/device-profile`, json('POST', {device_class: deviceClass}))
export const renameTargetAsset = (id: string, name: string) => request(`/targets/${encodeURIComponent(id)}`, json('PATCH', {name}))
export const authorizeTargetAsset = (id: string, approvedBy: string, environment?: string) => request(`/targets/${encodeURIComponent(id)}/authorization`, json('POST', {approved_by: approvedBy, environment, risk_tier:'active'}))
export const revokeTargetAsset = (id: string, revokedBy: string, reason: string) => request<{revoked: number}>(`/targets/${encodeURIComponent(id)}/authorization`, json('DELETE', {revoked_by: revokedBy, reason}))

/** Register a host-level target; port hints guide its network scans. */
export const createHostTarget = (input: {locator: string; name?: string; environment: string; approvedBy?: string; portHints?: number[]}) =>
  request<{id: string; asset_id: string; url: string; status: 'created' | 'already_exists'}>('/targets/hosts', json('POST', {
    locator: input.locator, name: input.name, environment: input.environment,
    approved_by: input.approvedBy, port_hints: input.portHints || [],
  }))

/** Register a web app. Without a scheme the scanner detects HTTP or HTTPS on the first scan. */
export const createWebTarget = (url: string, environment: string, name?: string) =>
  request<{id: string; url: string; status?: 'created' | 'already_exists'; dns_fallback?: unknown}>('/targets', json('POST', {url, name, cohort: environment}))

/** Discover open ports and web services; discovered web apps link to the host automatically. */
export const startTargetDiscovery = (id: string, portHints: number[] = []) =>
  request<{scan_id?: string; id?: string}>(`/targets/${encodeURIComponent(id)}/network-scans`, json('POST', {
    profile: 'inventory', include_web_dast: false, confirm_authorized: true, port_hints: portHints,
  }))

export async function registerTargetAsset(input: {locator: string; name?: string; environment: string; approvedBy?: string; portHints?: number[]}): Promise<string> {
  const value = input.locator.trim()
  const isOrigin = /^https?:\/\//i.test(value)
  const created = isOrigin
    ? await request<{id: string}>('/targets', json('POST', {url:value,name:input.name,cohort:input.environment}))
    : await request<{id: string}>('/targets/hosts', json('POST', {locator:value,name:input.name,environment:input.environment,port_hints:input.portHints || []}))
  const detail = await getTargetAsset(created.id)
  if (input.approvedBy) {
    try { await authorizeTargetAsset(detail.target.id,input.approvedBy,input.environment) }
    catch (error) { throw new Error(`Target saved, but authorization was not recorded: ${error instanceof Error ? error.message : 'scope review failed'}`) }
  }
  return detail.target.id
}

/** Fetch every metadata page; selectors must not silently lose assets after the first page. */
export async function getAllTargetAssets(signal?: AbortSignal, includeServices = false): Promise<TargetAsset[]> {
  const assets = new Map<string, TargetAsset>()
  let offset = 0
  for (;;) {
    const page = await getTargetAssets({limit:500,offset,include_services:includeServices},signal)
    for (const asset of page.targets) assets.set(asset.id,asset)
    offset += page.targets.length
    if (offset >= page.total) return [...assets.values()]
    if (!page.targets.length) throw new Error('Target inventory changed while paging; refresh the selector')
  }
}
