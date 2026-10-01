import { API_URL, getApiErrorMessage } from './apiConfig'
import type { CredentialProfile } from './credentialApi'

export interface TargetAsset {
  id: string
  asset_id: string
  name: string | null
  url: string
  locator: string
  is_active: boolean
  environment: string
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
  created_at: string
  updated_at: string
}

export interface AssetOrigin {
  id: string
  url: string
  name: string | null
  is_active: boolean
  current_membership: boolean
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
  target: TargetAsset
  requested_target_id: string
  origins: AssetOrigin[]
  services: Array<{id: string; transport: string; port: number; state: string; service_name: string; product?: string | null; version?: string | null; web_origin?: string | null; last_seen_at?: string | null}>
  credentials: CredentialProfile[]
  request_collections: Array<{id: string; name: string; format: string; home_target_id: string; request_count: number; is_active: boolean}>
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

export function getTargetAssets(params: {search?: string; offset?: number; limit?: number; connected_only?: boolean; include_inactive?: boolean} = {}, signal?: AbortSignal): Promise<{targets: TargetAsset[]; total: number; offset: number; limit: number}> {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) if (value !== undefined) search.set(key, String(value))
  return request(`/targets/inventory?${search}`, { signal })
}
export const getTargetAsset = (id: string, signal?: AbortSignal) => request<AssetDetail>(`/targets/${encodeURIComponent(id)}/asset`, { signal })
export const getTargetAssetHistory = (id: string, kind: AssetHistoryKind, offset = 0, signal?: AbortSignal) => request<AssetHistory>(`/targets/${encodeURIComponent(id)}/history?${new URLSearchParams({kind,offset:String(offset),limit:'25'})}`, { signal })
export const enableTargetNetworkView = (id: string, deviceClass = 'generic') => request<{asset_id: string; device_id: string}>(`/targets/${encodeURIComponent(id)}/device-profile`, json('POST', {device_class: deviceClass}))
export const renameTargetAsset = (id: string, name: string) => request(`/targets/${encodeURIComponent(id)}`, json('PATCH', {name}))
export const authorizeTargetAsset = (id: string, approvedBy: string, environment?: string) => request(`/targets/${encodeURIComponent(id)}/authorization`, json('POST', {approved_by: approvedBy, environment, risk_tier:'active'}))

export async function registerTargetAsset(input: {locator: string; name?: string; environment: string; approvedBy?: string}): Promise<string> {
  const value = input.locator.trim()
  const isOrigin = /^https?:\/\//i.test(value)
  const created = isOrigin
    ? await request<{id: string}>('/targets', json('POST', {url:value,name:input.name,cohort:input.environment}))
    : await request<{id: string}>('/targets/hosts', json('POST', {locator:value,name:input.name,environment:input.environment}))
  const detail = await getTargetAsset(created.id)
  if (input.approvedBy) {
    try { await authorizeTargetAsset(detail.target.id,input.approvedBy,input.environment) }
    catch (error) { throw new Error(`Target saved, but authorization was not recorded: ${error instanceof Error ? error.message : 'scope review failed'}`) }
  }
  return detail.target.id
}
