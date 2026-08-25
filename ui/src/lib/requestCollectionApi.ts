import { API_URL, getApiErrorMessage } from './apiConfig'
import type {
  RequestCollectionBindingUpsert as GeneratedRequestCollectionBindingUpsert,
  RequestCollectionCreate as GeneratedRequestCollectionCreate,
  RequestCollectionEnvironmentCreate as GeneratedRequestCollectionEnvironmentCreate,
  RequestCollectionSelectionUpsert as GeneratedRequestCollectionSelectionUpsert,
} from './publicApi.generated'

export type RequestCollectionTargetKind = 'web' | 'api' | 'device'
export type RequestCollectionReplayPolicy = 'discovery_only' | 'safe_reads' | 'confirmed_active'
export type RequestCollectionImportFormat = NonNullable<GeneratedRequestCollectionCreate['format']>

export interface SharedRequestCollection {
  id: string
  target_id?: string | null
  device_target_id?: string | null
  name: string
  format: string
  schema_version: string
  payload_sha256: string
  request_count: number
  safe_request_count: number
  potentially_mutating_request_count: number
  metadata_json?: Record<string, unknown>
  is_active: boolean
  created_at: string
  updated_at: string
  storage_encrypted: true
}

export interface RequestCollectionEnvironment {
  id: string
  collection_id: string
  name: string
  payload_sha256: string
  variable_count: number
  is_active: boolean
  storage_encrypted: true
  secret_values_visible: false
}

export interface RequestCollectionBinding {
  id: string
  collection_id: string
  target_kind: RequestCollectionTargetKind
  target_id: string
  allowed_origins: string[]
  environment_id?: string | null
  is_active: boolean
  secret_values_visible: false
}

export interface RequestCollectionSelector {
  request_ids: string[]
  folders: string[]
  methods: string[]
  path_regex?: string | null
  tags: string[]
  safe_methods_only: boolean
  max_requests: number
}

export interface RequestCollectionSelection {
  id: string
  collection_id: string
  binding_id: string
  name: string
  replay_policy: RequestCollectionReplayPolicy
  selector: RequestCollectionSelector
  selection_digest: string
  selected_request_count: number
  selected_mutating_count: number
  is_active: boolean
  secret_values_visible: false
}

export interface RequestCollectionInventoryItem {
  request_id: string
  ordinal: number
  folder?: string | null
  name?: string | null
  method: string
  redacted_url?: string | null
  normalized_path?: string | null
  body_mode?: string | null
  auth_type?: string | null
  tags: string[]
  safe_method: boolean
  supported: boolean
}

export interface RequestCollectionDetail {
  collection: SharedRequestCollection
  environments: RequestCollectionEnvironment[]
  bindings: RequestCollectionBinding[]
  selections: RequestCollectionSelection[]
  secret_values_visible: false
}

export async function listRequestCollections(
  targetId: string,
): Promise<{ collections: SharedRequestCollection[]; count: number }> {
  const search = new URLSearchParams({ target_id: targetId, limit: '500' })
  const response = await fetch(`${API_URL}/request-collections?${search}`, { cache: 'no-store' })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Failed to load request collections'))
  return response.json()
}

export async function getRequestCollection(collectionId: string): Promise<RequestCollectionDetail> {
  const response = await fetch(
    `${API_URL}/request-collections/${encodeURIComponent(collectionId)}`,
    { cache: 'no-store' },
  )
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Failed to load request collection'))
  return response.json()
}

export async function listRequestCollectionInventory(
  collectionId: string,
  params: { limit?: number; offset?: number } = {},
): Promise<{
  requests: RequestCollectionInventoryItem[]
  count: number
  total: number
  offset: number
  limit: number
  next_offset?: number | null
  secret_values_visible: false
}> {
  const search = new URLSearchParams({
    limit: String(params.limit ?? 100),
    offset: String(params.offset ?? 0),
  })
  const response = await fetch(
    `${API_URL}/request-collections/${encodeURIComponent(collectionId)}/requests?${search}`,
    { cache: 'no-store' },
  )
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Failed to load request inventory'))
  return response.json()
}

export async function createRequestCollection(payload: {
  target_id: string
  document: unknown
} & Omit<GeneratedRequestCollectionCreate, 'target_id' | 'document'>): Promise<SharedRequestCollection & {
  environment?: RequestCollectionEnvironment | null
  binding?: RequestCollectionBinding | null
}> {
  const response = await fetch(`${API_URL}/request-collections`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Failed to upload request collection'))
  return response.json()
}

export async function upsertRequestCollectionEnvironment(
  collectionId: string,
  payload: GeneratedRequestCollectionEnvironmentCreate,
): Promise<{ environment: RequestCollectionEnvironment }> {
  const response = await fetch(
    `${API_URL}/request-collections/${encodeURIComponent(collectionId)}/environments`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    },
  )
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Failed to save collection environment'))
  return response.json()
}

export async function upsertRequestCollectionBinding(
  collectionId: string,
  payload: GeneratedRequestCollectionBindingUpsert,
): Promise<{ binding: RequestCollectionBinding }> {
  const response = await fetch(
    `${API_URL}/request-collections/${encodeURIComponent(collectionId)}/bindings`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    },
  )
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Failed to bind request collection'))
  return response.json()
}

export async function upsertRequestCollectionSelection(
  collectionId: string,
  payload: GeneratedRequestCollectionSelectionUpsert,
): Promise<{
  selection: RequestCollectionSelection
  preview: {
    requests: RequestCollectionInventoryItem[]
    count: number
    preview_truncated: boolean
    secret_values_visible: false
  }
}> {
  const response = await fetch(
    `${API_URL}/request-collections/${encodeURIComponent(collectionId)}/selections`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    },
  )
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Failed to save request selection'))
  return response.json()
}
