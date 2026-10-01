import { API_URL, getApiErrorMessage } from './apiConfig'
import type {
  CredentialProfileCreate as GeneratedCredentialProfileCreate,
  CredentialProfileRotate as GeneratedCredentialProfileRotate,
} from './publicApi.generated'

export type CredentialTargetKind = GeneratedCredentialProfileCreate['target_kind']
export type CredentialPrincipalSlot = NonNullable<GeneratedCredentialProfileCreate['principal_slot']>
export type CredentialAuthKind = GeneratedCredentialProfileCreate['auth_kind']

export interface CredentialProfile {
  id: string
  target_kind: CredentialTargetKind
  target_id: string
  name: string
  auth_kind: CredentialAuthKind
  principal_label?: string | null
  principal_slot: CredentialPrincipalSlot
  configuration: {
    schema_version: string
    auth_kind: CredentialAuthKind
    username_configured: boolean
    secret_configured: boolean
    secondary_secret_configured: boolean
    header_name?: string | null
    endpoint_configured: boolean
    client_id_configured: boolean
    scope_count: number
    custom_header_names: string[]
    parameter_name?: string | null
    browser_storage_key?: string | null
    interactive_exchange_required: boolean
    secret_values_visible: false
  }
  current_version: number
  record_version: number
  is_active: boolean
  expires_at?: string | null
  rotated_at: string
  created_at: string
  updated_at: string
  allowed_capabilities: string[]
  secret_configured: true
  secret_values_visible: false
  status: 'active' | 'inactive' | 'expired'
  refresh_required: boolean
  execution_compatible: boolean
  storage_encrypted: true
  encryption_available: boolean
  /** The profile's own target (its owner). target_id is the same value. */
  home_target_id?: string
  /** The target this copy was listed for; differs from home_target_id when shared. */
  granted_target_id?: string | null
  /** Listed for a target it is shared with, not its own. */
  shared?: boolean
  home_target_name?: string | null
  home_target_locator?: string | null
  /** Library listing only: how many other targets it is shared with. */
  shared_target_count?: number
}

/** A target a credential serves: its own (home) target, or one it is shared with. */
export interface CredentialGrant {
  target_id: string
  home: boolean
  active: boolean
  granted_by?: string | null
  granted_at?: string | null
  revoked_at?: string | null
  target_name?: string | null
  target_locator?: string | null
}

export type CredentialSecretPayload = Omit<
  GeneratedCredentialProfileRotate,
  'expected_record_version' | 'created_by'
>

export type CredentialProfileCreatePayload = GeneratedCredentialProfileCreate & {
  allow_active_capabilities?: boolean
  approval_receipt_id?: string
}

export interface CredentialCapabilityOption {
  name: string
  description: string
  risk_tier: string
  requires_active_approval: boolean
  default: boolean
}

export async function listCredentialCapabilities(params: {
  target_kind: CredentialTargetKind
  auth_kind: CredentialAuthKind
}): Promise<{
  blank_semantics: 'safe_server_defaults'
  safe_defaults: string[]
  capabilities: CredentialCapabilityOption[]
}> {
  const search = new URLSearchParams({
    target_kind: params.target_kind,
    auth_kind: params.auth_kind,
  })
  const response = await fetch(`${API_URL}/credential-profiles/capabilities?${search}`, { cache: 'no-store' })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Failed to load credential capabilities'))
  return response.json()
}

export async function listCredentialProfiles(params: {
  target_kind: CredentialTargetKind
  target_id: string
  include_inactive?: boolean
}): Promise<{ profiles: CredentialProfile[]; count: number }> {
  const search = new URLSearchParams({
    target_kind: params.target_kind,
    target_id: params.target_id,
  })
  if (params.include_inactive) search.set('include_inactive', 'true')
  const response = await fetch(`${API_URL}/credential-profiles?${search}`, { cache: 'no-store' })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Failed to load credential profiles'))
  return response.json()
}

export async function createCredentialProfile(
  payload: CredentialProfileCreatePayload,
): Promise<{ profile: CredentialProfile }> {
  const response = await fetch(`${API_URL}/credential-profiles`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Failed to create credential profile'))
  return response.json()
}

export async function rotateCredentialProfile(
  profileId: string,
  payload: CredentialSecretPayload & { expected_record_version: number; created_by?: string },
): Promise<{ profile: CredentialProfile }> {
  const response = await fetch(`${API_URL}/credential-profiles/${encodeURIComponent(profileId)}/rotate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Failed to rotate credential profile'))
  return response.json()
}

export async function deactivateCredentialProfile(
  profileId: string,
): Promise<{ status: string; profile: CredentialProfile }> {
  const response = await fetch(`${API_URL}/credential-profiles/${encodeURIComponent(profileId)}`, {
    method: 'DELETE',
  })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Failed to deactivate credential profile'))
  return response.json()
}

/** Every credential profile, with how many other targets each is shared with. */
export async function listCredentialLibrary(params: {
  include_inactive?: boolean
  search?: string
  limit?: number
  offset?: number
} = {}): Promise<{ profiles: CredentialProfile[]; count: number; total: number }> {
  const search = new URLSearchParams()
  if (params.include_inactive) search.set('include_inactive', 'true')
  if (params.search) search.set('search', params.search)
  if (params.limit) search.set('limit', String(params.limit))
  if (params.offset) search.set('offset', String(params.offset))
  const response = await fetch(`${API_URL}/credential-profiles?${search}`, { cache: 'no-store' })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Failed to load credentials'))
  return response.json()
}

export async function listCredentialGrants(profileId: string): Promise<{ grants: CredentialGrant[] }> {
  const response = await fetch(`${API_URL}/credential-profiles/${encodeURIComponent(profileId)}/grants`, { cache: 'no-store' })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Failed to load where this credential is used'))
  return response.json()
}

export async function grantCredentialProfile(
  profileId: string,
  payload: { target_kind: CredentialTargetKind; target_id: string; approval_receipt_id?: string },
): Promise<{ grant: CredentialGrant }> {
  const response = await fetch(`${API_URL}/credential-profiles/${encodeURIComponent(profileId)}/grants`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...payload, granted_by: 'credentials_ui' }),
  })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Failed to share credential'))
  return response.json()
}

export async function revokeCredentialGrant(profileId: string, targetId: string): Promise<{ grant: CredentialGrant }> {
  const response = await fetch(
    `${API_URL}/credential-profiles/${encodeURIComponent(profileId)}/grants/${encodeURIComponent(targetId)}`,
    { method: 'DELETE' },
  )
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Failed to stop sharing credential'))
  return response.json()
}
