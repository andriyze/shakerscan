export type PrincipalSlot = 'user1' | 'user2'

export interface PrincipalProfileDraft {
  label: string
  role: string
  tenantId: string
  credentialProfile: string
}

export interface PrincipalProfilePayload {
  label: string
  role: string
  auth_state: PrincipalSlot
  tenant_id?: string
  credential_profile?: string
}

export function emptyPrincipalProfileDraft(): PrincipalProfileDraft {
  return { label: '', role: 'user', tenantId: '', credentialProfile: '' }
}

export function buildPrincipalProfilePayload(
  slot: PrincipalSlot,
  draft: PrincipalProfileDraft,
  updating: boolean
): PrincipalProfilePayload {
  const payload: PrincipalProfilePayload = {
    label: draft.label.trim(),
    role: draft.role.trim() || 'user',
    auth_state: slot,
  }
  const tenantId = draft.tenantId.trim()
  const credentialProfile = draft.credentialProfile.trim()

  if (updating || tenantId) payload.tenant_id = tenantId
  if (updating || credentialProfile) payload.credential_profile = credentialProfile
  return payload
}
