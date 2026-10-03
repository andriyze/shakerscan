import { API_URL, getApiErrorMessage } from './apiConfig'

export interface TargetHuntAuthority {
  target_id: string
  revision: number
  metadata_changes: boolean
  credential_profile_ids: string[]
  collection_ids: string[]
  ssh_host_keys: Array<{port: number; fingerprint: string}>
  ssh_trust_first_contact: boolean
  recorded_by?: string | null
  updated_at?: string | null
}
export type AuthorityWrite = Omit<TargetHuntAuthority, 'target_id'|'revision'|'recorded_by'|'updated_at'> & {expected_revision: number}

async function request(id: string, init?: RequestInit): Promise<TargetHuntAuthority> {
  const response = await fetch(`${API_URL}/targets/${encodeURIComponent(id)}/hunt-authority`, {cache:'no-store', ...init})
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Could not update Hunt permissions'))
  const value = await response.json()
  if (!Number.isSafeInteger(value.revision) || !Array.isArray(value.credential_profile_ids) || !Array.isArray(value.collection_ids) || !Array.isArray(value.ssh_host_keys)) throw new Error('Invalid Hunt permissions response. Reload and try again.')
  return value
}
export const getTargetHuntAuthority = (id: string) => request(id)
export const saveTargetHuntAuthority = (id: string, body: AuthorityWrite) => request(id, {
  method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body),
})
