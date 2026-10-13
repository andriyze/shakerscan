import { API_URL, getApiErrorMessage } from './apiConfig'

/** A secret found on a target: metadata only; the value is never part of a listing. */
export interface DiscoveredSecret {
  ref: string
  kind: string
  label: string
  length: number
  source: { kind?: string; id?: string; hunt_id?: string }
  first_seen_at: string
  last_seen_at: string
  seen_count: number
  state: 'active' | 'revoked_by_operator' | 'expired' | 'superseded'
  expires_at: string
  uses: number
  reveals: number
  last_used_at: string | null
  found_on: string
  granted_to: string[]
  promoted_profile_id: string | null
}

/** The Enterprise gateway asks for the person's step-up for this one decision. */
export class StepUpRequired extends Error {}

const base = (targetId: string) => `${API_URL}/targets/${encodeURIComponent(targetId)}/discovered-secrets`
const secretPath = (targetId: string, ref: string) => `${base(targetId)}/${encodeURIComponent(ref.replace(/^secret:\/\//, ''))}`

async function send<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, { cache: 'no-store', ...init })
  if (response.status === 403 && response.headers.get('x-shakerscan-step-up') === 'required') {
    throw new StepUpRequired(await getApiErrorMessage(response, 'This decision needs your step-up'))
  }
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Discovered-secret request failed'))
  return response.json() as Promise<T>
}
const post = (body: unknown): RequestInit => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })

export const listDiscoveredSecrets = (targetId: string, signal?: AbortSignal) =>
  send<{ secrets: DiscoveredSecret[]; count: number }>(base(targetId), { signal })
export const setDiscoveredSecretState = (targetId: string, ref: string, state: 'active' | 'revoked_by_operator') =>
  send(`${secretPath(targetId, ref)}/state`, post({ state }))
export const setDiscoveredSecretExpiry = (targetId: string, ref: string, days: number) =>
  send(`${secretPath(targetId, ref)}/expiry`, post({ days }))
export const grantDiscoveredSecret = (targetId: string, ref: string, toTargetId: string) =>
  send(`${secretPath(targetId, ref)}/grants`, post({ target_id: toTargetId }))
export const ungrantDiscoveredSecret = (targetId: string, ref: string, toTargetId: string) =>
  send(`${secretPath(targetId, ref)}/grants/${encodeURIComponent(toTargetId)}`, { method: 'DELETE' })
export const revealDiscoveredSecret = (targetId: string, ref: string) =>
  send<{ value: string }>(`${secretPath(targetId, ref)}/reveal`, post({}))
export const promoteDiscoveredSecret = (targetId: string, ref: string, input: { name: string; auth_kind: string; header_name?: string }) =>
  send<{ profile: { id: string } }>(`${secretPath(targetId, ref)}/promote`, post(input))
export const purgeDiscoveredSecrets = (targetId: string) =>
  send<{ deleted: number }>(base(targetId), { method: 'DELETE' })

/** The terminal command that makes a step-up decision on Enterprise. */
export const terminalCommand = (action: 'reveal' | 'grant' | 'promote', targetId: string, ref: string) =>
  `shakerscan secrets ${action} ${targetId} ${ref}${action === 'grant' ? ' --to <target-id>' : action === 'promote' ? ' --name <name> --auth-kind <kind>' : ''}`
