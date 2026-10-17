import { pathSegment } from './apiPath.mjs'
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

const secretId = (ref: string) => ref.replace(/^secret:\/\//, '')

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, { cache: 'no-store', ...init })
  if (response.status === 403 && response.headers.get('x-shakerscan-step-up') === 'required') {
    throw new StepUpRequired(await getApiErrorMessage(response, 'This decision needs your step-up'))
  }
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Discovered-secret request failed'))
  return response.json() as Promise<T>
}
const json = (method: string, body: unknown): RequestInit => ({ method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })

export const listDiscoveredSecrets = (targetId: string, signal?: AbortSignal) =>
  request<{ secrets: DiscoveredSecret[]; count: number }>(`/targets/${pathSegment(targetId)}/discovered-secrets`, { signal })
export const setDiscoveredSecretState = (targetId: string, ref: string, state: 'active' | 'revoked_by_operator') =>
  request(`/targets/${pathSegment(targetId)}/discovered-secrets/${pathSegment(secretId(ref))}/state`, json('POST', { state }))
export const setDiscoveredSecretExpiry = (targetId: string, ref: string, days: number) =>
  request(`/targets/${pathSegment(targetId)}/discovered-secrets/${pathSegment(secretId(ref))}/expiry`, json('POST', { days }))
export const grantDiscoveredSecret = (targetId: string, ref: string, toTargetId: string) =>
  request(`/targets/${pathSegment(targetId)}/discovered-secrets/${pathSegment(secretId(ref))}/grants`, json('POST', { target_id: toTargetId }))
export const ungrantDiscoveredSecret = (targetId: string, ref: string, toTargetId: string) =>
  request(`/targets/${pathSegment(targetId)}/discovered-secrets/${pathSegment(secretId(ref))}/grants/${pathSegment(toTargetId)}`, { method: 'DELETE' })
export const revealDiscoveredSecret = (targetId: string, ref: string) =>
  request<{ value: string }>(`/targets/${pathSegment(targetId)}/discovered-secrets/${pathSegment(secretId(ref))}/reveal`, json('POST', {}))
export const promoteDiscoveredSecret = (targetId: string, ref: string, input: { name: string; auth_kind: string; header_name?: string }) =>
  request<{ profile: { id: string } }>(`/targets/${pathSegment(targetId)}/discovered-secrets/${pathSegment(secretId(ref))}/promote`, json('POST', input))

/** The terminal command that makes a step-up decision on Enterprise. */
export const terminalCommand = (action: 'reveal' | 'grant' | 'promote', targetId: string, ref: string) =>
  `shakerscan secrets ${action} ${targetId} ${ref}${action === 'grant' ? ' --to <target-id>' : action === 'promote' ? ' --name <name> --auth-kind <kind>' : ''}`
