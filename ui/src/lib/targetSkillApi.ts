import { API_URL, getApiErrorMessage } from './apiConfig'

export interface TargetSkill {
  schema_version: 'hunt-skill/v2'
  skill_id: string
  target_id: string
  title: string
  methodology: string
  version: string
  body_sha256: string
  updated_at: string
  written_by?: string | null
  purpose?: 'instructions' | 'knowledge'
  instruction_authority?: 'operator' | 'target_metadata_delegation' | 'none'
  delegation_revision?: number | null
}
export interface TargetSkillState {
  target_id: string
  revision: number
  skill: TargetSkill | null
  max_characters: number
  operator_skill?: TargetSkill | null
  knowledge?: TargetSkill | null
  trust?: 'none' | 'operator' | 'operator_delegated' | 'hunt_advisory' | 'unknown_advisory'
}
export interface TargetSkillSnapshot extends TargetSkillState {
  loaded_at_start: boolean
  editing_affects: 'future_hunts'
  advisory?: {title?:string;methodology?:string;written_by?:string|null;source_hunt_id?:string|null;revision:string;body_included:boolean;authority_granted:false} | null
}

async function request(id: string, init?: RequestInit, query = ''): Promise<TargetSkillState> {
  const response = await fetch(`${API_URL}/targets/${encodeURIComponent(id)}/skill${query}`, {cache:'no-store', ...init})
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Could not update target instructions'))
  const value: TargetSkillState = await response.json()
  if (!Number.isSafeInteger(value.revision) || value.revision < 0 || !Number.isSafeInteger(value.max_characters) || value.max_characters <= 0 || (value.skill !== null && typeof value.skill?.methodology !== 'string') || (value.operator_skill != null && typeof value.operator_skill.methodology !== 'string') || (value.knowledge != null && typeof value.knowledge.methodology !== 'string') || (value.trust !== undefined && !['none', 'operator', 'operator_delegated', 'hunt_advisory', 'unknown_advisory'].includes(value.trust))) {
    throw new Error('The server returned an invalid target instructions record. Reload and try again.')
  }
  return value
}
export const getTargetSkill = (id: string, signal?: AbortSignal) => request(id, {signal})
export const saveTargetSkill = (id: string, state: TargetSkillState, title: string, methodology: string, purpose:'instructions'|'knowledge'='instructions') => request(id, {
  method: (purpose==='knowledge' ? state.knowledge : state.operator_skill ?? (['operator','operator_delegated'].includes(state.trust || '') ? state.skill : null)) ? 'PUT' : 'POST', headers: {'Content-Type':'application/json'},
  body: JSON.stringify({title,methodology,expected_revision:state.revision,purpose}),
})
export const deleteTargetSkill = (id: string, revision: number, purpose:'instructions'|'knowledge'='instructions') => request(id, {method:'DELETE'}, `?expected_revision=${revision}&purpose=${purpose}`)
