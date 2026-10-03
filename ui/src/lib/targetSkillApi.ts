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
}
export interface TargetSkillState {
  target_id: string
  revision: number
  skill: TargetSkill | null
  max_characters: number
}
export interface TargetSkillSnapshot extends TargetSkillState {
  loaded_at_start: boolean
  editing_affects: 'future_hunts'
}

async function request(id: string, init?: RequestInit, query = ''): Promise<TargetSkillState> {
  const response = await fetch(`${API_URL}/targets/${encodeURIComponent(id)}/skill${query}`, {cache:'no-store', ...init})
  if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Could not update target instructions'))
  const value: TargetSkillState = await response.json()
  if (!Number.isSafeInteger(value.revision) || value.revision < 0 || !Number.isSafeInteger(value.max_characters) || value.max_characters <= 0 || (value.skill !== null && typeof value.skill?.methodology !== 'string')) {
    throw new Error('The server returned an invalid target instructions record. Reload and try again.')
  }
  return value
}
export const getTargetSkill = (id: string, signal?: AbortSignal) => request(id, {signal})
export const saveTargetSkill = (id: string, state: TargetSkillState, title: string, methodology: string) => request(id, {
  method: state.skill ? 'PUT' : 'POST', headers: {'Content-Type':'application/json'},
  body: JSON.stringify({title,methodology,expected_revision:state.revision}),
})
export const deleteTargetSkill = (id: string, revision: number) => request(id, {method:'DELETE'}, `?expected_revision=${revision}`)
