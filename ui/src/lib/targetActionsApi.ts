import {API_URL, getApiErrorMessage} from './apiConfig'

export interface TargetActionStep {capability:string; input:Record<string,unknown>; description?:string}
export interface TargetAction {id:string;target_id:string;name:string;instructions:string;steps:TargetActionStep[];parameters:Record<string,{type:'string'|'integer'|'boolean';description?:string;default?:unknown}>;revision:number;body_sha256:string;updated_at:string;written_by:string}
export interface TargetActions {target_id:string;revision:number;actions:TargetAction[];max_actions:number;authority_granted:false}
async function request(id:string, suffix='', init?:RequestInit):Promise<TargetActions> {
  const response = await fetch(`${API_URL}/targets/${encodeURIComponent(id)}/actions${suffix}`, {cache:'no-store',...init})
  if (!response.ok) throw new Error(await getApiErrorMessage(response,'Could not update saved actions'))
  const value = await response.json()
  if (!Array.isArray(value.actions) || !Number.isInteger(value.revision)) throw new Error('Saved action response was incomplete. Reload before editing.')
  return value
}
export const getTargetActions = (id:string,signal?:AbortSignal) => request(id,'',{signal})
export const saveTargetAction = (id:string, revision:number, action:Pick<TargetAction,'name'|'instructions'|'steps'|'parameters'>, actionId?:string) =>
  request(id,actionId ? '/'+encodeURIComponent(actionId) : '', {method:actionId ? 'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({...action,expected_revision:revision})})
export const deleteTargetAction = (id:string, revision:number, actionId:string) =>
  request(id,'/'+encodeURIComponent(actionId)+'?expected_revision='+revision,{method:'DELETE'})
