import { pathSegment, queryString } from './apiPath.mjs'
import {API_URL, getApiErrorMessage} from './apiConfig'

export interface TargetActionStep {capability:string; input:Record<string,unknown>; description?:string}
export interface TargetAction {id:string;target_id:string;name:string;instructions:string;steps:TargetActionStep[];parameters:Record<string,{type:'string'|'integer'|'boolean';description?:string;default?:unknown}>;revision:number;body_sha256:string;updated_at:string;written_by:string;trust?:'operator'|'operator_delegated'|'agent_unconfirmed'}
export interface TargetActions {target_id:string;revision:number;actions:TargetAction[];max_actions:number;authority_granted:false}
async function request(id:string, actionId='', init?:RequestInit, query=new URLSearchParams()):Promise<TargetActions> {
  const response = actionId
    ? await fetch(`${API_URL}/targets/${pathSegment(id)}/actions/${pathSegment(actionId)}${queryString(query)}`, {cache:'no-store',...init})
    : await fetch(`${API_URL}/targets/${pathSegment(id)}/actions${queryString(query)}`, {cache:'no-store',...init})
  if (!response.ok) throw new Error(await getApiErrorMessage(response,'Could not update saved actions'))
  const value = await response.json()
  if (!Array.isArray(value.actions) || !Number.isInteger(value.revision)) throw new Error('Saved action response was incomplete. Reload before editing.')
  return value
}
export const getTargetActions = (id:string,signal?:AbortSignal) => request(id,'',{signal})
export const saveTargetAction = (id:string, revision:number, action:Pick<TargetAction,'name'|'instructions'|'steps'|'parameters'>, actionId?:string) =>
  request(id,actionId || '', {method:actionId ? 'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({...action,expected_revision:revision})})
export const deleteTargetAction = (id:string, revision:number, actionId:string) =>
  request(id,actionId,{method:'DELETE'},new URLSearchParams({expected_revision:String(revision)}))
