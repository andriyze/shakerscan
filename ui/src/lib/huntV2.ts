import type { DeviceAgentShellPlan } from './api'
import { API_URL, getApiErrorMessage } from './apiConfig'
import {
  HUNT_START_CONTRACT,
  type HuntBudgetProfile,
  type HuntTargetKind,
} from './huntContract.generated'
import type { StartHuntHuntsPostRequest } from './publicApi.generated'

export type { HuntBudgetProfile, HuntTargetKind } from './huntContract.generated'

export interface HuntActionV2 {
  action_id: string
  capability_name: string
  status: 'reserved' | 'running' | 'completed' | 'blocked' | 'cancelled' | 'failed' | 'partial'
  input_digest?: string | null
  idempotency_key_sha256?: string | null
  receipt_id?: string | null
  started_at?: string | null
  completed_at?: string | null
  result: {
    ok: boolean
    partial: boolean
    timed_out: boolean
    observation_count: number
    budget_consumed: Record<string, number>
    reference_ids: {
      scan_ids: string[]
      finding_ids: string[]
      candidate_ids: string[]
      evidence_ids: string[]
    }
  }
}

export interface HuntV2 {
  hunt_id: string
  target_kind: 'web' | 'api' | 'device' | 'network'
  target_id: string
  objective: string
  status: 'created' | 'active' | 'awaiting_planner' | 'completed' | 'cancelled' | 'failed' | 'budget_exhausted'
  budget_profile: 'fast' | 'balanced' | 'thorough'
  policy: Record<string, unknown>
  budget: Record<string, number>
  budget_used: Record<string, number>
  context_pack?: Record<string, unknown>
  capabilities?: Array<{
    name: string
    description: string
    risk_tier: string
    input_schema: Record<string, unknown>
    budget_cost: Record<string, number>
  }>
  actions?: HuntActionV2[]
  final_debrief?: { summary?: string; next_actions?: string[] }
  stop_reason?: string | null
  queued_scan?: { scan_id: string; job_id?: string; status: string; ui_url?: string }
  created_at?: string
  updated_at?: string
}

export interface HuntStartV2Request {
  targetId: string
  targetKind: HuntTargetKind
  goal: string
  budgetProfile: HuntBudgetProfile
  budgets?: Record<string, number>
  policy: {
    activeTesting: boolean
    allowStateChangingHttp: boolean
    networkDiscovery: boolean
    allowOobInteractions: boolean
    authorizationConfirmed: boolean
    approvalReceiptId?: string
    scopeReceiptId?: string
  }
  credentialRefs?: Record<string, string>
  capabilities?: string[]
  requestCollectionIds?: string[]
}

export async function startHuntV2Native(request: HuntStartV2Request): Promise<HuntV2> {
  const payload: StartHuntHuntsPostRequest = {
    schema_version: HUNT_START_CONTRACT.schema_version,
    target_id: request.targetId,
    target_kind: request.targetKind,
    goal: request.goal,
    budget_profile: request.budgetProfile,
    budgets: request.budgets || {},
    policy: {
      active_testing: request.policy.activeTesting,
      allow_state_changing_http: request.policy.allowStateChangingHttp,
      network_discovery: request.policy.networkDiscovery,
      allow_oob_interactions: request.policy.allowOobInteractions,
      authorization_confirmed: request.policy.authorizationConfirmed,
      approval_receipt_id: request.policy.approvalReceiptId || undefined,
      scope_receipt_id: request.policy.scopeReceiptId || undefined,
    },
    credential_refs: request.credentialRefs || {},
    capabilities: request.capabilities || [],
    request_collection_ids: request.requestCollectionIds || [],
  }
  const response = await fetch(`${API_URL}/hunts`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, `Hunt start failed (${response.status})`))
  const contract = response.headers.get('x-shakerscan-hunt-contract')
  if (contract !== 'v2') {
    throw new Error(`Server did not admit the Hunt through the V2 contract (${contract || 'missing'})`)
  }
  return response.json()
}

export async function getHuntV2(huntId: string): Promise<HuntV2> {
  const response = await fetch(`${API_URL}/hunts/${encodeURIComponent(huntId)}`)
  if (!response.ok) throw new Error(await getApiErrorMessage(response, `Failed to load Hunt (${response.status})`))
  return response.json()
}

export async function listHuntsV2(params: {
  targetId?: string
  status?: HuntV2['status']
  limit?: number
} = {}): Promise<{ hunts: HuntV2[]; count: number }> {
  const search = new URLSearchParams()
  if (params.targetId) search.set('target_id', params.targetId)
  if (params.status) search.set('status', params.status)
  if (params.limit) search.set('limit', String(params.limit))
  const suffix = search.size ? `?${search.toString()}` : ''
  const response = await fetch(`${API_URL}/hunts${suffix}`, { cache: 'no-store' })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, `Failed to list Hunts (${response.status})`))
  return response.json()
}

export async function cancelHuntV2(huntId: string): Promise<HuntV2> {
  const response = await fetch(`${API_URL}/hunts/${encodeURIComponent(huntId)}/cancel`, { method: 'POST' })
  if (!response.ok) throw new Error(await getApiErrorMessage(response, `Failed to cancel Hunt (${response.status})`))
  return response.json()
}

export async function confirmHuntShellPlan(huntId: string, plan: DeviceAgentShellPlan): Promise<HuntV2> {
  const response = await fetch(
    `${API_URL}/hunts/${encodeURIComponent(huntId)}/shell-plans/${encodeURIComponent(plan.plan_id)}/confirm`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        plan_digest: plan.plan_digest,
        confirmation_phrase: plan.confirmation_phrase,
        confirm_exact_commands: true,
        confirm_remote_device_effects: true,
      }),
    },
  )
  if (!response.ok) {
    throw new Error(await getApiErrorMessage(response, `Failed to confirm Hunt SSH shell plan (${response.status})`))
  }
  return response.json()
}
