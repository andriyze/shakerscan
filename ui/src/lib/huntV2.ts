import { API_URL, type HuntV2 } from './api'
import {
  HUNT_START_CONTRACT,
  type HuntBudgetProfile,
  type HuntTargetKind,
} from './huntContract.generated'
import type { StartHuntHuntsPostRequest } from './publicApi.generated'

export type { HuntBudgetProfile, HuntTargetKind } from './huntContract.generated'

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

async function apiError(response: Response): Promise<string> {
  try {
    const data = await response.json()
    const detail = data?.detail
    if (typeof detail === 'string') return detail
    if (detail && typeof detail === 'object') {
      if (typeof detail.message === 'string') return detail.message
      if (typeof detail.error === 'string') return detail.error
    }
  } catch {
    // Use the stable fallback below when an intermediary did not return JSON.
  }
  return `Hunt start failed (${response.status})`
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
  if (!response.ok) throw new Error(await apiError(response))
  const contract = response.headers.get('x-shakerscan-hunt-contract')
  if (contract !== 'v2') {
    throw new Error(`Server did not admit the Hunt through the V2 contract (${contract || 'missing'})`)
  }
  return response.json()
}
