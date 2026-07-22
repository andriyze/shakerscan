export interface AuthzReplayReview {
  available: boolean
  method?: string | null
  path?: string | null
  proofState?: string | null
  observationCount: number
  violationCount: number
  mismatchCount: number
  authenticatedPrincipalCount: number
  accessGrantedCount: number
  softDenialCount: number
  redirectDenialCount: number
  differentialObserved: boolean
  promotedFindingIds: string[]
}

export interface AuthzExecutionFeedbackInput {
  dispatched?: boolean
  dry_run?: boolean
  execution_enabled?: boolean
  execution_blocked_reason?: string | null
  action_state?: Record<string, unknown> | null
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {}
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : []
}

function numberValue(value: unknown): number {
  const parsed = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(parsed) ? parsed : 0
}

function stringValue(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null
}

export function buildAuthzReplayReview(resultJson: unknown): AuthzReplayReview {
  const result = asRecord(resultJson)
  const plan = asRecord(result.authz_replay_plan)
  const replay = asRecord(result.authz_replay)
  const replayPlan = Object.keys(replay).length ? asRecord(replay.plan) : plan
  const proof = asRecord(replay.proof_bundle)
  const promotion = asRecord(result.authz_replay_promotion)
  const findingIds = asArray(promotion.finding_ids)
    .map((item) => stringValue(item))
    .filter((item): item is string => Boolean(item))
  const observations = asArray(replay.observations)

  return {
    available: Object.keys(plan).length > 0 || Object.keys(replay).length > 0,
    method: stringValue(replayPlan.method),
    path: stringValue(replayPlan.path),
    proofState: stringValue(replay.proof_state),
    observationCount: observations.length,
    violationCount: numberValue(replay.violation_count),
    mismatchCount: numberValue(replay.mismatch_count),
    authenticatedPrincipalCount: numberValue(proof.authenticated_principal_count),
    accessGrantedCount: numberValue(proof.access_granted_count),
    softDenialCount: numberValue(proof.soft_200_denial_count),
    redirectDenialCount: numberValue(proof.denial_redirect_count),
    differentialObserved: proof.differential_observed === true,
    promotedFindingIds: findingIds,
  }
}

export function sessionMatchesTarget(sessionTarget: string, actionTarget?: string | null): boolean {
  if (!sessionTarget || !actionTarget) return false
  try {
    return new URL(sessionTarget).origin === new URL(actionTarget).origin
  } catch {
    return sessionTarget.replace(/\/$/, '') === actionTarget.replace(/\/$/, '')
  }
}

export function authzExecutionFeedback(
  response: AuthzExecutionFeedbackInput,
  successMessage: string
): { blocked: boolean; message: string } {
  const state = asRecord(response.action_state)
  const reason = stringValue(response.execution_blocked_reason)
    || stringValue(state.blocked_reason)
    || stringValue(state.phase)
  const blocked = Boolean(
    reason
    || response.execution_enabled === false
    || response.dispatched === false
    || response.dry_run === true
  )
  return blocked
    ? { blocked: true, message: `Execution blocked: ${reason || 'request was not dispatched'}` }
    : { blocked: false, message: successMessage }
}
