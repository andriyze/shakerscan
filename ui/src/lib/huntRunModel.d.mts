export type RunTab = 'results' | 'requests' | 'timeline' | 'details' | 'ssh'
export const RUN_TABS: RunTab[]
export function huntIsLive(hunt: { status?: string; completed_at?: string | null } | null | undefined): boolean
export function defaultRunTab(hunt: { status?: string; completed_at?: string | null } | null | undefined, hash?: string): RunTab
export interface BudgetUsageRow { name: string; label: string; used: number; limit: number; ratio: number }
export function budgetUsage(
  hunt: { budget?: Record<string, number | undefined>; budget_used?: Record<string, number | undefined>; created_at?: string; completed_at?: string | null } | null | undefined,
  labels?: Record<string, string>,
  nowMs?: number,
): { rows: BudgetUsageRow[]; disabled: string[] }
export type PendingDecision =
  | { kind: 'ssh_plan'; id: string }
  | { kind: 'budget'; id: 'budget'; reason: string }
  | { kind: 'permission'; id: string; title: string; command: string }
export interface PendingPermissionRequest { id?: string; kind?: string; title?: string; approve_command?: string }
export function pendingDecisions(
  hunt: {
    status?: string; stop_reason?: string | null; completed_at?: string | null
    pending_permission_requests?: PendingPermissionRequest[] | null
  } | null | undefined,
  shellPlans?: Array<{ plan_id: string; status?: string }>,
): PendingDecision[]
export function requestsByAction<T extends { hunt_action_id?: string | null }>(rows: T[] | null | undefined): { byAction: Map<string, T[]>; unlinked: T[] }
export function agentHandoff(hunt: { hunt_id?: string } | null | undefined): { command: string; prompt: string }
export interface ActionOutcome { input: Record<string, unknown> | null; errors: string[] }
export function actionOutcomes(record: { decision_trace?: unknown[] } | null | undefined): Map<string, ActionOutcome>
export function callArguments(input: Record<string, unknown> | null | undefined, maxValue?: number): Array<{ key: string; value: string; full: string }>
export function exhaustedDimension(hunt: { stop_reason?: string | null; budget?: Record<string, number | undefined> } | null | undefined): string | null
export function huntStopReasonText(reason: string | null | undefined): string
export function huntStopReasonLabel(reason: string | null | undefined): string
