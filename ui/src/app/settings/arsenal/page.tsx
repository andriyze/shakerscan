'use client'

import { useEffect, useMemo, useState } from 'react'
import { Boxes, CheckCircle2, RefreshCw, ShieldCheck, TerminalSquare, XCircle } from 'lucide-react'
import {
  createAgentContextPack,
  createAgentDecisionTrace,
  createLocalAgentDryRunPlan,
  createOperationPlan,
  createApprovalReceipt,
  deriveRefuterReviewVerdict,
  executeAuthzReplay,
  executeRefuterReviewPlan,
  generateSourceIngestHypotheses,
  getAgentContextPacks,
  getAgentDecisionTraces,
  getArsenalCommands,
  getArsenalContracts,
  getCampaignActions,
  getCommandResults,
  getHypotheses,
  getHypothesisSituationReport,
  getRefuterWorkSummary,
  getRefuterReviews,
  generateAgentContextPackFromTarget,
  getOperationPlans,
  getArsenalTools,
  getLocalAgents,
  listInteractiveSessions,
  previewScopeReceipt,
  promoteAuthzReplay,
  reconcileHypothesisProof,
  recordRefuterReview,
  queueRefuterReviewsFromSummary,
  testLocalAgentCapability,
  type AgentContextPack,
  type AgentContextPackResponse,
  type AgentDecisionTrace,
  type AgentDecisionTraceResponse,
  type ApprovalReceipt,
  type ArsenalCommand,
  type ArsenalCommandsResponse,
  type ArsenalContractDefinition,
  type ArsenalContractsResponse,
  type CampaignAction,
  type CommandResult,
  type Hypothesis,
  type HypothesisReportItem,
  type HypothesisSituationReport,
  type InteractiveSessionSummary,
  type RefuterWorkSummary,
  type RefuterQueueResult,
  type RefuterReview,
  type OperationPlan,
  type OperationPlanResponse,
  type ArsenalTool,
  type ArsenalToolsResponse,
  type LocalAgentCapability,
  type LocalAgentsResponse,
  type LocalAgentTestResponse,
  type ScopeReceiptPreview,
  type SourceIngestResult,
} from '@/lib/api'
import { authzExecutionFeedback, buildAuthzReplayReview, sessionMatchesTarget } from '@/lib/authzReplay'
import { buildRefuterAnnotationPayload, buildRefuterReviewPlanView, refuterVerdictClass } from '@/lib/refuterReview'
import { Badge, Button, Card, EmptyState, ErrorState, Skeleton } from '@/components/ui'

function statusClass(status: string): string {
  switch (status) {
    case 'runnable':
    case 'read_only':
    case 'proof_backed':
    case 'available':
      return 'bg-green-500/15 text-green-300'
    case 'gated':
    case 'installed':
    case 'dry_run':
      return 'bg-blue-500/15 text-blue-300'
    case 'wired':
    case 'experimental':
      return 'bg-amber-500/15 text-amber-300'
    case 'catalog_only':
    case 'waived':
    case 'missing':
      return 'bg-gray-800 text-gray-300'
    case 'disabled':
    case 'out_of_scope':
      return 'bg-red-500/15 text-red-300'
    default:
      return 'bg-gray-800 text-gray-300'
  }
}

function riskClass(risk: string): string {
  switch (risk) {
    case 'read_only':
      return 'bg-green-500/15 text-green-300'
    case 'passive':
      return 'bg-cyan-500/15 text-cyan-300'
    case 'active':
      return 'bg-blue-500/15 text-blue-300'
    case 'credential':
    case 'intrusive':
      return 'bg-amber-500/15 text-amber-300'
    case 'dangerous':
      return 'bg-red-500/15 text-red-300'
    default:
      return 'bg-gray-800 text-gray-300'
  }
}

function countBy<T extends { status: string }>(items: T[]): Record<string, number> {
  return items.reduce<Record<string, number>>((acc, item) => {
    acc[item.status] = (acc[item.status] || 0) + 1
    return acc
  }, {})
}

function splitReferenceIds(value: string): string[] {
  return [...new Set(value.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean))].slice(0, 100)
}

function Stat({
  label,
  value,
  tone = 'text-white',
}: {
  label: string
  value: string | number
  tone?: string
}) {
  return (
    <div className="rounded-md border border-gray-800 bg-gray-950 p-3">
      <div className={`text-lg font-semibold ${tone}`}>{value}</div>
      <div className="mt-1 text-xs text-gray-500">{label}</div>
    </div>
  )
}

function CommandRow({ command }: { command: ArsenalCommand }) {
  return (
    <div className="rounded-md border border-gray-800 bg-gray-950 p-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="break-all font-mono text-sm text-white">{command.name}</span>
            <Badge className={statusClass(command.status)}>{command.status}</Badge>
            <Badge className={riskClass(command.risk_tier)}>{command.risk_tier}</Badge>
          </div>
          <p className="mt-2 text-sm text-gray-400">{command.description}</p>
        </div>
        <div className="max-w-full break-all rounded bg-gray-900 px-2 py-1 font-mono text-xs text-gray-300 sm:shrink-0">
          {command.method} {command.path}
        </div>
      </div>
      <div className="mt-3 flex flex-wrap gap-2 break-words text-xs text-gray-500">
        {command.scope_fields.length > 0 && <span>scope: {command.scope_fields.join(', ')}</span>}
        {command.required_confirmations.length > 0 && <span>confirm: {command.required_confirmations.join(', ')}</span>}
        {command.evidence_contract.length > 0 && <span>evidence: {command.evidence_contract.slice(0, 3).join(', ')}</span>}
      </div>
    </div>
  )
}

function CommandResultRow({ result }: { result: CommandResult }) {
  return (
    <div className="rounded-md border border-gray-800 bg-gray-950 px-3 py-2">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="break-all font-mono text-sm text-white">{result.command}</span>
            <Badge className={statusClass(result.status)}>{result.status}</Badge>
            <Badge className={riskClass(result.risk_tier)}>{result.risk_tier}</Badge>
            {result.dry_run && <Badge className={statusClass('dry_run')}>dry run</Badge>}
          </div>
          <p className="mt-1 break-words text-sm text-gray-400">{result.operator_message}</p>
        </div>
        {result.next_action ? (
          <a
            href={result.next_action}
            className="rounded-md border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:border-blue-400 hover:text-white"
          >
            Open
          </a>
        ) : null}
      </div>
      <div className="mt-2 grid gap-2 text-xs text-gray-500 md:grid-cols-2">
        <div>operation: <span className="break-all font-mono text-gray-300">{result.id}</span></div>
        <div>scan: <span className="break-all font-mono text-gray-300">{result.scan_id || 'none'}</span></div>
        <div>scope receipt: <span className="break-all font-mono text-gray-300">{result.scope_receipt_id || 'none'}</span></div>
        <div>approval receipt: <span className="break-all font-mono text-gray-300">{result.approval_receipt_id || 'none'}</span></div>
      </div>
      {(result.finding_ids.length > 0 || result.blocked_by.length > 0) && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {result.finding_ids.slice(0, 4).map((id) => (
            <Badge key={id} className="bg-gray-800 text-gray-300">finding {id.slice(0, 8)}</Badge>
          ))}
          {result.finding_ids.length > 4 && <Badge className="bg-gray-800 text-gray-300">+{result.finding_ids.length - 4}</Badge>}
          {result.blocked_by.map((reason) => (
            <Badge key={reason} className={statusClass('out_of_scope')}>{reason}</Badge>
          ))}
        </div>
      )}
    </div>
  )
}

function CampaignActionRow({
  action,
  sessions,
  approvalReceiptId,
  operator,
  onRefresh,
}: {
  action: CampaignAction
  sessions: InteractiveSessionSummary[]
  approvalReceiptId?: string
  operator: string
  onRefresh: () => Promise<void>
}) {
  const status = action.live_scan_status || action.status
  const review = useMemo(() => buildAuthzReplayReview(action.result_json), [action.result_json])
  const matchingSessions = useMemo(
    () => sessions.filter((session) => !session.is_expired && sessionMatchesTarget(session.target_url, action.target_url)),
    [sessions, action.target_url]
  )
  const availableSessions = matchingSessions.length > 0
    ? [...matchingSessions, ...sessions.filter((session) => !session.is_expired && !matchingSessions.includes(session))]
    : sessions.filter((session) => !session.is_expired)
  const [sessionId, setSessionId] = useState('')
  const [executing, setExecuting] = useState<'replay' | 'promote' | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [actionMessage, setActionMessage] = useState<string | null>(null)

  useEffect(() => {
    if (!sessionId && availableSessions.length > 0) {
      setSessionId(availableSessions[0].session_id)
    }
  }, [availableSessions, sessionId])

  async function runReplay() {
    if (!sessionId || !approvalReceiptId) return
    setExecuting('replay')
    setActionError(null)
    setActionMessage(null)
    try {
      const response = await executeAuthzReplay(action.id, {
        session_id: sessionId,
        execute: true,
        confirmations: ['confirm_authorized'],
        approval_receipt_id: approvalReceiptId,
        created_by: operator || 'operator',
      })
      const feedback = authzExecutionFeedback(response, 'Authorization replay completed')
      if (feedback.blocked) setActionError(feedback.message)
      else setActionMessage(feedback.message)
      await onRefresh()
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Authorization replay failed')
    } finally {
      setExecuting(null)
    }
  }

  async function promoteReplay() {
    if (!approvalReceiptId) return
    setExecuting('promote')
    setActionError(null)
    setActionMessage(null)
    try {
      const response = await promoteAuthzReplay(action.id, {
        execute: true,
        confirmations: ['confirm_authorized'],
        approval_receipt_id: approvalReceiptId,
        created_by: operator || 'operator',
      })
      const feedback = authzExecutionFeedback(response, 'Authorization replay promoted')
      if (feedback.blocked) setActionError(feedback.message)
      else setActionMessage(feedback.message)
      await onRefresh()
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Authorization replay promotion failed')
    } finally {
      setExecuting(null)
    }
  }

  return (
    <div className="rounded-md border border-gray-800 bg-gray-950 px-3 py-2">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="break-all font-mono text-sm text-white">{action.action_name || action.command}</span>
            <Badge className={statusClass(status)}>{status}</Badge>
            <Badge className={riskClass(action.risk_tier)}>{action.risk_tier}</Badge>
            {action.dry_run && <Badge className={statusClass('dry_run')}>dry run</Badge>}
          </div>
          <p className="mt-1 break-words text-sm text-gray-400">
            {action.operator_message || 'Recorded campaign action'}
          </p>
        </div>
        {action.next_action ? (
          <a
            href={action.next_action}
            className="rounded-md border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:border-blue-400 hover:text-white"
          >
            Open
          </a>
        ) : null}
      </div>
      <div className="mt-2 grid gap-2 text-xs text-gray-500 md:grid-cols-2">
        <div>action: <span className="break-all font-mono text-gray-300">{action.id}</span></div>
        <div>command result: <span className="break-all font-mono text-gray-300">{action.command_result_id || 'standalone'}</span></div>
        <div>campaign: <span className="break-all font-mono text-gray-300">{action.campaign_id || 'none'}</span></div>
        <div>scan: <span className="break-all font-mono text-gray-300">{action.scan_id || 'none'}</span></div>
        <div>scope receipt: <span className="break-all font-mono text-gray-300">{action.scope_receipt_id || 'none'}</span></div>
        <div>approval receipt: <span className="break-all font-mono text-gray-300">{action.approval_receipt_id || 'none'}</span></div>
      </div>
      {(action.hypothesis_ids.length > 0 || action.evidence_object_ids.length > 0 || action.blocked_by.length > 0) && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {action.hypothesis_ids.slice(0, 3).map((id) => (
            <Badge key={id} className="bg-gray-800 text-gray-300">hypothesis {id.slice(0, 8)}</Badge>
          ))}
          {action.evidence_object_ids.slice(0, 3).map((id) => (
            <Badge key={id} className="bg-gray-800 text-gray-300">evidence {id.slice(0, 8)}</Badge>
          ))}
          {action.blocked_by.map((reason) => (
            <Badge key={reason} className={statusClass('out_of_scope')}>{reason}</Badge>
          ))}
        </div>
      )}
      {review.available && (
        <div className="mt-3 border-t border-gray-800 pt-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <Badge className="bg-cyan-500/15 text-cyan-300">authz replay</Badge>
              <span className="break-all font-mono text-xs text-gray-300">
                {review.method || 'GET'} {review.path || 'planned endpoint'}
              </span>
            </div>
            {review.proofState && <Badge className={review.violationCount > 0 ? statusClass('wired') : statusClass('read_only')}>{review.proofState}</Badge>}
          </div>
          {review.observationCount > 0 && (
            <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Stat label="observations" value={review.observationCount} />
              <Stat label="principals" value={review.authenticatedPrincipalCount} />
              <Stat label="mismatches" value={review.mismatchCount} tone={review.mismatchCount > 0 ? 'text-amber-300' : 'text-white'} />
              <Stat label="violations" value={review.violationCount} tone={review.violationCount > 0 ? 'text-red-300' : 'text-white'} />
            </div>
          )}
          <div className="mt-3 flex flex-wrap items-end gap-2">
            <label className="min-w-64 flex-1">
              <span className="text-xs text-gray-400">Interactive session</span>
              <select
                value={sessionId}
                onChange={(event) => setSessionId(event.target.value)}
                className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
              >
                {availableSessions.length === 0 && <option value="">No active sessions</option>}
                {availableSessions.map((session) => (
                  <option key={session.session_id} value={session.session_id}>
                    {session.target_url}{matchingSessions.includes(session) ? '' : ' (different origin)'}
                  </option>
                ))}
              </select>
            </label>
            <a
              href="/interactive"
              className="rounded-md border border-gray-700 px-3 py-2 text-xs font-medium text-gray-300 hover:border-blue-400 hover:text-white"
            >
              Sessions
            </a>
            <Button
              size="sm"
              variant="secondary"
              onClick={() => void runReplay()}
              disabled={!sessionId || !approvalReceiptId || executing !== null}
            >
              <RefreshCw className={`h-3.5 w-3.5 ${executing === 'replay' ? 'animate-spin' : ''}`} aria-hidden="true" />
              Run replay
            </Button>
            {review.violationCount > 0 && review.differentialObserved && review.promotedFindingIds.length === 0 && (
              <Button
                size="sm"
                variant="danger"
                onClick={() => void promoteReplay()}
                disabled={!approvalReceiptId || executing !== null}
              >
                <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
                Promote finding
              </Button>
            )}
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {!approvalReceiptId && <Badge className={statusClass('out_of_scope')}>approval receipt required</Badge>}
            {review.accessGrantedCount > 0 && <Badge className={statusClass('wired')}>access granted {review.accessGrantedCount}</Badge>}
            {review.softDenialCount > 0 && <Badge className="bg-gray-800 text-gray-300">soft denials {review.softDenialCount}</Badge>}
            {review.redirectDenialCount > 0 && <Badge className="bg-gray-800 text-gray-300">redirect denials {review.redirectDenialCount}</Badge>}
            {review.promotedFindingIds.map((id) => (
              <a key={id} href={`/findings/${id}`}>
                <Badge className={statusClass('proof_backed')}>finding {id.slice(0, 8)}</Badge>
              </a>
            ))}
          </div>
          {actionError && <p role="alert" className="mt-2 text-sm text-red-300">{actionError}</p>}
          {actionMessage && <p role="status" className="mt-2 text-sm text-green-300">{actionMessage}</p>}
        </div>
      )}
    </div>
  )
}

function HypothesisRow({ hypothesis, approvalReceiptId, operator, onRefresh }: {
  hypothesis: Hypothesis
  approvalReceiptId?: string
  operator?: string
  onRefresh?: () => Promise<void> | void
}) {
  const claimOwner = hypothesis.claim_state?.owner || hypothesis.claim_owner
  const displayStatus = hypothesis.effective_status || hypothesis.status
  const promotedFindingIds = hypothesis.promoted_finding_ids || []
  const [reconciling, setReconciling] = useState(false)
  const [reconcileError, setReconcileError] = useState<string | null>(null)
  const [reconcileMessage, setReconcileMessage] = useState<string | null>(null)

  async function reconcileProof() {
    if (!approvalReceiptId || !hypothesis.campaign_action_id) return
    if (!window.confirm('Reconcile this hypothesis against deterministic proof from its linked campaign action?')) return
    setReconciling(true)
    setReconcileError(null)
    setReconcileMessage(null)
    try {
      const result = await reconcileHypothesisProof(hypothesis.id, {
        expected_version: hypothesis.version,
        campaign_action_id: hypothesis.campaign_action_id,
        approval_receipt_id: approvalReceiptId,
        created_by: operator || 'settings-arsenal',
      })
      setReconcileMessage(
        result.promoted
          ? `Promoted from ${(result.hypothesis.promoted_finding_ids || []).length} deterministic finding(s).`
          : 'No exact deterministic proof was eligible; the hypothesis remains open.'
      )
      await onRefresh?.()
    } catch (err) {
      setReconcileError(err instanceof Error ? err.message : 'Failed to reconcile hypothesis proof')
    } finally {
      setReconciling(false)
    }
  }

  return (
    <div className="rounded-md border border-gray-800 bg-gray-950 px-3 py-2">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="break-all font-mono text-sm text-white">{hypothesis.family}</span>
            <Badge className={statusClass(displayStatus)}>{displayStatus}</Badge>
            {hypothesis.severity_guess && <Badge className={riskClass(hypothesis.severity_guess)}>{hypothesis.severity_guess}</Badge>}
            <Badge className="bg-gray-800 text-gray-300">{hypothesis.source}</Badge>
            {hypothesis.claim_state?.expired && <Badge className="bg-amber-500/15 text-amber-300">claim expired</Badge>}
          </div>
          <p className="mt-1 break-words text-sm text-gray-400">
            {hypothesis.title || hypothesis.description || hypothesis.dedupe_key}
          </p>
        </div>
        <div className="text-right text-xs text-gray-500">
          <div className="font-mono text-gray-300">{Math.round((hypothesis.confidence || 0) * 100)}%</div>
          <div>confidence</div>
        </div>
      </div>
      <div className="mt-2 grid gap-2 text-xs text-gray-500 md:grid-cols-2">
        <div>hypothesis: <span className="break-all font-mono text-gray-300">{hypothesis.id}</span></div>
        <div>version: <span className="font-mono text-gray-300">{hypothesis.version}</span></div>
        <div>campaign: <span className="break-all font-mono text-gray-300">{hypothesis.campaign_id || 'none'}</span></div>
        <div>claim: <span className="break-all font-mono text-gray-300">{claimOwner || 'open'}</span></div>
      </div>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {hypothesis.evidence_object_ids.slice(0, 3).map((id) => (
          <Badge key={id} className="bg-gray-800 text-gray-300">evidence {id.slice(0, 8)}</Badge>
        ))}
        {hypothesis.tool_receipt_ids.slice(0, 3).map((id) => (
          <Badge key={id} className="bg-gray-800 text-gray-300">tool {id.slice(0, 8)}</Badge>
        ))}
        {promotedFindingIds.map((id) => (
          <a key={id} href={`/findings/${id}`}>
            <Badge className={statusClass('proof_backed')}>finding {id.slice(0, 8)}</Badge>
          </a>
        ))}
        {promotedFindingIds.length === 0 && <Badge className="bg-gray-800 text-gray-300">lead only</Badge>}
      </div>
      {hypothesis.can_reconcile_proof && hypothesis.campaign_action_id && (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            variant="secondary"
            disabled={!approvalReceiptId || reconciling}
            onClick={() => void reconcileProof()}
            title={!approvalReceiptId ? 'A target-scoped approval receipt is required' : 'Reconcile deterministic campaign proof'}
          >
            <ShieldCheck className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
            {reconciling ? 'Reconciling...' : 'Reconcile proof'}
          </Button>
          {!approvalReceiptId && <Badge className={statusClass('out_of_scope')}>target approval required</Badge>}
        </div>
      )}
      {reconcileError && <p role="alert" className="mt-2 text-xs text-red-300">{reconcileError}</p>}
      {reconcileMessage && <p role="status" className="mt-2 text-xs text-gray-300">{reconcileMessage}</p>}
    </div>
  )
}

function HypothesisReportRow({ item }: { item: HypothesisReportItem }) {
  const claimOwner = item.claim_state?.owner
  const displayStatus = item.effective_status || item.status
  return (
    <div className="rounded-md border border-gray-800 bg-gray-950 px-3 py-2">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="break-all font-mono text-sm text-white">{item.family}</span>
            <Badge className={statusClass(displayStatus)}>{displayStatus}</Badge>
            {item.severity_guess && <Badge className={riskClass(item.severity_guess)}>{item.severity_guess}</Badge>}
            <Badge className="bg-gray-800 text-gray-300">{item.source}</Badge>
            {claimOwner && <Badge className="bg-blue-500/15 text-blue-300">claim {claimOwner}</Badge>}
            {item.claim_state?.expired && <Badge className="bg-amber-500/15 text-amber-300">expired</Badge>}
          </div>
          <p className="mt-1 break-words text-sm text-gray-400">
            {item.title || item.dedupe_key}
          </p>
        </div>
        <div className="text-right text-xs text-gray-500">
          <div className="font-mono text-gray-300">{Math.round((item.confidence || 0) * 100)}%</div>
          <div>confidence</div>
        </div>
      </div>
      <div className="mt-2 flex flex-wrap gap-1.5 text-xs">
        <Badge className="bg-gray-800 text-gray-300">v{item.version}</Badge>
        <Badge className="bg-gray-800 text-gray-300">endorse {item.endorsement_count}</Badge>
        <Badge className="bg-gray-800 text-gray-300">refute {item.refutation_count}</Badge>
        {item.terminal_reason && <Badge className="bg-red-500/15 text-red-300">{item.terminal_reason}</Badge>}
      </div>
    </div>
  )
}

function SituationBucket({
  title,
  items,
  empty,
}: {
  title: string
  items: HypothesisReportItem[]
  empty: string
}) {
  return (
    <div className="min-w-0">
      <h3 className="mb-2 text-sm font-medium text-gray-200">{title}</h3>
      {items.length === 0 ? (
        <div className="rounded-md border border-gray-800 bg-gray-950 p-3 text-sm text-gray-500">{empty}</div>
      ) : (
        <div className="grid gap-2">
          {items.map((item) => (
            <HypothesisReportRow key={item.id} item={item} />
          ))}
        </div>
      )}
    </div>
  )
}

function HypothesisGraphContextPanel({ context }: { context?: HypothesisSituationReport['graph_context'] }) {
  if (!context || context.summary.hypothesis_target_count === 0) return null
  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-medium text-gray-200">Application Graph Context</h3>
        <div className="flex flex-wrap gap-1.5">
          {context.truncated && <Badge className="bg-amber-500/15 text-amber-300">target list truncated</Badge>}
          {context.summary.missing_graph_target_count > 0 && (
            <Badge className="bg-red-500/15 text-red-300">{context.summary.missing_graph_target_count} missing graph</Badge>
          )}
        </div>
      </div>
      <div className="grid gap-3 md:grid-cols-4">
        <Stat label="graph targets" value={context.summary.target_count} />
        <Stat label="graph nodes" value={context.summary.node_count} />
        <Stat label="graph edges" value={context.summary.edge_count} />
        <Stat label="auth boundaries" value={context.summary.auth_boundary_edge_count} tone="text-amber-300" />
      </div>
      <div className="mt-3 grid gap-2">
        {context.targets.slice(0, 5).map((target) => (
          <div key={target.target_id} className="rounded-md border border-gray-800 bg-gray-950 px-3 py-2">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <a href={`/targets/${target.target_id}/graph`} className="break-all font-mono text-sm text-cyan-300 hover:text-cyan-200">
                {target.target_id}
              </a>
              <div className="flex flex-wrap gap-1.5">
                <Badge className="bg-gray-800 text-gray-300">hypotheses {target.hypothesis_count}</Badge>
                <Badge className="bg-gray-800 text-gray-300">routes {target.route_nodes}</Badge>
                <Badge className="bg-gray-800 text-gray-300">objects {target.object_nodes}</Badge>
                <Badge className="bg-gray-800 text-gray-300">principals {target.principal_nodes}</Badge>
                <Badge className="bg-amber-500/15 text-amber-300">auth {target.auth_boundary_edges}</Badge>
              </div>
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5 text-xs">
              {Object.entries(target.families).slice(0, 4).map(([family, count]) => (
                <Badge key={family} className="bg-violet-500/15 text-violet-300">
                  {family}: {count}
                </Badge>
              ))}
            </div>
            {target.sample_route_keys.length > 0 && (
              <div className="mt-2 truncate font-mono text-xs text-gray-500">
                {target.sample_route_keys.slice(0, 3).join(' | ')}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function RefuterCandidateRow({ candidate }: { candidate: RefuterWorkSummary['candidates'][number] }) {
  return (
    <div className="rounded-md border border-gray-800 bg-gray-950 px-3 py-2">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="break-all font-mono text-sm text-white">{candidate.trigger_type}</span>
            {candidate.severity && <Badge className={riskClass(candidate.severity)}>{candidate.severity}</Badge>}
            {candidate.source && <Badge className="bg-gray-800 text-gray-300">{candidate.source}</Badge>}
            {candidate.already_reviewed && <Badge className="bg-green-500/15 text-green-300">reviewed</Badge>}
          </div>
          <p className="mt-1 break-words text-sm text-gray-400">{candidate.title || candidate.subject_id || 'Refuter candidate'}</p>
        </div>
        <div className="text-right text-xs text-gray-500">
          <div className="font-mono text-gray-300">{candidate.proof_state || 'unknown'}</div>
          <div>proof</div>
        </div>
      </div>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {candidate.trigger_reasons.slice(0, 3).map((reason) => (
          <Badge key={reason} className="bg-amber-500/15 text-amber-300">{reason}</Badge>
        ))}
      </div>
      {candidate.automation_plan && (
        <div className="mt-3 rounded-md border border-gray-800 bg-gray-900/60 p-2">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2 text-xs">
            <span className="font-medium text-gray-200">Automation plan</span>
            <div className="flex flex-wrap gap-1.5">
              <Badge className="bg-gray-800 text-gray-300">{candidate.automation_plan.status}</Badge>
              <Badge className="bg-gray-800 text-gray-300">{candidate.automation_plan.recommended_basis || 'signal_only'}</Badge>
              {!candidate.automation_plan.execution_enabled && <Badge className="bg-blue-500/15 text-blue-300">preview only</Badge>}
            </div>
          </div>
          <div className="grid gap-1.5">
            {candidate.automation_plan.steps.slice(0, 3).map((step) => (
              <div key={step.id} className="flex flex-wrap items-center gap-2 text-xs text-gray-400">
                <span className="rounded bg-gray-800 px-1.5 py-0.5 font-mono text-gray-300">{step.command}</span>
                <span className="text-gray-300">{step.label}</span>
                <span>{step.mode}</span>
              </div>
            ))}
          </div>
          {candidate.automation_plan.minimal_reproducer && (
            <div className="mt-2 text-xs text-gray-500">
              reproducer: {candidate.automation_plan.minimal_reproducer.available ? 'available' : 'missing'} ·
              url {candidate.automation_plan.minimal_reproducer.has_url ? 'yes' : 'no'} ·
              request {candidate.automation_plan.minimal_reproducer.has_request ? 'yes' : 'no'}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function RefuterQueueResultPanel({ result }: { result: RefuterQueueResult }) {
  const [busyId, setBusyId] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function requestGate(review: RefuterReview) {
    setBusyId(`gate:${review.id}`)
    setError(null)
    setMessage(null)
    try {
      const response = await executeRefuterReviewPlan(review.id, {
        execute: false,
        confirmations: [],
        requested_by: 'arsenal_ui',
      })
      const blocked = response.execution_blocked_reason || String(response.action_state?.phase || response.status || 'recorded')
      setMessage(`Execution gate: ${blocked}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to request execution gate')
    } finally {
      setBusyId(null)
    }
  }

  async function deriveVerdict(review: RefuterReview) {
    setBusyId(`derive:${review.id}`)
    setError(null)
    setMessage(null)
    try {
      const response = await deriveRefuterReviewVerdict(review.id, { created_by: 'arsenal_ui' })
      const derived = response.result?.refuter_review as RefuterReview | undefined
      if (response.execution_enabled === false || response.execution_blocked_reason) {
        setMessage(`Derive gate: ${response.execution_blocked_reason || String(response.action_state?.phase || 'approval required')}`)
      } else {
        setMessage(`Derived ${derived?.refuter_verdict || derived?.refuter_signal || response.status || 'review'}`)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to derive verdict')
    } finally {
      setBusyId(null)
    }
  }

  return (
    <div className="rounded-md border border-green-500/20 bg-green-500/5 p-3 text-sm text-green-200">
      <div>Recorded {result.created} signal-only review row{result.created === 1 ? '' : 's'}; findings updated: {result.findings_updated}.</div>
      {result.refuter_reviews.length > 0 && (
        <div className="mt-3 grid gap-2">
          {result.refuter_reviews.slice(0, 5).map((review) => (
            <div key={review.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-green-500/10 bg-black/20 px-2 py-2">
              <div className="min-w-0">
                <div className="truncate font-mono text-xs text-green-100">{review.id}</div>
                <div className="text-xs text-green-300/80">{review.trigger_reason}</div>
              </div>
              <div className="flex flex-wrap gap-1.5">
                <Button type="button" onClick={() => void requestGate(review)} disabled={busyId !== null}>
                  <ShieldCheck className={`h-4 w-4 ${busyId === `gate:${review.id}` ? 'animate-spin' : ''}`} aria-hidden="true" />
                  Gate
                </Button>
                <Button type="button" onClick={() => void deriveVerdict(review)} disabled={busyId !== null}>
                  <CheckCircle2 className={`h-4 w-4 ${busyId === `derive:${review.id}` ? 'animate-spin' : ''}`} aria-hidden="true" />
                  Derive
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
      {message && <div className="mt-2 rounded border border-green-500/20 bg-green-500/10 px-2 py-1 text-xs text-green-100">{message}</div>}
      {error && <div className="mt-2 rounded border border-red-500/20 bg-red-500/10 px-2 py-1 text-xs text-red-200">{error}</div>}
    </div>
  )
}

function RefuterReviewRow({ review, approvalReceiptId, operator, onRefresh }: {
  review: RefuterReview
  approvalReceiptId?: string
  operator: string
  onRefresh: () => Promise<void>
}) {
  const plan = useMemo(() => buildRefuterReviewPlanView(review.metadata_json), [review.metadata_json])
  const [stepId, setStepId] = useState(plan.steps[0]?.id || '')
  const [busy, setBusy] = useState<'execute' | 'derive' | 'record' | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [annotationOpen, setAnnotationOpen] = useState(false)
  const [annotationMode, setAnnotationMode] = useState<'signal' | 'human_verdict'>('signal')
  const [annotationSignal, setAnnotationSignal] = useState<'support' | 'question' | 'weaken' | 'refute'>('question')
  const [annotationVerdict, setAnnotationVerdict] = useState<'supported' | 'weakened' | 'refuted' | 'inconclusive'>('inconclusive')
  const [observedBehavior, setObservedBehavior] = useState('inconclusive')
  const [annotationNotes, setAnnotationNotes] = useState('')
  const [evidenceRefs, setEvidenceRefs] = useState('')
  const [toolReceiptRefs, setToolReceiptRefs] = useState('')

  async function executeStep() {
    if (!approvalReceiptId) return
    setBusy('execute')
    setMessage(null)
    try {
      const response = await executeRefuterReviewPlan(review.id, {
        execute: true, confirmations: ['confirm_authorized'], approval_receipt_id: approvalReceiptId,
        step_id: stepId || undefined, requested_by: operator,
      })
      setMessage(response.execution_blocked_reason || 'Review step dispatched')
      await onRefresh()
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'Review step failed')
    } finally { setBusy(null) }
  }

  async function deriveVerdict() {
    if (!approvalReceiptId) return
    setBusy('derive')
    setMessage(null)
    try {
      const response = await deriveRefuterReviewVerdict(review.id, {
        execute: true, confirmations: ['confirm_authorized'], approval_receipt_id: approvalReceiptId, created_by: operator,
      })
      setMessage(response.execution_blocked_reason || 'Verdict derivation completed')
      await onRefresh()
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'Verdict derivation failed')
    } finally { setBusy(null) }
  }

  async function recordCounterevidence() {
    setBusy('record')
    setMessage(null)
    try {
      const payload = buildRefuterAnnotationPayload(review, {
        mode: annotationMode,
        signal: annotationSignal,
        verdict: annotationVerdict,
        observedBehavior,
        notes: annotationNotes,
        evidenceObjectIds: splitReferenceIds(evidenceRefs),
        toolReceiptIds: splitReferenceIds(toolReceiptRefs),
        createdBy: operator,
      })
      await recordRefuterReview(payload)
      setMessage(annotationMode === 'human_verdict' ? `Recorded human verdict: ${annotationVerdict}` : 'Recorded signal-only counterevidence')
      setAnnotationOpen(false)
      setAnnotationNotes('')
      setEvidenceRefs('')
      setToolReceiptRefs('')
      await onRefresh()
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'Counterevidence recording failed')
    } finally { setBusy(null) }
  }

  return (
    <div className="rounded-md border border-gray-800 bg-gray-950 p-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Badge className="bg-amber-500/15 text-amber-300">{review.refuter_signal}</Badge>
            <Badge className="bg-gray-800 text-gray-300">{review.verdict_basis}</Badge>
            {review.refuter_verdict && <Badge className={refuterVerdictClass(review.refuter_verdict, review.verdict_basis)}>{review.refuter_verdict}</Badge>}
          </div>
          <p className="mt-2 break-words text-sm text-gray-300">{review.trigger_reason}</p>
          <p className="mt-1 break-all font-mono text-xs text-gray-500">{review.id}</p>
        </div>
        {review.finding_id && <a href={`/findings/${review.finding_id}`} className="text-xs text-blue-300 hover:text-blue-200">Finding</a>}
      </div>
      {plan.available && (
        <div className="mt-3 grid gap-3 lg:grid-cols-2">
          <div><div className="text-xs font-medium text-gray-300">Review questions</div><div className="mt-1 grid gap-1">
            {plan.reviewQuestions.map((item) => <p key={item} className="text-xs text-gray-500">{item}</p>)}
          </div></div>
          <div><div className="text-xs font-medium text-gray-300">Benign explanations</div><div className="mt-1 flex flex-wrap gap-1.5">
            {plan.benignExplanations.map((item) => <Badge key={item} className="max-w-full break-words bg-gray-800 text-gray-300">{item}</Badge>)}
          </div></div>
          <div><div className="text-xs font-medium text-gray-300">Required evidence</div><div className="mt-1 flex flex-wrap gap-1.5">
            {plan.requiredEvidenceRefs.map((item) => <Badge key={item} className="bg-blue-500/15 text-blue-300">{item}</Badge>)}
          </div></div>
          <div><div className="text-xs font-medium text-gray-300">Verdict paths</div><div className="mt-1 grid gap-1">
            {plan.verdictPaths.map((item) => <p key={item.verdict} className="text-xs text-gray-500"><span className="text-gray-300">{item.verdict}:</span> {item.description}</p>)}
          </div></div>
        </div>
      )}
      <div className="mt-3 flex flex-wrap items-end gap-2 border-t border-gray-800 pt-3">
        {plan.steps.length > 0 && <label className="min-w-64 flex-1"><span className="text-xs text-gray-400">Review step</span>
          <select value={stepId} onChange={(event) => setStepId(event.target.value)} className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white">
            {plan.steps.map((step) => <option key={step.id} value={step.id}>{step.label} · {step.command}</option>)}
          </select></label>}
        <Button size="sm" variant="secondary" disabled={!approvalReceiptId || busy !== null || plan.steps.length === 0} onClick={() => void executeStep()}>
          <RefreshCw className={`h-3.5 w-3.5 ${busy === 'execute' ? 'animate-spin' : ''}`} aria-hidden="true" /> Execute step
        </Button>
        <Button size="sm" disabled={!approvalReceiptId || busy !== null} onClick={() => void deriveVerdict()}>
          <CheckCircle2 className={`h-3.5 w-3.5 ${busy === 'derive' ? 'animate-spin' : ''}`} aria-hidden="true" /> Derive verdict
        </Button>
        <Button size="sm" variant="ghost" disabled={busy !== null} onClick={() => setAnnotationOpen((open) => !open)}>
          <Boxes className="h-3.5 w-3.5" /> {annotationOpen ? 'Close evidence' : 'Add evidence'}
        </Button>
      </div>
      {annotationOpen && (
        <div className="mt-3 space-y-3 rounded-md border border-gray-800 bg-gray-900/60 p-3">
          <div className="inline-flex rounded-md border border-gray-700 bg-gray-950 p-0.5" role="group" aria-label="Annotation mode">
            <button type="button" onClick={() => setAnnotationMode('signal')} className={`rounded px-3 py-1.5 text-xs ${annotationMode === 'signal' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'}`}>Signal note</button>
            <button type="button" onClick={() => setAnnotationMode('human_verdict')} className={`rounded px-3 py-1.5 text-xs ${annotationMode === 'human_verdict' ? 'bg-amber-600 text-white' : 'text-gray-400 hover:text-white'}`}>Human verdict</button>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            {annotationMode === 'signal' ? (
              <label className="block"><span className="text-xs text-gray-400">Signal</span><select value={annotationSignal} onChange={(event) => setAnnotationSignal(event.target.value as typeof annotationSignal)} className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white">
                <option value="support">support</option><option value="question">question</option><option value="weaken">weaken</option><option value="refute">refute</option>
              </select></label>
            ) : (
              <label className="block"><span className="text-xs text-gray-400">Verdict</span><select value={annotationVerdict} onChange={(event) => setAnnotationVerdict(event.target.value as typeof annotationVerdict)} className="mt-1 w-full rounded-md border border-amber-700 bg-gray-950 px-3 py-2 text-sm text-white">
                <option value="supported">supported</option><option value="weakened">weakened</option><option value="refuted">refuted</option><option value="inconclusive">inconclusive</option>
              </select></label>
            )}
            <label className="block"><span className="text-xs text-gray-400">Observed behavior</span><select value={observedBehavior} onChange={(event) => setObservedBehavior(event.target.value)} className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white">
              <option value="fixed">fixed</option><option value="blocked">blocked</option><option value="non_reproducible">non-reproducible</option><option value="benign_explanation">benign explanation</option><option value="still_vulnerable">still vulnerable</option><option value="inconclusive">inconclusive</option>
            </select></label>
            <label className="block"><span className="text-xs text-gray-400">Evidence object IDs</span><input value={evidenceRefs} onChange={(event) => setEvidenceRefs(event.target.value)} placeholder="UUIDs separated by spaces" className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 font-mono text-xs text-white" /></label>
            <label className="block"><span className="text-xs text-gray-400">Tool receipt IDs</span><input value={toolReceiptRefs} onChange={(event) => setToolReceiptRefs(event.target.value)} placeholder="UUIDs separated by spaces" className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 font-mono text-xs text-white" /></label>
          </div>
          <label className="block"><span className="text-xs text-gray-400">Analyst notes</span><textarea value={annotationNotes} onChange={(event) => setAnnotationNotes(event.target.value)} rows={3} className="mt-1 w-full resize-y rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white" /></label>
          <div className="flex justify-end"><Button size="sm" variant={annotationMode === 'human_verdict' ? 'danger' : 'secondary'} disabled={busy !== null || !annotationNotes.trim()} onClick={() => void recordCounterevidence()}>
            <ShieldCheck className={`h-3.5 w-3.5 ${busy === 'record' ? 'animate-pulse' : ''}`} /> Record {annotationMode === 'human_verdict' ? 'human verdict' : 'counterevidence'}
          </Button></div>
        </div>
      )}
      <div className="mt-2 flex flex-wrap gap-2">
        {!approvalReceiptId && <Badge className={statusClass('out_of_scope')}>approval receipt required</Badge>}
        {message && <span className="text-xs text-gray-300">{message}</span>}
      </div>
    </div>
  )
}

function ToolRow({ tool }: { tool: ArsenalTool }) {
  const Icon = tool.status === 'runnable' || tool.status === 'installed' ? CheckCircle2 : tool.status === 'wired' || tool.status === 'gated' ? ShieldCheck : XCircle
  return (
    <div className="rounded-md border border-gray-800 bg-gray-950 p-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Icon className="h-4 w-4 text-gray-400" aria-hidden="true" />
            <span className="break-all font-mono text-sm text-white">{tool.tool_name}</span>
            <Badge className={statusClass(tool.status)}>{tool.status}</Badge>
            <Badge className={riskClass(tool.risk_tier)}>{tool.risk_tier}</Badge>
          </div>
          <p className="mt-2 text-sm text-gray-400">{tool.description}</p>
        </div>
        <div className="max-w-full text-left text-xs text-gray-500 sm:shrink-0 sm:text-right">
          <div>{tool.family}</div>
          {tool.version && (
            <div className="mt-1 max-w-44 truncate font-mono text-gray-300">
              version: {tool.version}
            </div>
          )}
        </div>
      </div>
      <div className="mt-3 grid gap-2 text-xs text-gray-500 md:grid-cols-2">
        <div className="min-w-0 truncate">parser: <span className="text-gray-300">{tool.evidence_parser || 'none'}</span></div>
        <div className="min-w-0 truncate">proof: <span className="text-gray-300">{tool.proof_contract || 'none'}</span></div>
        <div className="min-w-0 truncate">binary: <span className="font-mono text-gray-300">{tool.binary_path || 'not detected'}</span></div>
        <div className="min-w-0 truncate">expected: <span className="text-gray-300">{tool.expected_status}</span></div>
      </div>
      {tool.version_probe_error && (
        <p role="alert" className="mt-2 text-xs text-amber-300">{tool.version_probe_error}</p>
      )}
    </div>
  )
}

function LocalAgentRow({
  agent,
  testResult,
  testing,
  onTest,
}: {
  agent: LocalAgentCapability
  testResult?: LocalAgentTestResponse
  testing: boolean
  onTest: (agent: string) => void
}) {
  const Icon = agent.status === 'available' || agent.status === 'installed' ? CheckCircle2 : XCircle
  return (
    <div className="rounded-md border border-gray-800 bg-gray-950 p-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Icon className="h-4 w-4 text-gray-400" aria-hidden="true" />
            <span className="break-all font-mono text-sm text-white">{agent.agent}</span>
            <Badge className={statusClass(agent.status)}>{agent.status}</Badge>
            <Badge className="bg-gray-800 text-gray-300">planner disabled</Badge>
          </div>
          <p className="mt-2 text-sm text-gray-400">{agent.display_name}</p>
        </div>
        <div className="max-w-full text-left text-xs text-gray-500 sm:shrink-0 sm:text-right">
          <div>{agent.auth_detected ? agent.auth_detection_method : 'auth not detected'}</div>
          {agent.version && (
            <div className="mt-1 max-w-44 truncate font-mono text-gray-300">
              version: {agent.version}
            </div>
          )}
          <Button
            size="sm"
            variant="secondary"
            className="mt-2 h-8 px-3 text-xs"
            onClick={() => onTest(agent.agent)}
            disabled={testing}
          >
            {testing ? 'Pinging...' : 'Ping'}
          </Button>
        </div>
      </div>
      <div className="mt-3 grid gap-2 text-xs text-gray-500 md:grid-cols-2">
        <div className="min-w-0 truncate">binary: <span className="font-mono text-gray-300">{agent.binary_path || 'not detected'}</span></div>
        <div>auth contents read: <span className="text-gray-300">{agent.auth_artifact_contents_read ? 'yes' : 'no'}</span></div>
        <div>headless prompt: <span className="text-gray-300">{agent.supports_headless_prompt ? 'supported' : 'not assumed'}</span></div>
        <div>json mode: <span className="text-gray-300">{agent.supports_json_mode ? 'supported' : 'post-validate only'}</span></div>
        <div>timeout: <span className="text-gray-300">{agent.supports_timeout ? 'supported' : 'not assumed'}</span></div>
        <div>network disable: <span className="text-gray-300">{agent.supports_network_disable ? 'supported' : 'not assumed'}</span></div>
      </div>
      {agent.auth_artifacts.length > 0 && (
        <div className="mt-2 truncate text-xs text-gray-500">
          auth refs: <span className="font-mono text-gray-300">{agent.auth_artifacts.join(', ')}</span>
        </div>
      )}
      {agent.version_probe_error && (
        <p role="alert" className="mt-2 text-xs text-amber-300">{agent.version_probe_error}</p>
      )}
      {testResult && (
        <div className="mt-3 rounded-md border border-gray-800 bg-gray-900/60 p-2 text-xs text-gray-400">
          <div className="flex flex-wrap items-center gap-2">
            <span>capability ping:</span>
            <Badge className={statusClass(testResult.status)}>{testResult.status}</Badge>
            {testResult.reason && <span className="text-gray-500">{testResult.reason}</span>}
          </div>
          <div className="mt-2 grid gap-1 md:grid-cols-2">
            <div>prompt sent: <span className="text-gray-200">{testResult.prompt_sent ? 'yes' : 'no'}</span></div>
            <div>planner execution: <span className="text-gray-200">{testResult.planner_execution_enabled ? 'enabled' : 'disabled'}</span></div>
            <div>scanner work queued: <span className="text-gray-200">{testResult.scanner_work_queued ? 'yes' : 'no'}</span></div>
            <div>env keys stripped: <span className="text-gray-200">{testResult.environment_policy.stripped_variable_count}</span></div>
          </div>
          {testResult.version && (
            <div className="mt-2 truncate font-mono text-gray-300">version: {testResult.version}</div>
          )}
          {testResult.error && (
            <p role="alert" className="mt-2 text-amber-300">{testResult.error}</p>
          )}
        </div>
      )}
    </div>
  )
}

function ContractRow({
  name,
  contract,
}: {
  name: string
  contract: ArsenalContractDefinition
}) {
  const required = contract.required || []
  const invariants = contract.invariants || []
  const forbidden = contract.forbidden_fields || []
  const fieldNames = Object.keys(contract.fields || {})

  return (
    <div className="rounded-md border border-gray-800 bg-gray-950 p-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="break-all font-mono text-sm text-white">{name}</span>
            <Badge className={statusClass(contract.status)}>{contract.status}</Badge>
          </div>
          <p className="mt-2 text-sm text-gray-400">{contract.description}</p>
        </div>
        <div className="shrink-0 rounded bg-gray-900 px-2 py-1 text-xs text-gray-400">
          {fieldNames.length} fields
        </div>
      </div>
      <div className="mt-3 grid gap-2 text-xs text-gray-500 md:grid-cols-2">
        <div className="min-w-0">
          <span className="text-gray-400">required: </span>
          <span className="break-words text-gray-300">{required.length ? required.slice(0, 6).join(', ') : 'none'}</span>
        </div>
        <div className="min-w-0">
          <span className="text-gray-400">fields: </span>
          <span className="break-words text-gray-300">{fieldNames.slice(0, 6).join(', ')}</span>
        </div>
      </div>
      {invariants.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {invariants.slice(0, 3).map((invariant) => (
            <Badge key={invariant} className="max-w-full break-words bg-blue-500/15 text-blue-300">
              {invariant}
            </Badge>
          ))}
        </div>
      )}
      {forbidden.length > 0 && (
        <p className="mt-2 text-xs text-red-300">
          forbidden: <span className="break-words">{forbidden.join(', ')}</span>
        </p>
      )}
    </div>
  )
}

export default function ArsenalSettingsPage() {
  const [commands, setCommands] = useState<ArsenalCommandsResponse | null>(null)
  const [contracts, setContracts] = useState<ArsenalContractsResponse | null>(null)
  const [tools, setTools] = useState<ArsenalToolsResponse | null>(null)
  const [localAgents, setLocalAgents] = useState<LocalAgentsResponse | null>(null)
  const [scopeUrl, setScopeUrl] = useState('https://app.example.com/')
  const [scopeHosts, setScopeHosts] = useState('app.example.com')
  const [scopeRoots, setScopeRoots] = useState('example.com')
  const [scopeEnvironment, setScopeEnvironment] = useState('production')
  const [scopeRedirects, setScopeRedirects] = useState('')
  const [scopePreview, setScopePreview] = useState<ScopeReceiptPreview | null>(null)
  const [scopeLoading, setScopeLoading] = useState(false)
  const [scopeError, setScopeError] = useState<string | null>(null)
  const [approvalRiskTier, setApprovalRiskTier] = useState('active')
  const [approvalActor, setApprovalActor] = useState('operator')
  const [denialReason, setDenialReason] = useState('')
  const [approvalReceipt, setApprovalReceipt] = useState<ApprovalReceipt | null>(null)
  const [approvalLoading, setApprovalLoading] = useState(false)
  const [approvalError, setApprovalError] = useState<string | null>(null)
  const [planObjective, setPlanObjective] = useState('Review target coverage and record the next safe action')
  const [planCommand, setPlanCommand] = useState('asm.gaps')
  const [planRiskTier, setPlanRiskTier] = useState('read_only')
  const [planContextHash, setPlanContextHash] = useState('0'.repeat(64))
  const [planResult, setPlanResult] = useState<OperationPlanResponse | null>(null)
  const [recentPlans, setRecentPlans] = useState<OperationPlan[]>([])
  const [recentCommandResults, setRecentCommandResults] = useState<CommandResult[]>([])
  const [recentCampaignActions, setRecentCampaignActions] = useState<CampaignAction[]>([])
  const [interactiveSessions, setInteractiveSessions] = useState<InteractiveSessionSummary[]>([])
  const [recentHypotheses, setRecentHypotheses] = useState<Hypothesis[]>([])
  const [hypothesisSituation, setHypothesisSituation] = useState<HypothesisSituationReport | null>(null)
  const [sourceTargetId, setSourceTargetId] = useState('')
  const [sourceLabel, setSourceLabel] = useState('operator-source-hints')
  const [sourceKind, setSourceKind] = useState('openapi_operation')
  const [sourceMethod, setSourceMethod] = useState('GET')
  const [sourcePath, setSourcePath] = useState('/rest/basket/{id}')
  const [sourceRiskHints, setSourceRiskHints] = useState('idor')
  const [sourceObjectKeys, setSourceObjectKeys] = useState('basket.id')
  const [sourceBodyPaths, setSourceBodyPaths] = useState('')
  const [sourceConfidence, setSourceConfidence] = useState('0.6')
  const [sourceIngestResult, setSourceIngestResult] = useState<SourceIngestResult | null>(null)
  const [sourceIngestLoading, setSourceIngestLoading] = useState(false)
  const [sourceIngestError, setSourceIngestError] = useState<string | null>(null)
  const [refuterSummary, setRefuterSummary] = useState<RefuterWorkSummary | null>(null)
  const [refuterQueueResult, setRefuterQueueResult] = useState<RefuterQueueResult | null>(null)
  const [recentRefuterReviews, setRecentRefuterReviews] = useState<RefuterReview[]>([])
  const [refuterQueueLoading, setRefuterQueueLoading] = useState(false)
  const [refuterQueueError, setRefuterQueueError] = useState<string | null>(null)
  const [planLoading, setPlanLoading] = useState(false)
  const [planError, setPlanError] = useState<string | null>(null)
  const [contextResult, setContextResult] = useState<AgentContextPackResponse | null>(null)
  const [traceResult, setTraceResult] = useState<AgentDecisionTraceResponse | null>(null)
  const [contextTargetId, setContextTargetId] = useState('')
  const [localPlannerAgent, setLocalPlannerAgent] = useState('codex')
  const [localPlannerContextId, setLocalPlannerContextId] = useState('')
  const [testingAgent, setTestingAgent] = useState<string | null>(null)
  const [localAgentTestResults, setLocalAgentTestResults] = useState<Record<string, LocalAgentTestResponse>>({})
  const [recentContextPacks, setRecentContextPacks] = useState<AgentContextPack[]>([])
  const [recentDecisionTraces, setRecentDecisionTraces] = useState<AgentDecisionTrace[]>([])
  const [contextTraceLoading, setContextTraceLoading] = useState(false)
  const [contextTraceError, setContextTraceError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [probing, setProbing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function load(probeVersions = false) {
    setError(null)
    if (probeVersions) setProbing(true)
    else setLoading(true)
    try {
      const [
        commandData,
        contractData,
        toolData,
        localAgentData,
        planData,
        commandResultData,
        campaignActionData,
        hypothesisSituationData,
        hypothesisData,
        refuterSummaryData,
        contextData,
        traceData,
        sessionData,
        refuterReviewData,
      ] = await Promise.all([
        getArsenalCommands(),
        getArsenalContracts(),
        getArsenalTools({ probeVersions }),
        getLocalAgents({ probeVersions }),
        getOperationPlans(5),
        getCommandResults(5),
        getCampaignActions(20),
        getHypothesisSituationReport(5, approvalActor || 'operator'),
        getHypotheses(5),
        getRefuterWorkSummary(5, 200),
        getAgentContextPacks(5),
        getAgentDecisionTraces(5),
        listInteractiveSessions(),
        getRefuterReviews(10),
      ])
      setCommands(commandData)
      setContracts(contractData)
      setTools(toolData)
      setLocalAgents(localAgentData)
      setRecentPlans(planData.operation_plans)
      setRecentCommandResults(commandResultData.command_results)
      setRecentCampaignActions(campaignActionData.campaign_actions)
      setHypothesisSituation(hypothesisSituationData)
      setRecentHypotheses(hypothesisData.hypotheses)
      setRefuterSummary(refuterSummaryData)
      setRecentContextPacks(contextData.context_packs)
      setRecentDecisionTraces(traceData.decision_traces)
      setInteractiveSessions(sessionData.sessions || [])
      setRecentRefuterReviews(refuterReviewData.refuter_reviews || [])
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load Command Arsenal status')
    } finally {
      setLoading(false)
      setProbing(false)
    }
  }

  useEffect(() => {
    void load(false)
  }, [])

  async function refreshCampaignActions() {
    const [actionData, sessionData] = await Promise.all([
      getCampaignActions(20),
      listInteractiveSessions(),
    ])
    setRecentCampaignActions(actionData.campaign_actions)
    setInteractiveSessions(sessionData.sessions || [])
  }

  async function refreshRefuterReviews() {
    const data = await getRefuterReviews(10)
    setRecentRefuterReviews(data.refuter_reviews || [])
  }

  async function refreshHypotheses() {
    const [hypothesisData, situationData] = await Promise.all([
      getHypotheses(5),
      getHypothesisSituationReport(5, approvalActor || 'operator'),
    ])
    setRecentHypotheses(hypothesisData.hypotheses)
    setHypothesisSituation(situationData)
  }

  const commandCounts = useMemo(() => countBy(commands?.commands || []), [commands])
  const gatedCommands = useMemo(
    () => (commands?.commands || []).filter((command) => command.status === 'gated'),
    [commands]
  )
  const readOnlyCommands = useMemo(
    () => (commands?.commands || []).filter((command) => command.status === 'read_only'),
    [commands]
  )
  const contractEntries = useMemo(
    () => contracts?.contract_names.map((name) => [name, contracts.contracts[name]] as const).filter((entry) => Boolean(entry[1])) || [],
    [contracts]
  )
  const visibleTools = tools?.tools || []
  const visibleLocalAgents = localAgents?.agents || []
  const selectedPlanCommand = useMemo(
    () => (commands?.commands || []).find((command) => command.name === planCommand),
    [commands, planCommand]
  )

  function splitLines(value: string): string[] {
    return value
      .split(/[\n,]/)
      .map((item) => item.trim())
      .filter(Boolean)
  }

  async function submitSourceHint() {
    setSourceIngestLoading(true)
    setSourceIngestError(null)
    setSourceIngestResult(null)
    try {
      const confidence = Number.parseFloat(sourceConfidence)
      const result = await generateSourceIngestHypotheses({
        target_id: sourceTargetId.trim() || undefined,
        source_label: sourceLabel.trim() || 'operator-source-hints',
        created_by: approvalActor.trim() || 'operator',
        hints: [{
          kind: sourceKind,
          method: sourceMethod.trim().toUpperCase() || 'GET',
          path: sourcePath.trim(),
          risk_hints: splitLines(sourceRiskHints),
          object_keys: splitLines(sourceObjectKeys),
          body_paths: splitLines(sourceBodyPaths),
          confidence: Number.isFinite(confidence) ? Math.max(0, Math.min(1, confidence)) : 0.35,
        }],
      })
      setSourceIngestResult(result)
      const [hypothesisData, situationData] = await Promise.all([
        getHypotheses(5),
        getHypothesisSituationReport(5, approvalActor || 'operator'),
      ])
      setRecentHypotheses(hypothesisData.hypotheses)
      setHypothesisSituation(situationData)
    } catch (err) {
      setSourceIngestError(err instanceof Error ? err.message : 'Failed to record source-informed hypothesis')
    } finally {
      setSourceIngestLoading(false)
    }
  }

  async function queueRefuterWork() {
    setRefuterQueueLoading(true)
    setRefuterQueueError(null)
    setRefuterQueueResult(null)
    try {
      const result = await queueRefuterReviewsFromSummary({
        limit: 5,
        finding_window: 200,
        created_by: approvalActor || 'settings-arsenal',
      })
      setRefuterQueueResult(result)
      setRefuterSummary(await getRefuterWorkSummary(5, 200))
      await refreshRefuterReviews()
    } catch (err) {
      setRefuterQueueError(err instanceof Error ? err.message : 'Failed to queue refuter review work')
    } finally {
      setRefuterQueueLoading(false)
    }
  }

  async function previewScope() {
    setScopeLoading(true)
    setScopeError(null)
    try {
      const response = await previewScopeReceipt({
        url: scopeUrl,
        allowed_hosts: splitLines(scopeHosts),
        allowed_root_domains: splitLines(scopeRoots),
        environment: scopeEnvironment,
        redirect_urls: splitLines(scopeRedirects),
      })
      setScopePreview(response.scope_receipt)
      setApprovalReceipt(null)
      setApprovalError(null)
    } catch (err) {
      setScopeError(err instanceof Error ? err.message : 'Failed to preview scope receipt')
    } finally {
      setScopeLoading(false)
    }
  }

  async function recordApproval(action: 'approve' | 'deny') {
    if (!scopePreview) return
    setApprovalLoading(true)
    setApprovalError(null)
    try {
      const confirmations = ['confirm_authorized']
      if (scopePreview.verdict === 'needs_approval') confirmations.push('confirm_scope_reviewed')
      const response = await createApprovalReceipt({
        scope_receipt_id: scopePreview.receipt_id,
        risk_tier: approvalRiskTier,
        confirmations,
        approved_by: action === 'approve' ? approvalActor.trim() || 'operator' : undefined,
        denial_reason: action === 'deny' ? denialReason.trim() || 'Denied during receipt preview' : undefined,
      })
      setApprovalReceipt(response.approval_receipt)
    } catch (err) {
      setApprovalError(err instanceof Error ? err.message : 'Failed to create approval receipt')
    } finally {
      setApprovalLoading(false)
    }
  }

  async function createPlan() {
    setPlanLoading(true)
    setPlanError(null)
    try {
      const command = selectedPlanCommand
      const gated = command?.status === 'gated'
      const confirmations = gated ? ['confirm_authorized'] : []
      const response = await createOperationPlan({
        objective: planObjective,
        planner: { kind: 'ui', name: 'settings-arsenal', version: commands?.schema_version || 'unknown' },
        context_hash: planContextHash,
        target_scope: {
          url: scopeUrl,
          allowed_hosts: splitLines(scopeHosts),
          allowed_root_domains: splitLines(scopeRoots),
          environment: scopeEnvironment,
        },
        risk_tier: planRiskTier,
        confirmations,
        actions: [{
          command: planCommand,
          risk_tier: command?.risk_tier || planRiskTier,
          parameters: {},
          scope_receipt_id: scopePreview?.receipt_id,
          approval_receipt_id: approvalReceipt?.approved_by ? approvalReceipt.id : undefined,
          reason: 'operator dry-run preview',
        }],
        stop_conditions: ['scope_blocked', 'budget_exhausted', 'operator_cancelled'],
        success_criteria: ['plan_validated', 'no_execution_performed'],
        scope_receipt_id: scopePreview?.receipt_id,
        approval_receipt_id: approvalReceipt?.approved_by ? approvalReceipt.id : undefined,
        created_by: approvalActor.trim() || 'operator',
      })
      setPlanResult(response)
      setRecentPlans((plans) => [response.operation_plan, ...plans].slice(0, 5))
    } catch (err) {
      setPlanError(err instanceof Error ? err.message : 'Failed to validate operation plan')
    } finally {
      setPlanLoading(false)
    }
  }

  async function recordContextAndTrace() {
    setContextTraceLoading(true)
    setContextTraceError(null)
    try {
      const allowedCommands = commands?.commands
        .filter((command) => command.status === 'read_only' || command.status === 'dry_run')
        .slice(0, 12)
        .map((command) => command.name) || ['target.list', 'asm.gaps', 'operation_plan.preview']
      const contextResponse = await createAgentContextPack({
        context_hash: planContextHash,
        target_summary: {
          url: scopeUrl,
          environment: scopeEnvironment,
          allowed_hosts: splitLines(scopeHosts),
          allowed_root_domains: splitLines(scopeRoots),
        },
        current_surface: {
          source: 'settings-arsenal',
          commands_loaded: commands?.commands.length || 0,
          tools_loaded: tools?.tools.length || 0,
        },
        current_gaps: [
          { kind: 'operator_review', reason: planObjective },
        ],
        findings_summary: [],
        hypotheses_summary: [],
        allowed_commands: allowedCommands,
        disallowed_commands: (commands?.commands || [])
          .filter((command) => command.status === 'gated' || command.status === 'catalog_only' || command.status === 'out_of_scope')
          .slice(0, 8)
          .map((command) => ({ command: command.name, reason: `${command.status}:${command.risk_tier}` })),
        known_preconditions: {
          scope_receipt: scopePreview?.receipt_id || 'missing',
          approval_receipt: approvalReceipt?.approved_by ? approvalReceipt.id : 'missing',
          execution_enabled: false,
        },
        created_by: approvalActor.trim() || 'operator',
      })
      const traceResponse = await createAgentDecisionTrace({
        context_pack_id: contextResponse.context_pack.id,
        operation_plan_id: planResult?.operation_plan.id,
        planner: { kind: 'ui', name: 'settings-arsenal', version: commands?.schema_version || 'unknown' },
        context_hash: contextResponse.context_pack.context_hash,
        command_schema_version: commands?.schema_version || 'unknown',
        steps: [
          {
            kind: 'proposed_action',
            command: planCommand,
            status: 'planned',
            reason: 'operator dry-run planning trace',
            refs: planResult?.operation_plan.id ? [planResult.operation_plan.id] : [contextResponse.context_pack.id],
          },
          {
            kind: 'summary',
            status: 'recorded',
            reason: 'No command execution was requested or enabled.',
            refs: [contextResponse.context_pack.id],
          },
        ],
        final_rationale: 'Recorded bounded context and dry-run decision trace for operator review.',
        created_by: approvalActor.trim() || 'operator',
      })
      setContextResult(contextResponse)
      setTraceResult(traceResponse)
      setRecentContextPacks((packs) => [contextResponse.context_pack, ...packs].slice(0, 5))
      setRecentDecisionTraces((traces) => [traceResponse.decision_trace, ...traces].slice(0, 5))
    } catch (err) {
      setContextTraceError(err instanceof Error ? err.message : 'Failed to record context and trace')
    } finally {
      setContextTraceLoading(false)
    }
  }

  async function generateContextFromTarget() {
    setContextTraceLoading(true)
    setContextTraceError(null)
    try {
      const response = await generateAgentContextPackFromTarget({
        target_id: contextTargetId.trim(),
        created_by: approvalActor.trim() || 'operator',
        include_findings: true,
        include_endpoints: true,
        include_gaps: true,
      })
      setContextResult(response)
      setTraceResult(null)
      setLocalPlannerContextId(response.context_pack.id)
      setRecentContextPacks((packs) => [response.context_pack, ...packs].slice(0, 5))
    } catch (err) {
      setContextTraceError(err instanceof Error ? err.message : 'Failed to generate context pack')
    } finally {
      setContextTraceLoading(false)
    }
  }

  async function planWithLocalAgent() {
    setPlanLoading(true)
    setPlanError(null)
    try {
      const response = await createLocalAgentDryRunPlan({
        agent: localPlannerAgent,
        context_pack_id: localPlannerContextId.trim(),
        objective: planObjective,
        created_by: approvalActor.trim() || 'operator',
      })
      setPlanResult(response)
      setRecentPlans((plans) => [response.operation_plan, ...plans].slice(0, 5))
    } catch (err) {
      setPlanError(err instanceof Error ? err.message : 'Failed to create local-agent dry-run plan')
    } finally {
      setPlanLoading(false)
    }
  }

  async function pingLocalAgent(agent: string) {
    setTestingAgent(agent)
    try {
      const response = await testLocalAgentCapability({
        agent,
        timeout_seconds: 5,
        max_output_bytes: 2000,
      })
      setLocalAgentTestResults((results) => ({ ...results, [agent]: response }))
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to test local-agent capability'
      setLocalAgentTestResults((results) => ({
        ...results,
        [agent]: {
          agent,
          display_name: agent,
          ok: false,
          status: 'failed',
          reason: 'api_error',
          binary_path: null,
          auth_detected: false,
          auth_detection_method: 'unknown',
          auth_artifact_contents_read: false,
          planner_execution_enabled: false,
          local_agent_spawned: false,
          prompt_sent: false,
          prompt_bytes_sent: 0,
          target_state_mutated: false,
          scanner_work_queued: false,
          process_spawned: false,
          timeout_seconds: 5,
          max_output_bytes: 2000,
          output: '',
          output_truncated: false,
          output_bytes_captured: 0,
          version: null,
          return_code: null,
          timed_out: false,
          error: message,
          command_kind: 'version_probe',
          argv_redacted: [agent, '--version'],
          environment_policy: {
            provider_api_keys_stripped: true,
            sensitive_values_returned: false,
            environment_variable_names_returned: false,
            stripped_variable_count: 0,
          },
        },
      }))
    } finally {
      setTestingAgent(null)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Command Arsenal</h1>
          <p className="mt-1 max-w-3xl text-gray-400">
            Read-only command schemas and integrated tool status. State-changing commands stay gated through the existing API paths.
          </p>
        </div>
        <Button
          type="button"
          variant="secondary"
          onClick={() => void load(true)}
          disabled={loading || probing}
        >
          <RefreshCw className={`h-4 w-4 ${probing ? 'animate-spin' : ''}`} />
          Probe versions
        </Button>
      </div>

      {error && <ErrorState message={error} onRetry={() => void load(false)} />}

      {loading ? (
        <div className="grid gap-3 md:grid-cols-4">
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
        </div>
      ) : (
        <div className="grid gap-3 md:grid-cols-4">
          <Stat label="schema" value={commands?.schema_version || '-'} tone="text-blue-300" />
          <Stat label="commands" value={commands?.commands.length || 0} />
          <Stat label="read-only" value={commandCounts.read_only || 0} tone="text-green-300" />
          <Stat label="gated" value={commandCounts.gated || 0} tone="text-blue-300" />
          <Stat label="contracts" value={contracts?.contract_names.length || 0} tone="text-cyan-300" />
        </div>
      )}

      <Card className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-green-300" aria-hidden="true" />
            <h2 className="font-medium text-white">Mission Contracts</h2>
          </div>
          {contracts && <Badge className="bg-gray-800 text-gray-300">execution disabled</Badge>}
        </div>
        {contracts && (
          <div className="mb-3 rounded-md border border-gray-800 bg-gray-950 p-3 text-xs text-gray-400">
            Secret policy: <span className="text-gray-200">{contracts.secret_policy.default}</span>
            <span className="mx-2 text-gray-700">|</span>
            never inline: <span className="text-gray-300">{contracts.secret_policy.never_inline.slice(0, 6).join(', ')}</span>
          </div>
        )}
        {loading ? (
          <div className="space-y-3">
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
          </div>
        ) : contractEntries.length === 0 ? (
          <EmptyState message="No mission contracts are registered." />
        ) : (
          <div className="grid gap-3 xl:grid-cols-2">
            {contractEntries.map(([name, contract]) => (
              <ContractRow key={name} name={name} contract={contract} />
            ))}
          </div>
        )}
        {!loading && recentRefuterReviews.length > 0 && (
          <div className="mt-4 border-t border-gray-800 pt-4">
            <div className="mb-3 flex items-center justify-between gap-2">
              <h3 className="text-sm font-medium text-white">Durable Reviews</h3>
              <Badge className="bg-gray-800 text-gray-300">{recentRefuterReviews.length}</Badge>
            </div>
            <div className="grid gap-3">
              {recentRefuterReviews.map((review) => (
                <RefuterReviewRow
                  key={review.id}
                  review={review}
                  approvalReceiptId={approvalReceipt?.approved_by ? approvalReceipt.id : undefined}
                  operator={approvalActor.trim() || 'operator'}
                  onRefresh={refreshRefuterReviews}
                />
              ))}
            </div>
          </div>
        )}
      </Card>

      <Card className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-amber-300" aria-hidden="true" />
            <h2 className="font-medium text-white">Refuter Work</h2>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              onClick={() => void queueRefuterWork()}
              disabled={loading || refuterQueueLoading || !refuterSummary || refuterSummary.summary.unreviewed_count === 0}
            >
              <CheckCircle2 className={`h-4 w-4 ${refuterQueueLoading ? 'animate-spin' : ''}`} aria-hidden="true" />
              Queue Reviews
            </Button>
          </div>
        </div>
        <p className="mb-3 text-sm text-gray-400">
          Signal-only review work for weak high-impact findings, semantic AI Gate claims, and unanchored Model Intake trust claims.
        </p>
        {refuterQueueError && <div className="mb-3 rounded-md border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-300">{refuterQueueError}</div>}
        {refuterQueueResult && <div className="mb-3"><RefuterQueueResultPanel result={refuterQueueResult} /></div>}
        {loading ? (
          <div className="space-y-3">
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
          </div>
        ) : !refuterSummary || refuterSummary.summary.candidate_count === 0 ? (
          <EmptyState message="No refuter review candidates in the bounded summary." />
        ) : (
          <div className="space-y-4">
            <div className="grid gap-3 md:grid-cols-4">
              <Stat label="candidates" value={refuterSummary.summary.candidate_count} />
              <Stat label="unreviewed" value={refuterSummary.summary.unreviewed_count} tone="text-amber-300" />
              <Stat label="reviewed" value={refuterSummary.summary.already_reviewed_count} />
              <Stat label="queued now" value={refuterQueueResult?.created || 0} tone="text-green-300" />
            </div>
            <div className="grid gap-2">
              {refuterSummary.candidates.slice(0, 5).map((candidate) => (
                <RefuterCandidateRow
                  key={`${candidate.subject_type}:${candidate.subject_id || candidate.finding_id || candidate.title}`}
                  candidate={candidate}
                />
              ))}
            </div>
          </div>
        )}
      </Card>

      <Card className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Boxes className="h-4 w-4 text-blue-300" aria-hidden="true" />
            <h2 className="font-medium text-white">Source Hint Ingest</h2>
          </div>
          <Badge className="bg-gray-800 text-gray-300">record only</Badge>
        </div>
        <p className="mb-3 text-sm text-gray-400">
          Turn bounded source, route, or API facts into source-only hypotheses. This never queues scans or creates findings.
        </p>
        <div className="grid gap-3 lg:grid-cols-3">
          <label className="block lg:col-span-2">
            <span className="text-xs text-gray-400">Target ID (optional)</span>
            <input
              value={sourceTargetId}
              onChange={(event) => setSourceTargetId(event.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 font-mono text-xs text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Source label</span>
            <input
              value={sourceLabel}
              onChange={(event) => setSourceLabel(event.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Kind</span>
            <select
              value={sourceKind}
              onChange={(event) => setSourceKind(event.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="openapi_operation">openapi_operation</option>
              <option value="backend_route">backend_route</option>
              <option value="frontend_route">frontend_route</option>
              <option value="graphql_field">graphql_field</option>
              <option value="ai_tool_endpoint">ai_tool_endpoint</option>
              <option value="route">route</option>
            </select>
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Method</span>
            <input
              value={sourceMethod}
              onChange={(event) => setSourceMethod(event.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 font-mono text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Path</span>
            <input
              value={sourcePath}
              onChange={(event) => setSourcePath(event.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 font-mono text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Risk hints</span>
            <input
              value={sourceRiskHints}
              onChange={(event) => setSourceRiskHints(event.target.value)}
              placeholder="idor, sqli, xss"
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Object keys</span>
            <input
              value={sourceObjectKeys}
              onChange={(event) => setSourceObjectKeys(event.target.value)}
              placeholder="order.id"
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Body paths</span>
            <input
              value={sourceBodyPaths}
              onChange={(event) => setSourceBodyPaths(event.target.value)}
              placeholder="$.isAdmin"
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Confidence</span>
            <input
              value={sourceConfidence}
              onChange={(event) => setSourceConfidence(event.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <Button
            type="button"
            variant="secondary"
            onClick={() => void submitSourceHint()}
            disabled={sourceIngestLoading || !sourcePath.trim() || !sourceRiskHints.trim()}
          >
            {sourceIngestLoading ? 'Recording...' : 'Record source hint'}
          </Button>
          <span className="text-xs text-gray-500">source-only · runtime proof required · no scan queued</span>
          {sourceIngestError && <span role="alert" className="text-sm text-red-300">{sourceIngestError}</span>}
        </div>
        {sourceIngestResult && (
          <div className="mt-4 rounded-md border border-gray-800 bg-gray-950 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <Badge className="bg-green-500/15 text-green-300">
                recorded {sourceIngestResult.created_or_endorsed}
              </Badge>
              <Badge className="bg-gray-800 text-gray-300">skipped {sourceIngestResult.skipped_count}</Badge>
              <Badge className="bg-gray-800 text-gray-300">findings {sourceIngestResult.findings_created}</Badge>
              <Badge className="bg-gray-800 text-gray-300">queued scans {sourceIngestResult.queued_scans}</Badge>
            </div>
            {sourceIngestResult.hypotheses.length > 0 && (
              <div className="mt-3 grid gap-2">
                {sourceIngestResult.hypotheses.slice(0, 3).map((hypothesis) => (
                  <HypothesisRow key={hypothesis.id} hypothesis={hypothesis} />
                ))}
              </div>
            )}
          </div>
        )}
      </Card>

      <Card className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Boxes className="h-4 w-4 text-violet-300" aria-hidden="true" />
            <h2 className="font-medium text-white">Hypothesis Situation</h2>
          </div>
          <div className="flex flex-wrap gap-1.5">
            <Badge className="bg-gray-800 text-gray-300">bounded report</Badge>
            {hypothesisSituation?.board_truncated && <Badge className="bg-amber-500/15 text-amber-300">board truncated</Badge>}
          </div>
        </div>
        <p className="mb-3 text-sm text-gray-400">
          Bounded context for graph, scanner, AI Gate, Model Intake, and manual leads. These records cannot verify findings.
        </p>
        {loading ? (
          <div className="space-y-3">
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
          </div>
        ) : !hypothesisSituation || hypothesisSituation.summary.considered_count === 0 ? (
          <EmptyState message="No hypotheses recorded yet." />
        ) : (
          <div className="space-y-4">
            <div className="grid gap-3 md:grid-cols-4">
              <Stat label="considered" value={hypothesisSituation.summary.considered_count} />
              <Stat label="hot unclaimed" value={hypothesisSituation.hottest_unclaimed.length} />
              <Stat label="live blockers" value={hypothesisSituation.live_blockers.length} tone="text-amber-300" />
              <Stat label="avoid resurfacing" value={hypothesisSituation.avoid_resurfacing.length} tone="text-red-300" />
            </div>
            <HypothesisGraphContextPanel context={hypothesisSituation.graph_context} />
            <div className="grid gap-3 xl:grid-cols-2">
              <SituationBucket title="Hot Unclaimed" items={hypothesisSituation.hottest_unclaimed} empty="No unclaimed hypotheses in the bounded report." />
              <SituationBucket title="Your Claims" items={hypothesisSituation.requester_claims} empty="No active claims for the requester." />
              <SituationBucket title="Live Blockers" items={hypothesisSituation.live_blockers} empty="No live claims blocking this requester." />
              <SituationBucket title="Avoid Resurfacing" items={hypothesisSituation.avoid_resurfacing} empty="No refuted or dead hypotheses in the bounded report." />
            </div>
            <div>
              <h3 className="mb-2 text-sm font-medium text-gray-200">Missing Preconditions</h3>
              {hypothesisSituation.missing_preconditions.length === 0 ? (
                <div className="rounded-md border border-gray-800 bg-gray-950 p-3 text-sm text-gray-500">No missing preconditions in the bounded report.</div>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {hypothesisSituation.missing_preconditions.map((item) => (
                    <Badge key={item.requirement} className="bg-amber-500/15 text-amber-300">
                      {item.requirement}: {item.count}
                    </Badge>
                  ))}
                </div>
              )}
            </div>
            {recentHypotheses.length > 0 && (
              <div>
                <h3 className="mb-2 text-sm font-medium text-gray-200">Recent Board Entries</h3>
                <div className="grid gap-2">
                  {recentHypotheses.slice(0, 5).map((hypothesis) => (
                    <HypothesisRow
                      key={hypothesis.id}
                      hypothesis={hypothesis}
                      approvalReceiptId={approvalReceipt?.approved_by ? approvalReceipt.id : undefined}
                      operator={approvalActor.trim() || 'operator'}
                      onRefresh={refreshHypotheses}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </Card>

      <Card className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <TerminalSquare className="h-4 w-4 text-blue-300" aria-hidden="true" />
            <h2 className="font-medium text-white">Local Agent Capabilities</h2>
          </div>
          {localAgents && (
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(localAgents.summary).map(([status, count]) => (
                <Badge key={status} className={statusClass(status)}>{status}: {count}</Badge>
              ))}
            </div>
          )}
        </div>
        {localAgents && (
          <div className="mb-3 rounded-md border border-gray-800 bg-gray-950 p-3 text-xs text-gray-400">
            Auth detection only: <span className="text-gray-300">{localAgents.auth_policy.detection_only ? 'yes' : 'no'}</span>
            <span className="mx-2 text-gray-700">|</span>
            auth contents read: <span className="text-gray-300">{localAgents.auth_policy.auth_artifact_contents_read ? 'yes' : 'no'}</span>
            <span className="mx-2 text-gray-700">|</span>
            planner execution: <span className="text-gray-300">{localAgents.planner_execution_enabled ? 'enabled' : 'disabled'}</span>
          </div>
        )}
        {loading ? (
          <div className="space-y-3">
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
          </div>
        ) : visibleLocalAgents.length === 0 ? (
          <EmptyState message="No local agents are registered." />
        ) : (
          <div className="grid gap-3 xl:grid-cols-2">
            {visibleLocalAgents.map((agent) => (
              <LocalAgentRow
                key={agent.agent}
                agent={agent}
                testResult={localAgentTestResults[agent.agent]}
                testing={testingAgent === agent.agent}
                onTest={pingLocalAgent}
              />
            ))}
          </div>
        )}
      </Card>

      <Card className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <TerminalSquare className="h-4 w-4 text-emerald-300" aria-hidden="true" />
            <h2 className="font-medium text-white">Campaign Action Ledger</h2>
          </div>
          <Badge className="bg-amber-500/15 text-amber-300">gated replay</Badge>
        </div>
        <p className="mb-3 text-sm text-gray-400">
          Action-shaped records derived from product commands, with campaign, receipt, scan, evidence, and blocked-reason refs.
        </p>
        {loading ? (
          <div className="space-y-3">
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
          </div>
        ) : recentCampaignActions.length === 0 ? (
          <EmptyState message="No campaign action records yet." />
        ) : (
          <div className="grid gap-2">
            {recentCampaignActions.slice(0, 20).map((action) => (
              <CampaignActionRow
                key={action.id}
                action={action}
                sessions={interactiveSessions}
                approvalReceiptId={approvalReceipt?.approved_by ? approvalReceipt.id : undefined}
                operator={approvalActor.trim() || 'operator'}
                onRefresh={refreshCampaignActions}
              />
            ))}
          </div>
        )}
      </Card>

      <Card className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-cyan-300" aria-hidden="true" />
            <h2 className="font-medium text-white">Operation Plan Preview</h2>
          </div>
          <Badge className="bg-gray-800 text-gray-300">dry-run only</Badge>
        </div>
        <div className="grid gap-3 lg:grid-cols-2">
          <label className="block">
            <span className="text-xs text-gray-400">Objective</span>
            <input
              value={planObjective}
              onChange={(event) => setPlanObjective(event.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Command</span>
            <select
              value={planCommand}
              onChange={(event) => setPlanCommand(event.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            >
              {(commands?.commands || []).map((command) => (
                <option key={command.name} value={command.name}>
                  {command.name}
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Risk tier</span>
            <select
              value={planRiskTier}
              onChange={(event) => setPlanRiskTier(event.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="read_only">read_only</option>
              <option value="passive">passive</option>
              <option value="active">active</option>
              <option value="intrusive">intrusive</option>
              <option value="credential">credential</option>
              <option value="dangerous">dangerous</option>
            </select>
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Context hash</span>
            <input
              value={planContextHash}
              onChange={(event) => setPlanContextHash(event.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 font-mono text-xs text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <Button type="button" variant="secondary" onClick={() => void createPlan()} disabled={planLoading || !commands?.commands.length}>
            {planLoading ? 'Validating...' : 'Persist dry-run plan'}
          </Button>
          {selectedPlanCommand && (
            <span className="text-xs text-gray-500">
              {selectedPlanCommand.status} / {selectedPlanCommand.risk_tier}
              {selectedPlanCommand.status === 'gated' && !approvalReceipt?.approved_by ? ' / approval receipt required' : ''}
            </span>
          )}
          {planError && <span role="alert" className="text-sm text-red-300">{planError}</span>}
        </div>
        {planResult && (
          <div className="mt-4 rounded-md border border-gray-800 bg-gray-950 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <Badge className={planResult.validated ? statusClass('read_only') : statusClass('out_of_scope')}>
                {planResult.operation_plan.status}
              </Badge>
              <span className="break-all font-mono text-xs text-gray-400">{planResult.operation_plan.id}</span>
              <span className="text-xs text-gray-500">execution disabled</span>
            </div>
            <div className="mt-3 grid gap-2 text-xs text-gray-500 md:grid-cols-2">
              <div>errors: <span className="break-words text-gray-300">{planResult.operation_plan.validation_errors.length ? planResult.operation_plan.validation_errors.join(', ') : 'none'}</span></div>
              <div>warnings: <span className="break-words text-gray-300">{planResult.operation_plan.validation_warnings.length ? planResult.operation_plan.validation_warnings.join(', ') : 'none'}</span></div>
              <div>scope receipt: <span className="break-all font-mono text-gray-300">{planResult.operation_plan.scope_receipt_id || 'none'}</span></div>
              <div>approval receipt: <span className="break-all font-mono text-gray-300">{planResult.operation_plan.approval_receipt_id || 'none'}</span></div>
            </div>
          </div>
        )}
        {recentPlans.length > 0 && (
          <div className="mt-4 grid gap-2">
            {recentPlans.slice(0, 5).map((plan) => (
              <div key={plan.id} className="rounded-md border border-gray-800 bg-gray-950 px-3 py-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="min-w-0 break-words text-sm text-gray-200">{plan.objective}</span>
                  <div className="flex min-w-0 flex-wrap items-center justify-end gap-2">
                    <Badge className={plan.status === 'blocked' ? statusClass('out_of_scope') : statusClass('read_only')}>{plan.status}</Badge>
                    <span className="break-all font-mono text-xs text-gray-500">{plan.id}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
        <div className="mt-4 rounded-md border border-gray-800 bg-gray-950 p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-medium text-white">Local-Agent Dry-Run Planner</h3>
              <p className="mt-1 text-xs text-gray-500">
                Creates a validated OperationPlan from a saved context pack without spawning a local agent or executing commands.
              </p>
            </div>
            <Badge className="bg-gray-800 text-gray-300">execution disabled</Badge>
          </div>
          <div className="mt-3 grid gap-3 md:grid-cols-[minmax(0,12rem)_minmax(0,1fr)_auto]">
            <label className="block">
              <span className="text-xs text-gray-500">Planner</span>
              <select
                value={localPlannerAgent}
                onChange={(event) => setLocalPlannerAgent(event.target.value)}
                className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
              >
                {visibleLocalAgents.map((agent) => (
                  <option key={agent.agent} value={agent.agent}>
                    {agent.display_name}
                  </option>
                ))}
                {visibleLocalAgents.length === 0 && <option value="codex">Codex</option>}
              </select>
            </label>
            <label className="block">
              <span className="text-xs text-gray-500">Context pack ID</span>
              <input
                value={localPlannerContextId}
                onChange={(event) => setLocalPlannerContextId(event.target.value)}
                placeholder="00000000-0000-0000-0000-000000000000"
                className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 font-mono text-xs text-white focus:border-blue-500 focus:outline-none"
              />
            </label>
            <div className="flex items-end">
              <Button
                type="button"
                variant="secondary"
                onClick={() => void planWithLocalAgent()}
                disabled={planLoading || !localPlannerContextId.trim() || !planObjective.trim()}
              >
                Plan from context
              </Button>
            </div>
          </div>
        </div>
      </Card>

      <Card className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <TerminalSquare className="h-4 w-4 text-cyan-300" aria-hidden="true" />
            <h2 className="font-medium text-white">Command Result Audit</h2>
          </div>
          <Badge className="bg-gray-800 text-gray-300">read only</Badge>
        </div>
        <p className="mb-3 text-sm text-gray-400">
          Recent queued or partial product actions with operation IDs, receipts, target refs, and next actions.
        </p>
        {loading ? (
          <div className="space-y-3">
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
          </div>
        ) : recentCommandResults.length === 0 ? (
          <EmptyState message="No command-result audit records yet." />
        ) : (
          <div className="grid gap-2">
            {recentCommandResults.slice(0, 5).map((result) => (
              <CommandResultRow key={result.id} result={result} />
            ))}
          </div>
        )}
      </Card>

      <Card className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <TerminalSquare className="h-4 w-4 text-blue-300" aria-hidden="true" />
            <h2 className="font-medium text-white">Context Packs and Decision Traces</h2>
          </div>
          <Badge className="bg-gray-800 text-gray-300">dry-run records</Badge>
        </div>
        <div className="rounded-md border border-gray-800 bg-gray-950 p-3 text-sm text-gray-400">
          <div className="grid gap-2 md:grid-cols-3">
            <div>
              <span className="text-xs text-gray-500">context hash</span>
              <div className="break-all font-mono text-xs text-gray-300">{planContextHash}</div>
            </div>
            <div>
              <span className="text-xs text-gray-500">planner</span>
              <div className="text-gray-300">settings-arsenal</div>
            </div>
            <div>
              <span className="text-xs text-gray-500">execution</span>
              <div className="text-gray-300">disabled</div>
            </div>
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <Button
              type="button"
              variant="secondary"
              onClick={() => void recordContextAndTrace()}
              disabled={contextTraceLoading || !commands?.commands.length}
            >
              {contextTraceLoading ? 'Recording...' : 'Record context + trace'}
            </Button>
            {contextTraceError && <span role="alert" className="text-sm text-red-300">{contextTraceError}</span>}
          </div>
          <div className="mt-4 grid gap-3 border-t border-gray-800 pt-3 md:grid-cols-[1fr_auto]">
            <label className="block">
              <span className="text-xs text-gray-500">Target ID</span>
              <input
                value={contextTargetId}
                onChange={(event) => setContextTargetId(event.target.value)}
                placeholder="00000000-0000-0000-0000-000000000000"
                className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 font-mono text-xs text-white focus:border-blue-500 focus:outline-none"
              />
            </label>
            <div className="flex items-end">
              <Button
                type="button"
                variant="secondary"
                onClick={() => void generateContextFromTarget()}
                disabled={contextTraceLoading || !contextTargetId.trim()}
              >
                Generate from target
              </Button>
            </div>
          </div>
        </div>
        {(contextResult || traceResult) && (
          <div className="mt-4 grid gap-3 lg:grid-cols-2">
            {contextResult && (
              <div className="rounded-md border border-gray-800 bg-gray-950 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge className={contextResult.validated ? statusClass('read_only') : statusClass('out_of_scope')}>
                    {contextResult.context_pack.status}
                  </Badge>
                  <span className="break-all font-mono text-xs text-gray-400">{contextResult.context_pack.id}</span>
                  <span className="text-xs text-gray-500">context pack</span>
                </div>
                <div className="mt-2 text-xs text-gray-500">
                  errors: <span className="break-words text-gray-300">{contextResult.context_pack.validation_errors.length ? contextResult.context_pack.validation_errors.join(', ') : 'none'}</span>
                </div>
                <div className="mt-1 text-xs text-gray-500">
                  allowed commands: <span className="break-words text-gray-300">{contextResult.context_pack.allowed_commands.slice(0, 6).join(', ') || 'none'}</span>
                </div>
              </div>
            )}
            {traceResult && (
              <div className="rounded-md border border-gray-800 bg-gray-950 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge className={traceResult.validated ? statusClass('read_only') : statusClass('out_of_scope')}>
                    {traceResult.decision_trace.status}
                  </Badge>
                  <span className="break-all font-mono text-xs text-gray-400">{traceResult.decision_trace.id}</span>
                  <span className="text-xs text-gray-500">decision trace</span>
                </div>
                <div className="mt-2 text-xs text-gray-500">
                  errors: <span className="break-words text-gray-300">{traceResult.decision_trace.validation_errors.length ? traceResult.decision_trace.validation_errors.join(', ') : 'none'}</span>
                </div>
                <div className="mt-1 text-xs text-gray-500">
                  steps: <span className="text-gray-300">{traceResult.decision_trace.steps.length}</span>
                </div>
              </div>
            )}
          </div>
        )}
        {(recentContextPacks.length > 0 || recentDecisionTraces.length > 0) && (
          <div className="mt-4 grid gap-3 lg:grid-cols-2">
            <div className="space-y-2">
              <h3 className="text-xs font-medium uppercase text-gray-500">Recent context packs</h3>
              {recentContextPacks.slice(0, 5).map((pack) => (
                <div key={pack.id} className="rounded-md border border-gray-800 bg-gray-950 px-3 py-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="break-all font-mono text-xs text-gray-400">{pack.id}</span>
                    <Badge className={pack.status === 'recorded' ? statusClass('read_only') : statusClass('out_of_scope')}>{pack.status}</Badge>
                  </div>
                  <div className="mt-1 break-all font-mono text-xs text-gray-600">{pack.context_hash}</div>
                </div>
              ))}
            </div>
            <div className="space-y-2">
              <h3 className="text-xs font-medium uppercase text-gray-500">Recent decision traces</h3>
              {recentDecisionTraces.slice(0, 5).map((trace) => (
                <div key={trace.id} className="rounded-md border border-gray-800 bg-gray-950 px-3 py-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="break-all font-mono text-xs text-gray-400">{trace.id}</span>
                    <Badge className={trace.status === 'recorded' ? statusClass('read_only') : statusClass('out_of_scope')}>{trace.status}</Badge>
                  </div>
                  <div className="mt-1 text-xs text-gray-600">{trace.steps.length} steps / {trace.command_schema_version}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </Card>

      <Card className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-blue-300" aria-hidden="true" />
            <h2 className="font-medium text-white">Scope Receipt Preview</h2>
          </div>
          <Badge className="bg-gray-800 text-gray-300">no execution</Badge>
        </div>
        <div className="grid gap-3 lg:grid-cols-2">
          <label className="block">
            <span className="text-xs text-gray-400">URL</span>
            <input
              value={scopeUrl}
              onChange={(event) => setScopeUrl(event.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Environment</span>
            <select
              value={scopeEnvironment}
              onChange={(event) => setScopeEnvironment(event.target.value)}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="production">production</option>
              <option value="staging">staging</option>
              <option value="preview">preview</option>
              <option value="lab">lab</option>
              <option value="development">development</option>
            </select>
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Allowed hosts</span>
            <textarea
              value={scopeHosts}
              onChange={(event) => setScopeHosts(event.target.value)}
              rows={3}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
          <label className="block">
            <span className="text-xs text-gray-400">Allowed root domains</span>
            <textarea
              value={scopeRoots}
              onChange={(event) => setScopeRoots(event.target.value)}
              rows={3}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
          <label className="block lg:col-span-2">
            <span className="text-xs text-gray-400">Redirect destinations to validate</span>
            <textarea
              value={scopeRedirects}
              onChange={(event) => setScopeRedirects(event.target.value)}
              rows={2}
              className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            />
          </label>
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <Button type="button" variant="secondary" onClick={() => void previewScope()} disabled={scopeLoading}>
            {scopeLoading ? 'Validating...' : 'Preview receipt'}
          </Button>
          {scopeError && <span role="alert" className="text-sm text-red-300">{scopeError}</span>}
        </div>
        {scopePreview && (
          <div className="mt-4 rounded-md border border-gray-800 bg-gray-950 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <Badge className={scopePreview.verdict === 'allowed' ? statusClass('read_only') : scopePreview.verdict === 'blocked' ? statusClass('out_of_scope') : statusClass('dry_run')}>
                {scopePreview.verdict}
              </Badge>
              <span className="font-mono text-xs text-gray-400">{scopePreview.receipt_id}</span>
              <span className="text-xs text-gray-500">persisted receipt preview</span>
            </div>
            <div className="mt-3 grid gap-2 text-xs text-gray-500 md:grid-cols-2">
              <div>host: <span className="text-gray-300">{String(scopePreview.normalized_scope.host || 'none')}</span></div>
              <div>blocked: <span className="text-gray-300">{scopePreview.blocked_by.length ? scopePreview.blocked_by.join(', ') : 'none'}</span></div>
              <div>warnings: <span className="text-gray-300">{scopePreview.warnings.length ? scopePreview.warnings.join(', ') : 'none'}</span></div>
              <div>redirects: <span className="text-gray-300">{scopePreview.redirect_destinations.length}</span></div>
            </div>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {scopePreview.checks.slice(0, 8).map((check) => (
                <Badge key={`${check.name}-${check.status}`} className={check.status === 'passed' ? statusClass('read_only') : check.status === 'blocked' ? statusClass('out_of_scope') : statusClass('dry_run')}>
                  {check.name}: {check.status}
                </Badge>
              ))}
            </div>
            <div className="mt-4 border-t border-gray-800 pt-3">
              <div className="mb-3 flex flex-wrap items-center gap-2">
                <span className="text-sm font-medium text-white">Approval Receipt</span>
                <Badge className="bg-gray-800 text-gray-300">no execution</Badge>
              </div>
              <div className="grid gap-3 md:grid-cols-3">
                <label className="block">
                  <span className="text-xs text-gray-400">Risk tier</span>
                  <select
                    value={approvalRiskTier}
                    onChange={(event) => setApprovalRiskTier(event.target.value)}
                    className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
                  >
                    <option value="active">active</option>
                    <option value="intrusive">intrusive</option>
                    <option value="credential">credential</option>
                    <option value="dangerous">dangerous</option>
                  </select>
                </label>
                <label className="block">
                  <span className="text-xs text-gray-400">Approved by</span>
                  <input
                    value={approvalActor}
                    onChange={(event) => setApprovalActor(event.target.value)}
                    className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
                  />
                </label>
                <label className="block">
                  <span className="text-xs text-gray-400">Denial reason</span>
                  <input
                    value={denialReason}
                    onChange={(event) => setDenialReason(event.target.value)}
                    className="mt-1 w-full rounded-md border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
                  />
                </label>
              </div>
              <div className="mt-3 flex flex-wrap items-center gap-3">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => void recordApproval('approve')}
                  disabled={approvalLoading || scopePreview.verdict === 'blocked'}
                >
                  Record approval
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => void recordApproval('deny')}
                  disabled={approvalLoading}
                >
                  Record denial
                </Button>
                {approvalError && <span role="alert" className="text-sm text-red-300">{approvalError}</span>}
              </div>
              {approvalReceipt && (
                <div className="mt-3 rounded-md border border-gray-800 bg-gray-900 px-3 py-2 text-xs text-gray-400">
                  Receipt: <span className="font-mono text-gray-200">{approvalReceipt.id}</span>
                  <span className="mx-2 text-gray-700">|</span>
                  {approvalReceipt.approved_by ? 'approved' : 'denied'}
                  <span className="mx-2 text-gray-700">|</span>
                  execution disabled
                </div>
              )}
            </div>
          </div>
        )}
      </Card>

      <Card className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <TerminalSquare className="h-4 w-4 text-blue-300" aria-hidden="true" />
            <h2 className="font-medium text-white">Command Schemas</h2>
          </div>
          {commands && <Badge className="bg-gray-800 text-gray-300">execution disabled</Badge>}
        </div>
        {loading ? (
          <div className="space-y-3">
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
          </div>
        ) : !commands?.commands.length ? (
          <EmptyState message="No commands are registered." />
        ) : (
          <div className="grid gap-3 xl:grid-cols-2">
            {[...readOnlyCommands, ...gatedCommands].map((command) => (
              <CommandRow key={command.name} command={command} />
            ))}
          </div>
        )}
      </Card>

      <Card className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Boxes className="h-4 w-4 text-cyan-300" aria-hidden="true" />
            <h2 className="font-medium text-white">Integrated Tool Status</h2>
          </div>
          {tools && (
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(tools.summary).map(([status, count]) => (
                <Badge key={status} className={statusClass(status)}>{status}: {count}</Badge>
              ))}
            </div>
          )}
        </div>
        {loading ? (
          <div className="space-y-3">
            <Skeleton className="h-24" />
            <Skeleton className="h-24" />
          </div>
        ) : visibleTools.length === 0 ? (
          <EmptyState message="No tools are registered." />
        ) : (
          <div className="grid gap-3 xl:grid-cols-2">
            {visibleTools.map((tool) => (
              <ToolRow key={tool.tool_name} tool={tool} />
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
