'use client'
import { featureEnabled } from '@/lib/workspaceCapabilities'
import { DeleteRecordsButton } from '@/components/lifecycle/DeleteRecordsButton'

import { startHuntV2Native } from '@/lib/huntV2'
import { useEffect, useMemo, useRef, useState, useCallback, Suspense } from 'react'
import { BrainCircuit, ExternalLink, Loader2, ShieldCheck } from 'lucide-react'
import { useParams, useSearchParams, useRouter } from 'next/navigation'
import Link from '@/components/WorkspaceLink'
import {
  formatDate,
  createTargetPolicyApproval,
  createFindingException,
  deleteFindingException,
  extractFindingTriage,
  getFinding,
  getFindingExceptions,
  getFindingRetests,
  getFindingEvidence,
  getPolicyProfiles,
  getTarget,
  retestFinding,
  retestAiFinding,
  updateFinding,
  getFindingResearchProvenance,
  type Finding,
  type FindingException,
  type PolicyProfile,
  type RetestRecord,
  type EvidenceObject
} from '@/lib/api'
import { FINDING_STATUSES, RETEST_VERDICT_LABELS, type FindingSourceType } from '@/lib/constants'
import { formatAnomaly, parseEvidence, extractEndpoint, decodePayload } from '@/lib/evidence-parser'
import { canonicalFindingProofVerified } from '@/lib/findingProof'
import { formatRelativeTime } from '@/lib/format'
import { findingObservation, hostOf, pathOf, verificationSource } from '@/lib/findingObservation'
import {
  Button,
  ConfirmDialog,
  ErrorState,
  ProofStateBadge,
  RetestVerdictBadge,
  SeverityBadge,
  SourceTypeBadge,
  useToast,
} from '@/components/ui'
import { CopyButton } from '@/components/findings/detail/CopyButton'
import { HowToFix } from '@/components/findings/detail/HowToFix'
import { EvidenceObjectsList } from '@/components/findings/detail/EvidenceObjectsList'
import { ExceptionDialog, type ExceptionFormValues } from '@/components/findings/detail/ExceptionDialog'
import { Fact, Section } from '@/components/findings/detail/Section'
import { WhatWeFound } from '@/components/findings/detail/WhatWeFound'

function getFindingSourceType(finding: Finding): FindingSourceType {
  if (finding.source === 'device') {
    return 'Device'
  }
  if (finding.source === 'model_intake' || finding.tool === 'model_intake') {
    return 'Model Intake'
  }
  if (finding.source === 'ai_gate' || finding.ai_target_id) {
    return 'AI Gate'
  }
  if (finding.source === 'ai_session') {
    return 'Interactive'
  }
  if (finding.source === 'autonomous' || finding.tool === 'autonomous_workflow' || getFindingResearchProvenance(finding)) {
    return 'Hunt'
  }
  if (finding.source === 'asm') {
    return 'ASM'
  }
  if (finding.source === 'manual') {
    return 'Manual'
  }
  return 'DAST'
}

function isAiReplayFinding(finding: Finding): boolean {
  const sourceType = getFindingSourceType(finding)
  return sourceType === 'AI Gate' || sourceType === 'Interactive'
}

function autonomousWebTargetUrl(finding: Finding): string | null {
  const sourceType = getFindingSourceType(finding)
  if (!finding.target_id || !(['DAST', 'Hunt', 'ASM', 'Manual'] as FindingSourceType[]).includes(sourceType)) return null
  const candidate = finding.target_url || finding.url
  if (!candidate) return null
  try {
    const parsed = new URL(candidate)
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed.toString() : null
  } catch {
    return null
  }
}

function autonomousUnsupportedReason(finding: Finding): string {
  const sourceType = getFindingSourceType(finding)
  if (sourceType === 'Model Intake') {
    return 'Model Intake findings must be investigated by re-running the artifact check.'
  }
  if (sourceType === 'AI Gate' || sourceType === 'Interactive') {
    return 'These findings use their dedicated replay workflow; web verification supports DAST, Hunt, ASM, and manual findings.'
  }
  if (!finding.target_id) {
    return 'This finding is not linked to a ShakerScan web target.'
  }
  return 'Autonomous investigation requires an HTTP or HTTPS target.'
}

function recommendationList(value: unknown): string[] {
  if (Array.isArray(value)) return value.map((item) => String(item)).filter(Boolean)
  if (typeof value === 'string' && value.trim()) {
    try {
      const parsed = JSON.parse(value)
      if (Array.isArray(parsed)) return parsed.map((item) => String(item)).filter(Boolean)
      if (typeof parsed === 'string') return [parsed]
    } catch {
      // Plain prose, not JSON.
    }
    return [value.trim()]
  }
  if (value && typeof value === 'object') return [JSON.stringify(value, null, 2)]
  return []
}

function formatTriageReason(value: string | undefined): string {
  if (!value) return ''
  return value.replaceAll('_', ' ')
}

function TriagePanel({ finding }: { finding: Finding }) {
  const triage = extractFindingTriage(finding)
  if (!triage) return null

  const policy = triage.precision_policy
  const hasSomethingToShow =
    triage.verified === true ||
    triage.suspected === true ||
    triage.needs_verification === true ||
    !!triage.verification_reason ||
    !!policy?.confidence_cap_reason ||
    policy?.severity_downgraded === true ||
    policy?.confidence_capped === true

  if (!hasSomethingToShow) return null

  const downgradedFromSeverity = policy?.original_severity
  const cappedFromConfidence = policy?.original_confidence
  const capReason = policy?.confidence_cap_reason

  return (
    <Section title="Scanner triage">
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          {triage.verified === true && (
            <span className="px-2 py-0.5 rounded-sm bg-emerald-500/20 text-emerald-300 text-xs font-medium">
              verified
            </span>
          )}
          {triage.suspected === true && (
            <span className="px-2 py-0.5 rounded-sm bg-amber-500/20 text-amber-300 text-xs font-medium">
              suspected lead
            </span>
          )}
          {triage.needs_verification === true && (
            <span className="px-2 py-0.5 rounded-sm bg-yellow-500/20 text-yellow-300 text-xs font-medium">
              needs verification
            </span>
          )}
          {triage.confidence_tier && (
            <span className="px-2 py-0.5 rounded-sm bg-gray-800 text-gray-300 text-xs">
              confidence tier: {triage.confidence_tier}
            </span>
          )}
          {typeof triage.confidence === 'number' && (
            <span className="px-2 py-0.5 rounded-sm bg-gray-800 text-gray-300 text-xs">
              confidence: {Math.round(triage.confidence * 100)}%
            </span>
          )}
        </div>

        {(downgradedFromSeverity || typeof cappedFromConfidence === 'number') && (
          <div className="rounded-sm border border-gray-800 bg-gray-950 p-3 text-xs text-gray-300">
            <p className="text-gray-400 font-medium mb-2">Precision policy adjustments</p>
            <div className="space-y-1">
              {downgradedFromSeverity && (
                <div>
                  Severity downgraded from{' '}
                  <span className="font-medium text-gray-200">{downgradedFromSeverity}</span> to{' '}
                  <span className="font-medium text-gray-200">{finding.severity}</span>.
                </div>
              )}
              {typeof cappedFromConfidence === 'number' && (
                <div>
                  Confidence capped from{' '}
                  <span className="font-medium text-gray-200">
                    {Math.round(cappedFromConfidence * 100)}%
                  </span>
                  {typeof triage.confidence === 'number' && (
                    <>
                      {' '}to{' '}
                      <span className="font-medium text-gray-200">
                        {Math.round(triage.confidence * 100)}%
                      </span>
                    </>
                  )}
                  .
                </div>
              )}
              {capReason && (
                <div className="text-gray-400">
                  Reason: <span className="text-gray-200">{formatTriageReason(capReason)}</span>
                </div>
              )}
            </div>
          </div>
        )}

        {triage.verification_reason && (
          <div className="rounded-sm border border-gray-800 bg-gray-950 p-3 text-xs">
            <p className="text-gray-400 font-medium mb-1">Verification reason</p>
            <p className="text-gray-200">{triage.verification_reason}</p>
          </div>
        )}
      </div>
    </Section>
  )
}

const STATUS_LABELS: Record<string, string> = {
  active: 'Active',
  resolved: 'Resolved',
  false_positive: 'False positive',
  accepted_risk: 'Accepted risk',
}

const ANALYST_VERDICTS = [
  { value: 'true_positive', label: 'True positive', status: 'active' },
  { value: 'false_positive', label: 'False positive', status: 'false_positive' },
  { value: 'duplicate', label: 'Duplicate', status: 'false_positive' },
  { value: 'accepted_risk', label: 'Accepted risk', status: 'accepted_risk' },
  { value: 'retest_needed', label: 'Retest needed', status: 'active' },
] as const

function asEvidenceObject(rawEvidence: string): Record<string, unknown> | null {
  if (!rawEvidence) return null
  try {
    const parsed = JSON.parse(rawEvidence)
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : null
  } catch {
    return null
  }
}

function redactEvidenceForDisplay(value: string): string {
  return value
    .replace(/("(?:authorization|cookie|set-cookie|password|token|api[_-]?key)"\s*:\s*")[^"]*(")/gi, '$1[redacted]$2')
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [redacted]')
}

function evidenceString(evidence: Record<string, unknown> | null, key: string): string {
  const value = evidence?.[key]
  return typeof value === 'string' ? value : ''
}

function evidenceStringList(evidence: Record<string, unknown> | null, key: string): string[] {
  const value = evidence?.[key]
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []
}

function FindingDetailContent() {
  const params = useParams()
  const searchParams = useSearchParams()
  const router = useRouter()
  const toast = useToast()
  const findingId = params.id as string
  const [finding, setFinding] = useState<Finding | null>(null)
  const [evidenceObjects, setEvidenceObjects] = useState<EvidenceObject[]>([])
  const [evidenceProvenance, setEvidenceProvenance] = useState<{
    originalFindingScanId?: string | null
    latestObservationScanId?: string | null
  }>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [statusUpdating, setStatusUpdating] = useState(false)
  const [exceptionToDelete, setExceptionToDelete] = useState<string | null>(null)
  const [exceptionDeleting, setExceptionDeleting] = useState(false)
  const [autonomousConfirmOpen, setAutonomousConfirmOpen] = useState(false)
  const [autonomousLoading, setAutonomousLoading] = useState(false)
  const [retestLoading, setRetestLoading] = useState(false)
  const [retestMessage, setRetestMessage] = useState<string | null>(null)
  const [retestMode, setRetestMode] = useState<'tiered' | 'deterministic' | 'ai' | 'same_probe' | 'same_family' | 'strict_replay'>('tiered')
  const [retestHistory, setRetestHistory] = useState<RetestRecord[]>([])
  const [targetInactive, setTargetInactive] = useState(false)
  const [historyExpanded, setHistoryExpanded] = useState(false)
  const [findingExceptions, setFindingExceptions] = useState<FindingException[]>([])
  const [policyProfiles, setPolicyProfiles] = useState<PolicyProfile[]>([])
  const [exceptionSaving, setExceptionSaving] = useState(false)
  const [exceptionDialogOpen, setExceptionDialogOpen] = useState(false)

  // Build back URL with preserved filters
  const backUrl = useMemo(() => {
    const returnParams = new URLSearchParams()
    searchParams.forEach((value, key) => {
      if (key.startsWith('return_')) {
        returnParams.set(key.replace('return_', ''), value)
      }
    })
    const queryString = returnParams.toString()
    return queryString ? `/findings?${queryString}` : '/findings'
  }, [searchParams])

  const fetchFinding = useCallback(async () => {
    try {
      const data = await getFinding(findingId)
      const [retestData, evidenceData, exceptionData, policyData, targetData] = await Promise.all([
        getFindingRetests(findingId, 10).catch(() => null),
        getFindingEvidence(findingId).catch(() => null),
        getFindingExceptions(data.target_id ? { target_id: data.target_id } : undefined).catch(() => null),
        getPolicyProfiles().catch(() => null),
        data.target_id ? getTarget(data.target_id).catch(() => null) : Promise.resolve(null),
      ])
      setFinding(data)
      setTargetInactive(targetData ? targetData.is_active === false : false)
      if (retestData) {
        setRetestHistory(retestData.retests || [])
      }
      setEvidenceObjects(evidenceData?.evidence_objects || [])
      setEvidenceProvenance({
        originalFindingScanId: evidenceData?.original_finding_scan_id,
        latestObservationScanId: evidenceData?.latest_observation_scan_id,
      })
      const exceptions = (exceptionData?.finding_exceptions || []).filter((item) =>
        item.finding_id === data.id || (data.fingerprint && item.fingerprint === data.fingerprint)
      )
      setFindingExceptions(exceptions)
      setPolicyProfiles(policyData?.policy_profiles || [])
      setError(null)
    } catch {
      setError('Failed to load finding details')
    } finally {
      setLoading(false)
    }
  }, [findingId])

  useEffect(() => {
    fetchFinding()
  }, [fetchFinding])

  const hasPendingRetest = retestHistory.some((r) => r.status === 'queued' || r.status === 'running')

  // While a retest is queued/running, poll so the verdict and verification
  // summary update live instead of requiring a manual page refresh.
  useEffect(() => {
    if (!hasPendingRetest) return
    const interval = setInterval(() => { void fetchFinding() }, 4000)
    return () => clearInterval(interval)
  }, [hasPendingRetest, fetchFinding])

  // Announce the result when a retest transitions from pending -> finished, so
  // the user gets a clear "it ran" signal instead of a banner stuck at "queued".
  const prevPendingRetest = useRef(false)
  useEffect(() => {
    if (prevPendingRetest.current && !hasPendingRetest) {
      const latest = retestHistory[0]
      const verdict = latest?.verdict || latest?.result_status || ''
      const label = RETEST_VERDICT_LABELS[verdict] || verdict.replace(/_/g, ' ') || 'complete'
      setRetestMessage(`Retest complete — ${label}`)
      if (verdict === 'exploited' || verdict === 'likely_vulnerable') {
        toast.error(`Retest: ${label}`)
      } else if (verdict === 'likely_fixed') {
        toast.success(`Retest: ${label}`)
      } else {
        toast.info(`Retest complete — ${label}`)
      }
    }
    prevPendingRetest.current = hasPendingRetest
  }, [hasPendingRetest, retestHistory, toast])

  async function handleStatusChange(newStatus: string) {
    if (!finding || statusUpdating) return
    try {
      setStatusUpdating(true)
      await updateFinding(finding.id, newStatus, undefined, finding.scan_id)
      await fetchFinding()
      toast.success(`Status updated to ${newStatus.replaceAll('_', ' ')}`)
    } catch (err) {
      console.error('Failed to update finding:', err)
      toast.error('Failed to update finding status')
    } finally {
      setStatusUpdating(false)
    }
  }

  async function handleAnalystVerdict(verdict: typeof ANALYST_VERDICTS[number]) {
    if (!finding || statusUpdating) return
    try {
      setStatusUpdating(true)
      await updateFinding(finding.id, verdict.status, finding.notes, finding.scan_id, verdict.value)
      await fetchFinding()
      toast.success(`Analyst verdict set to ${verdict.label.toLowerCase()}`)
    } catch (err) {
      console.error('Failed to update analyst verdict:', err)
      toast.error('Failed to update analyst verdict')
    } finally {
      setStatusUpdating(false)
    }
  }

  async function handleCreateException(exceptionForm: ExceptionFormValues): Promise<boolean> {
    if (!finding || exceptionSaving) return false
    const owner = exceptionForm.owner.trim()
    const approver = exceptionForm.approver.trim()
    const reason = exceptionForm.reason.trim()
    const controls = exceptionForm.compensating_controls.trim()
    if (!exceptionForm.policy_id) {
      toast.error('Select the exact policy this exception applies to')
      return false
    }
    if (!owner || !approver || !reason || !controls) {
      toast.error('Owner, approver, reason, and compensating controls are all required')
      return false
    }
    const days = Number(exceptionForm.expires_days || 30)
    if (!Number.isFinite(days) || days < 1) {
      toast.error('Expiry must be at least 1 day')
      return false
    }
    const expiresAt = new Date(Date.now() + Math.round(days) * 24 * 60 * 60 * 1000).toISOString()
    try {
      setExceptionSaving(true)
      await createFindingException({
        finding_id: finding.id,
        fingerprint: finding.fingerprint || null,
        target_id: finding.target_id || null,
        policy_id: exceptionForm.policy_id || null,
        scope: finding.title,
        owner: owner || null,
        approver: approver || null,
        reason,
        compensating_controls: controls,
        status: 'active',
        expires_at: expiresAt,
      })
      await fetchFinding()
      toast.success('Policy exception created')
      return true
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to create exception')
      return false
    } finally {
      setExceptionSaving(false)
    }
  }

  async function handleDeleteException() {
    const exceptionId = exceptionToDelete
    if (!exceptionId || exceptionDeleting) return
    setExceptionDeleting(true)
    try {
      await deleteFindingException(exceptionId)
      setFindingExceptions((prev) => prev.filter((item) => item.id !== exceptionId))
      toast.success('Policy exception deleted')
      setExceptionToDelete(null)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to delete exception')
    } finally {
      setExceptionDeleting(false)
    }
  }

  async function handleRetest() {
    if (!finding || retestLoading) return
    try {
      setRetestLoading(true)
      setRetestMessage(null)
      const aiFinding = isAiReplayFinding(finding)
      const effectiveMode = selectedRetestMode
      const queued = aiFinding
        ? await retestAiFinding(finding.id, {
            requested_by: 'ui',
            mode: ['same_probe', 'same_family', 'strict_replay'].includes(effectiveMode)
              ? effectiveMode as 'same_probe' | 'same_family' | 'strict_replay'
              : 'same_probe'
          })
        : await retestFinding(
            finding.id,
            { requested_by: 'ui' },
            effectiveMode === 'tiered' || ['same_probe', 'same_family', 'strict_replay'].includes(effectiveMode)
              ? undefined
              : effectiveMode as 'ai' | 'deterministic'
          )
      setRetestMessage(`${aiFinding ? 'AI Gate replay' : 'Retest'} queued (${queued.retest_id.slice(0, 8)}...)`)
      toast.success(`${aiFinding ? 'AI Gate replay' : 'Retest'} queued`)
      const history = await getFindingRetests(finding.id, 10)
      setRetestHistory(history.retests || [])
      await fetchFinding()
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to queue retest'
      console.error('Failed to queue retest:', err)
      setRetestMessage(message)
      toast.error(message)
    } finally {
      setRetestLoading(false)
    }
  }

  async function handleAutonomousInvestigation() {
    if (!finding || autonomousLoading) return
    const targetUrl = autonomousWebTargetUrl(finding)
    if (!finding.target_id || !targetUrl) {
      toast.error(autonomousUnsupportedReason(finding))
      return
    }
    try {
      setAutonomousLoading(true)
      // Canonical Hunt, not a Research episode: one investigation runtime owns
      // this. The finding is carried as the run's goal so the agent starts with
      // the same subject the old episode bound, and the run opens on /hunt.
      const approvalReceiptId = await createTargetPolicyApproval(finding.target_id, targetUrl, 30)
      const hunt = await startHuntV2Native({
        targetId: finding.target_id,
        targetKind: 'web',
        goal:
          `Verify finding ${finding.id} on ${targetUrl}: ` +
          `${finding.title || 'untitled finding'}. Confirm or refute it with evidence.`,
        budgetProfile: 'balanced',
        policy: {
          activeTesting: true,
          allowStateChangingHttp: false,
          networkDiscovery: false,
          allowOobInteractions: false,
          authorizationConfirmed: true,
          approvalReceiptId,
        },
      })
      setAutonomousConfirmOpen(false)
      toast.success('Hunt started for this finding')
      router.push(`/hunt?run=${encodeURIComponent(hunt.hunt_id)}`)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to start autonomous investigation')
    } finally {
      setAutonomousLoading(false)
    }
  }

  const evidence = useMemo(() => parseEvidence(finding?.evidence), [finding?.evidence])
  const primaryUrl = finding?.url || evidence.url || finding?.target_url || ''
  const request = finding?.request || evidence.request
  const response = finding?.response || evidence.response
  const statusCode = evidence.statusCode
  const responseAnomaly = evidence.responseAnomaly
  const summaryDescription = finding?.description || evidence.description || ''
  const showSummaryDescription = Boolean(
    summaryDescription.trim()
    && summaryDescription.trim().toLowerCase() !== String(finding?.title || '').trim().toLowerCase()
  )
  const rawEvidence =
    finding?.evidence && typeof finding.evidence === 'string'
      ? finding.evidence
      : finding?.evidence
      ? JSON.stringify(finding.evidence, null, 2)
      : ''
  const rawEvidenceObject = useMemo(() => asEvidenceObject(rawEvidence), [rawEvidence])
  const rawEvidenceDisplay = rawEvidenceObject ? JSON.stringify(rawEvidenceObject, null, 2) : rawEvidence
  const isAiFinding = finding ? isAiReplayFinding(finding) : false
  const research = finding ? getFindingResearchProvenance(finding) : null
  const autonomousTargetUrl = finding ? autonomousWebTargetUrl(finding) : null
  const latestRetest = retestHistory[0]
  const latestRetestVerdict = latestRetest?.verdict || latestRetest?.result_status || finding?.latest_retest_verdict
  const latestRetestStatus = latestRetest?.status || finding?.latest_retest_status
  const latestRetestConfidence = latestRetest?.confidence ?? finding?.latest_retest_confidence
  const latestRetestCompletedAt = latestRetest?.completed_at || finding?.latest_retest_completed_at
  const canonicalProofVerified = canonicalFindingProofVerified(finding)
  const canonicalProofState = canonicalProofVerified
    ? 'Deterministically verified'
    : finding?.is_suspected === true || finding?.proof_state === 'suspected'
      ? 'Suspected — proof not satisfied'
      : 'Not deterministically verified'
  const latestAiRetest = retestHistory.find((entry) => (
    entry.verification_mode === 'ai_driven' && Boolean(entry.ai_reasoning || entry.ai_plan || entry.verdict)
  ))
  // An inconclusive retest that is retryable means "we couldn't decide, try
  // again" — distinct from a terminal verdict. Surfaced so users understand the
  // finding stays active because verification didn't conclude.
  const lastVerdictInconclusive = latestRetestVerdict === 'inconclusive'
  const lastRetestRetryable = Boolean(
    lastVerdictInconclusive && latestRetest && latestRetest.status !== 'queued' && latestRetest.status !== 'running' && latestRetest.retryable
  )
  const retestSupported = finding?.retest_supported !== false
  const deviceFinding = finding ? getFindingSourceType(finding) === 'Device' : false
  const retestModes = finding?.retest_modes
  const dastRetestOptions = [
    { value: 'tiered', label: 'Tiered' },
    { value: 'deterministic', label: 'Deterministic only' },
    { value: 'ai', label: 'AI only' },
  ].filter((option) => !retestModes || retestModes.includes(option.value))
  const retestOptions = isAiFinding
    ? [
        { value: 'same_probe', label: 'Same probe' },
        { value: 'same_family', label: 'Same family' },
        { value: 'strict_replay', label: 'Strict replay' },
      ]
    : dastRetestOptions.length > 0
    ? dastRetestOptions
    : [{ value: 'tiered', label: 'Tiered' }]
  const selectedRetestMode = retestOptions.some((option) => option.value === retestMode)
    ? retestMode
    : retestOptions[0].value
  const retestUnsupportedMessage =
    finding?.retest_unsupported_reason === 'model_intake'
      ? 'Model Intake findings are re-checked by re-running the Model Intake scan for the artifact.'
      : featureEnabled('engine_admin')
        ? 'No deterministic prover covers this finding type. Enable AI verification in AI settings to retest it.'
        : 'No automated retest is available for this finding type in this workspace.'
  const manualVerifyCommands = evidenceStringList(rawEvidenceObject, 'verify_commands')
  const aiProbePrompt = evidenceString(rawEvidenceObject, 'prompt')
  const aiResponseExcerpt = evidenceString(rawEvidenceObject, 'response_excerpt')
  const aiProbeId = evidenceString(rawEvidenceObject, 'probe_id')
  const aiTechnique = evidenceString(rawEvidenceObject, 'technique')
  const aiProbeFamily = evidenceString(rawEvidenceObject, 'probe_family')
  const aiJudgeLayer = evidenceString(rawEvidenceObject, 'judge_layer')
  const aiTactics = evidenceStringList(rawEvidenceObject, 'tactics')
  const hasAiProbeEvidence = isAiFinding && (aiProbePrompt || aiResponseExcerpt || aiProbeId || aiTechnique || aiProbeFamily || aiJudgeLayer)
  const observation = useMemo(() => findingObservation(finding?.evidence), [finding?.evidence])
  // The API falls back to the scan-time verification verdict when no retest has run; name it as
  // such instead of presenting it as a replay next to "0 attempts".
  const verificationKind = verificationSource({
    retestRuns: retestHistory.length,
    latestRetestStatus: latestRetestStatus,
    verificationCount: finding?.verification_count,
  })
  const verificationLabel = verificationKind === 'retest' ? 'Latest replay' : 'Scan-time check'
  const aiRecommendations = useMemo(() => recommendationList(finding?.ai_recommendations), [finding?.ai_recommendations])
  // The newest retest is always shown in the verification history; an advisory AI retest that is
  // that entry is not repeated as a separate analysis.
  const aiRetestShownInHistory = Boolean(latestAiRetest && latestAiRetest === retestHistory[0])
  const hasAiAnalysis = Boolean(finding?.ai_verdict || finding?.ai_rationale || aiRecommendations.length > 0 || (latestAiRetest && !aiRetestShownInHistory))
  const verifyApplicable = featureEnabled('hunt') && !deviceFinding && Boolean(autonomousTargetUrl)
  const locations = evidence.allUrls.length > 0 ? evidence.allUrls : primaryUrl ? [primaryUrl] : []
  const latestScanId = finding?.last_seen_scan_id || evidenceProvenance.latestObservationScanId || finding?.scan_id || ''
  const originalScanId = finding?.first_seen_scan_id || evidenceProvenance.originalFindingScanId || ''
  const hostLabel = finding?.target_name || hostOf(finding?.target_url) || hostOf(primaryUrl) || finding?.target_url || ''
  const huntUnavailableReason = verifyApplicable && targetInactive && !hasPendingRetest
    ? 'Target is deactivated — reactivate it under Targets to verify.'
    : null

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    )
  }

  if (error || !finding) {
    return (
      <ErrorState
        message={error || 'Finding not found'}
        onRetry={() => { setLoading(true); fetchFinding() }}
      />
    )
  }

  const retestControls = !deviceFinding && (
    <div className="flex items-center gap-1 rounded-lg border border-gray-800 bg-gray-950/60 p-1">
      <select
        value={selectedRetestMode}
        onChange={(e) => setRetestMode(e.target.value as typeof retestMode)}
        className="rounded-md border border-gray-700 bg-gray-900 px-2 py-1.5 text-xs text-gray-200 focus:border-blue-500 focus:outline-hidden"
        title="Retest mode"
        aria-label="Retest mode"
      >
        {retestOptions.map((option) => (
          <option key={option.value} value={option.value}>{option.label}</option>
        ))}
      </select>
      <button
        type="button"
        onClick={handleRetest}
        disabled={retestLoading || hasPendingRetest || !retestSupported}
        title={!retestSupported ? retestUnsupportedMessage : hasPendingRetest ? 'A proof replay is already queued or running.' : 'Replay this finding with one bounded verifier'}
        className="rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {retestLoading ? 'Queueing...' : hasPendingRetest ? 'Verifying…' : 'Retest'}
      </button>
    </div>
  )

  return (
    <div className="space-y-5">
      <header className="space-y-4">
        <Link
          href={backUrl}
          aria-label="Back to findings"
          className="inline-flex items-center gap-1 rounded-sm text-sm text-gray-400 hover:text-white focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          <svg aria-hidden="true" className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
          Findings
        </Link>

        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <ProofStateBadge proofState={finding.proof_state} />
              <SourceTypeBadge type={getFindingSourceType(finding)} />
            </div>
            <h1 className="mt-2 text-2xl font-semibold leading-tight text-white wrap-break-word">{finding.title}</h1>
            <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-gray-400">
              {hostLabel && (
                finding.target_id
                  ? <Link href={`/targets/${finding.target_id}/graph`} className="text-gray-200 hover:text-white" title="Open target">{hostLabel}</Link>
                  : <span className="text-gray-200">{hostLabel}</span>
              )}
              {primaryUrl && (
                <span className="inline-flex min-w-0 max-w-full items-center gap-1">
                  <code className="min-w-0 truncate font-mono text-xs text-blue-300" title={primaryUrl}>{pathOf(primaryUrl)}</code>
                  <CopyButton text={primaryUrl} label="Copy URL" />
                </span>
              )}
              {finding.cwe && (
                <a
                  href={`https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-400 hover:text-blue-300"
                  title={finding.cwe_name || undefined}
                >
                  {finding.cwe}
                </a>
              )}
              {finding.cvss_score !== undefined && finding.cvss_score !== null && (
                <span>CVSS <span className="text-gray-200">{finding.cvss_score}</span></span>
              )}
              {finding.last_seen_at && (
                <span title={formatDate(finding.last_seen_at)}>Last seen {formatRelativeTime(finding.last_seen_at)}</span>
              )}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 lg:max-w-md lg:justify-end">
            <label className="flex items-center gap-2 text-xs text-gray-500">
              Status
              <select
                value={finding.status}
                onChange={(e) => handleStatusChange(e.target.value)}
                disabled={statusUpdating}
                title="Canonical lifecycle — the finding's status. Retests and AI assessments never change it."
                className="rounded-lg border border-gray-700 bg-gray-900 px-2 py-1.5 text-sm text-gray-100 focus:border-blue-500 focus:outline-hidden disabled:opacity-50"
              >
                {FINDING_STATUSES.map((status) => (
                  <option key={status} value={status}>{STATUS_LABELS[status] || status.replaceAll('_', ' ')}</option>
                ))}
              </select>
            </label>
            {retestControls}
            {verifyApplicable && (
              <button
                type="button"
                onClick={() => setAutonomousConfirmOpen(true)}
                disabled={!autonomousTargetUrl || autonomousLoading || hasPendingRetest || targetInactive}
                title={
                  hasPendingRetest
                    ? 'A proof replay is already queued or running for this finding.'
                    : targetInactive
                      ? "This finding's target is deactivated. Reactivate it under Targets to verify."
                      : autonomousTargetUrl
                        ? 'Inspect this finding, run at most one bounded proof replay, and conclude from its result.'
                        : autonomousUnsupportedReason(finding)
                }
                className="inline-flex items-center gap-1.5 rounded-lg bg-violet-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-violet-500 disabled:cursor-not-allowed disabled:opacity-45"
              >
                <BrainCircuit className="h-3.5 w-3.5" aria-hidden="true" />
                Verify finding
              </button>
            )}
          </div>
        </div>

        {!deviceFinding && (
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border border-gray-800 bg-gray-900/60 px-3 py-2 text-sm">
            <span className="inline-flex items-center gap-2">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">Finding proof</span>
              <span className={`rounded px-2 py-0.5 text-xs font-medium ${canonicalProofVerified ? 'bg-emerald-500/15 text-emerald-300' : 'bg-amber-500/15 text-amber-300'}`}>
                {canonicalProofState}
              </span>
            </span>
            {(latestRetestVerdict || hasPendingRetest) && (
              <span className="inline-flex items-center gap-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">{verificationLabel}</span>
                <RetestVerdictBadge verdict={latestRetestVerdict} pending={hasPendingRetest} />
                {latestRetestCompletedAt && !hasPendingRetest && (
                  <span className="text-xs text-gray-500" title={formatDate(latestRetestCompletedAt)}>{formatRelativeTime(latestRetestCompletedAt)}</span>
                )}
              </span>
            )}
          </div>
        )}
      </header>

      <ConfirmDialog
        open={autonomousConfirmOpen}
        title="Authorize finding verification"
        message={
          <div className="space-y-2">
            <p>The verifier will inspect this exact finding, run at most one bounded proof replay against <span className="font-medium text-gray-200">{autonomousTargetUrl}</span>, wait for the result, and conclude.</p>
            <p>Continue only if you own this target or have explicit permission to test it. Active authorization expires after 30 minutes.</p>
          </div>
        }
        confirmLabel="Authorize and start"
        busy={autonomousLoading}
        onConfirm={handleAutonomousInvestigation}
        onCancel={() => setAutonomousConfirmOpen(false)}
      />

      <ConfirmDialog
        open={exceptionToDelete !== null}
        title="Delete policy exception"
        message="Remove this policy exception? The finding will be re-evaluated against the active deployment gate. This cannot be undone."
        confirmLabel="Delete exception"
        danger
        busy={exceptionDeleting}
        onConfirm={handleDeleteException}
        onCancel={() => setExceptionToDelete(null)}
      />

      <ExceptionDialog
        open={exceptionDialogOpen}
        policyProfiles={policyProfiles}
        saving={exceptionSaving}
        onClose={() => setExceptionDialogOpen(false)}
        onSubmit={handleCreateException}
      />

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <div className="min-w-0 space-y-5">
          <WhatWeFound
            observation={observation}
            description={showSummaryDescription ? summaryDescription : null}
            payloads={evidence.allPayloads.map(decodePayload)}
            signals={evidence.evidenceDetails}
            anomaly={responseAnomaly ? formatAnomaly(responseAnomaly) : null}
            aiProbe={hasAiProbeEvidence ? {
              prompt: aiProbePrompt,
              responseExcerpt: aiResponseExcerpt,
              probeId: aiProbeId,
              family: aiProbeFamily,
              technique: aiTechnique,
              judge: aiJudgeLayer,
              tactics: aiTactics,
            } : null}
          />

          <HowToFix remediation={finding.remediation} toolSteps={evidence.remediation} />

          {locations.length > 0 && (
            <Section
              id="locations"
              title={locations.length === 1 ? 'Location' : `Locations (${locations.length})`}
              actions={evidence.parameter ? <span className="text-xs text-gray-500">Parameter <code className="font-mono text-purple-300">{evidence.parameter}</code></span> : undefined}
            >
              <ul className="space-y-1.5">
                {locations.map((url, i) => {
                  // A path-only location belongs to the finding's target; show and copy it in full.
                  const full = /^[a-z][a-z0-9+.-]*:\/\//i.test(url) || !finding?.target_url ? url : `${finding.target_url.replace(/\/+$/, '')}${url.startsWith('/') ? '' : '/'}${url}`
                  return (
                  <li key={i} className="flex items-start justify-between gap-2 rounded-md bg-gray-950/70 px-2.5 py-2">
                    <div className="min-w-0 flex-1">
                      <code className="block font-mono text-xs text-blue-300 break-all">{extractEndpoint(url)}</code>
                      {hostOf(full) && <span className="text-xs text-gray-500">{hostOf(full)}</span>}
                    </div>
                    <div className="flex shrink-0 items-center gap-1">
                      <CopyButton text={full} label="Copy full URL" />
                      {/^https?:\/\//i.test(full) && (
                        <a
                          href={full}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="rounded-sm p-1 transition-colors hover:bg-gray-800"
                          title="Open in new tab"
                          aria-label="Open in new tab"
                        >
                          <ExternalLink className="h-3.5 w-3.5 text-gray-400" aria-hidden="true" />
                        </a>
                      )}
                    </div>
                  </li>
                  )
                })}
              </ul>
            </Section>
          )}

          {(request || response) && (
            <Section id="http" title="HTTP request and response">
              <div className="grid gap-3 xl:grid-cols-2">
                {request && (
                  <details open={request.length < 4000} className="min-w-0 rounded-md border border-gray-800 bg-gray-950/70 p-3">
                    <summary className="cursor-pointer text-sm text-gray-300">Request</summary>
                    <pre className="mt-2 max-h-96 overflow-auto whitespace-pre-wrap text-xs text-gray-300 wrap-break-word">{request}</pre>
                  </details>
                )}
                {response && (
                  <details open={response.length < 4000} className="min-w-0 rounded-md border border-gray-800 bg-gray-950/70 p-3">
                    <summary className="cursor-pointer text-sm text-gray-300">Response{statusCode ? ` · ${statusCode}` : ''}</summary>
                    <pre className="mt-2 max-h-96 overflow-auto whitespace-pre-wrap text-xs text-gray-300 wrap-break-word">{response}</pre>
                  </details>
                )}
              </div>
            </Section>
          )}

          <Section id="retest" title="Proof and verification">
            <div className="space-y-3">
              <div className={`rounded border px-3 py-2 ${
                canonicalProofVerified
                  ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-100'
                  : 'border-amber-500/30 bg-amber-500/10 text-amber-100'
              }`}>
                <p className="flex items-center gap-2 text-sm font-medium">
                  <ShieldCheck className="h-4 w-4 shrink-0" aria-hidden="true" />
                  Canonical finding proof: {canonicalProofState}
                </p>
                <p className="mt-1 text-xs text-gray-300">
                  {canonicalProofVerified
                    ? 'The stored scan-time deterministic proof contract was satisfied. Later replay and AI assessments remain separate evidence and cannot downgrade that proof.'
                    : 'No stored deterministic proof contract currently verifies this finding. Replay and AI assessments may inform triage but do not become proof by themselves.'}
                </p>
              </div>

              <p className="text-sm text-gray-300">
                {verificationKind === 'scan_time'
                  ? latestRetestVerdict
                    ? <>No retest has run yet. The scan-time check recorded <span className="font-medium text-gray-100">{(RETEST_VERDICT_LABELS[latestRetestVerdict] || latestRetestVerdict.replaceAll('_', ' ')).toLowerCase()}</span>{typeof latestRetestConfidence === 'number' ? ` at ${Math.round(latestRetestConfidence * 100)}% confidence` : ''}{latestRetestCompletedAt ? ` ${formatRelativeTime(latestRetestCompletedAt)}` : ''}.</>
                    : 'No retest has run yet.'
                  : <>
                      {finding.verification_count ?? retestHistory.length} {(finding.verification_count ?? retestHistory.length) === 1 ? 'retest' : 'retests'} run.
                      {latestRetestStatus && <> Latest {latestRetestStatus.replaceAll('_', ' ')}</>}
                      {typeof latestRetestConfidence === 'number' && <>, {Math.round(latestRetestConfidence * 100)}% confidence</>}
                      {latestRetestCompletedAt && <>, {formatRelativeTime(latestRetestCompletedAt)}</>}.
                    </>}
              </p>

              {!retestSupported && (
                <div className="rounded-sm border border-amber-900/60 bg-amber-900/30 px-2 py-1 text-xs text-amber-300">
                  Automated retest unavailable: {retestUnsupportedMessage}
                </div>
              )}
              {huntUnavailableReason && (
                <p className="text-xs text-amber-300/80">Hunt verification unavailable: {huntUnavailableReason}</p>
              )}
              {manualVerifyCommands.length > 0 && (
                <div>
                  <p className="mb-1 text-xs text-gray-500">Manual verification commands (from evidence)</p>
                  <div className="space-y-1">
                    {manualVerifyCommands.map((command, idx) => (
                      <div key={idx} className="flex items-start gap-1">
                        <code className="flex-1 text-[11px] text-blue-300 break-all">{command}</code>
                        <CopyButton text={command} label="Copy verification command" />
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {hasPendingRetest && (
                <div className="inline-flex items-center gap-2 rounded-sm border border-blue-900/60 bg-blue-900/30 px-2 py-1 text-xs text-blue-300">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                  Verifying… results update automatically
                </div>
              )}
              {retestMessage && (
                <div className={`rounded px-2 py-1 text-xs ${
                  retestMessage.includes('Failed')
                    ? 'border border-red-900/60 bg-red-900/30 text-red-300'
                    : 'border border-blue-900/60 bg-blue-900/30 text-blue-300'
                }`}>
                  {retestMessage}
                </div>
              )}
              {finding.status === 'active' && lastVerdictInconclusive && verificationKind === 'retest' && (
                <div className="rounded-sm border border-gray-700 bg-gray-800/60 px-2 py-1.5 text-xs text-gray-300">
                  This finding remains <span className="text-yellow-400">active</span> because the latest retest was{' '}
                  <span className="text-amber-300">inconclusive</span> — verification did not conclude
                  {lastRetestRetryable ? ' and is retryable' : ''}. Retest verdicts inform triage; the
                  finding status is set by analysts using the status control.
                </div>
              )}
              {finding.status === 'active' && latestRetestVerdict === 'false_positive' && (
                <div className="rounded-sm border border-gray-700 bg-gray-800/60 px-2 py-1.5 text-xs text-gray-300">
                  The latest retest judged this a <span className="text-gray-300">false positive</span> with high
                  confidence. The finding is still <span className="text-yellow-400">active</span> — retests never
                  change finding status automatically. Set the status to{' '}
                  <span className="text-gray-300">false positive</span> if you agree.
                </div>
              )}

              {retestHistory.length > 0 && (
                <div className="space-y-2">
                  {(historyExpanded || hasPendingRetest ? retestHistory : retestHistory.slice(0, 1)).map((entry) => (
                    <div key={entry.id} className="rounded-sm bg-gray-800/60 p-2 text-xs">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-1.5 text-gray-300">
                          {(entry.status === 'queued' || entry.status === 'running') ? (
                            <>
                              <Loader2 className="h-3 w-3 animate-spin text-blue-400" aria-hidden="true" />
                              <span>{entry.finding_type} • {entry.status}</span>
                            </>
                          ) : (
                            <>
                              <span className="text-gray-400">{entry.finding_type}</span>
                              <RetestVerdictBadge verdict={entry.verdict || entry.result_status} />
                              {entry.result_status && entry.result_status !== entry.verdict && (
                                <span className="text-gray-500">({entry.result_status.replaceAll('_', ' ')})</span>
                              )}
                              {entry.retryable && (
                                <span className="rounded-sm bg-amber-500/15 px-1.5 py-0.5 text-[10px] text-amber-300/90">retryable</span>
                              )}
                            </>
                          )}
                        </div>
                        <div className="text-gray-500">
                          {entry.completed_at
                            ? formatDate(entry.completed_at)
                            : entry.created_at
                            ? formatDate(entry.created_at)
                            : 'N/A'}
                        </div>
                      </div>
                      {entry.verification_mode && (
                        <div className="mt-1 text-gray-400">
                          mode: {entry.verification_mode.replaceAll('_', ' ')}
                        </div>
                      )}
                      {entry.primary_tested_endpoint && (
                        <div className="mt-1 flex min-w-0 gap-1 text-gray-400">
                          <span className="shrink-0">primary tested endpoint:</span>
                          <code className="break-all text-blue-300">{entry.primary_tested_endpoint}</code>
                        </div>
                      )}
                      {Array.isArray(entry.tested_endpoints) && entry.tested_endpoints.length > 1 && (
                        <details className="mt-1 rounded-sm border border-gray-700/70 bg-gray-900/40 px-2 py-1.5">
                          <summary className="cursor-pointer text-gray-300">
                            Tested scope ({entry.tested_endpoints.length} endpoints)
                          </summary>
                          <ul className="mt-1 space-y-1">
                            {entry.tested_endpoints.map((endpoint) => (
                              <li key={endpoint}><code className="break-all text-blue-300">{endpoint}</code></li>
                            ))}
                          </ul>
                        </details>
                      )}
                      <div className="mt-1 flex flex-wrap gap-2 text-gray-400">
                        <span>deterministic proof: <strong className={entry.deterministic_proof_state === 'proven' ? 'text-emerald-300' : 'text-amber-300'}>{entry.deterministic_proof_state === 'proven' ? 'proven' : 'not proven'}</strong></span>
                        {entry.result_status && <span>execution result: <strong className="font-medium text-gray-300">{entry.result_status.replaceAll('_', ' ')}</strong></span>}
                        {entry.verdict_basis === 'ai_assessment' && <span className="text-violet-300">verdict basis: advisory AI assessment</span>}
                      </div>
                      {typeof entry.confidence === 'number' && (
                        <div className="mt-1 text-gray-400">
                          confidence: {Math.round(entry.confidence * 100)}%
                        </div>
                      )}
                      {entry.verdict_reason && entry.verdict_reason !== entry.ai_reasoning && <div className="mt-1 text-gray-400">{entry.verdict_reason}</div>}
                      {!entry.verdict_reason && entry.message && entry.message !== entry.ai_reasoning && <div className="mt-1 text-gray-400">{entry.message}</div>}
                      {entry.ai_reasoning && (
                        <div className="mt-1 rounded-sm border border-violet-500/20 bg-violet-500/5 p-2 text-gray-400">
                          <span className="font-medium text-violet-300">AI assessment — advisory, cannot override deterministic proof:</span> {entry.ai_reasoning}
                        </div>
                      )}
                      {entry.ai_plan && (
                        <details className="mt-2">
                          <summary className="cursor-pointer text-blue-300">AI plan</summary>
                          <pre className="mt-1 whitespace-pre-wrap text-[11px] text-gray-300 break-all">{JSON.stringify(entry.ai_plan, null, 2)}</pre>
                        </details>
                      )}
                      {Array.isArray(entry.replay_commands) && entry.replay_commands.length > 0 && (
                        <div className="mt-2 space-y-1">
                          {entry.replay_commands.slice(0, 3).map((command, idx) => (
                            <div key={idx} className="flex items-start gap-1">
                              <code className="flex-1 text-[11px] text-blue-300 break-all">{command}</code>
                              <CopyButton text={command} label="Copy replay command" />
                            </div>
                          ))}
                        </div>
                      )}
                      {entry.error_message && <div className="mt-1 text-red-300">{entry.error_message}</div>}
                    </div>
                  ))}
                  {retestHistory.length > 1 && !hasPendingRetest && (
                    <button
                      type="button"
                      onClick={() => setHistoryExpanded((v) => !v)}
                      className="text-xs text-blue-300 transition-colors hover:text-blue-200"
                    >
                      {historyExpanded
                        ? 'Show less'
                        : `Show ${retestHistory.length - 1} older retest${retestHistory.length - 1 === 1 ? '' : 's'}`}
                    </button>
                  )}
                </div>
              )}
            </div>
          </Section>

          {hasAiAnalysis && (
            <Section id="ai-analysis" title="AI analysis">
              <div className="space-y-3">
                {finding.ai_verdict && (
                  <div className="flex items-center gap-2">
                    <span
                      className={`rounded px-2 py-0.5 text-xs font-medium ${
                        finding.ai_verdict === 'true_positive'
                          ? 'bg-red-900/50 text-red-300'
                          : finding.ai_verdict === 'false_positive'
                          ? 'bg-green-900/50 text-green-300'
                          : 'bg-yellow-900/50 text-yellow-300'
                      }`}
                    >
                      AI: {finding.ai_verdict.replace('_', ' ')}
                    </span>
                    {typeof finding.ai_confidence === 'number' && (
                      <span className="text-xs text-gray-400">
                        {finding.ai_confidence > 1
                          ? `${Math.round(finding.ai_confidence)}% confidence`
                          : `${Math.round(finding.ai_confidence * 100)}% confidence`}
                      </span>
                    )}
                  </div>
                )}
                {finding.ai_rationale && (
                  <div>
                    <p className="mb-1 text-xs text-gray-500">Rationale</p>
                    <p className="whitespace-pre-wrap text-sm text-gray-300">{finding.ai_rationale}</p>
                  </div>
                )}
                {aiRecommendations.length > 0 && (
                  <div>
                    <p className="mb-1 text-xs text-gray-500">Recommendations</p>
                    <ul className="list-inside list-disc space-y-1 text-sm text-gray-300">
                      {aiRecommendations.map((rec, idx) => (
                        <li key={idx} className="whitespace-pre-wrap wrap-break-word">{rec}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {!finding.ai_verdict && !finding.ai_rationale && aiRecommendations.length === 0 && latestAiRetest && !aiRetestShownInHistory && (
                  <div className="rounded-sm border border-violet-500/25 bg-violet-500/5 p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded-sm bg-violet-500/15 px-2 py-0.5 text-xs font-medium text-violet-300">
                        Latest advisory AI retest
                      </span>
                      {latestAiRetest.verdict && (
                        <span className="text-xs text-gray-300">{latestAiRetest.verdict.replaceAll('_', ' ')}</span>
                      )}
                      {typeof latestAiRetest.confidence === 'number' && (
                        <span className="text-xs text-gray-400">{Math.round(latestAiRetest.confidence * 100)}% confidence</span>
                      )}
                    </div>
                    <p className="mt-2 text-xs text-violet-200/80">
                      Advisory only — this assessment cannot override the canonical deterministic proof state.
                    </p>
                    {latestAiRetest.ai_reasoning && (
                      <p className="mt-2 whitespace-pre-wrap text-sm text-gray-300">{latestAiRetest.ai_reasoning}</p>
                    )}
                  </div>
                )}
              </div>
            </Section>
          )}

          <TriagePanel finding={finding} />
        </div>

        <aside className="min-w-0 space-y-5" aria-label="Finding status and history">
          <Section id="triage" title="Triage">
            <div className="space-y-3">
              <label className="grid gap-1 text-xs text-gray-500">
                Analyst verdict
                <select
                  value={finding.analyst_verdict || ''}
                  onChange={(e) => {
                    const verdict = ANALYST_VERDICTS.find((item) => item.value === e.target.value)
                    if (verdict) void handleAnalystVerdict(verdict)
                  }}
                  disabled={statusUpdating}
                  className="rounded-lg border border-gray-700 bg-gray-900 px-2 py-1.5 text-sm text-gray-100 focus:border-blue-500 focus:outline-hidden disabled:opacity-50"
                >
                  <option value="" disabled>No verdict recorded</option>
                  {ANALYST_VERDICTS.map((verdict) => (
                    <option key={verdict.value} value={verdict.value}>{verdict.label}</option>
                  ))}
                </select>
              </label>
              <p className="text-xs text-gray-500">
                {finding.analyst_verdict && finding.analyst_verdict_at
                  ? `Recorded ${formatRelativeTime(finding.analyst_verdict_at)}. `
                  : ''}
                Setting a verdict also updates the status.
              </p>
              {finding.notes && (
                <div className="rounded-md bg-gray-950/70 p-3">
                  <p className="mb-1 text-xs text-gray-500">Analyst notes</p>
                  <p className="whitespace-pre-wrap text-sm text-gray-200">{finding.notes}</p>
                </div>
              )}
            </div>
          </Section>

          <Section id="tracking" title="History">
            <dl className="divide-y divide-gray-800/70">
              <Fact label="First seen"><span title={formatDate(finding.first_seen_at)}>{formatRelativeTime(finding.first_seen_at)}</span></Fact>
              <Fact label="Last seen"><span title={formatDate(finding.last_seen_at)}>{formatRelativeTime(finding.last_seen_at)}</span></Fact>
              {finding.resolved_at && (
                <Fact label="Resolved"><span title={formatDate(finding.resolved_at)}>{formatRelativeTime(finding.resolved_at)}</span></Fact>
              )}
              {evidence.duplicateCount > 0 && <Fact label="Occurrences">{evidence.duplicateCount}</Fact>}
              {typeof finding.resurfaced_count === 'number' && finding.resurfaced_count > 0 && (
                <Fact label="Returned after resolve">{finding.resurfaced_count}×</Fact>
              )}
              <Fact label="Source">{getFindingSourceType(finding)}</Fact>
              {finding.owasp && <Fact label="OWASP">{finding.owasp}</Fact>}
            </dl>
            <div className="mt-3 space-y-1.5 border-t border-gray-800/70 pt-3 text-xs">
              {originalScanId && (
                <p className="flex min-w-0 items-center gap-2">
                  <span className="shrink-0 text-gray-500">Original finding scan:</span>
                  <Link href={`/scans/${originalScanId}`} className="truncate font-mono text-blue-400 hover:text-blue-300" title={originalScanId}>{originalScanId.slice(0, 8)}</Link>
                </p>
              )}
              {latestScanId && (
                <p className="flex min-w-0 items-center gap-2">
                  <span className="shrink-0 text-gray-500">Latest observation scan:</span>
                  <Link href={`/scans/${latestScanId}`} className="truncate font-mono text-blue-400 hover:text-blue-300" title={latestScanId}>{latestScanId.slice(0, 8)}</Link>
                </p>
              )}
              {finding.target_id && (
                <p>
                  <Link href={`/findings?target_id=${encodeURIComponent(finding.target_id)}&status=active&freshness=all`} className="text-blue-400 hover:text-blue-300">
                    Other open findings on this target →
                  </Link>
                </p>
              )}
              {research && (
                <p className="flex min-w-0 items-center gap-2">
                  <span className="shrink-0 text-gray-500">Discovered by:</span>
                  <span className="text-indigo-300">Hunt</span>
                  {research.campaign_id && (
                    <Link href={`/deep-hunt/runs/${research.campaign_id}`} className="text-blue-400 hover:text-blue-300">
                      run {research.campaign_id.slice(0, 8)}
                    </Link>
                  )}
                </p>
              )}
            </div>
          </Section>

          <Section
            id="exceptions"
            title="Policy exceptions"
            actions={
              <Button size="sm" variant="secondary" onClick={() => setExceptionDialogOpen(true)}>
                Accept risk…
              </Button>
            }
          >
            {findingExceptions.length > 0 ? (
              <ul className="space-y-2">
                {findingExceptions.map((item) => (
                  <li key={item.id} className="rounded-md border border-gray-800 bg-gray-950/70 p-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0 space-y-1">
                        <div className="flex flex-wrap items-center gap-2 text-xs">
                          <span className={`rounded-sm px-2 py-0.5 ${item.status === 'active' ? 'bg-green-900/40 text-green-200' : 'bg-gray-800 text-gray-400'}`}>
                            {item.status}
                          </span>
                          {item.expires_at && <span className="text-gray-500" title={formatDate(item.expires_at)}>expires {formatRelativeTime(item.expires_at)}</span>}
                        </div>
                        {item.reason && <p className="text-sm text-gray-300 wrap-break-word">{item.reason}</p>}
                        <p className="text-xs text-gray-500 wrap-break-word">
                          {[item.owner && `owner ${item.owner}`, item.approver && `approver ${item.approver}`].filter(Boolean).join(' · ')}
                        </p>
                        {item.compensating_controls && <p className="text-xs text-gray-500 wrap-break-word">controls: <span className="text-gray-300">{item.compensating_controls}</span></p>}
                        {item.policy_id && <p className="font-mono text-[11px] text-gray-600 break-all">policy {item.policy_id}</p>}
                      </div>
                      <button
                        type="button"
                        onClick={() => setExceptionToDelete(item.id)}
                        className="shrink-0 rounded-sm border border-red-900/70 px-2 py-1 text-xs text-red-300 hover:bg-red-950/40 focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
                      >
                        Delete
                      </button>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-gray-500">None. The release gate counts this finding while it is open.</p>
            )}
          </Section>
        </aside>
      </div>

      <details className="group rounded-lg border border-gray-800 bg-gray-900/60">
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-gray-300 hover:text-white">
          Technical details
          <span className="ml-2 text-xs font-normal text-gray-500">identifiers, stored evidence records, raw evidence</span>
        </summary>
        <div className="space-y-5 border-t border-gray-800 px-4 py-4">
          <dl className="grid gap-x-6 gap-y-2 text-xs sm:grid-cols-2">
            <div className="flex min-w-0 items-center gap-2">
              <dt className="shrink-0 text-gray-500">Finding ID</dt>
              <dd className="flex min-w-0 items-center gap-1"><code className="break-all text-gray-300">{finding.id}</code><CopyButton text={finding.id} label="Copy finding ID" /></dd>
            </div>
            {finding.target_id && (
              <div className="flex min-w-0 items-center gap-2">
                <dt className="shrink-0 text-gray-500">Target ID</dt>
                <dd className="flex min-w-0 items-center gap-1"><code className="break-all text-gray-300">{finding.target_id}</code><CopyButton text={finding.target_id} label="Copy target ID" /></dd>
              </div>
            )}
            {latestScanId && (
              <div className="flex min-w-0 items-center gap-2">
                <dt className="shrink-0 text-gray-500">Latest observation scan ID</dt>
                <dd className="flex min-w-0 items-center gap-1"><code className="break-all text-gray-300">{latestScanId}</code><CopyButton text={latestScanId} label="Copy latest observation scan ID" /></dd>
              </div>
            )}
            {finding.tool && (
              <div className="flex min-w-0 items-center gap-2">
                <dt className="shrink-0 text-gray-500">Detector</dt>
                <dd className="min-w-0"><code className="break-all text-gray-300">{finding.tool}</code></dd>
              </div>
            )}
            {finding.fingerprint && (
              <div className="flex min-w-0 items-center gap-2">
                <dt className="shrink-0 text-gray-500">Fingerprint</dt>
                <dd className="min-w-0"><code className="break-all text-gray-400">{finding.fingerprint}</code></dd>
              </div>
            )}
          </dl>

          <EvidenceObjectsList objects={evidenceObjects} findingId={findingId} />

          {rawEvidence && (
            <div>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">Raw evidence</h3>
              <pre className="max-h-[32rem] overflow-auto rounded-md border border-gray-800 bg-gray-950 p-3 text-xs text-gray-300 whitespace-pre-wrap wrap-break-word">{redactEvidenceForDisplay(rawEvidenceDisplay)}</pre>
            </div>
          )}

          {/* Record deletion is an admin lifecycle action, not a triage decision, so it lives here
              in low emphasis. Same double gate as the Findings list. */}
          {featureEnabled('record_deletion') && featureEnabled('engine_admin') && (
            <section aria-labelledby="manage-record-heading" className="border-t border-gray-800 pt-4">
              <h3 id="manage-record-heading" className="text-xs font-semibold uppercase tracking-wider text-gray-500">Manage record</h3>
              <p className="mt-1 max-w-2xl text-sm text-gray-500">
                Deleting removes this finding&apos;s database record permanently after a preview and approval.
                Historical scans and evidence files are retained. To close a finding, change its status instead.
              </p>
              <div className="mt-3">
                <DeleteRecordsButton
                  variant="ghost"
                  className="text-red-400 hover:bg-red-500/10 hover:text-red-300"
                  label="Delete finding"
                  subject="finding"
                  selection={{ kind: 'findings', finding_ids: [finding.id], scan_id: finding.scan_id || undefined }}
                  onDeleted={() => router.push(backUrl)}
                />
              </div>
            </section>
          )}
        </div>
      </details>
    </div>
  )
}

export default function FindingDetailPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    }>
      <FindingDetailContent />
    </Suspense>
  )
}
