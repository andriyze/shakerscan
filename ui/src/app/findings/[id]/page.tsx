'use client'

import { useEffect, useMemo, useRef, useState, useCallback, Suspense } from 'react'
import { BrainCircuit, Check, Copy, ExternalLink, Loader2 } from 'lucide-react'
import { useParams, useSearchParams, useRouter } from 'next/navigation'
import Link from 'next/link'
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
  getResearchReadiness,
  launchResearchEpisode,
  retestFinding,
  retestAiFinding,
  updateFinding,
  deleteFinding,
  getFindingResearchProvenance,
  type Finding,
  type FindingException,
  type PolicyProfile,
  type RetestRecord,
  type EvidenceObject
} from '@/lib/api'
import { FINDING_STATUSES, RETEST_VERDICT_LABELS, type FindingSourceType } from '@/lib/constants'
import { formatAnomaly, parseEvidence, extractEndpoint, decodePayload } from '@/lib/evidence-parser'
import {
  Card,
  ConfirmDialog,
  ErrorState,
  FindingStatusBadge,
  RetestVerdictBadge,
  SectionCard,
  SeverityBadge,
  SourceTypeBadge,
  useToast,
} from '@/components/ui'

function getFindingSourceType(finding: Finding): FindingSourceType {
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
    return 'Deep Hunt'
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
  if (!finding.target_id || !(['DAST', 'Deep Hunt', 'ASM', 'Manual'] as FindingSourceType[]).includes(sourceType)) return null
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
    return 'These findings use their dedicated replay workflow; web verification supports DAST, Deep Hunt, ASM, and manual findings.'
  }
  if (!finding.target_id) {
    return 'This finding is not linked to a ShakerScan web target.'
  }
  return 'Autonomous investigation requires an HTTP or HTTPS target.'
}

function InfoItem({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-xs text-gray-500">{label}</p>
      <div className="text-sm text-gray-200 mt-1">{children}</div>
    </div>
  )
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
    <SectionCard title="Triage">
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          {triage.verified === true && (
            <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 text-xs font-medium">
              verified
            </span>
          )}
          {triage.suspected === true && (
            <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 text-xs font-medium">
              suspected lead
            </span>
          )}
          {triage.needs_verification === true && (
            <span className="px-2 py-0.5 rounded bg-yellow-500/20 text-yellow-300 text-xs font-medium">
              needs verification
            </span>
          )}
          {triage.confidence_tier && (
            <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-300 text-xs">
              confidence tier: {triage.confidence_tier}
            </span>
          )}
          {typeof triage.confidence === 'number' && (
            <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-300 text-xs">
              confidence: {Math.round(triage.confidence * 100)}%
            </span>
          )}
        </div>

        {(downgradedFromSeverity || typeof cappedFromConfidence === 'number') && (
          <div className="rounded border border-gray-800 bg-gray-950 p-3 text-xs text-gray-300">
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
          <div className="rounded border border-gray-800 bg-gray-950 p-3 text-xs">
            <p className="text-gray-400 font-medium mb-1">Verification reason</p>
            <p className="text-gray-200">{triage.verification_reason}</p>
          </div>
        )}
      </div>
    </SectionCard>
  )
}

const ANALYST_VERDICTS = [
  { value: 'true_positive', label: 'True positive', status: 'active' },
  { value: 'false_positive', label: 'False positive', status: 'false_positive' },
  { value: 'duplicate', label: 'Duplicate', status: 'false_positive' },
  { value: 'accepted_risk', label: 'Accepted risk', status: 'accepted_risk' },
  { value: 'retest_needed', label: 'Retest needed', status: 'active' },
] as const

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

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

function evidenceObjectContentText(content: unknown): string {
  if (content === undefined || content === null) return ''
  if (typeof content === 'string') {
    try {
      return JSON.stringify(JSON.parse(content), null, 2)
    } catch {
      return content
    }
  }
  try {
    return JSON.stringify(content, null, 2)
  } catch {
    return String(content)
  }
}

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy:', err)
    }
  }

  return (
    <button
      onClick={handleCopy}
      className="p-1 rounded hover:bg-gray-800 transition-colors"
      title={label || 'Copy'}
      aria-label={label || 'Copy'}
      type="button"
    >
      {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5 text-gray-400" />}
    </button>
  )
}

function FindingDetailContent() {
  const params = useParams()
  const searchParams = useSearchParams()
  const router = useRouter()
  const toast = useToast()
  const findingId = params.id as string
  const [finding, setFinding] = useState<Finding | null>(null)
  const [evidenceObjects, setEvidenceObjects] = useState<EvidenceObject[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [statusUpdating, setStatusUpdating] = useState(false)
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [exceptionToDelete, setExceptionToDelete] = useState<string | null>(null)
  const [exceptionDeleting, setExceptionDeleting] = useState(false)
  const [autonomousConfirmOpen, setAutonomousConfirmOpen] = useState(false)
  const [autonomousLoading, setAutonomousLoading] = useState(false)
  const [retestLoading, setRetestLoading] = useState(false)
  const [retestMessage, setRetestMessage] = useState<string | null>(null)
  const [retestMode, setRetestMode] = useState<'tiered' | 'deterministic' | 'ai' | 'same_probe' | 'same_family' | 'strict_replay'>('tiered')
  const [retestHistory, setRetestHistory] = useState<RetestRecord[]>([])
  const [historyExpanded, setHistoryExpanded] = useState(false)
  const [findingExceptions, setFindingExceptions] = useState<FindingException[]>([])
  const [policyProfiles, setPolicyProfiles] = useState<PolicyProfile[]>([])
  const [exceptionSaving, setExceptionSaving] = useState(false)
  const [exceptionForm, setExceptionForm] = useState({
    owner: '',
    approver: '',
    reason: '',
    compensating_controls: '',
    policy_id: '',
    expires_days: '30',
  })

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
      const [retestData, evidenceData, exceptionData, policyData] = await Promise.all([
        getFindingRetests(findingId, 10).catch(() => null),
        getFindingEvidence(findingId).catch(() => null),
        getFindingExceptions(data.target_id ? { target_id: data.target_id } : undefined).catch(() => null),
        getPolicyProfiles().catch(() => null),
      ])
      setFinding(data)
      if (retestData) {
        setRetestHistory(retestData.retests || [])
      }
      setEvidenceObjects(evidenceData?.evidence_objects || [])
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

  async function handleCreateException(event: React.FormEvent) {
    event.preventDefault()
    if (!finding || exceptionSaving) return
    const owner = exceptionForm.owner.trim()
    const approver = exceptionForm.approver.trim()
    if (!owner && !approver) {
      toast.error('Owner or approver is required')
      return
    }
    const days = Number(exceptionForm.expires_days || 30)
    if (!Number.isFinite(days) || days < 1) {
      toast.error('Expiry must be at least 1 day')
      return
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
        reason: exceptionForm.reason.trim() || null,
        compensating_controls: exceptionForm.compensating_controls.trim() || null,
        status: 'active',
        expires_at: expiresAt,
      })
      setExceptionForm({
        owner: '',
        approver: '',
        reason: '',
        compensating_controls: '',
        policy_id: '',
        expires_days: '30',
      })
      await fetchFinding()
      toast.success('Policy exception created')
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to create exception')
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

  async function handleDelete() {
    if (!finding || deleting) return
    try {
      setDeleting(true)
      await deleteFinding(finding.id)
      setDeleteConfirmOpen(false)
      toast.success('Finding deleted')
      router.push(backUrl)
    } catch (err) {
      console.error('Failed to delete finding:', err)
      toast.error('Failed to delete finding')
      setDeleting(false)
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
      const readiness = await getResearchReadiness()
      if (!readiness.planner_ready) throw new Error('Configure an AI model before starting an autonomous investigation.')
      if (!readiness.execution_enabled) throw new Error('Autonomous active execution is disabled by server policy.')
      const approvalReceiptId = await createTargetPolicyApproval(finding.target_id, targetUrl, 30)
      const detail = await launchResearchEpisode({
        subject_type: 'finding',
        subject_id: finding.id,
        mission_profile: 'verify_finding',
        intensity: 'hunt',
        approval_receipt_id: approvalReceiptId,
        autopilot: true,
        created_by: 'finding_detail_ui',
      })
      setAutonomousConfirmOpen(false)
      toast.success(detail.reused ? 'Opened the existing autonomous investigation' : 'Autonomous investigation started')
      router.push(`/deep-hunt/runs/${encodeURIComponent(detail.episode.id)}`)
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
  const rawEvidence =
    finding?.evidence && typeof finding.evidence === 'string'
      ? finding.evidence
      : finding?.evidence
      ? JSON.stringify(finding.evidence, null, 2)
      : ''
  const rawEvidenceObject = useMemo(() => asEvidenceObject(rawEvidence), [rawEvidence])
  const isAiFinding = finding ? isAiReplayFinding(finding) : false
  const research = finding ? getFindingResearchProvenance(finding) : null
  const autonomousTargetUrl = finding ? autonomousWebTargetUrl(finding) : null
  const latestRetest = retestHistory[0]
  // An inconclusive retest that is retryable means "we couldn't decide, try
  // again" — distinct from a terminal verdict. Surfaced so users understand the
  // finding stays active because verification didn't conclude.
  const lastVerdictInconclusive = finding?.last_verification_verdict === 'inconclusive'
  const lastRetestRetryable = Boolean(
    lastVerdictInconclusive && latestRetest && latestRetest.status !== 'queued' && latestRetest.status !== 'running' && latestRetest.retryable
  )
  const retestSupported = finding?.retest_supported !== false
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
      : 'No deterministic prover covers this finding type. Enable AI verification in AI settings to retest it.'
  const manualVerifyCommands = evidenceStringList(rawEvidenceObject, 'verify_commands')
  const aiProbePrompt = evidenceString(rawEvidenceObject, 'prompt')
  const aiResponseExcerpt = evidenceString(rawEvidenceObject, 'response_excerpt')
  const aiProbeId = evidenceString(rawEvidenceObject, 'probe_id')
  const aiTechnique = evidenceString(rawEvidenceObject, 'technique')
  const aiProbeFamily = evidenceString(rawEvidenceObject, 'probe_family')
  const aiJudgeLayer = evidenceString(rawEvidenceObject, 'judge_layer')
  const aiTactics = evidenceStringList(rawEvidenceObject, 'tactics')
  const hasAiProbeEvidence = isAiFinding && (aiProbePrompt || aiResponseExcerpt || aiProbeId || aiTechnique || aiProbeFamily || aiJudgeLayer)

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

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <Link href={backUrl} className="text-gray-400 hover:text-white">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </Link>
          <h1 className="text-2xl font-bold text-white">Finding Detail</h1>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => setAutonomousConfirmOpen(true)}
            disabled={!autonomousTargetUrl || autonomousLoading || hasPendingRetest}
            title={
              hasPendingRetest
                ? 'A proof replay is already queued or running for this finding.'
                : autonomousTargetUrl
                  ? 'Inspect this finding, run at most one bounded proof replay, and conclude from its result.'
                  : autonomousUnsupportedReason(finding)
            }
            className="inline-flex items-center gap-2 rounded-lg bg-violet-600 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-violet-500 disabled:cursor-not-allowed disabled:opacity-45"
          >
            <BrainCircuit className="h-4 w-4" />
            Verify finding
          </button>
          {(!autonomousTargetUrl || hasPendingRetest) && (
            <span className={`max-w-64 text-xs leading-4 ${hasPendingRetest ? 'text-gray-500' : 'text-amber-300/80'}`}>
              {hasPendingRetest ? 'Available after the current proof replay finishes.' : autonomousUnsupportedReason(finding)}
            </span>
          )}
          <div className="flex flex-wrap items-center gap-2 rounded-lg border border-gray-800 bg-gray-950/50 p-1">
            <span className="pl-1 text-[10px] font-semibold uppercase tracking-wider text-gray-500">Proof replay</span>
            <RetestVerdictBadge
              verdict={finding.last_verification_verdict}
              pending={hasPendingRetest}
            />
            <select
              value={selectedRetestMode}
              onChange={(e) => setRetestMode(e.target.value as typeof retestMode)}
              className="px-2 py-1.5 bg-gray-900 border border-gray-700 rounded-lg text-xs text-gray-200 focus:outline-none focus:border-blue-500"
              title="Retest mode"
              aria-label="Retest mode"
            >
              {retestOptions.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
            <button
              onClick={handleRetest}
              disabled={retestLoading || hasPendingRetest || !retestSupported}
              title={!retestSupported ? retestUnsupportedMessage : hasPendingRetest ? 'A proof replay is already queued or running.' : 'Replay this finding with one bounded verifier'}
              className="px-3 py-1.5 bg-blue-900/50 text-blue-300 rounded-lg text-sm hover:bg-blue-900/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {retestLoading ? 'Queueing...' : 'Retest Finding'}
            </button>
          </div>
          <button
            onClick={() => setDeleteConfirmOpen(true)}
            className="px-3 py-1.5 bg-red-900/50 text-red-400 rounded-lg text-sm hover:bg-red-900/80 transition-colors"
          >
            Delete
          </button>
        </div>
      </div>

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
        open={deleteConfirmOpen}
        title="Delete finding"
        message="Delete this finding permanently? This cannot be undone."
        confirmLabel="Delete"
        danger
        busy={deleting}
        onConfirm={handleDelete}
        onCancel={() => setDeleteConfirmOpen(false)}
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

      <nav aria-label="Jump to section" className="flex flex-wrap items-center gap-1.5 rounded-lg border border-gray-800 bg-gray-900/60 p-2 text-xs">
        <span className="px-2 py-1 font-medium text-gray-500">Jump to</span>
        {([['overview', 'Overview'], ['tracking', 'Tracking'], ['retest', 'Retest'], ['evidence', 'Evidence'], ['ai-analysis', 'AI analysis'], ['http', 'HTTP']] as const).map(([anchor, label]) => (
          <a key={anchor} href={`#${anchor}`} className="rounded px-2 py-1 text-gray-400 transition-colors hover:bg-gray-800 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">{label}</a>
        ))}
      </nav>

      <SectionCard id="overview" title="Overview">
        <div className="flex flex-col gap-4">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                <FindingStatusBadge status={finding.status} />
                <SourceTypeBadge type={getFindingSourceType(finding)} />
                {finding.cvss_score !== undefined && (
                  <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-200 text-xs">
                    CVSS {finding.cvss_score}
                  </span>
                )}
                {finding.tool && (
                  <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-300 text-xs">
                    {finding.tool}
                  </span>
                )}
              </div>
              <h2 className="text-xl font-semibold text-white mt-2 break-words">{finding.title}</h2>
              {summaryDescription && (
                <p className="text-sm text-gray-300 mt-2 whitespace-pre-wrap">{summaryDescription}</p>
              )}
              <div className="flex flex-wrap gap-2 mt-3 text-xs text-gray-400">
                {finding.cwe && (
                  <a
                    href={`https://cwe.mitre.org/data/definitions/${finding.cwe.replace('CWE-', '')}.html`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-400 hover:text-blue-300"
                  >
                    {finding.cwe}{finding.cwe_name ? `: ${finding.cwe_name}` : ''}
                  </a>
                )}
                {finding.owasp && <span>{finding.owasp}</span>}
              </div>

              {/* Status change controls */}
              <div className="flex flex-wrap gap-2 mt-4">
                {FINDING_STATUSES.map((status) => (
                  <button
                    key={status}
                    onClick={() => handleStatusChange(status)}
                    disabled={finding.status === status || statusUpdating}
                    className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                      finding.status === status
                        ? 'bg-blue-600 text-white cursor-default'
                        : 'bg-gray-800 text-gray-400 hover:bg-gray-700 disabled:opacity-50'
                    }`}
                  >
                    {status.replace('_', ' ')}
                  </button>
                ))}
              </div>

              <div className="mt-4 rounded-lg border border-gray-800 bg-gray-950 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <p className="text-xs font-medium text-gray-300">Analyst validation</p>
                    <p className="mt-1 text-xs text-gray-500">
                      {finding.analyst_verdict
                        ? `${finding.analyst_verdict.replaceAll('_', ' ')}${finding.analyst_verdict_at ? ` on ${formatDate(finding.analyst_verdict_at)}` : ''}`
                        : 'No analyst verdict recorded'}
                    </p>
                  </div>
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {ANALYST_VERDICTS.map((verdict) => (
                    <button
                      key={verdict.value}
                      type="button"
                      onClick={() => handleAnalystVerdict(verdict)}
                      disabled={finding.analyst_verdict === verdict.value || statusUpdating}
                      className={`rounded px-2.5 py-1 text-xs font-medium ${
                        finding.analyst_verdict === verdict.value
                          ? 'bg-emerald-600 text-white'
                          : 'bg-gray-800 text-gray-300 hover:bg-gray-700 disabled:opacity-50'
                      }`}
                    >
                      {verdict.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="space-y-2 text-xs text-gray-400">
              <div className="flex items-center gap-2">
                <span>Finding ID:</span>
                <code className="text-gray-300 break-all">{finding.id}</code>
                <CopyButton text={finding.id} label="Copy finding ID" />
              </div>
              {research && (
                <div className="flex items-center gap-2">
                  <span>Discovered by:</span>
                  <span className="text-indigo-300">Deep hunt</span>
                  {research.campaign_id && (
                    <Link
                      href={`/deep-hunt/runs/${research.campaign_id}`}
                      className="text-blue-400 hover:text-blue-300"
                    >
                      View run {research.campaign_id.slice(0, 8)}…
                    </Link>
                  )}
                </div>
              )}
              {finding.scan_id && (
                <div className="flex items-center gap-2">
                  <span>Scan:</span>
                  <Link href={`/scans/${finding.scan_id}`} className="text-blue-400 hover:text-blue-300 break-all">
                    {finding.scan_id}
                  </Link>
                  <CopyButton text={finding.scan_id} label="Copy scan ID" />
                </div>
              )}
              {finding.target_id && (
                <div className="flex items-center gap-2">
                  <span>Target ID:</span>
                  <code className="text-gray-300 break-all">{finding.target_id}</code>
                  <CopyButton text={finding.target_id} label="Copy target ID" />
                </div>
              )}
              {(finding.target_name || finding.target_url) && (
                <div className="flex items-center gap-2">
                  <span>Target:</span>
                  <span className="text-gray-300">
                    {finding.target_name || finding.target_url}
                  </span>
                </div>
              )}
            </div>
          </div>

          {finding.notes && (
            <div className="bg-gray-800/60 rounded-lg p-3">
              <p className="text-xs text-gray-400 mb-1">Analyst notes</p>
              <p className="text-sm text-gray-200 whitespace-pre-wrap">{finding.notes}</p>
            </div>
          )}
        </div>
      </SectionCard>

      <TriagePanel finding={finding} />

      <SectionCard id="tracking" title="Tracking">
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
          <InfoItem label="First seen">{formatDate(finding.first_seen_at)}</InfoItem>
          <InfoItem label="Last seen">{formatDate(finding.last_seen_at)}</InfoItem>
          {finding.resolved_at && (
            <InfoItem label="Resolved at">{formatDate(finding.resolved_at)}</InfoItem>
          )}
          {finding.resurfaced_count !== undefined && (
            <InfoItem label="Resurfaced count">{finding.resurfaced_count}</InfoItem>
          )}
        </div>
      </SectionCard>

      <SectionCard title="Policy Exceptions">
        <div className="space-y-4">
          {findingExceptions.length > 0 ? (
            <div className="space-y-2">
              {findingExceptions.map((item) => (
                <div key={item.id} className="rounded-lg border border-gray-800 bg-gray-950 p-3">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        <span className={`rounded px-2 py-0.5 ${item.status === 'active' ? 'bg-green-900/40 text-green-200' : 'bg-gray-800 text-gray-400'}`}>
                          {item.status}
                        </span>
                        {item.expires_at && <span className="text-gray-500">expires {formatDate(item.expires_at)}</span>}
                        {item.policy_id && <span className="font-mono text-gray-500">policy {item.policy_id}</span>}
                      </div>
                      {item.reason && <p className="mt-2 text-sm text-gray-300">{item.reason}</p>}
                      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-500">
                        {item.owner && <span>owner: <span className="text-gray-300">{item.owner}</span></span>}
                        {item.approver && <span>approver: <span className="text-gray-300">{item.approver}</span></span>}
                        {item.compensating_controls && <span>controls: <span className="text-gray-300">{item.compensating_controls}</span></span>}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => setExceptionToDelete(item.id)}
                      className="rounded border border-red-900/70 px-2 py-1 text-xs text-red-300 hover:bg-red-950/40 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-lg border border-gray-800 bg-gray-950 p-3 text-sm text-gray-500">
              No active exception is recorded for this finding.
            </div>
          )}

          <form onSubmit={handleCreateException} className="rounded-lg border border-gray-800 bg-gray-950 p-3">
            <div className="grid gap-3 md:grid-cols-2">
              <label className="grid gap-1 text-sm text-gray-300">
                Owner
                <input
                  value={exceptionForm.owner}
                  onChange={(e) => setExceptionForm((prev) => ({ ...prev, owner: e.target.value }))}
                  className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white"
                  placeholder="team or person"
                />
              </label>
              <label className="grid gap-1 text-sm text-gray-300">
                Approver
                <input
                  value={exceptionForm.approver}
                  onChange={(e) => setExceptionForm((prev) => ({ ...prev, approver: e.target.value }))}
                  className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white"
                  placeholder="security approver"
                />
              </label>
              <label className="grid gap-1 text-sm text-gray-300">
                Policy
                <select
                  value={exceptionForm.policy_id}
                  onChange={(e) => setExceptionForm((prev) => ({ ...prev, policy_id: e.target.value }))}
                  className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white"
                >
                  <option value="">Any policy</option>
                  {policyProfiles.map((profile) => (
                    <option key={profile.id} value={profile.id}>{profile.name} ({profile.environment})</option>
                  ))}
                </select>
              </label>
              <label className="grid gap-1 text-sm text-gray-300">
                Expires in days
                <input
                  value={exceptionForm.expires_days}
                  onChange={(e) => setExceptionForm((prev) => ({ ...prev, expires_days: e.target.value }))}
                  className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white"
                  inputMode="numeric"
                />
              </label>
            </div>
            <div className="mt-3 grid gap-3 md:grid-cols-2">
              <label className="grid gap-1 text-sm text-gray-300">
                Reason
                <textarea
                  value={exceptionForm.reason}
                  onChange={(e) => setExceptionForm((prev) => ({ ...prev, reason: e.target.value }))}
                  className="min-h-24 rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white"
                  placeholder="Risk acceptance rationale"
                />
              </label>
              <label className="grid gap-1 text-sm text-gray-300">
                Compensating controls
                <textarea
                  value={exceptionForm.compensating_controls}
                  onChange={(e) => setExceptionForm((prev) => ({ ...prev, compensating_controls: e.target.value }))}
                  className="min-h-24 rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white"
                  placeholder="Controls, monitoring, or rollout constraints"
                />
              </label>
            </div>
            <div className="mt-3 flex justify-end">
              <button
                type="submit"
                disabled={exceptionSaving}
                className="rounded-lg bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
              >
                {exceptionSaving ? 'Creating...' : 'Create Exception'}
              </button>
            </div>
          </form>
        </div>
      </SectionCard>

      <SectionCard id="retest" title="Retest Verification">
        <div className="space-y-3">
          {!retestSupported && (
            <div className="text-xs rounded px-2 py-1 bg-amber-900/30 text-amber-300 border border-amber-900/60">
              Automated retest unavailable: {retestUnsupportedMessage}
            </div>
          )}
          {manualVerifyCommands.length > 0 && (
            <div>
              <p className="text-xs text-gray-500 mb-1">Manual verification commands (from evidence)</p>
              <div className="space-y-1">
                {manualVerifyCommands.map((command, idx) => (
                  <div key={idx} className="flex items-start gap-1">
                    <code className="text-[11px] text-blue-300 break-all flex-1">{command}</code>
                    <CopyButton text={command} label="Copy verification command" />
                  </div>
                ))}
              </div>
            </div>
          )}
          {hasPendingRetest && (
            <div className="inline-flex items-center gap-2 rounded bg-blue-900/30 border border-blue-900/60 px-2 py-1 text-xs text-blue-300">
              <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
              Verifying… results update automatically
            </div>
          )}
          {retestMessage && (
            <div className={`text-xs rounded px-2 py-1 ${
              retestMessage.includes('Failed')
                ? 'bg-red-900/30 text-red-300 border border-red-900/60'
                : 'bg-blue-900/30 text-blue-300 border border-blue-900/60'
            }`}>
              {retestMessage}
            </div>
          )}
          {finding.status === 'active' && lastVerdictInconclusive && (
            <div className="text-xs rounded px-2 py-1.5 bg-gray-800/60 text-gray-300 border border-gray-700">
              This finding remains <span className="text-yellow-400">active</span> because the latest retest was{' '}
              <span className="text-amber-300">inconclusive</span> — verification did not conclude
              {lastRetestRetryable ? ' and is retryable' : ''}. Retest verdicts inform triage; the
              finding status is set by analysts using the status controls below.
            </div>
          )}
          {finding.status === 'active' && finding.last_verification_verdict === 'false_positive' && (
            <div className="text-xs rounded px-2 py-1.5 bg-gray-800/60 text-gray-300 border border-gray-700">
              The latest retest judged this a <span className="text-gray-300">false positive</span> with high
              confidence. The finding is still <span className="text-yellow-400">active</span> — retests never
              change finding status automatically. Review and set the status to{' '}
              <span className="text-gray-300">false positive</span> below if you agree.
            </div>
          )}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
            <InfoItem label="Last status">
              <span className="capitalize">{finding.last_verification_status || 'not tested'}</span>
            </InfoItem>
            <InfoItem label="Last verdict">
              {finding.last_verification_verdict ? (
                <div className="flex flex-col items-start gap-1">
                  <RetestVerdictBadge verdict={finding.last_verification_verdict} />
                  {lastRetestRetryable && (
                    <span className="text-[11px] text-amber-300/80">retryable — re-run to retry</span>
                  )}
                </div>
              ) : (
                <span className="text-gray-400">n/a</span>
              )}
            </InfoItem>
            <InfoItem label="Last confidence">
              {typeof finding.last_verification_confidence === 'number'
                ? `${Math.round(finding.last_verification_confidence * 100)}%`
                : 'N/A'}
            </InfoItem>
            <InfoItem label="Last verified">
              {finding.last_verified_at ? formatDate(finding.last_verified_at) : 'N/A'}
            </InfoItem>
            <InfoItem label="Verification count">
              {finding.verification_count ?? 0}
            </InfoItem>
          </div>

          {retestHistory.length > 0 ? (
            <div className="space-y-2">
              {(historyExpanded || hasPendingRetest ? retestHistory : retestHistory.slice(0, 1)).map((entry) => (
                <div key={entry.id} className="bg-gray-800/60 rounded p-2 text-xs">
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
                            <span className="px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300/90 text-[10px]">retryable</span>
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
                    <div className="text-gray-400 mt-1">
                      mode: {entry.verification_mode.replaceAll('_', ' ')}
                    </div>
                  )}
                  {typeof entry.confidence === 'number' && (
                    <div className="text-gray-400 mt-1">
                      confidence: {Math.round(entry.confidence * 100)}%
                    </div>
                  )}
                  {entry.verdict_reason && <div className="text-gray-400 mt-1">{entry.verdict_reason}</div>}
                  {!entry.verdict_reason && entry.message && <div className="text-gray-400 mt-1">{entry.message}</div>}
                  {entry.ai_reasoning && (
                    <div className="text-gray-400 mt-1">
                      ai: {entry.ai_reasoning}
                    </div>
                  )}
                  {entry.ai_plan && (
                    <details className="mt-2">
                      <summary className="cursor-pointer text-blue-300">AI plan</summary>
                      <pre className="mt-1 text-[11px] text-gray-300 whitespace-pre-wrap break-all">{JSON.stringify(entry.ai_plan, null, 2)}</pre>
                    </details>
                  )}
                  {Array.isArray(entry.replay_commands) && entry.replay_commands.length > 0 && (
                    <div className="mt-2 space-y-1">
                      {entry.replay_commands.slice(0, 3).map((command, idx) => (
                        <div key={idx} className="flex items-start gap-1">
                          <code className="text-[11px] text-blue-300 break-all flex-1">{command}</code>
                          <CopyButton text={command} label="Copy replay command" />
                        </div>
                      ))}
                    </div>
                  )}
                  {entry.error_message && <div className="text-red-300 mt-1">{entry.error_message}</div>}
                </div>
              ))}
              {retestHistory.length > 1 && !hasPendingRetest && (
                <button
                  type="button"
                  onClick={() => setHistoryExpanded((v) => !v)}
                  className="text-xs text-blue-300 hover:text-blue-200 transition-colors"
                >
                  {historyExpanded
                    ? 'Show less'
                    : `Show ${retestHistory.length - 1} older retest${retestHistory.length - 1 === 1 ? '' : 's'}`}
                </button>
              )}
            </div>
          ) : (
            <p className="text-xs text-gray-500">No retests recorded yet.</p>
          )}
        </div>
      </SectionCard>

      <SectionCard id="evidence" title="Evidence Summary">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <InfoItem label="Primary URL">
            {primaryUrl ? (
              <div className="flex items-center gap-2">
                <code className="text-xs text-blue-300 break-all">{primaryUrl}</code>
                <CopyButton text={primaryUrl} label="Copy URL" />
              </div>
            ) : (
              <span className="text-gray-400 text-sm">Not provided</span>
            )}
          </InfoItem>
          {evidence.duplicateCount > 0 && (
            <InfoItem label="Occurrences">{evidence.duplicateCount}</InfoItem>
          )}
          {evidence.parameter && (
            <InfoItem label="Parameter">
              <code className="text-xs text-purple-300">{evidence.parameter}</code>
            </InfoItem>
          )}
          {evidence.payload && (
            <InfoItem label="Payload">
              <code className="text-xs text-yellow-300 break-all">{evidence.payload}</code>
            </InfoItem>
          )}
          {evidence.context && (
            <InfoItem label="Context">
              <span className="text-xs text-green-300">{evidence.context}</span>
            </InfoItem>
          )}
          {statusCode && (
            <InfoItem label="Status Code">
              <span className="text-xs text-gray-200">{statusCode}</span>
            </InfoItem>
          )}
          {responseAnomaly && (
            <InfoItem label="Response anomaly">
              <span className="text-xs text-yellow-300">{formatAnomaly(responseAnomaly)}</span>
            </InfoItem>
          )}
        </div>

        {/* Vulnerable URLs */}
        {evidence.allUrls.length > 0 && (
          <div className="mt-4">
            <p className="text-xs text-gray-500 mb-2">Vulnerable URLs ({evidence.allUrls.length})</p>
            <div className="space-y-2">
              {evidence.allUrls.map((url, i) => (
                <div key={i} className="bg-gray-800/60 rounded p-2 flex items-start justify-between gap-2">
                  <code className="text-xs text-blue-300 break-all flex-1">{extractEndpoint(url)}</code>
                  <div className="flex items-center gap-1 shrink-0">
                    <CopyButton text={url} label="Copy full URL" />
                    <a
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-1 rounded hover:bg-gray-700 transition-colors"
                      title="Open in new tab"
                    >
                      <ExternalLink className="w-3.5 h-3.5 text-gray-400" />
                    </a>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Working Payloads */}
        {evidence.allPayloads.length > 0 && (
          <div className="mt-4">
            <p className="text-xs text-gray-500 mb-2">Working Payloads ({evidence.allPayloads.length})</p>
            <div className="space-y-2">
              {evidence.allPayloads.map((payload, i) => (
                <div key={i} className="bg-gray-800/60 rounded p-2 flex items-start justify-between gap-2">
                  <code className="text-xs text-yellow-300 break-all flex-1">{decodePayload(payload)}</code>
                  <CopyButton text={decodePayload(payload)} label="Copy payload" />
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Remediation Steps */}
        {evidence.remediation.length > 0 && (
          <div className="mt-4">
            <p className="text-xs text-gray-500 mb-2">Remediation Steps</p>
            <div className="space-y-2">
              {evidence.remediation.map((step, i) => (
                <div key={i} className="flex items-start gap-3 text-sm">
                  <div className="w-5 h-5 rounded border border-gray-600 flex items-center justify-center shrink-0 mt-0.5">
                    <span className="text-xs text-gray-500">{i + 1}</span>
                  </div>
                  <span className="text-gray-300">{step}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {evidence.evidenceDetails.length > 0 && (
          <div className="mt-4 space-y-2">
            <p className="text-xs text-gray-500">Evidence signals</p>
            <ul className="space-y-1 text-sm text-gray-300">
              {evidence.evidenceDetails.map((detail, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="text-yellow-400 mt-0.5">&#8226;</span>
                  <span className="break-words">{detail}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </SectionCard>

      {hasAiProbeEvidence && (
        <SectionCard title="AI Probe Evidence">
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
              {aiProbeId && <InfoItem label="Probe ID"><code className="text-blue-300 break-all">{aiProbeId}</code></InfoItem>}
              {aiProbeFamily && <InfoItem label="Family">{aiProbeFamily.replaceAll('_', ' ')}</InfoItem>}
              {aiTechnique && <InfoItem label="Technique">{aiTechnique.replaceAll('_', ' ')}</InfoItem>}
              {aiJudgeLayer && <InfoItem label="Judge">{aiJudgeLayer.replaceAll('_', ' ')}</InfoItem>}
            </div>

            {aiTactics.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {aiTactics.map((tactic) => (
                  <span key={tactic} className="px-2 py-0.5 rounded bg-gray-800 text-gray-300 text-xs">
                    {tactic.replaceAll('_', ' ')}
                  </span>
                ))}
              </div>
            )}

            <div className="space-y-3">
              {aiProbePrompt && (
                <div className="flex justify-start">
                  <div className="max-w-3xl rounded-lg border border-red-900/50 bg-red-950/30 p-3">
                    <p className="text-xs font-medium uppercase tracking-wide text-red-300">Probe</p>
                    <p className="mt-2 text-sm text-gray-100 whitespace-pre-wrap">{aiProbePrompt}</p>
                  </div>
                </div>
              )}
              {aiResponseExcerpt && (
                <div className="flex justify-end">
                  <div className="max-w-3xl rounded-lg border border-blue-900/50 bg-blue-950/30 p-3">
                    <p className="text-xs font-medium uppercase tracking-wide text-blue-300">Target response</p>
                    <p className="mt-2 text-sm text-gray-100 whitespace-pre-wrap">{aiResponseExcerpt}</p>
                  </div>
                </div>
              )}
            </div>

            {rawEvidence && (
              <details open className="bg-gray-800/60 rounded-lg p-3">
                <summary className="text-sm font-medium text-gray-300 cursor-pointer">Expanded raw evidence</summary>
                <pre className="mt-3 text-xs text-gray-300 whitespace-pre-wrap break-words">{redactEvidenceForDisplay(rawEvidence)}</pre>
              </details>
            )}
          </div>
        </SectionCard>
      )}

      {evidenceObjects.length > 0 && (
        <SectionCard
          title="Durable Evidence Objects"
          actions={
            <Link href={`/evidence?finding_id=${encodeURIComponent(findingId)}`} className="text-xs text-blue-400 hover:text-blue-300">
              Browse in Evidence →
            </Link>
          }
        >
          <p className="text-xs text-gray-500 mb-3">
            First-class evidence records — content hash, redaction profile, retention class, and storage URI.
            These persist independently of the embedded evidence above and survive worker churn.
          </p>
          <div className="space-y-2">
            {evidenceObjects.map((eo) => {
              const contentText = evidenceObjectContentText(eo.content)
              return (
                <div key={eo.id} className="bg-gray-800/60 rounded-lg p-3 space-y-2">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <span className="text-sm font-medium text-gray-200">{eo.object_type}</span>
                    <div className="flex items-center gap-2">
                      {eo.retention_class && (
                        <span
                          className={`px-2 py-0.5 rounded text-xs font-medium ${
                            eo.retention_class === 'sensitive'
                              ? 'bg-amber-900/50 text-amber-300'
                              : 'bg-gray-700 text-gray-300'
                          }`}
                        >
                          {eo.retention_class}
                        </span>
                      )}
                      {typeof eo.size_bytes === 'number' && (
                        <span className="text-xs text-gray-400">{formatBytes(eo.size_bytes)}</span>
                      )}
                    </div>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1 text-xs">
                    {eo.content_sha256 && (
                      <div className="flex gap-2 min-w-0">
                        <span className="text-gray-500 shrink-0">sha256</span>
                        <span className="text-gray-300 font-mono break-all">{eo.content_sha256}</span>
                      </div>
                    )}
                    {eo.storage_uri && (
                      <div className="flex gap-2 min-w-0">
                        <span className="text-gray-500 shrink-0">storage</span>
                        <span className="text-gray-300 font-mono break-all">{eo.storage_uri}</span>
                      </div>
                    )}
                    {eo.redaction_profile && (
                      <div className="flex gap-2 min-w-0">
                        <span className="text-gray-500 shrink-0">redaction</span>
                        <span className="text-gray-300">{eo.redaction_profile}</span>
                      </div>
                    )}
                    <div className="flex gap-2 min-w-0">
                      <span className="text-gray-500 shrink-0">id</span>
                      <span className="text-gray-400 font-mono break-all">{eo.id}</span>
                    </div>
                  </div>
                  {contentText && (
                    <details className="rounded border border-gray-800 bg-gray-950 p-2">
                      <summary className="cursor-pointer text-xs font-medium text-gray-300">Object content</summary>
                      <div className="mt-2 flex justify-end">
                        <CopyButton text={contentText} label="Copy evidence object content" />
                      </div>
                      <pre className="mt-2 max-h-96 overflow-auto whitespace-pre-wrap break-words text-xs text-gray-300">
                        {contentText}
                      </pre>
                    </details>
                  )}
                </div>
              )
            })}
          </div>
        </SectionCard>
      )}

      <SectionCard id="ai-analysis" title="AI Analysis">
        {finding.ai_verdict || finding.ai_rationale || finding.ai_recommendations ? (
          <div className="space-y-3">
            {finding.ai_verdict && (
              <div className="flex items-center gap-2">
                <span
                  className={`px-2 py-0.5 rounded text-xs font-medium ${
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
                <p className="text-xs text-gray-500 mb-1">Rationale</p>
                <p className="text-sm text-gray-300 whitespace-pre-wrap">{finding.ai_rationale}</p>
              </div>
            )}
            {finding.ai_recommendations && (
              <div>
                <p className="text-xs text-gray-500 mb-1">Recommendations</p>
                {Array.isArray(finding.ai_recommendations) ? (
                  <ul className="space-y-1 text-sm text-gray-300 list-disc list-inside">
                    {finding.ai_recommendations.map((rec, idx) => (
                      <li key={idx}>{rec}</li>
                    ))}
                  </ul>
                ) : (
                  <pre className="text-xs text-gray-300 whitespace-pre-wrap break-words">
                    {JSON.stringify(finding.ai_recommendations, null, 2)}
                  </pre>
                )}
              </div>
            )}
          </div>
        ) : (
          <p className="text-sm text-gray-500">No AI analysis available.</p>
        )}
      </SectionCard>

      {(request || response) && (
        <SectionCard id="http" title="HTTP Request/Response">
          <div className="space-y-3">
            {request && (
              <details className="bg-gray-800/60 rounded-lg p-3">
                <summary className="cursor-pointer text-sm text-gray-300">Request</summary>
                <pre className="mt-2 text-xs text-gray-300 whitespace-pre-wrap break-words">{request}</pre>
              </details>
            )}
            {response && (
              <details className="bg-gray-800/60 rounded-lg p-3">
                <summary className="cursor-pointer text-sm text-gray-300">Response</summary>
                <pre className="mt-2 text-xs text-gray-300 whitespace-pre-wrap break-words">{response}</pre>
              </details>
            )}
          </div>
        </SectionCard>
      )}

      {rawEvidence && !hasAiProbeEvidence && (
        <Card className="p-4">
          <details>
            <summary className="text-sm font-medium text-gray-400 cursor-pointer">Raw Evidence</summary>
            <pre className="mt-3 text-xs text-gray-300 whitespace-pre-wrap break-words">{redactEvidenceForDisplay(rawEvidence)}</pre>
          </details>
        </Card>
      )}
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
