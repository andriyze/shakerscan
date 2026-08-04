'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import Link from 'next/link'
import { Activity, Bot, CheckCircle2, Clipboard, Download, FileText, LockKeyhole, RefreshCw, Server, ShieldAlert } from 'lucide-react'
import { Card, useToast } from '@/components/ui'
import {
  attachModelIntakeStaticRun,
  cancelModelIntakeAgentSession,
  createModelIntakeAgentSession,
  createModelIntakeApproval,
  createModelIntakePolicyDecision,
  createModelIntakeRunnerJob,
  createModelIntakeSubmission,
  downloadModelIntakeSubmissionReport,
  freezeModelIntakeEvidence,
  getModelIntakeAgentSession,
  getModelIntakeRunnerReadiness,
  getModelIntakeSubmission,
  getModelIntakeSubmissionReport,
  listModelIntakeRunnerJobs,
  listModelIntakeAgentSessions,
  listModelIntakeSubmissions,
  promoteModelIntakeSubmission,
  refreshModelIntakeRunnerJob,
  replyModelIntakeAgentSession,
  type ModelIntakeDeploymentBundleRequest,
  type ModelIntakeAgentSession,
  type ModelIntakeCorporateReport,
  type ModelIntakeOperatorCredential,
  type ModelIntakePlatform,
  type ModelIntakeRunnerJob,
  type ModelIntakeRunnerReadiness,
  type ModelIntakeScanSummary,
  type ModelIntakeWorkflowDetail,
  type ModelIntakeWorkflowSubmission,
} from '@/lib/api'

const inputClass = 'min-w-0 w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none'
const textareaClass = 'min-w-0 w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 font-mono text-xs text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none'
const buttonClass = 'inline-flex items-center justify-center gap-2 rounded-lg border border-gray-700 px-3 py-2 text-xs font-medium text-gray-200 hover:bg-gray-800 disabled:cursor-not-allowed disabled:opacity-50'

type JsonObject = Record<string, unknown>

function objectValue(value: unknown): JsonObject {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as JsonObject : {}
}

function parseObject(raw: string, label: string): JsonObject {
  const value = JSON.parse(raw)
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be a JSON object`)
  return value as JsonObject
}

function shortDigest(value: unknown): string {
  const text = typeof value === 'string' ? value : ''
  if (!text) return 'not recorded'
  return text.length > 22 ? `${text.slice(0, 12)}…${text.slice(-8)}` : text
}

function statusClass(status: string): string {
  const normalized = status.toLowerCase()
  if (['pass', 'ready', 'completed', 'admitted', 'allow', 'active'].includes(normalized)) return 'bg-green-950/60 text-green-300'
  if (['failed', 'fail', 'block', 'blocked', 'error', 'reject', 'revoked', 'not_ready'].includes(normalized)) return 'bg-red-950/60 text-red-300'
  return 'bg-yellow-950/60 text-yellow-300'
}

function runnerObservations(job: ModelIntakeRunnerJob): JsonObject {
  const result = objectValue(job.result_json)
  const payload = objectValue(result.payload)
  return objectValue(payload.observations)
}

function subjectDigest(detail: ModelIntakeWorkflowDetail | null, kind: string): string {
  const subject = detail?.subjects.filter((item) => item.subject_kind === kind).at(-1)
  return typeof subject?.sha256 === 'string' ? subject.sha256 : ''
}

// The scan reads these from the exact revision it snapshotted, so the operator
// confirms published facts instead of hunting through config.json by hand.
function embeddingHints(detail: ModelIntakeWorkflowDetail | null): JsonObject {
  const subject = detail?.subjects.filter((item) => item.subject_kind === 'configuration').at(-1)
  return objectValue(objectValue(subject?.metadata_json).embedding_configuration_hints)
}

// A number input bound to 0 renders "0", which reads as a declared value and
// hides the placeholder showing what a real one looks like.
function positiveOrBlank(value: unknown): string {
  const parsed = Number(value)
  return Number.isFinite(parsed) && parsed > 0 ? String(parsed) : ''
}

function suggestIdempotencyKey(submissionId: string): string {
  const suffix = crypto.randomUUID().replace(/-/g, '').slice(0, 12)
  const prefix = submissionId ? submissionId.slice(0, 8) : 'model-intake'
  return `${prefix}-promote-${suffix}`
}

function blankBundle(environment: ModelIntakeWorkflowSubmission['requested_environment'] = 'production'): ModelIntakeDeploymentBundleRequest {
  return {
    model_artifact_sha256: '',
    repository_snapshot_sha256: '',
    custom_code_sha256: null,
    tokenizer_sha256: '',
    configuration_sha256: '',
    runtime_image_digest: '',
    loader_profile_sha256: '',
    embedding_configuration: {
      dimension: 0,
      pooling: '',
      normalization: false,
      max_sequence_length: 0,
      precision: '',
    },
    retrieval_application_digest: '',
    index_schema_digest: '',
    target_environment: environment,
  }
}

export function ControlledModelIntakeWorkflow({
  operatorToken,
  onOperatorTokenChange,
  operatorCredential,
  source,
  sourceKind,
  environment,
  expectedArtifactSha256,
  availableScans,
  staticScanId,
  onStaticScanIdChange,
  onEditContext,
}: {
  operatorToken: string
  onOperatorTokenChange: (value: string) => void
  operatorCredential: ModelIntakeOperatorCredential | null
  // Model reference, provider, deployment target, and digest pin are all chosen
  // once in step 1. This stage consumes them; it never asks for them again.
  source: string
  sourceKind: ModelIntakePlatform
  environment: ModelIntakeWorkflowSubmission['requested_environment']
  expectedArtifactSha256: string
  // Completed preflight scans, so binding evidence is a choice rather than a
  // UUID the operator has to copy back from the scan report.
  availableScans: ModelIntakeScanSummary[]
  staticScanId: string
  onStaticScanIdChange: (value: string) => void
  onEditContext: () => void
}) {
  const toast = useToast()
  const [runnerReadiness, setRunnerReadiness] = useState<ModelIntakeRunnerReadiness | null>(null)
  const [submissions, setSubmissions] = useState<ModelIntakeWorkflowSubmission[]>([])
  const [selectedId, setSelectedId] = useState('')
  const [detail, setDetail] = useState<ModelIntakeWorkflowDetail | null>(null)
  const [jobs, setJobs] = useState<ModelIntakeRunnerJob[]>([])
  const [agentSessions, setAgentSessions] = useState<ModelIntakeAgentSession[]>([])
  const [report, setReport] = useState<ModelIntakeCorporateReport | null>(null)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState<string | null>(null)

  const [intendedUse, setIntendedUse] = useState('{"purpose":"knowledge-graph vector embeddings","data_classification":"internal"}')
  const [bundleJson, setBundleJson] = useState(JSON.stringify(blankBundle(environment), null, 2))
  const [runnerOperation, setRunnerOperation] = useState<'calibration' | 'runtime' | 'conversion'>('runtime')
  const [knownAnswerInputs, setKnownAnswerInputs] = useState('["corporate security review","knowledge graph entity retrieval"]')
  const [knownAnswerDigest, setKnownAnswerDigest] = useState('')
  const [memoryMib, setMemoryMib] = useState(4096)
  const [vcpuCount, setVcpuCount] = useState(2)
  const [timeoutSeconds, setTimeoutSeconds] = useState(600)

  const [plannerObjective, setPlannerObjective] = useState('Inspect the current evidence, identify coverage gaps, and recommend the next bounded Model Intake action.')
  const [plannerSessionId, setPlannerSessionId] = useState('')
  const [plannerObservation, setPlannerObservation] = useState('')
  const [plannerReply, setPlannerReply] = useState('')

  // Seed each submission once, so a later reload never discards operator edits.
  const seededSubmissions = useRef<Set<string>>(new Set())
  const [manifestId, setManifestId] = useState('')
  const [approvalType, setApprovalType] = useState('model_security_reviewer')
  const [approvalDecision, setApprovalDecision] = useState<'approve' | 'reject'>('approve')
  const [approvalReason, setApprovalReason] = useState('Reviewed the exact frozen evidence and deployment bundle.')
  const [policyDecisionId, setPolicyDecisionId] = useState('')
  const [idempotencyKey, setIdempotencyKey] = useState('')

  // The deployment target is chosen once in step 1, so the bundle's
  // target_environment tracks it instead of being a third place to get it wrong.
  useEffect(() => {
    setBundleJson((current) => {
      try {
        const parsed = parseObject(current, 'Deployment bundle')
        if (parsed.target_environment === environment) return current
        return JSON.stringify({ ...parsed, target_environment: environment }, null, 2)
      } catch {
        return current
      }
    })
  }, [environment])

  const loadReadiness = useCallback(async () => {
    try {
      setRunnerReadiness(await getModelIntakeRunnerReadiness())
    } catch (caught) {
      setRunnerReadiness({ status: 'NOT_READY', ready: false, error: caught instanceof Error ? caught.message : 'Runner readiness unavailable' })
    }
  }, [])

  const loadSubmissions = useCallback(async () => {
    if (!operatorToken.trim()) {
      setSubmissions([])
      setDetail(null)
      setReport(null)
      return
    }
    try {
      const response = await listModelIntakeSubmissions(operatorToken, { limit: 50 })
      setSubmissions(response.submissions)
      setError(null)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Failed to load controlled submissions')
    }
  }, [operatorToken])

  const loadSelected = useCallback(async (id = selectedId) => {
    if (!id || !operatorToken.trim()) return
    setReport(null)
    try {
      const [nextDetail, nextJobs, nextSessions, nextReport] = await Promise.all([
        getModelIntakeSubmission(id, operatorToken),
        listModelIntakeRunnerJobs(id, operatorToken),
        listModelIntakeAgentSessions(id, operatorToken),
        getModelIntakeSubmissionReport(id, operatorToken),
      ])
      setDetail(nextDetail)
      setJobs(nextJobs.jobs)
      setAgentSessions(nextSessions.sessions)
      setReport(nextReport)
      setSelectedId(id)
      const latestManifest = nextDetail.manifests.at(-1)
      const latestDecision = nextDetail.policy_decisions.at(-1)
      if (typeof latestManifest?.id === 'string') setManifestId(latestManifest.id)
      if (typeof latestDecision?.id === 'string') setPolicyDecisionId(latestDecision.id)
      if (!seededSubmissions.current.has(id)) {
        seededSubmissions.current.add(id)
        setBundleJson(JSON.stringify(buildSeededBundle(nextDetail, nextJobs.jobs[0]), null, 2))
      }
      setError(null)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Failed to load submission evidence')
    }
  }, [operatorToken, selectedId])

  useEffect(() => {
    void loadReadiness()
  }, [loadReadiness])

  useEffect(() => {
    void loadSubmissions()
  }, [loadSubmissions])

  const latestJob = jobs[0]
  const bundle = useMemo(() => {
    try {
      return parseObject(bundleJson, 'Deployment bundle') as unknown as ModelIntakeDeploymentBundleRequest
    } catch {
      return null
    }
  }, [bundleJson])

  function requireSelection(): string {
    if (!operatorToken.trim()) throw new Error('Enter an operator credential in Trust & operator controls first')
    if (!selectedId) throw new Error('Select a controlled submission first')
    return selectedId
  }

  async function createSubmission() {
    setBusy('create')
    setError(null)
    try {
      if (!operatorToken.trim()) throw new Error('An operator credential is required')
      if (!source.trim()) throw new Error('Select a model reference in step 1 first')
      const response = await createModelIntakeSubmission({
        source: source.trim(),
        source_kind: sourceKind,
        intended_environment: environment,
        intended_use: parseObject(intendedUse, 'Intended use'),
        expected_artifact_sha256: expectedArtifactSha256.trim() || undefined,
      }, operatorToken)
      setSelectedId(response.submission.id)
      setBundleJson(JSON.stringify(blankBundle(environment), null, 2))
      await loadSubmissions()
      await loadSelected(response.submission.id)
      toast.success('Controlled Model Intake submission created')
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Failed to create submission')
    } finally {
      setBusy('')
    }
  }

  async function attachStaticRun() {
    setBusy('static')
    setError(null)
    try {
      const id = requireSelection()
      await attachModelIntakeStaticRun(id, staticScanId.trim(), operatorToken)
      await loadSelected(id)
      toast.success('Completed static scan attached as generated evidence')
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Failed to attach scan')
    } finally {
      setBusy('')
    }
  }

  function buildSeededBundle(
    target: ModelIntakeWorkflowDetail,
    job: ModelIntakeRunnerJob | undefined,
    previous?: ModelIntakeDeploymentBundleRequest | null,
  ): ModelIntakeDeploymentBundleRequest {
    const request = objectValue(job?.request_json)
    const seeded = blankBundle(target.submission.requested_environment)
    seeded.model_artifact_sha256 = subjectDigest(target, 'artifact')
    seeded.repository_snapshot_sha256 = subjectDigest(target, 'repository_snapshot')
    seeded.custom_code_sha256 = subjectDigest(target, 'custom_code') || null
    seeded.tokenizer_sha256 = subjectDigest(target, 'tokenizer')
    seeded.configuration_sha256 = subjectDigest(target, 'configuration')
    seeded.runtime_image_digest = typeof request.runtime_image_digest === 'string' ? request.runtime_image_digest : ''
    seeded.loader_profile_sha256 = typeof request.loader_profile_sha256 === 'string' ? request.loader_profile_sha256 : ''
    // Re-seeding refreshes digests from evidence. It must not wipe embedding
    // values the operator already declared just because the scanned revision
    // published nothing for that field.
    const hints = embeddingHints(target)
    const current = objectValue(previous?.embedding_configuration)
    seeded.embedding_configuration = {
      dimension: Number(hints.dimension) > 0 ? Number(hints.dimension) : Number(current.dimension) || 0,
      pooling: typeof hints.pooling === 'string' && hints.pooling ? hints.pooling : String(current.pooling || ''),
      normalization: typeof hints.normalization === 'boolean' ? hints.normalization : Boolean(current.normalization),
      max_sequence_length: Number(hints.max_sequence_length) > 0
        ? Number(hints.max_sequence_length)
        : Number(current.max_sequence_length) || 0,
      precision: typeof hints.precision === 'string' && hints.precision ? hints.precision : String(current.precision || ''),
    }
    return seeded
  }

  function seedBundleFromEvidence() {
    if (!detail) return
    setBundleJson(JSON.stringify(buildSeededBundle(detail, latestJob, bundle), null, 2))
  }

  function updateEmbeddingField(field: string, value: string | number | boolean) {
    setBundleJson((current) => {
      try {
        const parsed = parseObject(current, 'Deployment bundle')
        const embedding = { ...objectValue(parsed.embedding_configuration), [field]: value }
        return JSON.stringify({ ...parsed, embedding_configuration: embedding }, null, 2)
      } catch {
        return current
      }
    })
  }

  // These are deployment facts the operator declares; ShakerScan cannot invent
  // them. Naming the source file is what turns a rejection into an action.
  function embeddingContractGaps(candidate: ModelIntakeDeploymentBundleRequest | null): string[] {
    const embedding = objectValue(candidate?.embedding_configuration)
    const gaps: string[] = []
    const dimension = Number(embedding.dimension)
    const sequence = Number(embedding.max_sequence_length)
    if (!Number.isFinite(dimension) || dimension <= 0) {
      gaps.push("embedding dimension \u2014 the model's hidden_size in config.json")
    }
    if (!Number.isFinite(sequence) || sequence <= 0) {
      gaps.push('max sequence length \u2014 usually max_position_embeddings in config.json')
    }
    const placeholders = new Set(['', 'review-required', 'unknown', 'tbd'])
    if (placeholders.has(String(embedding.pooling || '').trim().toLowerCase())) {
      gaps.push('pooling \u2014 the sentence-transformer pooling mode this deployment uses')
    }
    if (placeholders.has(String(embedding.precision || '').trim().toLowerCase())) {
      gaps.push('precision \u2014 the dtype the deployment serves, e.g. float32')
    }
    return gaps
  }

  async function queueRunnerJob() {
    setBusy('runner')
    setError(null)
    try {
      const id = requireSelection()
      if (!bundle) throw new Error('Deployment bundle JSON is invalid')
      const gaps = embeddingContractGaps(bundle)
      if (gaps.length) {
        throw new Error(`Declare the embedding configuration before queueing: ${gaps.join('; ')}.`)
      }
      const parsedInputs = JSON.parse(knownAnswerInputs)
      if (!Array.isArray(parsedInputs) || parsedInputs.some((item) => typeof item !== 'string')) throw new Error('Known-answer inputs must be a JSON string array')
      await createModelIntakeRunnerJob(id, {
        operation: runnerOperation,
        deployment_bundle: bundle,
        known_answer_inputs: parsedInputs,
        known_answer_embedding_sha256: knownAnswerDigest.trim() || undefined,
        memory_mib: memoryMib,
        vcpu_count: vcpuCount,
        timeout_seconds: timeoutSeconds,
      }, operatorToken)
      await loadSelected(id)
      toast.success('Firecracker job queued for the exact deployment subject')
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Failed to queue runner job')
    } finally {
      setBusy('')
    }
  }

  async function refreshJob(jobId: string) {
    setBusy(`refresh:${jobId}`)
    setError(null)
    try {
      const id = requireSelection()
      const response = await refreshModelIntakeRunnerJob(id, jobId, operatorToken)
      const nextSubjects = response.conversion_rescan?.next_runtime_subjects
      if (nextSubjects) {
        setBundleJson((current) => {
          try {
            const parsed = parseObject(current, 'Deployment bundle') as unknown as ModelIntakeDeploymentBundleRequest
            return JSON.stringify({ ...parsed, ...nextSubjects }, null, 2)
          } catch {
            return JSON.stringify({ ...blankBundle(detail?.submission.requested_environment), ...nextSubjects }, null, 2)
          }
        })
        setRunnerOperation('runtime')
        toast.success(`Converted target rescan: ${response.conversion_rescan?.status || 'complete'}. Runtime bundle seeded.`)
      }
      await loadSelected(id)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Failed to refresh runner job')
    } finally {
      setBusy('')
    }
  }

  async function startPlanner() {
    setBusy('planner')
    setError(null)
    try {
      const id = requireSelection()
      const response = await createModelIntakeAgentSession(id, { objective: plannerObjective, max_iterations: 10, action_budget: 20 }, operatorToken)
      const session = objectValue(response.session)
      setPlannerSessionId(typeof session.id === 'string' ? session.id : '')
      setPlannerObservation(typeof response.observation === 'string' ? response.observation : JSON.stringify(response.observation, null, 2))
      await loadSelected(id)
      toast.success('Advisory planner session started')
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Failed to start planner')
    } finally {
      setBusy('')
    }
  }

  async function submitPlannerReply() {
    setBusy('planner-reply')
    setError(null)
    try {
      if (!plannerSessionId) throw new Error('Start a planner session first')
      const response = await replyModelIntakeAgentSession(plannerSessionId, plannerReply, operatorToken)
      const session = objectValue(response.session)
      const observation = response.observation ?? response.final_assessment ?? response
      setPlannerObservation(JSON.stringify(observation, null, 2))
      if (session.status === 'completed') toast.success('Advisory planner session completed')
      setPlannerReply('')
      if (selectedId) await loadSelected(selectedId)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Failed to submit planner turn')
    } finally {
      setBusy('')
    }
  }

  async function resumePlanner(sessionId: string) {
    setBusy(`planner-resume:${sessionId}`)
    setError(null)
    try {
      const response = await getModelIntakeAgentSession(sessionId, operatorToken)
      const transcript = Array.isArray(response.session.transcript_json) ? response.session.transcript_json : []
      const latestController = transcript.slice().reverse().find((item) => item.role === 'controller')
      setPlannerSessionId(response.session.status === 'awaiting_planner' ? response.session.id : '')
      setPlannerObjective(response.session.objective)
      setPlannerObservation(JSON.stringify(latestController?.content ?? response.session.final_assessment_json ?? {
        status: response.session.status,
        actions: response.actions,
      }, null, 2))
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Failed to resume planner session')
    } finally {
      setBusy('')
    }
  }

  async function cancelPlanner(sessionId: string) {
    setBusy(`planner-cancel:${sessionId}`)
    setError(null)
    try {
      await cancelModelIntakeAgentSession(sessionId, operatorToken)
      if (plannerSessionId === sessionId) setPlannerSessionId('')
      if (selectedId) await loadSelected(selectedId)
      toast.success('Advisory planner session cancelled')
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Failed to cancel planner session')
    } finally {
      setBusy('')
    }
  }

  async function freezeEvidence() {
    setBusy('freeze')
    setError(null)
    try {
      const id = requireSelection()
      if (!bundle) throw new Error('Deployment bundle JSON is invalid')
      await freezeModelIntakeEvidence(id, bundle, operatorToken)
      await loadSelected(id)
      toast.success('Exact evidence manifest frozen')
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Failed to freeze evidence')
    } finally {
      setBusy('')
    }
  }

  async function recordApproval() {
    setBusy('approval')
    setError(null)
    try {
      const id = requireSelection()
      await createModelIntakeApproval(id, {
        evidence_manifest_id: manifestId.trim(),
        approval_type: approvalType,
        decision: approvalDecision,
        reason: approvalReason,
      }, operatorToken)
      await loadSelected(id)
      toast.success('Identity-bound approval recorded')
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Failed to record approval')
    } finally {
      setBusy('')
    }
  }

  async function evaluatePolicy() {
    setBusy('policy')
    setError(null)
    try {
      const id = requireSelection()
      const response = await createModelIntakePolicyDecision(id, manifestId.trim(), operatorToken)
      const decision = objectValue(response.policy_decision ?? response.decision)
      if (typeof decision.id === 'string') setPolicyDecisionId(decision.id)
      await loadSelected(id)
      toast.success('Deterministic admission policy evaluated')
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Failed to evaluate policy')
    } finally {
      setBusy('')
    }
  }

  async function promote() {
    setBusy('promote')
    setError(null)
    try {
      const id = requireSelection()
      await promoteModelIntakeSubmission(id, policyDecisionId.trim(), idempotencyKey.trim(), operatorToken)
      await loadSelected(id)
      await loadSubmissions()
      toast.success('Signed admission issued by the isolated signer')
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Failed to promote admission')
    } finally {
      setBusy('')
    }
  }

  async function exportReport(format: 'json' | 'html' | 'sarif') {
    setBusy(`report:${format}`)
    setError(null)
    try {
      const id = requireSelection()
      const exported = await downloadModelIntakeSubmissionReport(id, format, operatorToken)
      const url = URL.createObjectURL(exported.blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = exported.filename
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
      window.setTimeout(() => URL.revokeObjectURL(url), 1000)
      toast.success(format === 'html' ? 'Printable HTML report downloaded' : `${format.toUpperCase()} report downloaded`)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Failed to export normalized report')
    } finally {
      setBusy('')
    }
  }

  const hintSources = (() => {
    const sources = embeddingHints(detail).sources
    return Array.isArray(sources) ? sources.filter((item): item is string => typeof item === 'string') : []
  })()
  const embeddingConfiguration = objectValue(bundle?.embedding_configuration)
  const embeddingGaps = embeddingContractGaps(bundle)
  const runnerUnsupported = runnerReadiness?.supported_host === false
  // Firecracker is a Linux technology, so "not available on linux" would read as
  // a bug. On a cloud guest the wall is the absent CPU extension, not the OS.
  const runnerUnavailableLabel =
    runnerReadiness?.unsupported_reason === 'no_hardware_virtualization'
      ? 'unavailable: no KVM on this host'
      : `not available on ${runnerReadiness?.host_platform || 'this host'}`
  const undeclaredEmbeddingFields = new Set<string>(
    embeddingGaps.map((gap) => {
      const label = gap.split(' \u2014 ')[0]
      if (label.includes('dimension')) return 'dimension'
      if (label.includes('sequence')) return 'max_sequence_length'
      if (label.includes('pooling')) return 'pooling'
      return 'precision'
    })
  )
  const embeddingFieldClass = (field: string) =>
    undeclaredEmbeddingFields.has(field) ? inputClass.replace('border-gray-700', 'border-yellow-600/60') : inputClass

  const queueBlockers: Array<{ summary: string; detail?: string }> = []
  if (!selectedId) {
    queueBlockers.push({ summary: 'No submission selected', detail: 'Create or pick one in stage 4.1' })
  }
  if (runnerReadiness && !runnerReadiness.ready) {
    queueBlockers.push({
      summary: runnerUnsupported ? 'This host cannot run a microVM' : 'Runner prerequisites are incomplete',
      detail: runnerUnsupported
        ? `runner reports ${runnerReadiness.unsupported_reason || 'unsupported host'}`
        : runnerReadiness.error || 'see the runner status below',
    })
  }
  if (!runnerReadiness) {
    queueBlockers.push({ summary: 'Runner readiness is still being checked' })
  }
  for (const gap of embeddingGaps) {
    const [summary, detail] = gap.split(' \u2014 ')
    queueBlockers.push({ summary: `Undeclared ${summary}`, detail })
  }

  const attachableScans = availableScans.filter(
    (scan) => scan.status === 'completed' && scan.target_url.trim() === source.trim(),
  )
  // A loopback deployment resolves its own credential, so the manual field
  // only appears when the UI server declined to provide one.
  const operatorCredentialAutofilled = Boolean(operatorToken.trim()) && operatorCredential?.available === true
  const performedControlIds = new Set(report?.assessment_scope?.checks_performed || [])
  const incompleteControlIds = new Set(report?.assessment_scope?.checks_not_completed || [])
  const performedControls = report?.controls.filter((control) => performedControlIds.has(control.id)) || []
  const incompleteControls = report?.controls.filter((control) => incompleteControlIds.has(control.id)) || []

  return (
    <Card className="min-w-0 p-4" id="controlled-model-intake-workflow">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 text-white">
            <LockKeyhole className="h-4 w-4 text-cyan-300" />
            <h2 className="text-sm font-semibold">4. Controlled Corporate Admission Workflow</h2>
          </div>
          <p className="mt-1 max-w-4xl text-xs text-gray-400">
            Generated static evidence, exact-subject Firecracker execution, frozen evidence, identity-separated approvals, deterministic policy, and isolated signing. Technical preflight above never grants deployment authority.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`rounded px-2 py-1 text-xs font-semibold ${runnerUnsupported ? 'bg-gray-800 text-gray-400' : statusClass(runnerReadiness?.status || 'checking')}`}>
            Firecracker {runnerUnsupported ? runnerUnavailableLabel : (runnerReadiness?.status || 'checking')}
          </span>
          <button type="button" className={buttonClass} onClick={() => { void loadReadiness(); void loadSubmissions(); if (selectedId) void loadSelected() }}>
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
        </div>
      </div>

      {operatorCredentialAutofilled ? (
        <div className="mt-4 flex gap-2 rounded border border-gray-800 bg-gray-950 p-3 text-xs text-gray-400">
          <LockKeyhole className="h-4 w-4 shrink-0 text-cyan-300" />
          <span>
            Using this deployment&apos;s own operator credential. Reviewer identities and roles are
            still resolved server-side from hashed credential records, and the submitter can never
            approve its own submission.
          </span>
        </div>
      ) : (
        <div className="mt-4 grid gap-2 rounded border border-gray-700 bg-gray-950 p-3 text-xs text-gray-400">
          <div className="flex gap-2">
            <ShieldAlert className="h-4 w-4 shrink-0 text-gray-500" />
            <span>
              Corporate approval actions are signed by a named reviewer, so this stage needs an
              operator credential. Everything before it — resolving a model and running the preflight
              evidence scan — needs nothing.
            </span>
          </div>
          <label className="mt-1 grid max-w-2xl gap-1 text-gray-300">
            Operator credential
            <input
              className={inputClass}
              type="password"
              autoComplete="off"
              value={operatorToken}
              onChange={(event) => onOperatorTokenChange(event.target.value)}
              placeholder="Reviewer credential for this deployment"
            />
            <span className="text-[11px] text-gray-500">Stored only in this browser session and never rendered in workflow evidence.</span>
          </label>
          {(operatorCredential?.detail || operatorCredential?.hint) && (
            <details>
              <summary className="cursor-pointer text-[11px] text-gray-500">Where do I get one?</summary>
              <div className="mt-1 text-[11px] text-gray-500">
                {operatorCredential?.detail}{' '}<span className="text-gray-400">{operatorCredential?.hint}</span>
              </div>
            </details>
          )}
        </div>
      )}
      {error && <div role="alert" className="mt-4 break-words rounded border border-red-700/50 bg-red-950/20 p-3 text-xs text-red-300">{error}</div>}

      <details className="mt-4 rounded-lg border border-gray-800 bg-gray-950" open>
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-white">4.1 Create or select a submission</summary>
        <div className="grid gap-4 border-t border-gray-800 p-4 xl:grid-cols-2">
          <div className="grid gap-3">
            <div className="rounded border border-gray-800 bg-gray-900 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs font-medium text-gray-300">Intake context from step 1</span>
                <button type="button" className={buttonClass} onClick={onEditContext}>Change</button>
              </div>
              <dl className="mt-3 grid gap-2 text-[11px] sm:grid-cols-2">
                <div className="min-w-0">
                  <dt className="text-gray-500">Immutable source reference</dt>
                  <dd className="mt-0.5 break-all font-mono text-gray-200">{source || 'not selected yet'}</dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-gray-500">Source kind</dt>
                  <dd className="mt-0.5 font-mono text-gray-200">{sourceKind}</dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-gray-500">Intended environment</dt>
                  <dd className="mt-0.5 font-mono text-gray-200">{environment}</dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-gray-500">Expected artifact SHA-256</dt>
                  <dd className="mt-0.5 break-all font-mono text-gray-200">{expectedArtifactSha256 || 'not pinned'}</dd>
                </div>
              </dl>
            </div>
            <label className="grid gap-1 text-xs text-gray-300">Intended-use declaration
              <textarea className={textareaClass} rows={4} value={intendedUse} onChange={(event) => setIntendedUse(event.target.value)} />
            </label>
            <button type="button" className={buttonClass} disabled={busy === 'create' || !source.trim()} onClick={createSubmission}>
              {busy === 'create' ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <LockKeyhole className="h-3.5 w-3.5" />} Create controlled submission
            </button>
            {!source.trim() && <div className="text-[11px] text-yellow-200">Select or resolve a model in step 1 to enable submission.</div>}
          </div>
          <div className="min-w-0">
            <div className="mb-2 flex items-center justify-between text-xs text-gray-400"><span>Recent controlled submissions</span><span>{submissions.length}</span></div>
            <div className="max-h-80 space-y-2 overflow-auto pr-1">
              {submissions.length === 0 ? <div className="rounded border border-gray-800 p-3 text-xs text-gray-500">No accessible submissions.</div> : submissions.map((submission) => (
                <button key={submission.id} type="button" onClick={() => void loadSelected(submission.id)} className={`w-full rounded border p-3 text-left ${selectedId === submission.id ? 'border-cyan-500 bg-cyan-950/30' : 'border-gray-800 bg-gray-900 hover:border-gray-700'}`}>
                  <div className="flex items-center justify-between gap-2"><span className="truncate font-mono text-xs text-gray-200">{submission.id}</span><span className={`rounded px-1.5 py-0.5 text-[10px] ${statusClass(submission.state)}`}>{submission.state}</span></div>
                  <div className="mt-1 text-[11px] text-gray-500">{submission.source_kind} · {submission.requested_environment} · {new Date(submission.created_at).toLocaleString()}</div>
                </button>
              ))}
            </div>
          </div>
        </div>
      </details>

      <details className="mt-3 rounded-lg border border-gray-800 bg-gray-950" open={Boolean(selectedId)}>
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-white">4.2 Bind completed static evidence</summary>
        <div className="border-t border-gray-800 p-4">
          <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto]">
            <label className="grid gap-1 text-xs text-gray-300">Completed Model Intake scan
              <select className={inputClass} value={attachableScans.some((scan) => scan.id === staticScanId) ? staticScanId : ''} onChange={(event) => onStaticScanIdChange(event.target.value)}>
                <option value="">{attachableScans.length ? 'Select a completed preflight scan' : 'No completed Model Intake scans yet'}</option>
                {attachableScans.map((scan) => (
                  <option key={scan.id} value={scan.id}>
                    {`${new Date(scan.created_at).toLocaleString()} · ${scan.target_url}`}
                  </option>
                ))}
              </select>
            </label>
            <button type="button" className={`${buttonClass} self-end`} disabled={busy === 'static' || !selectedId || !staticScanId.trim()} onClick={attachStaticRun}>Attach generated evidence</button>
          </div>
          <details className="mt-2">
            <summary className="cursor-pointer text-[11px] text-gray-500">Bind a scan from another session by ID</summary>
            <input
              className={`${inputClass} mt-2`}
              value={staticScanId}
              onChange={(event) => onStaticScanIdChange(event.target.value)}
              placeholder="UUID from a completed complete-snapshot scan"
            />
          </details>
          {attachableScans.length === 0 && (
            <div className="mt-2 text-[11px] text-yellow-200">
              Queue a preflight scan in step 2 first. Only a completed scan with a complete artifact
              subject can be bound as generated evidence.
            </div>
          )}
          {detail && (
            <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
              <div className="rounded border border-gray-800 p-3 text-xs"><div className="text-gray-500">State</div><div className="mt-1 text-gray-200">{detail.submission.state}</div></div>
              <div className="rounded border border-gray-800 p-3 text-xs"><div className="text-gray-500">Artifact</div><div className="mt-1 font-mono text-gray-200">{shortDigest(subjectDigest(detail, 'artifact'))}</div></div>
              <div className="rounded border border-gray-800 p-3 text-xs"><div className="text-gray-500">Snapshot</div><div className="mt-1 font-mono text-gray-200">{shortDigest(subjectDigest(detail, 'repository_snapshot'))}</div></div>
              <div className="rounded border border-gray-800 p-3 text-xs"><div className="text-gray-500">Evidence records</div><div className="mt-1 text-gray-200">{detail.evidence.length}</div></div>
            </div>
          )}
        </div>
      </details>

      <details className="mt-3 rounded-lg border border-gray-800 bg-gray-950" open={Boolean(selectedId)}>
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-white">4.3 Firecracker calibration, runtime, conversion, and telemetry</summary>
        <div className="grid gap-4 border-t border-gray-800 p-4 xl:grid-cols-[minmax(0,0.8fr)_minmax(0,1.2fr)]">
          <div className="grid gap-3">
            <div className="flex flex-wrap items-center justify-between gap-2"><span className="text-xs text-gray-400">Exact deployment bundle</span><button type="button" className={buttonClass} onClick={seedBundleFromEvidence}>Seed authoritative digests</button></div>
            <div className="rounded border border-gray-800 bg-gray-900 p-3">
              <div className="text-xs font-medium text-gray-300">Embedding configuration</div>
              {hintSources.length > 0 ? (
                <p className="mt-1 text-[11px] text-gray-500">
                  Prefilled from the scanned revision&apos;s own{' '}
                  <span className="text-gray-400">{hintSources.join(', ')}</span>. Confirm these are
                  the values this deployment will actually serve — they become part of the signed
                  bundle.
                </p>
              ) : (
                <p className="mt-1 text-[11px] text-gray-500">
                  Deployment facts ShakerScan cannot infer. For a Hugging Face model these come from
                  the repository&apos;s <code className="text-gray-400">config.json</code> and its
                  sentence-transformer pooling config.
                </p>
              )}
              <div className="mt-3 grid gap-3 sm:grid-cols-2">
                <label className="grid gap-1 text-xs text-gray-300">Dimension <span className="text-gray-600">(hidden_size)</span>
                  <input className={embeddingFieldClass('dimension')} type="number" min={1} value={positiveOrBlank(embeddingConfiguration.dimension)} onChange={(event) => updateEmbeddingField('dimension', Number(event.target.value))} placeholder="768" />
                </label>
                <label className="grid gap-1 text-xs text-gray-300">Max sequence length <span className="text-gray-600">(max_position_embeddings)</span>
                  <input className={embeddingFieldClass('max_sequence_length')} type="number" min={1} value={positiveOrBlank(embeddingConfiguration.max_sequence_length)} onChange={(event) => updateEmbeddingField('max_sequence_length', Number(event.target.value))} placeholder="8192" />
                </label>
                <label className="grid gap-1 text-xs text-gray-300">Pooling
                  <input className={embeddingFieldClass('pooling')} value={String(embeddingConfiguration.pooling ?? '')} onChange={(event) => updateEmbeddingField('pooling', event.target.value)} placeholder="mean, cls, or lasttoken" />
                </label>
                <label className="grid gap-1 text-xs text-gray-300">Precision
                  <input className={embeddingFieldClass('precision')} value={String(embeddingConfiguration.precision ?? '')} onChange={(event) => updateEmbeddingField('precision', event.target.value)} placeholder="float32" />
                </label>
              </div>
              <label className="mt-3 flex items-center gap-2 text-xs text-gray-300">
                <input type="checkbox" className="h-4 w-4 rounded border-gray-700 bg-gray-800" checked={Boolean(embeddingConfiguration.normalization)} onChange={(event) => updateEmbeddingField('normalization', event.target.checked)} />
                Normalize embeddings
              </label>
              {embeddingGaps.length > 0 && (
                <p className="mt-3 text-[11px] text-yellow-200">
                  The highlighted {embeddingGaps.length === 1 ? 'field is' : `${embeddingGaps.length} fields are`} still
                  undeclared. Each one is listed with its source next to the queue button below.
                </p>
              )}
            </div>
            <details>
              <summary className="cursor-pointer text-xs text-gray-500">Raw deployment bundle JSON</summary>
              <textarea className={`${textareaClass} mt-2`} rows={18} value={bundleJson} onChange={(event) => setBundleJson(event.target.value)} />
            </details>
            <div className="grid gap-3 sm:grid-cols-3">
              <label className="grid gap-1 text-xs text-gray-300">Operation<select className={inputClass} value={runnerOperation} onChange={(event) => setRunnerOperation(event.target.value as typeof runnerOperation)}><option value="calibration">calibration</option><option value="runtime">runtime</option><option value="conversion">conversion</option></select></label>
              <label className="grid gap-1 text-xs text-gray-300">vCPU<input className={inputClass} type="number" min={1} max={32} value={vcpuCount} onChange={(event) => setVcpuCount(Number(event.target.value))} /></label>
              <label className="grid gap-1 text-xs text-gray-300">Memory MiB<input className={inputClass} type="number" min={256} value={memoryMib} onChange={(event) => setMemoryMib(Number(event.target.value))} /></label>
            </div>
            <label className="grid gap-1 text-xs text-gray-300">Known-answer inputs (bounded JSON string array)<textarea className={textareaClass} rows={3} value={knownAnswerInputs} onChange={(event) => setKnownAnswerInputs(event.target.value)} /></label>
            <label className="grid gap-1 text-xs text-gray-300">Reviewed known-answer embedding SHA-256 {runnerOperation === 'runtime' ? '(required)' : '(optional)'}<input className={inputClass} value={knownAnswerDigest} onChange={(event) => setKnownAnswerDigest(event.target.value)} /></label>
            <label className="grid gap-1 text-xs text-gray-300">Wall-clock timeout seconds<input className={inputClass} type="number" min={30} max={3600} value={timeoutSeconds} onChange={(event) => setTimeoutSeconds(Number(event.target.value))} /></label>
            <button
              type="button"
              className={buttonClass}
              disabled={busy === 'runner' || queueBlockers.length > 0}
              title={queueBlockers.length ? `Blocked: ${queueBlockers.map((item) => item.summary).join('; ')}` : undefined}
              onClick={queueRunnerJob}
            >
              <Server className="h-3.5 w-3.5" /> Queue exact-subject Firecracker job
            </button>
            {queueBlockers.length > 0 && (
              // A disabled control has to say why. Three of these conditions
              // were previously silent, so the button just looked broken.
              <div className="rounded border border-gray-700 bg-gray-950 p-3 text-xs text-gray-400">
                <div className="font-medium text-gray-300">
                  {queueBlockers.length === 1 ? 'One thing is missing before this can run:' : `${queueBlockers.length} things are missing before this can run:`}
                </div>
                <ul className="mt-2 list-disc space-y-1 pl-5">
                  {queueBlockers.map((item) => (
                    <li key={item.summary}>
                      <span className="text-gray-200">{item.summary}</span>
                      {item.detail ? <span className="text-gray-500"> &mdash; {item.detail}</span> : null}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {runnerUnsupported ? (
              <div className="rounded border border-gray-700 bg-gray-950 p-3 text-xs text-gray-400">
                {runnerReadiness?.reason || 'The Firecracker microVM tier requires a Linux host with KVM.'}
                {' '}Every other Model Intake check — acquisition, static evidence, policy, approvals,
                and promotion — works normally on this host. Point the deployment at a Linux runner
                with <code className="text-gray-300">MODEL_INTAKE_RUNNER_URL</code> to enable this stage.
              </div>
            ) : !runnerReadiness?.ready ? (
              <div className="rounded border border-red-800/60 bg-red-950/20 p-3 text-xs text-red-300">No fallback is used. {runnerReadiness?.error || 'Linux/KVM runner prerequisites are incomplete.'}</div>
            ) : null}
          </div>
          <div className="min-w-0 space-y-3">
            {jobs.length === 0 ? <div className="rounded border border-gray-800 p-3 text-xs text-gray-500">No runner jobs for this submission.</div> : jobs.map((job) => {
              const observations = runnerObservations(job)
              const phases = objectValue(observations.phases)
              const network = objectValue(observations.network_telemetry)
              const resources = objectValue(observations.resource_telemetry)
              const convertedSnapshot = typeof observations.target_repository_snapshot_sha256 === 'string' ? observations.target_repository_snapshot_sha256 : ''
              const convertedArtifact = typeof observations.target_artifact_sha256 === 'string' ? observations.target_artifact_sha256 : ''
              const convertedStatic = detail?.evidence.filter((item) => {
                const bindings = objectValue(item.subject_bindings)
                return item.evidence_type === 'static_analysis' && bindings.repository_snapshot_sha256 === convertedSnapshot
              }).at(-1)
              return (
                <div key={job.id} className="rounded-lg border border-gray-800 bg-gray-900 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div><span className="font-mono text-xs text-gray-200">{job.operation} · {job.id}</span><div className="mt-1 text-[10px] text-gray-500">request {shortDigest(job.request_sha256)}</div></div>
                    <div className="flex items-center gap-2"><span className={`rounded px-2 py-1 text-[10px] font-semibold ${statusClass(job.state)}`}>{job.state}</span><button type="button" className={buttonClass} disabled={busy === `refresh:${job.id}`} onClick={() => void refreshJob(job.id)}><RefreshCw className={`h-3 w-3 ${busy === `refresh:${job.id}` ? 'animate-spin' : ''}`} /> Refresh</button></div>
                  </div>
                  {Object.keys(phases).length > 0 && <div className="mt-3"><div className="mb-2 flex items-center gap-2 text-xs text-gray-400"><Activity className="h-3.5 w-3.5" /> Phase timeline</div><div className="grid gap-2 sm:grid-cols-2">{Object.entries(phases).map(([name, value]) => { const phase = objectValue(value); const phaseStatus = String(phase.status || value); return <div key={name} className="rounded border border-gray-800 px-2 py-1.5 text-[11px]"><div className="flex justify-between gap-2"><span className="text-gray-300">{name.replace(/_/g, ' ')}</span><span className={statusClass(phaseStatus)}>{phaseStatus}</span></div>{phase.duration_ms !== undefined && <div className="mt-1 text-gray-600">{String(phase.duration_ms)} ms</div>}</div> })}</div></div>}
                  {Object.keys(network).length > 0 && <div className="mt-3 rounded border border-gray-800 p-3 text-[11px]"><div className="flex items-center justify-between gap-2"><span className="font-medium text-gray-300">Independent network telemetry</span><span className={network.complete === true && network.overflowed === false && network.lost_events === 0 ? 'text-green-300' : 'text-red-300'}>{network.complete === true ? 'complete' : 'incomplete'}</span></div><div className="mt-2 grid gap-1 text-gray-500 sm:grid-cols-2"><span>attempts: <b className="text-gray-200">{String(network.attempt_count ?? 'unknown')}</b></span><span>lost: <b className="text-gray-200">{String(network.lost_events ?? 'unknown')}</b></span><span>overflowed: <b className="text-gray-200">{String(network.overflowed ?? 'unknown')}</b></span><span>guest interfaces: <b className="text-gray-200">{Array.isArray(network.guest_interfaces) ? network.guest_interfaces.join(', ') : 'unknown'}</b></span><span>host drops: <b className="text-gray-200">{String(network.host_firewall_drop_count ?? 'unknown')}</b></span><span>digest: <b className="font-mono text-gray-200">{shortDigest(network.telemetry_sha256)}</b></span></div>{Number(network.attempt_count || 0) > 0 && <pre className="mt-2 max-h-32 overflow-auto whitespace-pre-wrap break-all rounded bg-gray-950 p-2 text-red-300">{JSON.stringify({ attempted_operations: network.attempted_operations, attempts_by_phase: network.attempts_by_phase }, null, 2)}</pre>}</div>}
                  {Object.keys(resources).length > 0 && <div className="mt-2 rounded border border-gray-800 p-3 text-[11px] text-gray-500"><span className="font-medium text-gray-300">Host resource envelope</span><pre className="mt-2 max-h-36 overflow-auto whitespace-pre-wrap break-all font-mono text-gray-400">{JSON.stringify(resources, null, 2)}</pre></div>}
                  {convertedSnapshot && <div className="mt-2 rounded border border-cyan-800/60 bg-cyan-950/20 p-3 text-[11px]"><div className="flex items-center justify-between gap-2"><span className="font-medium text-cyan-200">Converted target identity</span><span className={`rounded px-1.5 py-0.5 font-semibold ${statusClass(String(convertedStatic?.status || 'INCOMPLETE'))}`}>static {String(convertedStatic?.status || 'INCOMPLETE')}</span></div><div className="mt-2 grid gap-1 text-cyan-100/70 sm:grid-cols-2"><span>artifact: <b className="font-mono text-cyan-100">{shortDigest(convertedArtifact)}</b></span><span>snapshot: <b className="font-mono text-cyan-100">{shortDigest(convertedSnapshot)}</b></span></div><p className="mt-2 text-cyan-100/60">The converted snapshot is separately registered and rescanned. Seeded runtime fields still require a safe-loader Firecracker run and known-answer digest.</p></div>}
                  {job.error_json && <pre className="mt-2 max-h-36 overflow-auto whitespace-pre-wrap break-all rounded border border-red-900 bg-red-950/20 p-2 text-[11px] text-red-300">{JSON.stringify(job.error_json, null, 2)}</pre>}
                </div>
              )
            })}
          </div>
        </div>
      </details>

      <details className="mt-3 rounded-lg border border-gray-800 bg-gray-950">
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-white">4.4 Codex-guided investigation (advisory only)</summary>
        <div className="grid gap-4 border-t border-gray-800 p-4 xl:grid-cols-2">
          <div className="grid gap-3">
            <div className="rounded border border-cyan-800/60 bg-cyan-950/20 p-3 text-xs text-cyan-200">The coding agent may inspect evidence, check readiness, validate a runner plan, draft an embedding test plan, or recommend a follow-up. It cannot execute arbitrary commands, approve, change policy, freeze evidence, promote, or turn incomplete evidence into PASS.</div>
            {agentSessions.length > 0 && <div className="rounded border border-gray-800 p-3"><div className="mb-2 text-xs text-gray-400">Durable advisory sessions</div><div className="max-h-44 space-y-2 overflow-auto">{agentSessions.map((session) => <div key={session.id} className="flex flex-wrap items-center justify-between gap-2 rounded border border-gray-800 bg-gray-900 p-2"><div className="min-w-0"><div className="truncate text-xs text-gray-300">{session.objective}</div><div className="mt-1 text-[10px] text-gray-600">turn {session.iteration}/{session.max_iterations} · actions {session.actions_used}/{session.action_budget}</div></div><div className="flex items-center gap-2"><span className={`rounded px-1.5 py-0.5 text-[10px] ${statusClass(session.status)}`}>{session.status}</span><button type="button" className={buttonClass} disabled={busy === `planner-resume:${session.id}`} onClick={() => void resumePlanner(session.id)}>{session.status === 'awaiting_planner' ? 'Resume' : 'Inspect'}</button>{session.status === 'awaiting_planner' && <button type="button" className={buttonClass} disabled={busy === `planner-cancel:${session.id}`} onClick={() => void cancelPlanner(session.id)}>Cancel</button>}</div></div>)}</div></div>}
            <label className="grid gap-1 text-xs text-gray-300">Objective<textarea className={textareaClass} rows={4} value={plannerObjective} onChange={(event) => setPlannerObjective(event.target.value)} /></label>
            <button type="button" className={buttonClass} disabled={!selectedId || busy === 'planner'} onClick={startPlanner}><Bot className="h-3.5 w-3.5" /> Start keyless planner session</button>
            <label className="grid gap-1 text-xs text-gray-300">Planner reply (fenced controller JSON)<textarea className={textareaClass} rows={8} value={plannerReply} onChange={(event) => setPlannerReply(event.target.value)} placeholder={'```json\n{"tool_calls":[{"name":"inspect_submission","arguments":{}}]}\n```'} /></label>
            <button type="button" className={buttonClass} disabled={!plannerSessionId || !plannerReply.trim() || busy === 'planner-reply'} onClick={submitPlannerReply}>Submit bounded turn</button>
          </div>
          <div className="min-w-0">
            <div className="mb-2 flex items-center justify-between text-xs text-gray-400"><span>Controller observation</span>{plannerObservation && <button type="button" className={buttonClass} onClick={() => void navigator.clipboard.writeText(plannerObservation)}><Clipboard className="h-3 w-3" /> Copy</button>}</div>
            <pre className="min-h-64 max-h-[34rem] overflow-auto whitespace-pre-wrap break-words rounded border border-gray-800 bg-gray-900 p-3 text-[11px] text-gray-300">{plannerObservation || 'Start a session to receive the self-describing planner contract.'}</pre>
          </div>
        </div>
      </details>

      <details className="mt-3 rounded-lg border border-gray-800 bg-gray-950">
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-white">4.5 Freeze, approve, evaluate policy, and promote</summary>
        <div className="grid gap-4 border-t border-gray-800 p-4 xl:grid-cols-2">
          <div className="grid gap-3">
            <button type="button" className={buttonClass} disabled={!selectedId || busy === 'freeze'} onClick={freezeEvidence}><LockKeyhole className="h-3.5 w-3.5" /> Freeze exact current evidence</button>
            <label className="grid gap-1 text-xs text-gray-300">Frozen evidence manifest ID<input className={inputClass} value={manifestId} onChange={(event) => setManifestId(event.target.value)} /></label>
            <div className="grid gap-3 sm:grid-cols-2"><label className="grid gap-1 text-xs text-gray-300">Approval role<select className={inputClass} value={approvalType} onChange={(event) => setApprovalType(event.target.value)}>{['model_security_reviewer', 'ml_platform_reviewer', 'release_manager', 'legal_reviewer', 'privacy_reviewer', 'data_owner', 'risk_acceptance'].map((role) => <option key={role}>{role}</option>)}</select></label><label className="grid gap-1 text-xs text-gray-300">Decision<select className={inputClass} value={approvalDecision} onChange={(event) => setApprovalDecision(event.target.value as 'approve' | 'reject')}><option value="approve">approve</option><option value="reject">reject</option></select></label></div>
            <label className="grid gap-1 text-xs text-gray-300">Approval rationale<textarea className={textareaClass} rows={3} value={approvalReason} onChange={(event) => setApprovalReason(event.target.value)} /></label>
            <button type="button" className={buttonClass} disabled={!manifestId || busy === 'approval'} onClick={recordApproval}><CheckCircle2 className="h-3.5 w-3.5" /> Record identity-bound approval</button>
            <div className="text-[11px] text-gray-500">Production requires distinct server-configured identities for security, ML platform, and release-manager approvals. The submitter cannot approve its own submission.</div>
          </div>
          <div className="grid content-start gap-3">
            <button type="button" className={buttonClass} disabled={!manifestId || busy === 'policy'} onClick={evaluatePolicy}>Evaluate deterministic admission policy</button>
            <label className="grid gap-1 text-xs text-gray-300">Stored policy decision ID<input className={inputClass} value={policyDecisionId} onChange={(event) => setPolicyDecisionId(event.target.value)} /></label>
            <label className="grid gap-1 text-xs text-gray-300">Promotion idempotency key
              <div className="flex gap-2">
                <input className={inputClass} value={idempotencyKey} onChange={(event) => setIdempotencyKey(event.target.value)} placeholder="release-ticket-and-random-suffix (16+ chars)" />
                <button type="button" className={buttonClass} onClick={() => setIdempotencyKey(suggestIdempotencyKey(selectedId))}>Generate</button>
              </div>
              <span className="text-[11px] text-gray-500">Replace the suggestion with your release ticket when you have one; the key only has to be unique per promotion.</span>
            </label>
            <button type="button" className={buttonClass} disabled={!policyDecisionId || idempotencyKey.length < 16 || busy === 'promote'} onClick={promote}>Invoke isolated signer and promote</button>
            {detail && <div className="rounded border border-gray-800 p-3 text-xs"><div className="mb-2 text-gray-300">Submission event timeline</div><div className="max-h-64 space-y-2 overflow-auto">{detail.events.slice().reverse().slice(0, 30).map((event) => <div key={event.id} className="border-l border-gray-700 pl-3"><div className="text-gray-300">{String(event.event_type || 'event').replace(/_/g, ' ')}</div><div className="text-[10px] text-gray-600">{String(event.created_at || '')} · {String(event.actor || 'system')}</div>{typeof event.reason === 'string' && event.reason && <div className="mt-0.5 text-[11px] text-gray-500">{event.reason}</div>}</div>)}</div></div>}
            <Link href="/settings/policy-profiles" className={`${buttonClass} text-center`}>Review deployment policy profiles</Link>
          </div>
        </div>
      </details>

      <details className="mt-3 rounded-lg border border-gray-800 bg-gray-950" open={Boolean(report)}>
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-white">4.6 Normalized corporate review report</summary>
        <div className="border-t border-gray-800 p-4">
          {!report ? <div className="text-xs text-gray-500">Select a controlled submission to generate its authoritative report.</div> : (
            <div className="grid gap-4">
              <section className="rounded-lg border border-gray-800 bg-gray-900 p-4" aria-label="Model Intake executive summary">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">Executive summary</div>
                    <div className="mt-2 flex items-center gap-2"><FileText className="h-4 w-4 text-cyan-300" /><span className={`rounded px-2 py-1 text-xs font-bold ${statusClass(report.outcome)}`}>ShakerScan: {report.outcome}</span></div>
                    <p className="mt-2 max-w-4xl text-sm text-gray-200">{report.executive_summary.decision_statement}</p>
                    <p className="mt-2 text-xs text-gray-500">{report.executive_summary.authorization_scope}</p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {(['json', 'html', 'sarif'] as const).map((format) => <button key={format} type="button" className={buttonClass} disabled={busy === `report:${format}`} onClick={() => void exportReport(format)}><Download className="h-3.5 w-3.5" /> {format === 'html' ? 'Printable HTML / PDF' : format.toUpperCase()}</button>)}
                  </div>
                </div>
                <div className="mt-4 rounded border border-yellow-800/60 bg-yellow-950/20 p-3 text-xs text-yellow-100">
                  <div className="font-semibold">Full corporate approval: not determined by ShakerScan</div>
                  <p className="mt-1 text-yellow-100/80">{report.executive_summary.scope_warning}</p>
                </div>
                <div className="mt-4 grid gap-2 sm:grid-cols-3 xl:grid-cols-6">
                  {[
                    ['performed', report.executive_summary.coverage.performed],
                    ['passed', report.executive_summary.coverage.passed],
                    ['failed', report.executive_summary.coverage.failed],
                    ['review', report.executive_summary.coverage.review],
                    ['not completed', report.executive_summary.coverage.not_completed],
                    ['external', report.executive_summary.coverage.external_corporate_requirements],
                  ].map(([label, value]) => <div key={String(label)} className="rounded border border-gray-800 bg-gray-950 p-2 text-center"><div className="text-lg font-semibold text-white">{String(value ?? 0)}</div><div className="text-[10px] uppercase tracking-wide text-gray-500">{label}</div></div>)}
                </div>
                {report.executive_summary.required_actions.length > 0 && <div className="mt-4"><div className="text-xs font-semibold text-gray-300">Required next actions</div><ol className="mt-2 list-decimal space-y-1 pl-5 text-xs text-gray-400">{report.executive_summary.required_actions.map((action) => <li key={`${action.control_id}-${action.status}`}><span className={statusClass(action.status)}>{action.status}</span> · {action.action}</li>)}</ol></div>}
                <div className="mt-3 break-all font-mono text-[10px] text-gray-600">report sha256:{report.report_sha256}</div>
              </section>

              <section className="rounded-lg border border-gray-800 bg-gray-900 p-4" aria-label="Checks performed">
                <div className="text-sm font-semibold text-white">Checks performed</div>
                <p className="mt-1 text-xs text-gray-500">These controls produced a determinate PASS, FAIL, or REVIEW result for this exact submission.</p>
                <div className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                  {performedControls.length === 0 ? <div className="text-xs text-gray-500">No determinate control results.</div> : performedControls.map((control) => (
                    <div key={control.id} className="rounded border border-gray-800 bg-gray-950 p-3">
                      <div className="text-[10px] uppercase tracking-wide text-gray-600">{control.category}</div>
                      <div className="mt-1 flex items-start justify-between gap-2"><span className="text-xs font-medium text-gray-200">{control.label}</span><span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold ${statusClass(control.status)}`}>{control.status}</span></div>
                      <p className="mt-2 text-[11px] leading-5 text-gray-500">{control.detail}</p>
                    </div>
                  ))}
                </div>
              </section>

              <section className="rounded-lg border border-gray-800 bg-gray-900 p-4" aria-label="Checks not completed">
                <div className="text-sm font-semibold text-white">Supported checks not completed</div>
                <p className="mt-1 text-xs text-gray-500">ERROR, INCOMPLETE, and NOT_RUN are visible gaps and never count as approval evidence.</p>
                <div className="mt-3 space-y-2">
                  {incompleteControls.length === 0 ? <div className="text-xs text-green-300">No supported controls are incomplete or not run.</div> : incompleteControls.map((control) => (
                    <div key={control.id} className="rounded border border-red-900/50 bg-red-950/10 p-3">
                      <div className="flex flex-wrap items-start justify-between gap-2"><div><div className="text-[10px] uppercase tracking-wide text-gray-600">{control.category}</div><div className="mt-1 text-xs font-medium text-gray-200">{control.label}</div></div><span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${statusClass(control.status)}`}>{control.status}</span></div>
                      <p className="mt-2 text-[11px] text-gray-500">{control.detail}</p><p className="mt-1 text-[11px] text-cyan-300">Next: {control.remediation}</p>
                    </div>
                  ))}
                </div>
              </section>

              <details className="rounded-lg border border-gray-800 bg-gray-900">
                <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-white">Corporate approval requirements outside ShakerScan ({report.detailed_review.external_approval_requirements.length})</summary>
                <div className="border-t border-gray-800 p-4"><p className="mb-3 text-xs text-gray-500">These are expected corporate reviews—not hidden scanner failures. ShakerScan can bind resulting evidence, but it does not make these decisions.</p><div className="space-y-2">{report.detailed_review.external_approval_requirements.map((item) => <div key={item.id} className="rounded border border-gray-800 bg-gray-950 p-3"><div className="flex flex-wrap items-center gap-2"><span className="font-mono text-[10px] text-gray-600">{item.id}</span><span className="text-[10px] uppercase tracking-wide text-gray-500">{item.category}</span><span className="rounded bg-blue-950 px-1.5 py-0.5 text-[9px] font-semibold text-blue-300">{item.status}</span></div><div className="mt-1 text-xs text-gray-200">{item.requirement}</div><div className="mt-2 text-[11px] text-gray-500">Owner: {item.typical_owner} · Evidence: {item.expected_evidence}</div></div>)}</div></div>
              </details>

              <details className="rounded-lg border border-gray-800 bg-gray-900">
                <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-white">Detailed control evidence ({report.controls.length})</summary>
                <div className="grid gap-2 border-t border-gray-800 p-4 sm:grid-cols-2 xl:grid-cols-3">
                  {report.controls.map((control) => (
                    <div key={control.id} className="rounded border border-gray-800 bg-gray-950 p-3">
                      <div className="flex items-start justify-between gap-2"><span className="text-xs font-medium text-gray-200">{control.question}</span><span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold ${statusClass(control.status)}`}>{control.status}</span></div>
                      <p className="mt-2 text-[11px] leading-5 text-gray-500">{control.detail}</p><p className="mt-2 text-[10px] text-gray-600">Method: {control.method}</p>
                      {control.evidence_refs.length > 0 && <div className="mt-2 text-[10px] text-gray-600">{control.evidence_refs.length} evidence reference{control.evidence_refs.length === 1 ? '' : 's'}</div>}
                    </div>
                  ))}
                </div>
              </details>
              <div className="rounded border border-gray-800 bg-gray-900 p-3 text-[11px] text-gray-500">
                Statuses are normalized to PASS, FAIL, REVIEW, INCOMPLETE, ERROR, NOT_RUN, or NOT_APPLICABLE. The printable HTML uses the same report digest and browser printing provides the PDF artifact; SARIF contains every non-passing control for CI ingestion.
              </div>
            </div>
          )}
        </div>
      </details>
    </Card>
  )
}
