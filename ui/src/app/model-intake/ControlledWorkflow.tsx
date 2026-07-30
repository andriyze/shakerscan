'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
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
  type ModelIntakePlatform,
  type ModelIntakeRunnerJob,
  type ModelIntakeRunnerReadiness,
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
  const subject = detail?.subjects.find((item) => item.subject_kind === kind)
  return typeof subject?.sha256 === 'string' ? subject.sha256 : ''
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
      pooling: 'review-required',
      normalization: false,
      max_sequence_length: 0,
      precision: 'review-required',
    },
    retrieval_application_digest: '',
    index_schema_digest: '',
    target_environment: environment,
  }
}

export function ControlledModelIntakeWorkflow({
  operatorToken,
  onOperatorTokenChange,
  defaultSource,
  defaultSourceKind,
}: {
  operatorToken: string
  onOperatorTokenChange: (value: string) => void
  defaultSource: string
  defaultSourceKind: ModelIntakePlatform
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

  const [source, setSource] = useState(defaultSource)
  const [sourceKind, setSourceKind] = useState<ModelIntakePlatform>(defaultSourceKind)
  const [environment, setEnvironment] = useState<ModelIntakeWorkflowSubmission['requested_environment']>('production')
  const [expectedSha, setExpectedSha] = useState('')
  const [intendedUse, setIntendedUse] = useState('{"purpose":"knowledge-graph vector embeddings","data_classification":"internal"}')
  const [staticScanId, setStaticScanId] = useState('')
  const [bundleJson, setBundleJson] = useState(JSON.stringify(blankBundle(), null, 2))
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

  const [manifestId, setManifestId] = useState('')
  const [approvalType, setApprovalType] = useState('model_security_reviewer')
  const [approvalDecision, setApprovalDecision] = useState<'approve' | 'reject'>('approve')
  const [approvalReason, setApprovalReason] = useState('Reviewed the exact frozen evidence and deployment bundle.')
  const [policyDecisionId, setPolicyDecisionId] = useState('')
  const [idempotencyKey, setIdempotencyKey] = useState('')

  useEffect(() => {
    if (defaultSource) setSource(defaultSource)
  }, [defaultSource])

  useEffect(() => setSourceKind(defaultSourceKind), [defaultSourceKind])

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
      const response = await createModelIntakeSubmission({
        source: source.trim(),
        source_kind: sourceKind,
        intended_environment: environment,
        intended_use: parseObject(intendedUse, 'Intended use'),
        expected_artifact_sha256: expectedSha.trim() || undefined,
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

  function seedBundleFromEvidence() {
    if (!detail) return
    const request = objectValue(latestJob?.request_json)
    const seeded = blankBundle(detail.submission.requested_environment)
    seeded.model_artifact_sha256 = subjectDigest(detail, 'artifact')
    seeded.repository_snapshot_sha256 = subjectDigest(detail, 'repository_snapshot')
    seeded.runtime_image_digest = typeof request.runtime_image_digest === 'string' ? request.runtime_image_digest : ''
    seeded.loader_profile_sha256 = typeof request.loader_profile_sha256 === 'string' ? request.loader_profile_sha256 : ''
    setBundleJson(JSON.stringify(seeded, null, 2))
  }

  async function queueRunnerJob() {
    setBusy('runner')
    setError(null)
    try {
      const id = requireSelection()
      if (!bundle) throw new Error('Deployment bundle JSON is invalid')
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
      await refreshModelIntakeRunnerJob(id, jobId, operatorToken)
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

  return (
    <Card className="min-w-0 p-4" id="controlled-model-intake-workflow">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 text-white">
            <LockKeyhole className="h-4 w-4 text-cyan-300" />
            <h2 className="text-sm font-semibold">Controlled corporate admission workflow</h2>
          </div>
          <p className="mt-1 max-w-4xl text-xs text-gray-400">
            Generated static evidence, exact-subject Firecracker execution, frozen evidence, identity-separated approvals, deterministic policy, and isolated signing. Technical preflight above never grants deployment authority.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`rounded px-2 py-1 text-xs font-semibold ${statusClass(runnerReadiness?.status || 'checking')}`}>
            Firecracker {runnerReadiness?.status || 'checking'}
          </span>
          <button type="button" className={buttonClass} onClick={() => { void loadReadiness(); void loadSubmissions(); if (selectedId) void loadSelected() }}>
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
        </div>
      </div>

      {!operatorToken.trim() && (
        <div className="mt-4 flex gap-2 rounded border border-yellow-700/50 bg-yellow-950/20 p-3 text-xs text-yellow-200">
          <ShieldAlert className="h-4 w-4 shrink-0" /> Enter an operator credential below. It stays in session storage and is never rendered in workflow evidence.
        </div>
      )}
      <label className="mt-4 grid max-w-2xl gap-1 text-xs text-gray-300">
        Operator credential for controlled workflow
        <input
          className={inputClass}
          type="password"
          autoComplete="off"
          value={operatorToken}
          onChange={(event) => onOperatorTokenChange(event.target.value)}
          placeholder="Required for submissions, evidence, runner jobs, approvals, and promotion"
        />
        <span className="text-[11px] text-gray-500">Stored only in this browser session. Production reviewer identities and roles are resolved server-side from hashed credential records.</span>
      </label>
      {error && <div role="alert" className="mt-4 break-words rounded border border-red-700/50 bg-red-950/20 p-3 text-xs text-red-300">{error}</div>}

      <details className="mt-4 rounded-lg border border-gray-800 bg-gray-950" open>
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-white">1. Create or select a submission</summary>
        <div className="grid gap-4 border-t border-gray-800 p-4 xl:grid-cols-2">
          <div className="grid gap-3">
            <label className="grid gap-1 text-xs text-gray-300">Immutable source reference
              <input className={inputClass} value={source} onChange={(event) => setSource(event.target.value)} placeholder="hf://org/model@commit/model.safetensors" />
            </label>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="grid gap-1 text-xs text-gray-300">Source kind
                <select className={inputClass} value={sourceKind} onChange={(event) => setSourceKind(event.target.value as ModelIntakePlatform)}>
                  {['auto', 'huggingface', 'http', 's3', 'gcs', 'azure', 'oci', 'mlflow'].map((value) => <option key={value} value={value}>{value}</option>)}
                </select>
              </label>
              <label className="grid gap-1 text-xs text-gray-300">Intended environment
                <select className={inputClass} value={environment} onChange={(event) => setEnvironment(event.target.value as ModelIntakeWorkflowSubmission['requested_environment'])}>
                  {['development', 'test', 'staging', 'production'].map((value) => <option key={value} value={value}>{value}</option>)}
                </select>
              </label>
            </div>
            <label className="grid gap-1 text-xs text-gray-300">Expected artifact SHA-256 (optional until resolved)
              <input className={inputClass} value={expectedSha} onChange={(event) => setExpectedSha(event.target.value)} />
            </label>
            <label className="grid gap-1 text-xs text-gray-300">Intended-use declaration
              <textarea className={textareaClass} rows={4} value={intendedUse} onChange={(event) => setIntendedUse(event.target.value)} />
            </label>
            <button type="button" className={buttonClass} disabled={busy === 'create' || !source.trim()} onClick={createSubmission}>
              {busy === 'create' ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <LockKeyhole className="h-3.5 w-3.5" />} Create controlled submission
            </button>
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
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-white">2. Bind completed static evidence</summary>
        <div className="border-t border-gray-800 p-4">
          <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto]">
            <label className="grid gap-1 text-xs text-gray-300">Completed Model Intake scan ID
              <input className={inputClass} value={staticScanId} onChange={(event) => setStaticScanId(event.target.value)} placeholder="UUID from a completed complete-snapshot scan" />
            </label>
            <button type="button" className={`${buttonClass} self-end`} disabled={busy === 'static' || !selectedId || !staticScanId.trim()} onClick={attachStaticRun}>Attach generated evidence</button>
          </div>
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
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-white">3. Firecracker calibration, runtime, conversion, and telemetry</summary>
        <div className="grid gap-4 border-t border-gray-800 p-4 xl:grid-cols-[minmax(0,0.8fr)_minmax(0,1.2fr)]">
          <div className="grid gap-3">
            <div className="flex flex-wrap items-center justify-between gap-2"><span className="text-xs text-gray-400">Exact deployment bundle</span><button type="button" className={buttonClass} onClick={seedBundleFromEvidence}>Seed authoritative digests</button></div>
            <textarea className={textareaClass} rows={18} value={bundleJson} onChange={(event) => setBundleJson(event.target.value)} />
            <div className="grid gap-3 sm:grid-cols-3">
              <label className="grid gap-1 text-xs text-gray-300">Operation<select className={inputClass} value={runnerOperation} onChange={(event) => setRunnerOperation(event.target.value as typeof runnerOperation)}><option value="calibration">calibration</option><option value="runtime">runtime</option><option value="conversion">conversion</option></select></label>
              <label className="grid gap-1 text-xs text-gray-300">vCPU<input className={inputClass} type="number" min={1} max={32} value={vcpuCount} onChange={(event) => setVcpuCount(Number(event.target.value))} /></label>
              <label className="grid gap-1 text-xs text-gray-300">Memory MiB<input className={inputClass} type="number" min={256} value={memoryMib} onChange={(event) => setMemoryMib(Number(event.target.value))} /></label>
            </div>
            <label className="grid gap-1 text-xs text-gray-300">Known-answer inputs (bounded JSON string array)<textarea className={textareaClass} rows={3} value={knownAnswerInputs} onChange={(event) => setKnownAnswerInputs(event.target.value)} /></label>
            <label className="grid gap-1 text-xs text-gray-300">Reviewed known-answer embedding SHA-256 {runnerOperation === 'runtime' ? '(required)' : '(optional)'}<input className={inputClass} value={knownAnswerDigest} onChange={(event) => setKnownAnswerDigest(event.target.value)} /></label>
            <label className="grid gap-1 text-xs text-gray-300">Wall-clock timeout seconds<input className={inputClass} type="number" min={30} max={3600} value={timeoutSeconds} onChange={(event) => setTimeoutSeconds(Number(event.target.value))} /></label>
            <button type="button" className={buttonClass} disabled={busy === 'runner' || !selectedId || !runnerReadiness?.ready} onClick={queueRunnerJob}><Server className="h-3.5 w-3.5" /> Queue exact-subject Firecracker job</button>
            {!runnerReadiness?.ready && <div className="rounded border border-red-800/60 bg-red-950/20 p-3 text-xs text-red-300">No fallback is used. {runnerReadiness?.error || 'Linux/KVM runner prerequisites are incomplete.'}</div>}
          </div>
          <div className="min-w-0 space-y-3">
            {jobs.length === 0 ? <div className="rounded border border-gray-800 p-3 text-xs text-gray-500">No runner jobs for this submission.</div> : jobs.map((job) => {
              const observations = runnerObservations(job)
              const phases = objectValue(observations.phases)
              const network = objectValue(observations.network_telemetry)
              const resources = objectValue(observations.resource_telemetry)
              return (
                <div key={job.id} className="rounded-lg border border-gray-800 bg-gray-900 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div><span className="font-mono text-xs text-gray-200">{job.operation} · {job.id}</span><div className="mt-1 text-[10px] text-gray-500">request {shortDigest(job.request_sha256)}</div></div>
                    <div className="flex items-center gap-2"><span className={`rounded px-2 py-1 text-[10px] font-semibold ${statusClass(job.state)}`}>{job.state}</span><button type="button" className={buttonClass} disabled={busy === `refresh:${job.id}`} onClick={() => void refreshJob(job.id)}><RefreshCw className={`h-3 w-3 ${busy === `refresh:${job.id}` ? 'animate-spin' : ''}`} /> Refresh</button></div>
                  </div>
                  {Object.keys(phases).length > 0 && <div className="mt-3"><div className="mb-2 flex items-center gap-2 text-xs text-gray-400"><Activity className="h-3.5 w-3.5" /> Phase timeline</div><div className="grid gap-2 sm:grid-cols-2">{Object.entries(phases).map(([name, value]) => { const phase = objectValue(value); const phaseStatus = String(phase.status || value); return <div key={name} className="rounded border border-gray-800 px-2 py-1.5 text-[11px]"><div className="flex justify-between gap-2"><span className="text-gray-300">{name.replace(/_/g, ' ')}</span><span className={statusClass(phaseStatus)}>{phaseStatus}</span></div>{phase.duration_ms !== undefined && <div className="mt-1 text-gray-600">{String(phase.duration_ms)} ms</div>}</div> })}</div></div>}
                  {Object.keys(network).length > 0 && <div className="mt-3 rounded border border-gray-800 p-3 text-[11px]"><div className="flex items-center justify-between gap-2"><span className="font-medium text-gray-300">Independent network telemetry</span><span className={network.complete === true && network.overflowed === false && network.lost_events === 0 ? 'text-green-300' : 'text-red-300'}>{network.complete === true ? 'complete' : 'incomplete'}</span></div><div className="mt-2 grid gap-1 text-gray-500 sm:grid-cols-2"><span>attempts: <b className="text-gray-200">{String(network.attempt_count ?? 'unknown')}</b></span><span>lost: <b className="text-gray-200">{String(network.lost_events ?? 'unknown')}</b></span><span>overflowed: <b className="text-gray-200">{String(network.overflowed ?? 'unknown')}</b></span><span>guest interfaces: <b className="text-gray-200">{Array.isArray(network.guest_interfaces) ? network.guest_interfaces.join(', ') : 'unknown'}</b></span><span>host drops: <b className="text-gray-200">{String(network.host_firewall_drop_count ?? 'unknown')}</b></span><span>digest: <b className="font-mono text-gray-200">{shortDigest(network.telemetry_sha256)}</b></span></div>{Number(network.attempt_count || 0) > 0 && <pre className="mt-2 max-h-32 overflow-auto whitespace-pre-wrap break-all rounded bg-gray-950 p-2 text-red-300">{JSON.stringify({ attempted_operations: network.attempted_operations, attempts_by_phase: network.attempts_by_phase }, null, 2)}</pre>}</div>}
                  {Object.keys(resources).length > 0 && <div className="mt-2 rounded border border-gray-800 p-3 text-[11px] text-gray-500"><span className="font-medium text-gray-300">Host resource envelope</span><pre className="mt-2 max-h-36 overflow-auto whitespace-pre-wrap break-all font-mono text-gray-400">{JSON.stringify(resources, null, 2)}</pre></div>}
                  {job.error_json && <pre className="mt-2 max-h-36 overflow-auto whitespace-pre-wrap break-all rounded border border-red-900 bg-red-950/20 p-2 text-[11px] text-red-300">{JSON.stringify(job.error_json, null, 2)}</pre>}
                </div>
              )
            })}
          </div>
        </div>
      </details>

      <details className="mt-3 rounded-lg border border-gray-800 bg-gray-950">
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-white">4. Codex-guided investigation (advisory only)</summary>
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
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-white">5. Freeze, approve, evaluate policy, and promote</summary>
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
            <label className="grid gap-1 text-xs text-gray-300">Promotion idempotency key<input className={inputClass} value={idempotencyKey} onChange={(event) => setIdempotencyKey(event.target.value)} placeholder="release-ticket-and-random-suffix (16+ chars)" /></label>
            <button type="button" className={buttonClass} disabled={!policyDecisionId || idempotencyKey.length < 16 || busy === 'promote'} onClick={promote}>Invoke isolated signer and promote</button>
            {detail && <div className="rounded border border-gray-800 p-3 text-xs"><div className="mb-2 text-gray-300">Submission event timeline</div><div className="max-h-64 space-y-2 overflow-auto">{detail.events.slice().reverse().slice(0, 30).map((event) => <div key={event.id} className="border-l border-gray-700 pl-3"><div className="text-gray-300">{String(event.event_type || 'event').replace(/_/g, ' ')}</div><div className="text-[10px] text-gray-600">{String(event.created_at || '')} · {String(event.actor || 'system')}</div>{typeof event.reason === 'string' && event.reason && <div className="mt-0.5 text-[11px] text-gray-500">{event.reason}</div>}</div>)}</div></div>}
            <Link href="/settings/policy-profiles" className={`${buttonClass} text-center`}>Review deployment policy profiles</Link>
          </div>
        </div>
      </details>

      <details className="mt-3 rounded-lg border border-gray-800 bg-gray-950" open={Boolean(report)}>
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-white">6. Normalized corporate review report</summary>
        <div className="border-t border-gray-800 p-4">
          {!report ? <div className="text-xs text-gray-500">Select a controlled submission to generate its authoritative report.</div> : (
            <div className="grid gap-4">
              <div className="flex flex-wrap items-start justify-between gap-3 rounded-lg border border-gray-800 bg-gray-900 p-4">
                <div className="min-w-0">
                  <div className="flex items-center gap-2"><FileText className="h-4 w-4 text-cyan-300" /><span className={`rounded px-2 py-1 text-xs font-bold ${statusClass(report.outcome)}`}>{report.outcome}</span></div>
                  <p className="mt-2 text-sm text-gray-200">{report.plain_language}</p>
                  <div className="mt-2 break-all font-mono text-[10px] text-gray-600">report sha256:{report.report_sha256}</div>
                </div>
                <div className="flex flex-wrap gap-2">
                  {(['json', 'html', 'sarif'] as const).map((format) => <button key={format} type="button" className={buttonClass} disabled={busy === `report:${format}`} onClick={() => void exportReport(format)}><Download className="h-3.5 w-3.5" /> {format === 'html' ? 'Printable HTML / PDF' : format.toUpperCase()}</button>)}
                </div>
              </div>
              <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                {report.controls.map((control) => (
                  <div key={control.id} className="rounded border border-gray-800 bg-gray-900 p-3">
                    <div className="flex items-start justify-between gap-2"><span className="text-xs font-medium text-gray-200">{control.label}</span><span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold ${statusClass(control.status)}`}>{control.status}</span></div>
                    <p className="mt-2 text-[11px] leading-5 text-gray-500">{control.detail}</p>
                    {control.evidence_refs.length > 0 && <div className="mt-2 text-[10px] text-gray-600">{control.evidence_refs.length} evidence reference{control.evidence_refs.length === 1 ? '' : 's'}</div>}
                  </div>
                ))}
              </div>
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
