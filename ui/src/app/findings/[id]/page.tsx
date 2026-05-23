'use client'

import { useEffect, useMemo, useState, useCallback, Suspense } from 'react'
import { Check, Copy, ExternalLink } from 'lucide-react'
import { useParams, useSearchParams, useRouter } from 'next/navigation'
import Link from 'next/link'
import {
  formatDate,
  getFinding,
  getFindingRetests,
  retestFinding,
  retestAiFinding,
  updateFinding,
  deleteFinding,
  getSeverityBg,
  type Finding,
  type RetestRecord
} from '@/lib/api'
import { FINDING_STATUSES } from '@/lib/constants'
import { formatAnomaly, parseEvidence, extractEndpoint, decodePayload } from '@/lib/evidence-parser'

function StatusBadge({ status }: { status: Finding['status'] }) {
  const styles: Record<string, string> = {
    active: 'bg-yellow-500/20 text-yellow-400',
    resolved: 'bg-green-500/20 text-green-400',
    false_positive: 'bg-gray-500/20 text-gray-400',
    accepted_risk: 'bg-purple-500/20 text-purple-400'
  }

  return (
    <span className={`px-2 py-0.5 text-xs font-medium rounded ${styles[status] || styles.active}`}>
      {status.replace('_', ' ')}
    </span>
  )
}

function getFindingSourceType(finding: Finding): 'AI' | 'DAST' | 'Model Intake' {
  if (finding.source === 'model_intake' || finding.tool === 'model_intake') {
    return 'Model Intake'
  }
  if (finding.source === 'ai_gate' || finding.source === 'ai_session' || finding.ai_target_id) {
    return 'AI'
  }
  return 'DAST'
}

function SourceTypeBadge({ finding }: { finding: Finding }) {
  const type = getFindingSourceType(finding)
  const styles: Record<'AI' | 'DAST' | 'Model Intake', string> = {
    AI: 'bg-purple-500/20 text-purple-300',
    DAST: 'bg-blue-500/20 text-blue-300',
    'Model Intake': 'bg-cyan-500/20 text-cyan-300'
  }

  return (
    <span className={`px-2 py-0.5 text-xs font-medium rounded ${styles[type]}`}>
      {type}
    </span>
  )
}

function SectionCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
      <h2 className="text-sm font-medium text-gray-400 mb-3">{title}</h2>
      {children}
    </div>
  )
}

function InfoItem({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-xs text-gray-500">{label}</p>
      <div className="text-sm text-gray-200 mt-1">{children}</div>
    </div>
  )
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

function evidenceString(evidence: Record<string, unknown> | null, key: string): string {
  const value = evidence?.[key]
  return typeof value === 'string' ? value : ''
}

function evidenceStringList(evidence: Record<string, unknown> | null, key: string): string[] {
  const value = evidence?.[key]
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []
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
  const findingId = params.id as string
  const [finding, setFinding] = useState<Finding | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [statusUpdating, setStatusUpdating] = useState(false)
  const [retestLoading, setRetestLoading] = useState(false)
  const [retestMessage, setRetestMessage] = useState<string | null>(null)
  const [retestMode, setRetestMode] = useState<'tiered' | 'deterministic' | 'ai' | 'same_probe' | 'same_family' | 'strict_replay'>('tiered')
  const [retestHistory, setRetestHistory] = useState<RetestRecord[]>([])

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
      const [data, retestData] = await Promise.all([
        getFinding(findingId),
        getFindingRetests(findingId, 10).catch(() => null)
      ])
      setFinding(data)
      if (retestData) {
        setRetestHistory(retestData.retests || [])
      }
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

  async function handleStatusChange(newStatus: string) {
    if (!finding || statusUpdating) return
    try {
      setStatusUpdating(true)
      await updateFinding(finding.id, newStatus, undefined, finding.scan_id)
      await fetchFinding()
    } catch (err) {
      console.error('Failed to update finding:', err)
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
    } catch (err) {
      console.error('Failed to update analyst verdict:', err)
    } finally {
      setStatusUpdating(false)
    }
  }

  async function handleDelete() {
    if (!finding) return
    if (!confirm('Delete this finding permanently? This cannot be undone.')) return
    try {
      await deleteFinding(finding.id)
      router.push(backUrl)
    } catch (err) {
      console.error('Failed to delete finding:', err)
    }
  }

  async function handleRetest() {
    if (!finding || retestLoading) return
    try {
      setRetestLoading(true)
      setRetestMessage(null)
      const aiFinding = getFindingSourceType(finding) === 'AI'
      const queued = aiFinding
        ? await retestAiFinding(finding.id, {
            requested_by: 'ui',
            mode: ['same_probe', 'same_family', 'strict_replay'].includes(retestMode)
              ? retestMode as 'same_probe' | 'same_family' | 'strict_replay'
              : 'same_probe'
          })
        : await retestFinding(
            finding.id,
            { requested_by: 'ui' },
            retestMode === 'tiered' || ['same_probe', 'same_family', 'strict_replay'].includes(retestMode)
              ? undefined
              : retestMode as 'ai' | 'deterministic'
          )
      setRetestMessage(`${aiFinding ? 'AI Gate replay' : 'Retest'} queued (${queued.retest_id.slice(0, 8)}...)`)
      const history = await getFindingRetests(finding.id, 10)
      setRetestHistory(history.retests || [])
      await fetchFinding()
    } catch (err) {
      console.error('Failed to queue retest:', err)
      setRetestMessage('Failed to queue retest')
    } finally {
      setRetestLoading(false)
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
  const isAiFinding = finding ? getFindingSourceType(finding) === 'AI' : false
  const retestOptions = isAiFinding
    ? [
        { value: 'same_probe', label: 'Same probe' },
        { value: 'same_family', label: 'Same family' },
        { value: 'strict_replay', label: 'Strict replay' },
      ]
    : [
        { value: 'tiered', label: 'Tiered' },
        { value: 'deterministic', label: 'Deterministic only' },
        { value: 'ai', label: 'AI only' },
      ]
  const selectedRetestMode = retestOptions.some((option) => option.value === retestMode)
    ? retestMode
    : retestOptions[0].value
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
      <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 text-red-400">
        {error || 'Finding not found'}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Link href={backUrl} className="text-gray-400 hover:text-white">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </Link>
          <h1 className="text-2xl font-bold text-white">Finding Detail</h1>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={selectedRetestMode}
            onChange={(e) => setRetestMode(e.target.value as typeof retestMode)}
            className="px-2 py-1.5 bg-gray-900 border border-gray-700 rounded-lg text-xs text-gray-200 focus:outline-none focus:border-blue-500"
            title="Retest mode"
          >
            {retestOptions.map((option) => (
              <option key={option.value} value={option.value}>{option.label}</option>
            ))}
          </select>
          <button
            onClick={handleRetest}
            disabled={retestLoading}
            className="px-3 py-1.5 bg-blue-900/50 text-blue-300 rounded-lg text-sm hover:bg-blue-900/80 transition-colors disabled:opacity-50"
          >
            {retestLoading ? 'Queueing...' : 'Retest Finding'}
          </button>
          <button
            onClick={handleDelete}
            className="px-3 py-1.5 bg-red-900/50 text-red-400 rounded-lg text-sm hover:bg-red-900/80 transition-colors"
          >
            Delete
          </button>
        </div>
      </div>

      <SectionCard title="Overview">
        <div className="flex flex-col gap-4">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`px-2 py-0.5 text-xs font-medium rounded ${getSeverityBg(finding.severity)}`}>
                  {finding.severity}
                </span>
                <StatusBadge status={finding.status} />
                <SourceTypeBadge finding={finding} />
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

      <SectionCard title="Tracking">
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

      <SectionCard title="Retest Verification">
        <div className="space-y-3">
          {retestMessage && (
            <div className={`text-xs rounded px-2 py-1 ${
              retestMessage.includes('Failed')
                ? 'bg-red-900/30 text-red-300 border border-red-900/60'
                : 'bg-blue-900/30 text-blue-300 border border-blue-900/60'
            }`}>
              {retestMessage}
            </div>
          )}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
            <InfoItem label="Last status">
              <span className="capitalize">{finding.last_verification_status || 'not tested'}</span>
            </InfoItem>
            <InfoItem label="Last verdict">
              <span className="capitalize">{(finding.last_verification_verdict || 'n/a').replaceAll('_', ' ')}</span>
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
              {retestHistory.map((entry) => (
                <div key={entry.id} className="bg-gray-800/60 rounded p-2 text-xs">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="text-gray-300">
                      {entry.finding_type} • {(entry.verdict || entry.result_status || entry.status).replaceAll('_', ' ')}
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
            </div>
          ) : (
            <p className="text-xs text-gray-500">No retests recorded yet.</p>
          )}
        </div>
      </SectionCard>

      <SectionCard title="Evidence Summary">
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
                <pre className="mt-3 text-xs text-gray-300 whitespace-pre-wrap break-words">{rawEvidence}</pre>
              </details>
            )}
          </div>
        </SectionCard>
      )}

      <SectionCard title="AI Analysis">
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
        <SectionCard title="HTTP Request/Response">
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
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <details>
            <summary className="text-sm font-medium text-gray-400 cursor-pointer">Raw Evidence</summary>
            <pre className="mt-3 text-xs text-gray-300 whitespace-pre-wrap break-words">{rawEvidence}</pre>
          </details>
        </div>
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
