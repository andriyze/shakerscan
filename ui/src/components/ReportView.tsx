'use client'

import React, { useState } from 'react'
import Link from 'next/link'
import ExportPDFButton from '@/components/ExportPDFButton'
import ComplianceSection from '@/components/ComplianceSection'
import RemediationSummary from '@/components/RemediationSummary'
import FindingActions from '@/components/FindingActions'
import FindingCard from '@/components/FindingCard'
import {
  getApiUrl,
  getModelIntakeSbomSummary,
  downloadModelIntakeLicenseArtifact,
  downloadModelIntakeSbom,
  type ModelIntakeSbomSummary,
} from '@/lib/api'
import { gradeTextColor } from '@/components/ui'
import { SEVERITY_BADGE_STYLES, type SeverityLevel } from '@/lib/constants'
import { AlertTriangle, CheckCircle2, Download } from 'lucide-react'
import { normalizeSkipReasons } from '@/lib/deferredWorkContracts'
import { deviceScorePresentation } from '@/lib/deviceScanPresentation.mjs'
import { buildFindingLinkageIndex, linkedPersistedFinding } from '@/lib/findingLinkage'

type RemediationStatus = 'open' | 'in_progress' | 'remediated' | 'false_positive' | 'accepted_risk'

type RemediationData = {
  finding_id: string
  status: RemediationStatus
  notes?: string
}

type Props = {
  scan: any
  shareControls?: React.ReactNode
  isAuthenticated?: boolean
  remediations?: RemediationData[]
  enableRemediationTracking?: boolean
}

function getSeverityPill(severity?: string) {
  const s = (severity || 'info').toLowerCase()
  return SEVERITY_BADGE_STYLES[s as SeverityLevel] ?? SEVERITY_BADGE_STYLES.info
}

function getSeverityBorderClass(severity?: string) {
  const s = (severity || '').toLowerCase()
  return s === 'critical'
    ? 'border-red-500'
    : s === 'high'
    ? 'border-orange-500'
    : s === 'medium'
    ? 'border-yellow-500'
    : s === 'low'
    ? 'border-blue-500'
    : 'border-slate-500'
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

function sortBySeverity(findings: any[]): any[] {
  return [...findings].sort((a, b) => {
    const severityA = SEVERITY_ORDER[(a.severity || 'info').toLowerCase()] ?? 5
    const severityB = SEVERITY_ORDER[(b.severity || 'info').toLowerCase()] ?? 5
    return severityA - severityB
  })
}

function asRecord(value: any): Record<string, any> {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value
  }
  return {}
}

function formatCheckFamilyName(value: string): string {
  const labels: Record<string, string> = {
    sqli: 'SQLi',
    xss: 'XSS',
  }
  return labels[value] || value.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
}

function getCheckFamilyScopeLabel(scope: any): string | null {
  const rec = asRecord(scope)
  const families = Array.isArray(rec.families) ? rec.families.filter((v: any) => typeof v === 'string') : []
  if (rec.mode === 'focused' && typeof rec.focused_family === 'string') {
    return `${formatCheckFamilyName(rec.focused_family)} only`
  }
  if (rec.mode === 'active_mix' && families.length) {
    return families.map(formatCheckFamilyName).join(' + ')
  }
  if (rec.mode === 'custom_active') {
    return 'Custom active scope'
  }
  return null
}

function parseEvidenceRecord(evidence: any): Record<string, any> {
  if (!evidence) return {}
  if (typeof evidence === 'string') {
    try {
      return asRecord(JSON.parse(evidence))
    } catch {
      return {}
    }
  }
  return asRecord(evidence)
}

function formatConfidence(value: any): string | null {
  if (typeof value !== 'number' || Number.isNaN(value)) return null
  return value > 1 ? `${Math.round(value)}%` : `${Math.round(value * 100)}%`
}

function compactJson(value: any): string {
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

function formatBytes(value: any): string {
  const bytes = Number(value)
  if (!Number.isFinite(bytes) || bytes < 0) return 'unknown'
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(1)} GB`
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`
  return `${bytes} B`
}

function formatScanToken(value: any): string {
  return String(value || 'unknown')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase())
}

function activeAttemptStatusClass(status: any): string {
  const value = String(status || '').toLowerCase()
  if (value === 'completed') return 'bg-green-500/10 text-green-300'
  if (value === 'partial') return 'bg-yellow-500/10 text-yellow-300'
  if (value === 'skipped') return 'bg-blue-500/10 text-blue-300'
  if (value === 'failed' || value === 'error') return 'bg-red-500/10 text-red-300'
  return 'bg-gray-700 text-gray-300'
}

function activeAttemptFamilies(attempt: any): string[] {
  if (Array.isArray(attempt?.families)) {
    return attempt.families.filter((family: any) => typeof family === 'string' && family.trim())
  }
  if (typeof attempt?.family === 'string' && attempt.family.trim()) return [attempt.family]
  if (attempt?.family_attempts && typeof attempt.family_attempts === 'object') {
    return Object.keys(attempt.family_attempts)
  }
  return []
}

function activeAttemptParamSummary(attempt: any): string {
  const completed = Number(attempt?.completed_params_count ?? 0)
  const attempted = Number(attempt?.attempted_params_count ?? 0)
  const expected = Number(attempt?.param_count ?? 0)
  const left = Number.isFinite(completed) ? completed : 0
  const right = Number.isFinite(expected) && expected > 0
    ? expected
    : (Number.isFinite(attempted) && attempted > 0 ? attempted : 0)
  return `${left} / ${right} params`
}

function activeAttemptParamPreview(attempt: any): string | null {
  const names = Array.isArray(attempt?.param_names)
    ? attempt.param_names.filter((name: any) => typeof name === 'string' && name.trim())
    : []
  if (!names.length) return null
  const location = Array.isArray(attempt?.param_locations) && attempt.param_locations.length === 1
    ? `${String(attempt.param_locations[0]).replace(/_/g, ' ')}: `
    : (typeof attempt?.param_location === 'string' && attempt.param_location ? `${attempt.param_location.replace(/_/g, ' ')}: ` : '')
  const shown = names.slice(0, 6).join(', ')
  const suffix = names.length > 6 ? ` +${names.length - 6}` : ''
  return `${location}${shown}${suffix}`
}

function activeAttemptReason(attempt: any): string | null {
  const reason = attempt?.skip_reason || attempt?.budget_exhausted_reason
  if (!reason) return null
  return formatScanToken(reason)
}

function getAIDeployRecommendation(decision: string) {
  if (decision === 'block') return 'Do not deploy'
  if (decision === 'needs_approval') return 'Manual approval required'
  if (decision === 'allow') return 'Deployable with monitoring'
  return 'Awaiting verdict'
}

function formatAIProfile(profile: any) {
  const value = String(profile || '').toLowerCase()
  if (value === 'smoke') return 'Quick'
  if (value === 'trace') return 'Trace'
  if (value === 'standard') return 'Standard'
  if (value === 'deep') return 'Deep'
  return String(profile || 'AI Gate')
}

function getAIJudgingGateDisplay(status: any): { label: string; className: string; title: string } | null {
  switch (String(status || '').toLowerCase()) {
    case 'judging_completed':
      return {
        label: 'AI judged',
        className: 'bg-green-900/50 text-green-200',
        title: 'Semantic judge completed for the probes that required it.',
      }
    case 'judging_failed':
    case 'judging_required':
    case 'judging_unavailable':
      return {
        label: 'needs review',
        className: 'bg-yellow-900/50 text-yellow-200',
        title: 'Semantic judging was required but did not complete; rely on deterministic evidence and manual review.',
      }
    case 'not_required':
      return {
        label: 'deterministic only',
        className: 'bg-gray-800 text-gray-300',
        title: 'This run did not require semantic judging; the visible results are deterministic-only.',
      }
    default:
      return null
  }
}

function formatAIProbePack(pack: any) {
  const value = String(pack || '')
  const labels: Record<string, string> = {
    'shaker-ai-smoke': 'AI Smoke',
    'shaker-owasp-llm': 'OWASP LLM',
    'shaker-agent-abuse': 'Agent Abuse',
    'shaker-mcp-security': 'MCP Security',
    'shaker-rag-lite': 'RAG Lite',
  }
  return labels[value] || value
}

function getAIRecommendedFixes(findings: any[]) {
  const text = findings
    .map((finding) => `${finding.title || ''} ${finding.description || ''} ${finding.category || ''}`)
    .join(' ')
    .toLowerCase()
  const fixes: string[] = []

  if (text.includes('prompt') || text.includes('instruction')) {
    fixes.push('Block system prompt and developer instruction disclosure.')
  }
  if (text.includes('secret') || text.includes('credential') || text.includes('token') || text.includes('pii')) {
    fixes.push('Remove secrets from reachable context and add credential output filtering.')
  }
  if (text.includes('unbounded') || text.includes('cost') || text.includes('consumption')) {
    fixes.push('Enforce output, token, and request limits for expensive generations.')
  }
  if (text.includes('rag') || text.includes('tenant') || text.includes('retrieval')) {
    fixes.push('Apply retrieval ACLs before generation and redact cross-tenant source metadata.')
  }
  if (fixes.length === 0 && findings.length > 0) {
    fixes.push('Review failed probe transcripts, fix the accepted findings, and rerun the same probe pack.')
  }
  if (findings.length > 0) fixes.push('Rerun AI Smoke after fixes before promoting the target.')

  return fixes
}

const MODEL_INTAKE_CHECK_LABELS: Record<string, string> = {
  aibom: 'AIBOM generated',
  approval: 'Deployment approval',
  checksum: 'Checksum evidence',
  provenance: 'Source provenance',
  malware_scan: 'Malware scan evidence',
  license_policy: 'License policy',
  license_review: 'License review',
  security_evals: 'Security evaluation evidence',
  monitoring_plan: 'Monitoring plan',
  artifact_signing: 'Signature or attestation',
  sbom_dependencies: 'SBOM/dependencies',
  unsafe_serialization: 'Safe serialization format',
  signature_verification: 'Signature verification',
  deployment_restrictions: 'Deployment restrictions',
  format_specific_inspection: 'Format-specific inspection',
}

const MODEL_INTAKE_ACTIONS: Record<string, string> = {
  approval: 'Record deployment approval with approver, timestamp, and policy version.',
  checksum: 'Supply a trusted expected SHA-256, or explicitly pin the observed SHA-256 as the approved baseline for this exact artifact revision, then rerun intake.',
  provenance: 'Attach source repository, revision, and release provenance evidence.',
  malware_scan: 'Attach or run a malware/YARA scan result with engine, result, and timestamp.',
  license_policy: 'Record the license and review whether it permits the intended deployment.',
  license_review: 'Resolve the license-policy trigger and attach reviewer evidence.',
  security_evals: 'Attach model safety/security evaluation results and acceptance criteria.',
  monitoring_plan: 'Define monitoring for drift, abuse, leakage, cost anomalies, and incident response.',
  artifact_signing: 'Attach a signature, Sigstore bundle, cosign attestation, or registry signing evidence, then rerun intake for verification.',
  sbom_dependencies: 'Attach or generate an SBOM/dependency inventory for the model package, tokenizer/adapters, and serving runtime.',
  unsafe_serialization: 'Use a non-executable format or run legacy artifacts only through a sandboxed conversion pipeline.',
  signature_verification: 'Verify the signature or attestation and record verification status.',
  deployment_restrictions: 'Record approved environments, data-use limits, prohibited uses, and rollback constraints.',
}

function formatModelIntakeCheckName(check: string) {
  return MODEL_INTAKE_CHECK_LABELS[check] || check.replace(/_/g, ' ')
}

function hasModelIntakeSafeFormatEvidence(summary: any, supplyChain: any) {
  const inspection = supplyChain?.format_inspection || null
  return Boolean(
    summary?.extension === '.safetensors' &&
      inspection?.lower_code_execution_risk &&
      inspection?.safetensors_header?.valid_json
  )
}

function getModelIntakeCheckStatus(check: string, passed: any, summary: any, supplyChain: any) {
  if (check === 'checksum' && summary?.checksum_status === 'known_unverified_truncated') {
    return { label: 'pinned, sampled', className: 'text-yellow-300' }
  }
  if (check === 'unsafe_serialization' && hasModelIntakeSafeFormatEvidence(summary, supplyChain)) {
    return { label: 'passed', className: 'text-green-300' }
  }
  if (check === 'license_policy' && supplyChain?.license_policy?.status === 'missing') {
    return { label: 'missing', className: 'text-yellow-300' }
  }
  if (passed === null || passed === undefined) {
    return { label: 'not requested', className: 'text-gray-400' }
  }
  if (passed) {
    return { label: 'passed', className: 'text-green-300' }
  }
  if (check === 'unsafe_serialization' && summary?.extension === '.safetensors') {
    return { label: 'needs review', className: 'text-yellow-300' }
  }
  return { label: 'missing', className: 'text-red-300' }
}

function getModelIntakeRequiredActions(checks: any, summary: any, supplyChain: any, fetchMeta?: any) {
  if (!checks || typeof checks !== 'object') return []
  const safeFormatEvidence = hasModelIntakeSafeFormatEvidence(summary, supplyChain)
  const fetchWasTruncated = Boolean(fetchMeta?.truncated)
  return Object.entries(checks)
    .filter(([check, passed]) => {
      if (check === 'unsafe_serialization' && safeFormatEvidence) return false
      if (check === 'signature_verification' && checks.artifact_signing === false) return false
      if (passed === true) return false
      if (passed === null || passed === undefined) {
        return check === 'license_policy' && supplyChain?.license_policy?.status === 'missing'
      }
      return Boolean(MODEL_INTAKE_ACTIONS[check])
    })
    .map(([check]) => {
      const action = MODEL_INTAKE_ACTIONS[check] || `Review ${formatModelIntakeCheckName(check).toLowerCase()}.`
      if (check === 'checksum' && summary?.sha256) {
        if (fetchWasTruncated) {
          return `Supply a trusted full-artifact SHA-256, or rerun intake with a larger download cap before pinning this artifact. Observed SHA-256 of inspected bytes: ${summary.sha256}`
        }
        return `${action} Observed SHA-256 available to copy/pin: ${summary.sha256}`
      }
      return action
    })
}

function getAIProbeOutcome(
  turns: any[],
  detectorHits: any[],
  probeFindings: any[],
  wasSemanticallyReviewed: boolean
) {
  const hasHttpError = turns.some((turn) => Number(turn?.status_code || 0) >= 400)
  const hasRequestError = turns.some((turn) => {
    const stopReason = String(turn?.stop_reason || '').toLowerCase()
    return Boolean(turn?.error) || stopReason.includes('error') || stopReason.includes('failed')
  })

  if (probeFindings.length > 0) {
    return {
      label: 'Failed',
      className: 'border-red-500/40 bg-red-950/40 text-red-100',
      dotClassName: 'bg-red-300',
      explanation: 'Attack evidence matched and ShakerScan created a finding for this probe.',
    }
  }

  if (detectorHits.length > 0) {
    return {
      label: 'Needs review',
      className: 'border-yellow-500/40 bg-yellow-950/30 text-yellow-100',
      dotClassName: 'bg-yellow-300',
      explanation: 'A detector saw suspicious text, but it did not become an accepted finding.',
    }
  }

  if (hasHttpError || hasRequestError) {
    return {
      label: 'Request error',
      className: 'border-orange-500/40 bg-orange-950/30 text-orange-100',
      dotClassName: 'bg-orange-300',
      explanation: 'The probe could not be evaluated cleanly because the target request had an error.',
    }
  }

  return {
    label: 'Passed',
    className: 'border-green-500/40 bg-green-950/30 text-green-100',
    dotClassName: 'bg-green-300',
    explanation: wasSemanticallyReviewed
      ? 'No attack evidence was accepted; semantic review also did not create a finding.'
      : 'No attack evidence was accepted; the target stayed within the expected safe behavior.',
  }
}

function renderGenericEvidence(evidence: any): string {
  if (!evidence) return ''
  if (typeof evidence === 'string') return evidence
  const preferredFields = ['url', 'description', 'message', 'issue', 'path', 'parameter', 'payload', 'matched_at', 'note']
  for (const field of preferredFields) {
    if (evidence[field] && typeof evidence[field] === 'string') {
      return evidence[field]
    }
  }
  try {
    const json = JSON.stringify(evidence, null, 2)
    return json.length > 300 ? json.slice(0, 300) + '...' : json
  } catch {
    return String(evidence)
  }
}

function renderFindingEvidence(finding: any) {
  const evidence = finding.evidence || finding.description
  const text = renderGenericEvidence(evidence)
  if (!text) return null
  return <p className="text-gray-300 text-sm mt-1 whitespace-pre-wrap break-words">{text}</p>
}

// Keep the engineer-facing AIBOM prominent; generic package-manager exports
// remain available for downstream automation without dominating the UI.
function ModelIntakeSbomDownload({ scanId }: { scanId: string }) {
  const [summary, setSummary] = useState<ModelIntakeSbomSummary | null>(null)
  const [busy, setBusy] = useState('')
  const [error, setError] = useState<string | null>(null)

  React.useEffect(() => {
    let cancelled = false
    getModelIntakeSbomSummary(scanId).then((next) => {
      if (!cancelled) setSummary(next)
    })
    return () => { cancelled = true }
  }, [scanId])

  async function download(format: 'cyclonedx' | 'spdx' | 'aibom') {
    setBusy(format)
    setError(null)
    try {
      await downloadModelIntakeSbom(scanId, format)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Export failed')
    } finally {
      setBusy('')
    }
  }

  async function downloadLicense(format: 'license-bom' | 'third-party-notices') {
    setBusy(format)
    setError(null)
    try {
      await downloadModelIntakeLicenseArtifact(scanId, format)
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Export failed')
    } finally {
      setBusy('')
    }
  }

  if (!summary?.available) return null
  const thin = summary.dependency_inventory !== 'generated'
  return (
    <div className="text-right">
      <div className="flex flex-wrap items-center justify-end gap-2">
        {summary.aibom_available && (
          <button
            type="button"
            onClick={() => download('aibom')}
            disabled={busy === 'aibom'}
            className="inline-flex items-center gap-2 rounded border border-cyan-700 px-3 py-1.5 text-sm font-semibold text-cyan-200 hover:bg-cyan-950/50 disabled:opacity-50"
          >
            <Download className="h-4 w-4" />
            {busy === 'aibom' ? 'Exporting…' : 'AIBOM'}
          </button>
        )}
        <details className="rounded border border-gray-600 px-3 py-1.5 text-left text-sm text-gray-200">
          <summary className="cursor-pointer select-none">More inventory exports</summary>
          <div className="mt-3 grid gap-2">
            <button type="button" onClick={() => download('cyclonedx')} disabled={busy === 'cyclonedx'} className="inline-flex items-center gap-2 rounded border border-gray-600 px-3 py-1.5 hover:bg-gray-700 disabled:opacity-50">
              <Download className="h-4 w-4" />
              {busy === 'cyclonedx' ? 'Exporting…' : `SBOM (CycloneDX ${summary.spec_version || '1.5'})`}
            </button>
            <button type="button" onClick={() => download('spdx')} disabled={busy === 'spdx'} className="inline-flex items-center gap-2 rounded border border-gray-600 px-3 py-1.5 hover:bg-gray-700 disabled:opacity-50">
              <Download className="h-4 w-4" />
              {busy === 'spdx' ? 'Exporting…' : 'SBOM (SPDX 2.3)'}
            </button>
            <button type="button" onClick={() => downloadLicense('license-bom')} disabled={busy === 'license-bom'} className="inline-flex items-center gap-2 rounded border border-gray-600 px-3 py-1.5 hover:bg-gray-700 disabled:opacity-50">
              <Download className="h-4 w-4" />
              {busy === 'license-bom' ? 'Exporting…' : 'License BOM'}
            </button>
            <button type="button" onClick={() => downloadLicense('third-party-notices')} disabled={busy === 'third-party-notices'} className="inline-flex items-center gap-2 rounded border border-gray-600 px-3 py-1.5 hover:bg-gray-700 disabled:opacity-50">
              <Download className="h-4 w-4" />
              {busy === 'third-party-notices' ? 'Exporting…' : 'Notices draft'}
            </button>
          </div>
        </details>
      </div>
      <div className={`mt-1 text-xs ${thin ? 'text-yellow-300' : 'text-gray-500'}`}>
        {summary.ai_component_count ?? 1} model-system component{summary.ai_component_count === 1 ? '' : 's'} · {' '}
        {summary.dependency_component_count ?? 0} pinned dependenc{summary.dependency_component_count === 1 ? 'y' : 'ies'}
        {thin ? ' · no dependency manifest inventory: re-run at Full scan depth' : ''}
      </div>
      {summary.inventory_note && <div className="mt-1 max-w-xl text-xs text-gray-500">{summary.inventory_note}</div>}
      {summary.license_summary && (
        <div className={`mt-1 text-xs ${summary.license_follow_up_required ? 'text-yellow-300' : 'text-gray-500'}`}>
          License evidence: {summary.license_summary}
        </div>
      )}
      {error && <div className="mt-1 text-xs text-red-300">{error}</div>}
    </div>
  )
}

export default function ReportView({ scan, shareControls, isAuthenticated, remediations = [], enableRemediationTracking = false }: Props) {
  const [remediationData, setRemediationData] = useState<RemediationData[]>(remediations)
  const scanData = scan.result || scan.results || {}
  const input = scanData.input || {}
  const dns = scanData.dns || {}
  const tls = scanData.tls || {}
  const http = scanData.http || {}
  const discovery = scanData.discovery || {}
  const server_versions = discovery.server_versions || {}
  const rawModelIntake = scanData.model_intake || null
  const rawModelIntakeSummary = rawModelIntake?.summary || null
  const rawModelIntakeSupplyChain = rawModelIntake?.supply_chain || null
  const suppressModelIntakeUnsafeSerialization = hasModelIntakeSafeFormatEvidence(rawModelIntakeSummary, rawModelIntakeSupplyChain)
  const rawFindings = Array.isArray(scanData.findings)
    ? scanData.findings.filter((finding: any) => {
        if (!suppressModelIntakeUnsafeSerialization) return true
        const id = String(finding?.id || finding?.fingerprint || finding?.source_finding_id || '')
        return !id.endsWith('unsafe_serialization')
      })
    : []
  const persistedFindings = Array.isArray(scan.findings) ? scan.findings : []
  const rawOnlyFindings = rawFindings.length > 0 && persistedFindings.length === 0
  const findings = sortBySeverity(rawFindings)
  const persistedFindingIndex = buildFindingLinkageIndex(persistedFindings)
  const rawFindingsWithoutRecords = rawFindings.filter((finding: any) => !linkedPersistedFinding(finding, persistedFindingIndex))
  const partiallyPersistedFindings = rawFindings.length > 0 && persistedFindings.length > 0 && rawFindingsWithoutRecords.length > 0
  const result = scanData.result || {}
  const triage = scanData.triage || {}
  const coverageGaps = scanData.coverage_gaps || {}
  const js_dependencies = scanData.js_dependencies || {}
  const js_secrets = scanData.js_secrets || {}
  const cicd_exposure = scanData.cicd_exposure || {}
  const package_exposure = scanData.package_exposure || {}
  const cloud_buckets = scanData.cloud_buckets || {}
  const backup_files = scanData.backup_files || {}
  const delta = scanData.delta || {}
  const ssh = scanData.ssh || {}
  const noise_reduction_stats = scanData.noise_reduction_stats || {}
  // Get raw network_scan data from various paths
  const network_scan_raw =
    scanData.network_scan ||
    discovery.network_scan ||
    scanData.result?.network_scan ||
    scanData.result?.discovery?.network_scan ||
    {}

  // Get complete_ports data (from nmap scans)
  const complete_ports =
    discovery.complete_ports ||
    scanData.result?.discovery?.complete_ports ||
    {}

  // Merge network_scan and complete_ports - use complete_ports as fallback when network_scan is empty
  const network_scan = {
    ...network_scan_raw,
    open_ports: network_scan_raw.open_ports?.length > 0
      ? network_scan_raw.open_ports
      : complete_ports.open_ports || [],
    services: network_scan_raw.services?.length > 0
      ? network_scan_raw.services
      : complete_ports.services || [],
    os_detection: network_scan_raw.os_detection || complete_ports.os_detection || {},
    vulnerabilities: network_scan_raw.vulnerabilities?.length > 0
      ? network_scan_raw.vulnerabilities
      : complete_ports.vulnerabilities || [],
    scan_completed: network_scan_raw.scan_completed ?? complete_ports.scan_completed,
    errors: network_scan_raw.errors || complete_ports.errors
  }
  const network_services = scanData.network_services || {}
  const active_checks = scanData.active_checks || {}
  const activeEndpointAttempts = Array.isArray(active_checks.endpoint_attempts)
    ? active_checks.endpoint_attempts.filter((attempt: any) => attempt && typeof attempt === 'object')
    : []
  const access_control = scanData.access_control || {}
  const cloud_ssrf = scanData.cloud_ssrf || {}
  const kubernetes_exposure = scanData.kubernetes_exposure || {}
  const container_registry = scanData.container_registry || {}
  const scan_metadata = scanData.scan_metadata || {}
  const scanCompletionStatus = scanData.scan_completion_status || scan_metadata.scan_completion_status || {}
  const completionSkippedModules = Array.isArray(scanCompletionStatus.skipped_modules)
    ? scanCompletionStatus.skipped_modules
    : []
  const completionSkipViews = normalizeSkipReasons(completionSkippedModules)
  const completionCappedEntries = Object.entries(asRecord(scanCompletionStatus.capped_lists))
    .filter(([, cap]: [string, any]) => cap && typeof cap === 'object' && cap.capped)
  const scan_config = scanData.scan_config || {}
  const activeCheckFamilyScope = active_checks.check_family_scope || scan_config.check_family_scope
  const activeCheckFamilyScopeLabel = getCheckFamilyScopeLabel(activeCheckFamilyScope)
    || (typeof scan_config.focused_active_family === 'string'
      ? `${formatCheckFamilyName(scan_config.focused_active_family)} only`
      : null)
  const resolved_budget = scan_config.resolved_budget || scan.options?.resolved_budget || {}
  const requestBudget = scanData.request_budget || {}
  const budgetProfile = scan_config.budget_profile || scan.options?.budget_profile || resolved_budget.budget_profile
  const canonicalBudgetUsed = scanData.scan_metadata?.budget_used || {}
  const canonicalBudgetLimit = scan.options?.scan_execution_plan?.budget || scan.options?.resolved_scan_budget || {}
  const attemptedHttpRequests = requestBudget.attempted_requests ?? canonicalBudgetUsed.http_requests ?? 0
  const httpRequestLimit = requestBudget.request_limit
    ?? resolved_budget.request_max
    ?? canonicalBudgetLimit.max_http_requests
  const coverage = scanData.coverage || {}
  const smart_coverage = scanData.smart_coverage || {}
  const nucleiTemplates = smart_coverage.nuclei_templates || {}
  const nucleiRunApproximate = Boolean(nucleiTemplates.run_approximate)
  const attack_chains = scanData.attack_chains || scanData.result?.attack_chains || null
  const client_side_vulns = scanData.client_side_vulns || {}
  const auth_checks = scanData.auth_checks || {}
  const websocket_security = discovery.websocket_security || {}
  const api_security_web = scanData.api_security_web || {}
  const business_logic = scanData.business_logic || {}
  const file_upload = scanData.file_upload || {}
  const host_header_injection = scanData.host_header_injection || {}
  const open_redirect = scanData.open_redirect || {}
  const directory_listing = scanData.directory_listing || {}
  const ai_logs = scanData.ai_logs || null
  const ai_summary = ai_logs?.summary || null
  const ai_executive = ai_summary?.executive_summary || null
  const model_intake = rawModelIntake
  const modelIntakeSummary = model_intake?.summary || null
  const modelIntakeArtifact = model_intake?.artifact || null
  const modelIntakeFetch = modelIntakeArtifact?.fetch || null
  const modelIntakeMetadata = model_intake?.metadata || {}
  const modelIntakeChecks = model_intake?.checks || null
  const modelIntakeAibom = model_intake?.aibom || null
  const modelIntakeSupplyChain = model_intake?.supply_chain || null
  const modelIntakeEvaluation = model_intake?.generated_evaluation || null
  const modelIntakeCorporateUse = model_intake?.corporate_use || null
  const modelIntakeIsPreflight = String(modelIntakeSummary?.intake_mode || modelIntakeCorporateUse?.admission_mode || '').toLowerCase() === 'preflight'
  const modelIntakeActivity = Array.isArray(model_intake?.activity) ? model_intake.activity : []
  const modelIntakeScannerResults = Array.isArray(model_intake?.generated_evidence?.results)
    ? model_intake.generated_evidence.results
    : []
  const modelIntakeSbomResult = modelIntakeScannerResults.find(
    (item: any) => item?.scanner?.name === 'shakerscan-sbom',
  )
  const modelIntakeSbom = modelIntakeSbomResult?.summary?.sbom || null
  const modelIntakeSbomSummary = modelIntakeSbomResult?.summary?.sbom_summary || {
    component_count: Array.isArray(modelIntakeSbom?.components) ? modelIntakeSbom.components.length : 0,
    dependency_files: modelIntakeSbomResult?.coverage?.dependency_files_discovered ?? 0,
    unpinned_dependencies: Array.isArray(modelIntakeSbomResult?.findings) ? modelIntakeSbomResult.findings.length : 0,
  }
  const modelIntakeExecutionControls = [
    ...modelIntakeScannerResults.map((item: any) => ({
      name: item?.scanner?.name || 'scanner',
      status: item?.execution?.status || 'NOT_RUN',
      coverage: item?.coverage || {},
      detail: item?.execution?.error || item?.summary?.error || null,
    })),
    ...(!modelIntakeIsPreflight ? [{
      name: 'dynamic sandbox',
      status: model_intake?.dynamic_sandbox?.status || 'NOT_RUN',
      coverage: {},
      detail: model_intake?.dynamic_sandbox?.error || null,
    }, {
      name: 'provenance attestation',
      status: model_intake?.attestation?.status || 'NOT_RUN',
      coverage: {},
      detail: Array.isArray(model_intake?.attestation?.blockers) ? model_intake.attestation.blockers.join(', ') : model_intake?.attestation?.error || null,
    }, {
      name: 'embedding evaluation',
      status: modelIntakeEvaluation?.status || 'NOT_RUN',
      coverage: modelIntakeEvaluation?.metrics || {},
      detail: Array.isArray(modelIntakeEvaluation?.blockers) && modelIntakeEvaluation.blockers.length
        ? modelIntakeEvaluation.blockers.map((item: any) => item?.code).filter(Boolean).slice(0, 3).join(', ')
        : null,
    }, {
      name: 'signed admission',
      status: model_intake?.admission?.status || 'NOT_RUN',
      coverage: {},
      detail: model_intake?.admission?.error || null,
    }] : []),
  ]
  const modelIntakeControlGroups = modelIntakeExecutionControls.reduce(
    (groups: Record<string, any[]>, control: any) => {
      const status = String(control.status || 'NOT_RUN').toUpperCase()
      const bucket = status === 'PASS' || status === 'SIGNED'
        ? 'passed'
        : status === 'FAIL' || status === 'ERROR'
          ? 'failed'
          : status === 'WARNING' || status === 'REVIEW_REQUIRED'
            ? 'review'
            : status === 'NOT_APPLICABLE'
              ? 'notApplicable'
              : 'notTested'
      groups[bucket].push(control)
      return groups
    },
    { passed: [], failed: [], review: [], notTested: [], notApplicable: [] },
  )
  const ai_gate = scanData.ai_gate || null
  const devicePosture = scanData.device_posture || null
  const deviceServices = Array.isArray(devicePosture?.services) ? devicePosture.services : []
  const deviceObservations = Array.isArray(devicePosture?.inconclusive_observations)
    ? devicePosture.inconclusive_observations
    : []
  const deviceWebOrigins = Array.isArray(devicePosture?.web_origins) ? devicePosture.web_origins : []
  const deviceCompleteness = asRecord(devicePosture?.completeness)
  const deviceDecision = asRecord(devicePosture?.decision)
  const deviceToolReceipts = Array.isArray(deviceCompleteness.tool_receipts)
    ? deviceCompleteness.tool_receipts
    : []
  const aiGateControlEvidence = ai_gate?.control_evidence || null
  const aiGateDecision = ai_gate?.decision || {}
  const aiGateStats = ai_gate?.statistics || {}
  const aiGateSeverityCounts = aiGateDecision?.severity_counts || {}
  const aiGateTranscripts = Array.isArray(ai_gate?.transcripts) ? ai_gate.transcripts : []
  const aiGateErrors = Array.isArray(ai_gate?.errors) ? ai_gate.errors : []
  const aiGateCoverage = asRecord(ai_gate?.coverage_matrix)
  const aiGateCoverageSummary = asRecord(aiGateCoverage.summary)
  const aiGateEvidenceManifest = asRecord(ai_gate?.evidence_manifest)
  const aiGateEvidenceHashes = asRecord(aiGateEvidenceManifest.evidence_hashes)
  const aiGateProbeCatalog = asRecord(aiGateEvidenceManifest.probe_catalog)
  const aiGateDecisionText = String(aiGateDecision?.decision || '').toLowerCase()
  const aiGateExecutionPlan = asRecord(ai_gate?.execution_plan)
  const aiGateSemanticJudge = asRecord(aiGateExecutionPlan.semantic_judge)
  const aiGateJudgingGate = asRecord(aiGateExecutionPlan.judging_quality_gate)
  const aiGateJudgingGateDisplay = getAIJudgingGateDisplay(aiGateJudgingGate.status)
  const semanticReviewedIds = new Set(
    [
      ...(Array.isArray(aiGateExecutionPlan.semantic_reviewed) ? aiGateExecutionPlan.semantic_reviewed : []),
      ...(Array.isArray(aiGateSemanticJudge.reviewed_probe_ids) ? aiGateSemanticJudge.reviewed_probe_ids : []),
    ].map(String)
  )
  const aiGateDecisionClass =
    aiGateDecisionText === 'block'
      ? 'bg-red-900 text-red-200'
      : aiGateDecisionText === 'needs_approval'
      ? 'bg-yellow-900 text-yellow-200'
      : aiGateDecisionText === 'allow'
      ? 'bg-green-900 text-green-200'
      : 'bg-slate-700 text-slate-300'
  const isAIScan = scan.scan_type === 'ai_gate' || String(scan.run_kind || '').startsWith('ai_') || Boolean(ai_gate)
  const isModelIntakeScan = scan.scan_type === 'model_intake' || scan.run_kind === 'model_intake' || Boolean(model_intake)
  const isDeviceScan = scan.scan_type === 'device_posture' || scan.run_kind === 'device_posture' || Boolean(devicePosture)
  const scorePresentation = deviceScorePresentation(scan)
  // Continuous ASM recon is a DISCOVERY pass (active testing off by design) that
  // refreshes the endpoint inventory; active vuln testing runs as separate ASM
  // test batches. Don't frame its intentionally-off active modules as a
  // "budget exhausted / coverage incomplete" failure.
  const isAsmRecon = scan.scan_role === 'asm_recon'
  const isAsmBatch = scan.scan_role === 'asm_batch'
  const showCompletionBanner = !isAIScan && !isModelIntakeScan && !isDeviceScan && !isAsmRecon && (
    scanCompletionStatus.complete === false ||
    scanCompletionStatus.limited === true ||
    completionSkippedModules.length > 0 ||
    completionCappedEntries.length > 0
  )
  const scanTypeLabel = isAIScan
    ? 'AI Gate'
    : isModelIntakeScan
      ? 'Model Intake'
      : isDeviceScan
        ? 'Connected device posture'
      : isAsmRecon
        ? 'ASM recon (discovery)'
        : isAsmBatch
          ? 'ASM test batch'
          : scan.scan_type === 'scan' || scan.run_kind === 'web_dast'
            ? 'DAST Scan'
            : String(scan.scan_type || 'Standard').replace(/_/g, ' ')
  const scanBudgetAndPolicyLabel = `${formatCheckFamilyName(String(budgetProfile || 'balanced'))} + ${
    scan.options?.scan_policy?.active_testing || scan.options?.active ? 'active testing' : 'passive testing'
  }`
  const modelIntakeDecision = String(result?.decision || '').toLowerCase()
  const modelIntakeDecisionClass =
    modelIntakeDecision === 'block'
      ? 'border-red-500/40 bg-red-950/30 text-red-100'
      : modelIntakeDecision === 'review'
      ? 'border-yellow-500/40 bg-yellow-950/30 text-yellow-100'
      : modelIntakeDecision === 'allow'
      ? 'border-green-500/40 bg-green-950/30 text-green-100'
      : 'border-slate-700 bg-slate-900 text-slate-200'
  const modelIntakeFormatInspection = modelIntakeSupplyChain?.format_inspection || modelIntakeAibom?.format_inspection || null
  const modelIntakeSafetensorsHeader = modelIntakeFormatInspection?.safetensors_header || null
  const modelIntakeRequiredActions = getModelIntakeRequiredActions(modelIntakeChecks, modelIntakeSummary, modelIntakeSupplyChain, modelIntakeFetch)
  const modelIntakeDisplayFormatPosture = hasModelIntakeSafeFormatEvidence(modelIntakeSummary, modelIntakeSupplyChain)
    ? 'safer_static_format'
    : modelIntakeSummary?.format_posture
  const aiScanProfile = scan.options?.ai_scan_profile || ai_gate?.scan_profile || 'AI Gate'
  const aiScanProfileLabel = formatAIProfile(aiScanProfile)
  const aiGateFindingsByProbe = findings.reduce<Record<string, any[]>>((groups, finding) => {
    const evidence = parseEvidenceRecord(finding.evidence)
    const sourceFindingId = String(finding.source_finding_id || finding.id || '')
    const probeId = String(evidence.probe_id || sourceFindingId.split(':')[0] || '').trim()
    if (!probeId) return groups
    const enrichedFinding = { ...finding, evidence_record: evidence }
    groups[probeId] = [...(groups[probeId] || []), enrichedFinding]
    return groups
  }, {})
  const aiGateProbeSummaries: Array<{
    probeId: string
    family: string
    findings: any[]
    detectorHits: any[]
  }> = aiGateTranscripts.map((transcript: any, idx: number) => {
    const probeId = String(transcript.probe_id || `probe-${idx + 1}`)
    const turns = Array.isArray(transcript.turns) && transcript.turns.length > 0
      ? transcript.turns
      : [transcript]
    const detectorHits = turns.flatMap((turn: any) => Array.isArray(turn?.detector_hits) ? turn.detector_hits : [])
    return {
      probeId,
      family: transcript.probe_family || transcript.strategy_id || 'probe',
      findings: aiGateFindingsByProbe[probeId] || [],
      detectorHits,
    }
  })
  const aiGateFailedProbeCount = aiGateProbeSummaries.filter((probe) => probe.findings.length > 0).length
  const aiGateTotalProbeCount = Number(aiGateStats.total_probes ?? aiGateTranscripts.length)
  const aiGateDeployRecommendation = getAIDeployRecommendation(aiGateDecisionText)
  const aiGateRecommendedFixes = getAIRecommendedFixes(findings)
  const aiGateTopFinding = findings[0]

  const [expandedAI, setExpandedAI] = useState<Set<string>>(new Set())
  const [expandedAIRubrics, setExpandedAIRubrics] = useState<Set<string>>(new Set())
  const [severityFilter, setSeverityFilter] = useState<Set<string>>(new Set(['critical', 'high', 'medium', 'low', 'info']))
  const [minChainConfidence, setMinChainConfidence] = useState<number>(0.5)
  const [showPartialChains, setShowPartialChains] = useState<boolean>(false)
  const [fbShowAllFindings, setFbShowAllFindings] = useState<boolean>(false)
  const [fbExpandedCategories, setFbExpandedCategories] = useState<Set<string>>(new Set())

  const toggleAIDetails = (id: string) => {
    setExpandedAI(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const toggleAIRubric = (id: string) => {
    setExpandedAIRubrics(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const toggleSeverityFilter = (severity: string) => {
    setSeverityFilter(prev => {
      const next = new Set(prev)
      next.has(severity) ? next.delete(severity) : next.add(severity)
      return next
    })
  }

  const getChainConfidence = (chain: any) => {
    const value = chain?.confidence ?? chain?.completeness ?? 0
    return typeof value === 'number' && !Number.isNaN(value) ? value : 0
  }

  const filteredFindings = findings.filter((f: any) => severityFilter.has(f.severity?.toLowerCase() || 'info'))
  const completeChains = attack_chains?.chains || []
  const partialChains = attack_chains?.partial_chains || []
  const filteredChains = completeChains.filter((chain: any) => getChainConfidence(chain) >= minChainConfidence)
  const filteredPartialChains = showPartialChains
    ? partialChains.filter((chain: any) => getChainConfidence(chain) >= minChainConfidence)
    : []
  const attackChainsAvailable = !!attack_chains
  const attackChainsError = attack_chains?.error

  const handleDownloadJson = () => {
    const dataStr = JSON.stringify(scanData, null, 2)
    const blob = new Blob([dataStr], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `scan-${input.normalized_host || 'result'}-${new Date().toISOString().slice(0,10)}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const handleDownloadModelIntakeSbom = () => {
    if (!modelIntakeSbom) return
    const blob = new Blob([JSON.stringify(modelIntakeSbom, null, 2)], { type: 'application/vnd.cyclonedx+json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `model-intake-${scan.id}-sbom.cdx.json`
    document.body.appendChild(anchor)
    anchor.click()
    document.body.removeChild(anchor)
    URL.revokeObjectURL(url)
  }

  const handleDownloadAIRedTeamReport = async (format: 'json' | 'markdown') => {
    const apiUrl = getApiUrl()
    const res = await fetch(`${apiUrl}/scans/${scan.id}/ai-redteam-report?format=${format}`)
    if (!res.ok) {
      console.error('Failed to download AI red-team report')
      return
    }
    const text = format === 'json'
      ? JSON.stringify(await res.json(), null, 2)
      : await res.text()
    const extension = format === 'json' ? 'json' : 'md'
    const blob = new Blob([text], { type: format === 'json' ? 'application/json' : 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `shakerscan-ai-redteam-${scan.id}.${extension}`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  // For Model Intake scans the "target" is a long artifact URL (e.g. a HF resolve
  // link with a commit hash) that otherwise dominates the header on mobile and
  // pushes the block decision/rationale below the fold. Show a short label instead
  // and keep the full URL in a collapsed, copyable field.
  const fullArtifactUrl = scan.url || scan.target_url || input.target || ''
  const modelIntakeArtifactLabel = (() => {
    const named = modelIntakeArtifact?.name || modelIntakeSummary?.artifact_name
    if (named) return String(named)
    try {
      const u = new URL(fullArtifactUrl)
      const segs = u.pathname.split('/').filter(Boolean)
      if (u.hostname.includes('huggingface') && segs.length >= 2) return `${segs[0]}/${segs[1]}`
      return segs[segs.length - 1] || u.hostname
    } catch {
      return fullArtifactUrl || 'Model artifact'
    }
  })()

  return (
    <div className="max-w-7xl mx-auto flex flex-col px-4 sm:px-6 lg:px-8 py-8">
      {/* Scan Summary */}
      {!isModelIntakeScan && <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
        <div className="mb-4 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="min-w-0">
            {isModelIntakeScan ? (
              <>
                <h1 className="text-2xl sm:text-3xl font-bold mb-1 break-words">{modelIntakeArtifactLabel}</h1>
                {fullArtifactUrl && (
                  <details className="mb-2">
                    <summary className="text-xs text-blue-400 hover:text-blue-300 cursor-pointer select-none">
                      Show full artifact URL
                    </summary>
                    <p className="mt-1 text-xs text-gray-400 font-mono break-all">{fullArtifactUrl}</p>
                  </details>
                )}
              </>
            ) : (
              <h2 className="text-2xl font-bold mb-2">Detailed scan report</h2>
            )}
            <p className="text-gray-400">
              Scanned on {new Date(scan.created_at).toLocaleDateString()} at {new Date(scan.created_at).toLocaleTimeString()}
            </p>
            {input.normalized_host && (
              <p className="text-sm text-gray-500 mt-1">
                Host: {input.normalized_host} | Port: {input.port || 443} | Scheme: {input.scheme || 'https'}
              </p>
            )}
            {(scan.warning || scan.options?._target_warning) && (
              <p className="text-sm text-yellow-400 mt-2">
                {scan.warning || scan.options?._target_warning}
                {(scan.original_target || scan.options?._original_target) && (
                  <span className="text-yellow-300">
                    {" "}Original: {scan.original_target || scan.options?._original_target}
                  </span>
                )}
              </p>
            )}
          </div>
          <div className="flex flex-col items-start gap-2 lg:items-end lg:text-right">
            <div className="flex items-center gap-2 no-print">
              {shareControls}
              <ExportPDFButton />
              {isAuthenticated && (isAIScan || isModelIntakeScan) && (
                <>
                  <button type="button" onClick={() => handleDownloadAIRedTeamReport('markdown')} className="px-3 py-2 rounded border border-purple-500/60 text-purple-300 text-sm hover:bg-purple-500/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
                    AI Report MD
                  </button>
                  <button type="button" onClick={() => handleDownloadAIRedTeamReport('json')} className="px-3 py-2 rounded border border-purple-500/60 text-purple-300 text-sm hover:bg-purple-500/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
                    AI Report JSON
                  </button>
                </>
              )}
              {isAuthenticated && (
                <button type="button" onClick={handleDownloadJson} className="px-3 py-2 rounded border border-blue-500/60 text-blue-300 text-sm hover:bg-blue-500/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
                  Download JSON
                </button>
              )}
            </div>
            {scorePresentation.status === 'provisional' && (
              <div className="text-xs font-semibold uppercase tracking-wide text-amber-300">
                Provisional posture
              </div>
            )}
            {scorePresentation.status === 'unavailable' ? (
              <div className="text-sm font-medium text-amber-200">Posture score unavailable</div>
            ) : (
              <>
                {scorePresentation.grade && (
                  <div className={`text-5xl font-bold ${gradeTextColor(scorePresentation.grade)}`}>
                    {scorePresentation.grade}
                  </div>
                )}
                {scorePresentation.score != null && (
                  <div className="text-xl text-gray-400">Score: {scorePresentation.score}/100</div>
                )}
              </>
            )}
            {scorePresentation.note && (
              <div className="max-w-sm text-xs text-amber-200/80">{scorePresentation.note}</div>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5 mt-6">
          <div className="bg-gray-700/50 rounded-lg p-4">
            <h3 className="text-sm text-gray-400 mb-1">Status</h3>
            <p className="text-lg font-semibold capitalize">{scan.status}</p>
          </div>
          <div className="bg-gray-700/50 rounded-lg p-4">
            <h3 className="text-sm text-gray-400 mb-1">Workflow</h3>
            <p className="text-lg font-semibold capitalize">{scanTypeLabel}</p>
          </div>
          <div className="bg-gray-700/50 rounded-lg p-4">
            <h3 className="text-sm text-gray-400 mb-1">{isAIScan ? 'AI Depth' : isModelIntakeScan ? 'Intake Mode' : isDeviceScan ? 'Device Profile' : 'Budget & permissions'}</h3>
            <p className="text-lg font-semibold capitalize">
              {isAIScan ? aiScanProfileLabel : isModelIntakeScan ? 'Artifact checks' : isDeviceScan ? devicePosture?.profile || 'Posture' : scanBudgetAndPolicyLabel}
            </p>
          </div>
          {!isAIScan && !isModelIntakeScan && !isDeviceScan && (
            <div className="bg-gray-700/50 rounded-lg p-4">
              <h3 className="text-sm text-gray-400 mb-1">Coverage Budget</h3>
              <p className="text-lg font-semibold capitalize">{budgetProfile || 'Balanced'}</p>
              {(resolved_budget.max_urls || resolved_budget.active_max_endpoints) && (
                <p className="mt-1 text-xs text-gray-500">
                  {resolved_budget.max_urls ? `${resolved_budget.max_urls} URLs` : ''}
                  {resolved_budget.max_urls && resolved_budget.active_max_endpoints ? ' / ' : ''}
                  {resolved_budget.active_max_endpoints ? `${resolved_budget.active_max_endpoints} active endpoints` : ''}
                </p>
              )}
              {httpRequestLimit !== undefined && (
                <p className="mt-1 text-xs text-gray-500">
                  {attemptedHttpRequests}/{httpRequestLimit} requests used
                  {requestBudget.mode ? ` (${requestBudget.mode})` : ''}
                </p>
              )}
            </div>
          )}
          <div className="bg-gray-700/50 rounded-lg p-4">
            <h3 className="text-sm text-gray-400 mb-1">Issues Found</h3>
            <p className="text-lg font-semibold">{Array.isArray(findings) ? findings.length : 0}</p>
          </div>
        </div>
      </div>}

      {isDeviceScan && devicePosture && (
        <section className="mb-8 rounded-lg border border-gray-700 bg-gray-800/50 p-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold text-white">Connected-device network posture</h2>
              <p className="mt-1 text-sm text-gray-400">
                Policy is evaluated only against services that responded as confirmed open. Silent UDP probes remain unconfirmed and do not affect the score.
              </p>
            </div>
            <span className={`rounded px-2.5 py-1 text-xs font-semibold uppercase ${
              String(deviceDecision.decision || '').toLowerCase() === 'block'
                ? 'bg-red-900/60 text-red-200'
                : String(deviceDecision.decision || '').toLowerCase() === 'allow'
                  ? 'bg-green-900/60 text-green-200'
                  : 'bg-yellow-900/60 text-yellow-200'
            }`}>
              {String(deviceDecision.decision || 'needs review').replace(/_/g, ' ')}
            </span>
          </div>
          {deviceDecision.rationale && <p className="mt-3 text-sm text-gray-300">{String(deviceDecision.rationale)}</p>}

          <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded border border-gray-700 bg-gray-950/40 p-3">
              <div className="text-xl font-semibold text-white">{deviceServices.length}</div>
              <div className="text-xs text-gray-500">Confirmed services</div>
            </div>
            <div className="rounded border border-gray-700 bg-gray-950/40 p-3">
              <div className="text-xl font-semibold text-white">{deviceWebOrigins.length}</div>
              <div className="text-xs text-gray-500">Web interfaces</div>
            </div>
            <div className="rounded border border-gray-700 bg-gray-950/40 p-3">
              <div className="text-xl font-semibold text-amber-200">{deviceObservations.length}</div>
              <div className="text-xs text-gray-500">Inconclusive observations</div>
            </div>
            <div className="rounded border border-gray-700 bg-gray-950/40 p-3">
              <div className={`text-xl font-semibold ${deviceCompleteness.complete ? 'text-green-300' : 'text-amber-300'}`}>
                {deviceCompleteness.complete ? 'Complete' : 'Partial'}
              </div>
              <div className="text-xs text-gray-500">Required inventory stages</div>
            </div>
          </div>

          <div className="mt-4 grid gap-4 xl:grid-cols-2">
            <div className="rounded border border-gray-700 bg-gray-950/30 p-4">
              <h3 className="text-sm font-semibold text-gray-200">Confirmed listening services</h3>
              {deviceServices.length === 0 ? (
                <p className="mt-3 text-sm text-gray-500">No service was confirmed open.</p>
              ) : (
                <div className="mt-3 overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="text-xs uppercase text-gray-500"><tr><th className="pb-2 pr-3">Port</th><th className="pb-2 pr-3">Service</th><th className="pb-2 pr-3">Product</th><th className="pb-2">Policy</th></tr></thead>
                    <tbody className="divide-y divide-gray-800">
                      {deviceServices.map((service: any) => (
                        <tr key={`${service.transport}-${service.port}`}>
                          <td className="py-2 pr-3 font-mono text-gray-200">{service.port}/{service.transport}</td>
                          <td className="py-2 pr-3 text-white">
                            {service.web_origin ? <a href={service.web_origin} target="_blank" rel="noreferrer" className="text-blue-300 hover:text-blue-200">{service.service_name || 'unknown'}</a> : service.service_name || 'unknown'}
                          </td>
                          <td className="py-2 pr-3 text-gray-400">{[service.product, service.version].filter(Boolean).join(' ') || '—'}</td>
                          <td className="py-2 text-gray-300">{String(service.policy_disposition || 'unreviewed').replace(/_/g, ' ')}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            <div className="rounded border border-gray-700 bg-gray-950/30 p-4">
              <h3 className="text-sm font-semibold text-gray-200">Inconclusive network observations</h3>
              {deviceObservations.length === 0 ? (
                <p className="mt-3 text-sm text-gray-500">No ambiguous port states were returned.</p>
              ) : (
                <div className="mt-3 space-y-2">
                  {deviceObservations.map((observation: any) => (
                    <div key={`${observation.transport}-${observation.port}`} className="rounded border border-amber-500/20 bg-amber-950/10 p-3">
                      <div className="flex flex-wrap items-center gap-2 text-sm">
                        <span className="font-mono text-amber-100">{observation.port}/{observation.transport}</span>
                        <span className="text-gray-300">{observation.service_name || 'unknown'}</span>
                        <span className="rounded bg-amber-900/40 px-1.5 py-0.5 text-xs text-amber-200">{observation.state || 'inconclusive'}</span>
                        {observation.state_reason && <span className="text-xs text-gray-500">{observation.state_reason}</span>}
                      </div>
                      <p className="mt-1 text-xs text-gray-500">{observation.observation_reason || 'No response confirmed whether a service is listening.'}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <details className="mt-4 rounded border border-gray-700 bg-gray-950/30">
            <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-gray-200">Inventory stage evidence</summary>
            <div className="border-t border-gray-800 p-4">
              <div className="mb-3 flex flex-wrap gap-2 text-xs text-gray-400">
                <span>TCP scope: {String(deviceCompleteness.tcp_scope || 'unknown').replace(/_/g, ' ')}</span>
                <span>TCP discovery: {deviceCompleteness.tcp_discovery_complete ? 'complete' : 'partial'}</span>
                <span>Open-port inventory: {deviceCompleteness.tcp_visibility_complete ? 'complete' : 'partial'}</span>
                <span>Silent TCP ports: {deviceCompleteness.tcp_closed_filtered_classification_complete ? 'classified' : 'closed/filtered not distinguished'}</span>
                <span>Fingerprinting: {deviceCompleteness.tcp_fingerprinting_complete ? 'complete' : 'partial'}</span>
                <span>UDP probes: {deviceCompleteness.udp_discovery_complete ? 'complete' : 'partial'}</span>
              </div>
              <div className="grid gap-2 md:grid-cols-2">
                {deviceToolReceipts.map((receipt: any, index: number) => (
                  <div key={`${receipt.stage || receipt.transport}-${index}`} className="rounded border border-gray-800 bg-black/20 p-3 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-medium text-gray-200">{String(receipt.stage || receipt.transport || 'stage').replace(/_/g, ' ')}</span>
                      <span className={receipt.complete ? 'text-green-300' : receipt.required === false ? 'text-gray-400' : 'text-amber-300'}>
                        {receipt.complete ? 'complete' : receipt.required === false ? 'supplemental partial' : 'partial'}
                      </span>
                    </div>
                    <div className="mt-1 text-gray-500">{Number(receipt.confirmed_open_count || 0)} confirmed · {Number(receipt.inconclusive_count || 0)} inconclusive</div>
                    {Array.isArray(receipt.incomplete_reasons) && receipt.incomplete_reasons.length > 0 && (
                      <div className="mt-1 text-amber-300">{receipt.incomplete_reasons.join(', ').replace(/_/g, ' ')}</div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </details>
        </section>
      )}

      {isAsmRecon && (
        <div className="mb-8 rounded-lg border border-blue-500/40 bg-blue-950/20 p-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-blue-300" />
            <div className="min-w-0 flex-1">
              <h2 className="text-base font-semibold text-white">Continuous ASM — discovery pass</h2>
              <p className="mt-1 text-sm text-gray-300">
                This is an automated recon scan that re-enumerates the attack surface to keep the
                target&apos;s endpoint inventory fresh. Active vulnerability testing (SQLi, XSS, BOLA,
                etc.) is intentionally <span className="text-gray-100">off</span> here — it runs as
                separate <span className="text-gray-100">ASM test batches</span>, so a small finding
                count is expected. See coverage on the{' '}
                <a href="/asm" className="text-blue-300 hover:text-blue-200">Coverage</a> page.
              </p>
            </div>
          </div>
        </div>
      )}

      {showCompletionBanner && (
        <div className={`mb-8 rounded-lg border p-4 ${
          scanCompletionStatus.complete === false
            ? 'border-yellow-500/40 bg-yellow-950/20'
            : 'border-blue-500/40 bg-blue-950/20'
        }`}>
          <div className="flex items-start gap-3">
            <AlertTriangle className={`mt-0.5 h-5 w-5 shrink-0 ${
              scanCompletionStatus.complete === false ? 'text-yellow-300' : 'text-blue-300'
            }`} />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-base font-semibold text-white">
                  {scanCompletionStatus.complete === false ? 'Scan Coverage Incomplete' : 'Scan Coverage Limited'}
                </h2>
                {scanCompletionStatus.coverage_status && (
                  <span className="rounded bg-gray-900 px-2 py-0.5 text-xs text-gray-300">
                    Module coverage: {formatScanToken(scanCompletionStatus.coverage_status)}
                  </span>
                )}
                {scanCompletionStatus.budget_exhausted && (
                  <span className="rounded bg-yellow-900 px-2 py-0.5 text-xs text-yellow-100">
                    Budget exhausted{scanCompletionStatus.budget_exhausted_at ? `: ${formatScanToken(scanCompletionStatus.budget_exhausted_at)}` : ''}
                  </span>
                )}
              </div>
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                {completionCappedEntries.length > 0 && (
                  <div className="rounded border border-gray-800 bg-black/20 p-3">
                    <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-400">Capped Coverage</div>
                    <div className="space-y-1">
                      {completionCappedEntries.map(([name, cap]: [string, any]) => (
                        <div key={name} className="text-sm text-gray-300">
                          <span className="font-medium text-gray-100">{formatScanToken(name)}</span>
                          <span className="ml-2 text-gray-400">
                            {cap.selected ?? cap.tested ?? 0}/{cap.discovered ?? '?'} selected
                            {cap.budget ? ` (budget ${cap.budget})` : ''}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {completionSkippedModules.length > 0 && (
                  <div className="rounded border border-gray-800 bg-black/20 p-3">
                    <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-400">Skipped Modules</div>
                    <div className="flex flex-wrap gap-2">
                      {completionSkipViews.items.map((skip) => (
                        <span key={skip.key} className="rounded bg-gray-900 px-2 py-1 text-xs text-gray-300">
                          {formatScanToken(skip.label)}
                          {skip.reason ? `: ${formatScanToken(skip.reason)}` : ''}
                        </span>
                      ))}
                      {completionSkipViews.remaining > 0 && (
                        <span className="rounded bg-gray-900 px-2 py-1 text-xs text-gray-500">
                          +{completionSkipViews.remaining} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* AI Gate */}
      {ai_gate && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <div className="flex flex-wrap items-start justify-between gap-4 mb-5">
            <div>
              <h2 className="text-2xl font-bold">AI Gate</h2>
              <p className="text-sm text-gray-400 mt-1">
                {ai_gate.target_name || scan.target_name || scan.target_url || 'AI target'}
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {aiGateDecisionText && (
                <span className={`rounded px-3 py-1 text-sm font-medium ${aiGateDecisionClass}`}>
                  {aiGateDecisionText.replace('_', ' ')}
                </span>
              )}
              {ai_gate.probe_pack && (
                <span className="rounded bg-blue-900/40 px-3 py-1 text-sm text-blue-200">Probe pack: {formatAIProbePack(ai_gate.probe_pack)}</span>
              )}
              {ai_gate.scan_profile && (
                <span className="rounded bg-gray-700 px-3 py-1 text-sm text-gray-200">Depth: {formatAIProfile(ai_gate.scan_profile)}</span>
              )}
            </div>
          </div>

          {aiGateDecision?.rationale && (
            <p className="mb-5 rounded-lg border border-gray-700 bg-gray-900 p-4 text-sm text-gray-300">
              {aiGateDecision.rationale}
            </p>
          )}

          <div className={`mb-5 rounded-lg border p-4 ${
            aiGateDecisionText === 'block'
              ? 'border-red-500/40 bg-red-950/30'
              : aiGateDecisionText === 'needs_approval'
              ? 'border-yellow-500/40 bg-yellow-950/20'
              : aiGateDecisionText === 'allow'
              ? 'border-green-500/40 bg-green-950/20'
              : 'border-gray-700 bg-gray-900'
          }`}>
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className="text-xs font-medium uppercase tracking-wide text-gray-400">Deploy decision</div>
                <div className="mt-1 text-2xl font-bold text-white">{aiGateDeployRecommendation}</div>
                <p className="mt-2 text-sm text-gray-300">
                  {aiGateFailedProbeCount}/{aiGateTotalProbeCount || aiGateTranscripts.length} probes failed · {findings.length} finding{findings.length === 1 ? '' : 's'}
                  {aiGateTopFinding?.title ? ` · top issue: ${aiGateTopFinding.title}` : ''}
                </p>
              </div>
              <span className={`rounded px-3 py-1 text-sm font-medium ${aiGateDecisionClass}`}>
                {aiGateDecision.decision || 'unknown'}
              </span>
            </div>
            {aiGateRecommendedFixes.length > 0 && (
              <div className="mt-4 rounded border border-gray-800 bg-black/20 p-3">
                <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-400">Fix first</div>
                <div className="grid gap-2 md:grid-cols-2">
                  {aiGateRecommendedFixes.slice(0, 6).map((fix) => (
                    <div key={fix} className="flex gap-2 text-sm text-gray-200">
                      <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
                      <span>{fix}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 mb-5">
            <div className="bg-gray-700/40 rounded-lg p-3">
              <div className="text-xs text-gray-400">Target Type</div>
              <div className="text-sm font-semibold text-white">{ai_gate.target_type || 'api_chat'}</div>
            </div>
            <div className="bg-gray-700/40 rounded-lg p-3">
              <div className="text-xs text-gray-400">Probes</div>
              <div className="text-lg font-semibold text-white">{aiGateStats.total_probes ?? aiGateTranscripts.length}</div>
            </div>
            <div className="bg-gray-700/40 rounded-lg p-3">
              <div className="text-xs text-gray-400">Requests OK</div>
              <div className="text-lg font-semibold text-green-400">{aiGateStats.successful_requests ?? 0}</div>
            </div>
            <div className="bg-gray-700/40 rounded-lg p-3">
              <div className="text-xs text-gray-400">Findings</div>
              <div className="text-lg font-semibold text-orange-400">{aiGateStats.finding_count ?? findings.length}</div>
            </div>
            <div className="bg-gray-700/40 rounded-lg p-3">
              <div className="text-xs text-gray-400">Errors</div>
              <div className="text-lg font-semibold text-red-400">{aiGateStats.error_count ?? aiGateErrors.length}</div>
            </div>
          </div>

          {Object.keys(aiGateSeverityCounts).length > 0 && (
            <div className="mb-5 flex flex-wrap gap-2">
              {Object.entries(aiGateSeverityCounts).map(([severity, count]) => (
                Number(count) > 0 && (
                  <span key={severity} className={`rounded px-2 py-1 text-xs font-medium ${getSeverityPill(severity)}`}>
                    {severity}: {Number(count)}
                  </span>
                )
              ))}
            </div>
          )}

          {aiGateControlEvidence?.summary && Number(aiGateControlEvidence.summary.required || 0) > 0 && (
            <div className="mb-5 rounded-lg border border-gray-700 bg-gray-900 p-4">
              <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold text-gray-300">Deployment Readiness</h3>
                  <p className="mt-1 text-xs text-gray-500">
                    Control metadata, governance, and audit evidence. Probe failures above remain the primary ship/no-ship signal.
                  </p>
                  <p className="mt-1 text-xs text-gray-500">
                    {aiGateControlEvidence.summary.present || 0} present / {aiGateControlEvidence.summary.required || 0} required controls
                  </p>
                </div>
                <span className={`rounded px-2 py-1 text-xs font-medium ${aiGateControlEvidence.summary.evidence_ready ? 'bg-green-900 text-green-200' : 'bg-yellow-900 text-yellow-200'}`}>
                  {aiGateControlEvidence.summary.evidence_ready ? 'evidence ready' : `${aiGateControlEvidence.summary.missing || 0} missing`}
                </span>
              </div>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {(aiGateControlEvidence.controls || []).slice(0, 12).map((control: any) => (
                  <div key={control.id} className="rounded border border-gray-800 bg-black/20 p-2">
                    <div className="text-xs font-medium text-gray-200">{control.label}</div>
                    <div className={`mt-1 text-xs ${control.status === 'present' ? 'text-green-300' : 'text-yellow-300'}`}>
                      {control.status}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {aiGateCoverage?.schema_version && (
            <div className="mb-5 rounded-lg border border-gray-700 bg-gray-900 p-4">
              <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold text-gray-300">Coverage Matrix</h3>
                  <p className="mt-1 text-xs text-gray-500">
                    {aiGateCoverageSummary.executed ?? 0} executed / {aiGateCoverageSummary.planned ?? 0} planned probes
                  </p>
                </div>
                <span className="rounded bg-gray-800 px-2 py-1 text-xs text-gray-300">
                  skipped {aiGateCoverageSummary.skipped ?? 0}
                </span>
              </div>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                {Object.entries(asRecord(aiGateCoverage.by_family)).slice(0, 8).map(([family, stats]) => {
                  const familyStats = asRecord(stats)
                  return (
                    <div key={family} className="rounded border border-gray-800 bg-black/20 p-2">
                      <div className="truncate text-xs font-medium text-gray-200">{family}</div>
                      <div className="mt-1 text-xs text-gray-500">
                        {familyStats.executed ?? 0}/{familyStats.planned ?? 0} run · {familyStats.with_findings ?? 0} findings
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {aiGateProbeSummaries.some((probe) => probe.findings.length > 0) && (
            <div className="mb-5 rounded-lg border border-gray-700 bg-gray-900 p-4">
              <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold text-gray-300">Findings by Probe</h3>
                  <p className="mt-1 text-xs text-gray-500">What failed, grouped by the probe that produced accepted attack evidence.</p>
                </div>
                <span className="rounded bg-red-900/40 px-2 py-1 text-xs text-red-200">
                  {aiGateFailedProbeCount} failed probe{aiGateFailedProbeCount === 1 ? '' : 's'}
                </span>
              </div>
              <div className="grid gap-3 lg:grid-cols-3">
                {aiGateProbeSummaries.filter((probe) => probe.findings.length > 0).map((probe) => (
                  <div key={probe.probeId} className="rounded border border-red-500/30 bg-red-950/10 p-3">
                    <div className="font-mono text-xs text-red-200">{probe.probeId}</div>
                    <div className="mt-1 text-xs text-gray-500">{probe.family} · {probe.findings.length} finding{probe.findings.length === 1 ? '' : 's'}</div>
                    <div className="mt-3 space-y-2">
                      {probe.findings.slice(0, 4).map((finding: any) => (
                        <div key={finding.id || finding.title} className="rounded bg-black/20 p-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${getSeverityPill(finding.severity)}`}>
                              {finding.severity || 'info'}
                            </span>
                            <span className="text-xs font-medium text-gray-100">{finding.title || 'Finding'}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {aiGateEvidenceManifest?.schema_version && (
            <div className="mb-5 rounded-lg border border-gray-700 bg-gray-900 p-4">
              <h3 className="text-sm font-semibold text-gray-300">Evidence Manifest</h3>
              <div className="mt-3 grid gap-2 text-xs text-gray-400 md:grid-cols-2">
                <div className="break-all">target: <span className="text-gray-200">{String(aiGateEvidenceManifest.target_snapshot_hash || 'n/a')}</span></div>
                <div className="break-all">planned probes: <span className="text-gray-200">{String(aiGateProbeCatalog.planned_hash || 'n/a')}</span></div>
                <div className="break-all">executed probes: <span className="text-gray-200">{String(aiGateProbeCatalog.executed_hash || 'n/a')}</span></div>
                <div className="break-all">transcripts: <span className="text-gray-200">{String(aiGateEvidenceHashes.transcripts_hash || 'n/a')}</span></div>
                <div className="break-all">findings: <span className="text-gray-200">{String(aiGateEvidenceHashes.findings_hash || 'n/a')}</span></div>
                <div className="break-all">controls: <span className="text-gray-200">{String(aiGateEvidenceHashes.control_evidence_hash || 'n/a')}</span></div>
              </div>
            </div>
          )}

          {aiGateErrors.length > 0 && (
            <div className="mb-5 rounded-lg border border-red-500/30 bg-red-900/10 p-4">
              <h3 className="mb-2 text-sm font-semibold text-red-300">Errors</h3>
              <ul className="space-y-1 text-sm text-red-200">
                {aiGateErrors.slice(0, 5).map((error: string, idx: number) => (
                  <li key={idx} className="break-words">{error}</li>
                ))}
              </ul>
            </div>
          )}

          {aiGateTranscripts.length > 0 && (
            <div>
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h3 className="text-sm font-semibold text-gray-300">Probe Conversations</h3>
                  <p className="mt-1 text-xs text-gray-500">
                    Each card now starts with the result. The green/red boxes below are the test rubric, not the verdict.
                  </p>
                </div>
                {(Object.keys(aiGateSemanticJudge).length > 0 || aiGateJudgingGateDisplay) && (
                  <div className="flex flex-wrap gap-2 text-xs text-gray-300">
                    {aiGateJudgingGateDisplay && (
                      <span className={`rounded px-2 py-1 ${aiGateJudgingGateDisplay.className}`} title={aiGateJudgingGateDisplay.title}>
                        {aiGateJudgingGateDisplay.label}
                      </span>
                    )}
                    <span className="rounded bg-gray-800 px-2 py-1">
                      semantic judge: {aiGateSemanticJudge.enabled ? 'on' : 'off'}
                    </span>
                    {aiGateSemanticJudge.provider_configured !== undefined && (
                      <span className="rounded bg-gray-800 px-2 py-1">
                        provider: {aiGateSemanticJudge.provider_configured ? 'configured' : 'not configured'}
                      </span>
                    )}
                    {aiGateSemanticJudge.reviewed_count !== undefined && (
                      <span className="rounded bg-gray-800 px-2 py-1">
                        reviewed: {aiGateSemanticJudge.reviewed_count}
                      </span>
                    )}
                  </div>
                )}
              </div>
              <div className="mb-3 rounded-lg border border-gray-700 bg-gray-950 p-3 text-sm text-gray-300">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`rounded px-2 py-1 text-xs font-medium ${aiGateDecisionClass}`}>
                    scan verdict: {aiGateDecision.decision || 'unknown'}
                  </span>
                  <span className="text-gray-500">
                    {Number(aiGateStats.finding_count || 0)} finding{Number(aiGateStats.finding_count || 0) === 1 ? '' : 's'}
                  </span>
                  <span className="text-gray-500">
                    {Number(aiGateStats.total_probes || aiGateTranscripts.length)} probe{Number(aiGateStats.total_probes || aiGateTranscripts.length) === 1 ? '' : 's'} run
                  </span>
                </div>
                <p className="mt-2 text-xs text-gray-500">
                  Passed means no accepted attack evidence was found. Failed means the attack success condition produced a finding.
                </p>
              </div>
              <div className="space-y-3">
                {aiGateTranscripts.map((transcript: any, idx: number) => {
                  const probeId = String(transcript.probe_id || `probe-${idx + 1}`)
                  const transcriptKey = `${probeId}-${idx}`
                  const turns = Array.isArray(transcript.turns) && transcript.turns.length > 0
                    ? transcript.turns
                    : [transcript]
                  const detectorHits = turns.flatMap((turn: any) => Array.isArray(turn?.detector_hits) ? turn.detector_hits : [])
                  const probeFindings = aiGateFindingsByProbe[probeId] || []
                  const isExpanded = expandedAI.has(transcriptKey)
                  const hasRubric = Boolean(transcript.expected_safe_behavior || transcript.expected_attack_success)
                  const isRubricExpanded = expandedAIRubrics.has(transcriptKey)
                  const wasSemanticallyReviewed = semanticReviewedIds.has(probeId)
                  const probeOutcome = getAIProbeOutcome(turns, detectorHits, probeFindings, wasSemanticallyReviewed)

                  return (
                    <div key={transcriptKey} className="rounded-lg border border-gray-700 bg-gray-900 p-4">
                      <div className={`mb-3 rounded-lg border p-3 ${probeOutcome.className}`}>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className={`h-2 w-2 rounded-full ${probeOutcome.dotClassName}`} />
                          <span className="text-sm font-semibold">{probeOutcome.label}</span>
                          <span className="text-xs opacity-80">{probeId}</span>
                        </div>
                        <p className="mt-1 text-xs opacity-80">{probeOutcome.explanation}</p>
                      </div>
                      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="truncate font-mono text-sm text-blue-300">{probeId}</div>
                          <div className="mt-1 flex flex-wrap gap-2 text-xs text-gray-500">
                            <span>{transcript.probe_family || transcript.strategy_id || 'probe'}</span>
                            {transcript.technique && <span>{transcript.technique}</span>}
                            {transcript.status_code && <span>HTTP {transcript.status_code}</span>}
                            {transcript.stop_reason && <span>{transcript.stop_reason}</span>}
                            {transcript.turn_count !== undefined && <span>{transcript.turn_count} turn{transcript.turn_count === 1 ? '' : 's'}</span>}
                          </div>
                        </div>
                        <div className="flex flex-wrap items-center gap-2 text-xs">
                          {probeFindings.length > 0 && (
                            <span className="rounded bg-orange-900/40 px-2 py-1 text-orange-200">
                              {probeFindings.length} finding{probeFindings.length === 1 ? '' : 's'}
                            </span>
                          )}
                          {detectorHits.length > 0 && (
                            <span className="rounded bg-red-900/40 px-2 py-1 text-red-200">
                              {detectorHits.length} detector hit{detectorHits.length === 1 ? '' : 's'}
                            </span>
                          )}
                          {wasSemanticallyReviewed && (
                            <span className="rounded bg-purple-900/40 px-2 py-1 text-purple-200">semantic reviewed</span>
                          )}
                          <button
                            type="button"
                            onClick={() => toggleAIDetails(transcriptKey)}
                            aria-expanded={isExpanded}
                            className="rounded border border-gray-700 px-2 py-1 text-gray-300 hover:bg-gray-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                          >
                            {isExpanded ? 'Collapse' : 'Open chat'}
                          </button>
                        </div>
                      </div>

                      {hasRubric && (
                        <div className="mb-3">
                          <button
                            type="button"
                            onClick={() => toggleAIRubric(transcriptKey)}
                            aria-expanded={isRubricExpanded}
                            className="rounded text-xs text-blue-300 hover:text-blue-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                          >
                            {isRubricExpanded ? 'Hide expected/fail behavior' : 'Show expected/fail behavior'}
                          </button>
                          {isRubricExpanded && (
                            <div className="mt-2 grid gap-2 md:grid-cols-2">
                              {transcript.expected_safe_behavior && (
                                <div className="rounded border border-gray-800 bg-black/20 p-3">
                                  <div className="mb-1 text-xs font-medium text-green-300">Expected safe behavior</div>
                                  <p className="text-xs text-gray-400">{transcript.expected_safe_behavior}</p>
                                </div>
                              )}
                              {transcript.expected_attack_success && (
                                <div className="rounded border border-gray-800 bg-black/20 p-3">
                                  <div className="mb-1 text-xs font-medium text-red-300">Attack success condition</div>
                                  <p className="text-xs text-gray-400">{transcript.expected_attack_success}</p>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      )}

                      <div className="space-y-3">
                        {(isExpanded ? turns : turns.slice(0, 1)).map((turn: any, turnIdx: number) => (
                          <div key={`${transcriptKey}-turn-${turnIdx}`} className="space-y-2">
                            {turn.prompt && (
                              <div className="flex justify-start">
                                <div className="max-w-[92%] rounded-lg border border-blue-500/30 bg-blue-950/30 p-3">
                                  <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-blue-300">
                                    Probe {turn.turn_index ? `turn ${turn.turn_index}` : ''}
                                  </div>
                                  <p className="whitespace-pre-wrap break-words text-sm text-blue-50">{turn.prompt}</p>
                                </div>
                              </div>
                            )}
                            {turn.response_excerpt && (
                              <div className="flex justify-end">
                                <div className="max-w-[92%] rounded-lg border border-gray-700 bg-gray-800 p-3">
                                  <div className="mb-1 flex flex-wrap items-center gap-2 text-[11px] font-medium uppercase tracking-wide text-gray-400">
                                    <span>Answer</span>
                                    {turn.latency_ms !== undefined && <span>{Math.round(Number(turn.latency_ms))} ms</span>}
                                    {turn.refusal_detected && <span className="text-green-300">refusal detected</span>}
                                  </div>
                                  <p className="max-h-80 overflow-auto whitespace-pre-wrap break-words text-sm text-gray-100">{turn.response_excerpt}</p>
                                </div>
                              </div>
                            )}
                            {Array.isArray(turn.detector_hits) && turn.detector_hits.length > 0 && (
                              <div className="ml-auto max-w-[92%] rounded-lg border border-red-500/30 bg-red-950/20 p-3">
                                <div className="mb-2 text-xs font-medium text-red-300">Detector hits</div>
                                <div className="space-y-2">
                                  {turn.detector_hits.map((hit: any, hitIdx: number) => (
                                    <div key={`${transcriptKey}-hit-${turnIdx}-${hitIdx}`} className="text-xs text-red-100">
                                      <span className={`mr-2 rounded px-1.5 py-0.5 ${getSeverityPill(hit.severity)}`}>
                                        {hit.severity || 'info'}
                                      </span>
                                      <span className="font-medium">{hit.title || hit.type || hit.id}</span>
                                      {hit.judge_layer && <span className="text-red-200/70"> · {hit.judge_layer}</span>}
                                      {Array.isArray(hit.matched_markers) && hit.matched_markers.length > 0 && (
                                        <div className="mt-1 text-red-200/70">markers: {hit.matched_markers.join(', ')}</div>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>

                      {!isExpanded && turns.length > 1 && (
                        <button
                          type="button"
                          onClick={() => toggleAIDetails(transcriptKey)}
                          aria-expanded={isExpanded}
                          className="mt-3 rounded text-xs text-blue-300 hover:text-blue-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                        >
                          Show {turns.length - 1} more turn{turns.length - 1 === 1 ? '' : 's'}
                        </button>
                      )}

                      {isExpanded && probeFindings.length > 0 && (
                        <div className="mt-4 rounded-lg border border-gray-700 bg-black/20 p-3">
                          <h4 className="mb-2 text-xs font-semibold text-gray-300">Evaluations</h4>
                          <div className="space-y-3">
                            {probeFindings.map((finding: any, findingIdx: number) => {
                              const evidenceRecord = asRecord(finding.evidence_record)
                              const semanticResult = asRecord(evidenceRecord.semantic_result)
                              const confidence = formatConfidence(finding.confidence)
                              return (
                                <div key={`${transcriptKey}-finding-${findingIdx}`} className="rounded border border-gray-800 bg-gray-950 p-3">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <span className={`rounded px-2 py-0.5 text-xs font-medium ${getSeverityPill(finding.severity)}`}>
                                      {finding.severity || 'info'}
                                    </span>
                                    <span className="text-sm font-medium text-white">{finding.title}</span>
                                    {confidence && <span className="text-xs text-gray-400">{confidence} confidence</span>}
                                    {evidenceRecord.judge_layer && <span className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-300">{evidenceRecord.judge_layer}</span>}
                                  </div>
                                  {finding.description && (
                                    <p className="mt-2 text-xs text-gray-400">{finding.description}</p>
                                  )}
                                  {Object.keys(semanticResult).length > 0 && (
                                    <div className="mt-2 rounded bg-purple-950/20 p-2 text-xs text-purple-100">
                                      <div className="mb-1 font-medium">Semantic judge</div>
                                      <pre className="whitespace-pre-wrap break-words">{compactJson(semanticResult)}</pre>
                                    </div>
                                  )}
                                </div>
                              )
                            })}
                          </div>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Model Intake */}
      {model_intake && (
        <div className="order-first bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <div className="flex flex-wrap items-start justify-between gap-4 mb-5">
            <div>
              <div className="text-xs font-semibold uppercase tracking-wide text-cyan-300">{modelIntakeIsPreflight ? 'Static inspection' : 'Model Intake report'}</div>
              <h2 className="mt-1 text-2xl font-bold break-words">{modelIntakeArtifactLabel}</h2>
              <p className="mt-1 text-sm text-gray-400">Reviewed {new Date(scan.created_at).toLocaleString()}</p>
              {fullArtifactUrl && (
                <details className="mt-2">
                  <summary className="cursor-pointer select-none text-xs text-blue-400 hover:text-blue-300">Show full artifact URL</summary>
                  <p className="mt-1 break-all font-mono text-xs text-gray-400">{fullArtifactUrl}</p>
                </details>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {modelIntakeDisplayFormatPosture && (
                <span className="rounded bg-gray-700 px-3 py-1 text-sm text-gray-200">
                  {String(modelIntakeDisplayFormatPosture).replace(/_/g, ' ')}
                </span>
              )}
              <ModelIntakeSbomDownload scanId={scan.id} />
              <div className="no-print flex flex-wrap items-center gap-2">
                <ExportPDFButton />
                {isAuthenticated && (
                  <button type="button" onClick={handleDownloadJson} className="px-3 py-2 rounded border border-blue-500/60 text-blue-300 text-sm hover:bg-blue-500/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
                    Download JSON
                  </button>
                )}
              </div>
            </div>
          </div>

          {modelIntakeIsPreflight && (
            <div className="mb-5 rounded-lg border border-cyan-700/50 bg-cyan-950/20 p-4 text-cyan-50">
              <div className="text-sm font-semibold">Static acquisition and scanner stage</div>
              <p className="mt-1 max-w-4xl text-sm text-cyan-100/80">
                This page records the pinned revision, complete acquisition, hashes, format checks, repository scanners, and inventory artifacts. It does not contain the later Firecracker result. If this scan was started by Automatic Review, return there for the end-to-end technical result.
              </p>
              <Link href="/model-intake" className="mt-3 inline-flex rounded border border-cyan-600/60 px-3 py-1.5 text-xs font-medium text-cyan-200 hover:bg-cyan-900/30">Open Automatic Review</Link>
            </div>
          )}

          {modelIntakeCorporateUse && !modelIntakeIsPreflight && (
            <div className={`mb-5 rounded-lg border p-4 ${
              modelIntakeCorporateUse.verdict === 'APPROVED'
                ? 'border-green-500/40 bg-green-950/30 text-green-100'
                : modelIntakeCorporateUse.verdict === 'REJECT'
                  ? 'border-red-500/40 bg-red-950/30 text-red-100'
                  : 'border-yellow-500/40 bg-yellow-950/20 text-yellow-100'
            }`}>
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <div className="text-xs uppercase tracking-wide opacity-80">Use decision</div>
                  <div className="mt-1 text-xl font-semibold">{String(modelIntakeCorporateUse.verdict).replace(/_/g, ' ')}</div>
                  <div className="mt-1 max-w-3xl text-sm opacity-90">{modelIntakeCorporateUse.plain_language}</div>
                </div>
                <div className="text-right text-xs opacity-80">
                  <div>{modelIntakeCorporateUse.malicious_primitive_proven ? 'Malicious primitive proven' : 'No malicious primitive proven'}</div>
                  <div>Mode: {modelIntakeCorporateUse.admission_mode}</div>
                </div>
              </div>
              {Array.isArray(modelIntakeCorporateUse.controls) && (
                <div className="mt-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                  {modelIntakeCorporateUse.controls.map((control: any) => {
                    const status = String(control.status || 'INDETERMINATE').toUpperCase()
                    const statusClass = status === 'PASS'
                      ? 'text-green-300'
                      : status === 'FAIL'
                        ? 'text-red-300'
                        : 'text-yellow-300'
                    return (
                      <div key={control.id} className="rounded border border-white/10 bg-black/20 p-3">
                        <div className="flex items-start justify-between gap-2">
                          <div className="text-xs font-medium text-gray-200">{control.label}</div>
                          <div className={`text-xs font-semibold ${statusClass}`}>{status}</div>
                        </div>
                        <div className="mt-1 text-xs text-gray-400">{control.detail}</div>
                      </div>
                    )
                  })}
                </div>
              )}
              {Array.isArray(modelIntakeCorporateUse.next_actions) && modelIntakeCorporateUse.next_actions.length > 0 && (
                <div className="mt-4">
                  <div className="text-xs font-semibold uppercase tracking-wide opacity-80">Required next actions</div>
                  <ul className="mt-2 list-disc space-y-1 pl-5 text-sm opacity-90">
                    {modelIntakeCorporateUse.next_actions.slice(0, 8).map((action: string, index: number) => <li key={`${index}-${action}`}>{action}</li>)}
                  </ul>
                </div>
              )}
            </div>
          )}

          {modelIntakeDecision && !modelIntakeIsPreflight && (
            <div className={`mb-5 rounded-lg border p-4 ${modelIntakeDecisionClass}`}>
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="text-xs uppercase tracking-wide opacity-80">Deployment decision</div>
                  <div className="mt-1 text-xl font-semibold">{modelIntakeDecision.replace(/_/g, ' ')}</div>
                </div>
                <div className="max-w-3xl text-sm opacity-90">
                  {result?.decision_reason || 'Review model intake findings before approving this artifact.'}
                </div>
              </div>
            </div>
          )}

          <div className="mb-5 rounded-lg border border-gray-700 bg-gray-900 p-4">
            <div className="text-sm font-semibold text-white">Technical evidence coverage</div>
            <p className="mt-1 text-xs text-gray-400">
              Execution status for scanners and evidence-producing controls. Deployment follow-up is shown separately.
            </p>
            <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <div><div className="text-xs text-gray-500">Checks passed</div><div className="text-2xl font-semibold text-green-300">{modelIntakeControlGroups.passed.length}</div></div>
              <div><div className="text-xs text-gray-500">Checks failed</div><div className="text-2xl font-semibold text-red-300">{modelIntakeControlGroups.failed.length}</div></div>
              <div><div className="text-xs text-gray-500">Checks needing review</div><div className="text-2xl font-semibold text-yellow-300">{modelIntakeControlGroups.review.length}</div></div>
              <div><div className="text-xs text-gray-500">Checks not run / incomplete</div><div className="text-2xl font-semibold text-orange-300">{modelIntakeControlGroups.notTested.length}</div></div>
            </div>
            {(modelIntakeControlGroups.failed.length > 0 || modelIntakeControlGroups.notTested.length > 0) && (
              <div className="mt-4 grid gap-3 lg:grid-cols-2">
                {modelIntakeControlGroups.failed.length > 0 && (
                  <div className="rounded border border-red-800/50 bg-red-950/20 p-3">
                    <div className="text-xs font-semibold uppercase tracking-wide text-red-200">Failed</div>
                    <ul className="mt-2 space-y-1 text-sm text-red-100/90">
                      {modelIntakeControlGroups.failed.slice(0, 6).map((control: any) => (
                        <li key={`failed-${control.name}`}>• {String(control.name).replace(/_/g, ' ')}{control.detail ? ` — ${control.detail}` : ''}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {modelIntakeControlGroups.notTested.length > 0 && (
                  <div className="rounded border border-orange-800/50 bg-orange-950/20 p-3">
                    <div className="text-xs font-semibold uppercase tracking-wide text-orange-200">Not tested or incomplete</div>
                    <ul className="mt-2 space-y-1 text-sm text-orange-100/90">
                      {modelIntakeControlGroups.notTested.slice(0, 6).map((control: any) => (
                        <li key={`missing-${control.name}`}>• {String(control.name).replace(/_/g, ' ')}{control.detail ? ` — ${control.detail}` : ''}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>

          {modelIntakeRequiredActions.length > 0 && !modelIntakeIsPreflight && (
            <div className="mb-5 rounded border border-yellow-600/40 bg-yellow-950/20 p-4">
              <div className="text-sm font-semibold text-yellow-100">What to do next</div>
              <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm text-yellow-50/90">
                {modelIntakeRequiredActions.slice(0, 8).map((action, index) => (
                  <li key={`${action}-${index}`}>{action}</li>
                ))}
              </ol>
            </div>
          )}

          <details className="rounded-lg border border-gray-700 bg-gray-950/40">
            <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-gray-200 hover:text-white">
              Detailed technical evidence, SBOM, hashes and phase logs
            </summary>
            <div className="border-t border-gray-800 p-4">

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4 mb-5">
            <div className="bg-gray-700/40 rounded-lg p-3">
              <div className="text-xs text-gray-400">Artifact</div>
              <div className="text-sm font-semibold text-white break-all">{modelIntakeSummary?.artifact_name || modelIntakeArtifact?.name || 'artifact'}</div>
            </div>
            <div className="bg-gray-700/40 rounded-lg p-3">
              <div className="text-xs text-gray-400">Format</div>
              <div className="text-sm font-semibold text-white">{modelIntakeSummary?.extension || 'unknown'}</div>
            </div>
            <div className="bg-gray-700/40 rounded-lg p-3">
              <div className="text-xs text-gray-400">Source</div>
              <div className="text-sm font-semibold text-white">{modelIntakeSummary?.source_kind || 'unknown'}</div>
            </div>
            <div className="bg-gray-700/40 rounded-lg p-3">
              <div className="text-xs text-gray-400">Findings</div>
              <div className="text-lg font-semibold text-orange-400">{findings.length}</div>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
            {Object.entries(modelIntakeChecks || {}).map(([check, passed]) => {
              const status = getModelIntakeCheckStatus(check, passed, modelIntakeSummary, modelIntakeSupplyChain)
              return (
                <div key={check} className="rounded border border-gray-700 bg-gray-900 p-3">
                  <div className="text-xs text-gray-400">{formatModelIntakeCheckName(check)}</div>
                  <div className={`mt-1 text-sm font-semibold ${status.className}`}>{status.label}</div>
                </div>
              )
            })}
          </div>

          {(modelIntakeExecutionControls.length > 0 || modelIntakeActivity.length > 0) && (
            <div className="mt-5 grid gap-4 xl:grid-cols-[minmax(0,1.35fr)_minmax(18rem,0.65fr)]">
              <div className="min-w-0 overflow-hidden rounded border border-gray-700 bg-gray-900">
                <div className="border-b border-gray-800 px-3 py-2">
                  <div className="text-sm font-semibold text-gray-200">Control execution</div>
                  <div className="mt-0.5 text-xs text-gray-500">PASS means the control actually ran; missing, incomplete, unsupported, and skipped controls remain visible.</div>
                </div>
                <div className="divide-y divide-gray-800">
                  {modelIntakeExecutionControls.map((control: any, index: number) => {
                    const status = String(control.status || 'NOT_RUN').toUpperCase()
                    const statusClass = status === 'PASS' || status === 'SIGNED'
                      ? 'bg-green-950/60 text-green-300'
                      : status === 'WARNING' || status === 'REVIEW_REQUIRED'
                        ? 'bg-yellow-950/60 text-yellow-300'
                        : status === 'NOT_APPLICABLE'
                          ? 'bg-gray-800 text-gray-300'
                          : 'bg-red-950/60 text-red-300'
                    const coverage = Object.entries(control.coverage || {})
                      .filter(([, value]) => ['string', 'number', 'boolean'].includes(typeof value))
                      .slice(0, 4)
                      .map(([key, value]) => `${key.replace(/_/g, ' ')}: ${String(value)}`)
                      .join(' · ')
                    return (
                      <div key={`${control.name}-${index}`} className="grid min-w-0 gap-2 px-3 py-2.5 sm:grid-cols-[minmax(10rem,0.45fr)_auto_minmax(0,1fr)] sm:items-center">
                        <div className="truncate text-sm text-gray-200" title={String(control.name)}>{String(control.name).replace(/_/g, ' ')}</div>
                        <span className={`w-fit rounded px-2 py-0.5 text-[11px] font-semibold ${statusClass}`}>{status}</span>
                        <div className="min-w-0 break-words text-xs text-gray-500">{control.detail || coverage || 'No additional detail reported.'}</div>
                      </div>
                    )
                  })}
                </div>
              </div>

              <div className="min-w-0 rounded border border-gray-700 bg-gray-900 p-3">
                <div className="text-sm font-semibold text-gray-200">Intake phase timeline</div>
                {modelIntakeActivity.length ? (
                  <ol className="mt-3 space-y-2">
                    {modelIntakeActivity.map((event: any, index: number) => (
                      <li key={`${event?.phase || 'phase'}-${index}`} className="rounded border border-gray-800 bg-gray-950/60 p-2">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-medium text-gray-200">{String(event?.phase || 'phase').replace(/_/g, ' ')}</span>
                          <span className="text-[11px] text-gray-500">{event?.progress ?? 0}% · {String(event?.status || 'unknown')}</span>
                        </div>
                        {event?.at && <div className="mt-1 text-[10px] text-gray-600">{String(event.at)}</div>}
                      </li>
                    ))}
                  </ol>
                ) : (
                  <div className="mt-3 text-xs text-gray-500">No structured phase events were recorded.</div>
                )}
              </div>
            </div>
          )}

          {(modelIntakeAibom || modelIntakeSupplyChain || modelIntakeSbom) && (
            <div className="mt-5 grid grid-cols-1 gap-3 lg:grid-cols-4">
              <div className="rounded border border-gray-700 bg-gray-900 p-3">
                <div className="text-xs text-gray-400">AIBOM completeness</div>
                <div className="mt-1 text-lg font-semibold text-cyan-300">
                  {modelIntakeAibom?.completeness?.score !== undefined ? `${Math.round(Number(modelIntakeAibom.completeness.score) * 100)}%` : 'generated'}
                </div>
                <div className="mt-1 text-xs text-gray-500">
                  {(modelIntakeAibom?.components || []).length || 0} component{((modelIntakeAibom?.components || []).length || 0) === 1 ? '' : 's'}
                </div>
              </div>
              <div className="rounded border border-gray-700 bg-gray-900 p-3">
                <div className="text-xs text-gray-400">Signature verification</div>
                <div className="mt-1 text-sm font-semibold text-white">
                  {modelIntakeSupplyChain?.signature?.status || modelIntakeSummary?.signature_verification_status || 'unknown'}
                </div>
              </div>
              <div className="rounded border border-gray-700 bg-gray-900 p-3">
                <div className="text-xs text-gray-400">License evidence</div>
                <div className={`mt-1 text-sm font-semibold ${modelIntakeSupplyChain?.license_compliance?.legal_review_required ? 'text-yellow-300' : 'text-white'}`}>
                  {modelIntakeSupplyChain?.license_compliance?.legal_review_required
                    ? 'Review required'
                    : modelIntakeSupplyChain?.license_compliance?.missing_evidence?.length
                      ? 'Declaration found; source text missing'
                      : modelIntakeSupplyChain?.license_compliance?.policy_status === 'PASS'
                        ? 'No policy issue found'
                        : modelIntakeSupplyChain?.license_policy?.status || modelIntakeSummary?.license_policy_status || 'unknown'}
                </div>
                <div className="mt-1 text-xs text-gray-500">Component-level evidence and any policy triggers are available in the License BOM.</div>
              </div>
              <div className="rounded border border-gray-700 bg-gray-900 p-3">
                <div className="text-xs text-gray-400">CycloneDX SBOM</div>
                <div className="mt-1 text-lg font-semibold text-cyan-300">
                  {modelIntakeSbom ? `${modelIntakeSbomSummary.component_count || 0} components` : 'not generated'}
                </div>
                {modelIntakeSbom && (
                  <>
                    <div className="mt-1 text-xs text-gray-500">
                      {modelIntakeSbomSummary.dependency_files || 0} dependency files · {modelIntakeSbomSummary.unpinned_dependencies || 0} unpinned
                    </div>
                    <button type="button" onClick={handleDownloadModelIntakeSbom} className="mt-2 rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800">
                      Download SBOM
                    </button>
                  </>
                )}
              </div>
            </div>
          )}

          {modelIntakeEvaluation && modelIntakeEvaluation.status !== 'SKIPPED_BY_POLICY' && (
            <div className="mt-5 rounded border border-gray-700 bg-gray-900 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <div className="text-xs text-gray-400">Embedding and data-plane evaluation</div>
                  <div className="mt-1 text-sm font-semibold text-white">
                    {modelIntakeEvaluation.suite_id || 'provider-neutral suite'} {modelIntakeEvaluation.suite_version ? `v${modelIntakeEvaluation.suite_version}` : ''}
                  </div>
                </div>
                <span className={`rounded px-2 py-1 text-xs font-semibold ${modelIntakeEvaluation.status === 'PASS' ? 'bg-green-950/50 text-green-300' : modelIntakeEvaluation.status === 'WARNING' ? 'bg-yellow-950/50 text-yellow-300' : 'bg-red-950/50 text-red-300'}`}>
                  {modelIntakeEvaluation.status}
                </span>
              </div>
              <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
                <div><div className="text-xs text-gray-500">Recall@k</div><div className="text-sm font-semibold text-white">{modelIntakeEvaluation.metrics?.mean_recall_at_k ?? 'not measured'}</div></div>
                <div><div className="text-xs text-gray-500">ACL leaks</div><div className="text-sm font-semibold text-white">{modelIntakeEvaluation.metrics?.acl_leaks ?? 'not measured'}</div></div>
                <div><div className="text-xs text-gray-500">Poisoned hit rate</div><div className="text-sm font-semibold text-white">{modelIntakeEvaluation.metrics?.poisoned_top_k_rate ?? 'not measured'}</div></div>
                <div><div className="text-xs text-gray-500">Min stability</div><div className="text-sm font-semibold text-white">{modelIntakeEvaluation.metrics?.minimum_stability_cosine ?? 'not measured'}</div></div>
                <div><div className="text-xs text-gray-500">P95 latency</div><div className="text-sm font-semibold text-white">{modelIntakeEvaluation.metrics?.latency_ms?.p95 !== null && modelIntakeEvaluation.metrics?.latency_ms?.p95 !== undefined ? `${modelIntakeEvaluation.metrics.latency_ms.p95} ms` : 'not measured'}</div></div>
              </div>
              {Array.isArray(modelIntakeEvaluation.blockers) && modelIntakeEvaluation.blockers.length > 0 && (
                <ul className="mt-3 space-y-1 text-xs text-red-200">
                  {modelIntakeEvaluation.blockers.slice(0, 8).map((item: any, index: number) => <li key={`${item.code}-${index}`}>{item.code}: {item.detail}</li>)}
                </ul>
              )}
            </div>
          )}

          {modelIntakeFormatInspection && (
            <div className="mt-5 rounded border border-gray-700 bg-gray-900 p-3">
              <div className="text-xs text-gray-400">Format inspection</div>
              <div className="mt-2 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <div>
                  <div className="text-xs text-gray-500">Format</div>
                  <div className="text-sm font-semibold text-white">{modelIntakeFormatInspection.format || modelIntakeSummary?.extension || 'unknown'}</div>
                </div>
                <div>
                  <div className="text-xs text-gray-500">Code execution risk</div>
                  <div className={`text-sm font-semibold ${modelIntakeFormatInspection.lower_code_execution_risk ? 'text-green-300' : 'text-yellow-300'}`}>
                    {modelIntakeFormatInspection.lower_code_execution_risk ? 'lower' : 'review required'}
                  </div>
                </div>
                {modelIntakeSafetensorsHeader && (
                  <>
                    <div>
                      <div className="text-xs text-gray-500">Safetensors header</div>
                      <div className={`text-sm font-semibold ${modelIntakeSafetensorsHeader.valid_json ? 'text-green-300' : 'text-red-300'}`}>
                        {modelIntakeSafetensorsHeader.valid_json ? 'valid' : 'invalid'}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-gray-500">Tensor count</div>
                      <div className="text-sm font-semibold text-white">{modelIntakeSafetensorsHeader.tensor_count ?? 'unknown'}</div>
                    </div>
                  </>
                )}
              </div>
              {Array.isArray(modelIntakeSafetensorsHeader?.metadata_keys) && modelIntakeSafetensorsHeader.metadata_keys.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-2">
                  {modelIntakeSafetensorsHeader.metadata_keys.slice(0, 12).map((key: string) => (
                    <span key={key} className="rounded bg-gray-800 px-2 py-1 text-xs text-gray-300">{key}</span>
                  ))}
                </div>
              )}
            </div>
          )}

          {modelIntakeSummary?.sha256 && (
            <div className="mt-5 rounded border border-gray-700 bg-gray-900 p-3">
              <div className="text-xs text-gray-400">
                Observed SHA-256{modelIntakeFetch?.truncated ? ' of inspected bytes' : ''}
              </div>
              <div className="mt-1 break-all font-mono text-xs text-gray-300">{modelIntakeSummary.sha256}</div>
            </div>
          )}

          {modelIntakeSummary?.expected_sha256 && modelIntakeSummary.expected_sha256 !== modelIntakeSummary?.sha256 && (
            <div className="mt-3 rounded border border-gray-700 bg-gray-900 p-3">
              <div className="text-xs text-gray-400">Expected full-artifact SHA-256</div>
              <div className="mt-1 break-all font-mono text-xs text-gray-300">{modelIntakeSummary.expected_sha256}</div>
              {modelIntakeSummary?.checksum_status && (
                <div className="mt-2 text-xs text-gray-500">Status: {String(modelIntakeSummary.checksum_status).replace(/_/g, ' ')}</div>
              )}
            </div>
          )}

          <div className="mt-5 grid grid-cols-1 gap-3 lg:grid-cols-2">
            <div className="rounded border border-gray-700 bg-gray-900 p-3">
              <div className="text-xs text-gray-400">Artifact fetch</div>
              <div className="mt-2 grid gap-3 sm:grid-cols-2">
                <div>
                  <div className="text-xs text-gray-500">Source</div>
                  <div className="text-sm font-semibold text-white">{modelIntakeFetch?.source || modelIntakeSummary?.source_kind || 'unknown'}</div>
                </div>
                <div>
                  <div className="text-xs text-gray-500">HTTP status</div>
                  <div className="text-sm font-semibold text-white">{modelIntakeFetch?.status ?? 'not applicable'}</div>
                </div>
                <div>
                  <div className="text-xs text-gray-500">Bytes acquired</div>
                  <div className="text-sm font-semibold text-white">
                    {formatBytes(modelIntakeFetch?.bytes_observed)}
                    {modelIntakeFetch?.truncated ? <span className="ml-2 text-xs text-yellow-300">truncated</span> : null}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-gray-500">Acquisition limit</div>
                  <div className="text-sm font-semibold text-white">{formatBytes(scan.options?.max_download_bytes || modelIntakeFetch?.content_length)}</div>
                </div>
              </div>
              {modelIntakeFetch?.error && (
                <div className="mt-3 rounded bg-red-950/30 p-2 text-xs text-red-200">{modelIntakeFetch.error}</div>
              )}
            </div>

            <div className="rounded border border-gray-700 bg-gray-900 p-3">
              <div className="text-xs text-gray-400">Platform metadata</div>
              <div className="mt-2 grid gap-3 sm:grid-cols-2">
                <div>
                  <div className="text-xs text-gray-500">Repository</div>
                  <div className="break-all text-sm font-semibold text-white">{modelIntakeMetadata.huggingface_repo || modelIntakeSummary?.registry?.repository || 'unknown'}</div>
                </div>
                <div>
                  <div className="text-xs text-gray-500">Revision</div>
                  <div className="break-all text-sm font-semibold text-white">{modelIntakeMetadata.revision || modelIntakeSummary?.registry?.revision || 'not pinned'}</div>
                </div>
                <div>
                  <div className="text-xs text-gray-500">Library</div>
                  <div className="text-sm font-semibold text-white">{modelIntakeMetadata.library_name || 'unknown'}</div>
                </div>
                <div>
                  <div className="text-xs text-gray-500">Pipeline</div>
                  <div className="text-sm font-semibold text-white">{modelIntakeMetadata.pipeline_tag || 'unknown'}</div>
                </div>
                <div>
                  <div className="text-xs text-gray-500">Gated/private</div>
                  <div className="text-sm font-semibold text-white">
                    {modelIntakeMetadata.gated ? 'gated' : 'not gated'} / {modelIntakeMetadata.private ? 'private' : 'public'}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-gray-500">Artifact file</div>
                  <div className="break-all text-sm font-semibold text-white">{modelIntakeMetadata.huggingface_file || modelIntakeSummary?.registry?.path || 'unknown'}</div>
                </div>
              </div>
              {Array.isArray(modelIntakeMetadata.tags) && modelIntakeMetadata.tags.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-2">
                  {modelIntakeMetadata.tags.slice(0, 10).map((tag: string) => (
                    <span key={tag} className="rounded bg-gray-800 px-2 py-1 text-xs text-gray-300">{tag}</span>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="mt-5 rounded border border-gray-700 bg-gray-900 p-3">
            <div className="text-xs text-gray-400">Verification scope</div>
            <div className="mt-2 grid gap-2 text-sm text-gray-300 md:grid-cols-3">
              <div>Runtime execution: {String(model_intake?.dynamic_sandbox?.status || 'NOT_RUN').replace(/_/g, ' ')}</div>
              <div>Integrity: {modelIntakeFetch?.truncated ? 'partial artifact only' : modelIntakeSummary?.sha256 ? 'complete observed digest' : 'not established'}</div>
              <div>Admission status: {String(model_intake?.admission?.status || 'NOT_RUN').replace(/_/g, ' ')}</div>
            </div>
          </div>
            </div>
          </details>
        </div>
      )}

      {/* Triage + Coverage Gaps */}
      {(triage?.confirmed?.count !== undefined || (coverageGaps?.issues || []).length > 0) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Triage & Coverage</h2>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3 mb-4">
            <div className="bg-gray-700/40 rounded-lg p-3">
              <div className="text-xs text-gray-400">Confirmed</div>
              <div className="text-lg font-semibold text-green-400">{triage?.confirmed?.count || 0}</div>
            </div>
            <div className="bg-gray-700/40 rounded-lg p-3">
              <div className="text-xs text-gray-400">Suspected High</div>
              <div className="text-lg font-semibold text-orange-400">{triage?.suspected_high?.count || 0}</div>
            </div>
            <div className="bg-gray-700/40 rounded-lg p-3">
              <div className="text-xs text-gray-400">Needs Review</div>
              <div className="text-lg font-semibold text-yellow-400">{triage?.needs_review?.count || 0}</div>
            </div>
            <div className="bg-gray-700/40 rounded-lg p-3">
              <div className="text-xs text-gray-400">AI False Positives</div>
              <div className="text-lg font-semibold text-slate-300">{triage?.ai_false_positive?.count || 0}</div>
            </div>
            <div className="bg-gray-700/40 rounded-lg p-3">
              <div className="text-xs text-gray-400">Verification Skipped</div>
              <div className="text-lg font-semibold text-slate-300">{triage?.verification_skipped?.count || 0}</div>
            </div>
          </div>
          <div>
            <h3 className="text-sm text-gray-400 mb-2">Coverage Gaps</h3>
            {(coverageGaps?.issues || []).length > 0 ? (
              <ul className="list-disc list-inside text-sm text-gray-300 space-y-1">
                {coverageGaps.issues.map((issue: string, idx: number) => (
                  <li key={idx}>{issue}</li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-gray-400">No coverage gaps flagged.</p>
            )}
          </div>
        </div>
      )}

      {/* Compliance */}
      {result?.compliance && <ComplianceSection compliance={result.compliance} />}

      {/* Remediation Summary */}
      <details open={!isModelIntakeScan} className={isModelIntakeScan ? 'mb-4 rounded-lg border border-gray-700 bg-gray-800/50' : 'contents'}>
        <summary className={isModelIntakeScan ? 'cursor-pointer px-5 py-4 text-sm font-semibold text-gray-200' : 'hidden'}>
          Remediation tracking ({findings.length} raw finding{findings.length === 1 ? '' : 's'})
        </summary>
        {enableRemediationTracking && findings.length > 0 && (
          <RemediationSummary remediations={remediationData} totalFindings={findings.length} />
        )}
      </details>

      {/* WAF Detection */}
      {discovery.waf_detection?.detected && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">WAF Detection</h2>
          <div className="bg-yellow-900/20 border border-yellow-500/40 rounded-lg p-4">
            <div className="flex items-center gap-3">
              <svg className="w-6 h-6 text-yellow-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              <div>
                <span className="text-yellow-400 font-medium text-lg">
                  {discovery.waf_detection.product || 'Web Application Firewall Detected'}
                </span>
                {discovery.waf_detection.confidence && (
                  <span className="ml-2 text-gray-400 text-sm">
                    ({discovery.waf_detection.confidence}% confidence)
                  </span>
                )}
              </div>
            </div>
            {discovery.waf_detection.reason && (
              <p className="text-gray-400 text-sm mt-2">{discovery.waf_detection.reason}</p>
            )}
          </div>
        </div>
      )}

      {/* DNS */}
      {dns && Object.keys(dns).length > 0 && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">DNS Configuration</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {dns.a && <div><h3 className="text-sm text-gray-400 mb-1">A Records</h3><p className="font-mono text-sm">{Array.isArray(dns.a) ? dns.a.join(', ') : dns.a}</p></div>}
            {dns.aaaa && <div><h3 className="text-sm text-gray-400 mb-1">AAAA Records</h3><p className="font-mono text-sm">{Array.isArray(dns.aaaa) ? dns.aaaa.join(', ') : dns.aaaa}</p></div>}
            {dns.mx && <div><h3 className="text-sm text-gray-400 mb-1">MX Records</h3><p className="font-mono text-xs">{Array.isArray(dns.mx) ? dns.mx.map((r: any) => {
              if (typeof r === 'string') return r
              const host = r?.host ?? r?.exchange ?? r?.value ?? ''
              const prio = r?.priority
              if ((prio !== undefined && prio !== null) && host) return `${prio} ${host}`
              return host || (prio !== undefined && prio !== null ? String(prio) : '')
            }).filter(Boolean).join(', ') : dns.mx}</p></div>}
            {dns.spf && <div><h3 className="text-sm text-gray-400 mb-1">SPF Record</h3><p className="font-mono text-xs break-all">{dns.spf}</p></div>}
            {dns.dmarc?.record && <div><h3 className="text-sm text-gray-400 mb-1">DMARC Record</h3><p className="font-mono text-xs break-all">{dns.dmarc.record}</p></div>}
            {dns.dkim && <div><h3 className="text-sm text-gray-400 mb-1">DKIM</h3><p className={`text-sm ${dns.dkim.found ? 'text-green-400' : 'text-gray-500'}`}>{dns.dkim.found ? `Found (${dns.dkim.selectors_found?.join(', ') || 'selectors detected'})` : 'Not detected'}</p></div>}
            {dns.caa && <div><h3 className="text-sm text-gray-400 mb-1">CAA Records</h3><p className="font-mono text-xs">{Array.isArray(dns.caa) ? dns.caa.map((r: any) => typeof r === 'string' ? r : `${r.flags || 0} ${r.tag} ${r.value}`).join('; ') : (dns.caa.records ? dns.caa.records.join('; ') : 'Not configured')}</p></div>}
            {dns.dnssec && <div><h3 className="text-sm text-gray-400 mb-1">DNSSEC</h3><p className={`capitalize ${dns.dnssec.status === 'secure' ? 'text-green-400' : dns.dnssec.status === 'timeout' ? 'text-gray-500' : 'text-orange-400'}`}>{dns.dnssec.status === 'timeout' ? 'Check timed out' : dns.dnssec.status || 'Not configured'}</p></div>}
            {dns.mta_sts !== undefined && <div><h3 className="text-sm text-gray-400 mb-1">MTA-STS</h3><p className={`text-sm ${dns.mta_sts?.enabled || dns.mta_sts === true ? 'text-green-400' : 'text-gray-500'}`}>{dns.mta_sts?.enabled || dns.mta_sts === true ? 'Enabled' : 'Not configured'}</p></div>}
            {dns.tls_rpt !== undefined && <div><h3 className="text-sm text-gray-400 mb-1">TLS-RPT</h3><p className={`text-sm ${dns.tls_rpt?.enabled || dns.tls_rpt === true ? 'text-green-400' : 'text-gray-500'}`}>{dns.tls_rpt?.enabled || dns.tls_rpt === true ? 'Enabled' : 'Not configured'}</p></div>}
            {dns.zone_transfer !== undefined && <div><h3 className="text-sm text-gray-400 mb-1">Zone Transfer</h3><p className={`text-sm ${dns.zone_transfer?.vulnerable ? 'text-red-400' : 'text-green-400'}`}>{dns.zone_transfer?.vulnerable ? 'Vulnerable!' : 'Protected'}</p></div>}
          </div>
        </div>
      )}

      {/* TLS */}
      {tls && (tls.certificate || tls.cipher_suites || tls.sslyze || tls.testssl || tls.nmap) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">TLS/SSL Configuration</h2>
          {tls.certificate && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-4">
              <div className="bg-gray-900 rounded-lg p-4">
                <h4 className="text-sm text-gray-400 mb-1">Subject</h4>
                <p className="font-mono text-sm text-white">{tls.certificate.subject?.replace('CN = ', '') || '—'}</p>
              </div>
              <div className="bg-gray-900 rounded-lg p-4">
                <h4 className="text-sm text-gray-400 mb-1">Issuer</h4>
                <p className="font-mono text-sm text-white">
                  {(() => {
                    const issuer = tls.certificate.issuer || ''
                    // Extract both Organization and CN for better display
                    const oMatch = issuer.match(/O\s*=\s*([^,]+)/i)
                    const cnMatch = issuer.match(/CN\s*=\s*([^,]+)/i)
                    const org = oMatch ? oMatch[1].trim() : null
                    const cn = cnMatch ? cnMatch[1].trim() : null
                    // Show "Organization (CN)" or just one if only one exists
                    if (org && cn && org !== cn) return `${org} (${cn})`
                    if (org) return org
                    if (cn) return cn
                    return issuer || '—'
                  })()}
                </p>
              </div>
              <div className="bg-gray-900 rounded-lg p-4">
                <h4 className="text-sm text-gray-400 mb-1">Validity Period</h4>
                {tls.certificate.not_before && tls.certificate.not_after ? (
                  <p className="font-mono text-sm text-white">
                    {new Date(tls.certificate.not_before).toLocaleDateString()} - {new Date(tls.certificate.not_after).toLocaleDateString()}
                  </p>
                ) : (
                  <p className="font-mono text-sm text-white">—</p>
                )}
              </div>
              <div className="bg-gray-900 rounded-lg p-4">
                <h4 className="text-sm text-gray-400 mb-1">Expires In</h4>
                <p className={`text-lg font-bold ${
                  tls.certificate.days_remaining === null || tls.certificate.days_remaining === undefined
                    ? 'text-gray-400'
                    : tls.certificate.days_remaining < 14
                    ? 'text-red-500'
                    : tls.certificate.days_remaining < 30
                    ? 'text-orange-500'
                    : 'text-green-400'
                }`}>
                  {tls.certificate.days_remaining !== null && tls.certificate.days_remaining !== undefined
                    ? `${tls.certificate.days_remaining} days`
                    : '—'}
                </p>
              </div>
              <div className="bg-gray-900 rounded-lg p-4">
                <h4 className="text-sm text-gray-400 mb-1">Key</h4>
                <p className="font-mono text-sm text-white">
                  {tls.certificate.key_algo?.replace('Encryption', '').replace('rsaE', 'RSA E') || '—'} {tls.certificate.key_size ? `${tls.certificate.key_size}-bit` : ''}
                </p>
              </div>
              <div className="bg-gray-900 rounded-lg p-4">
                <h4 className="text-sm text-gray-400 mb-1">Signature</h4>
                <p className="font-mono text-sm text-white">{tls.certificate.sig_algo || '—'}</p>
              </div>
              {tls.certificate.serial && (
                <div className="bg-gray-900 rounded-lg p-4">
                  <h4 className="text-sm text-gray-400 mb-1">Serial</h4>
                  <p className="font-mono text-xs text-white break-all">{tls.certificate.serial}</p>
                </div>
              )}
              {tls.certificate.wildcard !== undefined && (
                <div className="bg-gray-900 rounded-lg p-4">
                  <h4 className="text-sm text-gray-400 mb-1">Type</h4>
                  <p className={`text-sm ${tls.certificate.wildcard ? 'text-yellow-400' : 'text-green-400'}`}>
                    {tls.certificate.wildcard ? 'Wildcard Certificate' : 'Single Domain'}
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Certificate Fingerprints */}
          {tls.certificate?.fingerprints && (
            <div className="mb-4">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Certificate Fingerprints</h3>
              <div className="bg-gray-900 rounded-lg p-3 space-y-2">
                {tls.certificate.fingerprints.sha256 && (
                  <div>
                    <span className="text-xs text-gray-500">SHA-256: </span>
                    <span className="text-xs font-mono text-gray-300 break-all">{tls.certificate.fingerprints.sha256}</span>
                  </div>
                )}
                {tls.certificate.fingerprints.sha1 && (
                  <div>
                    <span className="text-xs text-gray-500">SHA-1: </span>
                    <span className="text-xs font-mono text-gray-400 break-all">{tls.certificate.fingerprints.sha1}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Subject Alternative Names (SANs) */}
          {tls.certificate?.sans && Array.isArray(tls.certificate.sans) && tls.certificate.sans.length > 0 && (
            <div className="mb-4">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Subject Alternative Names (SANs)</h3>
              <div className="flex flex-wrap gap-2">
                {tls.certificate.sans.map((san: string, i: number) => (
                  <span key={i} className="px-2 py-1 bg-gray-900 text-gray-300 text-xs font-mono rounded">
                    {san}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* OCSP & CA Issuer URLs */}
          {(tls.certificate?.ocsp_urls?.length > 0 || tls.certificate?.ca_issuer_urls?.length > 0 || tls.ocsp?.ocsp_url) && (
            <div className="mb-4 grid grid-cols-1 md:grid-cols-2 gap-4">
              {(tls.certificate?.ocsp_urls?.length > 0 || tls.ocsp?.ocsp_url) && (
                <div className="bg-gray-900 rounded-lg p-3">
                  <h4 className="text-xs font-semibold text-gray-400 mb-2">OCSP Responder</h4>
                  <div className="space-y-1">
                    {tls.certificate?.ocsp_urls?.map((url: string, i: number) => (
                      <p key={i} className="text-xs font-mono text-blue-400 break-all">{url}</p>
                    ))}
                    {!tls.certificate?.ocsp_urls?.length && tls.ocsp?.ocsp_url && (
                      <p className="text-xs font-mono text-blue-400 break-all">{tls.ocsp.ocsp_url}</p>
                    )}
                  </div>
                </div>
              )}
              {tls.certificate?.ca_issuer_urls?.length > 0 && (
                <div className="bg-gray-900 rounded-lg p-3">
                  <h4 className="text-xs font-semibold text-gray-400 mb-2">CA Issuer URLs</h4>
                  <div className="space-y-1">
                    {tls.certificate.ca_issuer_urls.map((url: string, i: number) => (
                      <p key={i} className="text-xs font-mono text-blue-400 break-all">{url}</p>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Certificate Chain */}
          {tls.sslyze?.certificate_chain && tls.sslyze.certificate_chain.length > 1 && (
            <div className="mb-4">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Certificate Chain</h3>
              <div className="space-y-2">
                {tls.sslyze.certificate_chain.map((cert: any, idx: number) => {
                  const subjectCN = cert.subject?.rfc4514_string || cert.subject?.attributes?.find((a: any) => a.oid?.name === 'commonName')?.value || 'Unknown'
                  const issuerOrg = cert.issuer?.attributes?.find((a: any) => a.oid?.name === 'organizationName')?.value
                  const issuerCN = cert.issuer?.attributes?.find((a: any) => a.oid?.name === 'commonName')?.value
                  const issuerDisplay = issuerOrg && issuerCN && issuerOrg !== issuerCN ? `${issuerOrg} (${issuerCN})` : issuerOrg || issuerCN || 'Unknown'
                  return (
                    <div key={idx} className="bg-gray-900 rounded-lg p-3 flex items-center gap-3">
                      <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold ${idx === 0 ? 'bg-blue-900 text-blue-200' : idx === tls.sslyze.certificate_chain.length - 1 ? 'bg-green-900 text-green-200' : 'bg-gray-700 text-gray-300'}`}>
                        {idx + 1}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-white text-sm font-medium truncate">{subjectCN}</p>
                        <p className="text-gray-500 text-xs truncate">Issued by: {issuerDisplay}</p>
                      </div>
                      <div className="text-right text-xs text-gray-500">
                        {idx === 0 && <span className="px-2 py-0.5 bg-blue-900/50 text-blue-300 rounded">Leaf</span>}
                        {idx === tls.sslyze.certificate_chain.length - 1 && idx > 0 && <span className="px-2 py-0.5 bg-green-900/50 text-green-300 rounded">Root/Intermediate</span>}
                        {idx > 0 && idx < tls.sslyze.certificate_chain.length - 1 && <span className="px-2 py-0.5 bg-gray-700 text-gray-400 rounded">Intermediate</span>}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* TLS Versions - derive from cipher_suites, nmap, or sslyze.tls_versions */}
          {(() => {
            // Collect TLS versions from all available sources
            const versions: Record<string, boolean> = {}
            // From sslyze.tls_versions
            if (tls.sslyze?.tls_versions) {
              Object.entries(tls.sslyze.tls_versions).forEach(([v, supported]) => {
                if (supported) versions[v] = true
              })
            }
            // From cipher_suites keys (top-level)
            if (tls.cipher_suites) {
              Object.keys(tls.cipher_suites).forEach(v => {
                if (tls.cipher_suites[v]?.length > 0) versions[v] = true
              })
            }
            // From nmap.ciphers_by_protocol keys
            if (tls.nmap?.ciphers_by_protocol) {
              Object.keys(tls.nmap.ciphers_by_protocol).forEach(v => {
                if (tls.nmap.ciphers_by_protocol[v]?.length > 0) versions[v] = true
              })
            }
            const versionOrder = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3', 'ssl_2_0', 'ssl_3_0', 'tls_1_0', 'tls_1_1', 'tls_1_2', 'tls_1_3']
            const sortedVersions = Object.keys(versions).sort((a, b) => {
              const ai = versionOrder.findIndex(v => a.toLowerCase().includes(v.toLowerCase().replace('.', '').replace('_', '')))
              const bi = versionOrder.findIndex(v => b.toLowerCase().includes(v.toLowerCase().replace('.', '').replace('_', '')))
              return ai - bi
            })
            if (sortedVersions.length === 0) return null
            return (
              <div className="mb-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-2">Protocol Support</h3>
                <div className="flex flex-wrap gap-2">
                  {sortedVersions.map(version => (
                    <span key={version} className={`px-3 py-1 rounded text-sm font-mono ${
                      (version.includes('1.3') || version.includes('1.2') || version.includes('1_3') || version.includes('1_2'))
                        ? 'bg-green-900 text-green-200'
                        : (version.toLowerCase().includes('ssl') || version.includes('1.0') || version.includes('1.1') || version.includes('1_0') || version.includes('1_1'))
                        ? 'bg-red-900 text-red-200'
                        : 'bg-yellow-900 text-yellow-200'
                    }`}>
                      {version}: ✓
                    </span>
                  ))}
                </div>
              </div>
            )
          })()}

          {/* Cipher Suites - prefer nmap data (has grades), fallback to sslyze */}
          {(tls.nmap?.ciphers_by_protocol || tls.sslyze?.cipher_suites) && (
            <div className="mb-4">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Cipher Suites</h3>
              <div className="space-y-3">
                {/* Use nmap data if available (has grades and security info) */}
                {tls.nmap?.ciphers_by_protocol && Object.keys(tls.nmap.ciphers_by_protocol).length > 0 ? (
                  Object.entries(tls.nmap.ciphers_by_protocol)
                    .filter(([, ciphers]: [string, any]) => Array.isArray(ciphers) && ciphers.length > 0)
                    .map(([protocol, ciphers]: [string, any]) => (
                      <div key={protocol} className="bg-gray-900 rounded-lg p-3">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="text-xs font-mono text-blue-400">{protocol}</h4>
                          <span className="text-xs text-gray-500">{ciphers.length} cipher{ciphers.length !== 1 ? 's' : ''}</span>
                        </div>
                        <div className="space-y-1.5">
                          {ciphers.map((cipher: any, i: number) => (
                            <div key={i} className="flex items-center gap-2 text-xs">
                              {/* Grade badge */}
                              <span className={`px-1.5 py-0.5 rounded font-bold min-w-[24px] text-center bg-gray-800 ${gradeTextColor(cipher.grade)}`}>
                                {cipher.grade || '?'}
                              </span>
                              {/* Security indicator */}
                              <span className={`${
                                cipher.insecure ? 'text-red-400' :
                                cipher.weak ? 'text-yellow-400' :
                                cipher.secure ? 'text-green-400' :
                                'text-gray-400'
                              }`}>
                                {cipher.insecure ? '✗' : cipher.weak ? '!' : cipher.secure ? '✓' : '—'}
                              </span>
                              {/* Cipher name */}
                              <span className="font-mono text-gray-300 truncate" title={cipher.name}>
                                {cipher.name?.length > 45 ? cipher.name.substring(0, 45) + '...' : cipher.name}
                              </span>
                              {/* Reason tooltip */}
                              {cipher.reason && (
                                <span className="text-gray-500 truncate hidden sm:inline" title={cipher.reason}>
                                  ({cipher.reason.length > 30 ? cipher.reason.substring(0, 30) + '...' : cipher.reason})
                                </span>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    ))
                ) : (
                  /* Fallback to sslyze data (string names only) */
                  tls.sslyze?.cipher_suites && Object.keys(tls.sslyze.cipher_suites).length > 0 && (
                    Object.entries(tls.sslyze.cipher_suites)
                      .filter(([, ciphers]: [string, any]) => Array.isArray(ciphers) && ciphers.length > 0)
                      .map(([protocol, ciphers]: [string, any]) => (
                        <div key={protocol} className="bg-gray-900 rounded-lg p-3">
                          <h4 className="text-xs font-mono text-blue-400 mb-2">{protocol}</h4>
                          <div className="flex flex-wrap gap-1">
                            {ciphers.slice(0, 8).map((cipher: string, i: number) => (
                              <span key={i} className={`px-2 py-0.5 text-xs rounded font-mono ${
                                cipher.includes('CHACHA') || cipher.includes('GCM')
                                  ? 'bg-green-900/50 text-green-300'
                                  : cipher.includes('CBC')
                                  ? 'bg-yellow-900/50 text-yellow-300'
                                  : 'bg-gray-700 text-gray-300'
                              }`}>
                                {cipher.length > 40 ? cipher.substring(0, 40) + '...' : cipher}
                              </span>
                            ))}
                            {ciphers.length > 8 && (
                              <span className="px-2 py-0.5 text-xs text-gray-500">+{ciphers.length - 8} more</span>
                            )}
                          </div>
                        </div>
                      ))
                  )
                )}
              </div>
            </div>
          )}

          {/* Vulnerabilities */}
          {tls.sslyze?.vulnerabilities && tls.sslyze.vulnerabilities.length > 0 && (
            <div className="mb-4 p-4 bg-red-900/20 border border-red-500/40 rounded-lg">
              <h3 className="text-sm font-semibold text-red-400 mb-2">Vulnerabilities Detected</h3>
              <div className="space-y-1">
                {tls.sslyze.vulnerabilities.map((vuln: string, i: number) => (
                  <div key={i} className="flex items-center gap-2 text-sm text-red-300">
                    <span className="text-red-500">!</span>
                    <span>{vuln}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Weak Indicators from nmap */}
          {tls.nmap?.weak_indicators && tls.nmap.weak_indicators.length > 0 && (
            <div className="mb-4 p-4 bg-yellow-900/20 border border-yellow-500/40 rounded-lg">
              <h3 className="text-sm font-semibold text-yellow-400 mb-2">Configuration Warnings</h3>
              <div className="space-y-1">
                {tls.nmap.weak_indicators.map((indicator: string, i: number) => (
                  <div key={i} className="flex items-center gap-2 text-sm text-yellow-300">
                    <span className="text-yellow-500">!</span>
                    <span>{indicator}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* OCSP and other indicators */}
          <div className="flex flex-wrap items-center gap-3">
            {tls.ocsp && (
              <span className={`px-3 py-1 rounded text-sm ${tls.ocsp.stapled ? 'bg-green-900 text-green-200' : 'bg-yellow-900 text-yellow-200'}`}>
                OCSP Stapling: {tls.ocsp.stapled ? 'Enabled' : 'Not Detected'}
              </span>
            )}
            {tls.testssl?.supports_tls13 !== null && (
              <span className={`px-3 py-1 rounded text-sm ${tls.testssl.supports_tls13 ? 'bg-green-900 text-green-200' : 'bg-yellow-900 text-yellow-200'}`}>
                TLS 1.3: {tls.testssl.supports_tls13 ? 'Supported' : 'Not Supported'}
              </span>
            )}
            {tls.sslyze?.session_resumption?.session_id_resumption !== undefined && (
              <span className={`px-3 py-1 rounded text-sm ${tls.sslyze.session_resumption.session_id_resumption ? 'bg-green-900 text-green-200' : 'bg-gray-700 text-gray-400'}`}>
                Session Resumption: {tls.sslyze.session_resumption.session_id_resumption ? 'Enabled' : 'Disabled'}
              </span>
            )}
          </div>

          {/* Show message if no TLS data */}
          {!tls.certificate?.days_remaining && !tls.sslyze?.tls_versions && !tls.testssl?.supports_tls13 && (
            <p className="text-gray-500 text-sm">No TLS/SSL data available - target may not support HTTPS or scan was limited.</p>
          )}
        </div>
      )}

      {/* Open Ports & Services */}
      {(network_scan.open_ports?.length > 0 || network_scan.services?.length > 0) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Open Ports & Services</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
            {network_scan.open_ports?.map((port: any, i: number) => (
              <div key={i} className="bg-gray-900 rounded-lg p-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-lg text-white">{port.port}</span>
                  <span className="px-2 py-0.5 text-xs rounded bg-blue-900 text-blue-200">
                    {port.protocol || 'tcp'}
                  </span>
                </div>
                {port.service && (
                  <p className="text-gray-400 text-sm">{port.service}</p>
                )}
                {port.state && port.state !== 'open' && (
                  <p className="text-yellow-500 text-xs mt-1">{port.state}</p>
                )}
              </div>
            ))}
          </div>
          {network_scan.services?.length > 0 && (
            <div className="mt-4">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Service Details</h3>
              <div className="space-y-2">
                {network_scan.services.map((svc: any, i: number) => (
                  <div key={i} className="bg-gray-900 rounded-lg p-3 flex items-center justify-between">
                    <div>
                      <span className="text-white font-medium">{svc.name || 'unknown'}</span>
                      {svc.product && <span className="text-gray-400 ml-2">{svc.product}</span>}
                      {svc.version && <span className="px-1.5 py-0.5 bg-blue-900 text-blue-200 text-xs rounded ml-2">v{svc.version}</span>}
                    </div>
                    <span className="text-gray-500 font-mono text-sm">:{svc.port}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {network_scan.os_detection?.os_match && (
            <div className="mt-4 p-3 bg-gray-900 rounded-lg">
              <h3 className="text-sm font-semibold text-gray-400 mb-1">OS Detection</h3>
              <p className="text-white">{network_scan.os_detection.os_match}</p>
              {network_scan.os_detection.accuracy && (
                <span className="text-gray-500 text-sm">({network_scan.os_detection.accuracy}% confidence)</span>
              )}
            </div>
          )}
        </div>
      )}

      {/* Network Services Exposure */}
      {(network_services.vpn_endpoints?.length > 0 || network_services.remote_desktop?.length > 0 || network_services.database_exposure?.length > 0) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Network Services Exposure</h2>
          <div className="space-y-4">
            {network_services.vpn_endpoints?.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold text-gray-400 mb-2">VPN Endpoints</h3>
                <div className="space-y-2">
                  {network_services.vpn_endpoints.map((vpn: any, i: number) => (
                    <div key={i} className="bg-gray-900 rounded-lg p-3 flex items-center justify-between">
                      <span className="text-white">{vpn.type || 'VPN'}</span>
                      <span className="text-gray-400 font-mono text-sm">{vpn.endpoint || vpn.url}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {network_services.remote_desktop?.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold text-orange-400 mb-2">Remote Desktop Services</h3>
                <div className="space-y-2">
                  {network_services.remote_desktop.map((rd: any, i: number) => (
                    <div key={i} className="bg-orange-900/20 border border-orange-500/40 rounded-lg p-3 flex items-center justify-between">
                      <span className="text-orange-300">{rd.type || rd.service || 'RDP/VNC'}</span>
                      <span className="text-gray-400 font-mono text-sm">:{rd.port}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {network_services.database_exposure?.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold text-red-400 mb-2">Database Exposure</h3>
                <div className="space-y-2">
                  {network_services.database_exposure.map((db: any, i: number) => (
                    <div key={i} className="bg-red-900/20 border border-red-500/40 rounded-lg p-3 flex items-center justify-between">
                      <span className="text-red-300">{db.type || db.database || 'Database'}</span>
                      <span className="text-gray-400 font-mono text-sm">:{db.port}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* HTTP Security Headers */}
      {http && http.security_headers && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">HTTP Security Headers</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {[
              { name: 'HSTS', key: 'hsts', critical: true },
              { name: 'X-Frame-Options', key: 'x_frame_options', critical: true },
              { name: 'X-Content-Type-Options', key: 'x_content_type_options', critical: true },
              { name: 'Referrer-Policy', key: 'referrer_policy', critical: false },
              { name: 'Permissions-Policy', key: 'permissions_policy', critical: false },
              { name: 'COOP', key: 'coop', critical: false },
              { name: 'CORP', key: 'corp', critical: false },
            ].map(header => {
              const value = http.security_headers[header.key]
              const isSet = !!value
              return (
                <div key={header.key} className="bg-gray-900 rounded-lg p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-300 text-sm">{header.name}</span>
                    <span className={`px-2 py-1 text-xs rounded ${isSet ? 'bg-green-900 text-green-200' : header.critical ? 'bg-red-900 text-red-200' : 'bg-gray-700 text-gray-400'}`}>
                      {isSet ? (typeof value === 'string' && value.length < 20 ? value : 'Set') : 'Missing'}
                    </span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* CSP Evaluation */}
      {http?.csp_evaluation && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-2xl font-bold">Content Security Policy</h2>
            <div className="flex items-center gap-3">
              <span className={`text-3xl font-bold ${gradeTextColor(http.csp_evaluation.grade)}`}>
                {http.csp_evaluation.grade}
              </span>
              <span className="text-gray-400 text-sm">{http.csp_evaluation.score}/100</span>
            </div>
          </div>

          {http.csp_evaluation.issues?.length > 0 && (
            <div className="mb-6">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Issues</h3>
              <div className="space-y-2">
                {http.csp_evaluation.issues.map((issue: string, i: number) => (
                  <div key={i} className="flex items-start gap-2 text-sm">
                    <span className="text-yellow-500 mt-0.5">!</span>
                    <span className="text-gray-300">{issue}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {http.csp_evaluation.directives && (
            <div>
              <h3 className="text-sm font-semibold text-gray-400 mb-3">Directives</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {Object.entries(http.csp_evaluation.directives).map(([directive, values]: [string, any]) => (
                  <div key={directive} className="bg-gray-900 rounded-lg p-3">
                    <h4 className="text-xs font-mono text-blue-400 mb-1">{directive}</h4>
                    <div className="flex flex-wrap gap-1">
                      {Array.isArray(values) && values.map((v: string, i: number) => (
                        <span key={i} className={`px-1.5 py-0.5 text-xs rounded font-mono ${v.includes('unsafe') ? 'bg-red-900/50 text-red-300' : v === "'self'" ? 'bg-green-900/50 text-green-300' : v === "'none'" ? 'bg-green-900/50 text-green-300' : 'bg-gray-700 text-gray-300'}`}>
                          {v}
                        </span>
                      ))}
                      {(!Array.isArray(values) || values.length === 0) && (
                        <span className="text-gray-500 text-xs italic">empty</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Technology Stack */}
      {(discovery.tech?.items?.length > 0 || discovery.tech_stack_guess?.length > 0 || js_dependencies.vulnerable_libraries?.length > 0) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Technology Stack</h2>
          {js_dependencies.vulnerable_libraries?.length > 0 && (
            <div className="mb-6 p-4 bg-red-900/20 border border-red-500/40 rounded-lg">
              <h3 className="text-lg font-semibold text-red-400 mb-3">{js_dependencies.vulnerable_libraries.length} Vulnerable Libraries Detected</h3>
              <div className="space-y-3">
                {js_dependencies.vulnerable_libraries.map((lib: any, i: number) => (
                  <div key={i} className={`bg-gray-900/60 rounded-lg p-3 border-l-4 ${getSeverityBorderClass(lib.severity)}`}>
                    <span className="text-white font-medium">{lib.library}</span>
                    {lib.version && <span className="px-2 py-0.5 bg-red-900 text-red-200 text-xs rounded font-mono ml-2">v{lib.version}</span>}
                    {lib.cve && <a href={`https://nvd.nist.gov/vuln/detail/${lib.cve}`} target="_blank" rel="noopener noreferrer" className="text-blue-400 text-xs hover:underline ml-2">{lib.cve}</a>}
                    <p className="text-gray-400 text-sm mt-1">{lib.summary}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
          {discovery.tech?.items?.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {discovery.tech.items.map((tech: any, i: number) => (
                <div key={i} className="bg-gray-900 rounded-lg p-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-white font-medium">{tech.name}</span>
                      {tech.version && <span className="px-1.5 py-0.5 bg-blue-900 text-blue-200 text-xs rounded font-mono">v{tech.version}</span>}
                    </div>
                    <span className={`px-2 py-0.5 text-xs rounded ${tech.confidence >= 75 ? 'bg-green-900/50 text-green-300' : tech.confidence >= 50 ? 'bg-yellow-900/50 text-yellow-300' : 'bg-gray-700 text-gray-400'}`}>
                      {tech.confidence_label || `${tech.confidence}%`}
                    </span>
                  </div>
                  {tech.category && <p className="text-gray-500 text-xs mt-1">{tech.category}</p>}
                </div>
              ))}
            </div>
          ) : discovery.tech_stack_guess?.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {discovery.tech_stack_guess.map((tech: string, i: number) => (
                <span key={i} className="px-3 py-1 bg-blue-500/20 text-blue-400 rounded text-sm">{tech}</span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Discovered API Endpoints */}
      {discovery.browser_api_endpoints?.length > 0 && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Discovered API Endpoints</h2>
          <div className="space-y-2">
            {discovery.browser_api_endpoints.map((endpoint: any, i: number) => (
              <div key={i} className="bg-gray-900 rounded-lg p-3 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className={`px-2 py-0.5 text-xs font-mono rounded ${endpoint.method === 'GET' ? 'bg-green-900 text-green-200' : endpoint.method === 'POST' ? 'bg-blue-900 text-blue-200' : 'bg-gray-700 text-gray-300'}`}>
                    {endpoint.method || 'GET'}
                  </span>
                  <span className="font-mono text-sm text-gray-300">{endpoint.path || endpoint.url}</span>
                </div>
                <div className="flex items-center gap-2">
                  {endpoint.has_auth && <span className="px-2 py-0.5 text-xs bg-yellow-900/50 text-yellow-300 rounded">Auth</span>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Active Checks Results */}
      {(active_checks.xss || active_checks.sqli || active_checks.endpoints_tested || activeEndpointAttempts.length > 0 || activeCheckFamilyScopeLabel) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <h2 className="text-2xl font-bold">Active Security Testing</h2>
            {activeCheckFamilyScopeLabel && (
              <span className="rounded-full bg-blue-900/40 px-3 py-1 text-xs font-medium text-blue-200">
                Scope: {activeCheckFamilyScopeLabel}
              </span>
            )}
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {active_checks.xss && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-2">XSS Testing</h3>
                <div className="space-y-2">
                  {active_checks.xss.targets_tested !== undefined && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Targets Tested</span>
                      <span className="text-white">{active_checks.xss.targets_tested}</span>
                    </div>
                  )}
                  {active_checks.xss.reflections_found !== undefined && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Reflections Found</span>
                      <span className={active_checks.xss.reflections_found > 0 ? 'text-yellow-400' : 'text-gray-400'}>{active_checks.xss.reflections_found}</span>
                    </div>
                  )}
                  {active_checks.xss.vulnerabilities_found !== undefined && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Vulnerabilities</span>
                      <span className={active_checks.xss.vulnerabilities_found > 0 ? 'text-red-400' : 'text-green-400'}>{active_checks.xss.vulnerabilities_found}</span>
                    </div>
                  )}
                </div>
              </div>
            )}
            {active_checks.sqli && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-2">SQL Injection Testing</h3>
                <div className="space-y-2">
                  {active_checks.sqli.targets_tested !== undefined && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Targets Tested</span>
                      <span className="text-white">{active_checks.sqli.targets_tested}</span>
                    </div>
                  )}
                  {active_checks.sqli.parameters_tested !== undefined && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Parameters Tested</span>
                      <span className="text-white">{active_checks.sqli.parameters_tested}</span>
                    </div>
                  )}
                  {active_checks.sqli.vulnerabilities_found !== undefined && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">Vulnerabilities</span>
                      <span className={active_checks.sqli.vulnerabilities_found > 0 ? 'text-red-400' : 'text-green-400'}>{active_checks.sqli.vulnerabilities_found}</span>
                    </div>
                  )}
                  {active_checks.sqli.dbms_detected && (
                    <div className="flex justify-between text-sm">
                      <span className="text-gray-400">DBMS Detected</span>
                      <span className="text-blue-400">{active_checks.sqli.dbms_detected}</span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
          {active_checks.endpoints_tested?.length > 0 && (
            <div className="mt-4">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Endpoints Tested ({active_checks.endpoints_tested.length})</h3>
              <div className="max-h-32 overflow-y-auto bg-gray-900 rounded-lg p-3">
                {active_checks.endpoints_tested.slice(0, 20).map((ep: string, i: number) => (
                  <div key={i} className="text-xs font-mono text-gray-400 py-0.5 truncate">{ep}</div>
                ))}
                {active_checks.endpoints_tested.length > 20 && (
                  <div className="text-xs text-gray-500 mt-1">+{active_checks.endpoints_tested.length - 20} more</div>
                )}
              </div>
            </div>
          )}
          {activeEndpointAttempts.length > 0 && (
            <div className="mt-4">
              <div className="mb-2 flex items-center justify-between gap-3">
                <h3 className="text-sm font-semibold text-gray-400">Active Attempt Ledger ({activeEndpointAttempts.length})</h3>
                <span className="text-xs text-gray-500">showing {Math.min(activeEndpointAttempts.length, 12)}</span>
              </div>
              <div className="overflow-x-auto rounded-lg border border-gray-800 bg-gray-950/60">
                <table className="min-w-full divide-y divide-gray-800 text-left text-xs">
                  <thead className="bg-gray-900/80 text-gray-500">
                    <tr>
                      <th className="px-3 py-2 font-medium">Endpoint</th>
                      <th className="px-3 py-2 font-medium">Families</th>
                      <th className="px-3 py-2 font-medium">Params</th>
                      <th className="px-3 py-2 font-medium">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-900">
                    {activeEndpointAttempts.slice(0, 12).map((attempt: any, i: number) => {
                      const families = activeAttemptFamilies(attempt)
                      const reason = activeAttemptReason(attempt)
                      const paramPreview = activeAttemptParamPreview(attempt)
                      return (
                        <tr key={`${attempt.custom_endpoint || attempt.url || i}`} className="align-top">
                          <td className="max-w-[420px] px-3 py-2">
                            <div className="font-mono text-gray-300 break-all">
                              {attempt.custom_endpoint || attempt.url || 'unknown endpoint'}
                            </div>
                            {Array.isArray(attempt.techniques_attempted) && attempt.techniques_attempted.length > 0 && (
                              <div className="mt-1 text-[11px] text-gray-500">
                                techniques: {attempt.techniques_attempted.slice(0, 5).join(', ')}
                              </div>
                            )}
                          </td>
                          <td className="px-3 py-2">
                            <div className="flex flex-wrap gap-1">
                              {(families.length ? families : ['unknown']).map((family) => (
                                <span key={family} className="rounded bg-blue-500/10 px-1.5 py-0.5 text-[11px] text-blue-300">
                                  {formatCheckFamilyName(family)}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td className="px-3 py-2">
                            <div className="whitespace-nowrap text-gray-300">{activeAttemptParamSummary(attempt)}</div>
                            {paramPreview && <div className="mt-1 max-w-[260px] break-words font-mono text-[11px] text-gray-500">{paramPreview}</div>}
                          </td>
                          <td className="px-3 py-2">
                            <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${activeAttemptStatusClass(attempt.status)}`}>
                              {formatScanToken(attempt.status || 'unknown')}
                            </span>
                            {reason && <div className="mt-1 max-w-[220px] text-[11px] text-gray-500">{reason}</div>}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
              {activeEndpointAttempts.length > 12 && (
                <div className="mt-2 text-xs text-gray-500">+{activeEndpointAttempts.length - 12} more attempt rows in the raw report.</div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Access Control Testing */}
      {(access_control.forced_browsing || access_control.mass_assignment || access_control.bola_idor || access_control.bola) && (() => {
        const fb = access_control.forced_browsing
        const bola = access_control.bola_idor || access_control.bola
        const fbFindings = fb?.findings || []
        const fbSummary = fb?.summary || {}
        const bolaRawFindings = bola?.vulnerable_endpoints || bola?.findings || []
        const accessibleFindings = fbFindings.filter((f: any) => f.accessible && !f.false_positive_detected)
        const protectedFindings = fbFindings.filter((f: any) => f.protected)
        const fpFindings = fbFindings.filter((f: any) => f.false_positive_detected)
        const otherFindings = fbFindings.filter((f: any) => !f.accessible && !f.protected && !f.false_positive_detected)
        const bolaFindings = bolaRawFindings.map((f: any, i: number) => {
          if (typeof f === 'string') {
            return {
              key: `bola-finding-${i}`,
              endpoint: f,
              title: null,
              severity: null,
            }
          }
          const evidence = f?.evidence || {}
          return {
            key: f?.id || `bola-finding-${i}`,
            endpoint: f?.path || f?.url || evidence?.url || evidence?.path || evidence?.endpoint || null,
            title: f?.title || f?.type || null,
            severity: f?.severity || null,
          }
        }).filter((f: any) => f.endpoint || f.title)
        const bolaHasFindings = bolaFindings.length > 0
        const bolaClean = bola?.endpoints_tested > 0 && !bolaHasFindings && (bola?.access_violations ?? 0) === 0

        // Group non-accessible findings by category
        const fpByCategory: Record<string, any[]> = {}
        for (const f of [...fpFindings, ...otherFindings]) {
          const cat = f.category || 'other'
          if (!fpByCategory[cat]) fpByCategory[cat] = []
          fpByCategory[cat].push(f)
        }
        const categoryLabels: Record<string, string> = {
          admin_panels: 'Admin Panels',
          debug_dev: 'Debug / Dev Tools',
          sensitive_files: 'Sensitive Files',
          backup_files: 'Backup Files',
          management_consoles: 'Management Consoles',
          logs_monitoring: 'Logs & Monitoring',
          user_management: 'User Management',
          api_endpoints: 'API Endpoints',
          cloud_metadata: 'Cloud Metadata',
        }
        const sevColors: Record<string, string> = {
          critical: `${SEVERITY_BADGE_STYLES.critical} border-red-500/40`,
          high: `${SEVERITY_BADGE_STYLES.high} border-orange-500/40`,
          medium: `${SEVERITY_BADGE_STYLES.medium} border-yellow-500/40`,
          low: `${SEVERITY_BADGE_STYLES.low} border-blue-500/40`,
          info: `${SEVERITY_BADGE_STYLES.info} border-gray-500/40`,
        }

        return (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Access Control Testing</h2>
          <div className="space-y-4">
            {fb && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-3">Forced Browsing</h3>

                {/* Summary bar */}
                <div className="flex items-center gap-4 mb-3 flex-wrap">
                  {fb.paths_tested !== undefined && (
                    <span className="text-sm text-gray-400">Paths tested: <span className="text-white font-medium">{fb.paths_tested}</span></span>
                  )}
                  {Object.entries(fbSummary).filter(([, v]) => (v as number) > 0).map(([sev, count]) => (
                    <span key={sev} className={`text-xs px-2 py-0.5 rounded-full border ${sevColors[sev] || sevColors.info}`}>
                      {String(count)} {sev}
                    </span>
                  ))}
                </div>

                {/* Accessible paths - the real findings, always visible */}
                {accessibleFindings.length > 0 && (
                  <div className="mb-3">
                    <p className="text-xs font-semibold text-red-400 uppercase tracking-wider mb-2">Accessible (Confirmed)</p>
                    <div className="space-y-2">
                      {accessibleFindings.map((f: any, i: number) => (
                        <div key={i} className="bg-red-900/20 border border-red-500/30 rounded-lg p-3">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className={`text-xs px-2 py-0.5 rounded-full border ${sevColors[f.severity] || sevColors.info}`}>{f.severity}</span>
                            <span className="text-sm font-mono text-red-300">{f.path}</span>
                            <span className="text-xs text-gray-500">HTTP {f.status_code}</span>
                            {f.content_type && <span className="text-xs text-gray-500">{f.content_type.split(';')[0]}</span>}
                            {f.content_length && <span className="text-xs text-gray-500">{(f.content_length / 1024).toFixed(1)}KB</span>}
                          </div>
                          <p className="text-xs text-gray-400 mt-1">Category: {categoryLabels[f.category] || f.category}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {accessibleFindings.length === 0 && fb.paths_tested > 0 && (
                  <div className="mb-3 bg-green-900/20 border border-green-500/30 rounded-lg p-3">
                    <p className="text-sm text-green-400">No accessible sensitive paths found</p>
                  </div>
                )}

                {/* Protected endpoints (401/403) */}
                {protectedFindings.length > 0 && (
                  <div className="mb-3">
                    <p className="text-xs font-semibold text-blue-400 uppercase tracking-wider mb-2">Protected (Auth Required) - {protectedFindings.length}</p>
                    <div className="space-y-1">
                      {protectedFindings.map((f: any, i: number) => (
                        <div key={i} className="flex items-center gap-2 text-sm">
                          <span className="text-blue-400 font-mono">{f.path}</span>
                          <span className="text-xs text-gray-500">HTTP {f.status_code}</span>
                          <span className="text-xs text-gray-600">{categoryLabels[f.category] || f.category}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Collapsed: all tested paths grouped by category */}
                {(fpFindings.length > 0 || otherFindings.length > 0) && (
                  <div className="mt-3 border-t border-gray-700/50 pt-3">
                    <button
                      type="button"
                      onClick={() => setFbShowAllFindings(!fbShowAllFindings)}
                      aria-expanded={fbShowAllFindings}
                      className="flex items-center gap-2 rounded text-xs text-gray-500 hover:text-gray-300 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                    >
                      <svg className={`w-3 h-3 transition-transform ${fbShowAllFindings ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                      </svg>
                      {fbShowAllFindings ? 'Hide' : 'Show'} all tested paths ({fpFindings.length + otherFindings.length} not accessible)
                    </button>
                    {fbShowAllFindings && (
                      <div className="mt-3 space-y-2">
                        {Object.entries(fpByCategory).sort(([,a], [,b]) => b.length - a.length).map(([cat, items]) => (
                          <div key={cat} className="bg-gray-800/50 rounded-lg overflow-hidden">
                            <button
                              type="button"
                              onClick={() => {
                                setFbExpandedCategories(prev => {
                                  const next = new Set(prev)
                                  next.has(cat) ? next.delete(cat) : next.add(cat)
                                  return next
                                })
                              }}
                              aria-expanded={fbExpandedCategories.has(cat)}
                              className="w-full flex items-center justify-between px-3 py-2 text-xs hover:bg-gray-700/30 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                            >
                              <span className="text-gray-400 font-medium">{categoryLabels[cat] || cat}</span>
                              <span className="flex items-center gap-2">
                                <span className="text-gray-500">{items.length} paths</span>
                                <svg className={`w-3 h-3 text-gray-500 transition-transform ${fbExpandedCategories.has(cat) ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                </svg>
                              </span>
                            </button>
                            {fbExpandedCategories.has(cat) && (
                              <div className="px-3 pb-2 space-y-1">
                                {items.map((f: any, i: number) => (
                                  <div key={i} className="flex items-center gap-2 text-xs">
                                    <span className="font-mono text-gray-500">{f.path}</span>
                                    <span className="text-gray-600">HTTP {f.status_code}</span>
                                    {f.false_positive_detected && <span className="text-gray-600 italic">FP filtered</span>}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* BOLA/IDOR Testing */}
            {bola && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-2">BOLA/IDOR Testing</h3>
                {bola.endpoints_tested !== undefined && (
                  <div className="flex items-center gap-4 mb-2">
                    <span className="text-sm text-gray-400">Endpoints tested: <span className="text-white font-medium">{bola.endpoints_tested}</span></span>
                    {bola.access_violations > 0 && (
                      <span className="text-xs px-2 py-0.5 rounded-full border bg-red-500/20 text-red-400 border-red-500/40">{bola.access_violations} violations</span>
                    )}
                  </div>
                )}
                {bolaClean && (
                  <div className="bg-green-900/20 border border-green-500/30 rounded-lg p-3">
                    <p className="text-sm text-green-400">No BOLA/IDOR vulnerabilities detected</p>
                  </div>
                )}
                {bolaHasFindings && (
                  <div className="mt-2">
                    <p className="text-xs font-semibold text-red-400 uppercase tracking-wider mb-2">Findings</p>
                    {bolaFindings.map((f: any) => (
                      <div key={f.key} className="bg-red-900/20 border border-red-500/30 rounded-lg p-3 mb-2">
                        <div className="flex items-center gap-2 flex-wrap">
                          {f.severity && (
                            <span className={`text-xs px-2 py-0.5 rounded-full border ${sevColors[f.severity] || sevColors.info}`}>{f.severity}</span>
                          )}
                          {f.endpoint && <span className="text-sm text-red-300 font-mono">{f.endpoint}</span>}
                          {!f.endpoint && f.title && <span className="text-sm text-red-300">{f.title}</span>}
                        </div>
                        {f.endpoint && f.title && (
                          <p className="text-xs text-gray-400 mt-1">{f.title}</p>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
        )
      })()}

      {/* Cloud & Infrastructure Exposure */}
      {(cloud_buckets.findings?.length > 0 || cloud_ssrf.vulnerable || kubernetes_exposure.findings?.length > 0 || container_registry.exposed || cicd_exposure.findings?.length > 0) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Cloud & Infrastructure Exposure</h2>
          <div className="space-y-4">
            {cloud_buckets.findings?.length > 0 && (
              <div className="bg-red-900/20 border border-red-500/40 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-red-400 mb-2">Cloud Storage Buckets</h3>
                <div className="space-y-2">
                  {cloud_buckets.findings.map((bucket: any, i: number) => (
                    <div key={i} className="text-sm">
                      <span className="text-red-300">{bucket.url || bucket.bucket}</span>
                      {bucket.permissions && <span className="text-gray-400 ml-2">({bucket.permissions})</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {cloud_ssrf.vulnerable && (
              <div className="bg-red-900/20 border border-red-500/40 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-red-400 mb-2">Cloud SSRF</h3>
                <p className="text-red-300 text-sm">SSRF to cloud metadata endpoint detected</p>
                {cloud_ssrf.endpoint && <p className="text-gray-400 text-xs mt-1 font-mono">{cloud_ssrf.endpoint}</p>}
              </div>
            )}
            {kubernetes_exposure.findings?.length > 0 && (
              <div className="bg-red-900/20 border border-red-500/40 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-red-400 mb-2">Kubernetes Exposure</h3>
                <div className="space-y-2">
                  {kubernetes_exposure.findings.map((k8s: any, i: number) => (
                    <div key={i} className="text-sm text-red-300">{k8s.description || k8s.type || k8s}</div>
                  ))}
                </div>
              </div>
            )}
            {container_registry.exposed && (
              <div className="bg-orange-900/20 border border-orange-500/40 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-orange-400 mb-2">Container Registry</h3>
                <p className="text-orange-300 text-sm">Exposed container registry detected</p>
                {container_registry.url && <p className="text-gray-400 text-xs mt-1 font-mono">{container_registry.url}</p>}
              </div>
            )}
            {cicd_exposure.findings?.length > 0 && (
              <div className="bg-orange-900/20 border border-orange-500/40 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-orange-400 mb-2">CI/CD Exposure</h3>
                <div className="space-y-2">
                  {cicd_exposure.findings.map((ci: any, i: number) => (
                    <div key={i} className="text-sm text-orange-300">{ci.type || ci.description || ci}</div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Findings */}
      <details open={!isModelIntakeScan} className={isModelIntakeScan ? 'mb-8 rounded-lg border border-gray-700 bg-gray-800/50' : 'contents'}>
        <summary className={isModelIntakeScan ? 'cursor-pointer px-5 py-4 text-sm font-semibold text-gray-200' : 'hidden'}>
          Raw findings and remediation detail ({findings.length})
        </summary>
      {Array.isArray(findings) && findings.length > 0 && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <div className="mb-4">
            <h2 className="text-2xl font-bold">{rawOnlyFindings || partiallyPersistedFindings ? 'Findings reported by this scan' : 'Key Findings'}</h2>
            {(rawOnlyFindings || partiallyPersistedFindings) && (
              <p className="mt-2 text-sm text-amber-200">
                {rawOnlyFindings
                  ? 'These results came from scanner evidence but do not yet have saved finding records. They remain visible here; status and remediation actions become available after a record is linked.'
                  : `${rawFindingsWithoutRecords.length} of ${rawFindings.length} scan result(s) do not yet have saved finding records. Status and remediation actions are available only for linked findings.`}
              </p>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2 mb-4">
            <span className="text-gray-500 text-xs mr-2">Filter:</span>
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map(severity => {
              const count = findings.filter((f: any) => (f.severity?.toLowerCase() || 'info') === severity).length
              if (count === 0) return null
              const isActive = severityFilter.has(severity)
              return (
                <button key={severity} type="button" onClick={() => toggleSeverityFilter(severity)} aria-pressed={isActive} className={`px-2 py-1 rounded text-xs font-medium transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${isActive ? SEVERITY_BADGE_STYLES[severity] : 'bg-gray-700/50 text-gray-500 line-through'}`}>
                  {severity} ({count})
                </button>
              )
            })}
          </div>
          <p className="text-gray-400 text-sm mb-4">Showing {filteredFindings.length} of {findings.length} finding(s)</p>
          <div className="space-y-4">
            {filteredFindings.slice(0, 50).map((finding: any, idx: number) => {
              const persistedFinding = linkedPersistedFinding(finding, persistedFindingIndex)
              const findingId = String(persistedFinding?.id || finding.id || `finding-${idx}`)
              const remediation = remediationData.find(r => r.finding_id === findingId)
              const canTrackFinding = Boolean(persistedFinding)
              return (
                <div key={idx}>
                  <FindingCard finding={finding} />
                  {enableRemediationTracking && canTrackFinding && (
                    <div className="mt-2 ml-4 pl-4 border-l-2 border-gray-700">
                      <FindingActions
                        scanId={scan.id}
                        findingId={findingId}
                        currentStatus={remediation?.status || 'open'}
                        currentNotes={remediation?.notes || ''}
                        onStatusChange={(newStatus, notes) => {
                          setRemediationData(prev => {
                            const existing = prev.find(r => r.finding_id === findingId)
                            if (existing) return prev.map(r => r.finding_id === findingId ? { ...r, status: newStatus, notes } : r)
                            return [...prev, { finding_id: findingId, status: newStatus, notes }]
                          })
                        }}
                      />
                    </div>
                  )}
                  {enableRemediationTracking && !canTrackFinding && (rawOnlyFindings || partiallyPersistedFindings) && (
                    <p className="mt-2 ml-4 pl-4 border-l-2 border-gray-700 text-xs text-gray-500">
                      Remediation actions are unavailable because this raw finding is not linked to a persisted finding record.
                    </p>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}
      </details>

      {/* Client-Side Vulnerabilities */}
      {client_side_vulns.vulnerable && client_side_vulns.findings?.length > 0 && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Client-Side Vulnerabilities</h2>
          <p className="text-gray-400 mb-4">
            {client_side_vulns.files_scanned} JS files scanned
          </p>
          <div className="space-y-3">
            {client_side_vulns.findings.map((finding: any, i: number) => (
              <div key={i} className="bg-gray-900 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-yellow-400 font-medium">
                    {finding.type?.replace(/_/g, ' ')}
                  </span>
                  <span className={`text-xs px-2 py-1 rounded ${getSeverityPill(finding.severity)}`}>
                    {finding.severity}
                  </span>
                </div>
                <p className="text-gray-500 text-sm truncate">{finding.file}</p>
                {finding.evidence && (
                  <code className="text-xs text-gray-400 mt-2 block bg-gray-950 p-2 rounded overflow-x-auto">
                    {finding.evidence.substring(0, 100)}...
                  </code>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Authentication Security */}
      {(auth_checks.bruteforce_protection?.vulnerable || auth_checks.session_management?.issues?.length > 0) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Authentication Security</h2>

          {auth_checks.bruteforce_protection?.vulnerable && (
            <div className="mb-4">
              <h3 className="text-lg font-semibold text-orange-400 mb-2">
                Bruteforce Protection Issues
              </h3>
              {auth_checks.bruteforce_protection.issues?.length > 0 ? (
                auth_checks.bruteforce_protection.issues.map((issue: any, i: number) => (
                  <div key={i} className="bg-gray-900 rounded-lg p-3 mb-2">
                    <p className="text-gray-300">{issue.detail || issue.description || issue}</p>
                    {issue.endpoint && <p className="text-gray-500 text-sm">{issue.endpoint}</p>}
                  </div>
                ))
              ) : (
                <div className="bg-gray-900 rounded-lg p-3">
                  <p className="text-gray-300">Bruteforce protection weakness detected</p>
                  {auth_checks.bruteforce_protection.endpoint && (
                    <p className="text-gray-500 text-sm">{auth_checks.bruteforce_protection.endpoint}</p>
                  )}
                </div>
              )}
            </div>
          )}

          {auth_checks.session_management?.issues?.length > 0 && (
            <div>
              <h3 className="text-lg font-semibold text-orange-400 mb-2">
                Session Management Issues
              </h3>
              {auth_checks.session_management.issues.map((issue: any, i: number) => (
                <div key={i} className="bg-gray-900 rounded-lg p-3 mb-2">
                  <p className="text-gray-300">{issue.detail || issue.description || issue}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* WebSocket Security */}
      {websocket_security.endpoints?.length > 0 && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">WebSocket Security</h2>
          <p className="text-gray-400 mb-4">
            {websocket_security.endpoints_tested || websocket_security.endpoints?.length} endpoints tested
          </p>
          <div className="space-y-3">
            {websocket_security.endpoints.map((ep: any, i: number) => (
              <div key={i} className="bg-gray-900 rounded-lg p-4">
                <p className="text-blue-400 font-mono text-sm mb-2">{ep.url}</p>
                {ep.tests?.length > 0 && (
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                    {ep.tests.map((test: any, j: number) => (
                      <div key={j} className={`text-xs p-2 rounded ${
                        test.vulnerable ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                      }`}>
                        {test.name}: {test.vulnerable ? 'VULNERABLE' : 'OK'}
                      </div>
                    ))}
                  </div>
                )}
                {ep.vulnerable !== undefined && !ep.tests && (
                  <span className={`text-xs px-2 py-1 rounded ${
                    ep.vulnerable ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                  }`}>
                    {ep.vulnerable ? 'Vulnerabilities found' : 'No issues'}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Security Tests Summary */}
      {(api_security_web.endpoints_tested > 0 || business_logic.endpoints_tested > 0 ||
        file_upload.tested || host_header_injection.tested ||
        open_redirect.tested || directory_listing.tested) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Security Tests</h2>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
            {api_security_web.endpoints_tested > 0 && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-2">API Security</h3>
                <div className="flex items-center justify-between">
                  <span className="text-gray-300">{api_security_web.endpoints_tested} endpoints</span>
                  <span className={`text-xs px-2 py-1 rounded ${
                    api_security_web.vulnerabilities_found > 0 ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                  }`}>
                    {api_security_web.vulnerabilities_found || 0} issues
                  </span>
                </div>
              </div>
            )}
            {business_logic.endpoints_tested > 0 && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-2">Business Logic</h3>
                <div className="flex items-center justify-between">
                  <span className="text-gray-300">{business_logic.endpoints_tested} endpoints</span>
                  <span className={`text-xs px-2 py-1 rounded ${
                    business_logic.vulnerabilities_found > 0 ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                  }`}>
                    {business_logic.vulnerabilities_found || 0} issues
                  </span>
                </div>
              </div>
            )}
            {file_upload.tested && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-2">File Upload</h3>
                <span className={`text-xs px-2 py-1 rounded ${
                  file_upload.vulnerable ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                }`}>
                  {file_upload.vulnerable ? 'VULNERABLE' : 'OK'}
                </span>
              </div>
            )}
            {host_header_injection.tested && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-2">Host Header Injection</h3>
                <span className={`text-xs px-2 py-1 rounded ${
                  host_header_injection.vulnerable ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                }`}>
                  {host_header_injection.vulnerable ? 'VULNERABLE' : 'OK'}
                </span>
              </div>
            )}
            {open_redirect.tested && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-2">Open Redirect</h3>
                <span className={`text-xs px-2 py-1 rounded ${
                  open_redirect.vulnerable ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                }`}>
                  {open_redirect.vulnerable ? 'VULNERABLE' : 'OK'}
                </span>
              </div>
            )}
            {directory_listing.tested && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-2">Directory Listing</h3>
                <span className={`text-xs px-2 py-1 rounded ${
                  directory_listing.vulnerable ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                }`}>
                  {directory_listing.vulnerable ? 'VULNERABLE' : 'OK'}
                </span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Discovery */}
      {discovery.katana_sample?.length > 0 && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Discovery</h2>
          <div className="max-h-48 overflow-y-auto bg-gray-700/30 rounded p-3">
            {discovery.katana_sample.map((url: string, i: number) => (
              <div key={i} className="text-xs font-mono text-gray-300 py-1">{url}</div>
            ))}
          </div>
        </div>
      )}

      {/* Exposed Secrets */}
      {js_secrets.vulnerable && js_secrets.secrets_found?.length > 0 && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Exposed Secrets</h2>
          <div className="space-y-3">
            {js_secrets.secrets_found.map((secret: any, i: number) => (
              <div key={i} className="bg-gray-900 rounded-lg p-4 border-l-4 border-yellow-500">
                <span className="text-yellow-400 font-medium">{secret.type}</span>
                <p className="text-gray-500 text-xs mt-1">Found in: <code className="text-gray-400">{secret.file}</code></p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Historical coverage payload, rendered with canonical product language. */}
      {(smart_coverage.endpoints || smart_coverage.parameters || smart_coverage.nuclei_templates) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Scan Coverage</h2>

          {/* Coverage Progress Bars */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
            {/* Endpoint Coverage */}
            {smart_coverage.endpoints && (
              <div className="bg-gray-900 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-semibold text-gray-400">Endpoint Coverage</h3>
                  <span className="text-lg font-bold text-white">
                    {Math.round((smart_coverage.endpoints.coverage || 0) * 100)}%
                  </span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-2 mb-2">
                  <div
                    className="bg-blue-500 h-2 rounded-full transition-all"
                    style={{ width: `${Math.min((smart_coverage.endpoints.coverage || 0) * 100, 100)}%` }}
                  />
                </div>
                <p className="text-xs text-gray-500">
                  {smart_coverage.endpoints.tested || 0} tested / {smart_coverage.endpoints.discovered || 0} discovered
                </p>
              </div>
            )}

            {/* Parameter Coverage */}
            {smart_coverage.parameters && (
              <div className="bg-gray-900 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-semibold text-gray-400">Parameter Testing</h3>
                  <span className="text-lg font-bold text-white">
                    {(smart_coverage.parameters.discovered || 0) > 0
                      ? `${Math.round((smart_coverage.parameters.coverage || 0) * 100)}%`
                      : '—'}
                  </span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-2 mb-2">
                  <div
                    className="bg-green-500 h-2 rounded-full transition-all"
                    style={{ width: `${Math.min((smart_coverage.parameters.coverage || 0) * 100, 100)}%` }}
                  />
                </div>
                <p className="text-xs text-gray-500">
                  {(smart_coverage.parameters.discovered || 0) > 0
                    ? `${smart_coverage.parameters.tested || 0} probe attempts across ${smart_coverage.parameters.discovered} discovered parameters`
                    : `${smart_coverage.parameters.tested || 0} active parameter probes · no parameters inventoried`}
                </p>
              </div>
            )}

            {/* Nuclei Template Hit Rate */}
            {smart_coverage.nuclei_templates && (
              <div className="bg-gray-900 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-semibold text-gray-400">Template Hit Rate</h3>
                  <span className="text-lg font-bold text-white">
                    {Math.round((nucleiTemplates.hit_rate || 0) * 100)}%
                  </span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-2 mb-2">
                  <div
                    className={`h-2 rounded-full transition-all ${
                      (nucleiTemplates.hit_rate || 0) > 0.1 ? 'bg-red-500' :
                      (nucleiTemplates.hit_rate || 0) > 0.05 ? 'bg-yellow-500' : 'bg-green-500'
                    }`}
                    style={{ width: `${Math.min((nucleiTemplates.hit_rate || 0) * 100, 100)}%` }}
                  />
                </div>
                <p className="flex items-center gap-2 text-xs text-gray-500">
                  <span>
                    {nucleiTemplates.matched || 0} matched / {nucleiRunApproximate ? '~' : ''}{nucleiTemplates.run || 0} run
                  </span>
                  {nucleiRunApproximate && (
                    <span className="rounded bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-amber-300">
                      estimated
                    </span>
                  )}
                </p>
              </div>
            )}
          </div>

          {/* Breakdown by Method and Location */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            {/* Endpoints by Method */}
            {smart_coverage.endpoints?.by_method && Object.keys(smart_coverage.endpoints.by_method).length > 0 && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-3">Endpoints by Method</h3>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(smart_coverage.endpoints.by_method).map(([method, count]: [string, any]) => (
                    <span
                      key={method}
                      className={`px-2 py-1 text-xs font-mono rounded ${
                        method === 'GET' ? 'bg-green-900/50 text-green-300' :
                        method === 'POST' ? 'bg-blue-900/50 text-blue-300' :
                        method === 'PUT' ? 'bg-yellow-900/50 text-yellow-300' :
                        method === 'DELETE' ? 'bg-red-900/50 text-red-300' :
                        method === 'PATCH' ? 'bg-purple-900/50 text-purple-300' :
                        'bg-gray-700 text-gray-300'
                      }`}
                    >
                      {method}: {count}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Parameters by Location */}
            {smart_coverage.parameters?.by_location && Object.keys(smart_coverage.parameters.by_location).length > 0 && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-3">Parameters by Location</h3>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(smart_coverage.parameters.by_location).map(([location, count]: [string, any]) => (
                    <span
                      key={location}
                      className={`px-2 py-1 text-xs font-mono rounded ${
                        location === 'query' ? 'bg-blue-900/50 text-blue-300' :
                        location === 'body' ? 'bg-purple-900/50 text-purple-300' :
                        location === 'path' ? 'bg-green-900/50 text-green-300' :
                        location === 'header' ? 'bg-yellow-900/50 text-yellow-300' :
                        'bg-gray-700 text-gray-300'
                      }`}
                    >
                      {location}: {count}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Nuclei Categories */}
          {smart_coverage.nuclei_templates?.by_category && Object.keys(smart_coverage.nuclei_templates.by_category).length > 0 && (
            <div className="mb-6">
              <h3 className="text-sm font-semibold text-gray-400 mb-3">Templates by Category</h3>
              <div className="flex flex-wrap gap-2">
                {Object.entries(smart_coverage.nuclei_templates.by_category)
                  .sort(([, a]: [string, any], [, b]: [string, any]) => b - a)
                  .slice(0, 12)
                  .map(([category, count]: [string, any]) => (
                    <span key={category} className="px-2 py-1 bg-gray-900 text-gray-300 text-xs rounded">
                      {category}: {count}
                    </span>
                  ))}
                {Object.keys(smart_coverage.nuclei_templates.by_category).length > 12 && (
                  <span className="px-2 py-1 text-gray-500 text-xs">
                    +{Object.keys(smart_coverage.nuclei_templates.by_category).length - 12} more
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Auth States and Discovery Sources */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Auth States Tested */}
            {smart_coverage.auth_states_tested?.length > 0 && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-2">Auth States Tested</h3>
                <div className="flex flex-wrap gap-2">
                  {smart_coverage.auth_states_tested.map((state: string, i: number) => (
                    <span key={i} className="px-2 py-1 bg-yellow-900/30 text-yellow-400 rounded text-xs">
                      {state}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Discovery Sources */}
            {smart_coverage.discovery_sources?.length > 0 && (
              <div className="bg-gray-900 rounded-lg p-4">
                <h3 className="text-sm font-semibold text-gray-400 mb-2">Discovery Sources</h3>
                <div className="flex flex-wrap gap-2">
                  {smart_coverage.discovery_sources.map((source: string, i: number) => (
                    <span key={i} className="px-2 py-1 bg-blue-900/30 text-blue-400 rounded text-xs">
                      {source}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Attack Chains Analysis */}
      {attack_chains && !isAIScan && !isModelIntakeScan && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-4">
            <h2 className="text-2xl font-bold">Attack Chain Analysis</h2>
            <div className="flex flex-wrap items-center gap-3">
              <label className="text-sm text-gray-400">Min confidence</label>
              <select
                className="bg-gray-900 text-gray-200 text-sm rounded px-2 py-1 border border-gray-700"
                value={minChainConfidence}
                onChange={(e) => setMinChainConfidence(parseFloat(e.target.value))}
              >
                <option value={0}>All</option>
                <option value={0.3}>30%+</option>
                <option value={0.5}>50%+</option>
                <option value={0.7}>70%+</option>
                <option value={0.9}>90%+</option>
              </select>
              <label className="flex items-center gap-2 text-sm text-gray-400">
                <input
                  type="checkbox"
                  className="rounded bg-gray-900 border-gray-700"
                  checked={showPartialChains}
                  onChange={(e) => setShowPartialChains(e.target.checked)}
                />
                Show partial chains
              </label>
            </div>
          </div>

          {attackChainsError && (
            <div className="bg-red-900/20 border border-red-500/40 rounded-lg p-3 mb-4 text-red-300 text-sm">
              Attack chain analysis error: {attackChainsError}
            </div>
          )}

          {/* Summary Stats */}
          {attack_chains.summary && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              <div className="bg-gray-900 rounded-lg p-3">
                <h3 className="text-sm text-gray-400">Total Chains</h3>
                <p className="text-2xl font-bold text-white">{attack_chains.summary.total_chains}</p>
              </div>
              <div className="bg-gray-900 rounded-lg p-3">
                <h3 className="text-sm text-gray-400">Critical</h3>
                <p className="text-2xl font-bold text-red-400">{attack_chains.summary.critical_chains}</p>
              </div>
              <div className="bg-gray-900 rounded-lg p-3">
                <h3 className="text-sm text-gray-400">High</h3>
                <p className="text-2xl font-bold text-orange-400">{attack_chains.summary.high_chains}</p>
              </div>
              <div className="bg-gray-900 rounded-lg p-3">
                <h3 className="text-sm text-gray-400">Partial</h3>
                <p className="text-2xl font-bold text-yellow-400">{attack_chains.summary.total_partial_chains}</p>
              </div>
            </div>
          )}

          {/* Complete Chains */}
          {filteredChains.length > 0 && (
            <div className="mb-6">
              <h3 className="text-lg font-semibold text-gray-300 mb-3">Exploitable Attack Chains</h3>
              <div className="space-y-4">
                {filteredChains.map((chain: any, idx: number) => {
                  const matchedRequiredAny = chain.matched_required_any || []
                  const matchedRequiredAll = chain.matched_required_all || []
                  const matchedRequiredLegacy = (!matchedRequiredAny.length && !matchedRequiredAll.length)
                    ? (chain.matched_vulnerabilities?.required || chain.required_findings || [])
                    : []
                  const matchedSupporting = chain.matched_optional || chain.matched_vulnerabilities?.supporting || chain.optional_findings || []
                  const missingRequiredAny = chain.missing_required_any || []
                  const missingRequiredAll = chain.missing_required_all || []
                  const missingRequiredLegacy = (!missingRequiredAny.length && !missingRequiredAll.length)
                    ? (chain.missing_required || [])
                    : []
                  const evidenceFindings = chain.evidence?.supporting_findings || []

                  return (
                    <div key={idx} className={`bg-gray-900 rounded-lg p-4 border-l-4 ${getSeverityBorderClass(chain.severity)}`}>
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="font-semibold text-white">{chain.chain_type?.replace(/_/g, ' ').toUpperCase()}</h4>
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-1 rounded text-xs font-bold ${getSeverityPill(chain.severity)}`}>{chain.severity?.toUpperCase()}</span>
                          <span className="px-2 py-1 rounded text-xs bg-gray-800 text-gray-300">
                            Confidence {Math.round(getChainConfidence(chain) * 100)}%
                          </span>
                        </div>
                      </div>
                      <p className="text-gray-400 text-sm mb-3">{chain.business_impact}</p>
                      {chain.steps?.length > 0 && (
                        <div className="space-y-2">
                          {chain.steps.map((step: any, stepIdx: number) => (
                            <div key={stepIdx} className="flex items-start gap-3 text-sm">
                              <span className="w-6 h-6 rounded-full bg-gray-700 flex items-center justify-center text-xs font-bold">{step.step_number}</span>
                              <div>
                                <span className="text-gray-300">{step.description}</span>
                                <span className="text-gray-500 ml-2">({step.finding_type})</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                      <p className="text-gray-500 text-xs mt-3">Completeness: {Math.round((chain.completeness || 0) * 100)}%</p>
                      {(matchedRequiredAny.length > 0 || matchedRequiredAll.length > 0 || matchedSupporting.length > 0 || evidenceFindings.length > 0 || missingRequiredAny.length > 0 || missingRequiredAll.length > 0 || missingRequiredLegacy.length > 0) && (
                        <details className="mt-3">
                          <summary className="cursor-pointer text-sm text-blue-400">Why this chain?</summary>
                          <div className="mt-2 space-y-2 text-sm text-gray-400">
                            {matchedRequiredAny.length > 0 && (
                              <div>Matched required (one-of): {matchedRequiredAny.join(', ')}</div>
                            )}
                            {matchedRequiredAll.length > 0 && (
                              <div>Matched required (all-of): {matchedRequiredAll.join(', ')}</div>
                            )}
                            {matchedRequiredLegacy.length > 0 && (
                              <div>Matched required: {matchedRequiredLegacy.join(', ')}</div>
                            )}
                            {matchedSupporting.length > 0 && (
                              <div>Matched supporting: {matchedSupporting.join(', ')}</div>
                            )}
                            {missingRequiredAny.length > 0 && (
                              <div className="text-yellow-400">Missing one-of: {missingRequiredAny.join(', ')}</div>
                            )}
                            {missingRequiredAll.length > 0 && (
                              <div className="text-yellow-400">Missing required: {missingRequiredAll.join(', ')}</div>
                            )}
                            {missingRequiredLegacy.length > 0 && (
                              <div className="text-yellow-400">Missing required: {missingRequiredLegacy.join(', ')}</div>
                            )}
                            {chain.missing_optional?.length > 0 && (
                              <div className="text-gray-500">Missing optional: {chain.missing_optional.join(', ')}</div>
                            )}
                            {evidenceFindings.length > 0 && (
                              <div>
                                <div className="text-gray-500">Supporting findings</div>
                                <div className="space-y-1 mt-1">
                                  {evidenceFindings.slice(0, 5).map((finding: any, i: number) => (
                                    <div key={i} className="flex items-center justify-between">
                                      {finding.id ? (
                                        <a href={`/findings/${finding.id}`} className="text-blue-400 hover:text-blue-300">
                                          {finding.title || finding.id}
                                        </a>
                                      ) : (
                                        <span className="text-gray-300">{finding.title || 'Finding'}</span>
                                      )}
                                      <span className="text-xs text-gray-500">{finding.severity || 'info'}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        </details>
                      )}
                      {chain.remediation && (
                        <div className="mt-3 pt-3 border-t border-gray-700">
                          <p className="text-green-400 text-sm"><span className="font-semibold">Remediation:</span> {chain.remediation}</p>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {filteredChains.length === 0 && attack_chains.chains?.length > 0 && (
            <p className="text-gray-500 text-sm mb-4">No complete chains match the current confidence filter.</p>
          )}

          {/* Partial Chains */}
          {showPartialChains && (
            <div>
              <h3 className="text-lg font-semibold text-gray-300 mb-3">Partial Attack Chains</h3>
              <p className="text-gray-500 text-sm mb-3">Missing components but indicate potential risk</p>
              {filteredPartialChains.length > 0 ? (
                <div className="space-y-3">
                  {filteredPartialChains.map((chain: any, idx: number) => {
                    const matchedRequiredAny = chain.matched_required_any || []
                    const matchedRequiredAll = chain.matched_required_all || []
                    const matchedRequiredLegacy = (!matchedRequiredAny.length && !matchedRequiredAll.length)
                      ? (chain.matched_vulnerabilities?.required || chain.required_findings || [])
                      : []
                    const matchedSupporting = chain.matched_optional || chain.matched_vulnerabilities?.supporting || chain.optional_findings || []
                    const missingRequiredAny = chain.missing_required_any || []
                    const missingRequiredAll = chain.missing_required_all || []
                    const missingRequiredLegacy = (!missingRequiredAny.length && !missingRequiredAll.length)
                      ? (chain.missing_required || [])
                      : []
                    const evidenceFindings = chain.evidence?.supporting_findings || []

                    return (
                      <div key={idx} className="bg-gray-900/50 rounded-lg p-3 border border-gray-700">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-gray-300 font-medium">{chain.name || chain.chain_type?.replace(/_/g, ' ')}</span>
                          <span className={`text-xs px-2 py-1 rounded ${getSeverityPill(chain.severity)}`}>
                            {chain.severity} ({Math.round(getChainConfidence(chain) * 100)}% conf)
                          </span>
                        </div>
                        {chain.description && (
                          <p className="text-gray-400 text-sm mb-2">{chain.description}</p>
                        )}
                        <p className="text-gray-500 text-xs mb-2">Completeness: {Math.round((chain.completeness || 0) * 100)}%</p>
                        {(matchedRequiredAny.length > 0 || matchedRequiredAll.length > 0 || matchedSupporting.length > 0 || evidenceFindings.length > 0 || missingRequiredAny.length > 0 || missingRequiredAll.length > 0 || missingRequiredLegacy.length > 0) && (
                          <details className="mt-2">
                            <summary className="cursor-pointer text-sm text-blue-400">Why this chain?</summary>
                            <div className="mt-2 space-y-2 text-sm text-gray-400">
                              {matchedRequiredAny.length > 0 && (
                                <div>Matched required (one-of): {matchedRequiredAny.join(', ')}</div>
                              )}
                              {matchedRequiredAll.length > 0 && (
                                <div>Matched required (all-of): {matchedRequiredAll.join(', ')}</div>
                              )}
                              {matchedRequiredLegacy.length > 0 && (
                                <div>Matched required: {matchedRequiredLegacy.join(', ')}</div>
                              )}
                              {matchedSupporting.length > 0 && (
                                <div>Matched supporting: {matchedSupporting.join(', ')}</div>
                              )}
                              {missingRequiredAny.length > 0 && (
                                <div className="text-yellow-400">Missing one-of: {missingRequiredAny.join(', ')}</div>
                              )}
                              {missingRequiredAll.length > 0 && (
                                <div className="text-yellow-400">Missing required: {missingRequiredAll.join(', ')}</div>
                              )}
                              {missingRequiredLegacy.length > 0 && (
                                <div className="text-yellow-400">Missing required: {missingRequiredLegacy.join(', ')}</div>
                              )}
                              {chain.missing_optional?.length > 0 && (
                                <div className="text-gray-500">Missing optional: {chain.missing_optional.join(', ')}</div>
                              )}
                              {evidenceFindings.length > 0 && (
                                <div>
                                  <div className="text-gray-500">Supporting findings</div>
                                  <div className="space-y-1 mt-1">
                                    {evidenceFindings.slice(0, 5).map((finding: any, i: number) => (
                                      <div key={i} className="flex items-center justify-between">
                                        {finding.id ? (
                                          <a href={`/findings/${finding.id}`} className="text-blue-400 hover:text-blue-300">
                                            {finding.title || finding.id}
                                          </a>
                                        ) : (
                                          <span className="text-gray-300">{finding.title || 'Finding'}</span>
                                        )}
                                        <span className="text-xs text-gray-500">{finding.severity || 'info'}</span>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>
                          </details>
                        )}
                      </div>
                    )
                  })}
                </div>
              ) : (
                attack_chains.partial_chains?.length > 0 && (
                  <p className="text-gray-500 text-sm">No partial chains match the current confidence filter.</p>
                )
              )}
            </div>
          )}

          {attack_chains.chains?.length === 0 && attack_chains.partial_chains?.length === 0 && !attackChainsError && (
            <p className="text-gray-500 text-sm">No attack chains identified for this scan.</p>
          )}
        </div>
      )}

      {!attack_chains && findings.length > 0 && !isAIScan && !isModelIntakeScan && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-2">Attack Chain Analysis</h2>
          <p className="text-gray-400 text-sm">
            Attack chain analysis unavailable for this scan. The scanner may not have included chain analysis or an error prevented it from running.
          </p>
        </div>
      )}

      {/* Scan Metadata & Coverage */}
      {(scan_metadata.completed_at || scan_metadata.scanner_version || scan_metadata.schema_version || coverage.modules_completed || Object.keys(scan_metadata).length > 2) && (
        <div className="bg-gray-800/50 backdrop-blur-lg rounded-lg p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Scan Metadata</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {scan_metadata.scanner_version && (
              <div className="bg-gray-900 rounded-lg p-3">
                <h3 className="text-sm text-gray-400 mb-1">Scanner Version</h3>
                <p className="text-white font-mono text-sm">{scan_metadata.scanner_version}</p>
              </div>
            )}
            {scan_metadata.schema_version && (
              <div className="bg-gray-900 rounded-lg p-3">
                <h3 className="text-sm text-gray-400 mb-1">Schema Version</h3>
                <p className="text-white font-mono text-sm">{scan_metadata.schema_version}</p>
              </div>
            )}
            {scan_metadata.completed_at && (
              <div className="bg-gray-900 rounded-lg p-3">
                <h3 className="text-sm text-gray-400 mb-1">Completed At</h3>
                <p className="text-white text-sm">{new Date(scan_metadata.completed_at).toLocaleString()}</p>
              </div>
            )}
            {scan_metadata.duration_seconds !== undefined && (
              <div className="bg-gray-900 rounded-lg p-3">
                <h3 className="text-sm text-gray-400 mb-1">Duration</h3>
                <p className="text-white text-sm">
                  {scan_metadata.duration_seconds < 60
                    ? `${scan_metadata.duration_seconds}s`
                    : scan_metadata.duration_seconds < 3600
                    ? `${Math.floor(scan_metadata.duration_seconds / 60)}m ${scan_metadata.duration_seconds % 60}s`
                    : `${Math.floor(scan_metadata.duration_seconds / 3600)}h ${Math.floor((scan_metadata.duration_seconds % 3600) / 60)}m`}
                </p>
              </div>
            )}
            {coverage.coverage_percentage !== undefined && (
              <div className="bg-gray-900 rounded-lg p-3">
                <h3 className="text-sm text-gray-400 mb-1">Coverage</h3>
                <p className="text-white text-lg font-bold">{coverage.coverage_percentage}%</p>
              </div>
            )}
          </div>
          {coverage.modules_completed?.length > 0 && (
            <div className="mt-4">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Modules Completed</h3>
              <div className="flex flex-wrap gap-2">
                {coverage.modules_completed.map((mod: string, i: number) => (
                  <span key={i} className="px-2 py-1 bg-green-900/30 text-green-400 rounded text-xs">{mod}</span>
                ))}
              </div>
            </div>
          )}
          {scan_metadata.checks_skipped?.length > 0 && (
            <div className="mt-4">
              <h3 className="text-sm font-semibold text-gray-400 mb-2">Checks Skipped</h3>
              <div className="space-y-1">
                {scan_metadata.checks_skipped.map((skip: any, i: number) => (
                  <div key={i} className="text-sm text-gray-500">
                    <span className="text-gray-400">{typeof skip === 'string' ? skip : skip.name || skip.check || skip.module}</span>
                    {skip.reason && <span className="ml-2 text-gray-600">({skip.reason})</span>}
                  </div>
                ))}
              </div>
            </div>
          )}
          {scan_metadata.options && Object.keys(scan_metadata.options).length > 0 && (
            <details className="mt-4 rounded-lg border border-gray-800 bg-gray-950/40">
              <summary className="cursor-pointer px-3 py-2 text-sm font-medium text-gray-500 hover:text-gray-300">
                Developer diagnostics: resolved scan configuration
              </summary>
              <div className="border-t border-gray-800 p-3">
                <p className="mb-2 text-xs text-gray-600">
                  Internal execution details for troubleshooting. These do not change the result shown above.
                </p>
                <pre className="max-h-96 overflow-auto text-xs text-gray-500">{JSON.stringify(scan_metadata.options, null, 2)}</pre>
              </div>
            </details>
          )}
        </div>
      )}
    </div>
  )
}
