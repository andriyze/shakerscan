'use client'

import { useEffect, useState, Suspense, useRef } from 'react'
import { useParams, useSearchParams } from 'next/navigation'
import Link from 'next/link'
import { API_URL, getScan, getScanLogs, getDeviceScanActivity, getHealth, getFindings, getScanDeploymentDecision, replayAiScan, getAiScanCampaignHistory, formatDuration, formatDate, type AiScanCampaignHistory, type DeploymentDecision, type Finding } from '@/lib/api'
import { SEVERITY_BADGE_STYLES, SEVERITY_LEVELS, type SeverityLevel } from '@/lib/constants'
import { Card, ErrorState, PageHeader, gradeTextColor } from '@/components/ui'
import ReportView from '@/components/ReportView'
import { buildAiGateCampaignReview, type AiGateCampaignReview } from '@/lib/aiGateCampaign'
import { deviceActivityLogLines, deviceScorePresentation } from '@/lib/deviceScanPresentation.mjs'
import { normalizeParentCoverage } from '@/lib/deferredWorkContracts'
import { boundedDisplayText } from '@/lib/targetChoices'

function formatScanTypeLabel(scan: any): string {
  if (scan?.scan_type === 'ai_gate' || scan?.run_kind?.startsWith('ai_')) {
    return 'AI Gate'
  }
  if (scan?.scan_type === 'scan' || scan?.run_kind === 'web_dast') {
    return 'DAST'
  }
  return String(scan?.scan_type || '')
    .split('_')
    .filter(Boolean)
    .map((part: string) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ')
}

function countSeverities(scan: any): Record<SeverityLevel, number> {
  const counts: Record<SeverityLevel, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  const findings = Array.isArray(scan?.result?.findings)
    ? scan.result.findings
    : Array.isArray(scan?.findings)
      ? scan.findings
      : []
  for (const finding of findings) {
    const severity = String(finding?.severity || 'info').toLowerCase()
    const key = (SEVERITY_LEVELS as readonly string[]).includes(severity)
      ? (severity as SeverityLevel)
      : 'info'
    counts[key] += 1
  }
  return counts
}

function formatPct(value: any): string {
  const n = typeof value === 'number' ? value : Number(value)
  if (!Number.isFinite(n)) return '0%'
  return `${Math.round(Math.max(0, Math.min(1, n)) * 100)}%`
}

function coverageNumber(value: any): number {
  const n = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(n) ? n : 0
}

function formatShardFamily(value: any): string {
  const raw = String(value || 'all').toLowerCase()
  if (!raw || raw === 'all') return 'All families'
  if (raw === 'sqli') return 'SQLi'
  if (raw === 'xss') return 'XSS'
  return raw.replace(/_/g, ' ').toUpperCase()
}

function formatAttemptStatuses(statuses: any): string | null {
  if (!statuses || typeof statuses !== 'object') return null
  const entries = Object.entries(statuses)
    .map(([status, value]) => [status, Number(value)] as const)
    .filter(([, value]) => Number.isFinite(value) && value > 0)
  if (!entries.length) return null
  return entries
    .map(([status, value]) => `${value} ${status.replace(/_/g, ' ')}`)
    .join(' · ')
}

function formatRollupKeys(values: any, formatter: (value: string) => string = (value) => value): string {
  if (!values || typeof values !== 'object') return 'None'
  const keys = Object.keys(values).filter(Boolean)
  if (!keys.length) return 'None'
  const visible = keys.slice(0, 3).map(formatter).join(', ')
  return keys.length > 3 ? `${visible} +${keys.length - 3}` : visible
}

function CoverageMetric({ label, value, accent = 'text-white' }: { label: string; value: any; accent?: string }) {
  return (
    <div className="rounded border border-gray-800 bg-gray-950/50 p-3">
      <div className={`text-lg font-semibold ${accent}`}>{value}</div>
      <div className="mt-0.5 text-xs text-gray-500">{label}</div>
    </div>
  )
}

function ScanVerdictCard({ scan, buildVersion, buildFingerprint }: { scan: any; buildVersion?: string | null; buildFingerprint?: string | null }) {
  const severityCounts = countSeverities(scan)
  const severityEntries = SEVERITY_LEVELS
    .map((severity) => [severity, severityCounts[severity]] as const)
    .filter(([, count]) => count > 0)
  const totalCounted = severityEntries.reduce((sum, [, count]) => sum + count, 0)
  const scorePresentation = deviceScorePresentation(scan)
  const hasGrade = Boolean(scorePresentation.grade)
  const hasScore = typeof scorePresentation.score === 'number'
  const scanTypeLabel = formatScanTypeLabel(scan)
  const duration = scan.duration_seconds ? formatDuration(scan.duration_seconds) : null
  const scanVersion: string | null = scan?.result?.scanner_version || null
  const scanFingerprint: string | null =
    scan?.result?.build_fingerprint || scan?.result?.scan_metadata?.build_fingerprint || null
  // Red when the scan ran on a different build than the API currently serves
  // (stale image/worker). Prefer the source-tree fingerprint — it catches stale
  // 'dev' images that the version label can't — and fall back to the label.
  const versionMismatch = Boolean(
    (scanFingerprint && buildFingerprint && scanFingerprint !== buildFingerprint) ||
    (!scanFingerprint && scanVersion && buildVersion && scanVersion !== buildVersion)
  )

  return (
    <Card className="p-6 mb-6">
      <div className="flex flex-wrap items-center gap-x-8 gap-y-4">
        {(hasGrade || hasScore || scorePresentation.status === 'unavailable') && (
          <div>
            {scorePresentation.status === 'provisional' && (
              <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-amber-300">
                Provisional posture
              </p>
            )}
            {scorePresentation.status === 'unavailable' ? (
              <p className="text-sm font-medium text-amber-200">Posture score unavailable</p>
            ) : (
              <div className="flex items-baseline gap-3">
                {hasGrade && (
                  <span className={`text-5xl font-bold ${gradeTextColor(scorePresentation.grade)}`}>
                    {scorePresentation.grade}
                  </span>
                )}
                {hasScore && (
                  <span className="text-lg text-gray-400">{scorePresentation.score}/100</span>
                )}
              </div>
            )}
            {scorePresentation.note && (
              <p className="mt-1 max-w-md text-xs text-amber-200/80">{scorePresentation.note}</p>
            )}
          </div>
        )}
        {severityEntries.length > 0 ? (
          <div className="flex flex-wrap items-center gap-2">
            {severityEntries.map(([severity, count]) => (
              <Link
                key={severity}
                href={`/findings?scan_id=${scan.id}&severity=${severity}`}
                title={`View ${count} ${severity} finding${count === 1 ? '' : 's'} for this scan`}
                className={`inline-flex items-center gap-1.5 px-2 py-0.5 text-xs font-medium rounded uppercase cursor-pointer transition hover:opacity-90 hover:ring-1 hover:ring-white/25 ${SEVERITY_BADGE_STYLES[severity]}`}
              >
                {count} {severity}
              </Link>
            ))}
          </div>
        ) : totalCounted === 0 && (scan.findings_count || 0) === 0 ? (
          <span className="text-sm text-gray-500">No findings</span>
        ) : null}
        <div className="ml-auto text-right">
          {scanTypeLabel && (
            <p className="text-sm text-gray-300">{scanTypeLabel} scan</p>
          )}
          {duration && (
            <p className="text-xs text-gray-500 mt-0.5">Completed in {duration}</p>
          )}
          {scanVersion && (
            <p
              className={`text-xs mt-0.5 font-mono ${versionMismatch ? 'text-red-400 font-semibold' : 'text-gray-500'}`}
              title={
                versionMismatch
                  ? `This scan ran on build ${scanVersion}, but the current build is ${buildVersion}. Re-scan on the current build for up-to-date detection.`
                  : `Scanner build ${scanVersion}`
              }
            >
              {versionMismatch ? '⚠ ' : ''}scanner {scanVersion}
              {versionMismatch
                ? (scanVersion === buildVersion && scanFingerprint && buildFingerprint
                    // Same git label but different source fingerprint: show the
                    // fingerprints, else the UI prints a confusing "X ≠ X".
                    ? ` · build ${scanFingerprint.slice(0, 8)} ≠ ${buildFingerprint.slice(0, 8)}`
                    : ` ≠ ${buildVersion}`)
                : ''}
            </p>
          )}
          {(() => {
            // §2: warn when this scan was submitted against a build-stale fleet —
            // its results may have come from older detector code.
            const staleAtSubmit = Number((scan?.options as any)?.stale_worker_count_at_submit || 0)
            const fleetAtSubmit = Number((scan?.options as any)?.worker_fleet_size_at_submit || 0)
            if (staleAtSubmit > 0) {
              return (
                <p className="text-xs mt-0.5 font-mono text-amber-400"
                   title="Some workers were running older code than the current checkout when this scan was submitted; results may be from stale detectors. Restart workers and re-scan.">
                  ⚠ {staleAtSubmit}/{fleetAtSubmit} workers stale at submit
                </p>
              )
            }
            return null
          })()}
        </div>
      </div>
    </Card>
  )
}

function DeploymentDecisionCard({
  decision,
  loading,
  onRefresh,
}: {
  decision: DeploymentDecision | null
  loading: boolean
  onRefresh: () => void
}) {
  if (!decision && !loading) return null
  const verdict = String(decision?.decision || decision?.deploy_decision || 'unknown').toLowerCase()
  const blockingFindings = Array.isArray(decision?.blocking_findings) ? decision.blocking_findings : []
  const blockingCount = blockingFindings.length
  const targetActiveCount = blockingFindings.filter((f) => f?.from_target_active).length
  const appliedExceptions = Array.isArray(decision?.applied_exceptions)
    ? decision.applied_exceptions
    : Array.isArray(decision?.exceptions_applied)
      ? decision.exceptions_applied
      : []
  const exceptionCount = appliedExceptions.length
  const exceptionSummary = decision?.exception_summary
  const requiredEvidenceMissing = Array.isArray(decision?.required_evidence_missing) ? decision.required_evidence_missing : []
  const verdictClass =
    verdict === 'block'
      ? 'bg-red-900/50 text-red-200'
      : verdict === 'allow'
        ? 'bg-green-900/50 text-green-200'
        : 'bg-amber-900/50 text-amber-200'

  return (
    <Card className="p-4 mb-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-gray-300">Overall release decision</h2>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <span className={`rounded px-2 py-1 text-xs font-medium ${verdictClass}`}>{verdict.replace(/_/g, ' ')}</span>
            {decision?.policy_profile && <span className="rounded bg-gray-800 px-2 py-1 text-xs text-gray-300">{String(decision.policy_profile)}</span>}
            {decision?.policy_name && <span className="rounded bg-gray-800 px-2 py-1 text-xs text-gray-300">{String(decision.policy_name)}</span>}
          </div>
        </div>
        <button
          type="button"
          onClick={onRefresh}
          disabled={loading}
          className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800 disabled:opacity-50"
        >
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>
      {(decision?.rationale || decision?.reason) && (
        <p className="mt-3 text-sm text-gray-300">{String(decision.rationale || decision.reason)}</p>
      )}
      <p className="mt-2 text-xs text-gray-500">
        This decision combines the scan result with unresolved findings and policy for the target. A completed scan or high technical score does not override a blocked release decision.
      </p>
      <div className="mt-3 flex flex-wrap gap-2 text-xs text-gray-500">
        <span>{blockingCount} blocking finding{blockingCount === 1 ? '' : 's'}</span>
        <span>{exceptionCount} exception{exceptionCount === 1 ? '' : 's'} applied</span>
        {exceptionSummary?.total !== undefined && <span>{Number(exceptionSummary.total || 0)} exception record{Number(exceptionSummary.total || 0) === 1 ? '' : 's'} evaluated</span>}
        {decision?.expires_at && <span>expires {formatDate(String(decision.expires_at))}</span>}
      </div>
      {requiredEvidenceMissing.length > 0 && (
        <div className="mt-3 rounded border border-amber-500/20 bg-amber-500/10 p-3">
          <div className="text-xs font-semibold uppercase tracking-wide text-amber-200">Required evidence missing</div>
          <div className="mt-2 grid gap-2 md:grid-cols-2">
            {requiredEvidenceMissing.slice(0, 6).map((item, index) => (
              <div key={`${item.id || 'evidence'}-${index}`} className="rounded border border-amber-500/20 bg-gray-950/40 p-2 text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-amber-100">{String(item.label || item.id || 'Evidence')}</span>
                  {item.status && <span className="rounded bg-amber-900/40 px-1.5 py-0.5 text-amber-200">{String(item.status).replace(/_/g, ' ')}</span>}
                </div>
                {item.id === 'policy_required_trust_anchors' && (
                  <div className="mt-1 space-y-1 text-gray-400">
                    {item.policy_profile && <div>profile: {String(item.policy_profile)}</div>}
                    {item.signature_verification_status && <div>signature: {String(item.signature_verification_status).replace(/_/g, ' ')}</div>}
                    {Array.isArray(item.required_trust_anchor_ids) && item.required_trust_anchor_ids.length > 0 && (
                      <div className="break-all">required anchors: {item.required_trust_anchor_ids.map((id) => id.slice(0, 8)).join(', ')}</div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
          {requiredEvidenceMissing.length > 6 && (
            <p className="mt-2 text-xs text-amber-200">+{requiredEvidenceMissing.length - 6} more evidence requirement{requiredEvidenceMissing.length - 6 === 1 ? '' : 's'}</p>
          )}
        </div>
      )}
      {exceptionSummary && (
        <div className="mt-3 rounded border border-gray-800 bg-gray-950/40 p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="text-xs font-semibold uppercase tracking-wide text-gray-400">Exception hygiene</div>
            {exceptionSummary.profile_disables_exceptions && (
              <span className="rounded bg-red-900/40 px-2 py-0.5 text-xs text-red-200">disabled by profile</span>
            )}
          </div>
          <div className="mt-2 flex flex-wrap gap-2 text-xs">
            <span className="rounded bg-gray-800 px-2 py-1 text-gray-300">{Number(exceptionSummary.applied_count || 0)} applied</span>
            {Number(exceptionSummary.expired || 0) > 0 && <span className="rounded bg-red-900/40 px-2 py-1 text-red-200">{exceptionSummary.expired} expired</span>}
            {Number(exceptionSummary.expiring_soon || 0) > 0 && <span className="rounded bg-amber-900/40 px-2 py-1 text-amber-200">{exceptionSummary.expiring_soon} expiring soon</span>}
            {Number(exceptionSummary.missing_owner || 0) > 0 && <span className="rounded bg-amber-900/40 px-2 py-1 text-amber-200">{exceptionSummary.missing_owner} missing owner</span>}
            {Number(exceptionSummary.missing_approver || 0) > 0 && <span className="rounded bg-amber-900/40 px-2 py-1 text-amber-200">{exceptionSummary.missing_approver} missing approver</span>}
            {Number(exceptionSummary.missing_compensating_controls || 0) > 0 && <span className="rounded bg-amber-900/40 px-2 py-1 text-amber-200">{exceptionSummary.missing_compensating_controls} missing controls</span>}
            {Number(exceptionSummary.missing_expiry || 0) > 0 && <span className="rounded bg-amber-900/40 px-2 py-1 text-amber-200">{exceptionSummary.missing_expiry} missing expiry</span>}
            {Number(exceptionSummary.inactive_or_revoked || 0) > 0 && <span className="rounded bg-gray-800 px-2 py-1 text-gray-300">{exceptionSummary.inactive_or_revoked} inactive/revoked</span>}
          </div>
          {Number(exceptionSummary.review_required || 0) > 0 && (
            <p className="mt-2 text-xs text-amber-200">
              {exceptionSummary.review_required} exception record{Number(exceptionSummary.review_required) === 1 ? '' : 's'} need review before relying on this gate decision.
            </p>
          )}
        </div>
      )}
      {blockingCount > 0 && (
        <div className="mt-3 border-t border-gray-800 pt-3">
          {targetActiveCount > 0 && (
            <p className="mb-2 text-xs text-amber-300/90">
              {targetActiveCount} of these {targetActiveCount === 1 ? 'is an' : 'are'} unresolved
              critical/high finding{targetActiveCount === 1 ? '' : 's'} already open on this target
              (not necessarily detected by this scan). Resolve them or add a policy exception to unblock deploy.
            </p>
          )}
          <ul className="space-y-1">
            {blockingFindings.slice(0, 8).map((f, i) => (
              <li key={f.id || i} className="flex items-center gap-2 text-xs">
                <span className={`shrink-0 rounded px-1.5 py-0.5 font-medium ${deploySeverityClass(f.severity)}`}>
                  {String(f.severity || 'finding')}
                </span>
                {f.id ? (
                  <Link href={`/findings/${f.id}`} className="text-gray-300 hover:text-white break-all">
                    {f.title || 'Untitled finding'}
                  </Link>
                ) : (
                  <span className="text-gray-300 break-all">{f.title || 'Untitled finding'}</span>
                )}
                {f.from_target_active && (
                  <span
                    className="shrink-0 rounded bg-amber-900/40 px-1.5 py-0.5 text-amber-300"
                    title="Unresolved on this target from another scan"
                  >
                    on target
                  </span>
                )}
              </li>
            ))}
          </ul>
          {blockingCount > 8 && (
            <p className="mt-1 text-xs text-gray-500">+{blockingCount - 8} more</p>
          )}
        </div>
      )}
    </Card>
  )
}

function deploySeverityClass(severity?: string): string {
  switch (String(severity || '').toLowerCase()) {
    case 'critical':
      return 'bg-red-900/50 text-red-200'
    case 'high':
      return 'bg-orange-900/50 text-orange-200'
    case 'medium':
      return 'bg-yellow-900/40 text-yellow-200'
    case 'low':
      return 'bg-blue-900/40 text-blue-200'
    default:
      return 'bg-gray-700 text-gray-300'
  }
}

function ScanFindingContextCard({
  scan,
  targetFindings,
  targetFindingsTotal,
  loading,
  error,
}: {
  scan: any
  targetFindings: Finding[]
  targetFindingsTotal: number
  loading: boolean
  error: string | null
}) {
  if (!scan?.target_id) return null
  const rawCurrent = Array.isArray(scan?.result?.findings) ? scan.result.findings : []
  const persistedCurrent = targetFindings.filter((finding) => finding.scan_id === scan.id)
  const currentKeys = new Set(rawCurrent.map((finding: any) => [
    String(finding?.title || ''),
    String(finding?.url || ''),
    String(finding?.cwe || ''),
  ].join('|')))
  const additionalPersistedCurrent = persistedCurrent.filter((finding) => !currentKeys.has([
    String(finding.title || ''),
    String(finding.url || ''),
    String(finding.cwe || ''),
  ].join('|')))
  const current = [
    ...rawCurrent.map((finding: any, index: number) => ({
      ...finding,
      _rowKey: `raw-${finding.id || finding.fingerprint || index}`,
      _origin: 'this scan' as const,
      _persisted: false,
    })),
    ...additionalPersistedCurrent.map((finding) => ({
      ...finding,
      _rowKey: `persisted-${finding.id}`,
      _origin: 'this scan' as const,
      _persisted: true,
    })),
  ]
  const existingTotal = Math.max(0, targetFindingsTotal - persistedCurrent.length)

  return (
    <Card className="mb-6 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-gray-200">Findings from this scan</h2>
          <p className="mt-1 text-xs text-gray-500">
            This run's signals are kept separate from findings already tracked on the target.
          </p>
        </div>
        <Link href={`/findings?target_id=${scan.target_id}`} className="text-xs text-blue-300 hover:text-blue-200">
          Open all target findings
        </Link>
      </div>
      <div className="mt-3 flex flex-wrap gap-2 text-xs">
        <span className="rounded bg-blue-500/10 px-2 py-1 text-blue-200">{current.length} from this scan</span>
        <span className="rounded bg-gray-800 px-2 py-1 text-gray-300">{existingTotal} earlier on target</span>
      </div>
      {loading ? (
        <p className="mt-3 text-sm text-gray-500">Loading target finding history…</p>
      ) : error ? (
        <p role="alert" className="mt-3 text-sm text-amber-300">{error}</p>
      ) : current.length === 0 ? (
        <p className="mt-3 text-sm text-gray-500">
          No findings were reported by this scan.{existingTotal > 0 ? ` The target has ${existingTotal} earlier saved findings; use the link above to review them.` : ''}
        </p>
      ) : (
        <ul className="mt-3 divide-y divide-gray-800 rounded-lg border border-gray-800">
          {current.map((finding: any) => (
            <li key={finding._rowKey} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm">
              <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${deploySeverityClass(finding.severity)}`}>
                {String(finding.severity || 'info')}
              </span>
              <span className={`rounded px-1.5 py-0.5 text-xs ${finding._origin === 'this scan' ? 'bg-blue-500/10 text-blue-200' : 'bg-gray-800 text-gray-300'}`}>
                {finding._origin}
              </span>
              {finding.id && finding._persisted ? (
                <Link href={`/findings/${finding.id}`} className="min-w-0 flex-1 break-words text-gray-200 hover:text-white">
                  {finding.title || 'Untitled finding'}
                </Link>
              ) : (
                <span className="min-w-0 flex-1 break-words text-gray-200">{finding.title || 'Untitled finding'}</span>
              )}
              <span className="text-xs text-gray-500">
                {finding.proof_state?.replaceAll('_', ' ') || (finding.verified ? 'verified' : finding.suspected ? 'needs verification' : finding.status?.replaceAll('_', ' ') || 'unverified')}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  )
}

function formatAiGateLabel(value: string | null | undefined): string {
  return String(value || 'unknown').replace(/_/g, ' ')
}

function aiGateJudgingGateDisplay(status: string | null | undefined): { label: string; className: string; title: string } | null {
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

function formatDelta(value: number | undefined, suffix: string = ''): string {
  const num = Number(value || 0)
  if (num > 0) return `+${num}${suffix}`
  return `${num}${suffix}`
}

function deltaClass(value: number | undefined, invert: boolean = false): string {
  const num = Number(value || 0)
  if (num === 0) return 'text-gray-400'
  const good = invert ? num < 0 : num > 0
  return good ? 'text-green-300' : 'text-red-300'
}

function AiGateCampaignReviewCard({ scan }: { scan: any }) {
  const review: AiGateCampaignReview = buildAiGateCampaignReview(scan?.result)
  const [replayLoading, setReplayLoading] = useState<string | null>(null)
  const [replayError, setReplayError] = useState<string | null>(null)
  const [replayQueued, setReplayQueued] = useState<{ scan_id: string; ui_url?: string; label: string } | null>(null)
  const [confirmProductionReplay, setConfirmProductionReplay] = useState(false)
  const [campaignHistory, setCampaignHistory] = useState<AiScanCampaignHistory | null>(null)
  const [campaignHistoryError, setCampaignHistoryError] = useState<string | null>(null)
  const [collapsed, setCollapsed] = useState(false)
  const judgingGate = aiGateJudgingGateDisplay(review.judging_gate_status)

  useEffect(() => {
    let cancelled = false
    if (!review.available || !scan?.id || scan.status !== 'completed') {
      setCampaignHistory(null)
      setCampaignHistoryError(null)
      return
    }
    getAiScanCampaignHistory(scan.id)
      .then((history) => {
        if (!cancelled) {
          setCampaignHistory(history)
          setCampaignHistoryError(null)
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setCampaignHistory(null)
          setCampaignHistoryError(err instanceof Error ? err.message : 'Failed to load campaign history')
        }
      })
    return () => {
      cancelled = true
    }
  }, [review.available, scan?.id, scan?.status])
  if (!review.available) return null

  const coveragePct = review.planned > 0 ? Math.round((review.executed / review.planned) * 100) : 0
  const transcriptUrl = `${API_URL}/ai/scans/${scan.id}/transcript`
  const reportUrl = `${API_URL}/scans/${scan.id}/ai-redteam-report`
  const isProduction = review.environment === 'production'
  const decisionClass =
    review.decision === 'block'
      ? 'bg-red-900/50 text-red-200'
      : review.decision === 'allow'
        ? 'bg-green-900/50 text-green-200'
        : 'bg-amber-900/50 text-amber-200'

  async function queueReplay(
    label: string,
    mode: 'skipped' | 'errors' | 'family' | 'transcript' | 'all',
    options: { probeFamily?: string; probeId?: string; transcriptIndex?: number } = {}
  ) {
    const replayTarget = options.probeFamily || options.probeId || options.transcriptIndex || ''
    const replayKey = `${mode}:${replayTarget}`
    setReplayLoading(replayKey)
    setReplayError(null)
    setReplayQueued(null)
    try {
      const result = await replayAiScan(scan.id, {
        mode,
        probe_family: options.probeFamily,
        probe_id: options.probeId,
        transcript_index: options.transcriptIndex,
        confirm_production: confirmProductionReplay,
        requested_by: 'ui',
      })
      setReplayQueued({ scan_id: result.scan_id, ui_url: result.ui_url, label })
    } catch (err) {
      setReplayError(err instanceof Error ? err.message : 'Failed to queue AI Gate replay')
    } finally {
      setReplayLoading(null)
    }
  }

  return (
    <Card className="p-4 mb-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-gray-300">AI Red-Team Campaign</h2>
          <p className="mt-0.5 text-xs text-gray-500">
            {review.target_name || 'AI target'} · {formatAiGateLabel(review.target_type)} · {formatAiGateLabel(review.probe_pack)} · {formatAiGateLabel(review.scan_profile)}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {review.decision && (
            <span className={`rounded px-2 py-1 text-xs ${decisionClass}`}>{formatAiGateLabel(review.decision)}</span>
          )}
          {review.environment && <span className="rounded bg-gray-800 px-2 py-1 text-xs text-gray-300">{formatAiGateLabel(review.environment)}</span>}
          {judgingGate && (
            <span className={`rounded px-2 py-1 text-xs ${judgingGate.className}`} title={judgingGate.title}>
              {judgingGate.label}
            </span>
          )}
          <button
            type="button"
            onClick={() => setCollapsed((v) => !v)}
            aria-expanded={!collapsed}
            className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            {collapsed ? 'Show details' : 'Hide details'}
          </button>
        </div>
      </div>

      {!collapsed && (
        <>
      {review.rationale && <p className="mt-3 text-sm text-gray-300">{review.rationale}</p>}

      <div className="mt-4 rounded border border-gray-800 bg-gray-950/50 p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="text-xs font-medium uppercase tracking-wide text-gray-500">Campaign History</div>
            <p className="mt-1 text-xs text-gray-500">
              Compares recent completed runs with the same target, probe pack, profile, and environment.
            </p>
          </div>
          {campaignHistory?.previous_run && (
            <Link href={campaignHistory.previous_run.ui_url || `/scans/${campaignHistory.previous_run.id}`} className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800">
              Previous run
            </Link>
          )}
        </div>
        {campaignHistoryError && <p role="alert" className="mt-2 text-xs text-amber-300">{campaignHistoryError}</p>}
        {campaignHistory?.deltas ? (
          <div className="mt-3 grid gap-2 sm:grid-cols-5">
            <CoverageMetric label="Findings delta" value={formatDelta(campaignHistory.deltas.findings_count)} accent={deltaClass(campaignHistory.deltas.findings_count, true)} />
            <CoverageMetric label="Coverage delta" value={formatDelta(campaignHistory.deltas.coverage_pct, '%')} accent={deltaClass(campaignHistory.deltas.coverage_pct)} />
            <CoverageMetric label="Executed delta" value={formatDelta(campaignHistory.deltas.executed)} accent={deltaClass(campaignHistory.deltas.executed)} />
            <CoverageMetric label="Skipped delta" value={formatDelta(campaignHistory.deltas.skipped)} accent={deltaClass(campaignHistory.deltas.skipped, true)} />
            <CoverageMetric label="Errors delta" value={formatDelta(campaignHistory.deltas.errors)} accent={deltaClass(campaignHistory.deltas.errors, true)} />
          </div>
        ) : (
          <p className="mt-2 text-sm text-gray-500">
            {campaignHistory ? 'No comparable previous campaign was found for this target/profile.' : 'Loading campaign history...'}
          </p>
        )}
        {campaignHistory?.deltas?.decision_changed && (
          <p className="mt-2 text-xs text-amber-300">
            Deployment decision changed from {formatAiGateLabel(campaignHistory.previous_run?.decision)} to {formatAiGateLabel(review.decision)}.
          </p>
        )}
        {campaignHistory?.runs && campaignHistory.runs.length > 0 && (
          <div className="mt-3 overflow-x-auto">
            <table className="min-w-full text-left text-xs">
              <thead className="text-gray-500">
                <tr>
                  <th className="py-1 pr-3 font-medium">Run</th>
                  <th className="py-1 pr-3 font-medium">Decision</th>
                  <th className="py-1 pr-3 font-medium">Coverage</th>
                  <th className="py-1 pr-3 font-medium">Findings</th>
                  <th className="py-1 pr-3 font-medium">Completed</th>
                </tr>
              </thead>
              <tbody>
                {campaignHistory.runs.slice(0, 6).map((run) => (
                  <tr key={run.id} className="border-t border-gray-800">
                    <td className="py-1 pr-3">
                      <Link href={run.ui_url || `/scans/${run.id}`} className="font-mono text-blue-300 hover:underline">
                        {run.current ? 'current' : run.id.slice(0, 8)}
                      </Link>
                    </td>
                    <td className="py-1 pr-3 text-gray-300">{formatAiGateLabel(run.decision)}</td>
                    <td className="py-1 pr-3 text-gray-300">{run.coverage_pct}%</td>
                    <td className="py-1 pr-3 text-gray-300">{run.findings_count}</td>
                    <td className="py-1 pr-3 text-gray-500">{run.completed_at ? formatDate(run.completed_at) : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="mt-4 rounded border border-gray-800 bg-gray-950/50 p-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-xs font-medium uppercase tracking-wide text-gray-500">Campaign replay</div>
            <p className="mt-1 text-xs text-gray-500">
              Queue a focused AI Gate run using the original target, probe pack, profile, and environment.
            </p>
          </div>
          {isProduction && (
            <label className="flex items-center gap-2 text-xs text-amber-200">
              <input
                type="checkbox"
                checked={confirmProductionReplay}
                onChange={(event) => setConfirmProductionReplay(event.target.checked)}
                className="h-4 w-4 rounded border-gray-700 bg-gray-800"
              />
              Confirm production replay
            </label>
          )}
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => queueReplay('Skipped probes', 'skipped')}
            disabled={replayLoading !== null || review.skipped === 0 || (isProduction && !confirmProductionReplay)}
            className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800 disabled:opacity-50"
          >
            {replayLoading === 'skipped:' ? 'Queueing...' : 'Rerun skipped'}
          </button>
          <button
            type="button"
            onClick={() => queueReplay('Errored families', 'errors')}
            disabled={replayLoading !== null || review.errors === 0 || (isProduction && !confirmProductionReplay)}
            className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800 disabled:opacity-50"
          >
            {replayLoading === 'errors:' ? 'Queueing...' : 'Rerun errors'}
          </button>
          <button
            type="button"
            onClick={() => queueReplay('Full campaign', 'all')}
            disabled={replayLoading !== null || (isProduction && !confirmProductionReplay)}
            className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800 disabled:opacity-50"
          >
            {replayLoading === 'all:' ? 'Queueing...' : 'Rerun all'}
          </button>
        </div>
        {replayError && <p role="alert" className="mt-2 text-xs text-red-300">{replayError}</p>}
        {replayQueued && (
          <p className="mt-2 text-xs text-green-300">
            Queued {replayQueued.label}.{' '}
            <Link href={replayQueued.ui_url || `/scans/${replayQueued.scan_id}`} className="underline hover:text-green-100">
              View scan
            </Link>
          </p>
        )}
      </div>

      <div className="mt-4 grid gap-2 sm:grid-cols-3 lg:grid-cols-6">
        <CoverageMetric label="Planned probes" value={review.planned} />
        <CoverageMetric label="Executed" value={`${review.executed} (${coveragePct}%)`} accent={review.executed ? 'text-green-300' : 'text-gray-300'} />
        <CoverageMetric label="Skipped" value={review.skipped} accent={review.skipped ? 'text-yellow-300' : 'text-gray-300'} />
        <CoverageMetric label="Transcripts" value={review.with_transcripts} accent={review.with_transcripts ? 'text-blue-300' : 'text-gray-300'} />
        <CoverageMetric label="Finding probes" value={review.with_findings} accent={review.with_findings ? 'text-red-300' : 'text-gray-300'} />
        <CoverageMetric label="Errors" value={review.errors} accent={review.errors ? 'text-red-300' : 'text-gray-300'} />
      </div>

      <div className="mt-4 grid gap-3 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,0.8fr)]">
        <div className="min-w-0 rounded border border-gray-800 bg-gray-950/50 p-3">
          <div className="mb-2 text-xs font-medium uppercase tracking-wide text-gray-500">Coverage Matrix</div>
          {review.families.length ? (
            <div className="space-y-2">
              {review.families.slice(0, 8).map((family) => (
                <div key={family.family} className="rounded border border-gray-800 bg-gray-900/60 p-2">
                  <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                    <span className="font-medium text-gray-200">{formatAiGateLabel(family.family)}</span>
                    <span className="text-gray-500">{family.executed}/{family.planned} executed</span>
                  </div>
                  <div className="mt-2 h-1.5 rounded bg-gray-800">
                    <div
                      className="h-1.5 rounded bg-purple-500"
                      style={{ width: `${family.planned ? Math.min(100, Math.round((family.executed / family.planned) * 100)) : 0}%` }}
                    />
                  </div>
                  <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-gray-500">
                    <span>{family.with_transcript} transcript{family.with_transcript === 1 ? '' : 's'}</span>
                    <span>{family.with_findings} finding probe{family.with_findings === 1 ? '' : 's'}</span>
                    {family.skipped > 0 && <span>{family.skipped} skipped</span>}
                    {family.errors > 0 && <span className="text-red-300">{family.errors} errors</span>}
                  </div>
                  <button
                    type="button"
                    onClick={() => queueReplay(formatAiGateLabel(family.family), 'family', { probeFamily: family.family })}
                    disabled={replayLoading !== null || (isProduction && !confirmProductionReplay)}
                    className="mt-2 rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800 disabled:opacity-50"
                  >
                    {replayLoading === `family:${family.family}` ? 'Queueing...' : 'Rerun family'}
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-gray-500">No family coverage matrix was stored for this run.</p>
          )}
        </div>

        <div className="min-w-0 space-y-3">
          <div className="rounded border border-gray-800 bg-gray-950/50 p-3">
            <div className="mb-2 text-xs font-medium uppercase tracking-wide text-gray-500">Skipped / Blocked</div>
            {review.skipped_reasons.length ? (
              <div className="space-y-2">
                {review.skipped_reasons.slice(0, 6).map((reason) => (
                  <div key={reason.reason} className="rounded bg-gray-900/70 p-2 text-xs">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-gray-200">{formatAiGateLabel(reason.reason)}</span>
                      <span className="text-yellow-300">{reason.count}</span>
                    </div>
                    <div className="mt-1 break-words text-gray-500">{reason.families.map(formatAiGateLabel).join(', ')}</div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-500">No skipped probes were recorded.</p>
            )}
          </div>

          <div className="rounded border border-gray-800 bg-gray-950/50 p-3">
            <div className="mb-2 text-xs font-medium uppercase tracking-wide text-gray-500">Evidence Pack</div>
            <div className="space-y-1 text-xs text-gray-500">
              {review.planned_hash && <div className="truncate">planned: <span className="font-mono text-gray-300">{review.planned_hash}</span></div>}
              {review.executed_hash && <div className="truncate">executed: <span className="font-mono text-gray-300">{review.executed_hash}</span></div>}
              {review.transcripts_hash && <div className="truncate">transcripts: <span className="font-mono text-gray-300">{review.transcripts_hash}</span></div>}
              {review.execution_plan_hash && <div className="truncate">plan: <span className="font-mono text-gray-300">{review.execution_plan_hash}</span></div>}
              {review.evidence_manifest_hash && <div className="truncate">manifest: <span className="font-mono text-gray-300">{review.evidence_manifest_hash}</span></div>}
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              <a href={transcriptUrl} target="_blank" rel="noreferrer" className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800">
                Transcripts
              </a>
              <a href={reportUrl} target="_blank" rel="noreferrer" className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800">
                Export report
              </a>
            </div>
          </div>

          <div className="rounded border border-gray-800 bg-gray-950/50 p-3">
            <div className="mb-2 text-xs font-medium uppercase tracking-wide text-gray-500">Transcript Replay</div>
            {review.transcripts.length ? (
              <div className="space-y-2">
                {review.transcripts.slice(0, 6).map((transcript) => (
                  <div key={`${transcript.index}-${transcript.probe_id}`} className="rounded bg-gray-900/70 p-2 text-xs">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="min-w-0 break-all font-mono text-gray-200">{transcript.probe_id}</span>
                      {transcript.error && <span className="rounded bg-red-900/50 px-1.5 py-0.5 text-[11px] text-red-200">error</span>}
                    </div>
                    <div className="mt-1 flex flex-wrap gap-2 text-[11px] text-gray-500">
                      {transcript.probe_family && <span>{formatAiGateLabel(transcript.probe_family)}</span>}
                      {transcript.technique && <span>{formatAiGateLabel(transcript.technique)}</span>}
                      {transcript.status_code ? <span>HTTP {transcript.status_code}</span> : null}
                      {transcript.turn_count !== null && transcript.turn_count !== undefined && <span>{transcript.turn_count} turn{transcript.turn_count === 1 ? '' : 's'}</span>}
                    </div>
                    <button
                      type="button"
                      onClick={() => queueReplay(`Transcript ${transcript.probe_id}`, 'transcript', {
                        probeId: transcript.probe_id || undefined,
                        transcriptIndex: transcript.index,
                      })}
                      disabled={replayLoading !== null || (isProduction && !confirmProductionReplay)}
                      className="mt-2 rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800 disabled:opacity-50"
                    >
                      {replayLoading === `transcript:${transcript.probe_id || transcript.index}` ? 'Queueing...' : 'Replay transcript'}
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-500">No replayable transcript probe IDs were stored for this run.</p>
            )}
          </div>
        </div>
      </div>

      {review.findings.length > 0 && (
        <div className="mt-4 rounded border border-gray-800 bg-gray-950/50 p-3">
          <div className="mb-2 text-xs font-medium uppercase tracking-wide text-gray-500">Replay / Rerun Findings</div>
          <div className="grid gap-2 lg:grid-cols-2">
            {review.findings.map((finding) => (
              <div key={finding.id || `${finding.title}-${finding.probe_id}`} className="rounded border border-gray-800 bg-gray-900/60 p-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${deploySeverityClass(finding.severity)}`}>
                    {finding.severity}
                  </span>
                  <span className="min-w-0 flex-1 break-words text-xs text-gray-200">{finding.title}</span>
                </div>
                <div className="mt-1 text-[11px] text-gray-500">
                  {finding.probe_id || 'probe unknown'}{finding.probe_family ? ` · ${formatAiGateLabel(finding.probe_family)}` : ''}
                </div>
                {finding.id && (
                  <Link href={`/findings/${finding.id}`} className="mt-2 inline-block rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800">
                    Review / replay
                  </Link>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
        </>
      )}
    </Card>
  )
}

function ParentCoverageRollup({ scan }: { scan: any }) {
  if (scan?.scan_role !== 'parent') return null

  const smartCoverage = scan?.result?.smart_coverage || {}
  const endpoints = smartCoverage?.endpoints
  if (!endpoints || typeof endpoints !== 'object') return null
  const strategy = String(scan?.options?.parallel_strategy || scan?.options?.shard_strategy || '').toLowerCase()
  const basisRaw = String(smartCoverage.coverage_basis || endpoints.basis || '')
  if (strategy !== 'coverage' && !/attempt|campaign/.test(basisRaw)) return null

  const discovered = coverageNumber(endpoints.discovered ?? endpoints.total)
  const tested = coverageNumber(endpoints.tested ?? endpoints.completed)
  const attempted = coverageNumber(endpoints.attempted)
  const partial = coverageNumber(endpoints.partial)
  const untested = coverageNumber(endpoints.untested)
  const authBlocked = coverageNumber(endpoints.auth_blocked)
  const rateLimited = coverageNumber(endpoints.rate_limited)
  const errors = coverageNumber(endpoints.error)
  const coverage = typeof endpoints.coverage === 'number'
    ? endpoints.coverage
    : discovered > 0
      ? tested / discovered
      : 0
  const basis = basisRaw.replace(/_/g, ' ')
  const assignment = smartCoverage.endpoint_assignment_rollup
  const allocation = String(scan?.options?.coverage_allocation || '').toLowerCase()

  return (
    <Card className="p-4 mb-6">
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-gray-300">Full Coverage Rollup</h2>
          <p className="mt-0.5 text-xs text-gray-500">
            Campaign endpoint coverage from merged shard attempts.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {allocation && (
            <span className="rounded bg-blue-500/10 px-2 py-1 text-xs text-blue-300">
              {allocation} allocation
            </span>
          )}
          {basis && (
            <span className="rounded bg-gray-800 px-2 py-1 text-xs text-gray-300">
              {basis}
            </span>
          )}
        </div>
      </div>

      <div className="mb-3">
        <div className="mb-1 flex items-center justify-between text-xs text-gray-500">
          <span>{tested} tested / {discovered} discovered</span>
          <span className="text-gray-300">{formatPct(coverage)}</span>
        </div>
        <div className="h-2 rounded-full bg-gray-800">
          <div
            className="h-2 rounded-full bg-green-500"
            style={{ width: `${Math.max(0, Math.min(100, coverage * 100))}%` }}
          />
        </div>
      </div>

      <div className="grid gap-2 sm:grid-cols-3 lg:grid-cols-6">
        <CoverageMetric label="Attempted" value={attempted || tested + partial} />
        <CoverageMetric label="Partial" value={partial} accent={partial ? 'text-yellow-300' : 'text-gray-300'} />
        <CoverageMetric label="Untested" value={untested} accent={untested ? 'text-blue-300' : 'text-gray-300'} />
        <CoverageMetric label="Auth blocked" value={authBlocked} accent={authBlocked ? 'text-amber-300' : 'text-gray-300'} />
        <CoverageMetric label="Rate limited" value={rateLimited} accent={rateLimited ? 'text-purple-300' : 'text-gray-300'} />
        <CoverageMetric label="Errors" value={errors} accent={errors ? 'text-red-300' : 'text-gray-300'} />
      </div>

      {assignment?.basis && (
        <p className="mt-3 text-xs text-gray-500">
          Static assignment context retained as fallback: {String(assignment.basis).replace(/_/g, ' ')}.
        </p>
      )}
    </Card>
  )
}

function ParallelShardRollup({ scan }: { scan: any }) {
  if (scan?.scan_role !== 'parent') {
    return null
  }

  const shards = Array.isArray(scan?.shards) ? scan.shards : []
  const discovery = scan?.parallel_discovery
  const strategy = scan.options?.parallel_strategy || scan.options?.shard_strategy
  const strategyBadge = strategy ? (
    <span className="px-2 py-1 rounded bg-blue-500/10 text-xs text-blue-300">
      {String(strategy)} strategy
    </span>
  ) : null

  // Discovery is an actual placed execution stage, not invisible planner time.
  if (shards.length === 0) {
    if (['running', 'pending', 'queued'].includes(scan.status)) {
      return (
        <Card className="p-4 mb-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-gray-300">Parallel execution</h2>
              <p className="text-xs text-gray-500 mt-0.5">
                {discovery
                  ? `Discovery ${String(discovery.status || 'pending')} · ${Number(discovery.progress || 0)}%${discovery.worker_id ? ` · ${String(discovery.worker_id)}` : ''}`
                  : 'Preparing execution stages…'}
              </p>
            </div>
            {strategyBadge}
          </div>
        </Card>
      )
    }
    return null
  }

  const rollup = scan.shard_rollup || {}
  const plannedRequestBudget = Number(scan.options?.parallel_planned_request_budget || 0)
  const backboneRequestBudget = Number(scan.options?.parallel_backbone_request_budget || 0)
  return (
    <Card className="p-4 mb-6">
      <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
        <div>
          <h2 className="text-sm font-semibold text-gray-300">Parallel Shards</h2>
          <p className="text-xs text-gray-500 mt-0.5">
            {rollup.terminal || 0}/{rollup.total || scan.shards.length} terminal,
            {' '}{rollup.completed || 0} completed,
            {' '}{rollup.failed || 0} failed,
            {' '}{rollup.cancelled || 0} cancelled
          </p>
        </div>
        {scan.options?.parallel_strategy && (
          <span className="px-2 py-1 rounded bg-blue-500/10 text-xs text-blue-300">
            {String(scan.options.parallel_strategy)} strategy
          </span>
        )}
      </div>
      {discovery && (
        <div className="mb-3 rounded border border-gray-800 bg-gray-950/50 p-3 text-xs text-gray-400">
          <span className="font-medium text-gray-200">Discovery</span>
          {' · '}{String(discovery.status || 'unknown')}
          {discovery.executing_node_id ? ` · node ${String(discovery.executing_node_id).slice(0, 8)}` : ''}
          {discovery.worker_id ? ` · ${String(discovery.worker_id)}` : ''}
        </div>
      )}
      {plannedRequestBudget > 0 && (
        <div className="mb-3 text-xs text-gray-500">
          Planned request budgets: {plannedRequestBudget.toLocaleString()} aggregate
          {backboneRequestBudget > 0 ? ` · ${backboneRequestBudget.toLocaleString()} backbone` : ''}.
          Actual traffic remains subject to per-target rate limits and completion budgets.
        </div>
      )}
      <ShardContributionRollup rollup={rollup} />
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {scan.shards.map((shard: any) => (
          <ShardCard shard={shard} key={shard.id} />
        ))}
      </div>
    </Card>
  )
}

function ShardContributionRollup({ rollup }: { rollup: any }) {
  const contribution = rollup?.contribution
  if (!contribution || typeof contribution !== 'object') return null

  const normalizedCoverage = normalizeParentCoverage(contribution)
  const assigned = normalizedCoverage.assigned
  const attempted = normalizedCoverage.attempted
  const selected = normalizedCoverage.selected
  const activeBudget = coverageNumber(contribution.active_max_seconds)
  const duration = coverageNumber(contribution.duration_seconds)
  const telemetry = normalizedCoverage.telemetryShards
  const contributing = normalizedCoverage.contributingShards
  const statusSummary = formatAttemptStatuses(contribution.attempt_statuses)

  return (
    <div className="mb-3 grid gap-2 text-xs sm:grid-cols-2 lg:grid-cols-4">
      <div className="rounded border border-gray-800 bg-gray-950/50 p-3">
        <div className="text-gray-500">Endpoint work</div>
        <div className="mt-1 text-gray-200">
          {attempted || selected || 0} attempted{assigned ? ` · ${assigned} assigned` : ''}
        </div>
        {statusSummary && <div className="mt-1 text-gray-500">{statusSummary}</div>}
      </div>
      <div className="rounded border border-gray-800 bg-gray-950/50 p-3">
        <div className="text-gray-500">Runtime / active cap</div>
        <div className="mt-1 text-gray-200">
          {duration ? formatDuration(duration) : '0s'}
          {activeBudget ? ` / ${formatDuration(activeBudget)}` : ''}
        </div>
        {typeof contribution.active_budget_utilization === 'number' && (
          <div className="mt-1 text-gray-500">{formatPct(contribution.active_budget_utilization)} of cap</div>
        )}
      </div>
      <div className="rounded border border-gray-800 bg-gray-950/50 p-3">
        <div className="text-gray-500">Families</div>
        <div className="mt-1 text-gray-200">
          {formatRollupKeys(contribution.by_check_family, formatShardFamily)}
        </div>
        {telemetry ? <div className="mt-1 text-gray-500">{telemetry} shard telemetry</div> : null}
      </div>
      <div className="rounded border border-gray-800 bg-gray-950/50 p-3">
        <div className="text-gray-500">Auth states</div>
        <div className="mt-1 text-gray-200">
          {formatRollupKeys(contribution.by_auth_state, (value) => value.replace(/_/g, ' '))}
        </div>
        {contributing ? <div className="mt-1 text-gray-500">{contributing} contributing shards</div> : null}
      </div>
    </div>
  )
}

function ShardCard({ shard }: { shard: any }) {
  const contribution = shard?.contribution || {}
  const assigned = coverageNumber(contribution.assigned_endpoints)
  const attempted = coverageNumber(contribution.attempted_endpoints)
  const selected = coverageNumber(contribution.active_endpoints_selected)
  const worklistTotal = coverageNumber(contribution.active_worklist_total)
  const endpointBudget = coverageNumber(contribution.active_endpoint_budget)
  const activeSeconds = coverageNumber(contribution.active_max_seconds)
  const statusSummary = formatAttemptStatuses(contribution.attempt_statuses)
  const duration = shard.duration_seconds ? formatDuration(shard.duration_seconds) : null
  const endpointSummary = assigned || attempted
    ? `${attempted || selected || 0}${assigned ? ` / ${assigned}` : ''}`
    : selected || worklistTotal
      ? `${selected}${worklistTotal ? ` / ${worklistTotal}` : ''}`
      : null

  return (
    <Link
      href={`/scans/${shard.id}`}
      className="block rounded border border-gray-800 bg-gray-900/60 p-3 hover:border-gray-700"
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm text-white">Shard {Number(shard.shard_index ?? 0) + 1}</span>
        <span className="text-xs uppercase text-gray-400">{shard.status}</span>
      </div>
      <div className="mt-2 h-1.5 rounded bg-gray-800">
        <div
          className="h-1.5 rounded bg-blue-500"
          style={{ width: `${Math.max(0, Math.min(100, Number(shard.progress || 0)))}%` }}
        />
      </div>
      <div className="mt-2 flex items-center justify-between text-xs text-gray-500">
        <span>
          {shard.current_phase && shard.current_phase !== shard.status
            ? shard.current_phase
            : shard.executing_node_id
              ? `node ${String(shard.executing_node_id).slice(0, 8)}`
              : 'queued'}
        </span>
        <span>{shard.findings_count || 0} findings</span>
      </div>
      <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
        {endpointSummary && (
          <div className="rounded bg-gray-950/60 px-2 py-1">
            <div className="text-gray-500">Endpoints</div>
            <div className="text-gray-200">{endpointSummary}</div>
          </div>
        )}
        <div className="rounded bg-gray-950/60 px-2 py-1">
          <div className="text-gray-500">Family</div>
          <div className="text-gray-200">{formatShardFamily(contribution.check_family)}</div>
        </div>
        {contribution.auth_state && (
          <div className="rounded bg-gray-950/60 px-2 py-1">
            <div className="text-gray-500">Auth</div>
            <div className="truncate text-gray-200">{String(contribution.auth_state).replace(/_/g, ' ')}</div>
          </div>
        )}
        {(endpointBudget || activeSeconds) && (
          <div className="rounded bg-gray-950/60 px-2 py-1">
            <div className="text-gray-500">Active budget</div>
            <div className="text-gray-200">
              {endpointBudget ? `${endpointBudget} ep` : 'auto'}
              {activeSeconds ? ` · ${formatDuration(activeSeconds)}` : ''}
            </div>
          </div>
        )}
      </div>
      {statusSummary && (
        <p className="mt-2 text-xs text-gray-500">{statusSummary}</p>
      )}
      {duration && (
        <p className="mt-1 text-xs text-gray-600">Duration {duration}</p>
      )}
    </Link>
  )
}

function ShardContextBanner({ scan }: { scan: any }) {
  if (scan?.scan_role !== 'shard' || !scan?.parent_scan_id) return null

  const shardNumber = Number(scan?.shard_index ?? 0) + 1
  const shardCount = Number(scan?.shard_count || 0)
  const terminal = ['completed', 'failed', 'cancelled'].includes(String(scan?.status || ''))
  return (
    <div className="mb-6 rounded-lg border border-blue-500/30 bg-blue-500/10 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-blue-200">
            Parallel work unit · shard {shardNumber}{shardCount ? ` of ${shardCount}` : ''}
          </p>
          <p className="mt-1 max-w-3xl text-sm text-blue-100/75">
            This page is one child execution, not the final Scan verdict.
            {terminal
              ? ' Its terminal state must be interpreted through the parent’s complete shard rollup.'
              : ' The parent Scan remains the authoritative progress and result view.'}
          </p>
        </div>
        <Link
          href={`/scans/${scan.parent_scan_id}`}
          className="inline-flex rounded-lg border border-blue-400/30 bg-blue-400/10 px-3 py-1.5 text-sm font-medium text-blue-100 hover:bg-blue-400/20"
        >
          Open parent Scan
        </Link>
      </div>
    </div>
  )
}

// Plain-language explanation for a failed scan: which phase it died in, whether
// any partial baseline/discovery data was recovered, that there is no final
// score/grade, and what to do next. Rendered above any results.
function FailedScanPanel({ scan, hasPartialResults }: { scan: any; hasPartialResults: boolean }) {
  const failurePhase = String(
    scan?.result?.scan_metadata?.terminated_at_phase ||
    scan?.current_phase ||
    ''
  )
    .replace(/_/g, ' ')
    .trim()
  const failureMessage =
    scan?.result?.scan_metadata?.terminated_reason ||
    scan?.error_message ||
    scan?.error ||
    'No specific error was reported.'
  const targetUrl = String(scan?.target_url || scan?.target || '').trim()
  const looksLikeReachabilityFailure = /dns|resolve|host|connect|timeout|unreachable/i.test(String(failureMessage))
  const isShard = scan?.scan_role === 'shard' && Boolean(scan?.parent_scan_id)

  return (
    <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-5 mb-6">
      <div className="flex items-start gap-3">
        <svg className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <div className="min-w-0">
          <h2 className="text-red-300 font-semibold">{isShard ? 'Shard failed' : 'Scan failed'}</h2>
          <p className="text-red-200/90 text-sm mt-1">
            {failurePhase
              ? <>This {isShard ? 'shard' : 'scan'} stopped during the <span className="font-medium">{failurePhase}</span> phase and did not finish.</>
              : `This ${isShard ? 'shard' : 'scan'} stopped before it finished.`}
          </p>
          <p className="text-red-200/70 text-sm mt-1">{failureMessage}</p>
          <ul className="mt-3 space-y-1 text-sm text-red-200/80 list-disc list-inside">
            {hasPartialResults ? (
              <li>Partial baseline / discovery data was recovered and is shown below, but the scan is incomplete.</li>
            ) : (
              <li>No baseline or discovery data could be recovered from this run.</li>
            )}
            <li>No final score or grade was produced, so this {isShard ? 'work unit' : 'scan'} should not be used as a pass/fail verdict.</li>
          </ul>
          <div className="mt-4 rounded-lg border border-amber-500/20 bg-amber-500/10 p-3">
            <p className="text-sm font-medium text-amber-200">Recommended next step</p>
            <p className="mt-1 text-sm text-amber-100/80">
              {isShard
                ? 'Open the parent Scan to review sibling status and the authoritative final result.'
                : looksLikeReachabilityFailure
                  ? 'Confirm the target address is correct and reachable from the scanner, then try again.'
                  : 'Review the failure above, then retry this target when the underlying problem is resolved.'}
            </p>
            {isShard ? (
              <Link
                href={`/scans/${scan.parent_scan_id}`}
                className="mt-3 inline-flex rounded-lg bg-amber-500/15 px-3 py-1.5 text-sm font-medium text-amber-100 hover:bg-amber-500/25"
              >
                Review parent Scan
              </Link>
            ) : targetUrl && (
              <Link
                href={`/scan/new?target=${encodeURIComponent(targetUrl)}`}
                className="mt-3 inline-flex rounded-lg bg-amber-500/15 px-3 py-1.5 text-sm font-medium text-amber-100 hover:bg-amber-500/25"
              >
                Review target and retry
              </Link>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function formatExecutionBudget(value: any): string {
  if (!value || typeof value !== 'object') return 'None'
  const labels: Record<string, string> = {
    http_requests: 'HTTP requests',
    state_changing_requests: 'state changes',
    browser_actions: 'browser actions',
    tcp_ports_attempted: 'TCP attempts',
    hosts_attempted: 'hosts',
    tool_wall_seconds: 'seconds',
  }
  const entries = Object.entries(value)
    .map(([name, amount]) => [name, Number(amount)] as const)
    .filter(([, amount]) => Number.isFinite(amount) && amount > 0)
  if (!entries.length) return 'None'
  return entries
    .map(([name, amount]) => `${amount.toLocaleString()} ${labels[name] || name.replace(/_/g, ' ')}`)
    .join(' · ')
}

function executionStatusClass(status: string): string {
  if (status === 'success' || status === 'complete') return 'bg-green-500/10 text-green-300'
  if (status === 'failed' || status === 'blocked') return 'bg-red-500/10 text-red-300'
  if (status === 'partial' || status === 'timed_out' || status === 'complete_with_gaps') return 'bg-amber-500/10 text-amber-300'
  if (status === 'cancelled') return 'bg-gray-700 text-gray-300'
  if (status === 'running' || status === 'leased') return 'bg-blue-500/10 text-blue-300'
  return 'bg-gray-800 text-gray-400'
}

function ExecutionPlanCard({ scan }: { scan: any }) {
  const explanation = scan?.execution_explanation
  const actions = Array.isArray(explanation?.actions) ? explanation.actions : []
  const stages = Array.isArray(explanation?.stage_timeline) ? explanation.stage_timeline : []
  if (!actions.length) return null

  const coverage = explanation?.coverage || {}
  const matrix = coverage?.capability_coverage || {}
  const reliability = coverage?.grade_reliability || {}
  const parity = explanation?.transport_parity || {}
  const budget = explanation?.budget || {}
  const planRevision = explanation?.plan_revision || {}
  const completed = Number(matrix.completed || 0)
  const total = Number(matrix.total || Math.max(0, actions.length - 1))
  const hasGap = Number(matrix.partial || 0) + Number(matrix.blocked || 0) + Number(matrix.failed || 0) + Number(matrix.skipped || 0) > 0
  const apiRecordUrl = `${API_URL}/scans/${scan.id}/actions`

  return (
    <Card className="mb-6 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-gray-200">What this scan ran</h2>
          <p className="mt-1 text-xs text-gray-500">
            {completed} of {total} security capabilities completed
            {hasGap ? ' · coverage gaps are explained below' : ''}.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className={`rounded px-2 py-1 text-xs ${parity.consistent === false ? 'bg-red-500/10 text-red-300' : 'bg-green-500/10 text-green-300'}`}>
            {parity.consistent === false ? 'Execution record mismatch' : 'Same local / fleet contract'}
          </span>
          <a
            href={apiRecordUrl}
            target="_blank"
            rel="noreferrer"
            className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800"
          >
            Open execution record
          </a>
        </div>
      </div>

      <div className="mt-3 grid gap-2 text-[11px] text-gray-500 md:grid-cols-2">
        <div className="rounded border border-gray-800 bg-gray-950/50 p-2">
          <span className="text-gray-400">Plan:</span>{' '}
          <span className="font-mono">{String(explanation?.plan_digest || 'pending')}</span>
        </div>
        <div className="rounded border border-gray-800 bg-gray-950/50 p-2">
          <span className="text-gray-400">Plan version:</span>{' '}
          {String(planRevision.schema_version || explanation?.schema_version || 'unknown')}
          {planRevision.revision !== undefined ? ` · revision ${Number(planRevision.revision)}` : ''}
        </div>
        {planRevision.continuation_plan_digest && (
          <div className="rounded border border-gray-800 bg-gray-950/50 p-2 md:col-span-2">
            <span className="text-gray-400">Continuation:</span>{' '}
            <span className="font-mono">{String(planRevision.continuation_plan_digest)}</span>
          </div>
        )}
      </div>

      {reliability.reliable === false && (
        <div className="mt-3 rounded border border-amber-500/25 bg-amber-500/10 p-3">
          <div className="text-sm font-medium text-amber-200">Grade is provisional</div>
          <p className="mt-1 text-xs text-amber-100/80">
            {String(reliability.warning || 'Required coverage did not complete cleanly.')}
          </p>
          {Array.isArray(reliability.reason_labels) && reliability.reason_labels.length > 0 && (
            <p className="mt-1 text-xs text-amber-200/70">{reliability.reason_labels.join(' · ')}</p>
          )}
        </div>
      )}

      <div className="mt-4 grid gap-2 text-[11px] text-gray-500 md:grid-cols-2">
        <div className="rounded border border-gray-800 bg-gray-950/50 p-2">
          <span className="text-gray-400">Plan limit:</span> {formatExecutionBudget(budget.limit)}
        </div>
        <div className="rounded border border-gray-800 bg-gray-950/50 p-2">
          <span className="text-gray-400">Allocated:</span> {formatExecutionBudget(budget.allocated)}
        </div>
        <div className="rounded border border-gray-800 bg-gray-950/50 p-2">
          <span className="text-gray-400">Used:</span> {formatExecutionBudget(budget.consumed)}
        </div>
        <div className="rounded border border-gray-800 bg-gray-950/50 p-2">
          <span className="text-gray-400">Unused:</span> {formatExecutionBudget(budget.unallocated)}
        </div>
        {formatExecutionBudget(budget.uncertain) !== 'None' && (
          <div className="rounded border border-amber-500/25 bg-amber-500/10 p-2 text-amber-200 md:col-span-2">
            Uncertain after interrupted execution: {formatExecutionBudget(budget.uncertain)}
          </div>
        )}
      </div>

      <div className="mt-4 flex gap-2 overflow-x-auto pb-1">
        {stages.map((stage: any) => (
          <div key={String(stage.stage)} className="min-w-36 rounded border border-gray-800 bg-gray-950/50 p-2">
            <div className="text-xs font-medium text-gray-300">{String(stage.label || stage.stage)}</div>
            <div className="mt-1 flex items-center justify-between gap-2">
              <span className={`rounded px-1.5 py-0.5 text-[11px] ${executionStatusClass(String(stage.status || 'pending'))}`}>
                {String(stage.status || 'pending').replace(/_/g, ' ')}
              </span>
              <span className="text-[11px] text-gray-600">{Number(stage.action_count || 0)}</span>
            </div>
          </div>
        ))}
      </div>

      <details className="mt-4 rounded border border-gray-800 bg-gray-950/40">
        <summary className="cursor-pointer px-3 py-2 text-xs font-medium text-gray-300 hover:text-white">
          Capability details ({actions.length})
        </summary>
        <div className="divide-y divide-gray-800 border-t border-gray-800">
          {actions.map((action: any) => {
            const placement = action?.placement || {}
            const allocated = action?.budget?.allocated || {}
            const reserved = action?.budget?.reserved || {}
            const consumed = action?.budget?.consumed || {}
            const observationCount = Number(action?.observation?.count || 0)
            return (
              <div id={String(action.action_id)} key={String(action.action_id)} className="p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-medium text-gray-200">{String(action.label || action.action_id)}</span>
                  <span className={`rounded px-1.5 py-0.5 text-[11px] ${executionStatusClass(String(action.status || 'planned'))}`}>
                    {String(action.status || 'planned').replace(/_/g, ' ')}
                  </span>
                  {action.required && <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[11px] text-gray-400">required</span>}
                </div>
                {action.reason && <p className="mt-1 text-xs text-amber-300/80">{String(action.reason)}</p>}
                <div className="mt-2 grid gap-1 text-[11px] text-gray-500 md:grid-cols-2">
                  <div>
                    Ran on: {placement.backend ? String(placement.backend) : 'not assigned'}
                    {placement.worker_id ? ` · ${String(placement.worker_id)}` : ''}
                  </div>
                  <div>Evidence observations: {observationCount.toLocaleString()}</div>
                  <div className="break-words">Allocated: {formatExecutionBudget(allocated)}</div>
                  <div className="break-words">Reserved: {formatExecutionBudget(reserved)}</div>
                  <div className="break-words">Used: {formatExecutionBudget(consumed)}</div>
                </div>
              </div>
            )
          })}
        </div>
      </details>
    </Card>
  )
}

function ScanDetailContent() {
  const params = useParams()
  const searchParams = useSearchParams()
  const scanId = params.id as string
  const [scan, setScan] = useState<any | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [retryNonce, setRetryNonce] = useState(0)
  const [logs, setLogs] = useState<string[]>([])
  const [logsError, setLogsError] = useState<string | null>(null)
  const [buildVersion, setBuildVersion] = useState<string | null>(null)
  const [buildFingerprint, setBuildFingerprint] = useState<string | null>(null)
  const [deploymentDecision, setDeploymentDecision] = useState<DeploymentDecision | null>(null)
  const [deploymentDecisionLoading, setDeploymentDecisionLoading] = useState(false)
  const [targetFindings, setTargetFindings] = useState<Finding[]>([])
  const [targetFindingsTotal, setTargetFindingsTotal] = useState(0)
  const [targetFindingsLoading, setTargetFindingsLoading] = useState(false)
  const [targetFindingsError, setTargetFindingsError] = useState<string | null>(null)
  const logsRef = useRef<HTMLDivElement | null>(null)
  // Latest known scan status, read inside the polling interval so the "should we
  // keep polling?" decision always sees the current value (not a stale closure
  // capture). Kept in sync with `scan?.status` below.
  const statusRef = useRef<string | null>(null)

  // Build back URL with preserved filters
  const buildBackUrl = () => {
    const returnParams = new URLSearchParams()
    searchParams.forEach((value, key) => {
      if (key.startsWith('return_')) {
        returnParams.set(key.replace('return_', ''), value)
      }
    })
    const queryString = returnParams.toString()
    return queryString ? `/scans?${queryString}` : '/scans'
  }

  const backUrl = buildBackUrl()

  async function refreshDeploymentDecision() {
    setDeploymentDecisionLoading(true)
    try {
      setDeploymentDecision(await getScanDeploymentDecision(scanId))
    } catch {
      setDeploymentDecision(null)
    } finally {
      setDeploymentDecisionLoading(false)
    }
  }

  useEffect(() => {
    async function fetchScanAndLogs() {
      try {
        const data = await getScan(scanId)
        // Track the freshest status so the interval below polls correctly even
        // though this effect only runs once per scanId/retry.
        statusRef.current = data?.status ?? null
        setScan(data)
        setError(null)
        if (data?.target_id && ['completed', 'failed'].includes(String(data?.status))) {
          setTargetFindingsLoading(true)
          try {
            const findingData = await getFindings({
              target_id: data.target_id,
              limit: 100,
              sort_by: 'severity',
              sort_order: 'desc',
            })
            setTargetFindings(findingData.findings || [])
            setTargetFindingsTotal(findingData.total || 0)
            setTargetFindingsError(null)
          } catch {
            setTargetFindingsError('Could not load earlier findings for this target.')
          } finally {
            setTargetFindingsLoading(false)
          }
        }
        if (data?.status === 'completed' || data?.status === 'failed') {
          refreshDeploymentDecision()
        }
        try {
          const logData = await getScanLogs(scanId, 200)
          let nextLogs = logData?.lines || []
          const isDeviceScan = ['device_posture', 'device_probe'].includes(
            String(data?.run_kind || data?.scan_type),
          )
          if (isDeviceScan && nextLogs.length === 0) {
            try {
              nextLogs = deviceActivityLogLines(await getDeviceScanActivity(scanId))
            } catch {
              // The ordinary log endpoint remains authoritative when the
              // content-free device activity feed is unavailable.
            }
          }
          setLogs(nextLogs)
          setLogsError(null)
        } catch {
          setLogsError('Failed to load logs')
        }
      } catch (err) {
        setError('Failed to load scan details')
      } finally {
        setLoading(false)
      }
    }

    fetchScanAndLogs()
    // Read the live status from the ref (not a captured closure value) so polling
    // keeps running through status transitions and stops once terminal.
    const interval = setInterval(() => {
      if (statusRef.current === 'running' || statusRef.current === 'pending') {
        fetchScanAndLogs()
      }
    }, 5000)
    return () => clearInterval(interval)
  }, [scanId, retryNonce])

  useEffect(() => {
    getHealth()
      .then((h) => {
        setBuildVersion(h?.scanner_version || null)
        setBuildFingerprint(h?.build_fingerprint || null)
      })
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (logsRef.current) {
      logsRef.current.scrollTop = logsRef.current.scrollHeight
    }
  }, [logs])

  const renderScanActivityLogs = (live: boolean) => {
    const isModelIntake = scan?.run_kind === 'model_intake' || scan?.scan_type === 'model_intake'
    const title = isModelIntake ? 'Model Intake Activity' : live ? 'Live Logs' : 'Scan Logs'
    return (
      <Card className="p-4">
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-sm font-semibold text-gray-400">{title}</h2>
          <span className="text-xs text-gray-500">{logs.length} lines</span>
        </div>
        <div ref={logsRef} className="max-h-64 overflow-y-auto bg-black/30 rounded p-3 font-mono text-xs text-gray-300">
          {logs.length > 0 ? (
            logs.map((line, idx) => (
              <div key={idx} className="whitespace-pre-wrap break-words">
                {line}
              </div>
            ))
          ) : (
            <div className="text-gray-500">
              {isModelIntake ? 'No Model Intake activity has been recorded yet.' : 'No logs yet.'}
            </div>
          )}
        </div>
        {logsError && (
          <p className="text-red-400 text-xs mt-2">{logsError}</p>
        )}
      </Card>
    )
  }

  const renderStoredScanLogs = (open = false) => (
    <details open={open} className="rounded-lg border border-gray-800 bg-gray-900/50">
      <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-gray-300 hover:text-white">
        Scan execution log ({logs.length} lines)
      </summary>
      <div className="px-4 pb-4">{renderScanActivityLogs(false)}</div>
    </details>
  )

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    )
  }

  if (error || !scan) {
    return (
      <ErrorState
        message={error || 'Scan not found'}
        onRetry={() => {
          setLoading(true)
          setError(null)
          setRetryNonce((n) => n + 1)
        }}
      />
    )
  }

  const isModelIntake = scan.run_kind === 'model_intake' || scan.scan_type === 'model_intake'

  // Show progress bar while running
  if (scan.status === 'running' || scan.status === 'pending') {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <Link href={backUrl} className="text-gray-400 hover:text-white">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </Link>
          <h1 className="break-words text-2xl font-bold text-white">{boundedDisplayText(scan.target_url, 200)}</h1>
        </div>
        <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-6">
          <div className="flex items-center justify-between mb-3">
            <span className="text-blue-400 font-medium text-lg">
              {scan.status === 'pending'
                ? 'Waiting to start...'
                : `Scanning: ${(scan.current_phase || 'Processing').replace(/_/g, ' ')}`}
            </span>
            <span className="text-blue-400 text-xl font-bold">{scan.progress || 0}%</span>
          </div>
          <div className="w-full bg-blue-500/20 rounded-full h-3">
            <div
              className="bg-blue-500 h-3 rounded-full transition-all duration-500"
              style={{ width: `${scan.progress || 0}%` }}
            ></div>
          </div>
          <p className="text-gray-400 text-sm mt-4">
            The scan is in progress. This page will automatically update when complete.
          </p>
        </div>
        <ShardContextBanner scan={scan} />
        <ParallelShardRollup scan={scan} />
        <ParentCoverageRollup scan={scan} />
        <ExecutionPlanCard scan={scan} />

        {renderScanActivityLogs(true)}
      </div>
    )
  }

  // Show error for failed scans - but show partial results if available
  if (scan.status === 'failed') {
    const hasPartialResults = scan.result && (
      scan.result.dns || scan.result.tls || scan.result.http ||
      (scan.result.findings && scan.result.findings.length > 0)
    )
    const isPartial = scan.result?.scan_metadata?.partial === true

    // If we have partial results, show the report with a warning banner
    if (hasPartialResults) {
      return (
        <div>
          <PageHeader title={scan.target_url} backHref={backUrl} backLabel="Back to scans" />
          <ShardContextBanner scan={scan} />
          <FailedScanPanel scan={scan} hasPartialResults={true} />
          <ParallelShardRollup scan={scan} />
          <ParentCoverageRollup scan={scan} />
          <ExecutionPlanCard scan={scan} />
          {renderStoredScanLogs(true)}
          <ScanFindingContextCard scan={scan} targetFindings={targetFindings} targetFindingsTotal={targetFindingsTotal} loading={targetFindingsLoading} error={targetFindingsError} />
          <AiGateCampaignReviewCard scan={scan} />
          <DeploymentDecisionCard
            decision={deploymentDecision}
            loading={deploymentDecisionLoading}
            onRefresh={refreshDeploymentDecision}
          />
          <ReportView
            scan={scan}
            isAuthenticated={true}
            enableRemediationTracking={true}
          />
        </div>
      )
    }

    // No partial results - show error only
    return (
      <div className="space-y-6">
        <PageHeader title={scan.target_url} backHref={backUrl} backLabel="Back to scans" />
        <ShardContextBanner scan={scan} />
        <FailedScanPanel scan={scan} hasPartialResults={false} />
        <ParallelShardRollup scan={scan} />
        <ParentCoverageRollup scan={scan} />
        <ExecutionPlanCard scan={scan} />
        {renderStoredScanLogs(true)}
        <ScanFindingContextCard scan={scan} targetFindings={targetFindings} targetFindingsTotal={targetFindingsTotal} loading={targetFindingsLoading} error={targetFindingsError} />
      </div>
    )
  }

  // Show full report for completed scans
  if (isModelIntake) {
    return (
      <div>
        <PageHeader title="Model Intake report" backHref={backUrl} backLabel="Back to scans" />
        <ReportView
          scan={scan}
          isAuthenticated={true}
          enableRemediationTracking={true}
        />
        <div className="mt-6 space-y-3">
          <details className="rounded-lg border border-gray-800 bg-gray-900/50">
            <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-gray-300 hover:text-white">
              Corporate policy decision and exception details
            </summary>
            <div className="px-4 pb-4">
              <DeploymentDecisionCard
                decision={deploymentDecision}
                loading={deploymentDecisionLoading}
                onRefresh={refreshDeploymentDecision}
              />
            </div>
          </details>
          <details className="rounded-lg border border-gray-800 bg-gray-900/50">
            <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-gray-300 hover:text-white">
              Model Intake execution log ({logs.length} lines)
            </summary>
            <div className="px-4 pb-4">{renderScanActivityLogs(false)}</div>
          </details>
        </div>
      </div>
    )
  }

  return (
    <div>
      <PageHeader title={scan.target_url} backHref={backUrl} backLabel="Back to scans" />
      <ShardContextBanner scan={scan} />
      {scan.status === 'completed' && <ScanVerdictCard scan={scan} buildVersion={buildVersion} buildFingerprint={buildFingerprint} />}
      <ParallelShardRollup scan={scan} />
      <ParentCoverageRollup scan={scan} />
      <ExecutionPlanCard scan={scan} />
      {renderStoredScanLogs()}
      <ScanFindingContextCard scan={scan} targetFindings={targetFindings} targetFindingsTotal={targetFindingsTotal} loading={targetFindingsLoading} error={targetFindingsError} />
      <AiGateCampaignReviewCard scan={scan} />
      <DeploymentDecisionCard
        decision={deploymentDecision}
        loading={deploymentDecisionLoading}
        onRefresh={refreshDeploymentDecision}
      />
      <ReportView
        scan={scan}
        isAuthenticated={true}
        enableRemediationTracking={true}
      />
    </div>
  )
}

export default function ScanDetailPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    }>
      <ScanDetailContent />
    </Suspense>
  )
}
