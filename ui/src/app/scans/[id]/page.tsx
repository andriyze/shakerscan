'use client'

import { useEffect, useState, Suspense, useRef } from 'react'
import { useParams, useSearchParams } from 'next/navigation'
import Link from 'next/link'
import { getScan, getScanLogs, getHealth, getScanDeploymentDecision, formatDuration, type DeploymentDecision } from '@/lib/api'
import { SEVERITY_BADGE_STYLES, SEVERITY_LEVELS, type SeverityLevel } from '@/lib/constants'
import { Card, ErrorState, gradeTextColor } from '@/components/ui'
import ReportView from '@/components/ReportView'

function formatScanTypeLabel(scan: any): string {
  if (scan?.scan_type === 'ai_gate' || scan?.run_kind?.startsWith('ai_')) {
    return 'AI Gate'
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
  const hasGrade = Boolean(scan.grade)
  const hasScore = typeof scan.score === 'number'
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
        {(hasGrade || hasScore) && (
          <div className="flex items-baseline gap-3">
            {hasGrade && (
              <span className={`text-5xl font-bold ${gradeTextColor(scan.grade)}`}>
                {scan.grade}
              </span>
            )}
            {hasScore && (
              <span className="text-lg text-gray-400">{scan.score}/100</span>
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
  const blockingCount = Array.isArray(decision?.blocking_findings) ? decision.blocking_findings.length : 0
  const exceptionCount = Array.isArray(decision?.exceptions_applied) ? decision.exceptions_applied.length : 0
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
          <h2 className="text-sm font-semibold text-gray-300">Deployment Decision</h2>
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
      <div className="mt-3 flex flex-wrap gap-2 text-xs text-gray-500">
        <span>{blockingCount} blocking finding{blockingCount === 1 ? '' : 's'}</span>
        <span>{exceptionCount} exception{exceptionCount === 1 ? '' : 's'} applied</span>
        {decision?.expires_at && <span>expires {String(decision.expires_at)}</span>}
      </div>
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
  const strategy = scan.options?.parallel_strategy || scan.options?.shard_strategy
  const strategyBadge = strategy ? (
    <span className="px-2 py-1 rounded bg-blue-500/10 text-xs text-blue-300">
      {String(strategy)} strategy
    </span>
  ) : null

  // Pre-fan-out window: a parent has no shards yet while the plan stage runs
  // (notably the `coverage` strategy's discover-once recon pass). Show a clear
  // planning state instead of a confusing "0/0 terminal".
  if (shards.length === 0) {
    if (['running', 'pending', 'queued'].includes(scan.status)) {
      return (
        <Card className="p-4 mb-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-gray-300">Parallel Shards</h2>
              <p className="text-xs text-gray-500 mt-0.5">
                {strategy === 'coverage'
                  ? 'Discovering endpoints once, then sharding the worklist across the fleet…'
                  : 'Planning shards…'}
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
  return (
    <Card className="p-4 mb-6">
      <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
        <div>
          <h2 className="text-sm font-semibold text-gray-300">Parallel Shards</h2>
          <p className="text-xs text-gray-500 mt-0.5">
            {rollup.terminal || 0}/{rollup.total || scan.shards.length} terminal,
            {' '}{rollup.completed || 0} completed,
            {' '}{rollup.failed || 0} failed
          </p>
        </div>
        {scan.options?.parallel_strategy && (
          <span className="px-2 py-1 rounded bg-blue-500/10 text-xs text-blue-300">
            {String(scan.options.parallel_strategy)} strategy
          </span>
        )}
      </div>
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

  const assigned = coverageNumber(contribution.assigned_endpoints)
  const attempted = coverageNumber(contribution.attempted_endpoints)
  const selected = coverageNumber(contribution.active_endpoints_selected)
  const activeBudget = coverageNumber(contribution.active_max_seconds)
  const duration = coverageNumber(contribution.duration_seconds)
  const telemetry = coverageNumber(contribution.telemetry_shards)
  const contributing = coverageNumber(contribution.shards_with_contribution)
  const statusSummary = formatAttemptStatuses(contribution.attempt_statuses)

  return (
    <div className="mb-3 grid gap-2 text-xs sm:grid-cols-2 lg:grid-cols-4">
      <div className="rounded border border-gray-800 bg-gray-950/50 p-3">
        <div className="text-gray-500">Endpoint work</div>
        <div className="mt-1 text-gray-200">
          {attempted || selected || 0}{assigned ? ` / ${assigned} assigned` : ''}
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
        <span>{shard.current_phase || 'queued'}</span>
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
  const logsRef = useRef<HTMLDivElement | null>(null)

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
        setScan(data)
        setError(null)
        if (data?.status === 'completed' || data?.status === 'failed') {
          refreshDeploymentDecision()
        }
        if (data?.status === 'running' || data?.status === 'pending') {
          try {
            const logData = await getScanLogs(scanId, 200)
            setLogs(logData?.lines || [])
            setLogsError(null)
          } catch {
            setLogsError('Failed to load logs')
          }
        }
      } catch (err) {
        setError('Failed to load scan details')
      } finally {
        setLoading(false)
      }
    }

    fetchScanAndLogs()
    const interval = setInterval(() => {
      if (scan?.status === 'running' || scan?.status === 'pending') {
        fetchScanAndLogs()
      }
    }, 5000)
    return () => clearInterval(interval)
  }, [scanId, scan?.status, retryNonce])

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
          <h1 className="text-2xl font-bold text-white">{scan.target_url}</h1>
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
        <ParallelShardRollup scan={scan} />
        <ParentCoverageRollup scan={scan} />

        <Card className="p-4">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-sm font-semibold text-gray-400">Live Logs</h2>
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
              <div className="text-gray-500">No logs yet.</div>
            )}
          </div>
          {logsError && (
            <p className="text-red-400 text-xs mt-2">{logsError}</p>
          )}
        </Card>
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
          <div className="flex items-center gap-3 mb-4">
            <Link href={backUrl} className="text-gray-400 hover:text-white">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </Link>
            <span className="text-gray-500">Back to scans</span>
          </div>
          <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4 mb-6">
            <div className="flex items-start gap-3">
              <svg className="w-5 h-5 text-amber-400 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <div>
                <h3 className="text-amber-400 font-semibold">Partial Results</h3>
                <p className="text-amber-300/80 text-sm mt-1">
                  {scan.result?.scan_metadata?.terminated_reason || scan.error_message || 'Scan was terminated before completion.'}
                  {scan.result?.scan_metadata?.terminated_at_phase && (
                    <span className="block mt-1 text-amber-300/60">
                      Last checkpoint: {scan.result.scan_metadata.terminated_at_phase}
                    </span>
                  )}
                </p>
              </div>
            </div>
          </div>
          <ParallelShardRollup scan={scan} />
          <ParentCoverageRollup scan={scan} />
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
        <div className="flex items-center gap-3">
          <Link href={backUrl} className="text-gray-400 hover:text-white">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </Link>
          <h1 className="text-2xl font-bold text-white">{scan.target_url}</h1>
        </div>
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-6 text-red-400">
          <h2 className="text-lg font-semibold mb-2">Scan Failed</h2>
          <p>{scan.error_message || 'An unknown error occurred during the scan.'}</p>
        </div>
        <ParallelShardRollup scan={scan} />
        <ParentCoverageRollup scan={scan} />
      </div>
    )
  }

  // Show full report for completed scans
  return (
    <div>
      <div className="flex items-center gap-3 mb-4">
        <Link href={backUrl} className="text-gray-400 hover:text-white">
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
        </Link>
        <span className="text-gray-500">Back to scans</span>
      </div>
      {scan.status === 'completed' && <ScanVerdictCard scan={scan} buildVersion={buildVersion} buildFingerprint={buildFingerprint} />}
      <ParallelShardRollup scan={scan} />
      <ParentCoverageRollup scan={scan} />
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
