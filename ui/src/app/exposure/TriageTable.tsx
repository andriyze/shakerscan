'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import {
  AlertTriangle,
  Bot,
  Boxes,
  ChevronRight,
  Clock3,
  ExternalLink,
  History,
  Loader2,
  Radar,
  RadioTower,
  ScanLine,
  ShieldAlert,
  ShieldOff,
  Target,
  X,
} from 'lucide-react'
import {
  getFindings,
  extractFindingTriage,
  updateFinding,
  type ExposureAsset,
  type ExposureAssetKind,
  type ExposureAssetMetrics,
  type Finding,
} from '@/lib/api'
import { FINDING_STATUSES, SEVERITY_BADGE_STYLES, type SeverityLevel } from '@/lib/constants'
import { gradeTextColor, useToast } from '@/components/ui'
import { ErrorState } from '@/components/ui'
import styles from './exposure.module.css'

const KIND_META: Record<ExposureAssetKind, { label: string; badge: string; icon: typeof Target }> = {
  web: { label: 'Web', badge: 'bg-blue-500/15 text-blue-300', icon: Target },
  ai: { label: 'AI', badge: 'bg-purple-500/15 text-purple-300', icon: Bot },
  model: { label: 'Model', badge: 'bg-slate-400/15 text-slate-300', icon: Boxes },
}

export const POSTURE_FILTERS = [
  { value: 'p1', label: 'P1' },
  { value: 'p2', label: 'P2' },
  { value: 'p3', label: 'P3' },
  { value: 'public', label: 'Public' },
  { value: 'internal', label: 'Internal' },
  { value: 'unscanned', label: 'Unscanned' },
  { value: 'failed', label: 'Failed' },
  { value: 'stale', label: 'Stale' },
  { value: 'incomplete', label: 'Incomplete' },
  { value: 'needs_verification', label: 'Needs verification' },
  { value: 'new', label: 'New' },
] as const

export type PostureFilter = (typeof POSTURE_FILTERS)[number]['value'] | 'all'

export const PRIORITY_STYLES: Record<string, string> = {
  P1: 'bg-red-500/20 text-red-300 border border-red-500/40',
  P2: 'bg-orange-500/15 text-orange-300 border border-orange-500/30',
  P3: 'bg-slate-500/15 text-slate-300 border border-slate-500/30',
}

const ACTION_LABELS: Record<string, string> = {
  never_scanned: 'Never scanned',
  stale_scan: 'Stale scan',
  incomplete_scan: 'Incomplete scan',
  critical_findings: 'Critical findings',
  high_findings: 'High findings',
  public_high_risk: 'Public high risk',
  production_ai_risk: 'Production AI risk',
  high_blast_radius: 'High blast radius',
  model_not_approved: 'Model not approved',
  failed_scan: 'Failed scan',
}

export function riskDot(asset: ExposureAsset): string {
  if (asset.active_critical > 0) return 'bg-red-500'
  if (asset.active_high > 0) return 'bg-orange-500'
  if (asset.active_total > 0) return 'bg-yellow-500'
  return 'bg-emerald-500/70'
}

function severityClass(severity?: string | null) {
  if (!severity) return 'bg-gray-700 text-gray-300'
  return SEVERITY_BADGE_STYLES[severity as SeverityLevel] ?? SEVERITY_BADGE_STYLES.info
}

function relativeTime(value?: string | null): string {
  if (!value) return 'never'
  const then = new Date(value).getTime()
  if (isNaN(then)) return 'never'
  const secs = Math.max(0, Math.floor((Date.now() - then) / 1000))
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`
  return `${Math.floor(secs / 86400)}d ago`
}

function postureMatches(asset: ExposureAsset, filter: PostureFilter): boolean {
  if (filter === 'all') return true
  if (filter === 'p1' || filter === 'p2' || filter === 'p3') return asset.action_priority === filter.toUpperCase()
  if (filter === 'public' || filter === 'internal') return asset.exposure_class === filter
  if (filter === 'unscanned') return (asset.action_reasons || []).includes('never_scanned')
  if (filter === 'failed') return (asset.action_reasons || []).includes('failed_scan')
  if (filter === 'stale') return (asset.action_reasons || []).includes('stale_scan')
  if (filter === 'incomplete') return Boolean(asset.scan_limited)
  if (filter === 'needs_verification') return (asset.active_needs_verification || 0) > 0
  if (filter === 'new') return Boolean(asset.is_new)
  return true
}

function actionLabel(reason: string): string {
  return ACTION_LABELS[reason] || reason.replace(/_/g, ' ')
}

function coverageLabel(asset: ExposureAsset): string {
  const posture = asset.coverage_posture || 'unknown'
  if (posture === 'fresh') return 'Fresh coverage'
  if (posture === 'limited') return 'Limited coverage'
  if (posture === 'failed') return 'Latest scan failed'
  if (posture === 'stale') return 'Stale coverage'
  if (posture === 'unscanned') return 'Never scanned'
  return 'Coverage unknown'
}

function coverageClass(asset: ExposureAsset): string {
  const posture = asset.coverage_posture
  if (posture === 'fresh') return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
  if (posture === 'limited' || posture === 'stale') return 'border-amber-400/30 bg-amber-400/10 text-amber-200'
  if (posture === 'failed' || posture === 'unscanned') return 'border-red-400/30 bg-red-400/10 text-red-200'
  return 'border-gray-700 bg-gray-800 text-gray-400'
}

function ExposureBadge({ asset }: { asset: ExposureAsset }) {
  const exposure = asset.exposure_class || 'unknown'
  const className =
    exposure === 'public'
      ? 'border-cyan-400/30 bg-cyan-400/10 text-cyan-200'
      : exposure === 'internal'
        ? 'border-slate-500/40 bg-slate-500/10 text-slate-300'
        : exposure === 'supply_chain'
          ? 'border-amber-400/30 bg-amber-400/10 text-amber-200'
          : 'border-gray-700 bg-gray-800 text-gray-400'
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] uppercase ${className}`}>
      <RadioTower className="h-2.5 w-2.5" aria-hidden="true" />
      {exposure === 'supply_chain' ? 'supply chain' : exposure}
    </span>
  )
}

export function PriorityBadge({ priority }: { priority?: string | null }) {
  if (!priority) return null
  return (
    <span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${PRIORITY_STYLES[priority] || 'bg-gray-700 text-gray-300'}`}>
      {priority}
    </span>
  )
}

const BLAST_STYLES: Record<string, string> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-300',
  high: 'border-purple-400/40 bg-purple-400/10 text-purple-200',
  medium: 'border-amber-400/30 bg-amber-400/10 text-amber-200',
  low: 'border-slate-500/30 bg-slate-500/10 text-slate-300',
}

// Blast radius is the defining AI-surface risk (the largest asset class here)
// and was previously only visible after expanding a row. Surface the tier and a
// missing-runtime-controls count inline so AI rows are triageable at a glance.
function BlastBadge({ asset }: { asset: ExposureAsset }) {
  const tier = asset.blast_radius_tier
  if (asset.kind !== 'ai' || !tier) return null
  const missing = (asset.missing_runtime_controls || []).length
  return (
    <span className="inline-flex items-center gap-1">
      <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] uppercase ${BLAST_STYLES[tier] || 'border-gray-700 bg-gray-800 text-gray-400'}`}>
        <RadioTower className="h-2.5 w-2.5" aria-hidden="true" />
        {tier} blast
      </span>
      {missing > 0 && (
        <span
          className="inline-flex items-center gap-1 rounded border border-amber-400/25 bg-amber-400/5 px-1.5 py-0.5 text-[10px] text-amber-200/90"
          title={(asset.missing_runtime_controls || []).join(', ')}
        >
          <ShieldOff className="h-2.5 w-2.5" aria-hidden="true" />
          {missing} missing
        </span>
      )}
    </span>
  )
}

// Compact posture for the collapsed row: priority + exposure + an issue count.
// Detail (reasons, coverage, blast, scan link) lives in the expanded row.
function RowPosture({ asset }: { asset: ExposureAsset }) {
  const issueCount = (asset.action_reasons || []).length
  return (
    <div className="mt-1 flex flex-wrap items-center gap-1.5">
      <PriorityBadge priority={asset.action_priority} />
      <ExposureBadge asset={asset} />
      <BlastBadge asset={asset} />
      {issueCount > 0 && (
        <span className="inline-flex items-center gap-1 text-[10px] text-gray-500">
          <AlertTriangle className="h-2.5 w-2.5" aria-hidden="true" />
          {issueCount} {issueCount === 1 ? 'issue' : 'issues'}
        </span>
      )}
    </div>
  )
}

function PostureDetail({ asset }: { asset: ExposureAsset }) {
  const reasons = asset.action_reasons || []
  // Blast tier is shown in the collapsed row now; the expanded detail adds the
  // *which* — the specific missing runtime controls and data sensitivity.
  const missingControls = asset.kind === 'ai' ? asset.missing_runtime_controls || [] : []
  const hasDetail =
    reasons.length > 0 || missingControls.length > 0 || asset.data_classification || asset.coverage_status || asset.latest_scan_href
  if (!hasDetail) return null
  return (
    <div className="flex flex-wrap items-center gap-1.5 border-b border-gray-800/40 px-4 py-2">
      {reasons.map((reason) => (
        <span key={reason} className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] uppercase text-gray-400">
          {actionLabel(reason)}
        </span>
      ))}
      {asset.data_classification && (
        <span className="rounded border border-fuchsia-400/25 bg-fuchsia-400/5 px-1.5 py-0.5 text-[10px] uppercase text-fuchsia-200/90">
          {asset.data_classification.replace(/_/g, ' ')}
        </span>
      )}
      {missingControls.map((control) => (
        <span
          key={control}
          className="inline-flex items-center gap-1 rounded border border-amber-400/25 bg-amber-400/5 px-1.5 py-0.5 text-[10px] text-amber-200/90"
        >
          <ShieldOff className="h-2.5 w-2.5" aria-hidden="true" />
          {control.replace(/_/g, ' ')}
        </span>
      ))}
      {asset.coverage_status && (
        <span className="rounded border border-gray-700 px-1.5 py-0.5 text-[10px] text-gray-500">coverage: {asset.coverage_status}</span>
      )}
      {asset.latest_scan_href && (
        <Link
          href={asset.latest_scan_href}
          className="ml-auto inline-flex items-center gap-1 rounded border border-gray-700 bg-gray-950 px-1.5 py-0.5 text-[10px] text-gray-400 hover:text-gray-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          <History className="h-2.5 w-2.5" aria-hidden="true" />
          {asset.latest_scan_type || 'scan'}
        </Link>
      )}
    </div>
  )
}

function AssetDetailDrawer({
  asset,
  onClose,
  onExplore,
  onScan,
  scanning,
}: {
  asset: ExposureAsset | null
  onClose: () => void
  onExplore: (nodeId: string) => void
  onScan: (asset: ExposureAsset) => void
  scanning: boolean
}) {
  const [findings, setFindings] = useState<Finding[] | null>(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    if (!asset) return
    setFindings(null)
    setError(false)
    let active = true
    const params =
      asset.kind === 'ai'
        ? { ai_target_id: asset.id, status: 'active', limit: 10, sort_by: 'severity' as const }
        : { target_id: asset.id, status: 'active', limit: 10, sort_by: 'severity' as const }
    getFindings(params)
      .then((res) => {
        if (active) setFindings(res.findings || [])
      })
      .catch(() => {
        if (active) setError(true)
      })
    return () => {
      active = false
    }
  }, [asset])

  if (!asset) return null
  const KindIcon = KIND_META[asset.kind].icon
  const recommended = asset.recommended_actions || []
  const verificationTotal = (asset.active_verified || 0) + (asset.active_needs_verification || 0)
  const verifiedPct = verificationTotal > 0 ? Math.round(((asset.active_verified || 0) / verificationTotal) * 100) : null

  return (
    <div className="fixed inset-0 z-40 bg-black/60" role="dialog" aria-modal="true" aria-label={`Asset details for ${asset.label}`}>
      <button type="button" className="absolute inset-0 cursor-default" aria-label="Close asset details backdrop" onClick={onClose} />
      <aside className="absolute right-0 top-0 flex h-full w-full max-w-xl flex-col border-l border-gray-800 bg-gray-950 shadow-2xl">
        <div className={`flex items-start justify-between gap-3 p-4 ${styles.moduleHeader}`}>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <KindIcon className="h-4 w-4 shrink-0 text-gray-500" aria-hidden="true" />
              <h2 className={`${styles.displayTitle} truncate text-base text-white`}>{asset.label}</h2>
              <PriorityBadge priority={asset.action_priority} />
            </div>
            <div className="mt-1 break-all text-xs text-gray-500">{asset.url || asset.root_domain || asset.origin}</div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close asset details"
            className="rounded p-1 text-gray-400 hover:bg-gray-800 hover:text-gray-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-auto p-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded border border-gray-800 bg-black/20 p-3">
              <div className="text-[10px] uppercase tracking-wide text-gray-600">Risk</div>
              <div className="mt-1 flex items-baseline gap-2">
                {asset.active_critical > 0 && <span className="text-lg font-semibold text-red-300">{asset.active_critical}C</span>}
                {asset.active_high > 0 && <span className="text-lg font-semibold text-orange-300">{asset.active_high}H</span>}
                {asset.active_total === 0 && <span className="text-lg font-semibold text-emerald-300">Clean</span>}
                {asset.grade && <span className={`ml-auto ${styles.displayTitle} text-lg ${gradeTextColor(asset.grade)}`}>{asset.grade}</span>}
              </div>
            </div>
            <div className="rounded border border-gray-800 bg-black/20 p-3">
              <div className="text-[10px] uppercase tracking-wide text-gray-600">Validation</div>
              <div className="mt-1 text-sm text-gray-200">
                {(asset.active_verified || 0)} verified · {(asset.active_needs_verification || 0)} need review
              </div>
              {verifiedPct !== null && <div className="mt-1 text-[11px] text-gray-500">{verifiedPct}% verified signal</div>}
            </div>
            <div className="rounded border border-gray-800 bg-black/20 p-3">
              <div className="text-[10px] uppercase tracking-wide text-gray-600">Coverage</div>
              <div className={`mt-1 inline-flex rounded border px-2 py-0.5 text-xs ${coverageClass(asset)}`}>{coverageLabel(asset)}</div>
              <div className="mt-1 text-[11px] text-gray-500">
                {asset.latest_scan_type || 'No scan'} · {relativeTime(asset.last_scanned_at)}
              </div>
            </div>
            <div className="rounded border border-gray-800 bg-black/20 p-3">
              <div className="text-[10px] uppercase tracking-wide text-gray-600">Exposure</div>
              <div className="mt-1 flex flex-wrap gap-1.5">
                <ExposureBadge asset={asset} />
                <BlastBadge asset={asset} />
              </div>
            </div>
          </div>

          {recommended.length > 0 && (
            <section className="rounded border border-teal-400/20 bg-teal-400/5 p-3">
              <div className="text-[10px] uppercase tracking-wide text-teal-300">Recommended next actions</div>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {recommended.map((action) => (
                  <span key={action} className="rounded bg-gray-900 px-2 py-1 text-xs text-gray-200">{action}</span>
                ))}
              </div>
            </section>
          )}

          <section className="rounded border border-gray-800 bg-black/20">
            <div className={`flex items-center justify-between gap-2 px-3 py-2 ${styles.moduleHeader}`}>
              <div>
                <div className="text-[10px] uppercase tracking-wide text-gray-500">Asset facts</div>
              </div>
            </div>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-2 p-3 text-xs">
              <div><dt className="text-gray-600">Domain</dt><dd className="truncate text-gray-200">{asset.root_domain || asset.origin || 'n/a'}</dd></div>
              <div><dt className="text-gray-600">Kind</dt><dd className="text-gray-200">{KIND_META[asset.kind].label}</dd></div>
              <div><dt className="text-gray-600">Scans</dt><dd className="text-gray-200">{asset.total_scans ?? 0}</dd></div>
              <div><dt className="text-gray-600">First seen</dt><dd className="text-gray-200">{relativeTime(asset.first_seen_at)}</dd></div>
              <div><dt className="text-gray-600">Skipped modules</dt><dd className="text-gray-200">{asset.skipped_modules_count ?? 0}</dd></div>
              <div><dt className="text-gray-600">Capped lists</dt><dd className="text-gray-200">{asset.capped_lists_count ?? 0}</dd></div>
              {asset.data_classification && <div><dt className="text-gray-600">Data</dt><dd className="truncate text-gray-200">{asset.data_classification}</dd></div>}
              {asset.risk_tier && <div><dt className="text-gray-600">Risk tier</dt><dd className="text-gray-200">{asset.risk_tier}</dd></div>}
            </dl>
          </section>

          <section className="rounded border border-gray-800 bg-black/20">
            <div className={`flex items-center justify-between gap-2 px-3 py-2 ${styles.moduleHeader}`}>
              <div className="text-[10px] uppercase tracking-wide text-gray-500">Active findings</div>
              <Link href={asset.findings_href} className="text-[11px] text-blue-300 hover:text-blue-200">Open all</Link>
            </div>
            {error ? (
              <p className="p-3 text-xs text-gray-500">Could not load findings.</p>
            ) : !findings ? (
              <div className="space-y-2 p-3">
                {Array.from({ length: 3 }).map((_, i) => <div key={i} className="h-8 animate-pulse rounded bg-gray-800/60" />)}
              </div>
            ) : findings.length === 0 ? (
              <p className="p-3 text-xs text-gray-500">No active findings on this asset.</p>
            ) : (
              <div className="divide-y divide-gray-800/50">
                {findings.map((finding) => {
                  const triage = extractFindingTriage(finding)
                  const verdict = finding.last_verification_verdict || (triage?.verified ? 'verified' : triage?.needs_verification ? 'needs review' : null)
                  return (
                    <Link key={finding.id} href={`/findings/${finding.id}`} className="block px-3 py-2 hover:bg-gray-800/40 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
                      <div className="flex items-center gap-2">
                        <span className={`rounded px-1.5 py-0.5 text-[10px] uppercase ${severityClass(finding.severity)}`}>{finding.severity}</span>
                        <span className="min-w-0 flex-1 truncate text-xs text-gray-200">{finding.title}</span>
                      </div>
                      {verdict && <div className="mt-1 text-[10px] uppercase tracking-wide text-gray-600">{verdict.replace(/_/g, ' ')}</div>}
                    </Link>
                  )
                })}
              </div>
            )}
          </section>
        </div>

        <div className="flex flex-wrap gap-2 border-t border-gray-800 p-4">
          {asset.kind === 'web' && (
            <button
              type="button"
              onClick={() => onScan(asset)}
              disabled={scanning}
              className="inline-flex items-center gap-1 rounded border border-teal-400/30 bg-teal-400/10 px-3 py-1.5 text-xs text-teal-200 hover:bg-teal-400/20 disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              {scanning ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ScanLine className="h-3.5 w-3.5" />}
              Quick scan
            </button>
          )}
          <button
            type="button"
            onClick={() => { onExplore(asset.node_id); onClose() }}
            className="inline-flex items-center gap-1 rounded border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <Radar className="h-3.5 w-3.5" /> Explore map
          </button>
          {asset.latest_scan_href && (
            <Link href={asset.latest_scan_href} className="inline-flex items-center gap-1 rounded border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
              <History className="h-3.5 w-3.5" /> Latest scan
            </Link>
          )}
        </div>
      </aside>
    </div>
  )
}

function ActionQueue({
  assets,
  onScan,
  onExplore,
  scanningIds,
}: {
  assets: ExposureAsset[]
  onScan: (asset: ExposureAsset) => void
  onExplore: (nodeId: string) => void
  scanningIds: Set<string>
}) {
  const queue = [...assets.filter((asset) => asset.needs_action)]
    .sort((a, b) => (b.action_score || 0) - (a.action_score || 0))
    .slice(0, 6)
  if (queue.length === 0) return null
  const p1 = assets.filter((a) => a.action_priority === 'P1').length

  return (
    <div className={`${styles.module} ${styles.corners} overflow-hidden`}>
      <div className={`flex items-center justify-between gap-3 px-4 py-3 ${styles.moduleHeader}`}>
        <div>
          <h2 className={`${styles.displayTitle} text-sm text-white`}>Action queue</h2>
          <p className="mt-0.5 text-xs text-gray-500">Highest-priority assets to scan, triage, or review first.</p>
        </div>
        {p1 > 0 && (
          <span className="shrink-0 rounded bg-red-500/15 px-2 py-0.5 text-xs font-semibold text-red-300">{p1} P1</span>
        )}
      </div>
      <div className="grid divide-y divide-gray-800/60 lg:grid-cols-2 lg:divide-x lg:divide-y-0">
        {queue.map((asset) => (
          <div key={asset.node_id} className="flex min-w-0 items-center gap-3 p-3">
            <PriorityBadge priority={asset.action_priority} />
            <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${riskDot(asset)}`} aria-hidden="true" />
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm text-gray-100">{asset.label}</div>
              <div className="mt-1 flex flex-wrap gap-1.5">
                {(asset.action_reasons || []).slice(0, 3).map((reason) => (
                  <span key={reason} className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">
                    {actionLabel(reason)}
                  </span>
                ))}
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-1.5">
              {asset.kind === 'web' && (
                <button
                  type="button"
                  onClick={() => onScan(asset)}
                  disabled={scanningIds.has(asset.id)}
                  aria-label={`Start quick scan for ${asset.label}`}
                  className="rounded border border-teal-400/30 bg-teal-400/10 p-1.5 text-teal-200 hover:bg-teal-400/20 disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                >
                  {scanningIds.has(asset.id) ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ScanLine className="h-3.5 w-3.5" />}
                </button>
              )}
              <button
                type="button"
                onClick={() => onExplore(asset.node_id)}
                aria-label={`Explore ${asset.label}`}
                className="rounded border border-gray-700 p-1.5 text-gray-300 hover:bg-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
              >
                <Radar className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
              <Link
                href={asset.findings_href}
                aria-label={`Open findings for ${asset.label}`}
                className="rounded border border-gray-700 p-1.5 text-gray-300 hover:bg-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
              >
                <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
              </Link>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function InlineFindings({ asset }: { asset: ExposureAsset }) {
  const toast = useToast()
  const [findings, setFindings] = useState<Finding[] | null>(null)
  const [error, setError] = useState(false)
  const [busyId, setBusyId] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    const params =
      asset.kind === 'ai'
        ? { ai_target_id: asset.id, status: 'active', limit: 8, sort_by: 'severity' as const }
        : { target_id: asset.id, status: 'active', limit: 8, sort_by: 'severity' as const }
    getFindings(params)
      .then((res) => {
        if (active) setFindings(res.findings || [])
      })
      .catch(() => {
        if (active) setError(true)
      })
    return () => {
      active = false
    }
  }, [asset.id, asset.kind, asset.label])

  async function setStatus(finding: Finding, status: string) {
    setBusyId(finding.id)
    try {
      await updateFinding(finding.id, status)
      // The list shows active findings; drop this one unless it stays active.
      setFindings((prev) => (prev ? prev.filter((f) => f.id !== finding.id || status === 'active') : prev))
      toast.success(`Finding marked ${status.replace(/_/g, ' ')}`)
    } catch {
      toast.error('Failed to update finding')
    } finally {
      setBusyId(null)
    }
  }

  if (error) return <p className="px-4 py-3 text-xs text-gray-500">Could not load findings for this asset.</p>
  if (!findings) {
    return (
      <div className="space-y-2 px-4 py-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="h-7 animate-pulse rounded bg-gray-800/60" />
        ))}
      </div>
    )
  }
  if (findings.length === 0) {
    return <p className="px-4 py-3 text-xs text-gray-500">No active findings on this asset.</p>
  }

  return (
    <div className="divide-y divide-gray-800/40">
      {findings.map((finding) => (
        <div key={finding.id} className="flex items-center gap-3 px-4 py-2">
          <span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] uppercase ${severityClass(finding.severity)}`}>
            {finding.severity}
          </span>
          <Link
            href={`/findings/${finding.id}`}
            className="min-w-0 flex-1 truncate text-xs text-gray-200 hover:text-white focus:outline-none focus-visible:underline"
          >
            {finding.title}
          </Link>
          {busyId === finding.id ? (
            <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-gray-500" aria-hidden="true" />
          ) : (
            <select
              value={finding.status}
              onChange={(e) => setStatus(finding, e.target.value)}
              aria-label={`Set status for ${finding.title}`}
              className="shrink-0 rounded border border-gray-700 bg-gray-950 px-1.5 py-1 text-[11px] text-gray-300 focus:border-blue-500 focus:outline-none"
            >
              {FINDING_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s.replace(/_/g, ' ')}
                </option>
              ))}
            </select>
          )}
        </div>
      ))}
    </div>
  )
}

function AssetRow({
  asset,
  onExplore,
  onScan,
  onDetails,
  scanning,
}: {
  asset: ExposureAsset
  onExplore: (nodeId: string) => void
  onScan: (asset: ExposureAsset) => void
  onDetails: (asset: ExposureAsset) => void
  scanning: boolean
}) {
  const [open, setOpen] = useState(false)
  const KindIcon = KIND_META[asset.kind].icon

  const primaryAction =
    asset.kind === 'web'
      ? (
          <button
            type="button"
            onClick={() => onScan(asset)}
            disabled={scanning}
            className="inline-flex items-center gap-1 rounded border border-teal-400/30 bg-teal-400/10 px-2 py-1 text-[11px] text-teal-200 hover:bg-teal-400/20 disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            {scanning ? <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" /> : <ScanLine className="h-3 w-3" aria-hidden="true" />}
            Scan
          </button>
        )
      : (
          <Link
            href={asset.kind === 'ai' ? '/settings/ai-gate' : '/settings/model-intake'}
            className="inline-flex items-center gap-1 rounded border border-gray-700 px-2 py-1 text-[11px] text-gray-300 hover:bg-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <ScanLine className="h-3 w-3" aria-hidden="true" />
            {asset.kind === 'ai' ? 'Test' : 'Re-check'}
          </Link>
        )

  return (
    <div className="border-b border-gray-800/50 last:border-b-0">
      <div className="flex items-center gap-3 px-3 py-2.5">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          aria-controls={`findings-${asset.id}`}
          aria-label={`Toggle findings for ${asset.label}`}
          className="shrink-0 rounded p-0.5 text-gray-500 hover:text-gray-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          <ChevronRight className={`h-4 w-4 transition-transform ${open ? 'rotate-90' : ''}`} aria-hidden="true" />
        </button>
        <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${riskDot(asset)}`} aria-hidden="true" />

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <KindIcon className="h-3.5 w-3.5 shrink-0 text-gray-500" aria-hidden="true" />
            <span className="truncate text-sm text-gray-100">{asset.label}</span>
            <span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] uppercase ${KIND_META[asset.kind].badge}`}>
              {KIND_META[asset.kind].label}
            </span>
            {asset.is_new && (
              <span className="shrink-0 rounded bg-teal-400/15 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-teal-300">
                new
              </span>
            )}
            {asset.production_mode && (
              <span className="shrink-0 rounded bg-red-500/15 px-1.5 py-0.5 text-[10px] uppercase text-red-300">prod</span>
            )}
          </div>
          <div className="mt-0.5 truncate text-[11px] text-gray-600">
            {asset.root_domain || asset.origin || asset.url}
          </div>
          <RowPosture asset={asset} />
        </div>

        <div className="hidden w-28 shrink-0 items-center gap-2 text-xs sm:flex">
          {asset.active_critical > 0 && <span className="text-red-400">{asset.active_critical}C</span>}
          {asset.active_high > 0 && <span className="text-orange-400">{asset.active_high}H</span>}
          {asset.active_total === 0 && <span className="text-emerald-500/70">clean</span>}
          {asset.active_total > 0 && (asset.active_critical + asset.active_high) === 0 && (
            <span className="text-gray-500">{asset.active_total}</span>
          )}
        </div>

        <div className="hidden w-10 shrink-0 text-center md:block">
          {asset.grade ? (
            <span className={`${styles.displayTitle} text-base font-bold ${gradeTextColor(asset.grade)}`}>{asset.grade}</span>
          ) : (
            <span className="text-xs text-gray-600">—</span>
          )}
        </div>

        <div className="hidden w-24 shrink-0 text-right text-[11px] text-gray-600 lg:block">
          {relativeTime(asset.last_scanned_at)}
        </div>

        <div className="flex shrink-0 items-center gap-1.5">
          <button
            type="button"
            onClick={() => onDetails(asset)}
            aria-label={`Open details for ${asset.label}`}
            className="inline-flex items-center gap-1 rounded border border-blue-500/30 bg-blue-500/10 px-2 py-1 text-[11px] text-blue-200 hover:bg-blue-500/20 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            Details
          </button>
          {primaryAction}
          <Link
            href={asset.findings_href}
            aria-label="View findings"
            className="inline-flex items-center gap-1 rounded border border-gray-700 px-2 py-1 text-[11px] text-gray-300 hover:bg-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <ShieldAlert className="h-3 w-3" aria-hidden="true" />
            <span className="hidden lg:inline">Findings</span>
          </Link>
          <button
            type="button"
            onClick={() => onExplore(asset.node_id)}
            aria-label="Explore connections in the map"
            className="inline-flex items-center gap-1 rounded border border-gray-700 px-2 py-1 text-[11px] text-gray-300 hover:bg-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <Radar className="h-3 w-3" aria-hidden="true" />
            <span className="hidden lg:inline">Explore</span>
          </button>
        </div>
      </div>
      {open && (
        <div id={`findings-${asset.id}`} className="bg-black/30">
          <PostureDetail asset={asset} />
          <InlineFindings asset={asset} />
        </div>
      )}
    </div>
  )
}

export function TriageTable({
  assets,
  total,
  loading,
  error,
  onRetry,
  onExplore,
  onScan,
  onDetails,
  scanningIds,
  selectedAsset,
  onCloseDetails,
  kind,
  posture,
  onKindChange,
  onPostureChange,
}: {
  assets: ExposureAsset[]
  metrics?: ExposureAssetMetrics | null
  total?: number
  loading: boolean
  error: string | null
  onRetry: () => void
  onExplore: (nodeId: string) => void
  onScan: (asset: ExposureAsset) => void
  onDetails: (asset: ExposureAsset) => void
  scanningIds: Set<string>
  selectedAsset: ExposureAsset | null
  onCloseDetails: () => void
  kind: 'all' | ExposureAssetKind
  posture: PostureFilter
  onKindChange: (kind: 'all' | ExposureAssetKind) => void
  onPostureChange: (posture: PostureFilter) => void
}) {
  const [sortBy, setSortBy] = useState<'priority' | 'critical' | 'stale'>('priority')
  const [renderLimit, setRenderLimit] = useState(60)

  const filtered = useMemo(() => {
    const rows = assets.filter((a) => (kind === 'all' || a.kind === kind) && postureMatches(a, posture))
    const sorted = [...rows]
    if (sortBy === 'critical') sorted.sort((a, b) => b.active_critical - a.active_critical || b.active_high - a.active_high)
    else if (sortBy === 'stale') sorted.sort((a, b) => (b.scan_age_days ?? -1) - (a.scan_age_days ?? -1))
    return sorted
  }, [assets, kind, posture, sortBy])

  const visible = filtered.slice(0, renderLimit)
  const datasetTotal = total ?? assets.length

  // Mirror the page-level filter bar's active selections as removable chips so
  // the applied scope is visible (and clearable) from the list itself.
  const activeFilters: Array<{ key: string; label: string; clear: () => void }> = []
  if (kind !== 'all') {
    activeFilters.push({ key: 'kind', label: KIND_META[kind].label, clear: () => onKindChange('all') })
  }
  if (posture !== 'all') {
    const label = POSTURE_FILTERS.find((f) => f.value === posture)?.label ?? posture
    activeFilters.push({ key: 'posture', label, clear: () => onPostureChange('all') })
  }

  if (error) return <ErrorState message={error} onRetry={onRetry} />

  return (
    <div className="space-y-3">
      <ActionQueue assets={assets} onScan={onScan} onExplore={onExplore} scanningIds={scanningIds} />

      {/* Kind + posture filtering lives in the page-level Filter inventory bar
          (single source of truth). Here we mirror the active filters as
          removable chips and keep only sort, which is list-local. */}
      <div className="flex flex-wrap items-center gap-3">
        {activeFilters.length > 0 ? (
          activeFilters.map((f) => (
            <button
              key={f.key}
              type="button"
              onClick={f.clear}
              aria-label={`Remove ${f.label} filter`}
              className="inline-flex items-center gap-1.5 rounded-md border border-teal-400/30 bg-teal-500/10 px-2.5 py-1 text-xs text-teal-200 hover:bg-teal-500/20 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              {f.label}
              <X className="h-3 w-3" aria-hidden="true" />
            </button>
          ))
        ) : (
          <span className="text-xs text-gray-600">All assets · filter from the bar above</span>
        )}
        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value as 'priority' | 'critical' | 'stale')}
          aria-label="Sort assets"
          className={`px-2 py-1.5 text-xs text-gray-300 ${styles.input}`}
        >
          <option value="priority">Sort: priority</option>
          <option value="critical">Sort: most critical</option>
          <option value="stale">Sort: oldest scan</option>
        </select>
        <span className="ml-auto text-xs text-gray-500">
          Showing {Math.min(visible.length, filtered.length)} of {filtered.length}
          {filtered.length !== datasetTotal && ` · ${datasetTotal} total`}
        </span>
      </div>

      <div className={`${styles.module} ${styles.corners} overflow-hidden`}>
        <div className={`hidden items-center gap-3 px-3 py-2 text-[10px] uppercase tracking-wider text-gray-600 sm:flex ${styles.moduleHeader}`}>
          <span className="w-5 shrink-0" />
          <span className="w-2.5 shrink-0" />
          <span className="flex-1">Asset</span>
          <span className="w-28 shrink-0">Crit / High</span>
          <span className="hidden w-10 shrink-0 text-center md:block">Grade</span>
          <span className="hidden w-24 shrink-0 text-right lg:block">Scanned</span>
          <span className="shrink-0">Actions</span>
        </div>
        {loading ? (
          <div className="space-y-2 p-3">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="h-9 animate-pulse rounded bg-gray-800/50" />
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <p className="p-8 text-center text-sm text-gray-500">No assets match this filter.</p>
        ) : (
          <>
            {visible.map((asset) => (
              <AssetRow
                key={asset.node_id}
                asset={asset}
                onExplore={onExplore}
                onScan={onScan}
                onDetails={onDetails}
                scanning={scanningIds.has(asset.id)}
              />
            ))}
            {filtered.length > visible.length && (
              <button
                type="button"
                onClick={() => setRenderLimit((n) => n + 60)}
                className="w-full px-4 py-3 text-center text-xs text-teal-300 hover:bg-gray-800/40 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
              >
                Show {Math.min(60, filtered.length - visible.length)} more ({filtered.length - visible.length} hidden)
              </button>
            )}
          </>
        )}
      </div>
      <AssetDetailDrawer
        asset={selectedAsset}
        onClose={onCloseDetails}
        onExplore={onExplore}
        onScan={onScan}
        scanning={Boolean(selectedAsset && scanningIds.has(selectedAsset.id))}
      />
    </div>
  )
}
