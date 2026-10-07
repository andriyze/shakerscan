'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import Link from '@/components/WorkspaceLink'
import {
  AlertTriangle,
  Bot,
  Boxes,
  BrainCircuit,
  ChevronRight,
  Download,
  ExternalLink,
  History,
  Loader2,
  Radar,
  RadioTower,
  Pencil,
  ScanLine,
  ShieldAlert,
  ShieldOff,
  Target,
  UserPlus,
  X,
} from 'lucide-react'
import {
  getFindings,
  extractFindingTriage,
  updateTargetMetadata,
  type ExposureAsset,
  type ExposureAssetKind,
  type ExposureAssetMetrics,
  type Finding,
} from '@/lib/api'
import { SEVERITY_BADGE_STYLES, type SeverityLevel } from '@/lib/constants'
import {
  ActionMenu,
  ConfirmDialog,
  ErrorState,
  MenuItem,
  ROW_ACTION_REVEAL,
  buttonClasses,
  fieldClasses,
  gradeTextColor,
  useModalA11y,
  useToast,
} from '@/components/ui'

// Kinds are categories, not risk, so their badges stay neutral.
const KIND_META: Record<ExposureAssetKind, { label: string; badge: string; icon: typeof Target }> = {
  web: { label: 'Web', badge: 'bg-gray-800 text-gray-300', icon: Target },
  ai: { label: 'AI', badge: 'bg-gray-800 text-gray-300', icon: Bot },
  model: { label: 'Model', badge: 'bg-gray-800 text-gray-300', icon: Boxes },
}

const TAG = 'inline-flex items-center gap-1 rounded-sm px-1.5 py-0.5 text-[11px] leading-4'
const SUBHEADING = 'text-xs font-medium text-gray-400'

export const POSTURE_FILTERS = [
  { value: 'p1', label: 'P1' },
  { value: 'p2', label: 'P2' },
  { value: 'p3', label: 'P3' },
  { value: 'public', label: 'Public' },
  { value: 'public_critical', label: 'Public critical' },
  { value: 'internal', label: 'Internal' },
  { value: 'unscanned', label: 'Unscanned' },
  { value: 'failed', label: 'Failed' },
  { value: 'stale', label: 'Stale' },
  { value: 'incomplete', label: 'Incomplete' },
  { value: 'verified', label: 'Proven risk' },
  { value: 'needs_verification', label: 'Needs verification' },
  { value: 'unverified_high', label: 'Unverified high-impact' },
  { value: 'investigator_verified', label: 'Investigator verified' },
  { value: 'investigator_suspected', label: 'Investigator suspected' },
  { value: 'prod', label: 'Production' },
  { value: 'new', label: 'New (7d)' },
  { value: 'unowned', label: 'Unowned' },
] as const

export type PostureFilter = (typeof POSTURE_FILTERS)[number]['value'] | 'all'

export type TriageSort = 'priority' | 'critical' | 'stale'

export const PRIORITY_STYLES: Record<string, string> = {
  P1: 'bg-red-500/15 text-red-300',
  P2: 'bg-orange-500/15 text-orange-300',
  P3: 'bg-gray-800 text-gray-300',
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

// Single definition of "production AI surface", shared with the page so the
// "prod" posture, scan environment, and confirmation logic always agree: the
// explicit flag OR declared environment metadata.
export function isProductionAIAsset(asset: ExposureAsset): boolean {
  // The API emits environment normalized (trimmed/lowercased); compare
  // case-insensitively anyway so this can never drift from the API again.
  return asset.kind === 'ai' && (Boolean(asset.production_mode) || (asset.environment || '').toLowerCase() === 'production')
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

export function postureMatches(asset: ExposureAsset, filter: PostureFilter, newWindowDays?: number): boolean {
  if (filter === 'all') return true
  if (filter === 'p1' || filter === 'p2' || filter === 'p3') return asset.action_priority === filter.toUpperCase()
  if (filter === 'public' || filter === 'internal') return asset.exposure_class === filter
  if (filter === 'public_critical') return asset.exposure_class === 'public' && asset.active_critical > 0
  if (filter === 'unscanned') return (asset.action_reasons || []).includes('never_scanned')
  if (filter === 'failed') return (asset.action_reasons || []).includes('failed_scan')
  if (filter === 'stale') {
    // With a window (?posture=stale&window=30, set by the change strip), show
    // only assets that *crossed* the 30-day threshold inside that window —
    // the exact cohort the tile counted — instead of everything stale.
    if (newWindowDays && typeof asset.scan_age_days === 'number') {
      return asset.scan_age_days >= 30 && asset.scan_age_days <= 30 + newWindowDays
    }
    return (asset.action_reasons || []).includes('stale_scan')
  }
  if (filter === 'incomplete') return Boolean(asset.scan_limited)
  if (filter === 'verified') return (asset.active_verified || 0) > 0
  if (filter === 'needs_verification') return (asset.active_needs_verification || 0) > 0
  // High-impact slice of the (otherwise ~all-assets) needs-verification set:
  // unreviewed findings on an asset that also carries critical/high risk.
  if (filter === 'unverified_high') return (asset.active_needs_verification || 0) > 0 && asset.active_critical + asset.active_high > 0
  if (filter === 'investigator_verified') return (asset.investigator_verified_count || 0) > 0
  if (filter === 'investigator_suspected') return (asset.investigator_suspected_count || 0) > 0
  if (filter === 'prod') return Boolean(asset.production_mode) || (asset.environment || '').toLowerCase() === 'production'
  if (filter === 'new') {
    // The change strip links here with its own window (?window=30); fall back
    // to the server's 7-day is_new flag when no explicit window is given.
    if (newWindowDays && asset.first_seen_at) {
      const ageMs = Date.now() - new Date(asset.first_seen_at).getTime()
      return ageMs <= newWindowDays * 86400000
    }
    return Boolean(asset.is_new)
  }
  if (filter === 'unowned') return !asset.owner
  return true
}

function actionLabel(reason: string): string {
  return ACTION_LABELS[reason] || reason.replace(/_/g, ' ')
}

function csvCell(value: unknown): string {
  const s = value === null || value === undefined ? '' : String(value)
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

// Client-side inventory export: /exposure/assets already returns the full
// enriched asset list, so no dedicated backend export endpoint is needed.
function exportAssetsCsv(rows: ExposureAsset[]) {
  const header = [
    'label', 'kind', 'url', 'root_domain', 'owner', 'environment', 'exposure', 'priority', 'reasons',
    'coverage', 'critical', 'high', 'total_findings', 'grade', 'last_scanned_at',
  ]
  const lines = [header.join(',')]
  for (const a of rows) {
    lines.push(
      [
        a.label, a.kind, a.url || '', a.root_domain || a.origin || '', a.owner || '', a.environment || '',
        a.exposure_class || '',
        a.action_priority || '', (a.action_reasons || []).join('; '), a.coverage_posture || '',
        a.active_critical, a.active_high, a.active_total, a.grade || '', a.last_scanned_at || '',
      ].map(csvCell).join(',')
    )
  }
  const blob = new Blob([lines.join('\n')], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `exposure-assets-${new Date().toISOString().slice(0, 10)}.csv`
  link.click()
  URL.revokeObjectURL(url)
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

// Compact posture word for the table column; the drawer keeps the full label.
function coverageShortLabel(asset: ExposureAsset): string {
  const posture = asset.coverage_posture || 'unknown'
  if (posture === 'unscanned') return 'never'
  if (posture === 'unknown') return '—'
  return posture
}

function coverageClass(asset: ExposureAsset): string {
  const posture = asset.coverage_posture
  if (posture === 'fresh') return 'bg-emerald-500/10 text-emerald-300'
  if (posture === 'limited' || posture === 'stale') return 'bg-amber-400/10 text-amber-200'
  if (posture === 'failed' || posture === 'unscanned') return 'bg-red-400/10 text-red-200'
  return 'bg-gray-800 text-gray-400'
}

function ExposureBadge({ asset }: { asset: ExposureAsset }) {
  const exposure = asset.exposure_class || 'unknown'
  // Only supply-chain exposure is a warning; public/internal are facts about the asset.
  const className = exposure === 'supply_chain' ? 'bg-amber-400/10 text-amber-200' : 'bg-gray-800 text-gray-300'
  return (
    <span className={`${TAG} ${className}`}>
      <RadioTower className="h-2.5 w-2.5" aria-hidden="true" />
      {exposure === 'supply_chain' ? 'supply chain' : exposure}
    </span>
  )
}

export function PriorityBadge({ priority }: { priority?: string | null }) {
  if (!priority) return null
  return (
    <span className={`shrink-0 rounded-sm px-1.5 py-0.5 text-[11px] font-semibold leading-4 ${PRIORITY_STYLES[priority] || 'bg-gray-800 text-gray-300'}`}>
      {priority}
    </span>
  )
}

const BLAST_STYLES: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-300',
  high: 'bg-orange-500/10 text-orange-300',
  medium: 'bg-amber-400/10 text-amber-200',
  low: 'bg-gray-800 text-gray-300',
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
      <span className={`${TAG} ${BLAST_STYLES[tier] || 'bg-gray-800 text-gray-400'}`}>
        <RadioTower className="h-2.5 w-2.5" aria-hidden="true" />
        {tier} blast
      </span>
      {missing > 0 && (
        <span
          className={`${TAG} bg-amber-400/10 text-amber-200`}
          title={(asset.missing_runtime_controls || []).join(', ')}
        >
          <ShieldOff className="h-2.5 w-2.5" aria-hidden="true" />
          {missing} missing
        </span>
      )}
    </span>
  )
}

// Compact posture for the collapsed row: priority + exposure + the top reasons
// driving that priority, so P1/P2 rows self-explain without opening the drawer.
function RowPosture({ asset }: { asset: ExposureAsset }) {
  const reasons = asset.action_reasons || []
  const shown = reasons.slice(0, 2)
  const hidden = reasons.length - shown.length
  return (
    <div className="mt-1 flex flex-wrap items-center gap-1.5" title={reasons.length > 0 ? reasons.map(actionLabel).join(' · ') : undefined}>
      <PriorityBadge priority={asset.action_priority} />
      <ExposureBadge asset={asset} />
      <BlastBadge asset={asset} />
      <InvestigatorTierBadges asset={asset} />
      {shown.map((reason) => (
        <span key={reason} className={`${TAG} text-gray-400`}>
          <AlertTriangle className="h-2.5 w-2.5" aria-hidden="true" />
          {actionLabel(reason)}
        </span>
      ))}
      {hidden > 0 && <span className="text-[11px] text-gray-500">+{hidden} more</span>}
      {asset.owner ? (
        <span className={`${TAG} bg-gray-800 text-gray-300`}>{asset.owner}</span>
      ) : (
        <span className={`${TAG} bg-amber-400/10 text-amber-200`}>unowned</span>
      )}
    </div>
  )
}

function InvestigatorTierBadges({ asset }: { asset: ExposureAsset }) {
  const verified = asset.investigator_verified_count || 0
  const suspected = asset.investigator_suspected_count || 0
  if (verified === 0 && suspected === 0) return null
  return (
    <>
      {verified > 0 && (
        <span className={`${TAG} bg-emerald-500/10 text-emerald-300`} title="Deterministically verified investigator findings">
          {verified} verified
        </span>
      )}
      {suspected > 0 && (
        <span className={`${TAG} bg-amber-500/10 text-amber-300`} title="Evidence-backed investigator leads awaiting deterministic proof">
          {suspected} suspected
        </span>
      )}
    </>
  )
}

function AssetDetailDrawer({
  asset,
  onClose,
  onExplore,
  onScan,
  onInvestigate,
  scanning,
  onUpdated,
}: {
  asset: ExposureAsset | null
  onClose: () => void
  onExplore: (nodeId: string) => void
  onScan: (asset: ExposureAsset) => void
  onInvestigate: (asset: ExposureAsset) => Promise<void>
  scanning: boolean
  onUpdated: () => void
}) {
  const [findings, setFindings] = useState<Finding[] | null>(null)
  const [error, setError] = useState(false)
  const closeRef = useRef<HTMLButtonElement>(null)
  const panelRef = useRef<HTMLElement>(null)
  const toast = useToast()
  // Ownership is editable for web/model targets (AI surfaces manage it in AI
  // Gate settings). Local copy keeps the drawer current after a save without
  // waiting for the asset list to refetch.
  const [ownership, setOwnership] = useState<{ owner: string; environment: string; cohort: string }>({ owner: '', environment: '', cohort: '' })
  const [editingOwnership, setEditingOwnership] = useState(false)
  const [ownerInput, setOwnerInput] = useState('')
  const [envInput, setEnvInput] = useState('')
  const [cohortInput, setCohortInput] = useState('')
  const [savingOwnership, setSavingOwnership] = useState(false)
  const [autonomousLoading, setAutonomousLoading] = useState(false)

  useEffect(() => {
    if (!asset) return
    setFindings(null)
    setError(false)
    setOwnership({ owner: asset.owner || '', environment: asset.environment || '', cohort: asset.cohort || 'unclassified' })
    setEditingOwnership(false)
    setSavingOwnership(false)
    setAutonomousLoading(false)
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

  // Modal behaviour (focus trap, Escape close, focus restore, inert page
  // background) via the shared hook; the drawer is portaled to <body> so the
  // inert background can't disable the drawer itself.
  useModalA11y(Boolean(asset), panelRef, onClose, closeRef)

  if (!asset || typeof document === 'undefined') return null
  const KindIcon = KIND_META[asset.kind].icon
  const ownershipEditable = asset.kind !== 'ai'

  async function saveOwnership() {
    if (!asset) return
    setSavingOwnership(true)
    try {
      const owner = ownerInput.trim()
      const environment = envInput.trim()
      const cohort = cohortInput.trim()
      await updateTargetMetadata(asset.id, { owner, environment, cohort })
      setOwnership({ owner, environment, cohort })
      setEditingOwnership(false)
      toast.success('Ownership updated')
      onUpdated()
    } catch {
      toast.error('Failed to update ownership')
    } finally {
      setSavingOwnership(false)
    }
  }

  async function startAutonomousInvestigation() {
    if (!asset || asset.kind !== 'web' || autonomousLoading) return
    setAutonomousLoading(true)
    try {
      await onInvestigate(asset)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to open Hunt')
    } finally {
      setAutonomousLoading(false)
    }
  }

  const recommended = asset.recommended_actions || []
  const missingControls = asset.kind === 'ai' ? asset.missing_runtime_controls || [] : []
  const verified = asset.active_verified || 0
  const needsVerification = asset.active_needs_verification || 0

  // Map a recommendation to the action it performs, so it renders as a real
  // CTA. "scan" queues the kind-appropriate scan directly for every kind.
  function recTarget(rkind: string): { href?: string; onClick?: () => void } {
    if (rkind === 'findings') return { href: asset!.findings_href }
    if (rkind === 'deep_hunt') return { onClick: startAutonomousInvestigation }
    if (rkind === 'latest_scan' && asset!.latest_scan_href) return { href: asset!.latest_scan_href }
    if (rkind === 'scan') return { onClick: () => onScan(asset!) }
    return {}
  }

  return (
    <>
      {createPortal(
        <div className="fixed inset-0 z-40 bg-black/60" role="dialog" aria-modal="true" aria-label={`Asset details for ${asset.label}`}>
      <button type="button" className="absolute inset-0 cursor-default" aria-label="Close asset details backdrop" onClick={onClose} />
      <aside ref={panelRef} className="absolute right-0 top-0 flex h-full w-full max-w-xl flex-col border-l border-gray-800 bg-gray-950 shadow-2xl">
        <div className="flex items-start justify-between gap-3 border-b border-gray-800 p-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <KindIcon className="h-4 w-4 shrink-0 text-gray-500" aria-hidden="true" />
              <h2 className="truncate text-base font-semibold text-white">{asset.label}</h2>
              <PriorityBadge priority={asset.action_priority} />
            </div>
            <div className="mt-1 break-all text-xs text-gray-500">{asset.url || asset.root_domain || asset.origin}</div>
          </div>
          <button
            ref={closeRef}
            type="button"
            onClick={onClose}
            aria-label="Close asset details"
            className="rounded-sm p-1 text-gray-400 hover:bg-gray-800 hover:text-gray-200 focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-auto p-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-lg border border-gray-800 bg-gray-900 p-3">
              <div className={SUBHEADING}>Risk</div>
              <div className="mt-1 flex items-baseline gap-2">
                {asset.active_critical > 0 && <span className="text-lg font-semibold text-red-300">{asset.active_critical}C</span>}
                {asset.active_high > 0 && <span className="text-lg font-semibold text-orange-300">{asset.active_high}H</span>}
                {asset.active_total === 0 && <span className="text-lg font-semibold text-emerald-300">Clean</span>}
                {asset.grade && <span className={`ml-auto text-lg font-semibold ${gradeTextColor(asset.grade)}`}>{asset.grade}</span>}
              </div>
            </div>
            <div className="rounded-lg border border-gray-800 bg-gray-900 p-3">
              <div className={SUBHEADING}>Validation</div>
              <div className="mt-1 flex items-baseline gap-2">
                <span className={`text-lg font-semibold ${verified > 0 ? 'text-red-300' : 'text-gray-400'}`}>{verified}</span>
                <span className="text-xs text-gray-500">proven{verified === 1 ? '' : ''}</span>
              </div>
              <div className="mt-0.5 text-xs text-gray-500">
                {needsVerification > 0 ? `${needsVerification} unverified` : 'all findings reviewed'}
              </div>
              {(asset.investigator_verified_count || asset.investigator_suspected_count) ? (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  <InvestigatorTierBadges asset={asset} />
                </div>
              ) : null}
            </div>
            <div className="rounded-lg border border-gray-800 bg-gray-900 p-3">
              <div className={SUBHEADING}>Coverage</div>
              <div className={`mt-1 inline-flex rounded-sm px-1.5 py-0.5 text-xs ${coverageClass(asset)}`}>{coverageLabel(asset)}</div>
              <div className="mt-1 text-xs text-gray-500">
                {asset.latest_scan_type || 'No scan'} · {relativeTime(asset.last_scanned_at)}
              </div>
            </div>
            <div className="rounded-lg border border-gray-800 bg-gray-900 p-3">
              <div className={SUBHEADING}>Exposure</div>
              <div className="mt-1 flex flex-wrap gap-1.5">
                <ExposureBadge asset={asset} />
                <BlastBadge asset={asset} />
              </div>
            </div>
          </div>

          {recommended.length > 0 && (
            <section className="rounded-lg border border-gray-800 bg-gray-900 p-3">
              <div className={SUBHEADING}>Recommended next actions</div>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {recommended.map((action) => {
                  const target = recTarget(action.kind)
                  const actionable = buttonClasses('secondary', 'sm')
                  if (target.href) {
                    return (
                      <Link key={action.label} href={target.href} className={actionable}>
                        {action.label}
                      </Link>
                    )
                  }
                  if (target.onClick) {
                    return (
                      <button key={action.label} type="button" onClick={target.onClick} className={actionable}>
                        {action.label}
                      </button>
                    )
                  }
                  return (
                    <span key={action.label} className="rounded-md px-2 py-1 text-xs text-gray-300">
                      {action.label}
                    </span>
                  )
                })}
              </div>
            </section>
          )}

          {missingControls.length > 0 && (
            <section className="rounded-lg border border-amber-400/20 bg-amber-400/5 p-3">
              <div className="text-xs font-medium text-amber-300">Missing AI runtime controls</div>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {missingControls.map((control) => (
                  <span key={control} className={`${TAG} bg-amber-400/10 text-amber-200`}>
                    <ShieldOff className="h-3 w-3" aria-hidden="true" />
                    {control.replace(/_/g, ' ')}
                  </span>
                ))}
              </div>
            </section>
          )}

          <section className="rounded-lg border border-gray-800 bg-gray-900">
            <div className="flex items-center justify-between gap-2 border-b border-gray-800 px-3 py-2">
              <div>
                <div className={SUBHEADING}>Asset facts</div>
              </div>
              {ownershipEditable ? (
                <button
                  type="button"
                  onClick={() => {
                    setOwnerInput(ownership.owner)
                    setEnvInput(ownership.environment)
                    setCohortInput(ownership.cohort)
                    setEditingOwnership((v) => !v)
                  }}
                  className="inline-flex items-center gap-1 rounded-sm px-1.5 py-0.5 text-xs text-blue-400 hover:text-blue-300 focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
                >
                  <Pencil className="h-3 w-3" aria-hidden="true" />
                  {editingOwnership ? 'Cancel' : 'Edit ownership'}
                </button>
              ) : (
                <span className="text-xs text-gray-500">Ownership via AI Gate settings</span>
              )}
            </div>
            {editingOwnership && (
              <div className="flex flex-wrap items-end gap-2 border-b border-gray-800 p-3">
                <label className="flex flex-col gap-1 text-xs text-gray-400">
                  Owner
                  <input
                    type="text"
                    value={ownerInput}
                    onChange={(e) => setOwnerInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') void saveOwnership() }}
                    placeholder="team or person"
                    className={`${fieldClasses()} w-40`}
                  />
                </label>
                <label className="flex flex-col gap-1 text-xs text-gray-400">
                  Environment
                  <select
                    value={envInput}
                    onChange={(e) => setEnvInput(e.target.value)}
                    className={fieldClasses()}
                  >
                    <option value="">unset</option>
                    <option value="production">production</option>
                    <option value="staging">staging</option>
                    <option value="development">development</option>
                  </select>
                </label>
                <label className="flex flex-col gap-1 text-xs text-gray-400">
                  Executive cohort
                  <select
                    value={cohortInput}
                    onChange={(e) => setCohortInput(e.target.value)}
                    className={fieldClasses()}
                  >
                    <option value="unclassified">unclassified</option>
                    <option value="production">production</option>
                    <option value="staging">staging</option>
                    <option value="lab">lab</option>
                    <option value="demo">demo</option>
                    <option value="calibration">calibration</option>
                    <option value="internal">internal</option>
                  </select>
                </label>
                <button
                  type="button"
                  onClick={() => void saveOwnership()}
                  disabled={savingOwnership}
                  className={buttonClasses('primary', 'md')}
                >
                  {savingOwnership ? <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" /> : null}
                  Save
                </button>
              </div>
            )}
            <dl className="grid grid-cols-2 gap-x-4 gap-y-2 p-3 text-xs">
              <div><dt className="text-gray-500">Owner</dt><dd className={`truncate ${ownership.owner ? 'text-gray-200' : 'text-amber-200/80'}`}>{ownership.owner || 'Unassigned'}</dd></div>
              <div><dt className="text-gray-500">Environment</dt><dd className="truncate text-gray-200">{ownership.environment || 'n/a'}</dd></div>
              <div><dt className="text-gray-500">Cohort</dt><dd className="truncate text-gray-200">{ownership.cohort || 'unclassified'}</dd></div>
              <div><dt className="text-gray-500">Domain</dt><dd className="truncate text-gray-200">{asset.root_domain || asset.origin || 'n/a'}</dd></div>
              <div><dt className="text-gray-500">Kind</dt><dd className="text-gray-200">{KIND_META[asset.kind].label}</dd></div>
              <div><dt className="text-gray-500">Scans</dt><dd className="text-gray-200">{asset.total_scans ?? 0}</dd></div>
              <div><dt className="text-gray-500">First seen</dt><dd className="text-gray-200">{relativeTime(asset.first_seen_at)}</dd></div>
              <div><dt className="text-gray-500">Skipped modules</dt><dd className="text-gray-200">{asset.skipped_modules_count ?? 0}</dd></div>
              <div><dt className="text-gray-500">Capped lists</dt><dd className="text-gray-200">{asset.capped_lists_count ?? 0}</dd></div>
              {asset.data_classification && <div><dt className="text-gray-500">Data</dt><dd className="truncate text-gray-200">{asset.data_classification}</dd></div>}
              {asset.risk_tier && <div><dt className="text-gray-500">Risk tier</dt><dd className="text-gray-200">{asset.risk_tier}</dd></div>}
            </dl>
          </section>

          <section className="rounded-lg border border-gray-800 bg-gray-900">
            <div className="flex items-center justify-between gap-2 border-b border-gray-800 px-3 py-2">
              <div className={SUBHEADING}>Active findings</div>
              <Link href={asset.findings_href} className="text-xs text-blue-400 hover:text-blue-300">Open all</Link>
            </div>
            {error ? (
              <p className="p-3 text-xs text-gray-500">Could not load findings.</p>
            ) : !findings ? (
              <div className="space-y-2 p-3">
                {Array.from({ length: 3 }).map((_, i) => <div key={i} className="h-8 animate-pulse rounded-sm bg-gray-800/60" />)}
              </div>
            ) : findings.length === 0 ? (
              <p className="p-3 text-xs text-gray-500">No active findings on this asset.</p>
            ) : (
              <div className="divide-y divide-gray-800">
                {findings.map((finding) => {
                  const triage = extractFindingTriage(finding)
                  const verdict = finding.last_verification_verdict || (triage?.verified ? 'verified' : triage?.needs_verification ? 'needs review' : null)
                  return (
                    <Link key={finding.id} href={`/findings/${finding.id}`} className="block px-3 py-2 hover:bg-gray-800/40 focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500">
                      <div className="flex items-center gap-2">
                        <span className={`rounded-sm px-1.5 py-0.5 text-[10px] uppercase ${severityClass(finding.severity)}`}>{finding.severity}</span>
                        <span className="min-w-0 flex-1 truncate text-xs text-gray-200">{finding.title}</span>
                      </div>
                      {verdict && <div className="mt-1 text-xs text-gray-500">{verdict.replace(/_/g, ' ')}</div>}
                    </Link>
                  )
                })}
              </div>
            )}
          </section>
        </div>

        <div className="flex flex-wrap gap-2 border-t border-gray-800 p-4">
          <button
            type="button"
            onClick={() => onScan(asset)}
            disabled={scanning}
            className={buttonClasses('primary', 'sm')}
          >
            {scanning ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ScanLine className="h-3.5 w-3.5" />}
            {asset.kind === 'web' ? 'Run Scan' : asset.kind === 'ai' ? 'Run smoke test' : 'Re-check model'}
          </button>
          {asset.kind === 'web' && (
            <button
              type="button"
              onClick={() => void startAutonomousInvestigation()}
              disabled={autonomousLoading}
              className={buttonClasses('secondary', 'sm')}
            >
              {autonomousLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <BrainCircuit className="h-3.5 w-3.5" />}
              Open Hunt
            </button>
          )}
          <button
            type="button"
            onClick={() => { onExplore(asset.node_id); onClose() }}
            className={buttonClasses('secondary', 'sm')}
          >
            <Radar className="h-3.5 w-3.5" /> Explore map
          </button>
          {asset.latest_scan_href && (
            <Link href={asset.latest_scan_href} className={buttonClasses('ghost', 'sm')}>
              <History className="h-3.5 w-3.5" /> Latest scan
            </Link>
          )}
        </div>
      </aside>
        </div>,
        document.body
      )}
    </>
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
    <div className="overflow-hidden rounded-lg border border-gray-800 bg-gray-900">
      <div className="flex items-center justify-between gap-3 border-b border-gray-800 px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold text-gray-100">Action queue</h2>
          <p className="mt-0.5 text-xs text-gray-400">Highest-priority assets to scan, triage, or review first.</p>
        </div>
        {p1 > 0 && (
          <span className="shrink-0 rounded-sm bg-red-500/15 px-1.5 py-0.5 text-xs font-semibold tabular-nums text-red-300">{p1} P1</span>
        )}
      </div>
      {/* gap-px over the border color draws hairlines between cells in both layouts. */}
      <div className="grid gap-px bg-gray-800 lg:grid-cols-2">
        {queue.map((asset) => (
          <div key={asset.node_id} className="group/row flex min-w-0 items-center gap-3 bg-gray-900 px-4 py-3">
            <PriorityBadge priority={asset.action_priority} />
            <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${riskDot(asset)}`} aria-hidden="true" />
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm text-gray-100">{asset.label}</div>
              <div className="mt-1 flex flex-wrap gap-1.5">
                {(asset.action_reasons || []).slice(0, 3).map((reason) => (
                  <span key={reason} className={`${TAG} bg-gray-800 text-gray-400`}>
                    {actionLabel(reason)}
                  </span>
                ))}
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-1">
              <button
                type="button"
                onClick={() => onScan(asset)}
                disabled={scanningIds.has(asset.id)}
                aria-label={`Start scan for ${asset.label}`}
                className={`${buttonClasses('secondary', 'sm')} ${scanningIds.has(asset.id) ? '' : ROW_ACTION_REVEAL}`}
              >
                {scanningIds.has(asset.id) ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <ScanLine className="h-3.5 w-3.5" aria-hidden="true" />}
                Scan
              </button>
              <ActionMenu label={`More actions for ${asset.label}`}>
                <MenuItem icon={<Radar />} onSelect={() => onExplore(asset.node_id)}>Explore in map</MenuItem>
                <MenuItem icon={<ExternalLink />} href={asset.findings_href}>Open findings</MenuItem>
              </ActionMenu>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// Guardrail before fanning out scans: spell out what gets queued per asset
// class, how many jobs that is, and call out production AI surfaces.
function BulkScanConfirm({
  open,
  assets,
  busy,
  onConfirm,
  onCancel,
}: {
  open: boolean
  assets: ExposureAsset[]
  busy: boolean
  onConfirm: () => void
  onCancel: () => void
}) {
  const web = assets.filter((a) => a.kind === 'web').length
  const ai = assets.filter((a) => a.kind === 'ai').length
  const model = assets.filter((a) => a.kind === 'model').length
  const prodAI = assets.filter(isProductionAIAsset)
  return (
    <ConfirmDialog
      open={open}
      title={`Queue ${assets.length} scan${assets.length === 1 ? '' : 's'}?`}
      message={
        <div className="space-y-2 text-sm">
          <ul className="list-disc space-y-1 pl-5 text-gray-300">
            {web > 0 && <li>{web} web quick scan{web === 1 ? '' : 's'} — passive checks, ~1–2 min each</li>}
            {ai > 0 && <li>{ai} AI Gate smoke probe{ai === 1 ? '' : 's'} — sends test prompts to the target</li>}
            {model > 0 && <li>{model} model intake re-check{model === 1 ? '' : 's'} — re-runs the last intake policy</li>}
          </ul>
          {prodAI.length > 0 && (
            <p className="rounded-sm border border-red-500/30 bg-red-500/10 p-2 text-xs text-red-300">
              {prodAI.length === 1 ? '1 production AI surface' : `${prodAI.length} production AI surfaces`} (
              {prodAI.map((a) => a.label).join(', ')}) — probes will run against production.
            </p>
          )}
          <p className="text-xs text-gray-500">Each scan takes one worker slot from the queue.</p>
        </div>
      }
      confirmLabel="Queue scans"
      danger={prodAI.length > 0}
      busy={busy}
      onConfirm={onConfirm}
      onCancel={onCancel}
    />
  )
}

function AssetRow({
  asset,
  onExplore,
  onScan,
  onDetails,
  scanning,
  selected,
  onToggleSelect,
}: {
  asset: ExposureAsset
  onExplore: (nodeId: string) => void
  onScan: (asset: ExposureAsset) => void
  onDetails: (asset: ExposureAsset) => void
  scanning: boolean
  selected: boolean
  onToggleSelect: () => void
}) {
  const KindIcon = KIND_META[asset.kind].icon

  // Several assets can share a display label (e.g. repeated model artifact
  // URLs), so accessible names carry a short id to stay distinguishable.
  const shortId = asset.id.slice(0, 8)
  const a11yName = `${asset.label} (${shortId})`

  // One-click scan for every kind: web quick scan, AI Gate smoke probe, or
  // model intake re-check — the handler queues the right scan type.
  const scanLabel = asset.kind === 'web' ? 'Scan' : asset.kind === 'ai' ? 'Test' : 'Re-check'
  const primaryAction = (
    <button
      type="button"
      onClick={() => onScan(asset)}
      disabled={scanning}
      aria-label={`${scanLabel} ${a11yName}`}
      className={`${buttonClasses('secondary', 'sm')} ${scanning ? '' : ROW_ACTION_REVEAL}`}
    >
      {scanning ? <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" /> : <ScanLine className="h-3 w-3" aria-hidden="true" />}
      {scanLabel}
    </button>
  )

  return (
    <div className={`group/row flex items-center gap-3 border-b border-gray-800 px-4 py-2.5 transition-colors last:border-b-0 ${selected ? 'bg-blue-500/[0.06]' : 'hover:bg-gray-800/40'}`}>
      <input
        type="checkbox"
        checked={selected}
        onChange={onToggleSelect}
        aria-label={`Select ${a11yName}`}
        className="h-4 w-4 shrink-0 cursor-pointer accent-blue-500"
      />
      <button
        type="button"
        onClick={() => onDetails(asset)}
        aria-label={`Open details for ${a11yName}`}
        className="flex min-w-0 flex-1 items-center gap-3 rounded-sm text-left focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
      >
        <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${riskDot(asset)}`} aria-hidden="true" />

        <span className="min-w-0 flex-1">
          <span className="flex items-center gap-2">
            <KindIcon className="h-3.5 w-3.5 shrink-0 text-gray-500" aria-hidden="true" />
            <span className="truncate text-sm text-gray-100" title={asset.url || undefined}>{asset.label}</span>
            <span className={`${TAG} shrink-0 ${KIND_META[asset.kind].badge}`}>
              {KIND_META[asset.kind].label}
            </span>
            {asset.production_mode && (
              <span className={`${TAG} shrink-0 bg-red-500/15 text-red-300`}>prod</span>
            )}
          </span>
          <span className="mt-0.5 block truncate text-xs text-gray-500">
            {asset.root_domain || asset.origin || asset.url}
            {/* Model artifacts often repeat the same URL across submissions —
                short id + first-seen makes each instance identifiable. */}
            {asset.kind === 'model' && ` · ${shortId} · first seen ${relativeTime(asset.first_seen_at)}`}
          </span>
          <RowPosture asset={asset} />
        </span>

        <span className="hidden w-28 shrink-0 items-center gap-2 text-xs tabular-nums sm:flex">
          {asset.active_critical > 0 && <span className="text-red-400">{asset.active_critical}C</span>}
          {asset.active_high > 0 && <span className="text-orange-400">{asset.active_high}H</span>}
          {asset.active_total === 0 && <span className="text-emerald-500/70">clean</span>}
          {asset.active_total > 0 && (asset.active_critical + asset.active_high) === 0 && (
            <span className="text-gray-500">{asset.active_total}</span>
          )}
        </span>

        <span className="hidden w-10 shrink-0 text-center md:block">
          {asset.grade ? (
            <span className={`text-base font-semibold ${gradeTextColor(asset.grade)}`}>{asset.grade}</span>
          ) : (
            <span className="text-xs text-gray-600">—</span>
          )}
        </span>

        <span className="hidden w-24 shrink-0 flex-col items-end gap-0.5 lg:flex">
          <span className={`${TAG} ${coverageClass(asset)}`}>
            {coverageShortLabel(asset)}
          </span>
          <span className="text-[11px] text-gray-500">{relativeTime(asset.last_scanned_at)}</span>
        </span>

        <ChevronRight className="h-4 w-4 shrink-0 text-gray-600" aria-hidden="true" />
      </button>

      <div className="flex shrink-0 items-center gap-1">
        {primaryAction}
        <ActionMenu label={`More actions for ${a11yName}`}>
          <MenuItem icon={<ShieldAlert />} href={asset.findings_href}>View findings</MenuItem>
          <MenuItem icon={<Radar />} onSelect={() => onExplore(asset.node_id)}>Explore in map</MenuItem>
        </ActionMenu>
      </div>
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
  onInvestigate,
  onDetails,
  scanningIds,
  selectedAsset,
  onCloseDetails,
  kind,
  posture,
  sort,
  onKindChange,
  onPostureChange,
  onSortChange,
  onBulkScan,
  newWindowDays,
  query = '',
  onQueryChange,
}: {
  assets: ExposureAsset[]
  metrics?: ExposureAssetMetrics | null
  total?: number
  loading: boolean
  error: string | null
  onRetry: () => void
  onExplore: (nodeId: string) => void
  onScan: (asset: ExposureAsset) => void
  onInvestigate: (asset: ExposureAsset) => Promise<void>
  onDetails: (asset: ExposureAsset) => void
  scanningIds: Set<string>
  selectedAsset: ExposureAsset | null
  onCloseDetails: () => void
  kind: 'all' | ExposureAssetKind
  posture: PostureFilter
  sort: TriageSort
  onKindChange: (kind: 'all' | ExposureAssetKind) => void
  onPostureChange: (posture: PostureFilter) => void
  onSortChange: (sort: TriageSort) => void
  onBulkScan: (assets: ExposureAsset[]) => Promise<boolean>
  newWindowDays?: number
  query?: string
  onQueryChange?: (query: string) => void
}) {
  const sortBy = sort
  const [renderLimit, setRenderLimit] = useState(60)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [bulkOwnerOpen, setBulkOwnerOpen] = useState(false)
  const [bulkOwner, setBulkOwner] = useState('')
  const [assigningOwner, setAssigningOwner] = useState(false)
  const [bulkScanConfirmOpen, setBulkScanConfirmOpen] = useState(false)
  const [bulkScanning, setBulkScanning] = useState(false)
  const toast = useToast()

  // A selection made under one scope is invisible under another — clear it on
  // any filter change (kind/posture/query/window) AND whenever the dataset
  // itself reloads (domain change, refresh, post-action refetch), so stale
  // selections can't silently reappear and feed a bulk action.
  useEffect(() => {
    setSelectedIds(new Set())
  }, [kind, posture, query, newWindowDays, assets])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    const rows = assets.filter(
      (a) =>
        (kind === 'all' || a.kind === kind) &&
        postureMatches(a, posture, newWindowDays) &&
        (!q ||
          a.label.toLowerCase().includes(q) ||
          (a.url || '').toLowerCase().includes(q) ||
          (a.root_domain || '').toLowerCase().includes(q))
    )
    const sorted = [...rows]
    if (sortBy === 'critical') sorted.sort((a, b) => b.active_critical - a.active_critical || b.active_high - a.active_high)
    else if (sortBy === 'stale') sorted.sort((a, b) => (b.scan_age_days ?? -1) - (a.scan_age_days ?? -1))
    return sorted
  }, [assets, kind, posture, sortBy, newWindowDays, query])

  const visible = filtered.slice(0, renderLimit)
  const datasetTotal = total ?? assets.length

  const selectedAssets = useMemo(() => filtered.filter((a) => selectedIds.has(a.node_id)), [filtered, selectedIds])
  // Owner lives in targets.metadata_json, so AI surfaces (separate table,
  // managed in AI Gate settings) are excluded from bulk assignment.
  const selectedOwnable = selectedAssets.filter((a) => a.kind !== 'ai')
  const allVisibleSelected = visible.length > 0 && visible.every((a) => selectedIds.has(a.node_id))

  async function applyBulkOwner() {
    const owner = bulkOwner.trim()
    if (!owner || selectedOwnable.length === 0) return
    setAssigningOwner(true)
    try {
      const results = await Promise.allSettled(selectedOwnable.map((a) => updateTargetMetadata(a.id, { owner })))
      const ok = results.filter((result) => result.status === 'fulfilled').length
      const failed = results.length - ok
      if (ok > 0) toast.success(`Owner set on ${ok} asset${ok === 1 ? '' : 's'}${failed > 0 ? ` · ${failed} failed` : ''}`)
      else toast.error('Failed to assign owner')
    } finally {
      setAssigningOwner(false)
      setBulkOwnerOpen(false)
      setBulkOwner('')
      onRetry()
    }
  }

  function toggleSelect(nodeId: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(nodeId)) next.delete(nodeId)
      else next.add(nodeId)
      return next
    })
  }

  function toggleSelectAllVisible() {
    setSelectedIds((prev) => {
      if (allVisibleSelected) {
        const next = new Set(prev)
        visible.forEach((a) => next.delete(a.node_id))
        return next
      }
      return new Set([...prev, ...visible.map((a) => a.node_id)])
    })
  }

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
  if (query.trim() && onQueryChange) {
    activeFilters.push({ key: 'query', label: `Search: "${query.trim()}"`, clear: () => onQueryChange('') })
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
              className="inline-flex items-center gap-1.5 rounded-md border border-gray-700 bg-gray-800 px-2.5 py-1 text-xs font-medium text-gray-200 hover:border-gray-600 hover:text-white focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              {f.label}
              <X className="h-3 w-3" aria-hidden="true" />
            </button>
          ))
        ) : (
          <span className="text-xs text-gray-500">All assets · filter from the bar above</span>
        )}
        <select
          value={sortBy}
          onChange={(e) => onSortChange(e.target.value as TriageSort)}
          aria-label="Sort assets"
          className={`${fieldClasses()} py-1 text-xs`}
        >
          <option value="priority">Sort: priority</option>
          <option value="critical">Sort: most critical</option>
          <option value="stale">Sort: oldest scan</option>
        </select>
        <button
          type="button"
          onClick={() => exportAssetsCsv(selectedAssets.length > 0 ? selectedAssets : filtered)}
          disabled={filtered.length === 0}
          className={buttonClasses('secondary', 'sm')}
        >
          <Download className="h-3.5 w-3.5" aria-hidden="true" />
          Export CSV{selectedAssets.length > 0 ? ` (${selectedAssets.length})` : ''}
        </button>
        <span className="ml-auto text-xs tabular-nums text-gray-500">
          Showing {Math.min(visible.length, filtered.length)} of {filtered.length}
          {filtered.length !== datasetTotal && ` · ${datasetTotal} total`}
        </span>
      </div>

      {selectedAssets.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 rounded-lg border border-gray-700 bg-gray-900 px-3 py-2">
          <span className="mr-1 text-sm font-medium text-white">{selectedAssets.length} selected</span>
          <button
            type="button"
            onClick={() => setBulkScanConfirmOpen(true)}
            className={buttonClasses('secondary', 'sm')}
          >
            <ScanLine className="h-3 w-3" aria-hidden="true" />
            Scan selected ({selectedAssets.length})
          </button>
          {!bulkOwnerOpen ? (
            <button
              type="button"
              onClick={() => setBulkOwnerOpen(true)}
              disabled={selectedOwnable.length === 0}
              title={selectedOwnable.length === 0 ? 'AI surfaces manage ownership in AI Gate settings' : undefined}
              className={buttonClasses('secondary', 'sm')}
            >
              <UserPlus className="h-3 w-3" aria-hidden="true" />
              Assign owner ({selectedOwnable.length})
            </button>
          ) : (
            <span className="inline-flex items-center gap-1.5">
              <input
                type="text"
                value={bulkOwner}
                onChange={(e) => setBulkOwner(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') void applyBulkOwner() }}
                placeholder="team or person"
                autoFocus
                aria-label="Owner for selected assets"
                className={`${fieldClasses()} w-40 py-1 text-xs`}
              />
              <button
                type="button"
                onClick={() => void applyBulkOwner()}
                disabled={!bulkOwner.trim() || assigningOwner}
                className={buttonClasses('secondary', 'sm')}
              >
                {assigningOwner ? <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" /> : null}
                Set owner
              </button>
              <button
                type="button"
                onClick={() => { setBulkOwnerOpen(false); setBulkOwner('') }}
                className={buttonClasses('ghost', 'sm')}
              >
                Cancel
              </button>
            </span>
          )}
          <button
            type="button"
            onClick={() => exportAssetsCsv(selectedAssets)}
            className={buttonClasses('secondary', 'sm')}
          >
            <Download className="h-3 w-3" aria-hidden="true" />
            Export selection
          </button>
          <button
            type="button"
            onClick={() => setSelectedIds(new Set())}
            className={`${buttonClasses('ghost', 'sm')} ml-auto`}
          >
            <X className="h-3 w-3" aria-hidden="true" />
            Clear selection
          </button>
        </div>
      )}

      <div className="overflow-hidden rounded-lg border border-gray-800 bg-gray-900">
        <div className="hidden items-center gap-3 border-b border-gray-800 px-4 py-2.5 text-xs font-medium text-gray-400 sm:flex">
          <input
            type="checkbox"
            checked={allVisibleSelected}
            onChange={toggleSelectAllVisible}
            disabled={visible.length === 0}
            aria-label="Select all visible assets"
            className="h-4 w-4 shrink-0 cursor-pointer accent-blue-500"
          />
          <span className="w-2.5 shrink-0" />
          <span className="flex-1">Asset</span>
          <span className="w-28 shrink-0">Crit / High</span>
          <span className="hidden w-10 shrink-0 text-center md:block">Grade</span>
          <span className="hidden w-24 shrink-0 text-right lg:block">Coverage</span>
          <span className="w-4 shrink-0" aria-hidden="true" />
          <span className="w-[7.5rem] shrink-0"><span className="sr-only">Actions</span></span>
        </div>
        {loading ? (
          <div className="space-y-2 p-3">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="h-9 animate-pulse rounded-sm bg-gray-800/50" />
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
                selected={selectedIds.has(asset.node_id)}
                onToggleSelect={() => toggleSelect(asset.node_id)}
              />
            ))}
            {filtered.length > visible.length && (
              <button
                type="button"
                onClick={() => setRenderLimit((n) => n + 60)}
                className="w-full px-4 py-3 text-center text-xs font-medium text-blue-400 hover:bg-gray-800/40 hover:text-blue-300 focus:outline-hidden focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-500"
              >
                Show {Math.min(60, filtered.length - visible.length)} more ({filtered.length - visible.length} hidden)
              </button>
            )}
          </>
        )}
      </div>
      <BulkScanConfirm
        open={bulkScanConfirmOpen}
        assets={selectedAssets}
        busy={bulkScanning}
        onCancel={() => setBulkScanConfirmOpen(false)}
        onConfirm={async () => {
          setBulkScanning(true)
          try {
            // Clear the selection only once something was actually queued —
            // on total failure keep it for retry.
            const queued = await onBulkScan(selectedAssets)
            if (queued) setSelectedIds(new Set())
          } finally {
            setBulkScanning(false)
            setBulkScanConfirmOpen(false)
          }
        }}
      />
      <AssetDetailDrawer
        asset={selectedAsset}
        onClose={onCloseDetails}
        onExplore={onExplore}
        onScan={onScan}
        onInvestigate={onInvestigate}
        scanning={Boolean(selectedAsset && scanningIds.has(selectedAsset.id))}
        onUpdated={onRetry}
      />
    </div>
  )
}
