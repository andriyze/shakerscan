'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { Bot, Boxes, ChevronRight, Loader2, Radar, ScanLine, ShieldAlert, Target } from 'lucide-react'
import {
  getFindings,
  updateFinding,
  type ExposureAsset,
  type ExposureAssetKind,
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

const KIND_FILTERS: Array<{ value: 'all' | ExposureAssetKind; label: string }> = [
  { value: 'all', label: 'All' },
  { value: 'web', label: 'Web' },
  { value: 'ai', label: 'AI' },
  { value: 'model', label: 'Model' },
]

function riskDot(asset: ExposureAsset): string {
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

function InlineFindings({ asset }: { asset: ExposureAsset }) {
  const toast = useToast()
  const [findings, setFindings] = useState<Finding[] | null>(null)
  const [error, setError] = useState(false)
  const [busyId, setBusyId] = useState<string | null>(null)

  useEffect(() => {
    let active = true
    const params =
      asset.kind === 'ai'
        ? { source_type: 'ai' as const, status: 'active', limit: 8, sort_by: 'severity' as const, search: asset.label }
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
  scanning,
}: {
  asset: ExposureAsset
  onExplore: (nodeId: string) => void
  onScan: (asset: ExposureAsset) => void
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

        <div className="hidden w-20 shrink-0 text-right text-[11px] text-gray-600 lg:block">{relativeTime(asset.last_scanned_at)}</div>

        <div className="flex shrink-0 items-center gap-1.5">
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
      {open && <div className="bg-black/30">{<InlineFindings asset={asset} />}</div>}
    </div>
  )
}

export function TriageTable({
  assets,
  loading,
  error,
  onRetry,
  onExplore,
  onScan,
  scanningIds,
}: {
  assets: ExposureAsset[]
  loading: boolean
  error: string | null
  onRetry: () => void
  onExplore: (nodeId: string) => void
  onScan: (asset: ExposureAsset) => void
  scanningIds: Set<string>
}) {
  const [kind, setKind] = useState<'all' | ExposureAssetKind>('all')
  const [newOnly, setNewOnly] = useState(false)

  const filtered = useMemo(() => {
    return assets.filter((a) => (kind === 'all' || a.kind === kind) && (!newOnly || a.is_new))
  }, [assets, kind, newOnly])

  if (error) return <ErrorState message={error} onRetry={onRetry} />

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <div className={`inline-flex p-0.5 ${styles.input}`} role="tablist" aria-label="Asset kind">
          {KIND_FILTERS.map((f) => (
            <button
              key={f.value}
              type="button"
              role="tab"
              aria-selected={kind === f.value}
              onClick={() => setKind(f.value)}
              className={`rounded-md px-3 py-1 text-xs focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                kind === f.value ? 'bg-teal-500/20 text-teal-200' : 'text-gray-400 hover:text-white'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>
        <label className={`flex items-center gap-2 px-3 py-1.5 text-xs text-gray-300 ${styles.input}`}>
          <input
            type="checkbox"
            checked={newOnly}
            onChange={(e) => setNewOnly(e.target.checked)}
            className="rounded border-gray-700 bg-gray-800"
          />
          New only
        </label>
        <span className="text-xs text-gray-500">{filtered.length} assets · ranked by risk</span>
      </div>

      <div className={`${styles.module} ${styles.corners} overflow-hidden`}>
        <div className={`hidden items-center gap-3 px-3 py-2 text-[10px] uppercase tracking-wider text-gray-600 sm:flex ${styles.moduleHeader}`}>
          <span className="w-5 shrink-0" />
          <span className="w-2.5 shrink-0" />
          <span className="flex-1">Asset</span>
          <span className="w-28 shrink-0">Crit / High</span>
          <span className="hidden w-10 shrink-0 text-center md:block">Grade</span>
          <span className="hidden w-20 shrink-0 text-right lg:block">Scanned</span>
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
          filtered.map((asset) => (
            <AssetRow
              key={asset.node_id}
              asset={asset}
              onExplore={onExplore}
              onScan={onScan}
              scanning={scanningIds.has(asset.id)}
            />
          ))
        )}
      </div>
    </div>
  )
}
