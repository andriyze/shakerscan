'use client'

import { Suspense, useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  BrainCircuit,
  CheckCircle2,
  Crosshair,
  ExternalLink,
  Play,
  Radar,
  RefreshCw,
  Repeat,
  Search,
  SlidersHorizontal,
  Sparkles,
  Trash2,
} from 'lucide-react'
import {
  getAsmActivity,
  getAsmCheckFamilies,
  getAsmEndpoints,
  getAsmDiff,
  getAsmGaps,
  getAsmPolicy,
  getDomains,
  getTarget,
  getTargetsGrouped,
  getWorkers,
  improveAsmTarget,
  pruneAsmInventory,
  reconAsmTarget,
  testAsmTarget,
  updateAsmPolicy,
  formatDate,
  type AsmActivity,
  type AsmActivityResponse,
  type AsmCheckFamily,
  type AsmConfig,
  type AsmCoverage,
  type AsmEndpoint,
  type AsmGaps,
  type AsmInventorySemantics,
  type AsmPolicy,
  type AsmSchedulerState,
  type AsmTimelineEvent,
  type HypothesisReportItem,
  type HypothesisSituationReport,
  type Target,
} from '@/lib/api'
import { boundedTargetDisplay } from '@/lib/targetChoices'
import { useUrlFilters } from '@/lib/useUrlFilters'
import { normalizeFamilyCoverage, safeRemediationHref } from '@/lib/deferredWorkContracts'
import {
  asmCoverageDenominator,
  currentCompletedVariantCount,
  resolvedCoverage,
} from '@/lib/asmCoverage'
import {
  Badge,
  Button,
  Card,
  ConfirmDialog,
  EmptyState,
  ErrorState,
  Skeleton,
  TableSkeleton,
  useToast,
} from '@/components/ui'
import { ApprovalReceiptField } from '@/components/ApprovalReceiptField'

interface AsmFilters {
  [key: string]: string | number | undefined
  target_id?: string
  domain?: string
  status?: string
}

const STATUS_OPTIONS = [
  { value: '', label: 'All statuses' },
  { value: 'untested', label: 'Untested' },
  { value: 'in_progress', label: 'In progress' },
  { value: 'tested', label: 'Tested' },
  { value: 'stale', label: 'Stale' },
  { value: 'gone', label: 'Gone' },
]

const STATUS_BADGE: Record<string, string> = {
  tested: 'bg-green-500/15 text-green-400',
  untested: 'bg-gray-700/50 text-gray-300',
  in_progress: 'bg-blue-500/15 text-blue-400',
  stale: 'bg-yellow-500/15 text-yellow-400',
  gone: 'bg-red-500/15 text-red-400',
}

const METHOD_BADGE: Record<string, string> = {
  GET: 'bg-sky-500/15 text-sky-400',
  POST: 'bg-emerald-500/15 text-emerald-400',
  PUT: 'bg-amber-500/15 text-amber-400',
  PATCH: 'bg-orange-500/15 text-orange-400',
  DELETE: 'bg-red-500/15 text-red-400',
}

const PROVENANCE_BADGE: Record<string, string> = {
  response_observed: 'bg-emerald-500/15 text-emerald-300',
  declared_or_imported: 'bg-violet-500/15 text-violet-300',
  scanner_discovered: 'bg-sky-500/15 text-sky-300',
  unknown: 'bg-gray-700/50 text-gray-300',
}

const REACHABILITY_BADGE: Record<string, string> = {
  reachable_observed: 'bg-emerald-500/15 text-emerald-300',
  unreachable_observed: 'bg-amber-500/15 text-amber-300',
  retired_unreachable: 'bg-red-500/15 text-red-300',
  not_checked: 'bg-gray-700/50 text-gray-300',
  inconclusive: 'bg-yellow-500/15 text-yellow-300',
}

function pct(coverage: number): string {
  return `${(coverage * 100).toFixed(1)}%`
}

// The ASM scheduling window is stored/evaluated in UTC; these helpers surface
// the local-time equivalent so users can schedule against their own clock.
const LOCAL_TZ =
  typeof Intl !== 'undefined' ? Intl.DateTimeFormat().resolvedOptions().timeZone : 'local'

function localOffsetLabel(): string {
  const off = -new Date().getTimezoneOffset() // minutes east of UTC
  const sign = off >= 0 ? '+' : '-'
  const abs = Math.abs(off)
  const h = Math.floor(abs / 60)
  const m = abs % 60
  return `UTC${sign}${h}${m ? ':' + String(m).padStart(2, '0') : ''}`
}

function utcHourToLocalLabel(h: number | null | undefined): string | null {
  if (h === null || h === undefined) return null
  const d = new Date()
  d.setUTCHours(((h % 24) + 24) % 24, 0, 0, 0)
  return `${String(d.getHours()).padStart(2, '0')}:00`
}

function nowLocalUtcLabel(): string {
  const d = new Date()
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())} local = ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`
}

function CoverageBar({ coverage }: { coverage: number }) {
  const width = Math.max(0, Math.min(100, coverage * 100))
  const color = width >= 80 ? 'bg-green-500' : width >= 30 ? 'bg-yellow-500' : 'bg-blue-500'
  return (
    <div className="h-2 w-full rounded-full bg-gray-800" role="presentation">
      <div className={`h-2 rounded-full ${color}`} style={{ width: `${width}%` }} />
    </div>
  )
}

function CoverageStat({ label, value, accent = '' }: { label: string; value: number | string; accent?: string }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-3">
      <div className={`text-xl font-semibold ${accent || 'text-white'}`}>{value}</div>
      <div className="text-xs text-gray-500">{label}</div>
    </div>
  )
}

// ---- Rollup view (no target selected) -------------------------------------

interface RollupRow {
  target: Target
  root_domain: string
}

function RollupView({
  domains,
  onSelect,
}: {
  domains: string[]
  onSelect: (targetId: string) => void
}) {
  const { filters, setFilter } = useUrlFilters<AsmFilters>()
  const [rows, setRows] = useState<RollupRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)

  const load = useCallback(() => {
    setLoading(true)
    setError(false)
    getTargetsGrouped({ sort_by: 'active_findings_count', sort_order: 'desc' })
      .then((data) => {
        const flat: RollupRow[] = []
        for (const d of data.domains) {
          if (d.root_target?.asm_coverage) flat.push({ target: d.root_target, root_domain: d.root_domain })
          for (const s of d.subdomains) {
            if (s.asm_coverage) flat.push({ target: s, root_domain: d.root_domain })
          }
        }
        flat.sort((a, b) => resolvedCoverage(a.target.asm_coverage) - resolvedCoverage(b.target.asm_coverage))
        setRows(flat)
      })
      .catch(() => setError(true))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const visible = filters.domain ? rows.filter((r) => r.root_domain === filters.domain) : rows

  if (loading) return <TableSkeleton />
  if (error) return <ErrorState message="Failed to load attack-surface inventory." onRetry={load} />

  return (
    <Card className="p-4 space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <select
          value={filters.domain ?? ''}
          onChange={(e) => setFilter('domain', e.target.value || undefined)}
          aria-label="Filter endpoints by domain"
          className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          <option value="">All domains</option>
          {domains.map((d) => (
            <option key={d} value={d}>{d}</option>
          ))}
        </select>
        <span className="text-xs text-gray-500">
          {visible.length} target{visible.length === 1 ? '' : 's'} with a persistent inventory
        </span>
        <Button variant="ghost" size="sm" className="ml-auto" onClick={load}>
          <RefreshCw className="h-4 w-4" /> Refresh
        </Button>
      </div>

      {visible.length === 0 ? (
        <EmptyState
          message="No attack-surface inventory yet"
          hint="Run a coverage scan on a target to populate its persistent endpoint inventory, then come back to track and close coverage over time."
        />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-xs uppercase text-gray-500">
                <th className="px-3 py-2 font-medium">Target</th>
                <th className="px-3 py-2 font-medium">Coverage</th>
                <th className="px-3 py-2 font-medium text-right">Completed / Route variants</th>
                <th className="px-3 py-2 font-medium text-right">Remaining</th>
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {visible.map(({ target }) => {
                const cov = target.asm_coverage!
                const denominator = asmCoverageDenominator(cov)
                const currentCoverage = resolvedCoverage(cov)
                const completed = currentCompletedVariantCount(cov)
                const remaining = Math.max(denominator.value - completed, 0)
                return (
                  <tr key={target.id} className="border-b border-gray-800/60 hover:bg-gray-800/30">
                    <td className="px-3 py-2">
                      <button
                        type="button"
                        onClick={() => onSelect(target.id)}
                        className="text-left text-blue-400 hover:text-blue-300"
                      >
                        {boundedTargetDisplay(target)}
                      </button>
                      <div className="text-xs text-gray-500">{target.root_domain}</div>
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-2">
                        <CoverageBar coverage={currentCoverage} />
                        <span className="w-12 shrink-0 text-right text-xs text-gray-400">{pct(currentCoverage)}</span>
                      </div>
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums text-gray-300">
                      {completed} / {denominator.value}
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums text-gray-400">{remaining}</td>
                    <td className="px-3 py-2 text-right">
                      <Button variant="secondary" size="sm" onClick={() => onSelect(target.id)}>
                        View
                      </Button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

// ---- Continuous testing policy card ---------------------------------------

const WEEKDAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

function NumField({
  label, value, onChange, min = 0, hint,
}: {
  label: string; value: number; onChange: (n: number) => void; min?: number; hint?: string
}) {
  return (
    <label className="block">
      <span className="text-xs text-gray-400">{label}</span>
      <input
        type="number"
        min={min}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-800 px-2 py-1 text-sm text-gray-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
      />
      {hint && <span className="text-[11px] text-gray-600">{hint}</span>}
    </label>
  )
}

const ASM_PRESETS: Array<{ key: string; label: string; description: string; config: Partial<AsmConfig> }> = [
  {
    key: 'safe',
    label: 'Safe',
    description: 'Slow, low-load coverage for production targets.',
    config: {
      batch_size: 50,
      stale_days: 30,
      min_interval_minutes: 120,
      daily_endpoint_cap: 500,
      recon_interval_hours: 168,
      exploit_depth: false,
      max_requests_per_hour_per_domain: 250,
      window_start_hour: null,
      window_end_hour: null,
      window_days: null,
    },
  },
  {
    key: 'balanced',
    label: 'Balanced',
    description: 'Default steady coverage for owned apps.',
    config: {
      batch_size: 100,
      stale_days: 21,
      min_interval_minutes: 60,
      daily_endpoint_cap: 2000,
      recon_interval_hours: 72,
      exploit_depth: false,
      max_requests_per_hour_per_domain: 1000,
      window_start_hour: null,
      window_end_hour: null,
      window_days: null,
    },
  },
  {
    key: 'lab',
    label: 'Lab',
    description: 'Higher budget for Juice Shop, crAPI, Honey, and staging labs.',
    config: {
      batch_size: 250,
      stale_days: 7,
      min_interval_minutes: 15,
      daily_endpoint_cap: 10000,
      recon_interval_hours: 24,
      exploit_depth: true,
      max_requests_per_hour_per_domain: 0,
      window_start_hour: null,
      window_end_hour: null,
      window_days: null,
    },
  },
]

type AsmCheckFamilyOption = {
  value: string
  label: string
  description: string
  riskLevel?: string
  disabled?: boolean
}

const FALLBACK_ASM_CHECK_FAMILY_OPTIONS: AsmCheckFamilyOption[] = [
  { value: 'all', label: 'All checks', description: 'Use the normal ASM active mix.' },
  { value: 'sqli', label: 'SQLi only · medium risk', description: 'Focus the next test batch on SQL injection.', riskLevel: 'medium' },
  { value: 'xss', label: 'XSS only · medium risk', description: 'Focus the next test batch on cross-site scripting.', riskLevel: 'medium' },
]

function formatRiskLevel(value?: string): string | null {
  const risk = String(value || '').trim().toLowerCase()
  return risk ? `${risk.replace(/_/g, ' ')} risk` : null
}

function riskBadgeClass(value?: string): string {
  const risk = String(value || '').trim().toLowerCase()
  if (risk === 'high') return 'bg-red-500/15 text-red-300'
  if (risk === 'medium') return 'bg-yellow-500/15 text-yellow-300'
  return 'bg-gray-800 text-gray-300'
}

function toAsmCheckFamilyOptions(
  families: AsmCheckFamily[] | undefined,
  allowed: string[] | undefined,
  defaultValue: string | undefined
): AsmCheckFamilyOption[] {
  const allowedNames = new Set((allowed && allowed.length ? allowed : ['all', 'sqli', 'xss']).map((v) => String(v)))
  const byName = new Map((families || []).map((family) => [family.name, family]))
  const defaultFamily = byName.get(defaultValue || 'all')
  const options: AsmCheckFamilyOption[] = [
    defaultFamily
      ? {
          value: defaultValue || 'all',
          label: defaultFamily.label || 'All checks',
          description: defaultFamily.description || 'Use the normal ASM active mix.',
          riskLevel: defaultFamily.risk_level,
        }
      : FALLBACK_ASM_CHECK_FAMILY_OPTIONS[0],
  ]

  allowedNames.forEach((name) => {
    if (name === (defaultValue || 'all')) return
    if (name === 'all') return
    const family = byName.get(name)
    if (family && family.runnable) {
      const riskLabel = formatRiskLevel(family.risk_level)
      options.push({
        value: family.name,
        label: `${family.label} only${riskLabel ? ` · ${riskLabel}` : ''}`,
        description: family.description,
        riskLevel: family.risk_level,
      })
      return
    }
    const fallback = FALLBACK_ASM_CHECK_FAMILY_OPTIONS.find((option) => option.value === name)
    if (fallback) options.push(fallback)
  })

  for (const family of families || []) {
    if (!family.is_active || family.runnable || allowedNames.has(family.name)) continue
    const riskLabel = formatRiskLevel(family.risk_level)
    options.push({
      value: `planned:${family.name}`,
      label: `${family.label} · planned · ${riskLabel || 'risk pending'} · unavailable`,
      description: family.description || 'Registered but not available for ASM endpoint batches yet.',
      riskLevel: family.risk_level,
      disabled: true,
    })
  }

  return options.length ? options : FALLBACK_ASM_CHECK_FAMILY_OPTIONS
}

function ContinuousCard({ targetId, targetUrl }: { targetId: string; targetUrl: string }) {
  const toast = useToast()
  const [policy, setPolicy] = useState<AsmPolicy | null>(null)
  const [cfg, setCfg] = useState<AsmConfig | null>(null)
  const [enabled, setEnabled] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false)

  const load = useCallback(() => {
    setError(false)
    getAsmPolicy(targetId)
      .then((p) => {
        setPolicy(p)
        setCfg(p.config)
        setEnabled(p.enabled)
      })
      .catch(() => setError(true))
  }, [targetId])

  useEffect(() => { load() }, [load])

  const save = async () => {
    if (!cfg) return
    if (enabled && !cfg.approval_receipt_id?.trim()) {
      toast.error('A current target-bound approval receipt is required to enable active background batches.')
      return
    }
    setSaving(true)
    try {
      const updated = await updateAsmPolicy(targetId, { enabled, config: cfg })
      setPolicy(updated)
      setCfg(updated.config)
      setEnabled(updated.enabled)
      toast.success(enabled ? 'Continuous ASM enabled' : 'Policy saved')
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to save policy')
    } finally {
      setSaving(false)
    }
  }

  const set = (patch: Partial<AsmConfig>) => setCfg((c) => (c ? { ...c, ...patch } : c))

  if (error) return <ErrorState message="Failed to load continuous policy." onRetry={load} />
  if (!cfg) return <Card className="p-4"><Skeleton className="h-6 w-48" /></Card>

  const toggleDay = (d: number) => {
    const days = new Set(cfg.window_days || [])
    days.has(d) ? days.delete(d) : days.add(d)
    set({ window_days: days.size ? Array.from(days).sort((a, b) => a - b) : null })
  }

  return (
    <Card className="p-4 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Repeat className="h-5 w-5 text-blue-400" />
          <h2 className="text-sm font-medium text-gray-300">Continuous testing</h2>
          <Badge className={enabled ? 'bg-green-500/15 text-green-400' : 'bg-gray-700/50 text-gray-400'}>
            {enabled ? 'on' : 'off'}
          </Badge>
        </div>
        <label className="inline-flex cursor-pointer items-center gap-2 text-sm text-gray-300">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            className="h-4 w-4 rounded border-gray-600 bg-gray-800"
          />
          Enable background dispatcher
        </label>
      </div>

      <p className="text-xs text-gray-500">
        When enabled, ShakerScan refreshes discovery and tests untested/stale endpoints in small
        background batches. It chooses one action at a time and respects the caps below. Active
        batches stop when their saved approval expires; recon remains passive.
      </p>

      {(enabled || Boolean(cfg.approval_receipt_id)) && (
        <div className="space-y-3">
          <label className="flex items-start gap-3 rounded-lg border border-amber-800/70 bg-amber-950/20 p-3 text-sm text-amber-100">
            <input
              className="mt-1"
              type="checkbox"
              checked={authorizationConfirmed}
              onChange={(event) => setAuthorizationConfirmed(event.target.checked)}
            />
            <span>I own or have explicit authorization to run recurring active checks against this target.</span>
          </label>
          <ApprovalReceiptField
            targetId={targetId}
            targetUrl={targetUrl}
            authorizationConfirmed={authorizationConfirmed}
            receiptId={cfg.approval_receipt_id || ''}
            onReceiptIdChange={(approval_receipt_id) => set({ approval_receipt_id: approval_receipt_id || null })}
            ttlMinutes={7 * 24 * 60}
            riskTier="active"
            required
          />
        </div>
      )}

      <div className="grid gap-2 sm:grid-cols-3">
        {ASM_PRESETS.map((preset) => (
          <button
            key={preset.key}
            type="button"
            onClick={() => set(preset.config)}
            className="rounded-lg border border-gray-800 bg-gray-900/70 p-3 text-left hover:border-blue-700 hover:bg-blue-950/20"
          >
            <div className="text-sm font-medium text-gray-200">{preset.label}</div>
            <div className="mt-1 text-xs text-gray-500">{preset.description}</div>
          </button>
        ))}
      </div>

      <div className="grid gap-3 rounded-lg border border-gray-800 bg-gray-950/60 p-3 sm:grid-cols-4">
        <CoverageStat label="Batch" value={cfg.batch_size} />
        <CoverageStat label="Daily cap" value={cfg.daily_endpoint_cap || '∞'} />
        <CoverageStat label="Recon every" value={`${cfg.recon_interval_hours}h`} />
        <CoverageStat label="Depth" value={cfg.exploit_depth ? 'Deep' : 'Standard'} accent={cfg.exploit_depth ? 'text-yellow-400' : 'text-gray-200'} />
      </div>

      <button
        type="button"
        onClick={() => setShowAdvanced((v) => !v)}
        className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-gray-200"
      >
        <SlidersHorizontal className="h-4 w-4" />
        {showAdvanced ? 'Hide advanced policy' : 'Advanced policy'}
      </button>

      {showAdvanced && (
        <div className="space-y-4 rounded-lg border border-gray-800 bg-gray-950/40 p-3">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <NumField label="Batch size" value={cfg.batch_size} min={1} onChange={(n) => set({ batch_size: n })} hint="endpoints / batch" />
            <NumField label="Re-test after (days)" value={cfg.stale_days} onChange={(n) => set({ stale_days: n })} hint="freshness TTL" />
            <NumField label="Min interval (min)" value={cfg.min_interval_minutes} min={5} onChange={(n) => set({ min_interval_minutes: n })} hint="between batches" />
            <NumField label="Daily cap" value={cfg.daily_endpoint_cap} onChange={(n) => set({ daily_endpoint_cap: n })} hint="0 = unlimited / 24h" />
            <NumField label="Recon every (h)" value={cfg.recon_interval_hours} onChange={(n) => set({ recon_interval_hours: n })} hint="0 = never" />
            <NumField label="Domain rate /h" value={cfg.max_requests_per_hour_per_domain} onChange={(n) => set({ max_requests_per_hour_per_domain: n })} hint="0 = unlimited" />
          </div>

          <div className="flex flex-wrap items-center gap-4">
            <label className="inline-flex items-center gap-2 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={cfg.exploit_depth}
                onChange={(e) => set({ exploit_depth: e.target.checked })}
                className="h-4 w-4 rounded border-gray-600 bg-gray-800"
              />
              Deeper active checks
            </label>
            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-400">Window (UTC h):</span>
              <input
                type="number" min={0} max={23} placeholder="start"
                aria-label="Coverage window start hour (UTC, 0-23)"
                value={cfg.window_start_hour ?? ''}
                onChange={(e) => set({ window_start_hour: e.target.value === '' ? null : Number(e.target.value) })}
                className="w-16 rounded border border-gray-700 bg-gray-800 px-2 py-1 text-sm text-gray-200"
              />
              <span className="text-gray-600">–</span>
              <input
                type="number" min={0} max={23} placeholder="end"
                aria-label="Coverage window end hour (UTC, 0-23)"
                value={cfg.window_end_hour ?? ''}
                onChange={(e) => set({ window_end_hour: e.target.value === '' ? null : Number(e.target.value) })}
                className="w-16 rounded border border-gray-700 bg-gray-800 px-2 py-1 text-sm text-gray-200"
              />
              {cfg.window_start_hour !== null && cfg.window_end_hour !== null ? (
                <span className="text-[11px] text-blue-300">
                  = {utcHourToLocalLabel(cfg.window_start_hour)}–{utcHourToLocalLabel(cfg.window_end_hour)} {LOCAL_TZ}
                </span>
              ) : (
                <span className="text-[11px] text-gray-600">blank = any</span>
              )}
            </div>
          </div>

          <p className="text-[11px] text-gray-500">
            Scheduling is in <span className="text-gray-400">UTC</span>. Your timezone:{' '}
            <span className="text-gray-400">{LOCAL_TZ} ({localOffsetLabel()})</span> — now {nowLocalUtcLabel()}.
            Days are UTC weekdays.
          </p>

          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-xs text-gray-400">Days:</span>
            {WEEKDAYS.map((d, i) => {
              const on = (cfg.window_days || []).includes(i)
              return (
                <button
                  key={d}
                  type="button"
                  onClick={() => toggleDay(i)}
                  className={`rounded px-2 py-0.5 text-xs ${on ? 'bg-blue-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'}`}
                >
                  {d}
                </button>
              )
            })}
            <span className="ml-1 text-[11px] text-gray-600">none = every day</span>
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-gray-800 pt-3">
        <div className="text-xs text-gray-500">
          Last recon: {policy?.last_recon_at ? formatDate(policy.last_recon_at) : '—'} · Last test:{' '}
          {policy?.last_test_at ? formatDate(policy.last_test_at) : '—'}
        </div>
        <Button size="sm" onClick={save} disabled={saving}>
          {saving ? 'Saving…' : 'Save policy'}
        </Button>
      </div>
    </Card>
  )
}

// ---- New-surface (diff) feed ----------------------------------------------

function NewSurfaceCard({ targetId }: { targetId: string }) {
  const [data, setData] = useState<{ total_new: number; endpoints: AsmEndpoint[] } | null>(null)
  const [loaded, setLoaded] = useState(false)

  useEffect(() => {
    getAsmDiff(targetId, { days: 7, limit: 50 })
      .then((d) => setData(d))
      .catch(() => setData(null))
      .finally(() => setLoaded(true))
  }, [targetId])

  if (!loaded || !data || data.total_new === 0) return null

  return (
    <Card className="p-4 space-y-3">
      <div className="flex items-center gap-2">
        <Radar className="h-5 w-5 text-yellow-400" />
        <h2 className="text-sm font-medium text-gray-300">New surface</h2>
        <Badge className="bg-yellow-500/15 text-yellow-400">{data.total_new} in 7 days</Badge>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <tbody>
            {data.endpoints.slice(0, 15).map((e) => (
              <tr key={e.id} className="border-b border-gray-800/60">
                <td className="px-2 py-1.5">
                  <Badge className={METHOD_BADGE[e.method] || 'bg-gray-700/50 text-gray-300'}>{e.method}</Badge>
                </td>
                <td className="px-2 py-1.5 font-mono text-xs text-gray-300">{e.path}</td>
                <td className="px-2 py-1.5 text-right text-xs text-gray-500">
                  {e.first_seen_at ? formatDate(e.first_seen_at) : ''}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function CoverageAdvisorCard({
  targetId,
  targetUrl,
  coverage,
  gaps,
  onRefresh,
  authorizationConfirmed,
  approvalReceiptId,
  onAuthorizationConfirmedChange,
  onApprovalReceiptIdChange,
}: {
  targetId: string
  targetUrl: string
  coverage: AsmCoverage | null
  gaps: AsmGaps | null
  onRefresh: () => void
  authorizationConfirmed: boolean
  approvalReceiptId: string
  onAuthorizationConfirmedChange: (confirmed: boolean) => void
  onApprovalReceiptIdChange: (receiptId: string) => void
}) {
  const toast = useToast()
  const [busy, setBusy] = useState<'improve' | 'recon' | 'prune' | null>(null)
  const [checkFamily, setCheckFamily] = useState('all')
  const [endpointFilter, setEndpointFilter] = useState('')
  const [checkFamilyOptions, setCheckFamilyOptions] = useState<AsmCheckFamilyOption[]>(FALLBACK_ASM_CHECK_FAMILY_OPTIONS)

  useEffect(() => {
    let cancelled = false
    getAsmCheckFamilies()
      .then((res) => {
        if (cancelled) return
        const options = toAsmCheckFamilyOptions(res.families, res.asm_focus_allowed, res.default)
        setCheckFamilyOptions(options)
        setCheckFamily((current) => (
          options.some((option) => option.value === current && !option.disabled) ? current : (res.default || 'all')
        ))
      })
      .catch(() => {
        if (!cancelled) setCheckFamilyOptions(FALLBACK_ASM_CHECK_FAMILY_OPTIONS)
      })
    return () => { cancelled = true }
  }, [])

  const queueImprove = async () => {
    setBusy('improve')
    try {
      const opts: { check_family?: string; endpoint_filter?: string; approval_receipt_id?: string } = {}
      if (checkFamily !== 'all') opts.check_family = checkFamily
      if (endpointFilter) opts.endpoint_filter = endpointFilter
      if (next === 'test' && approvalReceiptId) opts.approval_receipt_id = approvalReceiptId
      const res = await improveAsmTarget(targetId, Object.keys(opts).length ? opts : undefined)
      if (res.action === 'wait') {
        toast.success(res.reason || 'ASM work is already active for this target')
      } else {
        const focus = res.check_family && res.check_family !== 'all' ? ` (${res.check_family.toUpperCase()})` : ''
        toast.success(res.action === 'recon' ? 'Queued ASM discovery refresh' : `Queued ASM test batch${focus}`, {
          link: res.scan_id ? { href: `/scans/${res.scan_id}`, label: 'View activity' } : undefined,
        })
      }
      setTimeout(onRefresh, 700)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to improve coverage')
    } finally {
      setBusy(null)
    }
  }

  const queueRecon = async () => {
    setBusy('recon')
    try {
      const res = await reconAsmTarget(targetId)
      toast.success('Queued ASM discovery refresh', {
        link: res.scan_id ? { href: `/scans/${res.scan_id}`, label: 'View activity' } : undefined,
      })
      setTimeout(onRefresh, 700)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to queue ASM recon')
    } finally {
      setBusy(null)
    }
  }

  // Re-probe reachability and retire phantom endpoints. Safe anytime (read-only
  // GET probes + reversible bookkeeping), so it runs directly like recon above.
  const runPrune = async () => {
    setBusy('prune')
    try {
      const res = await pruneAsmInventory(targetId)
      const sweep = res.sweep as { probed?: number; retired?: number }
      toast.success(`Pruned inventory: probed ${sweep?.probed ?? 0}, retired ${sweep?.retired ?? 0} phantom endpoint(s)`)
      setTimeout(onRefresh, 700)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to prune ASM inventory')
    } finally {
      setBusy(null)
    }
  }

  const denominator = asmCoverageDenominator(coverage)
  const rec = gaps?.recommendation
    ?? (coverage
      ? {
          next_action: denominator.value === 0 ? 'recon' as const : (coverage.untested + coverage.stale > 0 ? 'test' as const : 'recon' as const),
          label: denominator.value === 0 ? 'Discover endpoints' : (coverage.untested + coverage.stale > 0 ? 'Test next endpoint batch' : 'Refresh discovery'),
          reason: denominator.value === 0
            ? 'No persistent endpoint inventory exists yet.'
            : (coverage.untested + coverage.stale > 0
                ? `${coverage.untested + coverage.stale} endpoint(s) are untested or stale.`
                : 'Current inventory has no claimable endpoints; refresh discovery to find new surface.'),
          blockers: [],
        }
      : null)
  const next = rec?.next_action
  const icon = next === 'test' ? Play : next === 'recon' ? Search : CheckCircle2
  const Icon = icon
  const currentCoverage = resolvedCoverage(coverage)
  const coveragePct = coverage ? pct(currentCoverage) : '—'
  const coverageDenominatorText = coverage
    ? `${currentCompletedVariantCount(coverage)} of ${denominator.value} route variant${denominator.value === 1 ? '' : 's'} currently completed`
    : 'No coverage data'
  const recommendationReason = (rec?.reason || 'Load a target inventory to see the next coverage action.')
    .replace(/^1 endpoint\(s\)/, '1 endpoint')
    .replace(/endpoint\(s\)/g, 'endpoints')
  const selectedFamilyOption = checkFamilyOptions.find((option) => option.value === checkFamily && !option.disabled)
  const selectedRiskLabel = formatRiskLevel(selectedFamilyOption?.riskLevel)
  const scheduler = gaps?.scheduler_state
  const decision = scheduler?.decision
  const lastDecision = scheduler?.last_decision
  const activeScanId = decision?.active_scan_id || scheduler?.active_scan_ids?.[0] || lastDecision?.active_scan_id
  const activeApprovalMissing = next === 'test' && !approvalReceiptId.trim()

  return (
    <Card className="p-4 space-y-4">
      {next === 'test' && (
        <div className="space-y-3">
          <label className="flex items-start gap-3 rounded-lg border border-amber-800/70 bg-amber-950/20 p-3 text-sm text-amber-100">
            <input
              className="mt-1"
              type="checkbox"
              checked={authorizationConfirmed}
              onChange={(event) => onAuthorizationConfirmedChange(event.target.checked)}
            />
            <span>I own or have explicit authorization to run active endpoint checks against this target.</span>
          </label>
          <ApprovalReceiptField
            targetId={targetId}
            targetUrl={targetUrl}
            authorizationConfirmed={authorizationConfirmed}
            receiptId={approvalReceiptId}
            onReceiptIdChange={onApprovalReceiptIdChange}
            ttlMinutes={120}
            riskTier={checkFamily === 'auth' || checkFamily === 'bola' ? 'credential' : 'active'}
            required
          />
        </div>
      )}
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Sparkles className="h-5 w-5 text-blue-400" />
            <h2 className="text-sm font-medium text-gray-300">Coverage advisor</h2>
            {rec && (
              <Badge className={next === 'wait' ? 'bg-yellow-500/15 text-yellow-400' : 'bg-blue-500/15 text-blue-300'}>
                {rec.label}
              </Badge>
            )}
          </div>
          <div>
            <div className="text-2xl font-semibold text-white">{coveragePct}</div>
            <p className="mt-1 text-sm text-gray-400">
              {recommendationReason}
            </p>
            <div className="mt-1 text-xs text-gray-500">{coverageDenominatorText}</div>
          </div>
          {gaps?.recommendation?.blockers?.length ? (
            <div className="space-y-1">
              {gaps.recommendation.blockers.map((b) => (
                <div key={b.kind} className="flex items-start gap-2 text-xs text-yellow-300">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <span>
                    {b.message} ({b.count})
                    {b.kind === 'active_scan' && b.scan_id ? (
                      <>
                        {' '}
                        <Link href={`/scans/${b.scan_id}`} className="text-blue-400 underline hover:text-blue-300">
                          view scan
                        </Link>
                        <span className="text-gray-500"> (ASM batch/recon — hidden from the Scans list)</span>
                      </>
                    ) : null}
                  </span>
                </div>
              ))}
            </div>
          ) : null}
          <details className="rounded-lg border border-gray-800 bg-gray-950/40">
            <summary className="cursor-pointer px-3 py-2 text-xs font-medium text-gray-400 hover:text-gray-200">
              Why this recommendation?
            </summary>
            <div className="space-y-3 border-t border-gray-800 p-3">
            {gaps && (
              <div className="flex flex-wrap gap-2 text-xs">
              <Badge className="bg-gray-800 text-gray-300">{gaps.claimable} claimable</Badge>
              {Object.entries(gaps.last_attempt_status).slice(0, 4).map(([status, count]) => (
                <Badge key={status} className="bg-gray-800 text-gray-400">
                  {status.replace(/_/g, ' ')}: {count}
                </Badge>
              ))}
            </div>
          )}
          {decision && (
            <div className="grid gap-2 rounded border border-gray-800 bg-gray-950/50 p-2 text-xs sm:grid-cols-2">
              <div>
                <div className="text-[11px] uppercase text-gray-500">Scheduler decision</div>
                <div className="mt-1 text-gray-300">
                  {decision.action || 'none'}{decision.blocked_by ? ` · blocked by ${decision.blocked_by.replace(/_/g, ' ')}` : ''}
                </div>
                <div className="mt-0.5 text-gray-500">{decision.reason || 'No scheduler reason available.'}</div>
                {decision.next_eligible_at && (
                  <div className="mt-0.5 text-gray-500">Next eligible: {formatDate(decision.next_eligible_at)}</div>
                )}
                {activeScanId && (
                  <Link href={`/scans/${activeScanId}`} className="mt-1 inline-flex text-blue-400 underline hover:text-blue-300">
                    View active ASM scan
                  </Link>
                )}
              </div>
              <div>
                <div className="text-[11px] uppercase text-gray-500">Budget remaining</div>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  <Badge className="bg-gray-800 text-gray-300">
                    daily: {decision.daily_cap_remaining ?? 'unlimited'}
                  </Badge>
                  <Badge className="bg-gray-800 text-gray-300">
                    domain/hour: {decision.rate_cap_remaining ?? 'unlimited'}
                  </Badge>
                  <Badge className="bg-gray-800 text-gray-300">
                    tested today: {decision.tested_today ?? 0}
                  </Badge>
                </div>
                {lastDecision && (
                  <div className="mt-1 text-gray-500">
                    Last recorded {lastDecision.source || 'decision'}: {lastDecision.action || 'none'}
                    {lastDecision.recorded_at ? ` at ${formatDate(lastDecision.recorded_at)}` : ''}
                  </div>
                )}
              </div>
            </div>
          )}
          {gaps?.family_coverage && Object.keys(gaps.family_coverage).length > 0 && (
            <div className="space-y-1">
              <div className="text-[11px] uppercase text-gray-500">Family proof coverage</div>
              <div className="flex flex-wrap gap-1.5 text-xs">
                {Object.entries(gaps.family_coverage).map(([fam, c]) => {
                  const coverage = normalizeFamilyCoverage(c as unknown as Record<string, unknown>)
                  return (
                    <span key={fam} title={coverage.label}>
                      <Badge
                        className={coverage.proved > 0 ? 'bg-green-500/15 text-green-300' : 'bg-gray-800 text-gray-400'}>
                        {fam}: {coverage.proved}/{coverage.completed}/{coverage.attempted}
                      </Badge>
                    </span>
                  )
                })}
              </div>
              <p className="text-[11px] text-gray-500">Each badge is <strong>proved / completed / attempted</strong>. These are family-specific test cases, not endpoint counts.</p>
            </div>
          )}
          {gaps?.confidence_distribution && Object.keys(gaps.confidence_distribution).length > 0 && (
            <div className="space-y-1">
              <div className="text-[11px] uppercase text-gray-500" title="How trustworthy the findings are: 'verified' = proven by a deterministic re-test; 'suspected' = reported but not yet proven.">
                Proof quality (active findings)
              </div>
              <div className="flex flex-wrap gap-1.5 text-xs">
                {Object.entries(gaps.confidence_distribution).map(([tier, c]) => (
                  <span key={tier} title={`${c.high_critical} high/critical of ${c.total} findings in this tier`}>
                    <Badge className={
                      tier === 'verified' ? 'bg-green-500/15 text-green-300'
                        : tier === 'suspected' ? 'bg-amber-500/15 text-amber-300'
                        : 'bg-gray-800 text-gray-400'}>
                      {tier}: {c.total}{c.high_critical ? ` (${c.high_critical} H/C)` : ''}
                    </Badge>
                  </span>
                ))}
              </div>
            </div>
          )}
            {!!gaps?.stuck_verification && gaps.stuck_verification > 0 && (
            <div className="flex flex-wrap items-center gap-2 rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1.5 text-xs">
              <span className="font-medium text-amber-300">
                ⚠ {gaps.stuck_verification} high/critical finding{gaps.stuck_verification === 1 ? '' : 's'} stuck unproven
              </span>
              <span className="text-gray-400">
                a re-test has been wedged &gt;1h or exhausted its attempts — needs manual review
              </span>
            </div>
            )}
            </div>
          </details>
        </div>

        <div className="flex flex-col gap-2">
          <Button onClick={queueImprove} disabled={!!busy || next === 'wait' || activeApprovalMissing}>
            <Icon className="h-4 w-4" /> {busy === 'improve' ? 'Queuing…' : 'Improve coverage'}
          </Button>
          <details className="rounded-lg border border-gray-800 bg-gray-950/40">
            <summary className="cursor-pointer px-3 py-2 text-xs font-medium text-gray-400 hover:text-gray-200">
              Customize next batch
            </summary>
            <div className="space-y-2 border-t border-gray-800 p-3">
              <label className="block space-y-1 text-xs text-gray-500">
                <span>Security check</span>
                <select
                  value={checkFamily}
                  onChange={(e) => setCheckFamily(e.target.value)}
                  className="w-full rounded border border-gray-700 bg-gray-900 px-2 py-1.5 text-sm text-gray-200"
                >
                  {checkFamilyOptions.map((option) => (
                    <option key={option.value} value={option.value} disabled={option.disabled}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="block space-y-1 text-xs text-gray-500">
                <span>Endpoints</span>
                <select
                  value={endpointFilter}
                  onChange={(e) => setEndpointFilter(e.target.value)}
                  className="w-full rounded border border-gray-700 bg-gray-900 px-2 py-1.5 text-sm text-gray-200"
                >
                  <option value="">All endpoints</option>
                  <option value="api">API-like only</option>
                </select>
              </label>
              {selectedFamilyOption && (
                <div className="flex flex-wrap items-center gap-1.5 text-xs text-gray-400">
                  <span>{selectedFamilyOption.description}</span>
                  {selectedRiskLabel && (
                    <Badge className={riskBadgeClass(selectedFamilyOption.riskLevel)}>{selectedRiskLabel}</Badge>
                  )}
                </div>
              )}
            </div>
          </details>
          <details className="rounded-lg border border-gray-800 bg-gray-950/40">
            <summary className="cursor-pointer px-3 py-2 text-xs font-medium text-gray-400 hover:text-gray-200">
              Advanced coverage actions
            </summary>
            <div className="grid gap-2 border-t border-gray-800 p-2">
              <Button variant="secondary" onClick={queueRecon} disabled={!!busy}>
                <Search className="h-4 w-4" /> {busy === 'recon' ? 'Queuing…' : 'Refresh discovery'}
              </Button>
              <Button
                variant="secondary"
                onClick={runPrune}
                disabled={!!busy}
                title="Re-check reachability and retire phantom endpoints. This bookkeeping is reversible."
              >
                <Trash2 className="h-4 w-4" /> {busy === 'prune' ? 'Checking…' : 'Remove unreachable endpoints'}
              </Button>
            </div>
          </details>
        </div>
      </div>
      {gaps?.recommended_campaigns && gaps.recommended_campaigns.length > 0 && (
        <div className="space-y-1.5 border-t border-gray-800 pt-3">
          <div className="text-[11px] uppercase text-gray-500">Recommended follow-up work</div>
          <div className="grid gap-1.5 sm:grid-cols-2 xl:grid-cols-3">
            {gaps.recommended_campaigns.slice(0, 6).map((c) => (
              <div key={c.campaign} className="flex items-start gap-2 rounded border border-gray-800 bg-gray-950/40 p-2 text-xs">
                <Badge className={
                  c.priority === 'high' ? 'bg-red-500/15 text-red-300'
                  : c.priority === 'medium' ? 'bg-yellow-500/15 text-yellow-300'
                  : 'bg-gray-800 text-gray-400'}>
                  {c.label || c.campaign}
                </Badge>
                <span className="text-gray-500">{c.reason}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </Card>
  )
}

function GapsCard({ gaps, loading }: { gaps: AsmGaps | null; loading: boolean }) {
  if (!gaps) {
    return loading
      ? <Card className="p-4"><Skeleton className="h-20 w-full" /></Card>
      : (
        <Card className="p-4">
          <EmptyState
            message="Gap detail unavailable"
            hint="Coverage summary is still usable. Refresh after the API service has picked up the latest ASM endpoints."
          />
        </Card>
      )
  }

  const authRows = Object.entries(gaps.by_auth_state)
  const sample = gaps.sample_gaps.slice(0, 8)

  return (
    <Card className="p-4 space-y-3">
      <div className="flex items-center gap-2">
        <AlertTriangle className="h-5 w-5 text-yellow-400" />
        <h2 className="text-sm font-medium text-gray-300">Coverage gaps</h2>
      </div>

      <div className="grid gap-3 md:grid-cols-2">
        <div className="rounded-lg border border-gray-800 bg-gray-950/50 p-3">
          <div className="mb-2 text-xs uppercase text-gray-500">Auth states</div>
          {authRows.length === 0 ? (
            <div className="text-sm text-gray-500">No inventory yet.</div>
          ) : (
            <div className="space-y-1">
              {authRows.map(([state, counts]) => (
                <div key={state} className="flex items-center justify-between gap-3 text-sm">
                  <span className="text-gray-300">{state}</span>
                  <span className="text-xs text-gray-500">
                    tested {counts.tested || 0} · untested {(counts.untested || 0) + (counts.stale || 0)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="rounded-lg border border-gray-800 bg-gray-950/50 p-3">
          <div className="mb-2 text-xs uppercase text-gray-500">Parameter shapes</div>
          <div className="flex flex-wrap gap-2">
            {Object.entries(gaps.by_param_location).length ? Object.entries(gaps.by_param_location).map(([loc, count]) => (
              <Badge key={loc} className="bg-gray-800 text-gray-300">{loc}: {count}</Badge>
            )) : <span className="text-sm text-gray-500">No parameters discovered yet.</span>}
          </div>
        </div>
      </div>

      {sample.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-left text-xs uppercase text-gray-500">
                <th className="px-2 py-2 font-medium">Endpoint</th>
                <th className="px-2 py-2 font-medium">State</th>
                <th className="px-2 py-2 font-medium">Auth</th>
                <th className="px-2 py-2 font-medium">Reason</th>
              </tr>
            </thead>
            <tbody>
              {sample.map((e) => (
                <tr key={e.id} className="border-b border-gray-800/60">
                  <td className="px-2 py-2 font-mono text-xs text-gray-300">
                    <span className="mr-2 text-gray-500">{e.method}</span>{e.path}
                  </td>
                  <td className="px-2 py-2">
                    <Badge className={STATUS_BADGE[e.test_status] || 'bg-gray-700/50 text-gray-300'}>{e.test_status}</Badge>
                  </td>
                  <td className="px-2 py-2 text-gray-400">{e.auth_state || 'anonymous'}</td>
                  <td className="px-2 py-2 text-gray-400">{e.last_attempt_status || e.last_verdict || 'not attempted'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

const TIMELINE_BADGE: Record<string, string> = {
  active_scan: 'bg-blue-500/15 text-blue-300',
  scheduler_decision: 'bg-gray-800 text-gray-300',
  next_eligible: 'bg-yellow-500/15 text-yellow-300',
  scheduled_wave: 'bg-purple-500/15 text-purple-300',
  last_scheduler_decision: 'bg-gray-800 text-gray-400',
  activity: 'bg-gray-800 text-gray-300',
}

function ActivityCard({
  targetId,
  activity,
  schedulerState,
  timeline,
  onRefresh,
  approvalReceiptId,
}: {
  targetId: string
  activity: AsmActivity[]
  schedulerState?: AsmSchedulerState | null
  timeline?: AsmTimelineEvent[]
  onRefresh: () => void
  approvalReceiptId: string
}) {
  const toast = useToast()
  const [improving, setImproving] = useState(false)
  const decision = schedulerState?.decision
  const lastDecision = schedulerState?.last_decision
  const activeScanId = decision?.active_scan_id || schedulerState?.active_scan_ids?.[0] || lastDecision?.active_scan_id
  const decisionLabel = decision?.action
    ? `${decision.action}${decision.blocked_by ? ` · blocked by ${decision.blocked_by.replace(/_/g, ' ')}` : ''}`
    : 'No live decision'

  async function improveFromTimeline() {
    setImproving(true)
    try {
      const needsActiveApproval = decision?.action === 'test'
      const result = await improveAsmTarget(targetId, (
        needsActiveApproval && approvalReceiptId
          ? { approval_receipt_id: approvalReceiptId }
          : undefined
      ))
      toast.success(result.action === 'wait' ? (result.reason || 'ASM work is already active') : 'Queued ASM coverage work', {
        link: result.scan_id ? { href: `/scans/${result.scan_id}`, label: 'View activity' } : undefined,
      })
      setTimeout(onRefresh, 700)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to improve ASM coverage')
    } finally {
      setImproving(false)
    }
  }

  return (
    <Card className="p-4 space-y-3">
      <div className="flex items-center gap-2">
        <Activity className="h-5 w-5 text-blue-400" />
        <h2 className="text-sm font-medium text-gray-300">Recent coverage activity</h2>
      </div>
      {schedulerState && (
        <div className="rounded-lg border border-gray-800 bg-gray-950/50 p-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="text-[11px] uppercase text-gray-500">Current automation status</div>
              <div className="mt-1 text-sm text-gray-200">{decisionLabel}</div>
              <div className="mt-1 text-xs text-gray-500">
                {decision?.reason || lastDecision?.reason || 'No scheduler reason has been recorded yet.'}
              </div>
              {decision?.next_eligible_at && (
                <div className="mt-1 text-xs text-gray-500">Next eligible: {formatDate(decision.next_eligible_at)}</div>
              )}
              {lastDecision?.recorded_at && (
                <div className="mt-1 text-xs text-gray-600">
                  Last recorded: {formatDate(lastDecision.recorded_at)}
                  {lastDecision.source ? ` · ${lastDecision.source}` : ''}
                </div>
              )}
            </div>
            <div className="flex shrink-0 flex-wrap justify-end gap-1.5">
              <Badge className="bg-gray-800 text-gray-300">
                claimable: {schedulerState.claimable ?? 0}
              </Badge>
              <Badge className="bg-gray-800 text-gray-300">
                daily: {schedulerState.daily_cap_remaining ?? 'unlimited'}
              </Badge>
              <Badge className="bg-gray-800 text-gray-300">
                domain/hour: {schedulerState.rate_cap_remaining ?? 'unlimited'}
              </Badge>
            </div>
          </div>
          {activeScanId && (
            <Link href={`/scans/${activeScanId}`} className="mt-2 inline-flex text-xs text-blue-400 underline hover:text-blue-300">
              View active ASM scan
            </Link>
          )}
        </div>
      )}
      {timeline && timeline.length > 0 ? (
        <div className="space-y-2">
          {timeline.map((event) => {
            const action = event.remediation
            const actionHref = safeRemediationHref(action?.href)
            const eventTitle = event.title
              .replace(/^Scheduler decision:/i, 'Automation chose:')
              .replace(/\bcampaign\b/gi, 'coverage run')
            const content = (
              <div className="flex items-start justify-between gap-3 rounded-lg border border-gray-800 bg-gray-950/50 px-3 py-2 hover:border-gray-700">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm text-gray-200">{eventTitle}</span>
                    {event.status && (
                      <Badge className={TIMELINE_BADGE[event.kind] || STATUS_BADGE[event.status] || 'bg-gray-700/50 text-gray-300'}>
                        {event.status.replace(/_/g, ' ')}
                      </Badge>
                    )}
                  </div>
                  <div className="mt-1 text-xs text-gray-500">{event.detail || 'No detail recorded.'}</div>
                  {event.campaign_id && (
                    <Link
                      href={`/deep-hunt/runs/${event.campaign_id}`}
                      className="mt-1 inline-flex text-[11px] text-blue-400 hover:text-blue-300"
                    >
                      Open related hunt
                    </Link>
                  )}
                </div>
                <div className="flex shrink-0 flex-col items-end gap-2 text-right text-xs text-gray-500">
                  <span>{event.timestamp ? formatDate(event.timestamp) : '—'}</span>
                  {action?.kind === 'improve' ? (
                    <Button size="sm" variant="secondary" disabled={improving} onClick={() => void improveFromTimeline()}>
                      <Sparkles className={`h-3.5 w-3.5 ${improving ? 'animate-pulse' : ''}`} />
                      {action.label}
                    </Button>
                  ) : actionHref ? (
                    <Link href={actionHref} className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300">
                      {action?.label || 'Open remediation'} <ExternalLink className="h-3 w-3" />
                    </Link>
                  ) : event.href ? (
                    <Link href={event.href} className="text-blue-400 hover:text-blue-300">Open</Link>
                  ) : null}
                </div>
              </div>
            )
            return <div key={event.id}>{content}</div>
          })}
        </div>
      ) : activity.length === 0 ? (
        <EmptyState message="No coverage activity yet" hint="Run discovery or improve coverage to start building this target’s activity history." />
      ) : (
        <div className="space-y-2">
          {activity.slice(0, 8).map((item) => {
            const label = item.scan_role === 'asm_recon' ? 'Discovery' : 'Test batch'
            return (
              <Link
                key={item.id}
                href={`/scans/${item.id}`}
                className="flex items-center justify-between gap-3 rounded-lg border border-gray-800 bg-gray-950/50 px-3 py-2 hover:border-gray-700"
              >
                <div>
                  <div className="text-sm text-gray-200">{label}</div>
                  <div className="text-xs text-gray-500">{formatDate(item.created_at)}</div>
                </div>
                <div className="text-right">
                  <Badge className={STATUS_BADGE[item.status] || 'bg-gray-700/50 text-gray-300'}>
                    {item.status}
                  </Badge>
                  <div className="mt-1 text-xs text-gray-500">
                    {item.findings_count || 0} findings
                  </div>
                </div>
              </Link>
            )
          })}
        </div>
      )}
    </Card>
  )
}

function LeadRow({ item }: { item: HypothesisReportItem }) {
  const displayStatus = item.effective_status || item.status
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950/50 px-3 py-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="break-all font-mono text-sm text-gray-100">{item.family}</span>
        <Badge className={STATUS_BADGE[displayStatus] || 'bg-gray-700/50 text-gray-300'}>{displayStatus}</Badge>
        {item.severity_guess && <Badge className="bg-amber-500/15 text-amber-300">{item.severity_guess}</Badge>}
        <Badge className="bg-gray-800 text-gray-300">{item.source}</Badge>
      </div>
      <div className="mt-1 break-words text-sm text-gray-400">{item.title || item.dedupe_key}</div>
      <div className="mt-2 flex flex-wrap gap-1.5 text-xs">
        <Badge className="bg-gray-800 text-gray-300">{Math.round((item.confidence || 0) * 100)}% confidence</Badge>
        <Badge className="bg-gray-800 text-gray-300">endorse {item.endorsement_count}</Badge>
        <Badge className="bg-gray-800 text-gray-300">refute {item.refutation_count}</Badge>
      </div>
    </div>
  )
}

function HypothesisLeadsCard({
  report,
  targetId,
}: {
  report?: HypothesisSituationReport | null
  targetId: string
}) {
  const graphSummary = report?.graph_context?.summary
  const topLeads = report?.hottest_unclaimed || []
  const blockers = report?.live_blockers || []
  const missing = report?.missing_preconditions || []

  return (
    <Card className="p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Crosshair className="h-5 w-5 text-amber-300" />
          <h2 className="text-sm font-medium text-gray-300">Proof leads</h2>
        </div>
        <Link href={`/settings/arsenal?target_id=${targetId}`} className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300">
          Hypothesis Board <ExternalLink className="h-3.5 w-3.5" />
        </Link>
      </div>
      {!report || report.summary.considered_count === 0 ? (
        <EmptyState message="No proof leads for this target" hint="Graph, source, AI, Model Intake, and scanner signals will appear here after they create runtime-proof hypotheses." />
      ) : (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <CoverageStat label="considered" value={report.summary.considered_count} />
            <CoverageStat label="hot leads" value={topLeads.length} accent="text-amber-300" />
            <CoverageStat label="blockers" value={blockers.length} accent="text-red-300" />
            <CoverageStat label="graph nodes" value={graphSummary?.node_count ?? 0} accent="text-cyan-300" />
          </div>
          {topLeads.length > 0 ? (
            <div className="grid gap-2">
              {topLeads.slice(0, 3).map((item) => (
                <LeadRow key={item.id} item={item} />
              ))}
            </div>
          ) : (
            <div className="rounded-lg border border-gray-800 bg-gray-950/50 p-3 text-sm text-gray-500">
              No unclaimed leads in the bounded report.
            </div>
          )}
          {missing.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {missing.slice(0, 6).map((item) => (
                <Badge key={item.requirement} className="bg-amber-500/15 text-amber-300">
                  {item.requirement}: {item.count}
                </Badge>
              ))}
            </div>
          )}
        </div>
      )}
    </Card>
  )
}

// ---- Per-target view ------------------------------------------------------

function TargetView({ targetId }: { targetId: string }) {
  const { filters, setFilter } = useUrlFilters<AsmFilters>()
  const router = useRouter()
  const toast = useToast()
  const [target, setTarget] = useState<Target | null>(null)
  const [endpoints, setEndpoints] = useState<AsmEndpoint[]>([])
  const [inventorySemantics, setInventorySemantics] = useState<AsmInventorySemantics | null>(null)
  const [coverage, setCoverage] = useState<AsmCoverage | null>(null)
  const [gaps, setGaps] = useState<AsmGaps | null>(null)
  const [activity, setActivity] = useState<AsmActivity[]>([])
  const [activitySchedulerState, setActivitySchedulerState] = useState<AsmSchedulerState | null>(null)
  const [timeline, setTimeline] = useState<AsmTimelineEvent[]>([])
  const [hypothesisSituation, setHypothesisSituation] = useState<HypothesisSituationReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [testing, setTesting] = useState(false)
  const [workerCount, setWorkerCount] = useState<number | null>(null)
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false)
  const [approvalReceiptId, setApprovalReceiptId] = useState('')

  useEffect(() => {
    setAuthorizationConfirmed(false)
    setApprovalReceiptId('')
  }, [targetId])

  const load = useCallback(() => {
    setLoading(true)
    setError(false)
    Promise.all([
      getAsmEndpoints(targetId, { status: filters.status || undefined, limit: 200 }),
      getAsmGaps(targetId).catch(() => null),
      getAsmActivity(targetId, { limit: 12 }).catch((): AsmActivityResponse => ({ activity: [] })),
    ])
      .then(([endpointData, gapData, activityData]) => {
        setEndpoints(endpointData.endpoints)
        setInventorySemantics(endpointData.inventory_semantics || null)
        setCoverage(endpointData.coverage)
        setGaps(gapData)
        setActivity(activityData.activity)
        setActivitySchedulerState(activityData.scheduler_state || gapData?.scheduler_state || null)
        setTimeline(activityData.timeline || [])
        setHypothesisSituation(activityData.hypothesis_situation || null)
      })
      .catch(() => setError(true))
      .finally(() => setLoading(false))
  }, [targetId, filters.status])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    getWorkers().then((w) => setWorkerCount(w.count)).catch(() => setWorkerCount(null))
  }, [])

  useEffect(() => {
    let cancelled = false
    setTarget(null)
    getTarget(targetId)
      .then((data) => {
        if (cancelled) return
        setTarget(data)
      })
      .catch(() => { if (!cancelled) setTarget(null) })
    return () => { cancelled = true }
  }, [targetId])

  const runTest = async () => {
    if (!approvalReceiptId.trim()) {
      toast.error('A current target-bound approval receipt is required for active ASM testing.')
      return
    }
    setTesting(true)
    try {
      const res = await testAsmTarget(targetId, {
        batch_size: 100,
        stale_days: 30,
        approval_receipt_id: approvalReceiptId,
      })
      toast.success(`Queued ASM test batch over ${res.batch_size} endpoints`, {
        link: { href: `/scans/${res.scan_id}`, label: 'View batch scan' },
      })
      setConfirmOpen(false)
      // Coverage will rise once the batch completes; refresh shows in_progress immediately.
      setTimeout(load, 800)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to queue ASM test batch')
    } finally {
      setTesting(false)
    }
  }

  const openHuntForGaps = () => {
    if (!target) return
    if (!/^https?:\/\//i.test(target.url)) {
      toast.error('Hunt requires an HTTP or HTTPS web target.')
      return
    }
    const objective = 'Explore this target autonomously and close the highest-value unexplained coverage gaps with evidence.'
    router.push(`/hunt?target=${encodeURIComponent(target.id)}&objective=${encodeURIComponent(objective)}`)
  }

  const coverageDenominator = asmCoverageDenominator(coverage)

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={() => setFilter('target_id', undefined)}
          className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-gray-200"
        >
          <ArrowLeft className="h-4 w-4" /> All targets
        </button>
        <div className="ml-auto flex items-center gap-2">
          <Link
            href={`/findings?target_id=${targetId}&status=active`}
            className="inline-flex items-center gap-1.5 text-sm text-blue-400 hover:text-blue-300"
          >
            View findings <ExternalLink className="h-3.5 w-3.5" />
          </Link>
          <Button variant="ghost" size="sm" onClick={load}>
            <RefreshCw className="h-4 w-4" /> Refresh
          </Button>
          <button
            type="button"
            onClick={openHuntForGaps}
            disabled={!target}
            title="Open Hunt with this target and a coverage-gap objective."
            className="inline-flex items-center gap-1.5 rounded-lg bg-violet-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-violet-500 disabled:cursor-not-allowed disabled:opacity-45"
          >
            <BrainCircuit className="h-4 w-4" /> Open Hunt
          </button>
        </div>
      </div>

      <CoverageAdvisorCard
        targetId={targetId}
        targetUrl={target?.url || ''}
        coverage={coverage}
        gaps={gaps}
        onRefresh={load}
        authorizationConfirmed={authorizationConfirmed}
        approvalReceiptId={approvalReceiptId}
        onAuthorizationConfirmedChange={setAuthorizationConfirmed}
        onApprovalReceiptIdChange={setApprovalReceiptId}
      />

      {coverage && (
        <Card className="p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-gray-400">Coverage</span>
            <div className="text-right">
              <div className="text-sm text-gray-300">
                {pct(resolvedCoverage(coverage))} · {currentCompletedVariantCount(coverage)} of {coverageDenominator.value} route variants currently completed
              </div>
              <div className="text-xs text-gray-500">
                Current examination coverage · snapshot {coverage.metric_contract?.snapshot_at ? formatDate(coverage.metric_contract.snapshot_at) : 'time unavailable'}
              </div>
            </div>
          </div>
          <CoverageBar coverage={resolvedCoverage(coverage)} />
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-8">
            <CoverageStat label="Canonical routes" value={coverage.metric_contract?.inventory.canonical_routes ?? coverageDenominator.value} />
            <CoverageStat label="Route variants" value={coverageDenominator.value} />
            <CoverageStat label="Ever completed" value={coverage.metric_contract?.examination.variants_ever_completed ?? coverage.tested} accent="text-green-400" />
            <CoverageStat label="Fresh now" value={coverage.metric_contract?.examination.current_fresh_variants ?? coverage.tested} accent="text-blue-400" />
            <CoverageStat label="In progress" value={coverage.in_progress} accent="text-blue-400" />
            <CoverageStat label="Stale" value={coverage.stale} accent="text-yellow-400" />
            <CoverageStat label="Attempts" value={coverage.metric_contract?.execution.attempts ?? coverage.attempted ?? 0} />
            <CoverageStat label="Proof-bearing variants" value={coverage.metric_contract?.proof.proof_bearing_variants ?? 0} accent="text-emerald-400" />
          </div>
          <details className="rounded border border-gray-800 bg-gray-950/40 p-3 text-xs text-gray-400">
            <summary className="cursor-pointer font-medium text-gray-300">How coverage is counted</summary>
            <div className="mt-2 space-y-1">
              <p><strong>Canonical route</strong>: one normalized path.</p>
              <p><strong>Route variant</strong>: method, path, auth state, and parameter shape/location.</p>
              <p><strong>Attempt</strong>: one scanner ledger execution; retries and family checks count separately.</p>
              <p><strong>Proof-bearing</strong>: a deterministic verified/exploited/proven verdict. Synthetic variants are never called endpoints.</p>
              <p>Historical completed totals only fall when a variant is explicitly retired; fresh coverage may fall when completed work becomes stale.</p>
            </div>
          </details>
        </Card>
      )}

      <div className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
        <GapsCard gaps={gaps} loading={loading} />
        <ActivityCard
          targetId={targetId}
          activity={activity}
          schedulerState={activitySchedulerState}
          timeline={timeline}
          onRefresh={load}
          approvalReceiptId={approvalReceiptId}
        />
      </div>

      <details className="rounded-xl border border-gray-800 bg-gray-900/40">
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-gray-300 hover:text-white">
          Advanced: proof leads and continuous-testing policy
        </summary>
        <div className="space-y-4 border-t border-gray-800 p-4">
          <HypothesisLeadsCard report={hypothesisSituation} targetId={targetId} />
          <div className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
            <ContinuousCard targetId={targetId} targetUrl={target?.url || ''} />
            <NewSurfaceCard targetId={targetId} />
          </div>
        </div>
      </details>

      <details className="rounded-xl border border-gray-800 bg-gray-900/40">
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-gray-300 hover:text-white">
          Endpoint inventory <span className="ml-2 text-xs font-normal text-gray-500">({endpoints.length} shown)</span>
        </summary>
        <div className="space-y-4 border-t border-gray-800 p-4">
        <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 text-xs text-gray-300">
          <div className="font-medium text-blue-200">Inventory is a worklist, not a list of confirmed routes</div>
          <p className="mt-1 text-gray-400">
            {inventorySemantics?.route_claim || 'Discovery and imported route variants remain candidates until response or reachability evidence establishes them.'}
            {' '}This information does not affect the DAST score or grade.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <select
            value={filters.status ?? ''}
            onChange={(e) => setFilter('status', e.target.value || undefined)}
            aria-label="Filter endpoints by status"
            className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            {STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
          <span className="text-xs text-gray-500">
            {endpoints.length} endpoint{endpoints.length === 1 ? '' : 's'} shown (top 200 by priority)
          </span>
        </div>

        {loading ? (
          <TableSkeleton />
        ) : error ? (
          <ErrorState message="Failed to load endpoint inventory." onRetry={load} />
        ) : endpoints.length === 0 ? (
          <EmptyState
            message="No endpoints match"
            hint="No inventory endpoints match this filter. Try a different status or run a coverage scan to discover more surface."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-left text-xs uppercase text-gray-500">
                  <th className="px-3 py-2 font-medium">Method</th>
                  <th className="px-3 py-2 font-medium">Path</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium text-right">Priority</th>
                  <th className="px-3 py-2 font-medium">Provenance</th>
                  <th className="px-3 py-2 font-medium">Reachability</th>
                  <th className="px-3 py-2 font-medium">Auth</th>
                  <th className="px-3 py-2 font-medium">Last tested</th>
                  <th className="px-3 py-2 font-medium">Verdict</th>
                </tr>
              </thead>
              <tbody>
                {endpoints.map((e) => (
                  <tr key={e.id} className="border-b border-gray-800/60 hover:bg-gray-800/30">
                    <td className="px-3 py-2">
                      <Badge className={METHOD_BADGE[e.method] || 'bg-gray-700/50 text-gray-300'}>{e.method}</Badge>
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-gray-300">
                      {e.path}
                      {e.param_shape ? <span className="text-gray-600"> ?{e.param_shape}</span> : null}
                    </td>
                    <td className="px-3 py-2">
                      <Badge className={STATUS_BADGE[e.test_status] || 'bg-gray-700/50 text-gray-300'}>
                        {e.test_status.replace(/_/g, ' ')}
                      </Badge>
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums text-gray-400">{e.priority_score}</td>
                    <td className="px-3 py-2" title={e.provenance_explanation}>
                      <Badge className={PROVENANCE_BADGE[e.provenance_kind || 'unknown'] || PROVENANCE_BADGE.unknown}>
                        {e.provenance_label || 'Unknown source'}
                      </Badge>
                      <div className="mt-1 text-[11px] text-gray-600">{e.source || 'unspecified'}</div>
                    </td>
                    <td className="px-3 py-2" title={e.reachability_explanation}>
                      <Badge className={REACHABILITY_BADGE[e.reachability_state || 'not_checked'] || REACHABILITY_BADGE.not_checked}>
                        {e.reachability_label || 'Not checked'}
                      </Badge>
                      {e.last_http_status ? (
                        <div className="mt-1 text-[11px] text-gray-600">HTTP {e.last_http_status}</div>
                      ) : null}
                    </td>
                    <td className="px-3 py-2 text-gray-400">{e.auth_state || '—'}</td>
                    <td className="px-3 py-2 text-gray-400">{e.last_tested_at ? formatDate(e.last_tested_at) : '—'}</td>
                    <td className="px-3 py-2 text-gray-400">{e.last_verdict || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        </div>
      </details>

      <ConfirmDialog
        open={confirmOpen}
        title="Queue ASM test batch?"
        confirmLabel={testing ? 'Queuing…' : 'Queue batch'}
        busy={testing}
        message={
          <div className="space-y-2 text-sm text-gray-400">
            <p>
              This pulls the next 100 untested/stale endpoints (priority-ordered) and runs active
              checks over them as a background <code className="text-gray-300">asm_batch</code> scan.
            </p>
            {workerCount === 0 && (
              <p className="text-yellow-400">
                No workers are running — the batch will stay pending until you scale workers up.
              </p>
            )}
            <label className="flex items-start gap-3 rounded-lg border border-amber-800/70 bg-amber-950/20 p-3 text-sm text-amber-100">
              <input
                className="mt-1"
                type="checkbox"
                checked={authorizationConfirmed}
                onChange={(event) => setAuthorizationConfirmed(event.target.checked)}
              />
              <span>I own or have explicit authorization to run these active checks.</span>
            </label>
            <ApprovalReceiptField
              targetId={targetId}
              targetUrl={target?.url || ''}
              authorizationConfirmed={authorizationConfirmed}
              receiptId={approvalReceiptId}
              onReceiptIdChange={setApprovalReceiptId}
              ttlMinutes={120}
              riskTier="active"
              required
            />
          </div>
        }
        onConfirm={runTest}
        onCancel={() => setConfirmOpen(false)}
      />
    </div>
  )
}

// ---- Page shell -----------------------------------------------------------

function AsmContent() {
  const { filters, setFilter } = useUrlFilters<AsmFilters>()
  const [domains, setDomains] = useState<string[]>([])

  useEffect(() => {
    getDomains().then((d) => setDomains(d.domains || [])).catch(() => {})
  }, [])

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Crosshair className="h-6 w-6 text-blue-500" />
        <div>
          <h1 className="text-2xl font-bold text-white">Coverage</h1>
          <p className="text-sm text-gray-500">
            How much of each target’s discovered endpoints have been security-tested — tracked over time (Continuous ASM).
          </p>
        </div>
      </div>

      {filters.target_id ? (
        <TargetView targetId={String(filters.target_id)} />
      ) : (
        <RollupView domains={domains} onSelect={(id) => setFilter('target_id', id)} />
      )}
    </div>
  )
}

export default function AsmPage() {
  return (
    <Suspense fallback={<div className="p-6"><TableSkeleton /></div>}>
      <AsmContent />
    </Suspense>
  )
}
