'use client'

import { Suspense, useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
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
} from 'lucide-react'
import {
  getAsmActivity,
  getAsmEndpoints,
  getAsmDiff,
  getAsmGaps,
  getAsmPolicy,
  getDomains,
  getTargetsGrouped,
  getWorkers,
  improveAsmTarget,
  reconAsmTarget,
  testAsmTarget,
  updateAsmPolicy,
  formatDate,
  type AsmActivity,
  type AsmConfig,
  type AsmCoverage,
  type AsmEndpoint,
  type AsmGaps,
  type AsmPolicy,
  type Target,
} from '@/lib/api'
import { useUrlFilters } from '@/lib/useUrlFilters'
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
        flat.sort((a, b) => (a.target.asm_coverage!.coverage) - (b.target.asm_coverage!.coverage))
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
                <th className="px-3 py-2 font-medium text-right">Tested / Total</th>
                <th className="px-3 py-2 font-medium text-right">Untested</th>
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {visible.map(({ target }) => {
                const cov = target.asm_coverage!
                return (
                  <tr key={target.id} className="border-b border-gray-800/60 hover:bg-gray-800/30">
                    <td className="px-3 py-2">
                      <button
                        type="button"
                        onClick={() => onSelect(target.id)}
                        className="text-left text-blue-400 hover:text-blue-300"
                      >
                        {target.name || target.url}
                      </button>
                      <div className="text-xs text-gray-500">{target.root_domain}</div>
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-2">
                        <CoverageBar coverage={cov.coverage} />
                        <span className="w-12 shrink-0 text-right text-xs text-gray-400">{pct(cov.coverage)}</span>
                      </div>
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums text-gray-300">
                      {cov.tested} / {cov.total}
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums text-gray-400">{cov.untested}</td>
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

type AsmCheckFamily = 'all' | 'sqli' | 'xss'

const ASM_CHECK_FAMILY_OPTIONS: Array<{ value: AsmCheckFamily; label: string; description: string }> = [
  { value: 'all', label: 'All checks', description: 'Use the normal ASM active mix.' },
  { value: 'sqli', label: 'SQLi only', description: 'Focus the next test batch on SQL injection.' },
  { value: 'xss', label: 'XSS only', description: 'Focus the next test batch on cross-site scripting.' },
]

function ContinuousCard({ targetId }: { targetId: string }) {
  const toast = useToast()
  const [policy, setPolicy] = useState<AsmPolicy | null>(null)
  const [cfg, setCfg] = useState<AsmConfig | null>(null)
  const [enabled, setEnabled] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)

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
        background batches. It chooses one action at a time and respects the caps below.
      </p>

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
                value={cfg.window_start_hour ?? ''}
                onChange={(e) => set({ window_start_hour: e.target.value === '' ? null : Number(e.target.value) })}
                className="w-16 rounded border border-gray-700 bg-gray-800 px-2 py-1 text-sm text-gray-200"
              />
              <span className="text-gray-600">–</span>
              <input
                type="number" min={0} max={23} placeholder="end"
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
  coverage,
  gaps,
  onRefresh,
}: {
  targetId: string
  coverage: AsmCoverage | null
  gaps: AsmGaps | null
  onRefresh: () => void
}) {
  const toast = useToast()
  const [busy, setBusy] = useState<'improve' | 'recon' | null>(null)
  const [checkFamily, setCheckFamily] = useState<AsmCheckFamily>('all')

  const queueImprove = async () => {
    setBusy('improve')
    try {
      const res = await improveAsmTarget(targetId, checkFamily === 'all' ? undefined : { check_family: checkFamily })
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

  const rec = gaps?.recommendation
    ?? (coverage
      ? {
          next_action: coverage.total === 0 ? 'recon' as const : (coverage.untested + coverage.stale > 0 ? 'test' as const : 'recon' as const),
          label: coverage.total === 0 ? 'Discover endpoints' : (coverage.untested + coverage.stale > 0 ? 'Test next endpoint batch' : 'Refresh discovery'),
          reason: coverage.total === 0
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
  const coveragePct = coverage ? pct(coverage.coverage) : '—'

  return (
    <Card className="p-4">
      <div className="grid gap-4 lg:grid-cols-[1fr_auto]">
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
              {rec?.reason || 'Load a target inventory to see the next ASM action.'}
            </p>
          </div>
          {gaps?.recommendation.blockers.length ? (
            <div className="space-y-1">
              {gaps.recommendation.blockers.map((b) => (
                <div key={b.kind} className="flex items-start gap-2 text-xs text-yellow-300">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <span>{b.message} ({b.count})</span>
                </div>
              ))}
            </div>
          ) : null}
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
        </div>

        <div className="flex flex-col gap-2 sm:min-w-48">
          <label className="space-y-1 text-xs text-gray-500">
            <span>Next batch focus</span>
            <select
              value={checkFamily}
              onChange={(e) => setCheckFamily(e.target.value as AsmCheckFamily)}
              className="w-full rounded border border-gray-700 bg-gray-900 px-2 py-1.5 text-sm text-gray-200"
            >
              {ASM_CHECK_FAMILY_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
          </label>
          <Button onClick={queueImprove} disabled={!!busy || next === 'wait'}>
            <Icon className="h-4 w-4" /> {busy === 'improve' ? 'Queuing…' : 'Improve coverage'}
          </Button>
          <Button variant="secondary" onClick={queueRecon} disabled={!!busy}>
            <Search className="h-4 w-4" /> {busy === 'recon' ? 'Queuing…' : 'Run discovery'}
          </Button>
        </div>
      </div>
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

function ActivityCard({ activity }: { activity: AsmActivity[] }) {
  return (
    <Card className="p-4 space-y-3">
      <div className="flex items-center gap-2">
        <Activity className="h-5 w-5 text-blue-400" />
        <h2 className="text-sm font-medium text-gray-300">ASM activity</h2>
      </div>
      {activity.length === 0 ? (
        <EmptyState message="No ASM activity yet" hint="Run discovery or improve coverage to start building the activity history." />
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

// ---- Per-target view ------------------------------------------------------

function TargetView({ targetId }: { targetId: string }) {
  const { filters, setFilter } = useUrlFilters<AsmFilters>()
  const toast = useToast()
  const [endpoints, setEndpoints] = useState<AsmEndpoint[]>([])
  const [coverage, setCoverage] = useState<AsmCoverage | null>(null)
  const [gaps, setGaps] = useState<AsmGaps | null>(null)
  const [activity, setActivity] = useState<AsmActivity[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [testing, setTesting] = useState(false)
  const [workerCount, setWorkerCount] = useState<number | null>(null)

  const load = useCallback(() => {
    setLoading(true)
    setError(false)
    Promise.all([
      getAsmEndpoints(targetId, { status: filters.status || undefined, limit: 200 }),
      getAsmGaps(targetId).catch(() => null),
      getAsmActivity(targetId, { limit: 12 }).catch(() => ({ activity: [] })),
    ])
      .then(([endpointData, gapData, activityData]) => {
        setEndpoints(endpointData.endpoints)
        setCoverage(endpointData.coverage)
        setGaps(gapData)
        setActivity(activityData.activity)
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

  const runTest = async () => {
    setTesting(true)
    try {
      const res = await testAsmTarget(targetId, { batch_size: 100, stale_days: 30 })
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
          <Button
            size="sm"
            onClick={() => setConfirmOpen(true)}
            disabled={!coverage || coverage.total === 0}
          >
            <Play className="h-4 w-4" /> Test untested
          </Button>
        </div>
      </div>

      <CoverageAdvisorCard targetId={targetId} coverage={coverage} gaps={gaps} onRefresh={load} />

      {coverage && (
        <Card className="p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-gray-400">Coverage</span>
            <span className="text-sm text-gray-300">
              {pct(coverage.coverage)} · {coverage.tested} / {coverage.total} tested
            </span>
          </div>
          <CoverageBar coverage={coverage.coverage} />
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-6">
            <CoverageStat label="Total" value={coverage.total} />
            <CoverageStat label="Tested" value={coverage.tested} accent="text-green-400" />
            <CoverageStat label="Untested" value={coverage.untested} accent="text-gray-300" />
            <CoverageStat label="In progress" value={coverage.in_progress} accent="text-blue-400" />
            <CoverageStat label="Stale" value={coverage.stale} accent="text-yellow-400" />
            <CoverageStat label="Gone" value={coverage.gone} accent="text-red-400" />
          </div>
        </Card>
      )}

      <div className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
        <GapsCard gaps={gaps} loading={loading} />
        <ActivityCard activity={activity} />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
        <ContinuousCard targetId={targetId} />
        <NewSurfaceCard targetId={targetId} />
      </div>

      <Card className="p-4 space-y-4">
        <div className="flex flex-wrap items-center gap-3">
          <select
            value={filters.status ?? ''}
            onChange={(e) => setFilter('status', e.target.value || undefined)}
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
                  <th className="px-3 py-2 font-medium">Source</th>
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
                    <td className="px-3 py-2 text-gray-400">{e.source || '—'}</td>
                    <td className="px-3 py-2 text-gray-400">{e.auth_state || '—'}</td>
                    <td className="px-3 py-2 text-gray-400">{e.last_tested_at ? formatDate(e.last_tested_at) : '—'}</td>
                    <td className="px-3 py-2 text-gray-400">{e.last_verdict || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

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
          <h1 className="text-2xl font-bold text-white">Attack Surface</h1>
          <p className="text-sm text-gray-500">
            Persistent per-target endpoint inventory and test coverage over time (Continuous ASM).
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
