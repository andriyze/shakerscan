'use client'

import { Suspense, useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import { ArrowLeft, Crosshair, ExternalLink, Play, RefreshCw, Radar, Repeat } from 'lucide-react'
import {
  getAsmEndpoints,
  getAsmDiff,
  getAsmPolicy,
  getDomains,
  getTargetsGrouped,
  getWorkers,
  testAsmTarget,
  updateAsmPolicy,
  formatDate,
  type AsmConfig,
  type AsmCoverage,
  type AsmEndpoint,
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

function ContinuousCard({ targetId }: { targetId: string }) {
  const toast = useToast()
  const [policy, setPolicy] = useState<AsmPolicy | null>(null)
  const [cfg, setCfg] = useState<AsmConfig | null>(null)
  const [enabled, setEnabled] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(false)

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
        When enabled, ShakerScan automatically refreshes this target&apos;s surface (recon) and drains
        untested/stale endpoints (test batches) within the budget below — one action at a time, never
        stacking load.
      </p>

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

// ---- Per-target view ------------------------------------------------------

function TargetView({ targetId }: { targetId: string }) {
  const { filters, setFilter } = useUrlFilters<AsmFilters>()
  const toast = useToast()
  const [endpoints, setEndpoints] = useState<AsmEndpoint[]>([])
  const [coverage, setCoverage] = useState<AsmCoverage | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [testing, setTesting] = useState(false)
  const [workerCount, setWorkerCount] = useState<number | null>(null)

  const load = useCallback(() => {
    setLoading(true)
    setError(false)
    getAsmEndpoints(targetId, { status: filters.status || undefined, limit: 200 })
      .then((data) => {
        setEndpoints(data.endpoints)
        setCoverage(data.coverage)
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

      <ContinuousCard targetId={targetId} />
      <NewSurfaceCard targetId={targetId} />

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
