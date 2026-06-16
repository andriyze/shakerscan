'use client'

import { Suspense, useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import { ArrowLeft, Crosshair, ExternalLink, Play, RefreshCw } from 'lucide-react'
import {
  getAsmEndpoints,
  getDomains,
  getTargetsGrouped,
  getWorkers,
  testAsmTarget,
  formatDate,
  type AsmCoverage,
  type AsmEndpoint,
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
