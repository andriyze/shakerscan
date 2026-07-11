'use client'

import { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import { ChevronDown, ChevronRight, RefreshCw } from 'lucide-react'
import {
  getAISurfaceAttempts,
  getAISurfaces,
  syncAISurfaces,
  formatDate,
  type AISurface,
  type AISurfaceAttempt,
} from '@/lib/api'
import { Button, EmptyState, ErrorState, RiskTierBadge, SectionCard, Skeleton, useToast } from '@/components/ui'

const PAGE_STEP = 25

function AttemptRow({ attempt }: { attempt: AISurfaceAttempt }) {
  return (
    <tr className="text-xs">
      <td className="px-3 py-1.5">
        <Link href={`/scans/${attempt.scan_id}`} className="text-blue-400 hover:text-blue-300">{attempt.probe_pack || 'scan'}</Link>
        {attempt.scan_profile && <span className="ml-1 text-gray-500">/ {attempt.scan_profile}</span>}
      </td>
      <td className="px-3 py-1.5 text-gray-400">{attempt.environment || '—'}</td>
      <td className="px-3 py-1.5 text-gray-400">{attempt.status}{attempt.proof_state ? ` · ${attempt.proof_state}` : ''}</td>
      <td className="px-3 py-1.5 text-gray-300">
        {attempt.findings_count}
        {attempt.critical_high_count > 0 && <span className="ml-1 text-red-400">({attempt.critical_high_count} c/h)</span>}
      </td>
      <td className="px-3 py-1.5 text-gray-500">{attempt.completed_at ? formatDate(attempt.completed_at) : '—'}</td>
    </tr>
  )
}

function SurfaceRow({ surface }: { surface: AISurface }) {
  const [expanded, setExpanded] = useState(false)
  const [attempts, setAttempts] = useState<AISurfaceAttempt[] | null>(null)
  const [loading, setLoading] = useState(false)

  async function toggle() {
    const next = !expanded
    setExpanded(next)
    if (next && attempts === null) {
      setLoading(true)
      try {
        const res = await getAISurfaceAttempts(surface.id)
        setAttempts(res.attempts || [])
      } catch {
        setAttempts([])
      } finally {
        setLoading(false)
      }
    }
  }

  return (
    <>
      <tr className="cursor-pointer hover:bg-gray-800/40" onClick={toggle}>
        <td className="px-3 py-2">
          <div className="flex items-center gap-2">
            {expanded ? <ChevronDown className="h-3.5 w-3.5 text-gray-500" /> : <ChevronRight className="h-3.5 w-3.5 text-gray-500" />}
            <div className="min-w-0">
              <p className="truncate text-sm text-white" title={surface.endpoint_url}>{surface.endpoint_url}</p>
              <p className="text-xs text-gray-500">{surface.surface_type}{surface.owner ? ` · ${surface.owner}` : ''}</p>
            </div>
          </div>
        </td>
        <td className="px-3 py-2"><RiskTierBadge tier={surface.risk_tier} /></td>
        <td className="px-3 py-2 text-xs text-gray-400">{surface.environment || '—'}</td>
        <td className="px-3 py-2 text-sm text-gray-300">{surface.attempt_count}</td>
        <td className="px-3 py-2 text-sm text-gray-300">
          {surface.total_findings}
          {surface.total_crit_high > 0 && <span className="ml-1 text-red-400">({surface.total_crit_high} c/h)</span>}
        </td>
        <td className="px-3 py-2 text-xs text-gray-500">{surface.last_tested ? formatDate(surface.last_tested) : 'never'}</td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={6} className="bg-gray-950 px-3 py-2">
            {loading ? (
              <Skeleton className="h-8 w-full" />
            ) : attempts && attempts.length > 0 ? (
              <table className="min-w-full text-left">
                <thead>
                  <tr className="text-[10px] uppercase tracking-wide text-gray-600">
                    <th className="px-3 py-1">Probe</th>
                    <th className="px-3 py-1">Env</th>
                    <th className="px-3 py-1">Status</th>
                    <th className="px-3 py-1">Findings</th>
                    <th className="px-3 py-1">Completed</th>
                  </tr>
                </thead>
                <tbody>
                  {attempts.map((a) => <AttemptRow key={a.id} attempt={a} />)}
                </tbody>
              </table>
            ) : (
              <p className="text-xs text-gray-500">No attempts recorded for this surface.</p>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

export default function AISurfaceInventoryPanel() {
  const toast = useToast()
  const [surfaces, setSurfaces] = useState<AISurface[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)
  const [syncing, setSyncing] = useState(false)
  const [search, setSearch] = useState('')
  const [visible, setVisible] = useState(PAGE_STEP)

  const load = useCallback(async () => {
    try {
      const res = await getAISurfaces()
      setSurfaces(res.ai_surfaces || [])
      setLoadError(false)
    } catch {
      setLoadError(true)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleSync() {
    setSyncing(true)
    try {
      const res = await syncAISurfaces()
      toast.success(`Synced: ${res.surfaces_upserted} surface(s), ${res.attempts_written} attempt(s) written${res.partial ? ' (partial)' : ''}`)
      await load()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to sync AI surfaces')
    } finally {
      setSyncing(false)
    }
  }

  const query = search.trim().toLowerCase()
  const filtered = query
    ? surfaces.filter((s) => s.endpoint_url.toLowerCase().includes(query) || (s.owner || '').toLowerCase().includes(query))
    : surfaces

  return (
    <SectionCard
      title="AI Surface Inventory"
      actions={
        <Button size="sm" variant="secondary" onClick={handleSync} disabled={syncing}>
          <RefreshCw className={`h-3.5 w-3.5 ${syncing ? 'animate-spin' : ''}`} />
          {syncing ? 'Syncing…' : 'Sync from AI targets'}
        </Button>
      }
    >
      <p className="mb-3 text-xs text-gray-500">
        Durable inventory of tested AI endpoints with per-surface attempt history, backfilled from completed AI Gate scans.
      </p>

      {loadError ? (
        <ErrorState message="Failed to load AI surfaces." onRetry={load} />
      ) : loading ? (
        <Skeleton className="h-24 w-full" />
      ) : surfaces.length === 0 ? (
        <EmptyState message="No AI surfaces yet" hint="Run “Sync from AI targets” to build the inventory from your AI Gate targets and completed scans." />
      ) : (
        <>
          <input
            type="text"
            value={search}
            onChange={(e) => { setSearch(e.target.value); setVisible(PAGE_STEP) }}
            placeholder={`Search ${surfaces.length} surfaces by endpoint or owner…`}
            className="mb-3 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-600 focus:border-blue-500 focus:outline-none"
          />
          <div className="max-h-[36rem] overflow-auto rounded-lg border border-gray-800">
            <table className="min-w-full divide-y divide-gray-800 text-sm">
              <thead className="sticky top-0 bg-gray-900">
                <tr className="text-left text-xs uppercase tracking-wide text-gray-500">
                  <th className="px-3 py-2">Endpoint</th>
                  <th className="px-3 py-2">Risk</th>
                  <th className="px-3 py-2">Env</th>
                  <th className="px-3 py-2">Attempts</th>
                  <th className="px-3 py-2">Findings</th>
                  <th className="px-3 py-2">Last tested</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {filtered.slice(0, visible).map((s) => <SurfaceRow key={s.id} surface={s} />)}
              </tbody>
            </table>
          </div>
          <div className="mt-2 flex items-center justify-between text-xs text-gray-500">
            <span>Showing {Math.min(visible, filtered.length)} of {filtered.length}{query ? ` (filtered from ${surfaces.length})` : ''}</span>
            {visible < filtered.length && (
              <button type="button" onClick={() => setVisible((v) => v + PAGE_STEP)} className="text-blue-400 hover:text-blue-300">
                Show more
              </button>
            )}
          </div>
        </>
      )}
    </SectionCard>
  )
}
