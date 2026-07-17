'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { AlertTriangle, ArrowRight, Bot, CalendarClock, Gauge, ListTodo, Minus, PackageCheck, Plus, RadioTower, Rocket, Server, ShieldCheck, Trash2, Workflow } from 'lucide-react'
import { getDashboard, getQueueStats, getWorkers, scaleWorkers, getGungnirStatus, startGungnir, stopGungnir, clearQueue, getGradeColor, formatDate, type QueueStats, type WorkerStats, type GungnirStatus, type DashboardActionItem, type DashboardProductStatusItem, type DashboardResponse } from '@/lib/api'
import {
  Badge,
  Card,
  ConfirmDialog,
  ErrorState,
  LastUpdated,
  ScanStatusBadge,
  SeverityBadge,
  Skeleton,
  TableSkeleton,
  useToast,
} from '@/components/ui'

const DASHBOARD_REFRESH_MS = 10000
const QUEUE_REFRESH_MS = 15000
const WORKERS_REFRESH_MS = 30000
const GUNGNIR_REFRESH_MS = 30000

const FOCUS_RING = 'focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500'

export default function Dashboard() {
  const toast = useToast()
  const [data, setData] = useState<DashboardResponse | null>(null)
  const [queue, setQueue] = useState<QueueStats | null>(null)
  const [workers, setWorkers] = useState<WorkerStats | null>(null)
  const [gungnir, setGungnir] = useState<GungnirStatus | null>(null)
  const [dashboardLoading, setDashboardLoading] = useState(true)
  const [dashboardError, setDashboardError] = useState<string | null>(null)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const [showClearQueue, setShowClearQueue] = useState(false)
  const [clearRetests, setClearRetests] = useState(false)
  const [clearingQueue, setClearingQueue] = useState(false)
  const [queueError, setQueueError] = useState<string | null>(null)
  const [workersError, setWorkersError] = useState<string | null>(null)
  const [scaling, setScaling] = useState(false)
  const [gungnirActionLoading, setGungnirActionLoading] = useState(false)

  const dashboardInFlight = useRef(false)
  const dashboardLoadedOnce = useRef(false)
  const queueInFlight = useRef(false)
  const workersInFlight = useRef(false)
  const gungnirInFlight = useRef(false)

  const fetchDashboard = async (showLoading = false): Promise<boolean | undefined> => {
    if (dashboardInFlight.current) return undefined
    dashboardInFlight.current = true
    if (showLoading) setDashboardLoading(true)
    try {
      const dashboardData = await getDashboard()
      setData(dashboardData)
      setDashboardError(null)
      setLastUpdated(new Date())
      dashboardLoadedOnce.current = true
      return true
    } catch (err) {
      console.error('Failed to load dashboard:', err)
      if (!dashboardLoadedOnce.current) {
        setDashboardError('Failed to load dashboard. Is the API running?')
      }
      return false
    } finally {
      dashboardInFlight.current = false
      setDashboardLoading(false)
    }
  }

  const fetchQueueStats = async () => {
    if (queueInFlight.current) return
    queueInFlight.current = true
    try {
      const queueData = await getQueueStats()
      setQueue(queueData)
      setQueueError(null)
    } catch (err) {
      setQueueError('Queue status unavailable')
    } finally {
      queueInFlight.current = false
    }
  }

  const handleClearQueue = async () => {
    setClearingQueue(true)
    try {
      const res = await clearQueue(clearRetests)
      toast.success(`Cleared ${res.cleared} pending job(s)${clearRetests ? ` + ${res.retest_cleared} retest job(s)` : ''}`)
      await fetchQueueStats()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to clear queue')
    } finally {
      setClearingQueue(false)
      setShowClearQueue(false)
    }
  }

  const fetchWorkers = async (force = false) => {
    if (workersInFlight.current && !force) return
    workersInFlight.current = true
    try {
      const workerData = await getWorkers()
      setWorkers(workerData)
      setWorkersError(workerData?.error || null)
    } catch (err) {
      setWorkersError('Workers unavailable')
    } finally {
      workersInFlight.current = false
    }
  }

  const fetchGungnirStatus = async (force = false) => {
    if (gungnirInFlight.current && !force) return
    gungnirInFlight.current = true
    try {
      const gungnirData = await getGungnirStatus()
      setGungnir(gungnirData)
    } catch (err) {
      console.error('Failed to fetch gungnir status:', err)
    } finally {
      gungnirInFlight.current = false
    }
  }

  useEffect(() => {
    fetchDashboard(true)
    const interval = setInterval(() => fetchDashboard(false), DASHBOARD_REFRESH_MS)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    fetchQueueStats()
    const interval = setInterval(fetchQueueStats, QUEUE_REFRESH_MS)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    fetchWorkers()
    const interval = setInterval(fetchWorkers, WORKERS_REFRESH_MS)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    fetchGungnirStatus()
    const interval = setInterval(fetchGungnirStatus, GUNGNIR_REFRESH_MS)
    return () => clearInterval(interval)
  }, [])

  const handleManualRefresh = async () => {
    if (refreshing) return
    setRefreshing(true)
    const ok = await fetchDashboard(false)
    setRefreshing(false)
    if (ok === false) {
      toast.error('Failed to refresh dashboard')
    }
  }

  const handleScale = async (count: number) => {
    if (scaling) return
    setScaling(true)
    try {
      await scaleWorkers(count)
      await fetchWorkers(true)
      toast.success(`Scaled workers to ${count}`)
    } catch (err) {
      console.error('Failed to scale workers:', err)
      toast.error(err instanceof Error ? err.message : 'Failed to scale workers')
    } finally {
      setScaling(false)
    }
  }

  const handleGungnirToggle = async () => {
    if (gungnirActionLoading) return
    setGungnirActionLoading(true)
    const wasRunning = Boolean(gungnir?.running)
    try {
      if (wasRunning) {
        await stopGungnir()
      } else {
        await startGungnir()
      }
      await fetchGungnirStatus(true)
      toast.success(wasRunning ? 'Gungnir CT monitor stopped' : 'Gungnir CT monitor started')
    } catch (err) {
      console.error('Failed to toggle gungnir:', err)
      toast.error(err instanceof Error ? err.message : 'Failed to toggle Gungnir CT monitor')
    } finally {
      setGungnirActionLoading(false)
    }
  }

  const metrics = data?.metrics
  const metricsReady = Boolean(metrics)
  const metricsLoading = dashboardLoading && !metricsReady
  const metricSkeleton = <Skeleton className="h-8 w-12" />
  const totalTargets = metricsReady ? metrics?.total_targets || 0 : '--'
  const totalScans = metricsReady ? metrics?.total_scans || 0 : '--'
  const activeFindings = metricsReady ? metrics?.active_findings || 0 : '--'
  const criticalFindings = metricsReady ? metrics?.critical_findings || 0 : 0
  const highFindings = metricsReady ? metrics?.high_findings || 0 : 0
  const avgScore = metricsReady
    ? metrics?.avg_score
      ? Math.round(metrics.avg_score)
      : 'N/A'
    : '--'
  const queuePending = queue ? queue.pending : '--'
  const queueRunning = queue ? queue.running : '--'
  const workerCount = workers?.count
  const workersKnown = workerCount !== undefined && workerCount >= 0
  const maxWorkers = workers?.max_allowed && workers.max_allowed > 0 ? workers.max_allowed : 20
  const staleCount = workers?.stale_workers?.length ?? 0

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-gray-400 mt-1">Security scanning overview</p>
        </div>
        <div className="flex w-full flex-wrap items-center gap-2 xl:w-auto xl:justify-end">
          <div className="flex h-10 items-center gap-2 rounded-lg border border-gray-800 bg-gray-900 px-2.5" aria-label="Scan queue">
            <ListTodo className="h-4 w-4 shrink-0 text-gray-500" aria-hidden="true" />
            {queueError ? (
              <span className="flex items-center gap-1.5 text-xs text-red-300" title={queueError}>
                <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" /> Queue unavailable
              </span>
            ) : (
              <>
                <Link
                  href="/scans?status=pending"
                  title={`${queuePending} pending scans`}
                  className={`flex items-center gap-1.5 rounded text-xs text-gray-300 hover:text-white ${FOCUS_RING}`}
                >
                  <span className={`h-2 w-2 rounded-full bg-amber-400 ${queuePending !== '--' && queuePending > 0 ? 'animate-pulse' : ''}`} />
                  <span className="font-medium tabular-nums">{queuePending}</span>
                  <span className="hidden text-gray-500 sm:inline">pending</span>
                </Link>
                <Link
                  href="/scans?status=running"
                  title={`${queueRunning} running scans`}
                  className={`flex items-center gap-1.5 rounded text-xs text-gray-300 hover:text-white ${FOCUS_RING}`}
                >
                  <span className={`h-2 w-2 rounded-full bg-blue-500 ${queueRunning !== '--' && queueRunning > 0 ? 'animate-pulse' : ''}`} />
                  <span className="font-medium tabular-nums">{queueRunning}</span>
                  <span className="hidden text-gray-500 sm:inline">running</span>
                </Link>
              </>
            )}
            <button
              type="button"
              onClick={() => { setClearRetests(false); setShowClearQueue(true) }}
              aria-label="Emergency clear pending jobs"
              title="Emergency clear pending jobs"
              className={`ml-0.5 flex h-7 w-7 items-center justify-center rounded text-gray-600 transition-colors hover:bg-red-500/10 hover:text-red-400 ${FOCUS_RING}`}
            >
              <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>

          <div
            className="flex h-10 items-center gap-2 rounded-lg border border-gray-800 bg-gray-900 px-2.5"
            title={workersError || `${workerCount ?? '--'} of ${maxWorkers} workers running`}
          >
            <Server className="h-4 w-4 shrink-0 text-gray-500" aria-hidden="true" />
            <span className="min-w-6 text-center text-sm font-medium tabular-nums text-white">
              {workersKnown ? workerCount : '--'}
            </span>
            <span className="hidden text-xs text-gray-500 sm:inline">workers</span>
            {staleCount > 0 && (
              <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-300" title="Workers running an outdated build">
                {staleCount} stale
              </span>
            )}
            <span className="h-5 w-px bg-gray-800" aria-hidden="true" />
            <button
              type="button"
              onClick={() => handleScale(Math.max(1, (workerCount || 1) - 1))}
              disabled={scaling || !workersKnown || (workerCount || 0) <= 1}
              aria-label="Decrease worker count"
              title="Decrease worker count"
              className={`flex h-7 w-7 items-center justify-center rounded text-gray-400 transition-colors hover:bg-gray-800 hover:text-white disabled:cursor-not-allowed disabled:opacity-30 ${FOCUS_RING}`}
            >
              <Minus className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
            <button
              type="button"
              onClick={() => handleScale(Math.min(maxWorkers, (workerCount || 1) + 1))}
              disabled={scaling || !workersKnown || (workerCount || 0) >= maxWorkers}
              aria-label="Increase worker count"
              title="Increase worker count"
              className={`flex h-7 w-7 items-center justify-center rounded text-gray-400 transition-colors hover:bg-gray-800 hover:text-white disabled:cursor-not-allowed disabled:opacity-30 ${FOCUS_RING}`}
            >
              <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>

          <button
            type="button"
            onClick={handleGungnirToggle}
            disabled={gungnirActionLoading}
            aria-label={gungnir?.running ? 'Stop Gungnir CT monitor' : 'Start Gungnir CT monitor'}
            title={gungnir?.running
              ? `Stop CT monitor · ${gungnir.domains_monitored} domains · ${gungnir.session_found} found this session`
              : 'Start Certificate Transparency monitor'}
            className={`flex h-10 items-center gap-2 rounded-lg border px-3 text-xs font-medium transition-colors disabled:opacity-50 ${FOCUS_RING} ${
              gungnir?.running
                ? 'border-emerald-800/60 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/15'
                : 'border-gray-800 bg-gray-900 text-gray-400 hover:bg-gray-800 hover:text-gray-200'
            }`}
          >
            <RadioTower className={`h-4 w-4 ${gungnir?.running ? 'text-emerald-400' : 'text-gray-500'}`} aria-hidden="true" />
            <span>CT</span>
            <span className={`h-2 w-2 rounded-full ${gungnir?.running ? 'animate-pulse bg-emerald-400' : 'bg-gray-600'}`} aria-hidden="true" />
            <span className="text-gray-500">{gungnirActionLoading ? '…' : gungnir?.running ? 'on' : 'off'}</span>
          </button>

          <LastUpdated updatedAt={lastUpdated} onRefresh={handleManualRefresh} refreshing={refreshing} />
        </div>
      </div>

      <ConfirmDialog
        open={showClearQueue}
        title="Clear the scan queue?"
        message={
          <div className="space-y-3">
            <p>This removes all pending scan jobs from the queue. Running scans are not affected.</p>
            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input type="checkbox" checked={clearRetests} onChange={(e) => setClearRetests(e.target.checked)} className="accent-red-500" />
              Also clear pending retest jobs
            </label>
          </div>
        }
        confirmLabel="Clear queue"
        danger
        busy={clearingQueue}
        onConfirm={handleClearQueue}
        onCancel={() => setShowClearQueue(false)}
      />

      {dashboardError && (
        <ErrorState message={dashboardError} onRetry={() => fetchDashboard(true)} />
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Targets"
          value={metricsLoading ? metricSkeleton : totalTargets}
          icon={<TargetIcon />}
          color="blue"
          href="/targets"
        />
        <StatCard
          title="Total Scans"
          value={metricsLoading ? metricSkeleton : totalScans}
          icon={<ScanIcon />}
          color="green"
          href="/scans"
        />
        <StatCard
          title="Active Findings"
          value={metricsLoading ? metricSkeleton : activeFindings}
          icon={<AlertIcon />}
          color="yellow"
          subtitle={metricsReady ? `${criticalFindings} critical, ${highFindings} high` : metricsLoading ? undefined : '--'}
          href="/findings?status=active"
        />
        <StatCard
          title="Avg Score"
          value={metricsLoading ? metricSkeleton : avgScore}
          icon={<ScoreIcon />}
          color="purple"
        />
      </div>

      <ActionCenter items={data?.action_center || []} loading={dashboardLoading && !data} />

      <ProductStatusStrip items={data?.product_status || []} loading={dashboardLoading && !data} />

      {/* Recent Scans & Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Scans */}
        <Card>
          <div className="p-4 border-b border-gray-800">
            <h2 className="font-medium text-white">Recent Scans</h2>
          </div>
          <div className="divide-y divide-gray-800">
            {data?.recent_scans?.length ? (
              data.recent_scans.slice(0, 5).map((scan) => (
                <Link
                  key={scan.id}
                  href={`/scans/${scan.id}`}
                  className={`flex items-center justify-between p-4 hover:bg-gray-800/50 transition-colors ${FOCUS_RING} focus-visible:ring-inset`}
                >
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-white truncate">{scan.target_url}</p>
                    <p className="text-xs text-gray-500">{formatDate(scan.created_at)}</p>
                  </div>
                  <div className="flex items-center gap-3">
                    {scan.grade && (
                      <span className={`text-lg font-bold ${getGradeColor(scan.grade)}`}>
                        {scan.grade}
                      </span>
                    )}
                    <ScanStatusBadge status={scan.status} />
                  </div>
                </Link>
              ))
            ) : dashboardLoading ? (
              <TableSkeleton rows={5} cols={3} />
            ) : (
              <p className="p-4 text-sm text-gray-500">No scans yet</p>
            )}
          </div>
          <div className="p-3 border-t border-gray-800">
            <Link href="/scans" className={`text-sm text-blue-400 hover:text-blue-300 rounded ${FOCUS_RING}`}>
              View all scans &rarr;
            </Link>
          </div>
        </Card>

        {/* Recent Findings */}
        <Card>
          <div className="p-4 border-b border-gray-800">
            <h2 className="font-medium text-white">Critical & High Findings</h2>
          </div>
          <div className="divide-y divide-gray-800">
            {data?.recent_findings?.length ? (
              data.recent_findings.slice(0, 5).map((finding) => (
                <Link
                  key={finding.id}
                  href={`/findings/${finding.id}`}
                  className={`flex items-center gap-3 p-4 hover:bg-gray-800/50 transition-colors ${FOCUS_RING} focus-visible:ring-inset`}
                >
                  <SeverityBadge severity={finding.severity} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-white truncate">{finding.title}</p>
                    <p className="text-xs text-gray-500 truncate">{finding.tool}</p>
                  </div>
                </Link>
              ))
            ) : dashboardLoading ? (
              <TableSkeleton rows={5} cols={3} />
            ) : (
              <p className="p-4 text-sm text-gray-500">No critical or high findings</p>
            )}
          </div>
          <div className="p-3 border-t border-gray-800">
            <Link href="/findings" className={`text-sm text-blue-400 hover:text-blue-300 rounded ${FOCUS_RING}`}>
              View all findings &rarr;
            </Link>
          </div>
        </Card>
      </div>
    </div>
  )
}

function ProductStatusStrip({
  items,
  loading,
}: {
  items: DashboardProductStatusItem[]
  loading: boolean
}) {
  const visibleItems = items.filter((item) => item.id !== 'workers').slice(0, 6)

  return (
    <Card className="p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="font-medium text-white">Area health</h2>
          <p className="mt-1 text-sm text-gray-400">Every product area at a glance</p>
        </div>
        {visibleItems.length > 0 && (
          <Badge className="bg-gray-800 text-gray-300">{visibleItems.length} areas</Badge>
        )}
      </div>

      {loading ? (
        <div className="flex flex-wrap gap-2">
          <Skeleton className="h-9 w-32" />
          <Skeleton className="h-9 w-28" />
          <Skeleton className="h-9 w-32" />
          <Skeleton className="h-9 w-24" />
        </div>
      ) : visibleItems.length ? (
        <div className="flex flex-wrap gap-2">
          {visibleItems.map((item) => (
            <ProductStatusPill key={item.id} item={item} />
          ))}
        </div>
      ) : (
        <div className="rounded-md border border-gray-800 bg-gray-950 px-4 py-3 text-sm text-gray-400">
          Area health is not available yet.
        </div>
      )}
    </Card>
  )
}

function ProductStatusPill({ item }: { item: DashboardProductStatusItem }) {
  const tone = productStatusTone(item.status)
  const Icon = productStatusIcon(item.id)

  return (
    <Link
      href={item.href}
      title={item.summary || undefined}
      className={`inline-flex items-center gap-2 rounded-lg border bg-gray-950 px-3 py-2 text-sm transition-colors hover:border-gray-600 ${tone.border} ${FOCUS_RING}`}
    >
      <Icon className={`h-4 w-4 ${tone.text}`} aria-hidden="true" />
      <span className="font-medium text-white">{item.label}</span>
      <span className={`h-1.5 w-1.5 rounded-full ${tone.dot}`} aria-hidden="true" />
      <span className="sr-only">{item.status}</span>
      {typeof item.primary_count === 'number' && (
        <span className="tabular-nums text-xs text-gray-400">{item.primary_count}</span>
      )}
    </Link>
  )
}

function ActionCenter({
  items,
  loading,
}: {
  items: DashboardActionItem[]
  loading: boolean
}) {
  const [showAll, setShowAll] = useState(false)
  const visibleItems = showAll ? items : items.slice(0, 6)

  return (
    <Card className="p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="font-medium text-white">Priority actions</h2>
          <p className="mt-1 text-sm text-gray-400">What to do first, ranked by urgency</p>
        </div>
        {items.length > 0 && (
          <Badge className="bg-blue-500/15 text-blue-300">{items.length} item{items.length === 1 ? '' : 's'}</Badge>
        )}
      </div>

      {loading ? (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
        </div>
      ) : visibleItems.length ? (
        <>
          <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
            {visibleItems.map((item) => (
              <ActionCenterRow key={item.id} item={item} />
            ))}
          </div>
          {items.length > 6 && (
            <button
              type="button"
              onClick={() => setShowAll((value) => !value)}
              className="mt-3 w-full rounded-md border border-gray-800 bg-gray-950 px-4 py-2 text-sm text-gray-300 hover:bg-gray-900 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              {showAll ? 'Show less' : `Show all ${items.length}`}
            </button>
          )}
        </>
      ) : (
        <div className="rounded-md border border-gray-800 bg-gray-950 px-4 py-3 text-sm text-gray-400">
          No high-priority operational actions right now.
        </div>
      )}
    </Card>
  )
}

function productStatusIcon(id: string) {
  switch (id) {
    case 'asm':
      return Workflow
    case 'ai_gate':
      return Bot
    case 'model_intake':
      return PackageCheck
    case 'exceptions':
      return AlertTriangle
    case 'deployment':
      return Rocket
    case 'dast':
      return ShieldCheck
    default:
      return Gauge
  }
}

function productStatusTone(status: string) {
  switch (status) {
    case 'critical':
      return {
        border: 'border-red-800/60',
        badge: 'bg-red-500/15 text-red-300',
        icon: 'bg-red-500/15 text-red-300',
        text: 'text-red-300',
        dot: 'bg-red-400',
      }
    case 'warning':
      return {
        border: 'border-amber-800/60',
        badge: 'bg-amber-500/15 text-amber-300',
        icon: 'bg-amber-500/15 text-amber-300',
        text: 'text-amber-300',
        dot: 'bg-amber-400',
      }
    case 'ok':
      return {
        border: 'border-emerald-800/50',
        badge: 'bg-emerald-500/15 text-emerald-300',
        icon: 'bg-emerald-500/15 text-emerald-300',
        text: 'text-emerald-300',
        dot: 'bg-emerald-400',
      }
    default:
      return {
        border: 'border-gray-800',
        badge: 'bg-blue-500/15 text-blue-300',
        icon: 'bg-blue-500/15 text-blue-300',
        text: 'text-blue-300',
        dot: 'bg-gray-500',
      }
  }
}

function ActionCenterRow({ item }: { item: DashboardActionItem }) {
  const tone = actionPriorityTone(item.priority)
  const actions = item.actions?.length
    ? item.actions
    : item.href
      ? [{ label: item.action_label || 'Open', href: item.href, variant: 'primary' }]
      : []
  const content = (
    <>
      <div className="flex min-w-0 items-start gap-3">
        <div className={`mt-0.5 rounded-md p-1.5 ${tone.icon}`}>
          {item.priority === 'info' ? (
            <CalendarClock className="h-4 w-4" aria-hidden="true" />
          ) : (
            <AlertTriangle className="h-4 w-4" aria-hidden="true" />
          )}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Badge className={tone.badge}>{item.priority}</Badge>
            <span className="text-xs text-gray-500">{item.category}</span>
            {typeof item.count === 'number' && item.count > 1 && (
              <span className="text-xs text-gray-500">{item.count} affected</span>
            )}
          </div>
          <h3 className="mt-1 text-sm font-medium text-white">{item.title}</h3>
          <p className="mt-1 text-sm text-gray-400">{item.detail}</p>
          {item.samples?.length ? (
            <div className="mt-2 space-y-1">
              {item.samples.slice(0, 2).map((sample, idx) => (
                <div key={`${item.id}-sample-${idx}`} className="truncate text-xs text-gray-500">
                  {sample.href ? (
                    <Link href={sample.href} className={`text-gray-400 hover:text-gray-200 ${FOCUS_RING}`}>
                      {sample.label || sample.href}
                    </Link>
                  ) : (
                    <span className="text-gray-400">{sample.label}</span>
                  )}
                  {sample.detail ? <span> - {sample.detail}</span> : null}
                </div>
              ))}
            </div>
          ) : null}
        </div>
      </div>
      {actions.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {actions.slice(0, 3).map((action, idx) => {
            const primary = (action.variant || (idx === 0 ? 'primary' : 'secondary')) === 'primary'
            return (
              <Link
                key={`${item.id}-action-${idx}`}
                href={action.href}
                className={`inline-flex min-h-8 items-center gap-1 rounded border px-2.5 py-1.5 text-xs font-medium transition-colors ${FOCUS_RING} ${
                  primary
                    ? 'border-blue-500/40 bg-blue-500/15 text-blue-200 hover:border-blue-400/60 hover:bg-blue-500/25'
                    : 'border-gray-700 bg-gray-900 text-gray-300 hover:border-gray-600 hover:text-gray-100'
                }`}
              >
                {action.label}
                <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
              </Link>
            )
          })}
        </div>
      )}
    </>
  )

  return (
    <div className="flex min-h-24 flex-col gap-3 rounded-md border border-gray-800 bg-gray-950 p-3">
      {content}
    </div>
  )
}

function actionPriorityTone(priority: DashboardActionItem['priority']) {
  switch (priority) {
    case 'critical':
      return {
        badge: 'bg-red-500/20 text-red-300',
        icon: 'bg-red-500/10 text-red-300',
      }
    case 'high':
      return {
        badge: 'bg-orange-500/20 text-orange-300',
        icon: 'bg-orange-500/10 text-orange-300',
      }
    case 'medium':
      return {
        badge: 'bg-yellow-500/20 text-yellow-300',
        icon: 'bg-yellow-500/10 text-yellow-300',
      }
    case 'low':
      return {
        badge: 'bg-gray-500/20 text-gray-300',
        icon: 'bg-gray-500/10 text-gray-300',
      }
    default:
      return {
        badge: 'bg-blue-500/20 text-blue-300',
        icon: 'bg-blue-500/10 text-blue-300',
      }
  }
}

function StatCard({
  title,
  value,
  icon,
  color,
  subtitle,
  href
}: {
  title: string
  value: React.ReactNode
  icon: React.ReactNode
  color: 'blue' | 'green' | 'yellow' | 'purple'
  subtitle?: string
  href?: string
}) {
  const colors = {
    blue: 'bg-blue-500/10 text-blue-400',
    green: 'bg-green-500/10 text-green-400',
    yellow: 'bg-yellow-500/10 text-yellow-400',
    purple: 'bg-purple-500/10 text-purple-400'
  }

  const content = (
    <div className="flex items-center gap-3">
      <div className={`p-2 rounded-lg ${colors[color]}`}>
        {icon}
      </div>
      <div>
        <p className="text-sm text-gray-400">{title}</p>
        <div className="text-2xl font-bold text-white">{value}</div>
        {subtitle && <p className="text-xs text-gray-500 mt-1">{subtitle}</p>}
      </div>
    </div>
  )

  if (href) {
    return (
      <Link
        href={href}
        className={`block bg-gray-900 rounded-lg border border-gray-800 p-4 hover:bg-gray-800/50 transition-colors ${FOCUS_RING}`}
      >
        {content}
      </Link>
    )
  }

  return (
    <Card className="p-4">
      {content}
    </Card>
  )
}

// Icons
function TargetIcon() {
  return (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
    </svg>
  )
}

function ScanIcon() {
  return (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
    </svg>
  )
}

function AlertIcon() {
  return (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
    </svg>
  )
}

function ScoreIcon() {
  return (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
    </svg>
  )
}
