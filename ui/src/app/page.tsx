'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { AlertTriangle, ArrowRight, Bot, CalendarClock, Cpu, Gauge, PackageCheck, Rocket, ShieldCheck, Workflow } from 'lucide-react'
import { getDashboard, getQueueStats, getWorkers, scaleWorkers, getSystemResources, getGungnirStatus, startGungnir, stopGungnir, clearQueue, getGradeColor, formatDate, type QueueStats, type WorkerStats, type SystemResources, type GungnirStatus, type DashboardActionItem, type DashboardProductStatusItem, type DashboardResponse } from '@/lib/api'
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
  const [systemResources, setSystemResources] = useState<SystemResources | null>(null)
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

  const fetchSystemResources = async () => {
    try {
      setSystemResources(await getSystemResources())
    } catch {
      setSystemResources({ available: false, error: 'unavailable' })
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
    fetchSystemResources()
    const interval = setInterval(fetchSystemResources, WORKERS_REFRESH_MS)
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
  const queueCompleted = queue ? queue.completed : '--'
  const queueFailed = queue ? queue.failed : '--'
  const workerCount = workers?.count
  const workersKnown = workerCount !== undefined && workerCount >= 0
  const maxWorkers = workers?.max_allowed && workers.max_allowed > 0 ? workers.max_allowed : 20
  const staleCount = workers?.stale_workers?.length ?? 0
  // Busy workers ~= jobs currently running; idle = running workers - busy.
  const busyWorkers = typeof queue?.running === 'number' ? Math.min(queue.running, workerCount ?? 0) : null
  const idleWorkers = workersKnown && busyWorkers !== null ? Math.max(0, (workerCount as number) - busyWorkers) : null
  const workerLabel = workersError
    ? workersError
    : workersKnown
      ? `${workerCount} running`
      : 'Workers unavailable'
  // Docker resource ceiling (Docker Desktop VM allocation on mac/win; host on Linux).
  const dockerGiB = systemResources?.available && systemResources.mem_total_bytes
    ? systemResources.mem_total_bytes / 1024 ** 3
    : null
  const scaleOptions = Array.from(new Set([1, 2, 3, 5, 10, 15, 20, 25, 30, 40].filter(n => n <= maxWorkers)))

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-gray-400 mt-1">Security scanning overview</p>
        </div>
        <LastUpdated updatedAt={lastUpdated} onRefresh={handleManualRefresh} refreshing={refreshing} />
      </div>

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

      <ProductStatusStrip items={data?.product_status || []} loading={dashboardLoading && !data} />

      <ActionCenter items={data?.action_center || []} loading={dashboardLoading && !data} />

      {/* Queue Status & Worker Control */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Queue Status */}
        <Card className="p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-medium text-gray-400">Queue Status</h2>
            <button
              type="button"
              onClick={() => { setClearRetests(false); setShowClearQueue(true) }}
              className={`text-xs text-gray-500 hover:text-red-400 transition-colors rounded ${FOCUS_RING}`}
            >
              Emergency clear
            </button>
          </div>
          <div className="flex flex-wrap gap-4">
            <Link href="/scans?status=pending" className={`flex items-center gap-2 hover:opacity-80 transition-opacity rounded ${FOCUS_RING}`}>
              <div className={`w-2 h-2 rounded-full bg-yellow-500 ${queuePending !== '--' && queuePending > 0 ? 'animate-pulse' : ''}`}></div>
              <span className="text-sm">{queuePending} pending</span>
            </Link>
            <Link href="/scans?status=running" className={`flex items-center gap-2 hover:opacity-80 transition-opacity rounded ${FOCUS_RING}`}>
              <div className={`w-2 h-2 rounded-full bg-blue-500 ${queueRunning !== '--' && queueRunning > 0 ? 'animate-pulse' : ''}`}></div>
              <span className="text-sm">{queueRunning} running</span>
            </Link>
            <Link href="/scans?status=completed" className={`flex items-center gap-2 hover:opacity-80 transition-opacity rounded ${FOCUS_RING}`}>
              <div className="w-2 h-2 rounded-full bg-green-500"></div>
              <span className="text-sm">{queueCompleted} completed</span>
            </Link>
            <Link href="/scans?status=failed" className={`flex items-center gap-2 hover:opacity-80 transition-opacity rounded ${FOCUS_RING}`}>
              <div className="w-2 h-2 rounded-full bg-red-500"></div>
              <span className="text-sm">{queueFailed} failed</span>
            </Link>
          </div>
          {queueError && (
            <p className="text-xs text-red-400 mt-3">{queueError}</p>
          )}
        </Card>

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

        {/* Workers & Resources */}
        <Card className="p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-medium text-gray-400">Workers &amp; Resources</h2>
            {staleCount > 0 && (
              <span
                title="Workers running an outdated build (version skew). Re-scale to refresh."
                className="text-xs px-1.5 py-0.5 rounded bg-amber-900/40 text-amber-400 border border-amber-800/50"
              >
                ⚠ {staleCount} stale
              </span>
            )}
          </div>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <WorkerIcon />
              <span className="text-sm">{workerLabel}{workersKnown ? <span className="text-gray-500"> / {maxWorkers} max</span> : null}</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => handleScale(Math.max(1, (workerCount || 1) - 1))}
                disabled={scaling || !workersKnown || (workerCount || 0) <= 1}
                aria-label="Decrease worker count"
                className={`px-2 py-1 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed rounded text-sm ${FOCUS_RING}`}
              >
                -
              </button>
              <span className="text-sm font-medium w-8 text-center">{workersKnown ? workerCount : '?'}</span>
              <button
                type="button"
                onClick={() => handleScale(Math.min(maxWorkers, (workerCount || 1) + 1))}
                disabled={scaling || !workersKnown || (workerCount || 0) >= maxWorkers}
                aria-label="Increase worker count"
                className={`px-2 py-1 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed rounded text-sm ${FOCUS_RING}`}
              >
                +
              </button>
              <select
                value=""
                onChange={(e) => handleScale(parseInt(e.target.value))}
                disabled={scaling || !workersKnown}
                aria-label="Scale workers to a specific count"
                className={`ml-2 px-2 py-1 bg-gray-800 border border-gray-700 rounded text-sm disabled:opacity-50 ${FOCUS_RING}`}
              >
                <option value="">Scale to...</option>
                {scaleOptions.map(n => (
                  <option key={n} value={n}>{n} workers</option>
                ))}
              </select>
            </div>
          </div>

          {/* busy / idle / capacity */}
          {workersKnown && (
            <div className="mt-3 flex items-center gap-4 text-xs">
              <span className="flex items-center gap-1.5">
                <span className={`w-2 h-2 rounded-full bg-blue-500 ${busyWorkers ? 'animate-pulse' : ''}`}></span>
                <span className="text-gray-400">{busyWorkers ?? '--'} busy</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-green-500"></span>
                <span className="text-gray-400">{idleWorkers ?? '--'} idle</span>
              </span>
              <span className="text-gray-600">capacity {maxWorkers}</span>
            </div>
          )}

          {/* Docker engine resources (Desktop VM allocation on mac/win, host on Linux) */}
          <div className="mt-3 pt-3 border-t border-gray-800 text-xs text-gray-400">
            {systemResources?.available ? (
              <div className="flex items-center gap-4">
                <span title="vCPUs available to the Docker engine">{systemResources.cpus ?? '--'} CPU</span>
                <span title="RAM available to the Docker engine">{dockerGiB !== null ? `${dockerGiB.toFixed(1)} GiB` : '-- GiB'} RAM</span>
                <span className="text-gray-600">
                  {systemResources.is_desktop_vm
                    ? `Docker Desktop VM${systemResources.operating_system ? ` · ${systemResources.operating_system}` : ''}`
                    : (systemResources.operating_system || 'Docker host')}
                </span>
              </div>
            ) : (
              <span className="text-gray-600">Docker resource info unavailable</span>
            )}
          </div>
          {scaling && (
            <p className="text-xs text-blue-400 mt-2">Scaling workers...</p>
          )}
        </Card>
      </div>

      {/* Gungnir CT Monitor */}
      <Card className="p-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-medium text-gray-400">Gungnir CT Monitor</h2>
            <p className="text-xs text-gray-500 mt-1">Real-time Certificate Transparency monitoring</p>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right text-sm">
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${gungnir?.running ? 'bg-green-500 animate-pulse' : 'bg-gray-500'}`}></div>
                <span className={gungnir?.running ? 'text-green-400' : 'text-gray-400'}>
                  {gungnir?.running ? 'Running' : 'Stopped'}
                </span>
              </div>
              {gungnir?.running && (
                <p className="text-xs text-gray-500 mt-1">
                  {gungnir.domains_monitored} domains - {gungnir.session_found} found this session
                </p>
              )}
            </div>
            <button
              type="button"
              onClick={handleGungnirToggle}
              disabled={gungnirActionLoading}
              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors disabled:opacity-50 ${FOCUS_RING} ${
                gungnir?.running
                  ? 'bg-red-500/20 text-red-400 hover:bg-red-500/30'
                  : 'bg-green-500/20 text-green-400 hover:bg-green-500/30'
              }`}
            >
              {gungnirActionLoading ? '...' : gungnir?.running ? 'Stop' : 'Start'}
            </button>
          </div>
        </div>
        {gungnir?.last_discovery && (
          <p className="text-xs text-gray-500 mt-2">
            Last discovery: <span className="text-gray-400">{gungnir.last_discovery}</span>
          </p>
        )}
        {gungnir?.subdomains_found ? (
          <p className="text-xs text-gray-500 mt-1">
            Total subdomains discovered: <span className="text-gray-400">{gungnir.subdomains_found}</span>
          </p>
        ) : null}
      </Card>

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
  const visibleItems = items.slice(0, 7)

  return (
    <Card className="p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="font-medium text-white">Product Status</h2>
          <p className="mt-1 text-sm text-gray-400">Blockers and quick links across DAST, ASM, AI, model trust, policy, and workers</p>
        </div>
        {visibleItems.length > 0 && (
          <Badge className="bg-gray-800 text-gray-300">{visibleItems.length} areas</Badge>
        )}
      </div>

      {loading ? (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
        </div>
      ) : visibleItems.length ? (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
          {visibleItems.map((item) => (
            <ProductStatusCard key={item.id} item={item} />
          ))}
        </div>
      ) : (
        <div className="rounded-md border border-gray-800 bg-gray-950 px-4 py-3 text-sm text-gray-400">
          Product status is not available yet.
        </div>
      )}
    </Card>
  )
}

function ProductStatusCard({ item }: { item: DashboardProductStatusItem }) {
  const tone = productStatusTone(item.status)
  const actions = item.actions?.length ? item.actions : [{ label: 'Open', href: item.href, variant: 'primary' }]
  const Icon = productStatusIcon(item.id)

  return (
    <div className={`flex min-h-32 flex-col justify-between rounded-md border bg-gray-950 p-3 ${tone.border}`}>
      <div>
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 items-center gap-2">
            <span className={`rounded-md p-1.5 ${tone.icon}`}>
              <Icon className="h-4 w-4" aria-hidden="true" />
            </span>
            <div className="min-w-0">
              <Link href={item.href} className={`block truncate text-sm font-medium text-white hover:text-blue-200 ${FOCUS_RING}`}>
                {item.label}
              </Link>
              <Badge className={`mt-1 ${tone.badge}`}>{item.status}</Badge>
            </div>
          </div>
          <div className="shrink-0 text-right">
            {typeof item.primary_count === 'number' && (
              <div className="text-lg font-semibold text-white">{item.primary_count}</div>
            )}
            {item.primary_label && (
              <div className="max-w-20 truncate text-xs text-gray-500">{item.primary_label}</div>
            )}
          </div>
        </div>
        <p className="mt-3 line-clamp-2 text-sm text-gray-400">{item.summary}</p>
        {typeof item.secondary_count === 'number' && item.secondary_label ? (
          <p className="mt-2 text-xs text-gray-500">
            <span className="text-gray-300">{item.secondary_count}</span> {item.secondary_label}
          </p>
        ) : null}
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        {actions.slice(0, 2).map((action, idx) => {
          const primary = (action.variant || (idx === 0 ? 'primary' : 'secondary')) === 'primary'
          return (
            <Link
              key={`${item.id}-status-action-${idx}`}
              href={action.href}
              className={`inline-flex min-h-8 items-center gap-1 rounded border px-2.5 py-1.5 text-xs font-medium transition-colors ${FOCUS_RING} ${
                primary
                  ? 'border-blue-500/40 bg-blue-500/15 text-blue-200 hover:border-blue-400/60 hover:bg-blue-500/25'
                  : 'border-gray-700 bg-gray-900 text-gray-300 hover:border-gray-600 hover:text-gray-100'
              }`}
            >
              {action.label}
              {primary && <ArrowRight className="h-3 w-3" aria-hidden="true" />}
            </Link>
          )
        })}
      </div>
    </div>
  )
}

function ActionCenter({
  items,
  loading,
}: {
  items: DashboardActionItem[]
  loading: boolean
}) {
  const visibleItems = items.slice(0, 6)

  return (
    <Card className="p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="font-medium text-white">Action Center</h2>
          <p className="mt-1 text-sm text-gray-400">Prioritized work from scanner, ASM, policy, AI, and model-intake state</p>
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
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          {visibleItems.map((item) => (
            <ActionCenterRow key={item.id} item={item} />
          ))}
        </div>
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
    case 'workers':
      return Cpu
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
      }
    case 'warning':
      return {
        border: 'border-amber-800/60',
        badge: 'bg-amber-500/15 text-amber-300',
        icon: 'bg-amber-500/15 text-amber-300',
      }
    case 'ok':
      return {
        border: 'border-emerald-800/50',
        badge: 'bg-emerald-500/15 text-emerald-300',
        icon: 'bg-emerald-500/15 text-emerald-300',
      }
    default:
      return {
        border: 'border-gray-800',
        badge: 'bg-blue-500/15 text-blue-300',
        icon: 'bg-blue-500/15 text-blue-300',
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

function WorkerIcon() {
  return (
    <svg className="w-4 h-4 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
    </svg>
  )
}
