'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import Link from 'next/link'
import { AlertTriangle, ArrowRight, CheckCircle2, CircleHelp, ListTodo, Minus, Plus, RadioTower, ScanLine, Server, ShieldAlert, Target, Trash2, Workflow } from 'lucide-react'
import {
  clearQueue, formatDate, getDashboard, getExposureAssets, getGradeColor, getGungnirStatus,
  getMissionTimeline, getQueueStats, getTargetsGrouped, getWorkers, scaleWorkers, startGungnir,
  stopGungnir, type DashboardActionItem, type DashboardResponse, type ExposureAssetsResponse,
  type GroupedDomain, type GungnirStatus, type QueueStats, type Scan, type TimelineEvent,
  type WorkerStats,
} from '@/lib/api'
import {
  Badge,
  Card,
  ConfirmDialog,
  ErrorState,
  LastUpdated,
  ScanStatusBadge,
  Skeleton,
  useToast,
} from '@/components/ui'
import { ChangesStrip } from '@/app/exposure/ChangesStrip'
import { boundedDisplayText } from '@/lib/targetChoices'

const DASHBOARD_REFRESH_MS = 10000
const QUEUE_REFRESH_MS = 15000
const WORKERS_REFRESH_MS = 30000
const GUNGNIR_REFRESH_MS = 30000
const OVERVIEW_REFRESH_MS = 60000

const FOCUS_RING = 'focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500'

export default function Dashboard() {
  const toast = useToast()
  const [data, setData] = useState<DashboardResponse | null>(null)
  const [queue, setQueue] = useState<QueueStats | null>(null)
  const [workers, setWorkers] = useState<WorkerStats | null>(null)
  const [gungnir, setGungnir] = useState<GungnirStatus | null>(null)
  const [exposure, setExposure] = useState<ExposureAssetsResponse | null>(null)
  const [groupedTargets, setGroupedTargets] = useState<GroupedDomain[]>([])
  const [timeline, setTimeline] = useState<TimelineEvent[]>([])
  const [overviewLoading, setOverviewLoading] = useState(true)
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
  const overviewInFlight = useRef(false)

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

  const fetchOverview = async () => {
    if (overviewInFlight.current) return
    overviewInFlight.current = true
    try {
      const [exposureResult, targetsResult, timelineResult] = await Promise.allSettled([
        getExposureAssets({ limit: 1000 }),
        getTargetsGrouped({ sort_by: 'active_findings_count', sort_order: 'desc' }),
        getMissionTimeline({ limit: 12 }),
      ])
      if (exposureResult.status === 'fulfilled') setExposure(exposureResult.value)
      if (targetsResult.status === 'fulfilled') setGroupedTargets(targetsResult.value.domains || [])
      if (timelineResult.status === 'fulfilled') setTimeline(timelineResult.value.events || [])
    } finally {
      overviewInFlight.current = false
      setOverviewLoading(false)
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

  useEffect(() => {
    fetchOverview()
    const interval = setInterval(fetchOverview, OVERVIEW_REFRESH_MS)
    return () => clearInterval(interval)
  }, [])

  const handleManualRefresh = async () => {
    if (refreshing) return
    setRefreshing(true)
    const [ok] = await Promise.all([fetchDashboard(false), fetchOverview()])
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

  const queuePending = queue ? queue.pending : '--'
  const queueRunning = queue ? queue.running : '--'
  const workPending = queue ? (queue.work_pending ?? queue.pending) : '--'
  const workRunning = queue ? (queue.work_running ?? queue.running) : '--'
  const workerCount = workers?.count
  const workersKnown = workerCount !== undefined && workerCount >= 0
  const executionCapacity = workers?.execution_capacity
  const fleetEnabled = workers?.fleet?.enabled === true
  const localAvailable = executionCapacity?.local_available ?? (workers?.current_count ?? workerCount ?? 0)
  const remoteAvailable = fleetEnabled ? (executionCapacity?.remote_available ?? 0) : 0
  const totalAvailable = fleetEnabled ? (executionCapacity?.total_available ?? localAvailable) : localAvailable
  const maxWorkers = workers?.max_allowed && workers.max_allowed > 0 ? workers.max_allowed : 20
  const staleCount = workers?.stale_workers?.length ?? 0
  const coverage = useMemo(() => buildCoverageRollup(groupedTargets), [groupedTargets])
  const meaningfulActivity = useMemo(
    () => timeline.filter(isMeaningfulActivity).slice(0, 5),
    [timeline],
  )

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-gray-400 mt-1">What changed, what is proven, and what needs attention</p>
        </div>
        <div className="flex w-full flex-wrap items-center gap-2 xl:w-auto xl:justify-end">
          <div className="flex h-10 items-center gap-2 rounded-lg border border-gray-800 bg-gray-900 px-2.5" aria-label="Scan and work queue">
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
                  <span className="hidden text-gray-500 sm:inline">scans pending</span>
                </Link>
                <Link
                  href="/scans?status=running"
                  title={`${queueRunning} running scans`}
                  className={`flex items-center gap-1.5 rounded text-xs text-gray-300 hover:text-white ${FOCUS_RING}`}
                >
                  <span className={`h-2 w-2 rounded-full bg-blue-500 ${queueRunning !== '--' && queueRunning > 0 ? 'animate-pulse' : ''}`} />
                  <span className="font-medium tabular-nums">{queueRunning}</span>
                  <span className="hidden text-gray-500 sm:inline">scan{queueRunning === 1 ? '' : 's'} running</span>
                </Link>
                {(workPending !== queuePending || workRunning !== queueRunning) && (
                  <span
                    className="hidden rounded bg-gray-800 px-1.5 py-0.5 text-[10px] font-medium text-gray-300 lg:inline"
                    title={`${workPending} queued and ${workRunning} running worker jobs, including parallel shards`}
                  >
                    {workRunning} work unit{workRunning === 1 ? '' : 's'} running
                  </span>
                )}
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
            id="workers"
            className="flex h-10 items-center gap-2 rounded-lg border border-gray-800 bg-gray-900 px-2.5"
            title={workersError || (fleetEnabled
              ? `${totalAvailable} available: ${localAvailable} local, ${remoteAvailable} remote`
              : `${localAvailable} current-build workers are schedulable`)}
          >
            <Server className="h-4 w-4 shrink-0 text-gray-500" aria-hidden="true" />
            <span className="min-w-6 text-center text-sm font-medium tabular-nums text-white">
              {workersKnown ? totalAvailable : '--'}
            </span>
            <span className="hidden text-xs text-gray-500 sm:inline">{fleetEnabled ? 'schedulable' : 'current'}</span>
            {fleetEnabled && (
              <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] font-medium text-gray-300" title={`${workerCount ?? 0} local ${(workerCount ?? 0) === 1 ? 'worker' : 'workers'} running`}>
                {localAvailable} local
              </span>
            )}
            {staleCount > 0 && (
              <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-300" title="Workers running an outdated build">
                {staleCount} stale
              </span>
            )}
            {!fleetEnabled && workersKnown && (
              <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] font-medium text-gray-300" title={`Worker safety limit: ${maxWorkers}`}>
                {workerCount} workers · limit {maxWorkers}
              </span>
            )}
            <span className="h-5 w-px bg-gray-800" aria-hidden="true" />
            <button
              type="button"
              onClick={() => handleScale(Math.max(1, (workerCount || 1) - 1))}
              disabled={scaling || !workersKnown || (workerCount || 0) <= 1}
              aria-label={fleetEnabled ? 'Decrease local worker count' : 'Decrease worker count'}
              title={fleetEnabled ? 'Decrease local worker count' : 'Decrease worker count'}
              className={`flex h-7 w-7 items-center justify-center rounded text-gray-400 transition-colors hover:bg-gray-800 hover:text-white disabled:cursor-not-allowed disabled:opacity-30 ${FOCUS_RING}`}
            >
              <Minus className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
            <button
              type="button"
              onClick={() => handleScale(Math.min(maxWorkers, (workerCount || 1) + 1))}
              disabled={scaling || !workersKnown || (workerCount || 0) >= maxWorkers}
              aria-label={fleetEnabled ? 'Increase local worker count' : 'Increase worker count'}
              title={(workerCount || 0) >= maxWorkers
                ? `Worker safety limit reached (${maxWorkers})`
                : fleetEnabled ? 'Increase local worker count' : 'Increase worker count'}
              className={`flex h-7 w-7 items-center justify-center rounded text-gray-400 transition-colors hover:bg-gray-800 hover:text-white disabled:cursor-not-allowed disabled:opacity-30 ${FOCUS_RING}`}
            >
              <Plus className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
            {fleetEnabled && (
              <Link
                href="/fleet"
                className="rounded bg-blue-500/10 px-1.5 py-0.5 text-[10px] font-medium text-blue-300 hover:bg-blue-500/20"
                title={`${executionCapacity?.remote_nodes_available ?? 0} remote nodes available`}
              >
                {remoteAvailable} remote
              </Link>
            )}
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

      <SecurityPosture exposure={exposure} loading={overviewLoading} />

      <ChangesStrip storageKey="dashboard" />

      <CoverageOverview exposure={exposure} coverage={coverage} loading={overviewLoading} />

      <ActionCenter items={data?.action_center || []} loading={dashboardLoading && !data} />

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <LatestResults scans={data?.recent_scans || []} loading={dashboardLoading && !data} />
        <RecentActivity events={meaningfulActivity} loading={overviewLoading} />
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
  const actionableItems = items.filter((item) => item.id !== 'worker-build-freshness' && item.priority !== 'info')
  const visibleItems = actionableItems.slice(0, 3)

  return (
    <Card className="p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="font-medium text-white">Top actions</h2>
          <p className="mt-1 text-sm text-gray-400">The three highest-impact things to address next</p>
        </div>
        <Link href="/exposure" className={`inline-flex items-center gap-1 text-xs text-blue-300 hover:text-blue-200 ${FOCUS_RING}`}>
          View all priorities <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>

      {loading ? (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
        </div>
      ) : visibleItems.length ? (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
          {visibleItems.map((item) => <ActionCenterRow key={item.id} item={item} />)}
        </div>
      ) : (
        <div className="rounded-md border border-gray-800 bg-gray-950 px-4 py-3 text-sm text-gray-400">
          No high-priority operational actions right now.
        </div>
      )}
    </Card>
  )
}

function ActionCenterRow({ item }: { item: DashboardActionItem }) {
  const tone = actionPriorityTone(item.priority)
  const action = (item.actions?.length
    ? item.actions
    : item.href
      ? [{ label: item.action_label || 'Open', href: item.href, variant: 'primary' }]
      : [])[0]
  return (
    <div className="flex min-h-40 flex-col rounded-lg border border-gray-800 bg-gray-950/70 p-4">
      <div className="flex min-w-0 flex-1 items-start gap-3">
        <div className={`mt-0.5 rounded-md p-1.5 ${tone.icon}`}>
          <AlertTriangle className="h-4 w-4" aria-hidden="true" />
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
          <p className="mt-1 line-clamp-2 text-sm leading-5 text-gray-400">{item.detail}</p>
        </div>
      </div>
      {action ? (
        <Link href={action.href} className={`mt-4 inline-flex items-center gap-1 self-start text-xs font-medium text-blue-300 hover:text-blue-200 ${FOCUS_RING}`}>
          {action.label} <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      ) : null}
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

function SecurityPosture({ exposure, loading }: { exposure: ExposureAssetsResponse | null; loading: boolean }) {
  const metrics = exposure?.metrics
  const verified = metrics?.active_verified || 0
  const needsVerification = metrics?.active_needs_verification || 0
  const p1 = metrics?.p1_count || 0
  const fresh = metrics?.fresh_scans || 0
  const assetCount = metrics?.asset_count || 0
  const proofTotal = verified + needsVerification
  const verifiedWidth = proofTotal ? Math.max(2, (verified / proofTotal) * 100) : 0
  const primary = verified > 0
    ? { href: '/exposure?posture=verified', label: 'Review proven risk' }
    : p1 > 0
      ? { href: '/exposure?posture=p1', label: 'Review P1 assets' }
      : assetCount > 0
        ? { href: '/scan/new', label: 'Start a scan' }
        : { href: '/targets', label: 'Add a target' }

  return (
    <Card className="overflow-hidden">
      <div className="flex flex-col gap-3 border-b border-gray-800 p-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="font-medium text-white">Security posture</h2>
          <p className="mt-1 text-sm text-gray-400">Verified risk, uncertain signals, and assets that need attention</p>
        </div>
        <Link href={primary.href} className={`inline-flex items-center gap-1 self-start rounded-lg border border-blue-500/40 bg-blue-500/10 px-3 py-2 text-sm font-medium text-blue-200 hover:bg-blue-500/20 ${FOCUS_RING}`}>
          {primary.label} <ArrowRight className="h-4 w-4" />
        </Link>
      </div>
      {loading && !metrics ? (
        <div className="grid gap-3 p-4 sm:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, index) => <Skeleton key={index} className="h-24" />)}
        </div>
      ) : (
        <>
          <div className="grid divide-y divide-gray-800 sm:grid-cols-2 sm:divide-x sm:divide-y-0 xl:grid-cols-4">
            <PostureStat href="/exposure?posture=verified" icon={<CheckCircle2 className="h-4 w-4" />} label="Proven active risk" value={verified} hint={`${metrics?.verified_assets || 0} affected assets`} tone="emerald" />
            <PostureStat href="/exposure?posture=needs_verification" icon={<CircleHelp className="h-4 w-4" />} label="Needs verification" value={needsVerification} hint={`${metrics?.unverified_high_assets || 0} high-impact assets`} tone="amber" />
            <PostureStat href="/exposure?posture=p1" icon={<ShieldAlert className="h-4 w-4" />} label="P1 assets" value={p1} hint="highest action priority" tone="red" />
            <PostureStat href="/exposure" icon={<Target className="h-4 w-4" />} label="Freshly assessed" value={fresh} hint={`of ${assetCount} known assets`} tone="blue" />
          </div>
          <div className="border-t border-gray-800 px-4 py-3">
            <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2 text-xs">
              <span className="text-gray-500">Evidence confidence across active findings</span>
              <span className="text-gray-400">{verified} proven · {needsVerification} awaiting verification</span>
            </div>
            <div className="flex h-2 overflow-hidden rounded-full bg-gray-800" aria-label={`${verified} proven active findings and ${needsVerification} findings needing verification`}>
              <div className="bg-emerald-500" style={{ width: `${verifiedWidth}%` }} />
              <div className="flex-1 bg-amber-500/70" />
            </div>
          </div>
        </>
      )}
    </Card>
  )
}

function PostureStat({ href, icon, label, value, hint, tone }: {
  href: string
  icon: React.ReactNode
  label: string
  value: number
  hint: string
  tone: 'emerald' | 'amber' | 'red' | 'blue'
}) {
  const tones = {
    emerald: 'bg-emerald-500/10 text-emerald-300',
    amber: 'bg-amber-500/10 text-amber-300',
    red: 'bg-red-500/10 text-red-300',
    blue: 'bg-blue-500/10 text-blue-300',
  }
  return (
    <Link href={href} className={`flex items-center gap-3 p-4 hover:bg-gray-800/30 ${FOCUS_RING} focus-visible:ring-inset`}>
      <span className={`rounded-lg p-2 ${tones[tone]}`}>{icon}</span>
      <span className="min-w-0">
        <span className="block text-xs text-gray-500">{label}</span>
        <span className="block text-2xl font-semibold tabular-nums text-white">{value.toLocaleString()}</span>
        <span className="block truncate text-xs text-gray-600">{hint}</span>
      </span>
    </Link>
  )
}

interface CoverageTarget {
  id: string
  url: string
  tested: number
  denominator: number
  remaining: number
  coverage: number
}

interface CoverageRollup {
  targets: CoverageTarget[]
  tested: number
  denominator: number
  remaining: number
  coverage: number
}

function buildCoverageRollup(domains: GroupedDomain[]): CoverageRollup {
  const targets: CoverageTarget[] = []
  const seen = new Set<string>()
  for (const domain of domains) {
    for (const target of [domain.root_target, ...(domain.subdomains || [])]) {
      if (!target?.asm_coverage || seen.has(target.id)) continue
      seen.add(target.id)
      const summary = target.asm_coverage
      const denominator = summary.testable ?? summary.denominator ?? summary.total ?? 0
      const tested = Math.min(denominator, summary.tested || 0)
      targets.push({
        id: target.id,
        url: target.url,
        tested,
        denominator,
        remaining: Math.max(0, denominator - tested),
        coverage: denominator ? tested / denominator : 0,
      })
    }
  }
  const tested = targets.reduce((sum, target) => sum + target.tested, 0)
  const denominator = targets.reduce((sum, target) => sum + target.denominator, 0)
  return {
    targets: targets.sort((a, b) => b.remaining - a.remaining),
    tested,
    denominator,
    remaining: Math.max(0, denominator - tested),
    coverage: denominator ? tested / denominator : 0,
  }
}

function CoverageOverview({ exposure, coverage, loading }: {
  exposure: ExposureAssetsResponse | null
  coverage: CoverageRollup
  loading: boolean
}) {
  const metrics = exposure?.metrics
  const totalAssets = metrics?.asset_count || 0
  const freshness = [
    { label: 'Fresh', value: metrics?.fresh_scans || 0, color: 'bg-emerald-500' },
    { label: 'Stale', value: metrics?.stale_assets || 0, color: 'bg-amber-500' },
    { label: 'Failed', value: metrics?.failed_scans || 0, color: 'bg-red-500' },
    { label: 'Never scanned', value: metrics?.unscanned_assets || 0, color: 'bg-gray-500' },
  ]
  return (
    <Card className="p-4">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="font-medium text-white">Coverage and freshness</h2>
          <p className="mt-1 text-sm text-gray-400">How much has been tested, and which results are aging out</p>
        </div>
        <Link href="/asm" className={`inline-flex items-center gap-1 text-xs text-blue-300 hover:text-blue-200 ${FOCUS_RING}`}>
          Open Coverage <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>
      {loading && !metrics ? <Skeleton className="h-40" /> : (
        <div className="grid gap-6 lg:grid-cols-2">
          <section>
            <div className="mb-3 flex items-center gap-2">
              <Target className="h-4 w-4 text-gray-500" />
              <h3 className="text-sm font-medium text-gray-200">Asset freshness</h3>
              <span className="ml-auto text-xs text-gray-600">{totalAssets} assets</span>
            </div>
            <div className="grid gap-2.5">
              {freshness.map((item) => (
                <ProgressRow key={item.label} label={item.label} value={item.value} total={totalAssets} color={item.color} />
              ))}
            </div>
          </section>
          <section className="border-t border-gray-800 pt-5 lg:border-l lg:border-t-0 lg:pl-6 lg:pt-0">
            <div className="mb-3 flex items-center gap-2">
              <Workflow className="h-4 w-4 text-gray-500" />
              <h3 className="text-sm font-medium text-gray-200">Continuous endpoint coverage</h3>
              <span className="ml-auto text-xs tabular-nums text-gray-500">{Math.round(coverage.coverage * 100)}%</span>
            </div>
            <ProgressRow label="Tested endpoints" value={coverage.tested} total={coverage.denominator} color="bg-blue-500" />
            <p className="mt-2 text-xs text-gray-600">{coverage.tested.toLocaleString()} tested · {coverage.remaining.toLocaleString()} remaining across {coverage.targets.length} inventoried targets</p>
            <div className="mt-3 grid gap-1.5">
              {coverage.targets.slice(0, 3).map((target) => (
                <Link key={target.id} href={`/asm?target_id=${target.id}`} className={`flex items-center gap-3 rounded-md px-2 py-1.5 hover:bg-gray-800/50 ${FOCUS_RING}`}>
                  <span className="min-w-0 flex-1 truncate text-xs text-gray-300">{shortHost(target.url)}</span>
                  <span className="text-xs tabular-nums text-gray-600">{target.remaining.toLocaleString()} remaining</span>
                </Link>
              ))}
              {!coverage.targets.length ? <p className="text-xs text-gray-600">No persistent endpoint inventories yet.</p> : null}
            </div>
          </section>
        </div>
      )}
    </Card>
  )
}

function ProgressRow({ label, value, total, color }: { label: string; value: number; total: number; color: string }) {
  const percent = total ? Math.min(100, Math.max(0, (value / total) * 100)) : 0
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-xs">
        <span className="text-gray-500">{label}</span>
        <span className="tabular-nums text-gray-400">{value.toLocaleString()}</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-gray-800">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${percent}%` }} />
      </div>
    </div>
  )
}

function LatestResults({ scans, loading }: { scans: Scan[]; loading: boolean }) {
  return (
    <Card className="overflow-hidden">
      <div className="flex items-center justify-between border-b border-gray-800 p-4">
        <div>
          <h2 className="font-medium text-white">Latest target results</h2>
          <p className="mt-1 text-sm text-gray-400">One current result per target</p>
        </div>
        <Link href="/scans" className={`text-xs text-blue-300 hover:text-blue-200 ${FOCUS_RING}`}>All scans</Link>
      </div>
      <div className="divide-y divide-gray-800">
        {loading ? Array.from({ length: 4 }).map((_, index) => <Skeleton key={index} className="m-4 h-10" />)
          : scans.length ? scans.slice(0, 5).map((scan) => (
            <Link key={scan.id} href={`/scans/${scan.id}`} className={`flex items-center gap-3 p-4 hover:bg-gray-800/40 ${FOCUS_RING} focus-visible:ring-inset`}>
              <span className="rounded-lg bg-blue-500/10 p-2 text-blue-300"><ScanLine className="h-4 w-4" /></span>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm font-medium text-gray-200">{shortHost(scan.target_url)}</span>
                <span className="block text-xs text-gray-500">{friendlyScanType(scan)} · {formatDate(scan.completed_at || scan.created_at)}</span>
              </span>
              {typeof scan.findings_count === 'number' ? <span className="hidden text-xs tabular-nums text-gray-500 sm:block">{scan.findings_count} findings</span> : null}
              {scan.grade ? <span className={`text-lg font-semibold ${getGradeColor(scan.grade)}`}>{scan.grade}</span> : null}
              <ScanStatusBadge status={scan.status} />
            </Link>
          )) : <p className="p-5 text-sm text-gray-500">No scan results yet. Add a target and run the first scan.</p>}
      </div>
    </Card>
  )
}

function RecentActivity({ events, loading }: { events: TimelineEvent[]; loading: boolean }) {
  return (
    <Card className="overflow-hidden">
      <div className="flex items-center justify-between border-b border-gray-800 p-4">
        <div>
          <h2 className="font-medium text-white">Recent activity</h2>
          <p className="mt-1 text-sm text-gray-400">Meaningful results across scans, verification, and investigations</p>
        </div>
        <Link href="/timeline" className={`text-xs text-blue-300 hover:text-blue-200 ${FOCUS_RING}`}>Full timeline</Link>
      </div>
      <div className="divide-y divide-gray-800">
        {loading ? Array.from({ length: 4 }).map((_, index) => <Skeleton key={index} className="m-4 h-10" />)
          : events.length ? events.map((event) => {
            const href = activityHref(event)
            const body = (
              <>
                <span className={`mt-0.5 h-2 w-2 flex-none rounded-full ${activityTone(event.status)}`} />
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-medium text-gray-200">{boundedDisplayText(activityTitle(event), 96)}</span>
                  <span className="block truncate text-xs text-gray-500">{boundedDisplayText(event.operator_message || event.target_url || event.kind.replace(/_/g, ' '), 160)}</span>
                </span>
                <span className="flex-none text-xs text-gray-600">{event.created_at ? formatDate(event.created_at) : ''}</span>
              </>
            )
            return href ? (
              <Link key={event.event_id} href={href} className={`flex items-start gap-3 p-4 hover:bg-gray-800/40 ${FOCUS_RING} focus-visible:ring-inset`}>{body}</Link>
            ) : <div key={event.event_id} className="flex items-start gap-3 p-4">{body}</div>
          }) : <p className="p-5 text-sm text-gray-500">No meaningful activity has been recorded yet.</p>}
      </div>
    </Card>
  )
}

function shortHost(url?: string | null): string {
  if (!url) return 'Unknown target'
  try { return boundedDisplayText(new URL(url).host, 96) } catch { return boundedDisplayText(url, 96) }
}

function friendlyScanType(scan: Scan): string {
  const value = String(scan.run_kind || scan.scan_type || 'scan').replace(/_/g, ' ')
  return value
    .replace(/\b\w/g, (character) => character.toUpperCase())
    .replace(/\bDast\b/g, 'DAST')
    .replace(/\bAi\b/g, 'AI')
}

function isMeaningfulActivity(event: TimelineEvent): boolean {
  const key = `${event.kind} ${event.command || ''} ${event.action_name || ''}`.toLowerCase()
  return ['failed', 'blocked', 'approval_required'].includes(event.status)
    || key.includes('scan')
    || key.includes('finding.retest')
    || key.includes('experiment.workflow')
    || key.includes('evidence')
    || key.includes('refuter')
    || key.includes('research.episode')
}

function activityHref(event: TimelineEvent): string | null {
  if (event.next_action?.startsWith('/') && !event.next_action.startsWith('/campaigns/')) return event.next_action
  if (event.scan_id) return `/scans/${event.scan_id}`
  const campaignId = event.campaign_id || event.mission_campaign_id
  if (campaignId) return `/deep-hunt/runs/${campaignId}`
  if (event.finding_ids?.length === 1) return `/findings/${event.finding_ids[0]}`
  return null
}

function activityTitle(event: TimelineEvent): string {
  const raw = event.action_name || event.command || event.kind
  const labels: Record<string, string> = {
    'Experiment.workflow': 'Autonomous test completed',
    'Research.episode': 'Investigation update',
    'Finding.retest': 'Finding verification',
    'Scan.submit': 'Scan queued',
    'Scan.result': 'Scan reviewed',
    evidence_bound: 'Evidence recorded',
    evidence_instance: 'Evidence recorded',
  }
  return labels[raw] || raw.replace(/_/g, ' ').replace(/^./, (character) => character.toUpperCase())
}

function activityTone(status: string): string {
  if (['failed', 'blocked', 'rejected'].includes(status)) return 'bg-red-400'
  if (['completed', 'accepted', 'verified'].includes(status)) return 'bg-emerald-400'
  if (['active', 'running', 'dispatching'].includes(status)) return 'bg-blue-400'
  return 'bg-amber-400'
}
