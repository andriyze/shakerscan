'use client'
import { featureEnabled, navigationAllowed } from '@/lib/workspaceCapabilities'
import { WorkspaceFeature } from '@/components/WorkspaceBoundary'

import { useEffect, useMemo, useRef, useState } from 'react'
import { workerCapacityLabel, workerCountLabel } from '@/lib/labels'
import Link from '@/components/WorkspaceLink'
import { AlertTriangle, ArrowRight, CircleHelp, Info, Minus, Plus, RadioTower, Server, Trash2 } from 'lucide-react'
import {
  clearQueue, formatDate, getDashboard, getExposureAssets, getGradeColor, getGungnirStatus,
  getMissionTimeline, getQueueStats, getTargetsGrouped, getWorkers, scaleWorkers, startGungnir,
  stopGungnir, type DashboardActionItem, type DashboardResponse, type ExposureAssetsResponse,
  type GroupedDomain, type GungnirStatus, type QueueStats, type Scan, type TimelineEvent,
  type WorkerStats, type ExposureAsset, type ExposureAssetMetrics, type TargetCohort,
} from '@/lib/api'
import {
  ActionMenu,
  buttonClasses,
  Card,
  ConfirmDialog,
  ErrorState,
  LastUpdated,
  MenuItem,
  PageHeader,
  ScanStatusBadge,
  Select,
  SeverityBadge,
  Skeleton,
  Stat,
  StatGroup,
  useToast,
} from '@/components/ui'
import { ChangesStrip } from '@/app/exposure/ChangesStrip'
import { boundedDisplayText } from '@/lib/targetChoices'
import { assuranceClass, scanAssurance } from '@/lib/assurance.mjs'

const DASHBOARD_REFRESH_MS = 10000
const QUEUE_REFRESH_MS = 15000
const WORKERS_REFRESH_MS = 30000
const GUNGNIR_REFRESH_MS = 30000
const OVERVIEW_REFRESH_MS = 60000

const FOCUS_RING = 'focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500'
// Small counters in the system status line (worker states, work units).
const CHIP = 'rounded-sm px-1.5 py-0.5 text-[11px] font-medium leading-4'
const SCALE_BUTTON = `flex h-6 w-6 items-center justify-center rounded-md text-gray-400 transition-colors hover:bg-gray-800 hover:text-white disabled:cursor-not-allowed disabled:opacity-30 ${FOCUS_RING}`
type CohortView = 'operational' | 'production' | 'staging' | 'non_operational' | 'all'

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
  const [cohortView, setCohortView] = useState<CohortView>('operational')

  const dashboardInFlight = useRef(false)
  const dashboardLoadedOnce = useRef(false)
  const queueInFlight = useRef(false)
  const workersInFlight = useRef(false)
  const gungnirInFlight = useRef(false)
  const overviewInFlight = useRef(false)
  const overviewRefreshPending = useRef(false)
  const cohortViewRef = useRef<CohortView>('operational')

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
    if (!featureEnabled('worker_status') && !featureEnabled('worker_admin')) return
    if (workersInFlight.current && !force) return
    workersInFlight.current = true
    try {
      const workerData = await getWorkers()
      setWorkers(workerData)
      setWorkersError(workerData?.error || null)
    } catch (err) {
      setWorkers(null)
      setWorkersError('Workers unavailable')
    } finally {
      workersInFlight.current = false
    }
  }

  const fetchGungnirStatus = async (force = false) => {
    if (!featureEnabled('ct_monitor')) return
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

  const fetchOverview = async (force = false) => {
    if (overviewInFlight.current) {
      if (force) overviewRefreshPending.current = true
      return
    }
    overviewInFlight.current = true
    try {
      const [exposureResult, targetsResult, timelineResult] = await Promise.allSettled([
        featureEnabled('exposure') ? getExposureAssets({ limit: 1000, cohort: cohortViewRef.current }) : Promise.resolve(null),
        getTargetsGrouped({ sort_by: 'active_findings_count', sort_order: 'desc' }),
        featureEnabled('timeline') ? getMissionTimeline({ limit: 12 }) : Promise.resolve({ events: [] }),
      ])
      if (exposureResult.status === 'fulfilled') setExposure(exposureResult.value)
      if (targetsResult.status === 'fulfilled') setGroupedTargets(targetsResult.value.domains || [])
      if (timelineResult.status === 'fulfilled') setTimeline(timelineResult.value.events || [])
    } finally {
      overviewInFlight.current = false
      setOverviewLoading(false)
      if (overviewRefreshPending.current) {
        overviewRefreshPending.current = false
        void fetchOverview(true)
      }
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
    fetchOverview(true)
    const interval = setInterval(fetchOverview, OVERVIEW_REFRESH_MS)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    cohortViewRef.current = cohortView
    fetchOverview()
  }, [cohortView])

  const handleManualRefresh = async () => {
    if (refreshing) return
    setRefreshing(true)
    const [ok] = await Promise.all([
      fetchDashboard(false), fetchOverview(), fetchWorkers(true), fetchQueueStats(),
    ])
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
  const pendingWorkerCount = workers?.pending_count
    ?? Math.max(0, (workerCount ?? 0) - (workers?.current_count ?? 0) - staleCount)
  const unavailableWorkerCount = (workers?.workers || []).filter((worker) => worker.status !== 'running').length
  const cohortCounts = useMemo(
    () => exposure?.cohort_counts || countCohorts(exposure?.assets || []),
    [exposure],
  )
  const scopedExposure = useMemo(() => scopeExposure(exposure, cohortView), [exposure, cohortView])
  const scopedTargets = useMemo(() => scopeTargetGroups(groupedTargets, cohortView), [groupedTargets, cohortView])
  const scopedTargetIds = useMemo(() => new Set(scopedTargets.flatMap((domain) => [domain.root_target, ...domain.subdomains].filter(Boolean).map((target) => target!.id))), [scopedTargets])
  const scopedUrls = useMemo(() => new Set((scopedExposure?.assets || []).flatMap((asset) => [asset.url, asset.root_domain].filter((value): value is string => Boolean(value)).map(normalizeScopeLocator))), [scopedExposure])
  const coverage = useMemo(() => buildCoverageRollup(scopedTargets), [scopedTargets])
  const meaningfulActivity = useMemo(
    () => timeline.filter((event) => isMeaningfulActivity(event) && (
      rowMatchesCohort(event.target_id, event.target_url, cohortView, scopedTargetIds, scopedUrls)
      || isGlobalActivity(event.target_id, event.target_url)
    )).slice(0, 5),
    [timeline, cohortView, scopedTargetIds, scopedUrls],
  )
  const recentScans = useMemo(
    () => (data?.recent_scans || []).filter((scan) => rowMatchesCohort(scan.target_id, scan.target_url, cohortView, scopedTargetIds, scopedUrls)),
    [data, cohortView, scopedTargetIds, scopedUrls],
  )
  const scopedActions = useMemo(
    () => cohortView === 'all' ? (data?.action_center || []) : buildCohortActions(scopedExposure),
    [cohortView, data, scopedExposure],
  )

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        description="What changed, what is proven, and what needs attention."
        actions={<LastUpdated updatedAt={lastUpdated} onRefresh={handleManualRefresh} refreshing={refreshing} />}
      />

      <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
        <CohortScopeBar value={cohortView} onChange={setCohortView} counts={cohortCounts} />

        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-gray-400">
          <div role="group" aria-label="Scan and work queue" className="flex items-center gap-3">
            {queueError ? (
              <span className="flex items-center gap-1.5 text-red-300" title={queueError}>
                <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" /> Queue unavailable
              </span>
            ) : (
              <>
                <Link
                  href="/scans?status=pending"
                  title={`${queuePending} pending scans`}
                  className={`flex items-center gap-1.5 rounded-sm hover:text-gray-100 ${FOCUS_RING}`}
                >
                  <span className={`h-1.5 w-1.5 rounded-full ${queuePending !== '--' && queuePending > 0 ? 'bg-amber-400' : 'bg-gray-600'}`} aria-hidden="true" />
                  <span className="font-medium tabular-nums text-gray-100">{queuePending}</span>
                  <span>scans pending</span>
                </Link>
                <Link
                  href="/scans?status=running"
                  title={`${queueRunning} running scans`}
                  className={`flex items-center gap-1.5 rounded-sm hover:text-gray-100 ${FOCUS_RING}`}
                >
                  <span className={`h-1.5 w-1.5 rounded-full ${queueRunning !== '--' && queueRunning > 0 ? 'animate-pulse bg-blue-400' : 'bg-gray-600'}`} aria-hidden="true" />
                  <span className="font-medium tabular-nums text-gray-100">{queueRunning}</span>
                  <span>scan{queueRunning === 1 ? '' : 's'} running</span>
                </Link>
                {(workPending !== queuePending || workRunning !== queueRunning) && (
                  <span
                    className={`hidden lg:inline ${CHIP} bg-gray-800 text-gray-300`}
                    title={`${workPending} queued and ${workRunning} running worker jobs, including parallel shards`}
                  >
                    {workRunning} work unit{workRunning === 1 ? '' : 's'} running
                  </span>
                )}
              </>
            )}
            <WorkspaceFeature name="worker_admin"><ActionMenu label="Queue actions">
              <MenuItem
                icon={<Trash2 />}
                tone="danger"
                description="Remove every pending scan job; running scans continue"
                onSelect={() => { setClearRetests(false); setShowClearQueue(true) }}
              >Emergency clear</MenuItem>
            </ActionMenu></WorkspaceFeature>
          </div>

          <WorkspaceFeature name="worker_status"><span className="hidden h-4 w-px bg-gray-800 sm:block" aria-hidden="true" />
          <div
            id="workers"
            className="flex flex-wrap items-center gap-2"
            title={workersError || workerCapacityLabel({
              fleetEnabled,
              totalAvailable,
              localAvailable,
              remoteAvailable,
            })}
          >
            <Server className="h-3.5 w-3.5 shrink-0 text-gray-500" aria-hidden="true" />
            <span>
              <span className="font-medium tabular-nums text-gray-100">{workersKnown ? totalAvailable : 'Unknown'}</span>{' '}
              {fleetEnabled ? 'ready across fleet' : 'ready to scan'}
            </span>
            {fleetEnabled && (
              <span className={`${CHIP} bg-gray-800 text-gray-300`} title={workerCountLabel(workerCount ?? 0)}>
                {localAvailable} local
              </span>
            )}
            {staleCount > 0 && (
              <span className={`${CHIP} bg-amber-500/10 text-amber-300`} title="Workers running an outdated build">
                {staleCount} stale
              </span>
            )}
            {pendingWorkerCount > 0 && (
              <span className={`${CHIP} bg-amber-500/10 text-amber-300`} title="Running worker processes that have not reported a current build identity yet">
                {pendingWorkerCount} starting
              </span>
            )}
            {unavailableWorkerCount > 0 && (
              <span className={`${CHIP} bg-red-500/10 text-red-300`} title="Worker containers that are stopped, restarting, or otherwise unavailable">
                {unavailableWorkerCount} unavailable
              </span>
            )}
            {!fleetEnabled && workersKnown && (
              <span className="tabular-nums text-gray-500" title={`${workerCount} running worker processes; configured safety maximum ${maxWorkers}`}>
                {workerCount} running · max {maxWorkers}
              </span>
            )}
            <WorkspaceFeature name="worker_admin"><span className="inline-flex items-center">
              <button
                type="button"
                onClick={() => handleScale(Math.max(1, (workerCount || 1) - 1))}
                disabled={scaling || !workersKnown || (workerCount || 0) <= 1}
                aria-label={fleetEnabled ? 'Decrease local worker count' : 'Decrease worker count'}
                title={fleetEnabled ? 'Decrease local worker count' : 'Decrease worker count'}
                className={SCALE_BUTTON}
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
                className={SCALE_BUTTON}
              >
                <Plus className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            </span>
            </WorkspaceFeature>{fleetEnabled && (
              <Link
                href="/fleet"
                className={`${CHIP} bg-gray-800 text-blue-300 hover:text-blue-200 ${FOCUS_RING}`}
                title={`${executionCapacity?.remote_nodes_available ?? 0} remote nodes available`}
              >
                {remoteAvailable} remote
              </Link>
            )}
          </div>

          </WorkspaceFeature><WorkspaceFeature name="ct_monitor"><span className="hidden h-4 w-px bg-gray-800 sm:block" aria-hidden="true" />
          <button
            type="button"
            onClick={handleGungnirToggle}
            disabled={gungnirActionLoading}
            aria-label={gungnir?.running ? 'Stop Gungnir CT monitor' : 'Start Gungnir CT monitor'}
            title={gungnir?.running
              ? `Stop CT monitor · ${gungnir.domains_monitored} domains · ${gungnir.session_found} found this session`
              : 'Start Certificate Transparency monitor'}
            className={`-mx-1.5 inline-flex h-7 items-center gap-1.5 rounded-md px-1.5 font-medium transition-colors hover:bg-gray-800 hover:text-gray-100 disabled:opacity-50 ${FOCUS_RING}`}
          >
            <RadioTower className="h-3.5 w-3.5 text-gray-500" aria-hidden="true" />
            <span>CT monitor</span>
            <span className={`h-1.5 w-1.5 rounded-full ${gungnir?.running ? 'bg-emerald-400' : 'bg-gray-600'}`} aria-hidden="true" />
            <span className={gungnir?.running ? 'text-emerald-300' : 'text-gray-500'}>{gungnirActionLoading ? '…' : gungnir?.running ? 'on' : 'off'}</span>
          </button>
          </WorkspaceFeature>
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

      <WorkspaceFeature name="exposure"><SecurityPosture exposure={scopedExposure} loading={overviewLoading} /></WorkspaceFeature>

      <WorkspaceFeature name="timeline">{cohortView === 'all' ? (
        <ChangesStrip storageKey="dashboard" />
      ) : (
        <p className="flex items-start gap-2 text-xs text-gray-500">
          <Info className="mt-px h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          <span>
            <span className="font-medium text-gray-400">Recent changes are shown per cohort.</span>{' '}
            Changes recorded before a target was assigned a cohort only appear under All cohorts.
          </span>
        </p>
      )}

      </WorkspaceFeature>
      <WorkspaceFeature name="asm"><CoverageOverview exposure={scopedExposure} coverage={coverage} loading={overviewLoading} /></WorkspaceFeature>

      <ActionCenter items={scopedActions.filter(item => item.href && navigationAllowed(item.href))} loading={dashboardLoading && !data} />

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <LatestResults scans={recentScans} loading={dashboardLoading && !data} />
        <WorkspaceFeature name="timeline"><RecentActivity events={meaningfulActivity} loading={overviewLoading} /></WorkspaceFeature>
      </div>
    </div>
  )
}

function cohortMatches(cohort: TargetCohort | undefined, view: CohortView): boolean {
  const value = cohort || 'unclassified'
  if (view === 'all') return true
  if (view === 'operational') return ['production', 'staging', 'unclassified'].includes(value)
  if (view === 'non_operational') return ['lab', 'demo', 'calibration', 'internal'].includes(value)
  return value === view
}

function normalizeScopeLocator(value: string): string {
  try {
    return new URL(value).hostname.toLowerCase()
  } catch {
    return value.trim().toLowerCase()
  }
}

function rowMatchesCohort(
  targetId: string | null | undefined,
  targetUrl: string | null | undefined,
  view: CohortView,
  targetIds: Set<string>,
  locators: Set<string>,
): boolean {
  if (view === 'all') return true
  if (targetId) return targetIds.has(targetId)
  return Boolean(targetUrl && locators.has(normalizeScopeLocator(targetUrl)))
}

function isGlobalActivity(
  targetId: string | null | undefined,
  targetUrl: string | null | undefined,
): boolean {
  return !targetId && !targetUrl
}

function countCohorts(assets: ExposureAsset[]): Record<string, number> {
  return assets.reduce<Record<string, number>>((counts, asset) => {
    const cohort = asset.cohort || 'unclassified'
    counts[cohort] = (counts[cohort] || 0) + 1
    return counts
  }, {})
}

function metricsFromAssets(assets: ExposureAsset[]): ExposureAssetMetrics {
  const count = (predicate: (asset: ExposureAsset) => boolean) => assets.filter(predicate).length
  return {
    asset_count: assets.length,
    active_critical: assets.reduce((sum, asset) => sum + asset.active_critical, 0),
    active_high: assets.reduce((sum, asset) => sum + asset.active_high, 0),
    active_verified: assets.reduce((sum, asset) => sum + (asset.active_verified || 0), 0),
    active_needs_verification: assets.reduce((sum, asset) => sum + (asset.active_needs_verification || 0), 0),
    ai_surfaces: count((asset) => asset.kind === 'ai'),
    web_targets: count((asset) => asset.kind === 'web'),
    model_artifacts: count((asset) => asset.kind === 'model'),
    public_assets: count((asset) => asset.exposure_class === 'public'),
    internal_assets: count((asset) => asset.exposure_class === 'internal'),
    unscanned_assets: count((asset) => asset.coverage_posture === 'unscanned'),
    stale_assets: count((asset) => asset.coverage_posture === 'stale'),
    incomplete_scans: count((asset) => asset.coverage_posture === 'limited'),
    failed_scans: count((asset) => asset.coverage_posture === 'failed'),
    fresh_scans: count((asset) => asset.coverage_posture === 'fresh'),
    verified_assets: count((asset) => (asset.active_verified || 0) > 0),
    unverified_high_assets: count((asset) => (asset.active_needs_verification || 0) > 0 && asset.active_critical + asset.active_high > 0),
    unowned_assets: count((asset) => !asset.owner),
    needs_action: count((asset) => Boolean(asset.needs_action)),
    p1_count: count((asset) => asset.action_priority === 'P1'),
    p2_count: count((asset) => asset.action_priority === 'P2'),
    p3_count: count((asset) => asset.action_priority === 'P3'),
    prod_ai_surfaces: count((asset) => asset.kind === 'ai' && (asset.production_mode || asset.environment === 'production')),
  }
}

function scopeExposure(exposure: ExposureAssetsResponse | null, view: CohortView): ExposureAssetsResponse | null {
  if (!exposure || exposure.cohort === view || (view === 'all' && exposure.cohort === 'all')) return exposure
  const assets = exposure.assets.filter((asset) => cohortMatches(asset.cohort, view))
  return {
    ...exposure,
    assets,
    count: assets.length,
    total: assets.length,
    new_count: assets.filter((asset) => asset.is_new).length,
    metrics: metricsFromAssets(assets),
  }
}

function scopeTargetGroups(groups: GroupedDomain[], view: CohortView): GroupedDomain[] {
  if (view === 'all') return groups
  return groups.flatMap((group) => {
    const root = group.root_target && cohortMatches(group.root_target.cohort, view) ? group.root_target : null
    const subdomains = group.subdomains.filter((target) => cohortMatches(target.cohort, view))
    if (!root && subdomains.length === 0) return []
    return [{ ...group, root_target: root, subdomains, subdomain_count: subdomains.length, total_count: subdomains.length + (root ? 1 : 0) }]
  })
}

function buildCohortActions(exposure: ExposureAssetsResponse | null): DashboardActionItem[] {
  const metrics = exposure?.metrics
  if (!metrics) return []
  const items: DashboardActionItem[] = []
  if ((metrics.failed_scans || 0) > 0) items.push({ id: 'cohort-failures', priority: 'high', category: 'Reliability', title: 'Review failed assessments', detail: `${metrics.failed_scans} scoped asset${metrics.failed_scans === 1 ? ' has' : 's have'} a failed latest assessment.`, href: '/scans?status=failed', action_label: 'Review failures', count: metrics.failed_scans })
  if ((metrics.active_needs_verification || 0) > 0) items.push({ id: 'cohort-unverified', priority: 'high', category: 'Evidence', title: 'Reduce unverified risk noise', detail: `${metrics.active_needs_verification} active scoped finding${metrics.active_needs_verification === 1 ? '' : 's'} still need deterministic verification.`, href: '/exposure?posture=needs_verification', action_label: 'Review evidence', count: metrics.active_needs_verification })
  if ((metrics.stale_assets || 0) > 0) items.push({ id: 'cohort-stale', priority: 'medium', category: 'Freshness', title: 'Refresh stale assets', detail: `${metrics.stale_assets} scoped asset${metrics.stale_assets === 1 ? '' : 's'} have stale evidence.`, href: '/exposure?posture=stale', action_label: 'Review stale assets', count: metrics.stale_assets })
  return items
}

const COHORT_SCOPE_HINT = 'Operational includes production, staging, and clearly labeled unclassified assets. Lab data is never silently mixed into it.'

function CohortScopeBar({ value, onChange, counts }: { value: CohortView; onChange: (value: CohortView) => void; counts: Record<string, number> }) {
  const nonOperational = ['lab', 'demo', 'calibration', 'internal'].reduce((sum, key) => sum + (counts[key] || 0), 0)
  const unclassified = counts.unclassified || 0
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
      <label htmlFor="dashboard-cohort" className="text-xs font-medium text-gray-400">Cohort</label>
      <Select
        id="dashboard-cohort"
        fullWidth={false}
        value={value}
        onChange={(event) => onChange(event.target.value as CohortView)}
        aria-label="Dashboard cohort scope"
        aria-describedby="dashboard-cohort-hint"
      >
        <option value="operational">Operational + unclassified</option>
        <option value="production">Production only</option>
        <option value="staging">Staging only</option>
        <option value="non_operational">Lab / demo / calibration / internal</option>
        <option value="all">All cohorts</option>
      </Select>
      <span className="flex items-center gap-1.5 text-xs text-gray-500">
        <span className="tabular-nums">{nonOperational} non-operational · {unclassified} unclassified</span>
        <span title={COHORT_SCOPE_HINT} className="inline-flex text-gray-600 hover:text-gray-400">
          <CircleHelp className="h-3.5 w-3.5" aria-hidden="true" />
        </span>
        <span id="dashboard-cohort-hint" className="sr-only">{COHORT_SCOPE_HINT}</span>
      </span>
    </div>
  )
}

/** The shared header for dashboard panels: title, one-line description, one text link. */
function PanelHeader({ title, description, action }: { title: string; description?: string; action?: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-gray-800 px-4 py-3">
      <div className="min-w-0">
        <h2 className="text-sm font-semibold text-gray-100">{title}</h2>
        {description && <p className="mt-0.5 text-xs text-gray-400">{description}</p>}
      </div>
      {action}
    </div>
  )
}

function PanelLink({ href, children, className = '' }: { href: string; children: React.ReactNode; className?: string }) {
  return (
    <Link href={href} className={`inline-flex shrink-0 items-center gap-1 rounded-sm text-xs font-medium text-blue-400 hover:text-blue-300 ${FOCUS_RING} ${className}`}>
      {children} <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
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
  const actionableItems = items.filter((item) => item.id !== 'worker-build-freshness' && item.priority !== 'info')
  const visibleItems = actionableItems.slice(0, 3)

  return (
    <Card className="overflow-hidden">
      <PanelHeader
        title="Top actions"
        description="The three highest-impact things to address next"
        action={<PanelLink href="/exposure">View all priorities</PanelLink>}
      />
      {loading ? (
        <div className="grid divide-y divide-gray-800 lg:grid-cols-3 lg:divide-x lg:divide-y-0">
          {Array.from({ length: 3 }).map((_, index) => <div key={index} className="p-4"><Skeleton className="h-16" /></div>)}
        </div>
      ) : visibleItems.length ? (
        <div className="grid divide-y divide-gray-800 lg:grid-cols-3 lg:divide-x lg:divide-y-0">
          {visibleItems.map((item) => <ActionCenterRow key={item.id} item={item} />)}
        </div>
      ) : (
        <p className="px-4 py-6 text-sm text-gray-500">No high-priority operational actions right now.</p>
      )}
    </Card>
  )
}

function ActionCenterRow({ item }: { item: DashboardActionItem }) {
  const action = (item.actions?.length
    ? item.actions
    : item.href
      ? [{ label: item.action_label || 'Open', href: item.href, variant: 'primary' }]
      : [])[0]
  return (
    <div className="flex flex-col p-4">
      <div className="flex flex-wrap items-center gap-2 text-xs text-gray-500">
        <SeverityBadge severity={item.priority} />
        <span>{item.category}</span>
        {typeof item.count === 'number' && item.count > 1 && (
          <span className="tabular-nums">· {item.count.toLocaleString()} affected</span>
        )}
      </div>
      <h3 className="mt-2 text-sm font-medium text-gray-100">{item.title}</h3>
      <p className="mt-1 line-clamp-2 flex-1 text-sm leading-5 text-gray-400">{item.detail}</p>
      {action ? <PanelLink href={action.href} className="mt-3 self-start">{action.label}</PanelLink> : null}
    </div>
  )
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
    <section aria-labelledby="dashboard-posture-heading">
      {/* One bordered strip: header, the four headline numbers and the evidence bar, split by hairlines. */}
      <StatGroup columns={4}>
        <div className="col-span-full flex flex-col gap-3 bg-gray-900 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="min-w-0">
            <h2 id="dashboard-posture-heading" className="text-sm font-semibold text-gray-100">Security posture</h2>
            <p className="mt-0.5 text-xs text-gray-400">Verified risk, uncertain signals, and assets that need attention</p>
          </div>
          <Link href={primary.href} className={`${buttonClasses('secondary', 'sm')} self-start sm:self-auto`}>
            {primary.label} <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
          </Link>
        </div>
        {loading && !metrics ? (
          Array.from({ length: 4 }).map((_, index) => (
            <div key={index} className="bg-gray-900 px-4 py-3">
              <Skeleton className="h-3 w-24" />
              <Skeleton className="mt-2 h-7 w-16" />
              <Skeleton className="mt-2 h-3 w-28" />
            </div>
          ))
        ) : (
          <>
            <Stat href="/exposure?posture=verified" label="Proven active risk" value={verified.toLocaleString()} caption={`${metrics?.verified_assets || 0} affected assets`} tone={verified > 0 ? 'danger' : 'default'} />
            <Stat href="/exposure?posture=needs_verification" label="Needs verification" value={needsVerification.toLocaleString()} caption={`${metrics?.unverified_high_assets || 0} high-impact assets`} tone={needsVerification > 0 ? 'warning' : 'default'} />
            <Stat href="/exposure?posture=p1" label="P1 assets" value={p1.toLocaleString()} caption="highest action priority" />
            <Stat href="/exposure" label="Freshly assessed" value={fresh.toLocaleString()} caption={`of ${assetCount} known assets`} />
            <div className="col-span-full bg-gray-900 px-4 py-3">
              <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2 text-xs">
                <span className="text-gray-400">Evidence confidence across active findings</span>
                <span className="tabular-nums text-gray-500">{verified} proven · {needsVerification} awaiting verification</span>
              </div>
              <div className="flex h-1.5 overflow-hidden rounded-full bg-gray-800" aria-label={`${verified} proven active findings and ${needsVerification} findings needing verification`}>
                <div className="bg-emerald-500" style={{ width: `${verifiedWidth}%` }} />
                <div className="flex-1 bg-amber-500/60" />
              </div>
            </div>
          </>
        )}
      </StatGroup>
    </section>
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
    <Card className="overflow-hidden">
      <PanelHeader
        title="Coverage and freshness"
        description="How much has been tested, and which results are aging out"
        action={<PanelLink href="/asm">Open Coverage</PanelLink>}
      />
      {loading && !metrics ? <div className="p-4"><Skeleton className="h-40" /></div> : (
        <div className="grid divide-y divide-gray-800 lg:grid-cols-2 lg:divide-x lg:divide-y-0">
          <section className="p-4">
            <div className="mb-3 flex items-baseline gap-2">
              <h3 className="text-sm font-medium text-gray-200">Asset freshness</h3>
              <span className="ml-auto text-xs tabular-nums text-gray-500">{totalAssets} assets</span>
            </div>
            <div className="grid gap-2.5">
              {freshness.map((item) => (
                <ProgressRow key={item.label} label={item.label} value={item.value} total={totalAssets} color={item.color} />
              ))}
            </div>
          </section>
          <section className="p-4">
            <div className="mb-3 flex items-baseline gap-2">
              <h3 className="text-sm font-medium text-gray-200">Continuous endpoint coverage</h3>
              <span className="ml-auto text-xs tabular-nums text-gray-500">{Math.round(coverage.coverage * 100)}%</span>
            </div>
            <ProgressRow label="Tested endpoints" value={coverage.tested} total={coverage.denominator} color="bg-blue-500" />
            <p className="mt-2 text-xs text-gray-500">{coverage.tested.toLocaleString()} tested · {coverage.remaining.toLocaleString()} remaining across {coverage.targets.length} inventoried targets</p>
            <div className="-mx-2 mt-3 grid gap-0.5">
              {coverage.targets.slice(0, 3).map((target) => (
                <Link key={target.id} href={`/asm?target_id=${target.id}`} className={`flex items-center gap-3 rounded-md px-2 py-1.5 hover:bg-gray-800/60 ${FOCUS_RING}`}>
                  <span className="min-w-0 flex-1 truncate text-xs text-gray-300">{shortHost(target.url)}</span>
                  <span className="text-xs tabular-nums text-gray-500">{target.remaining.toLocaleString()} remaining</span>
                </Link>
              ))}
              {!coverage.targets.length ? <p className="px-2 text-xs text-gray-500">No persistent endpoint inventories yet.</p> : null}
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
        <span className="text-gray-400">{label}</span>
        <span className="tabular-nums text-gray-300">{value.toLocaleString()}</span>
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
      <PanelHeader title="Latest target results" description="One current result per target" action={<PanelLink href="/scans">All scans</PanelLink>} />
      <div className="divide-y divide-gray-800">
        {loading ? Array.from({ length: 4 }).map((_, index) => <div key={index} className="px-4 py-3"><Skeleton className="h-9" /></div>)
          : scans.length ? scans.slice(0, 5).map((scan) => {
            const assurance = scanAssurance(scan)
            return (
            <Link key={scan.id} href={`/scans/${scan.id}`} className={`flex items-center gap-4 px-4 py-3 transition-colors hover:bg-gray-800/40 ${FOCUS_RING} focus-visible:ring-inset`}>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm font-medium text-gray-100">{shortHost(scan.target_url)}</span>
                <span className="block truncate text-xs text-gray-500">{friendlyScanType(scan)} · {formatDate(scan.completed_at || scan.created_at)}</span>
              </span>
              {typeof scan.findings_count === 'number' ? <span className="hidden text-xs tabular-nums text-gray-400 sm:block">{scan.findings_count} finding{scan.findings_count === 1 ? '' : 's'}</span> : null}
              {scan.grade ? (
                <span className="hidden text-right sm:block">
                  <span className={`block text-xs font-medium ${getGradeColor(scan.grade)}`} title="Risk observed by this run; not an overall safety score">Observed posture {scan.grade}</span>
                  <span className={`block text-[11px] ${assuranceClass(assurance?.band)}`}>
                    {assurance ? `${assurance.label} · ${assurance.score}/100` : 'Examination strength unavailable'}
                  </span>
                </span>
              ) : null}
              <span className="w-24 shrink-0 text-right"><ScanStatusBadge status={scan.status} /></span>
            </Link>
            )
          }) : <p className="px-4 py-6 text-sm text-gray-500">No scan results yet. Add a target and run the first scan.</p>}
      </div>
    </Card>
  )
}

function RecentActivity({ events, loading }: { events: TimelineEvent[]; loading: boolean }) {
  return (
    <Card className="overflow-hidden">
      <PanelHeader
        title="Recent activity"
        description="Meaningful results across scans, verification, and investigations"
        action={<PanelLink href="/timeline">Full timeline</PanelLink>}
      />
      <div className="divide-y divide-gray-800">
        {loading ? Array.from({ length: 4 }).map((_, index) => <div key={index} className="px-4 py-3"><Skeleton className="h-9" /></div>)
          : events.length ? events.map((event) => {
            const href = activityHref(event)
            const body = (
              <>
                <span className={`mt-1.5 h-1.5 w-1.5 flex-none rounded-full ${activityTone(event.status)}`} aria-hidden="true" />
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-medium text-gray-100">{boundedDisplayText(activityTitle(event), 96)}</span>
                  <span className="block truncate text-xs text-gray-500">{boundedDisplayText(event.operator_message || event.target_url || event.kind.replace(/_/g, ' '), 160)}</span>
                </span>
                <span className="flex-none text-xs tabular-nums text-gray-500">{event.created_at ? formatDate(event.created_at) : ''}</span>
              </>
            )
            return href ? (
              <Link key={event.event_id} href={href} className={`flex items-start gap-3 px-4 py-3 transition-colors hover:bg-gray-800/40 ${FOCUS_RING} focus-visible:ring-inset`}>{body}</Link>
            ) : <div key={event.event_id} className="flex items-start gap-3 px-4 py-3">{body}</div>
          }) : <p className="px-4 py-6 text-sm text-gray-500">No meaningful activity has been recorded yet.</p>}
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
  if (raw === 'scan.submit') {
    return ({ accepted: 'Scan accepted for queueing', queued: 'Scan queued', running: 'Scan running', completed: 'Scan completed', failed: 'Scan failed', cancelled: 'Scan cancelled', blocked: 'Scan blocked' } as Record<string, string>)[event.status] || 'Scan submission'
  }
  const labels: Record<string, string> = {
    'Experiment.workflow': 'Autonomous test completed',
    'Research.episode': 'Investigation update',
    'Finding.retest': 'Finding verification',
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
