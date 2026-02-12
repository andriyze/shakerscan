'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { getDashboard, getQueueStats, getWorkers, scaleWorkers, getGungnirStatus, startGungnir, stopGungnir, getSeverityBg, getGradeColor, formatDate, type Scan, type Finding, type QueueStats, type WorkerStats, type GungnirStatus } from '@/lib/api'

interface DashboardData {
  metrics: {
    total_targets: number
    total_scans: number
    running_scans: number
    active_findings: number
    critical_findings: number
    high_findings: number
    avg_score: number
  }
  recent_scans: Scan[]
  recent_findings: Finding[]
}

const DASHBOARD_REFRESH_MS = 10000
const QUEUE_REFRESH_MS = 15000
const WORKERS_REFRESH_MS = 30000
const GUNGNIR_REFRESH_MS = 30000

export default function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null)
  const [queue, setQueue] = useState<QueueStats | null>(null)
  const [workers, setWorkers] = useState<WorkerStats | null>(null)
  const [gungnir, setGungnir] = useState<GungnirStatus | null>(null)
  const [dashboardLoading, setDashboardLoading] = useState(true)
  const [dashboardError, setDashboardError] = useState<string | null>(null)
  const [queueError, setQueueError] = useState<string | null>(null)
  const [workersError, setWorkersError] = useState<string | null>(null)
  const [gungnirError, setGungnirError] = useState<string | null>(null)
  const [scaling, setScaling] = useState(false)
  const [gungnirActionLoading, setGungnirActionLoading] = useState(false)

  const dashboardInFlight = useRef(false)
  const queueInFlight = useRef(false)
  const workersInFlight = useRef(false)
  const gungnirInFlight = useRef(false)

  const fetchDashboard = async (showLoading = false) => {
    if (dashboardInFlight.current) return
    dashboardInFlight.current = true
    if (showLoading) setDashboardLoading(true)
    try {
      const dashboardData = await getDashboard()
      setData(dashboardData)
      setDashboardError(null)
    } catch (err) {
      setDashboardError('Failed to load dashboard. Is the API running?')
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

  const handleScale = async (count: number) => {
    if (scaling) return
    setScaling(true)
    try {
      await scaleWorkers(count)
      await fetchWorkers(true)
    } catch (err) {
      console.error('Failed to scale workers:', err)
    } finally {
      setScaling(false)
    }
  }

  const handleGungnirToggle = async () => {
    if (gungnirActionLoading) return
    setGungnirError(null)
    setGungnirActionLoading(true)
    try {
      if (gungnir?.running) {
        await stopGungnir()
      } else {
        await startGungnir()
      }
      await fetchGungnirStatus(true)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to toggle gungnir'
      setGungnirError(message)
    } finally {
      setGungnirActionLoading(false)
    }
  }

  const metrics = data?.metrics
  const metricsReady = Boolean(metrics)
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
  const workerLabel = workersError
    ? workersError
    : workersKnown
      ? `${workerCount} worker${workerCount !== 1 ? 's' : ''} running`
      : 'Workers unavailable'

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Dashboard</h1>
        <p className="text-gray-400 mt-1">Security scanning overview</p>
      </div>

      {dashboardError && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 text-red-400">
          {dashboardError}
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Targets"
          value={totalTargets}
          icon={<TargetIcon />}
          color="blue"
          href="/targets"
        />
        <StatCard
          title="Total Scans"
          value={totalScans}
          icon={<ScanIcon />}
          color="green"
          href="/scans"
        />
        <StatCard
          title="Active Findings"
          value={activeFindings}
          icon={<AlertIcon />}
          color="yellow"
          subtitle={metricsReady ? `${criticalFindings} critical, ${highFindings} high` : '--'}
          href="/findings?status=active"
        />
        <StatCard
          title="Avg Score"
          value={avgScore}
          icon={<ScoreIcon />}
          color="purple"
        />
      </div>

      {/* Queue Status & Worker Control */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Queue Status */}
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <h2 className="text-sm font-medium text-gray-400 mb-3">Queue Status</h2>
          <div className="flex flex-wrap gap-4">
            <Link href="/scans?status=pending" className="flex items-center gap-2 hover:opacity-80 transition-opacity">
              <div className={`w-2 h-2 rounded-full bg-yellow-500 ${queuePending !== '--' && queuePending > 0 ? 'animate-pulse' : ''}`}></div>
              <span className="text-sm">{queuePending} pending</span>
            </Link>
            <Link href="/scans?status=running" className="flex items-center gap-2 hover:opacity-80 transition-opacity">
              <div className={`w-2 h-2 rounded-full bg-blue-500 ${queueRunning !== '--' && queueRunning > 0 ? 'animate-pulse' : ''}`}></div>
              <span className="text-sm">{queueRunning} running</span>
            </Link>
            <Link href="/scans?status=completed" className="flex items-center gap-2 hover:opacity-80 transition-opacity">
              <div className="w-2 h-2 rounded-full bg-green-500"></div>
              <span className="text-sm">{queueCompleted} completed</span>
            </Link>
            <Link href="/scans?status=failed" className="flex items-center gap-2 hover:opacity-80 transition-opacity">
              <div className="w-2 h-2 rounded-full bg-red-500"></div>
              <span className="text-sm">{queueFailed} failed</span>
            </Link>
          </div>
          {queueError && (
            <p className="text-xs text-red-400 mt-3">{queueError}</p>
          )}
        </div>

        {/* Worker Control */}
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <h2 className="text-sm font-medium text-gray-400 mb-3">Worker Control</h2>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <WorkerIcon />
              <span className="text-sm">{workerLabel}</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => handleScale(Math.max(1, (workerCount || 1) - 1))}
                disabled={scaling || !workersKnown || (workerCount || 0) <= 1}
                className="px-2 py-1 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed rounded text-sm"
              >
                -
              </button>
              <span className="text-sm font-medium w-8 text-center">{workersKnown ? workerCount : '?'}</span>
              <button
                onClick={() => handleScale(Math.min(20, (workerCount || 1) + 1))}
                disabled={scaling || !workersKnown || (workerCount || 0) >= 20}
                className="px-2 py-1 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed rounded text-sm"
              >
                +
              </button>
              <select
                value=""
                onChange={(e) => handleScale(parseInt(e.target.value))}
                disabled={scaling || !workersKnown}
                className="ml-2 px-2 py-1 bg-gray-800 border border-gray-700 rounded text-sm disabled:opacity-50"
              >
                <option value="">Scale to...</option>
                {[1, 2, 3, 5, 10, 15, 20].map(n => (
                  <option key={n} value={n}>{n} workers</option>
                ))}
              </select>
            </div>
          </div>
          {scaling && (
            <p className="text-xs text-blue-400 mt-2">Scaling workers...</p>
          )}
        </div>
      </div>

      {/* Gungnir CT Monitor */}
      <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
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
              onClick={handleGungnirToggle}
              disabled={gungnirActionLoading}
              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors disabled:opacity-50 ${
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
        {gungnirError && (
          <p className="text-xs text-red-400 mt-2">{gungnirError}</p>
        )}
      </div>

      {/* Recent Scans & Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Scans */}
        <div className="bg-gray-900 rounded-lg border border-gray-800">
          <div className="p-4 border-b border-gray-800">
            <h2 className="font-medium text-white">Recent Scans</h2>
          </div>
          <div className="divide-y divide-gray-800">
            {data?.recent_scans?.length ? (
              data.recent_scans.slice(0, 5).map((scan) => (
                <Link
                  key={scan.id}
                  href={`/scans/${scan.id}`}
                  className="flex items-center justify-between p-4 hover:bg-gray-800/50 transition-colors"
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
                    <StatusBadge status={scan.status} />
                  </div>
                </Link>
              ))
            ) : dashboardLoading ? (
              <p className="p-4 text-sm text-gray-500">Loading scans...</p>
            ) : (
              <p className="p-4 text-sm text-gray-500">No scans yet</p>
            )}
          </div>
          <div className="p-3 border-t border-gray-800">
            <Link href="/scans" className="text-sm text-blue-400 hover:text-blue-300">
              View all scans &rarr;
            </Link>
          </div>
        </div>

        {/* Recent Findings */}
        <div className="bg-gray-900 rounded-lg border border-gray-800">
          <div className="p-4 border-b border-gray-800">
            <h2 className="font-medium text-white">Critical & High Findings</h2>
          </div>
          <div className="divide-y divide-gray-800">
            {data?.recent_findings?.length ? (
              data.recent_findings.slice(0, 5).map((finding) => (
                <Link
                  key={finding.id}
                  href={`/findings/${finding.id}`}
                  className="flex items-center gap-3 p-4 hover:bg-gray-800/50 transition-colors"
                >
                  <span className={`px-2 py-0.5 text-xs font-medium rounded ${getSeverityBg(finding.severity)}`}>
                    {finding.severity}
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-white truncate">{finding.title}</p>
                    <p className="text-xs text-gray-500 truncate">{finding.tool}</p>
                  </div>
                </Link>
              ))
            ) : dashboardLoading ? (
              <p className="p-4 text-sm text-gray-500">Loading findings...</p>
            ) : (
              <p className="p-4 text-sm text-gray-500">No critical or high findings</p>
            )}
          </div>
          <div className="p-3 border-t border-gray-800">
            <Link href="/findings" className="text-sm text-blue-400 hover:text-blue-300">
              View all findings &rarr;
            </Link>
          </div>
        </div>
      </div>
    </div>
  )
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
  value: number | string
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
        <p className="text-2xl font-bold text-white">{value}</p>
        {subtitle && <p className="text-xs text-gray-500 mt-1">{subtitle}</p>}
      </div>
    </div>
  )

  if (href) {
    return (
      <Link
        href={href}
        className="bg-gray-900 rounded-lg border border-gray-800 p-4 hover:bg-gray-800/50 transition-colors"
      >
        {content}
      </Link>
    )
  }

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
      {content}
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    pending: 'bg-gray-500/20 text-gray-400',
    running: 'bg-blue-500/20 text-blue-400',
    completed: 'bg-green-500/20 text-green-400',
    failed: 'bg-red-500/20 text-red-400'
  }

  return (
    <span className={`px-2 py-0.5 text-xs font-medium rounded ${styles[status] || styles.pending}`}>
      {status}
    </span>
  )
}

// Icons
function TargetIcon() {
  return (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
    </svg>
  )
}

function ScanIcon() {
  return (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
    </svg>
  )
}

function AlertIcon() {
  return (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
    </svg>
  )
}

function ScoreIcon() {
  return (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
    </svg>
  )
}

function WorkerIcon() {
  return (
    <svg className="w-4 h-4 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
    </svg>
  )
}
