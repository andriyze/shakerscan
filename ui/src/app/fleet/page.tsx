'use client'

import { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import {
  Activity,
  ChevronDown,
  ChevronRight,
  CircleStop,
  Eye,
  EyeOff,
  Gauge,
  Minus,
  Play,
  Plus,
  RefreshCw,
  ServerCog,
  ShieldCheck,
  TriangleAlert,
  Unplug,
} from 'lucide-react'
import {
  getFleetNodeActivity,
  getFleetNodeEvents,
  getFleetNodes,
  getWorkers,
  revokeFleetNode,
  scaleFleetWorkers,
  updateFleetNodeState,
  type FleetNode,
  type FleetNodeActivityResponse,
  type FleetNodeEventsResponse,
  type FleetSummary,
  type WorkerStats,
} from '@/lib/api'
import {
  Badge,
  Button,
  Card,
  ConfirmDialog,
  EmptyState,
  ErrorState,
  Input,
  LastUpdated,
  PageHeader,
  ScanStatusBadge,
  useToast,
} from '@/components/ui'

const REFRESH_MS = 10_000
const OPERATOR_TOKEN_KEY = 'shakerscan:fleet-operator-token'

const EMPTY_SUMMARY: FleetSummary = {
  total_nodes: 0,
  active_nodes: 0,
  healthy_nodes: 0,
  unhealthy_nodes: 0,
  stale_nodes: 0,
  draining_nodes: 0,
  desired_workers: 0,
  active_workers: 0,
  state_drift_nodes: 0,
  image_drift_nodes: 0,
  wireguard_connection_pending_nodes: 0,
}

function relativeTime(value?: string | null): string {
  if (!value) return 'Never'
  const time = new Date(value).getTime()
  if (!Number.isFinite(time)) return 'Unknown'
  const seconds = Math.max(0, Math.floor((Date.now() - time) / 1000))
  if (seconds < 60) return `${seconds}s ago`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}

function shortDigest(value?: string | null): string {
  if (!value) return 'Not reported'
  const digest = value.split('@').pop() || value
  return digest.length > 24 ? `${digest.slice(0, 18)}…${digest.slice(-6)}` : digest
}

function capacityLabel(capacity: Record<string, unknown>): string {
  const cpu = Number(capacity.cpu_count || 0)
  const memory = Number(capacity.memory_bytes || 0)
  const parts: string[] = []
  if (cpu > 0) parts.push(`${cpu} CPU`)
  if (memory > 0) parts.push(`${(memory / 1024 ** 3).toFixed(memory >= 10 * 1024 ** 3 ? 0 : 1)} GiB`)
  return parts.join(' · ') || 'Not reported'
}

function statusClasses(status: FleetNode['status']): string {
  if (status === 'healthy') return 'bg-emerald-500/15 text-emerald-300'
  if (status === 'stale') return 'bg-amber-500/15 text-amber-300'
  if (status === 'unhealthy') return 'bg-red-500/15 text-red-300'
  if (status === 'draining') return 'bg-blue-500/15 text-blue-300'
  if (status === 'disabled') return 'bg-red-500/15 text-red-300'
  return 'bg-gray-700 text-gray-300'
}

function SummaryCard({ label, value, detail, tone = 'normal' }: {
  label: string
  value: number | string
  detail: string
  tone?: 'normal' | 'good' | 'warning'
}) {
  const color = tone === 'good' ? 'text-emerald-300' : tone === 'warning' ? 'text-amber-300' : 'text-white'
  return (
    <Card className="p-4">
      <p className="text-xs font-medium uppercase tracking-wide text-gray-500">{label}</p>
      <p className={`mt-1 text-2xl font-semibold ${color}`}>{value}</p>
      <p className="mt-1 text-xs text-gray-500">{detail}</p>
    </Card>
  )
}

function OperatorAccessCard({
  operatorToken,
  showToken,
  onTokenChange,
  onToggleVisibility,
}: {
  operatorToken: string
  showToken: boolean
  onTokenChange: (value: string) => void
  onToggleVisibility: () => void
}) {
  return (
    <Card className="mb-6 p-4">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <div className="flex items-center gap-2 text-sm font-medium text-gray-200">
            <ShieldCheck className="h-4 w-4 text-blue-400" aria-hidden="true" />
            Operator access
          </div>
          <p className="mt-1 max-w-2xl text-xs text-gray-500">
            Fleet init creates the operator token. Enter it to load nodes and enable fleet changes from this browser.
            Remote access requires HTTPS or ShakerScan&apos;s verified Tailscale bind. The token stays in this browser tab only.
          </p>
        </div>
        <div className="flex w-full gap-2 lg:w-[28rem]">
          <Input
            type={showToken ? 'text' : 'password'}
            value={operatorToken}
            onChange={(event) => onTokenChange(event.target.value)}
            placeholder="Fleet operator token"
            aria-label="Fleet operator token"
            autoComplete="off"
          />
          <Button
            variant="secondary"
            size="sm"
            onClick={onToggleVisibility}
            aria-label={showToken ? 'Hide operator token' : 'Show operator token'}
          >
            {showToken ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </Button>
        </div>
      </div>
    </Card>
  )
}

export default function FleetPage() {
  const toast = useToast()
  const [nodes, setNodes] = useState<FleetNode[]>([])
  const [summary, setSummary] = useState<FleetSummary>(EMPTY_SUMMARY)
  const [staleAfterSeconds, setStaleAfterSeconds] = useState(0)
  const [reconciliationMode, setReconciliationMode] = useState<'automatic' | 'manual'>('automatic')
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null)
  const [operatorToken, setOperatorToken] = useState('')
  const [showToken, setShowToken] = useState(false)
  const [pendingNodeId, setPendingNodeId] = useState<string | null>(null)
  const [revokeNode, setRevokeNode] = useState<FleetNode | null>(null)
  const [expandedNodeId, setExpandedNodeId] = useState<string | null>(null)
  const [activity, setActivity] = useState<Record<string, FleetNodeActivityResponse>>({})
  const [events, setEvents] = useState<Record<string, FleetNodeEventsResponse>>({})
  const [activityLoading, setActivityLoading] = useState<string | null>(null)
  const [activityError, setActivityError] = useState<Record<string, string>>({})
  const [rolloutDigests, setRolloutDigests] = useState<Record<string, string>>({})
  const [fleetWorkerTarget, setFleetWorkerTarget] = useState('')
  const [fleetScaling, setFleetScaling] = useState(false)
  const [workers, setWorkers] = useState<WorkerStats | null>(null)

  const loadFleet = useCallback(async (background = false) => {
    if (background) setRefreshing(true)
    else setLoading(true)
    try {
      const workersResult = await getWorkers()
      setWorkers(workersResult)
      if (workersResult.fleet && !workersResult.fleet.enabled) {
        setNodes([])
        setSummary(EMPTY_SUMMARY)
        setStaleAfterSeconds(0)
        setUpdatedAt(new Date())
        setError(null)
        return
      }
      const response = await getFleetNodes(operatorToken)
      setNodes(response.nodes)
      setSummary(response.summary)
      setStaleAfterSeconds(response.stale_after_seconds)
      setReconciliationMode(response.reconciliation_mode || 'automatic')
      setUpdatedAt(new Date())
      setError(null)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to load fleet'
      setError(
        !operatorToken.trim() && /bearer credential is required/i.test(message)
          ? 'Enter the fleet operator token to load remote nodes and controls.'
          : message,
      )
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [operatorToken])

  const availableRemoteNodes = nodes.filter((node) => (
    node.status === 'healthy'
    && node.state_current
    && (node.image_current || node.local_build_active)
    && !node.drain
    && node.active_worker_count > 0
  ))
  const availableRemoteWorkers = availableRemoteNodes.reduce(
    (total, node) => total + node.active_worker_count,
    0,
  )
  const localAvailableWorkers = workers?.execution_capacity?.local_available ?? workers?.current_count ?? workers?.count ?? 0
  const localRunningWorkers = workers?.execution_capacity?.local_running ?? workers?.count ?? 0

  useEffect(() => {
    setOperatorToken(sessionStorage.getItem(OPERATOR_TOKEN_KEY) || '')
    void loadFleet()
    const timer = window.setInterval(() => void loadFleet(true), REFRESH_MS)
    return () => window.clearInterval(timer)
  }, [loadFleet])

  function changeOperatorToken(value: string) {
    setOperatorToken(value)
    if (value) sessionStorage.setItem(OPERATOR_TOKEN_KEY, value)
    else sessionStorage.removeItem(OPERATOR_TOKEN_KEY)
  }

  async function mutateNode(node: FleetNode, update: { desired_worker_count?: number; drain?: boolean; worker_image_digest?: string }, success: string) {
    setPendingNodeId(node.id)
    try {
      await updateFleetNodeState(node.id, update, operatorToken)
      toast.success(success)
      await loadFleet(true)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Fleet action failed')
    } finally {
      setPendingNodeId(null)
    }
  }

  async function confirmRevoke() {
    if (!revokeNode) return
    setPendingNodeId(revokeNode.id)
    try {
      await revokeFleetNode(revokeNode.id, operatorToken)
      toast.success(`${revokeNode.name} was revoked`)
      setRevokeNode(null)
      await loadFleet(true)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to revoke node')
    } finally {
      setPendingNodeId(null)
    }
  }

  async function applyFleetWorkerTarget() {
    const target = Number(fleetWorkerTarget)
    if (!Number.isInteger(target) || target < 0 || target > 16384) {
      toast.error('Fleet worker target must be a whole number from 0 to 16384')
      return
    }
    setFleetScaling(true)
    try {
      const response = await scaleFleetWorkers(target, operatorToken)
      toast.success(`Distributed ${response.desired_worker_count} workers across ${response.eligible_node_count} eligible nodes`)
      setFleetWorkerTarget('')
      await loadFleet(true)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to scale fleet')
    } finally {
      setFleetScaling(false)
    }
  }

  async function loadActivity(nodeId: string) {
    setActivityLoading(nodeId)
    try {
      const [response, eventResponse] = await Promise.all([
        getFleetNodeActivity(nodeId, 25, operatorToken),
        getFleetNodeEvents(nodeId, 25, operatorToken),
      ])
      setActivity((current) => ({ ...current, [nodeId]: response }))
      setEvents((current) => ({ ...current, [nodeId]: eventResponse }))
      setActivityError((current) => ({ ...current, [nodeId]: '' }))
    } catch (err) {
      setActivityError((current) => ({
        ...current,
        [nodeId]: err instanceof Error ? err.message : 'Failed to load activity',
      }))
    } finally {
      setActivityLoading(null)
    }
  }

  async function toggleActivity(node: FleetNode) {
    if (expandedNodeId === node.id) {
      setExpandedNodeId(null)
      return
    }
    setExpandedNodeId(node.id)
    await loadActivity(node.id)
  }

  const fleetState = workers?.fleet
  if (loading && !workers) {
    return (
      <div className="mx-auto max-w-4xl p-6">
        <PageHeader
          title="Fleet"
          description="Checking whether multi-node Fleet is available on this installation."
          icon={<ServerCog className="h-7 w-7" />}
        />
        <Card className="h-36 animate-pulse bg-gray-900/70" aria-label="Checking Fleet availability" />
      </div>
    )
  }
  if (!loading && !workers && error) {
    return (
      <div className="mx-auto max-w-4xl p-6">
        <PageHeader
          title="Fleet"
          description="Coordinate Linux worker nodes from one ShakerScan control plane."
          icon={<ServerCog className="h-7 w-7" />}
        />
        <ErrorState message={error} onRetry={() => void loadFleet()} />
      </div>
    )
  }
  if (!loading && fleetState && !fleetState.enabled) {
    const macosUnsupported = fleetState.status === 'unsupported' && fleetState.host_platform === 'macos'
    return (
      <div className="mx-auto max-w-4xl p-6">
        <PageHeader
          title="Fleet"
          description="Coordinate Linux worker nodes from one ShakerScan control plane."
          icon={<ServerCog className="h-7 w-7" />}
        />
        <Card className="p-6">
          <div className="flex items-start gap-4">
            <span className={`rounded-xl p-3 ${macosUnsupported ? 'bg-amber-500/10 text-amber-300' : 'bg-blue-500/10 text-blue-300'}`}>
              {macosUnsupported
                ? <TriangleAlert className="h-6 w-6" aria-hidden="true" />
                : <ServerCog className="h-6 w-6" aria-hidden="true" />}
            </span>
            <div className="min-w-0">
              <h2 className="text-lg font-semibold text-white">
                {macosUnsupported ? 'Multi-node Fleet is not supported on macOS' : 'Fleet is not enabled'}
              </h2>
              <p className="mt-2 text-sm leading-6 text-gray-400">
                {macosUnsupported
                  ? 'This Mac can run standalone ShakerScan, but managed control-plane and worker-node services require Linux host networking and service management. Use a Linux VPS or Linux VM as the control plane and Linux machines as worker nodes.'
                  : 'This installation is running in standalone mode. Fleet navigation, remote-worker counts, and remote placement stay hidden until this Linux control plane is explicitly initialized.'}
              </p>
              {!macosUnsupported && (
                <div className="mt-4 rounded-lg border border-gray-800 bg-gray-950 px-4 py-3 font-mono text-sm text-gray-300">
                  shakerscan fleet preflight --help<br />
                  shakerscan fleet init --help
                </div>
              )}
              <div className="mt-4 flex flex-wrap gap-4 text-sm">
                <Link href="/docs" className="font-medium text-blue-400 hover:text-blue-300">
                  Read the installed guide →
                </Link>
                <a
                  href="https://github.com/andriyze/shakerscan/blob/main/docs/multi-node-guide.md"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-medium text-blue-400 hover:text-blue-300"
                >
                  Multi-node setup guide ↗
                </a>
              </div>
            </div>
          </div>
        </Card>
      </div>
    )
  }
  if (!loading && error && nodes.length === 0) {
    return (
      <div className="mx-auto max-w-7xl p-6">
        <PageHeader
          title="Fleet"
          description="Operate every joined ShakerScan worker node from one control plane."
          icon={<ServerCog className="h-7 w-7" />}
          actions={
            <Button variant="secondary" size="sm" onClick={() => void loadFleet(true)} loading={refreshing}>
              <RefreshCw className="h-4 w-4" aria-hidden="true" />
              Refresh
            </Button>
          }
        />
        <OperatorAccessCard
          operatorToken={operatorToken}
          showToken={showToken}
          onTokenChange={changeOperatorToken}
          onToggleVisibility={() => setShowToken((value) => !value)}
        />
        <ErrorState message={error} onRetry={() => void loadFleet()} />
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-7xl p-6">
      <PageHeader
        title="Fleet"
        description="Operate every joined ShakerScan worker node from one control plane. Desired-state changes are applied by each node agent."
        icon={<ServerCog className="h-7 w-7" />}
        actions={
          <Button variant="secondary" size="sm" onClick={() => void loadFleet(true)} loading={refreshing}>
            <RefreshCw className="h-4 w-4" aria-hidden="true" />
            Refresh
          </Button>
        }
      />

      <div className="mb-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        <SummaryCard
          label="Remote nodes available"
          value={`${availableRemoteNodes.length}/${summary.active_nodes}`}
          detail={`${summary.unhealthy_nodes} unhealthy · ${summary.stale_nodes} stale · ${summary.draining_nodes} draining`}
          tone={summary.active_nodes === 0 ? 'normal' : availableRemoteNodes.length === summary.active_nodes ? 'good' : 'warning'}
        />
        <SummaryCard
          label="Remote workers available"
          value={`${availableRemoteWorkers}/${summary.desired_workers}`}
          detail={`${summary.active_workers} reported active across remote nodes`}
          tone={summary.desired_workers === 0 ? 'normal' : availableRemoteWorkers === summary.desired_workers ? 'good' : 'warning'}
        />
        <SummaryCard
          label="Local workers available"
          value={`${localAvailableWorkers}/${localRunningWorkers}`}
          detail="current / running on this control plane"
          tone={localRunningWorkers === 0 ? 'warning' : localAvailableWorkers === localRunningWorkers ? 'good' : 'warning'}
        />
        <SummaryCard
          label="Total execution capacity"
          value={localAvailableWorkers + availableRemoteWorkers}
          detail={`${localAvailableWorkers} local · ${availableRemoteWorkers} remote workers available`}
          tone={localAvailableWorkers + availableRemoteWorkers > 0 ? 'good' : 'warning'}
        />
        <SummaryCard
          label="State drift"
          value={summary.state_drift_nodes}
          detail="nodes not at desired state version"
          tone={summary.state_drift_nodes ? 'warning' : 'good'}
        />
        <SummaryCard
          label="Image drift"
          value={summary.image_drift_nodes}
          detail="running nodes on another image"
          tone={summary.image_drift_nodes ? 'warning' : 'good'}
        />
      </div>

      <OperatorAccessCard
        operatorToken={operatorToken}
        showToken={showToken}
        onTokenChange={changeOperatorToken}
        onToggleVisibility={() => setShowToken((value) => !value)}
      />

      <Card className="mb-6 p-4">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <div className="text-sm font-medium text-gray-200">Remote fleet worker target</div>
            <p className="mt-1 max-w-2xl text-xs text-gray-500">
              Set the remote-worker total. The control plane assigns integer shares by each healthy remote node&apos;s reported CPU or worker weight. Local workers are scaled separately from the Dashboard.
            </p>
          </div>
          <div className="flex w-full gap-2 lg:w-80">
            <Input
              type="number"
              min={0}
              max={16384}
              step={1}
              value={fleetWorkerTarget}
              onChange={(event) => setFleetWorkerTarget(event.target.value)}
              placeholder={`Current: ${summary.desired_workers}`}
              aria-label="Desired workers across the fleet"
            />
            <Button
              onClick={() => void applyFleetWorkerTarget()}
              loading={fleetScaling}
              disabled={fleetWorkerTarget.trim() === ''}
            >
              Apply
            </Button>
          </div>
        </div>
      </Card>

      {error && <div className="mb-4"><ErrorState message={error} onRetry={() => void loadFleet()} /></div>}

      {reconciliationMode === 'manual' && (
        <div className="mb-4 flex gap-3 rounded-lg border border-blue-500/25 bg-blue-500/10 p-4 text-sm text-blue-100" role="status">
          <TriangleAlert className="mt-0.5 h-5 w-5 shrink-0 text-blue-300" aria-hidden="true" />
          <div>
            <p className="font-medium">Manual WireGuard peer reconciliation is enabled</p>
            <p className="mt-1 text-xs text-blue-200/75">
              Run <code>shakerscan fleet reconcile</code> on the control plane after every WireGuard join or revocation.
            </p>
          </div>
        </div>
      )}

      {summary.wireguard_connection_pending_nodes > 0 && (
        <div className="mb-4 flex gap-3 rounded-lg border border-amber-500/25 bg-amber-500/10 p-4 text-sm text-amber-100" role="status">
          <TriangleAlert className="mt-0.5 h-5 w-5 shrink-0 text-amber-300" aria-hidden="true" />
          <div>
            <p className="font-medium">
              {summary.wireguard_connection_pending_nodes} WireGuard node{summary.wireguard_connection_pending_nodes === 1 ? '' : 's'} awaiting first connection
            </p>
            <p className="mt-1 text-xs text-amber-200/75">
              Check control-plane peer reconciliation and inbound UDP reachability. On a host initialized with <code>--no-reconcile-service</code>, run <code>shakerscan fleet reconcile</code> now.
            </p>
          </div>
        </div>
      )}

      {loading && nodes.length === 0 ? (
        <div className="space-y-3" aria-label="Loading fleet nodes">
          {[0, 1].map((item) => <Card key={item} className="h-56 animate-pulse bg-gray-900/70" />)}
        </div>
      ) : nodes.length === 0 ? (
        <EmptyState
          message="No remote worker nodes have joined this fleet yet."
          hint="Run shakerscan fleet join-token on the control plane, then shakerscan join on a worker VPS."
        />
      ) : (
        <div className="space-y-4">
          <div className="flex flex-wrap items-end justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-gray-200">Remote worker nodes</h2>
              <p className="mt-1 text-xs text-gray-500">{availableRemoteNodes.length} nodes and {availableRemoteWorkers} workers are currently schedulable.</p>
            </div>
            <Link href="/scan/new" className="text-xs font-medium text-blue-400 hover:text-blue-300">
              Start a scan on a selected node →
            </Link>
          </div>
          {nodes.map((node) => {
            const busy = pendingNodeId === node.id
            const disabled = node.status === 'disabled'
            const currentActivity = activity[node.id]
            const currentEvents = events[node.id]
            const expanded = expandedNodeId === node.id
            return (
              <Card key={node.id} className={disabled ? 'border-red-950/70 opacity-75' : ''}>
                <div className="p-5">
                  <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <h2 className="truncate text-lg font-semibold text-white">{node.name}</h2>
                        <Badge className={statusClasses(node.status)}>
                          {node.status === 'healthy' && <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />}
                          {node.status}
                        </Badge>
                        {!node.state_current && !disabled && <Badge className="bg-amber-500/15 text-amber-300">state drift</Badge>}
                        {node.wireguard_connection_pending && !disabled && <Badge className="bg-amber-500/15 text-amber-300">awaiting WireGuard</Badge>}
                        {node.local_build_active && node.active_worker_count > 0 && !disabled && <Badge className="bg-amber-500/15 text-amber-300">local test build</Badge>}
                        {!node.image_current && !node.local_build_active && node.active_worker_count > 0 && !disabled && <Badge className="bg-amber-500/15 text-amber-300">image drift</Badge>}
                        {node.rollout_in_progress && <Badge className="bg-blue-500/15 text-blue-300">rolling update</Badge>}
                      </div>
                      <p className="mt-1 text-sm text-gray-500">
                        {node.hostname || 'Hostname unknown'} · {node.region || 'No region'} · {node.overlay_ip || 'No overlay IP'}
                      </p>
                    </div>

                    {!disabled && (
                      <div className="flex flex-wrap items-center gap-2">
                        <div className="mr-1 flex items-center rounded-lg border border-gray-700 bg-gray-950">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="rounded-r-none px-2"
                            disabled={busy || node.desired_worker_count <= 0 || node.drain}
                            onClick={() => void mutateNode(node, { desired_worker_count: Math.max(0, node.desired_worker_count - 1) }, `Scaling ${node.name} to ${Math.max(0, node.desired_worker_count - 1)} workers`)}
                            aria-label={`Decrease desired workers for ${node.name}`}
                          >
                            <Minus className="h-4 w-4" />
                          </Button>
                          <span className="min-w-20 px-2 text-center text-xs text-gray-300" title="Active / desired remote workers">
                            {node.active_worker_count} / {node.desired_worker_count}
                          </span>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="rounded-l-none px-2"
                            disabled={busy || node.desired_worker_count >= 128 || node.drain}
                            onClick={() => void mutateNode(node, { desired_worker_count: Math.min(128, node.desired_worker_count + 1) }, `Scaling ${node.name} to ${Math.min(128, node.desired_worker_count + 1)} workers`)}
                            aria-label={`Increase desired workers for ${node.name}`}
                          >
                            <Plus className="h-4 w-4" />
                          </Button>
                        </div>
                        {node.drain ? (
                          <Button size="sm" disabled={busy || node.rollout_in_progress} onClick={() => void mutateNode(node, { drain: false }, `${node.name} resumed`)}>
                            <Play className="h-4 w-4" /> Resume
                          </Button>
                        ) : (
                          <Button variant="secondary" size="sm" disabled={busy} onClick={() => void mutateNode(node, { drain: true }, `${node.name} is draining`)}>
                            <CircleStop className="h-4 w-4" /> Drain
                          </Button>
                        )}
                        <Button variant="danger" size="sm" disabled={busy} onClick={() => setRevokeNode(node)}>
                          <Unplug className="h-4 w-4" /> Revoke
                        </Button>
                      </div>
                    )}
                  </div>

                  <dl className="mt-5 grid gap-4 border-t border-gray-800 pt-4 sm:grid-cols-2 lg:grid-cols-4">
                    <div>
                      <dt className="text-xs uppercase tracking-wide text-gray-600">Heartbeat</dt>
                      <dd className="mt-1 text-sm text-gray-300" title={node.last_heartbeat_at || undefined}>{relativeTime(node.last_heartbeat_at)}</dd>
                    </div>
                    <div>
                      <dt className="text-xs uppercase tracking-wide text-gray-600">Capacity</dt>
                      <dd className="mt-1 text-sm text-gray-300">{capacityLabel(node.capacity || {})}</dd>
                    </div>
                    <div>
                      <dt className="text-xs uppercase tracking-wide text-gray-600">Egress</dt>
                      <dd className="mt-1 truncate text-sm text-gray-300">{node.egress_ip || 'Not reported'}</dd>
                    </div>
                    <div>
                      <dt className="text-xs uppercase tracking-wide text-gray-600">Agent / state</dt>
                      <dd className="mt-1 text-sm text-gray-300">v{node.agent_version || '?'} · {node.applied_state_version}/{node.desired_state_version}</dd>
                    </div>
                    <div className="sm:col-span-2">
                      <dt className="text-xs uppercase tracking-wide text-gray-600">Active image</dt>
                      <dd className="mt-1 truncate font-mono text-xs text-gray-400" title={node.active_worker_image_digest || undefined}>{shortDigest(node.active_worker_image_digest)}</dd>
                    </div>
                    <div className="sm:col-span-2">
                      <dt className="text-xs uppercase tracking-wide text-gray-600">Desired image</dt>
                      <dd className="mt-1 truncate font-mono text-xs text-gray-400" title={node.worker_image_digest || undefined}>{shortDigest(node.worker_image_digest)}</dd>
                    </div>
                  </dl>

                  {!disabled && (
                    <div className="mt-4 border-t border-gray-800 pt-4">
                      <div className="text-xs uppercase tracking-wide text-gray-600">Rolling image update</div>
                      <div className="mt-2 flex flex-col gap-2 lg:flex-row">
                        <Input
                          value={rolloutDigests[node.id] || ''}
                          onChange={(event) => setRolloutDigests((current) => ({ ...current, [node.id]: event.target.value }))}
                          placeholder="registry.example/shakerscan@sha256:…"
                          aria-label={`Digest-pinned worker image for ${node.name}`}
                          disabled={busy || node.rollout_in_progress}
                        />
                        <Button
                          variant="secondary"
                          disabled={
                            busy
                            || node.rollout_in_progress
                            || !/^.+@sha256:[0-9a-fA-F]{64}$/.test((rolloutDigests[node.id] || '').trim())
                            || (rolloutDigests[node.id] || '').trim() === node.worker_image_digest
                          }
                          onClick={() => void mutateNode(
                            node,
                            { worker_image_digest: (rolloutDigests[node.id] || '').trim() },
                            `Rolling ${node.name} to the requested image`,
                          )}
                        >
                          <RefreshCw className="h-4 w-4" /> Roll out
                        </Button>
                      </div>
                      <p className="mt-2 text-xs text-gray-600">
                        The node stops taking new leases, lets active jobs finish, then replaces one idle worker per agent pass.
                      </p>
                    </div>
                  )}

                  {Object.keys(node.labels || {}).length > 0 && (
                    <div className="mt-4 border-t border-gray-800 pt-4">
                      <div className="text-xs uppercase tracking-wide text-gray-600">Placement labels</div>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {Object.entries(node.labels || {}).flatMap(([key, raw]) => {
                          const values = Array.isArray(raw) ? raw : [raw]
                          return values.slice(0, 12).map((value) => (
                            <Badge key={`${key}:${String(value)}`} className="bg-blue-500/10 text-blue-300">
                              {key}={String(value)}
                            </Badge>
                          ))
                        })}
                      </div>
                    </div>
                  )}

                  {node.last_error && (
                    <div className="mt-4 flex gap-2 rounded-lg border border-amber-500/20 bg-amber-500/10 p-3 text-sm text-amber-200">
                      <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" />
                      <span className="break-words">{node.last_error}</span>
                    </div>
                  )}

                  <button
                    type="button"
                    onClick={() => void toggleActivity(node)}
                    className="mt-4 inline-flex items-center gap-2 rounded text-sm text-blue-400 hover:text-blue-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                    aria-expanded={expanded}
                  >
                    {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                    <Activity className="h-4 w-4" /> Recent work
                  </button>
                </div>

                {expanded && (
                  <div className="border-t border-gray-800 bg-gray-950/40 p-5">
                    {activityLoading === node.id ? (
                      <p className="flex items-center gap-2 text-sm text-gray-500"><Gauge className="h-4 w-4 animate-pulse" /> Loading activity…</p>
                    ) : activityError[node.id] ? (
                      <ErrorState message={activityError[node.id]} onRetry={() => void loadActivity(node.id)} />
                    ) : (
                      <div className="space-y-6">
                        <div>
                          <h3 className="mb-2 text-xs font-medium uppercase tracking-wide text-gray-600">Lifecycle audit</h3>
                          {!currentEvents?.events.length ? (
                            <p className="text-sm text-gray-500">No lifecycle events recorded yet.</p>
                          ) : (
                            <div className="space-y-2">
                              {currentEvents.events.slice(0, 12).map((event) => (
                                <div key={event.id} className="flex flex-col gap-1 rounded-lg border border-gray-800 bg-gray-950/60 px-3 py-2 sm:flex-row sm:items-center sm:justify-between">
                                  <div className="flex items-center gap-2">
                                    <Badge className={event.severity === 'error' ? 'bg-red-500/15 text-red-300' : event.severity === 'warning' ? 'bg-amber-500/15 text-amber-300' : 'bg-gray-800 text-gray-300'}>
                                      {event.actor_type}
                                    </Badge>
                                    <span className="text-sm text-gray-300">{event.event_type.replaceAll('_', ' ')}</span>
                                  </div>
                                  <span className="text-xs text-gray-600" title={event.created_at}>{relativeTime(event.created_at)}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                        <div className="overflow-x-auto">
                          <h3 className="mb-2 text-xs font-medium uppercase tracking-wide text-gray-600">Attributed scans</h3>
                          {!currentActivity?.scans.length ? (
                            <p className="text-sm text-gray-500">No scans have been attributed to this node yet.</p>
                          ) : (
                        <table className="w-full min-w-[760px] text-left text-sm">
                          <thead className="text-xs uppercase tracking-wide text-gray-600">
                            <tr>
                              <th className="pb-2 font-medium">Target</th>
                              <th className="pb-2 font-medium">Work</th>
                              <th className="pb-2 font-medium">Status</th>
                              <th className="pb-2 font-medium">Worker</th>
                              <th className="pb-2 text-right font-medium">Started</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-gray-800">
                            {currentActivity.scans.map((scan) => (
                              <tr key={scan.id}>
                                <td className="max-w-xs py-3 pr-4">
                                  <Link href={`/scans/${scan.id}`} className="block truncate text-blue-400 hover:text-blue-300" title={scan.target_url}>{scan.target_url}</Link>
                                </td>
                                <td className="py-3 pr-4 text-gray-400">
                                  {scan.scan_role === 'shard' ? `Shard ${(scan.shard_index ?? 0) + 1}/${scan.shard_count || '?'}` : scan.scan_type}
                                </td>
                                <td className="py-3 pr-4"><ScanStatusBadge status={scan.status} /></td>
                                <td className="max-w-56 truncate py-3 pr-4 font-mono text-xs text-gray-500" title={scan.worker_id || undefined}>{scan.worker_id || 'Unknown'}</td>
                                <td className="py-3 text-right text-xs text-gray-500">{relativeTime(scan.started_at || scan.created_at)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </Card>
            )
          })}
        </div>
      )}

      <div className="mt-4 flex items-center justify-between text-xs text-gray-600">
        <span>Nodes become stale after {staleAfterSeconds ? `${Math.round(staleAfterSeconds / 60)} minutes` : 'the configured heartbeat window'}.</span>
        <LastUpdated updatedAt={updatedAt} onRefresh={() => void loadFleet(true)} refreshing={refreshing} />
      </div>

      <ConfirmDialog
        open={Boolean(revokeNode)}
        title={`Revoke ${revokeNode?.name || 'node'}?`}
        message="This disables the node, drains its workers, revokes all node credentials, and removes its WireGuard peer during reconciliation. Rejoining requires a new token."
        confirmLabel="Revoke node"
        danger
        busy={Boolean(revokeNode && pendingNodeId === revokeNode.id)}
        onConfirm={() => void confirmRevoke()}
        onCancel={() => setRevokeNode(null)}
      />
    </div>
  )
}
