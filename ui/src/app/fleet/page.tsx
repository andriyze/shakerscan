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
  getFleetNodes,
  revokeFleetNode,
  updateFleetNodeState,
  type FleetNode,
  type FleetNodeActivityResponse,
  type FleetSummary,
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
  stale_nodes: 0,
  draining_nodes: 0,
  desired_workers: 0,
  active_workers: 0,
  state_drift_nodes: 0,
  image_drift_nodes: 0,
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

export default function FleetPage() {
  const toast = useToast()
  const [nodes, setNodes] = useState<FleetNode[]>([])
  const [summary, setSummary] = useState<FleetSummary>(EMPTY_SUMMARY)
  const [staleAfterSeconds, setStaleAfterSeconds] = useState(0)
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
  const [activityLoading, setActivityLoading] = useState<string | null>(null)
  const [activityError, setActivityError] = useState<Record<string, string>>({})

  const loadFleet = useCallback(async (background = false) => {
    if (background) setRefreshing(true)
    else setLoading(true)
    try {
      const response = await getFleetNodes()
      setNodes(response.nodes)
      setSummary(response.summary)
      setStaleAfterSeconds(response.stale_after_seconds)
      setUpdatedAt(new Date())
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load fleet')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

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

  async function mutateNode(node: FleetNode, update: { desired_worker_count?: number; drain?: boolean }, success: string) {
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

  async function loadActivity(nodeId: string) {
    setActivityLoading(nodeId)
    try {
      const response = await getFleetNodeActivity(nodeId)
      setActivity((current) => ({ ...current, [nodeId]: response }))
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

      <div className="mb-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <SummaryCard
          label="Nodes online"
          value={`${summary.healthy_nodes}/${summary.active_nodes}`}
          detail={`${summary.stale_nodes} stale · ${summary.draining_nodes} draining`}
          tone={summary.stale_nodes ? 'warning' : summary.healthy_nodes ? 'good' : 'normal'}
        />
        <SummaryCard
          label="Workers active"
          value={`${summary.active_workers}/${summary.desired_workers}`}
          detail="active / desired across the fleet"
          tone={summary.desired_workers === 0 ? 'normal' : summary.active_workers === summary.desired_workers ? 'good' : 'warning'}
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

      <Card className="mb-6 p-4">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <div className="flex items-center gap-2 text-sm font-medium text-gray-200">
              <ShieldCheck className="h-4 w-4 text-blue-400" aria-hidden="true" />
              Operator access
            </div>
            <p className="mt-1 max-w-2xl text-xs text-gray-500">
              Loopback access needs no token. Remote lifecycle actions require the control plane&apos;s operator token over HTTPS; it stays in this browser tab only.
            </p>
          </div>
          <div className="flex w-full gap-2 lg:w-[28rem]">
            <Input
              type={showToken ? 'text' : 'password'}
              value={operatorToken}
              onChange={(event) => changeOperatorToken(event.target.value)}
              placeholder="Remote operator token (optional on loopback)"
              aria-label="Fleet operator token"
              autoComplete="off"
            />
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setShowToken((value) => !value)}
              aria-label={showToken ? 'Hide operator token' : 'Show operator token'}
            >
              {showToken ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </Button>
          </div>
        </div>
      </Card>

      {error && <div className="mb-4"><ErrorState message={error} onRetry={() => void loadFleet()} /></div>}

      {loading && nodes.length === 0 ? (
        <div className="space-y-3" aria-label="Loading fleet nodes">
          {[0, 1].map((item) => <Card key={item} className="h-56 animate-pulse bg-gray-900/70" />)}
        </div>
      ) : nodes.length === 0 ? (
        <EmptyState
          message="No worker nodes have joined this fleet yet."
          hint="Run shakerscan fleet join-token on the control plane, then shakerscan join on a worker VPS."
        />
      ) : (
        <div className="space-y-4">
          {nodes.map((node) => {
            const busy = pendingNodeId === node.id
            const disabled = node.status === 'disabled'
            const currentActivity = activity[node.id]
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
                        {!node.image_current && node.active_worker_count > 0 && !disabled && <Badge className="bg-amber-500/15 text-amber-300">image drift</Badge>}
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
                          <span className="min-w-20 px-2 text-center text-xs text-gray-300" title="Active / desired workers">
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
                          <Button size="sm" disabled={busy} onClick={() => void mutateNode(node, { drain: false }, `${node.name} resumed`)}>
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
                    ) : !currentActivity?.scans.length ? (
                      <p className="text-sm text-gray-500">No scans have been attributed to this node yet.</p>
                    ) : (
                      <div className="overflow-x-auto">
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
