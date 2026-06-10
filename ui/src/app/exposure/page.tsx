'use client'

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import {
  AlertTriangle,
  Bot,
  Boxes,
  Cloud,
  Code2,
  GitBranch,
  Globe2,
  KeyRound,
  Network,
  RefreshCw,
  Route,
  Search,
  ShieldAlert,
  Target,
} from 'lucide-react'
import {
  formatDate,
  getDomains,
  getExposureGraph,
  type ExposureEdge,
  type ExposureGraph,
  type ExposureNode,
  type ExposureNodeType,
} from '@/lib/api'
import { SEVERITY_BADGE_STYLES, type SeverityLevel } from '@/lib/constants'
import { Button, Card, CardSkeleton, EmptyState, ErrorState } from '@/components/ui'

const MAX_VISIBLE_EDGES = 80

const NODE_LABELS: Record<string, string> = {
  domain: 'Domains',
  web_target: 'Web targets',
  endpoint: 'Endpoints',
  api_surface: 'APIs',
  auth_role: 'Auth roles',
  third_party_js: 'Third-party JS',
  cloud_hint: 'Cloud hints',
  ai_target: 'AI surfaces',
  mcp_tool: 'MCP tools',
  scan: 'Scans',
  finding: 'Findings',
  vendor: 'Vendors',
  attack_chain: 'Attack chains',
}

const NODE_STYLES: Record<string, string> = {
  domain: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-200',
  web_target: 'border-blue-500/30 bg-blue-500/10 text-blue-200',
  endpoint: 'border-sky-500/30 bg-sky-500/10 text-sky-200',
  api_surface: 'border-indigo-500/30 bg-indigo-500/10 text-indigo-200',
  auth_role: 'border-lime-500/30 bg-lime-500/10 text-lime-200',
  third_party_js: 'border-yellow-500/30 bg-yellow-500/10 text-yellow-200',
  cloud_hint: 'border-teal-500/30 bg-teal-500/10 text-teal-200',
  ai_target: 'border-purple-500/30 bg-purple-500/10 text-purple-200',
  mcp_tool: 'border-fuchsia-500/30 bg-fuchsia-500/10 text-fuchsia-200',
  scan: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200',
  finding: 'border-orange-500/30 bg-orange-500/10 text-orange-200',
  vendor: 'border-amber-500/30 bg-amber-500/10 text-amber-200',
  attack_chain: 'border-red-500/30 bg-red-500/10 text-red-200',
}

function nodeIcon(type: ExposureNodeType) {
  const className = 'h-4 w-4'
  if (type === 'domain') return <Globe2 className={className} />
  if (type === 'web_target') return <Target className={className} />
  if (type === 'endpoint') return <Route className={className} />
  if (type === 'api_surface') return <Code2 className={className} />
  if (type === 'auth_role') return <KeyRound className={className} />
  if (type === 'third_party_js') return <Code2 className={className} />
  if (type === 'cloud_hint') return <Cloud className={className} />
  if (type === 'ai_target') return <Bot className={className} />
  if (type === 'mcp_tool') return <Boxes className={className} />
  if (type === 'scan') return <Search className={className} />
  if (type === 'finding') return <ShieldAlert className={className} />
  if (type === 'vendor') return <Boxes className={className} />
  return <GitBranch className={className} />
}

function severityClass(severity?: string | null) {
  if (!severity) return 'bg-gray-700 text-gray-300'
  return SEVERITY_BADGE_STYLES[severity as SeverityLevel] ?? SEVERITY_BADGE_STYLES.info
}

function metaString(node: ExposureNode, key: string) {
  const value = node.meta?.[key]
  if (value === undefined || value === null || value === '') return null
  return String(value)
}

function NodePill({ node }: { node: ExposureNode }) {
  const style = NODE_STYLES[node.type] || 'border-gray-700 bg-gray-800 text-gray-200'
  const body = (
    <div className={`min-w-0 rounded-lg border px-3 py-2 ${style}`}>
      <div className="flex min-w-0 items-center gap-2">
        {nodeIcon(node.type)}
        <span className="truncate text-sm font-medium">{node.label}</span>
        {node.severity && (
          <span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] uppercase ${severityClass(node.severity)}`}>
            {node.severity}
          </span>
        )}
      </div>
      {node.subtitle && <div className="mt-1 truncate text-xs opacity-75">{node.subtitle}</div>}
    </div>
  )

  if (node.href) {
    return (
      <Link
        href={node.href}
        className="block rounded-lg focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
      >
        {body}
      </Link>
    )
  }
  return body
}

function StatPanel({ label, value, icon }: { label: string; value: string | number; icon: React.ReactNode }) {
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs uppercase tracking-wide text-gray-500">{label}</div>
          <div className="mt-2 text-2xl font-semibold text-white">{value}</div>
        </div>
        <div className="rounded-lg bg-gray-800 p-2 text-gray-300">{icon}</div>
      </div>
    </Card>
  )
}

function RelationshipRow({
  edge,
  byId,
}: {
  edge: ExposureEdge
  byId: Map<string, ExposureNode>
}) {
  const source = byId.get(edge.source)
  const target = byId.get(edge.target)
  if (!source || !target) return null

  return (
    <div className="grid gap-3 border-b border-gray-800 px-4 py-3 last:border-b-0 lg:grid-cols-[minmax(0,1fr)_150px_minmax(0,1fr)]">
      <NodePill node={source} />
      <div className="flex items-center justify-start lg:justify-center">
        <span className="rounded-full border border-gray-700 bg-gray-950 px-3 py-1 text-xs text-gray-300">
          {edge.label}
        </span>
      </div>
      <NodePill node={target} />
    </div>
  )
}

export default function ExposurePage() {
  const [graph, setGraph] = useState<ExposureGraph | null>(null)
  const [domains, setDomains] = useState<string[]>([])
  const [domain, setDomain] = useState('')
  const [includeResolved, setIncludeResolved] = useState(false)
  const [selectedType, setSelectedType] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  async function loadGraph() {
    setLoading(true)
    try {
      const payload = await getExposureGraph({
        root_domain: domain || undefined,
        includeResolved,
        limitFindings: 250,
        limitScans: 150,
      })
      setGraph(payload)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load exposure graph')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    getDomains().then((payload) => setDomains(payload.domains || [])).catch(() => {})
  }, [])

  useEffect(() => {
    loadGraph()
  }, [domain, includeResolved])

  const byId = useMemo(() => new Map((graph?.nodes || []).map((node) => [node.id, node])), [graph])
  const nodeTypeCounts = graph?.summary.node_type_counts || {}
  const findingCounts = graph?.summary.severity_counts || {}
  const criticalHigh = (findingCounts.critical || 0) + (findingCounts.high || 0)

  const filteredEdges = useMemo(() => {
    const edges = graph?.edges || []
    if (!selectedType) return edges
    return edges.filter(
      (edge) => byId.get(edge.source)?.type === selectedType || byId.get(edge.target)?.type === selectedType
    )
  }, [graph, selectedType, byId])

  const visibleEdges = useMemo(() => filteredEdges.slice(0, MAX_VISIBLE_EDGES), [filteredEdges])

  const recentScans = useMemo(
    () =>
      (graph?.nodes || [])
        .filter((node) => node.type === 'scan')
        .sort((a, b) => String(b.meta.created_at || '').localeCompare(String(a.meta.created_at || '')))
        .slice(0, 8),
    [graph]
  )

  const hotspots = graph?.summary.hotspots || []
  const graphIsEmpty = !loading && (graph?.edges?.length ?? 0) === 0

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Exposure Graph</h1>
          <p className="mt-1 text-gray-400">Connected view of targets, AI surfaces, findings, vendors, scans, and attack chains</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <select
            value={domain}
            onChange={(event) => setDomain(event.target.value)}
            aria-label="Filter by domain"
            className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
          >
            <option value="">All domains</option>
            {domains.map((item) => (
              <option key={item} value={item}>{item}</option>
            ))}
          </select>
          <label className="flex items-center gap-2 rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-300">
            <input
              type="checkbox"
              checked={includeResolved}
              onChange={(event) => setIncludeResolved(event.target.checked)}
              className="rounded border-gray-700 bg-gray-800"
            />
            Include resolved
          </label>
          <Button onClick={() => void loadGraph()} disabled={loading}>
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
            Refresh
          </Button>
        </div>
      </div>

      {error && <ErrorState message={error} onRetry={() => void loadGraph()} />}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatPanel label="Nodes" value={graph?.summary.node_count ?? '--'} icon={<Network className="h-5 w-5" />} />
        <StatPanel label="Edges" value={graph?.summary.edge_count ?? '--'} icon={<GitBranch className="h-5 w-5" />} />
        <StatPanel label="AI Surfaces" value={nodeTypeCounts.ai_target || 0} icon={<Bot className="h-5 w-5" />} />
        <StatPanel label="Critical/High" value={criticalHigh} icon={<AlertTriangle className="h-5 w-5" />} />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.25fr_0.75fr]">
        <Card>
          <div className="flex flex-col gap-3 border-b border-gray-800 p-4 md:flex-row md:items-center md:justify-between">
            <div>
              <h2 className="font-semibold text-white">Relationships</h2>
              <p className="mt-1 text-sm text-gray-500">
                {filteredEdges.length > visibleEdges.length
                  ? `Showing ${visibleEdges.length} of ${filteredEdges.length} relationships`
                  : `${visibleEdges.length} visible relationships`}
              </p>
            </div>
            <select
              value={selectedType}
              onChange={(event) => setSelectedType(event.target.value)}
              aria-label="Filter by node type"
              className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="">All node types</option>
              {Object.entries(NODE_LABELS).map(([value, label]) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
          </div>
          {loading ? (
            <div className="p-4">
              <CardSkeleton count={3} />
            </div>
          ) : graphIsEmpty ? (
            <div className="p-4">
              <EmptyState
                message="No exposure data yet."
                hint="Run scans to build the exposure graph."
                action={{ label: 'New Scan', href: '/scan/new' }}
              />
            </div>
          ) : visibleEdges.length === 0 ? (
            <div className="p-4">
              <EmptyState message="No relationships found." hint="Try a different node type filter." />
            </div>
          ) : (
            <div>
              {visibleEdges.map((edge, index) => (
                <RelationshipRow key={`${edge.source}-${edge.target}-${edge.type}-${index}`} edge={edge} byId={byId} />
              ))}
            </div>
          )}
        </Card>

        <div className="space-y-6">
          <Card>
            <div className="border-b border-gray-800 p-4">
              <h2 className="font-semibold text-white">Hotspots</h2>
            </div>
            <div className="divide-y divide-gray-800">
              {hotspots.length === 0 ? (
                <div className="p-4 text-sm text-gray-500">No active high-risk nodes.</div>
              ) : (
                hotspots.map((node) => (
                  <div key={node.id} className="p-4">
                    <NodePill node={node} />
                    <div className="mt-2 flex flex-wrap gap-2 text-xs text-gray-500">
                      {metaString(node, 'active_findings_count') && <span>{metaString(node, 'active_findings_count')} active findings</span>}
                      {metaString(node, 'last_grade') && <span>Grade {metaString(node, 'last_grade')}</span>}
                      {metaString(node, 'target_type') && <span>{metaString(node, 'target_type')}</span>}
                      {metaString(node, 'confidence') && <span>{metaString(node, 'confidence')} confidence</span>}
                    </div>
                  </div>
                ))
              )}
            </div>
          </Card>

          <Card>
            <div className="border-b border-gray-800 p-4">
              <h2 className="font-semibold text-white">Inventory</h2>
            </div>
            <div className="grid grid-cols-2 gap-3 p-4">
              {Object.entries(NODE_LABELS).map(([type, label]) => (
                <button
                  type="button"
                  key={type}
                  onClick={() => setSelectedType(selectedType === type ? '' : type)}
                  aria-pressed={selectedType === type}
                  className={`rounded-lg border px-3 py-2 text-left transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                    selectedType === type
                      ? 'border-blue-500 bg-blue-500/10 text-blue-200'
                      : 'border-gray-800 bg-gray-950 text-gray-300 hover:border-gray-700'
                  }`}
                >
                  <div className="text-xs text-gray-500">{label}</div>
                  <div className="mt-1 text-lg font-semibold text-white">{nodeTypeCounts[type] || 0}</div>
                </button>
              ))}
            </div>
          </Card>

          <Card>
            <div className="border-b border-gray-800 p-4">
              <h2 className="font-semibold text-white">Recent Scans</h2>
            </div>
            <div className="divide-y divide-gray-800">
              {recentScans.length === 0 ? (
                <div className="p-4 text-sm text-gray-500">No scans in graph.</div>
              ) : (
                recentScans.map((scan) => (
                  <Link
                    key={scan.id}
                    href={scan.href || '#'}
                    className="block p-4 hover:bg-gray-800/50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div className="min-w-0">
                        <div className="truncate text-sm font-medium text-white">{scan.label}</div>
                        <div className="mt-1 truncate text-xs text-gray-500">{scan.subtitle}</div>
                      </div>
                      {scan.status && (
                        <span className="rounded bg-gray-800 px-2 py-1 text-xs text-gray-300">{scan.status}</span>
                      )}
                    </div>
                    {typeof scan.meta.created_at === 'string' && (
                      <div className="mt-2 text-xs text-gray-600">{formatDate(scan.meta.created_at)}</div>
                    )}
                  </Link>
                ))
              )}
            </div>
          </Card>
        </div>
      </div>
    </div>
  )
}
