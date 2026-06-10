'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import Link from 'next/link'
import { Chakra_Petch, Spline_Sans_Mono } from 'next/font/google'
import {
  AlertTriangle,
  ArrowLeft,
  Bot,
  Boxes,
  Cloud,
  Code2,
  ExternalLink,
  GitBranch,
  Globe2,
  KeyRound,
  Layers,
  Loader2,
  RefreshCw,
  Route,
  Search,
  ShieldAlert,
  Target,
  X,
} from 'lucide-react'
import {
  getDomains,
  getExposureGraph,
  getExposureNodes,
  type ExposureEdge,
  type ExposureGraph,
  type ExposureNode,
  type ExposureNodeType,
  type ExposureSearchNode,
} from '@/lib/api'
import { SEVERITY_BADGE_STYLES, type SeverityLevel } from '@/lib/constants'
import { Button, CardSkeleton, EmptyState, ErrorState } from '@/components/ui'
import { ExposureGraph as ExposureGraphCanvas, NODE_HEX } from '@/components/ExposureGraph'
import styles from './exposure.module.css'

const displayFont = Chakra_Petch({
  weight: ['500', '600', '700'],
  subsets: ['latin'],
  variable: '--font-display',
})

const monoFont = Spline_Sans_Mono({
  weight: ['400', '500', '600'],
  subsets: ['latin'],
  variable: '--font-mono',
})

const LIST_PAGE_SIZE = 40

const NODE_LABELS: Record<string, string> = {
  domain: 'Domains',
  web_target: 'Web targets',
  model_artifact: 'Model artifacts',
  endpoint: 'Endpoints',
  api_surface: 'APIs',
  auth_role: 'Auth roles',
  third_party_js: 'Third-party JS',
  cloud_hint: 'Cloud hints',
  ai_target: 'AI surfaces',
  mcp_tool: 'MCP tools',
  scan: 'Scans',
  finding: 'Findings',
  finding_group: 'Finding groups',
  vendor: 'Vendors',
  attack_chain: 'Attack chains',
}

const NODE_SINGULAR: Record<string, string> = {
  domain: 'Domain',
  web_target: 'Web target',
  model_artifact: 'Model artifact',
  endpoint: 'Endpoint',
  api_surface: 'API surface',
  auth_role: 'Auth role',
  third_party_js: 'Third-party script',
  cloud_hint: 'Cloud hint',
  ai_target: 'AI surface',
  mcp_tool: 'MCP tool',
  scan: 'Scan',
  finding: 'Finding',
  finding_group: 'Grouped findings',
  vendor: 'Vendor',
  attack_chain: 'Attack chain',
}

const NODE_STYLES: Record<string, string> = {
  domain: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-200',
  web_target: 'border-blue-500/30 bg-blue-500/10 text-blue-200',
  model_artifact: 'border-teal-500/30 bg-teal-500/10 text-teal-200',
  endpoint: 'border-sky-500/30 bg-sky-500/10 text-sky-200',
  api_surface: 'border-indigo-500/30 bg-indigo-500/10 text-indigo-200',
  auth_role: 'border-lime-500/30 bg-lime-500/10 text-lime-200',
  third_party_js: 'border-yellow-500/30 bg-yellow-500/10 text-yellow-200',
  cloud_hint: 'border-teal-500/30 bg-teal-500/10 text-teal-200',
  ai_target: 'border-purple-500/30 bg-purple-500/10 text-purple-200',
  mcp_tool: 'border-fuchsia-500/30 bg-fuchsia-500/10 text-fuchsia-200',
  scan: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200',
  finding: 'border-orange-500/30 bg-orange-500/10 text-orange-200',
  finding_group: 'border-orange-500/30 bg-orange-500/10 text-orange-200',
  vendor: 'border-amber-500/30 bg-amber-500/10 text-amber-200',
  attack_chain: 'border-red-500/30 bg-red-500/10 text-red-200',
}

// Per-node-type curated detail fields: [meta key, label].
const DETAIL_FIELDS: Partial<Record<ExposureNodeType, Array<[string, string]>>> = {
  web_target: [
    ['last_grade', 'Grade'],
    ['last_score', 'Score'],
    ['active_findings_count', 'Active findings'],
    ['total_scans', 'Total scans'],
    ['discovery_source', 'Discovered via'],
  ],
  ai_target: [
    ['target_type', 'Surface type'],
    ['blast_radius_tier', 'Blast radius'],
    ['blast_radius_score', 'Blast score'],
    ['production_mode', 'Production'],
    ['method', 'Method'],
    ['last_scanned_at', 'Last scanned'],
  ],
  model_artifact: [
    ['format_posture', 'Format posture'],
    ['signature_present', 'Signature'],
    ['provenance_present', 'Provenance'],
    ['expected_hash_present', 'Expected hash'],
    ['deployment_approved', 'Deploy approved'],
  ],
  finding: [
    ['severity', 'Severity'],
    ['status', 'Status'],
    ['tool', 'Tool'],
    ['cvss_score', 'CVSS'],
    ['last_verification_verdict', 'Verdict'],
  ],
  attack_chain: [
    ['chain_type', 'Chain type'],
    ['confidence', 'Confidence'],
    ['completeness', 'Completeness'],
    ['business_impact', 'Business impact'],
  ],
  vendor: [
    ['risk_level', 'Risk level'],
    ['risk_score', 'Risk score'],
  ],
  api_surface: [
    ['source', 'Source'],
    ['endpoint_count', 'Endpoints'],
    ['version', 'Version'],
  ],
}

function nodeIcon(type: ExposureNodeType) {
  const className = 'h-4 w-4'
  if (type === 'domain') return <Globe2 className={className} />
  if (type === 'web_target') return <Target className={className} />
  if (type === 'model_artifact') return <Boxes className={className} />
  if (type === 'endpoint') return <Route className={className} />
  if (type === 'api_surface') return <Code2 className={className} />
  if (type === 'auth_role') return <KeyRound className={className} />
  if (type === 'third_party_js') return <Code2 className={className} />
  if (type === 'cloud_hint') return <Cloud className={className} />
  if (type === 'ai_target') return <Bot className={className} />
  if (type === 'mcp_tool') return <Boxes className={className} />
  if (type === 'scan') return <Search className={className} />
  if (type === 'finding') return <ShieldAlert className={className} />
  if (type === 'finding_group') return <Layers className={className} />
  if (type === 'vendor') return <Boxes className={className} />
  return <GitBranch className={className} />
}

function severityClass(severity?: string | null) {
  if (!severity) return 'bg-gray-700 text-gray-300'
  return SEVERITY_BADGE_STYLES[severity as SeverityLevel] ?? SEVERITY_BADGE_STYLES.info
}

function formatMetaValue(value: unknown): string {
  if (value === true) return 'Yes'
  if (value === false) return 'No'
  if (typeof value === 'string' && value.length > 40) return `${value.slice(0, 39)}…`
  return String(value)
}

function NodePill({ node, onFocus }: { node: ExposureNode; onFocus?: (node: ExposureNode) => void }) {
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

  if (onFocus) {
    return (
      <button
        type="button"
        onClick={() => onFocus(node)}
        className="block w-full text-left rounded-lg focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
      >
        {body}
      </button>
    )
  }
  return body
}

function Panel({ className = '', children }: { className?: string; children: React.ReactNode }) {
  return <div className={`${styles.module} ${styles.corners} ${className}`}>{children}</div>
}

function StatPanel({
  label,
  value,
  icon,
  alert = false,
}: {
  label: string
  value: string | number
  icon: React.ReactNode
  alert?: boolean
}) {
  return (
    <Panel className="p-4">
      <div className="flex items-start justify-between">
        <div>
          <div className={styles.statLabel}>{label}</div>
          <div className={`${styles.statValue} ${alert ? styles.statAlert : ''}`}>{value}</div>
        </div>
        <div className="p-1 text-teal-200/40">{icon}</div>
      </div>
    </Panel>
  )
}

function RelationshipRow({ edge, byId, onFocus }: { edge: ExposureEdge; byId: Map<string, ExposureNode>; onFocus: (node: ExposureNode) => void }) {
  const source = byId.get(edge.source)
  const target = byId.get(edge.target)
  if (!source || !target) return null
  return (
    <div className="grid gap-3 border-b border-gray-800 px-4 py-3 last:border-b-0 lg:grid-cols-[minmax(0,1fr)_150px_minmax(0,1fr)]">
      <NodePill node={source} onFocus={onFocus} />
      <div className="flex items-center justify-start lg:justify-center">
        <span className="rounded-full border border-gray-700 bg-gray-950 px-3 py-1 text-xs text-gray-300">{edge.label}</span>
      </div>
      <NodePill node={target} onFocus={onFocus} />
    </div>
  )
}

function NodeDetailPanel({
  node,
  neighbors,
  onFocus,
  onClear,
}: {
  node: ExposureNode
  neighbors: Array<{ node: ExposureNode; label: string }>
  onFocus: (node: ExposureNode) => void
  onClear: () => void
}) {
  const fields = (DETAIL_FIELDS[node.type] || []).filter(([key]) => {
    const v = node.meta?.[key]
    return v !== undefined && v !== null && v !== ''
  })
  const members = node.type === 'finding_group' && Array.isArray(node.meta?.members)
    ? (node.meta.members as Array<{ id: string; title: string; severity?: string | null; status?: string | null; href?: string | null }>)
    : []

  return (
    <Panel>
      <div className={`flex items-center justify-between gap-2 p-4 ${styles.moduleHeader}`}>
        <h2 className={`${styles.displayTitle} text-sm text-white`}>Selected node</h2>
        <button
          type="button"
          onClick={onClear}
          aria-label="Clear selection"
          className="rounded p-1 text-gray-400 hover:bg-gray-800 hover:text-gray-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </button>
      </div>
      <div className="space-y-4 p-4">
        <div>
          <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-gray-500">
            <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ backgroundColor: NODE_HEX[node.type] || '#9ca3af' }} aria-hidden="true" />
            {NODE_SINGULAR[node.type] || node.type}
          </div>
          <div className="mt-1 break-words text-sm font-medium text-white">{node.label}</div>
          {node.subtitle && <div className="mt-0.5 break-words text-xs text-gray-500">{node.subtitle}</div>}
          <div className="mt-2 flex flex-wrap items-center gap-2">
            {node.severity && (
              <span className={`rounded px-2 py-0.5 text-[10px] uppercase ${severityClass(node.severity)}`}>{node.severity}</span>
            )}
            {node.status && <span className="rounded bg-gray-800 px-2 py-0.5 text-[10px] text-gray-300">{node.status}</span>}
            {node.href && (
              <Link
                href={node.href}
                className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] text-blue-400 hover:text-blue-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
              >
                Open <ExternalLink className="h-3 w-3" aria-hidden="true" />
              </Link>
            )}
          </div>
        </div>

        {fields.length > 0 && (
          <dl className="grid grid-cols-2 gap-x-3 gap-y-2">
            {fields.map(([key, label]) => (
              <div key={key} className="min-w-0">
                <dt className="text-[11px] text-gray-500">{label}</dt>
                <dd className="truncate text-xs text-gray-200">{formatMetaValue(node.meta[key])}</dd>
              </div>
            ))}
          </dl>
        )}

        {members.length > 0 && (
          <div>
            <div className="mb-2 text-xs uppercase tracking-wide text-gray-500">Findings in this group ({members.length})</div>
            <div className="max-h-64 space-y-1.5 overflow-auto pr-1">
              {members.map((m) => (
                <Link
                  key={m.id}
                  href={m.href || '#'}
                  className="flex items-center justify-between gap-2 rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 hover:bg-gray-800/50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                >
                  <span className="truncate text-xs text-gray-200">{m.title}</span>
                  {m.severity && (
                    <span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] uppercase ${severityClass(m.severity)}`}>{m.severity}</span>
                  )}
                </Link>
              ))}
            </div>
          </div>
        )}

        <div>
          <div className="mb-2 text-xs uppercase tracking-wide text-gray-500">
            Connected ({neighbors.length})
          </div>
          {neighbors.length === 0 ? (
            <p className="text-xs text-gray-600">No connected nodes at this depth.</p>
          ) : (
            <div className="max-h-72 space-y-2 overflow-auto pr-1">
              {neighbors.map(({ node: nb, label }) => (
                <div key={`${nb.id}-${label}`}>
                  <div className="mb-0.5 text-[10px] uppercase tracking-wide text-gray-600">{label}</div>
                  <NodePill node={nb} onFocus={onFocus} />
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </Panel>
  )
}

function Legend() {
  const items: ExposureNodeType[] = ['domain', 'web_target', 'ai_target', 'model_artifact', 'api_surface', 'finding', 'attack_chain', 'vendor']
  return (
    <div className="space-y-2 px-4 py-3 text-xs text-gray-400">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
        {items.map((type) => (
          <span key={type} className="inline-flex items-center gap-1.5">
            <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ backgroundColor: NODE_HEX[type] }} aria-hidden="true" />
            {NODE_SINGULAR[type] || type}
          </span>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-gray-600">
        <span>Larger = more findings</span>
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full ring-2 ring-red-500" aria-hidden="true" />
          Ring = severity
        </span>
        <span className="inline-flex items-center gap-1.5">
          <Layers className="h-3 w-3" aria-hidden="true" /> Numbered = grouped findings
        </span>
        <span className="ml-auto">Hover for label · scroll to zoom · click to focus</span>
      </div>
    </div>
  )
}

export default function ExposurePage() {
  const [graph, setGraph] = useState<ExposureGraph | null>(null)
  const [domains, setDomains] = useState<string[]>([])
  const [domain, setDomain] = useState('')
  const [includeResolved, setIncludeResolved] = useState(false)
  const [view, setView] = useState<'graph' | 'list'>('graph')
  const [focusId, setFocusId] = useState<string | null>(null)
  const [selectedNode, setSelectedNode] = useState<ExposureNode | null>(null)
  const [depth, setDepth] = useState(1)
  const [selectedType, setSelectedType] = useState('')
  const [highlightType, setHighlightType] = useState<string | null>(null)
  const [listPage, setListPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [refetching, setRefetching] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [searchIndex, setSearchIndex] = useState<ExposureSearchNode[]>([])
  const [searchQuery, setSearchQuery] = useState('')
  const [searchOpen, setSearchOpen] = useState(false)
  const hasLoadedRef = useRef(false)

  async function loadGraph() {
    if (hasLoadedRef.current) setRefetching(true)
    else setLoading(true)
    try {
      const payload = await getExposureGraph({
        root_domain: domain || undefined,
        includeResolved,
        limitFindings: 250,
        limitScans: 150,
        focus: focusId,
        depth,
      })
      setGraph(payload)
      setError(null)
      hasLoadedRef.current = true
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load exposure graph')
    } finally {
      setLoading(false)
      setRefetching(false)
    }
  }

  useEffect(() => {
    getDomains().then((payload) => setDomains(payload.domains || [])).catch(() => {})
  }, [])

  // Search index: refetched whenever the domain/resolved scope changes.
  useEffect(() => {
    getExposureNodes({ root_domain: domain || undefined, includeResolved })
      .then((payload) => setSearchIndex(payload.nodes || []))
      .catch(() => setSearchIndex([]))
  }, [domain, includeResolved])

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    loadGraph()
  }, [domain, includeResolved, focusId, depth])

  // Filters that change the domain/scope reset the focus back to the overview.
  function changeScope(next: () => void) {
    setFocusId(null)
    setSelectedNode(null)
    setHighlightType(null)
    next()
  }

  function handleFocus(node: ExposureNode) {
    setSelectedNode(node)
    setHighlightType(null)
    // Grouped findings are synthetic (not addressable by the backend), so show
    // their detail without re-focusing the graph.
    if (node.type === 'finding_group') return
    setFocusId(node.id)
    setView('graph')
  }

  function focusById(id: string) {
    setFocusId(id)
    setSelectedNode(null)
    setHighlightType(null)
    setView('graph')
  }

  function handleClear() {
    setSelectedNode(null)
    setFocusId(null)
  }

  const searchMatches = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q) return []
    return searchIndex.filter((n) => n.label.toLowerCase().includes(q)).slice(0, 12)
  }, [searchQuery, searchIndex])

  const byId = useMemo(() => new Map((graph?.nodes || []).map((node) => [node.id, node])), [graph])
  const summary = graph?.summary
  const nodeTypeCounts = summary?.node_type_counts || {}
  const metrics = summary?.metrics
  const hotspots = summary?.hotspots || []

  const neighbors = useMemo(() => {
    if (!focusId || !graph) return []
    const seen = new Set<string>()
    const result: Array<{ node: ExposureNode; label: string }> = []
    for (const edge of graph.edges) {
      let otherId: string | null = null
      if (edge.source === focusId) otherId = edge.target
      else if (edge.target === focusId) otherId = edge.source
      if (!otherId || seen.has(otherId)) continue
      const other = byId.get(otherId)
      if (!other) continue
      seen.add(otherId)
      result.push({ node: other, label: edge.label })
    }
    return result.sort(
      (a, b) =>
        (b.node.severity ? 1 : 0) - (a.node.severity ? 1 : 0) ||
        (Number(b.node.meta?.active_findings_count || 0) - Number(a.node.meta?.active_findings_count || 0))
    )
  }, [focusId, graph, byId])

  const SEVERITY_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
  const listEdges = useMemo(() => {
    const edges = graph?.edges || []
    const filtered = selectedType
      ? edges.filter((edge) => byId.get(edge.source)?.type === selectedType || byId.get(edge.target)?.type === selectedType)
      : edges
    return [...filtered].sort((a, b) => (SEVERITY_RANK[String(b.severity || '')] || 0) - (SEVERITY_RANK[String(a.severity || '')] || 0))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph, selectedType, byId])

  const listTotalPages = Math.max(1, Math.ceil(listEdges.length / LIST_PAGE_SIZE))
  const listPageClamped = Math.min(listPage, listTotalPages)
  const visibleListEdges = listEdges.slice((listPageClamped - 1) * LIST_PAGE_SIZE, listPageClamped * LIST_PAGE_SIZE)

  useEffect(() => {
    setListPage(1)
  }, [selectedType, focusId, domain])

  const graphIsEmpty = !loading && (graph?.nodes?.length ?? 0) === 0
  const renderedNodes = summary?.rendered_node_count ?? graph?.nodes?.length ?? 0
  const totalNodes = summary?.node_count ?? renderedNodes

  return (
    <div className={`${displayFont.variable} ${monoFont.variable} ${styles.page}`}>
      <div className={styles.pageGlow} aria-hidden="true" />
      <div className={`${styles.content} space-y-6`}>
      <div className={`flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between ${styles.rise} ${styles.d1}`}>
        <div>
          <div className="flex items-center gap-2.5">
            <span className={styles.liveDot} aria-hidden="true" />
            <span className={styles.kicker}>Attack surface · live</span>
          </div>
          <h1 className={`${styles.displayTitle} mt-1.5 text-2xl font-bold text-white`}>Exposure Graph</h1>
          <p className="mt-1 text-sm text-gray-400">
            Connected view of targets, AI surfaces, findings, vendors, and attack chains. Click a node to focus its neighborhood.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" aria-hidden="true" />
            <input
              type="text"
              value={searchQuery}
              onChange={(event) => { setSearchQuery(event.target.value); setSearchOpen(true) }}
              onFocus={() => setSearchOpen(true)}
              onBlur={() => setTimeout(() => setSearchOpen(false), 150)}
              placeholder="Search assets & findings…"
              aria-label="Search exposure nodes"
              className={`w-56 py-2 pl-8 pr-3 text-sm text-white placeholder:text-gray-500 ${styles.input}`}
            />
            {searchOpen && searchMatches.length > 0 && (
              <div className={`absolute z-20 mt-1 max-h-72 w-72 overflow-auto py-1 shadow-xl ${styles.input}`}>
                {searchMatches.map((match) => (
                  <button
                    key={match.id}
                    type="button"
                    onMouseDown={(event) => { event.preventDefault(); focusById(match.id); setSearchQuery(''); setSearchOpen(false) }}
                    className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-sm hover:bg-gray-800 focus:outline-none focus-visible:bg-gray-800"
                  >
                    <span className="inline-block h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: NODE_HEX[match.type] || '#9ca3af' }} aria-hidden="true" />
                    <span className="truncate text-gray-200">{match.label}</span>
                    <span className="ml-auto shrink-0 text-[10px] uppercase tracking-wide text-gray-500">{NODE_SINGULAR[match.type] || match.type}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
          <div className={`inline-flex p-0.5 ${styles.input}`} role="tablist" aria-label="View mode">
            {(['graph', 'list'] as const).map((mode) => (
              <button
                key={mode}
                type="button"
                role="tab"
                aria-selected={view === mode}
                onClick={() => setView(mode)}
                className={`rounded-md px-3 py-1.5 text-sm capitalize focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                  view === mode ? 'bg-teal-500/20 text-teal-200' : 'text-gray-300 hover:text-white'
                }`}
              >
                {mode}
              </button>
            ))}
          </div>
          <select
            value={domain}
            onChange={(event) => changeScope(() => setDomain(event.target.value))}
            aria-label="Filter by domain"
            className={`px-3 py-2 text-sm text-white ${styles.input}`}
          >
            <option value="">All domains</option>
            {domains.map((item) => (
              <option key={item} value={item}>{item}</option>
            ))}
          </select>
          <label className={`flex items-center gap-2 px-3 py-2 text-sm text-gray-300 ${styles.input}`}>
            <input
              type="checkbox"
              checked={includeResolved}
              onChange={(event) => changeScope(() => setIncludeResolved(event.target.checked))}
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

      <div className={`grid gap-4 md:grid-cols-2 xl:grid-cols-4 ${styles.rise} ${styles.d2}`}>
        <StatPanel label="Assets" value={metrics?.asset_count ?? '--'} icon={<Layers className="h-5 w-5" />} />
        <StatPanel
          label="Active Critical / High"
          value={metrics ? `${metrics.active_critical} / ${metrics.active_high}` : '--'}
          icon={<AlertTriangle className="h-5 w-5" />}
          alert={Boolean(metrics && metrics.active_critical > 0)}
        />
        <StatPanel label="Attack Chains" value={metrics?.attack_chains ?? '--'} icon={<GitBranch className="h-5 w-5" />} />
        <StatPanel label="AI Surfaces" value={metrics?.ai_surfaces ?? nodeTypeCounts.ai_target ?? '--'} icon={<Bot className="h-5 w-5" />} />
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.4fr_0.6fr]">
        <Panel className={`overflow-hidden ${styles.rise} ${styles.d4}`}>
          <div className={`flex flex-col gap-3 p-4 md:flex-row md:items-center md:justify-between ${styles.moduleHeader}`}>
            <div>
              <h2 className={`${styles.displayTitle} text-sm text-white`}>{focusId ? 'Focused neighborhood' : 'Risk overview'}</h2>
              <p className="mt-1 text-sm text-gray-500">
                {view === 'graph'
                  ? focusId
                    ? `${renderedNodes} connected nodes${summary?.truncated ? ' · riskiest shown' : ''}`
                    : `Showing the ${renderedNodes} riskiest of ${totalNodes} nodes · search or click to explore more`
                  : `${listEdges.length} relationship${listEdges.length === 1 ? '' : 's'}`}
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              {focusId && (
                <button
                  type="button"
                  onClick={handleClear}
                  className="inline-flex items-center gap-1 rounded-lg border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                >
                  <ArrowLeft className="h-3.5 w-3.5" aria-hidden="true" />
                  Back to overview
                </button>
              )}
              {focusId && (
                <select
                  value={depth}
                  onChange={(event) => setDepth(Number(event.target.value))}
                  aria-label="Neighborhood depth"
                  className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
                >
                  <option value={1}>Depth 1</option>
                  <option value={2}>Depth 2</option>
                  <option value={3}>Depth 3</option>
                </select>
              )}
              {view === 'list' && (
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
              )}
            </div>
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
          ) : view === 'graph' ? (
            <div>
              <div className={`relative h-[560px] w-full ${styles.graphBackdrop}`}>
                <div className={styles.radarRings} aria-hidden="true" />
                <div className={styles.sweep} aria-hidden="true" />
                <ExposureGraphCanvas
                  nodes={graph?.nodes || []}
                  edges={graph?.edges || []}
                  focusId={focusId}
                  highlightType={highlightType}
                  onNodeClick={handleFocus}
                  height={560}
                />
                <div className={styles.grain} aria-hidden="true" />
                {refetching && (
                  <div className="pointer-events-none absolute right-3 top-3 inline-flex items-center gap-2 rounded-full border border-gray-700 bg-gray-900/90 px-3 py-1 text-xs text-gray-300">
                    <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
                    Updating…
                  </div>
                )}
                {highlightType && (
                  <button
                    type="button"
                    onClick={() => setHighlightType(null)}
                    className="absolute left-3 top-3 inline-flex items-center gap-1.5 rounded-full border border-blue-500/40 bg-blue-500/10 px-3 py-1 text-xs text-blue-300 hover:bg-blue-500/20 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                  >
                    Highlighting {NODE_LABELS[highlightType] || highlightType}
                    <X className="h-3 w-3" aria-hidden="true" />
                  </button>
                )}
              </div>
              <div className="border-t border-gray-800">
                <Legend />
              </div>
            </div>
          ) : visibleListEdges.length === 0 ? (
            <div className="p-4">
              <EmptyState message="No relationships found." hint="Try a different node type filter." />
            </div>
          ) : (
            <div>
              {visibleListEdges.map((edge, index) => (
                <RelationshipRow key={`${edge.source}-${edge.target}-${edge.type}-${index}`} edge={edge} byId={byId} onFocus={handleFocus} />
              ))}
              {listTotalPages > 1 && (
                <div className="flex items-center justify-between border-t border-gray-800 px-4 py-3">
                  <span className="text-xs text-gray-500">Page {listPageClamped} of {listTotalPages}</span>
                  <div className="flex gap-2">
                    <Button variant="secondary" size="sm" disabled={listPageClamped <= 1} onClick={() => setListPage((p) => Math.max(1, p - 1))}>
                      Previous
                    </Button>
                    <Button variant="secondary" size="sm" disabled={listPageClamped >= listTotalPages} onClick={() => setListPage((p) => p + 1)}>
                      Next
                    </Button>
                  </div>
                </div>
              )}
            </div>
          )}
        </Panel>

        <div className="space-y-6">
          {selectedNode ? (
            <NodeDetailPanel node={selectedNode} neighbors={neighbors} onFocus={handleFocus} onClear={handleClear} />
          ) : (
            <>
              <Panel className={`${styles.rise} ${styles.d5}`}>
                <div className={`p-4 ${styles.moduleHeader}`}>
                  <h2 className={`${styles.displayTitle} text-sm text-white`}>Priority targets</h2>
                  <p className="mt-1 text-xs text-gray-500">Riskiest assets — click to explore</p>
                </div>
                <div className="divide-y divide-gray-800/60">
                  {hotspots.length === 0 ? (
                    <div className="p-4 text-sm text-gray-500">No active high-risk nodes.</div>
                  ) : (
                    hotspots.map((node, index) => (
                      <div key={node.id} className="flex gap-3 p-4">
                        <span className={`${styles.rank} pt-2.5`}>{String(index + 1).padStart(2, '0')}</span>
                        <div className="min-w-0 flex-1">
                          <NodePill node={node} onFocus={handleFocus} />
                          <div className="mt-2 flex flex-wrap gap-2 text-xs text-gray-500">
                            {node.meta?.active_findings_count ? <span>{String(node.meta.active_findings_count)} active findings</span> : null}
                            {node.meta?.last_grade ? <span>Grade {String(node.meta.last_grade)}</span> : null}
                            {node.meta?.blast_radius_tier ? <span>{String(node.meta.blast_radius_tier)} blast</span> : null}
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </Panel>

              <Panel>
                <div className={`p-4 ${styles.moduleHeader}`}>
                  <h2 className={`${styles.displayTitle} text-sm text-white`}>Inventory</h2>
                  <p className="mt-1 text-xs text-gray-500">Click a type to highlight it in the graph</p>
                </div>
                <div className="grid grid-cols-2 gap-3 p-4">
                  {Object.entries(NODE_LABELS)
                    .filter(([type]) => type !== 'finding_group')
                    .map(([type, label]) => {
                      const active = highlightType === type
                      return (
                        <button
                          key={type}
                          type="button"
                          aria-pressed={active}
                          onClick={() => { setHighlightType(active ? null : type); setView('graph') }}
                          className={`rounded-lg border px-3 py-2 text-left transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                            active ? 'border-blue-500 bg-blue-500/10' : 'border-gray-800 bg-gray-950 hover:border-gray-700'
                          }`}
                        >
                          <div className="flex items-center gap-1.5 text-xs text-gray-500">
                            <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: NODE_HEX[type] || '#9ca3af' }} aria-hidden="true" />
                            {label}
                          </div>
                          <div className="mt-1 text-lg font-semibold text-white">{nodeTypeCounts[type] || 0}</div>
                        </button>
                      )
                    })}
                </div>
              </Panel>
            </>
          )}
        </div>
      </div>
      </div>
    </div>
  )
}
