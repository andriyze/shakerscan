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
  ListTree,
  Loader2,
  Package,
  Radar,
  RefreshCw,
  Route,
  Search,
  ShieldAlert,
  Target,
  X,
} from 'lucide-react'
import {
  getDomains,
  getExposureAssets,
  getExposureAttackPaths,
  getExposureGraph,
  getExposureNodes,
  scanTarget,
  type ExposureAsset,
  type ExposureAssetMetrics,
  type ExposureAttackPath,
  type ExposureGraph,
  type ExposureNode,
  type ExposureNodeType,
  type ExposureSearchNode,
} from '@/lib/api'
import { SEVERITY_BADGE_STYLES, type SeverityLevel } from '@/lib/constants'
import { Button, CardSkeleton, EmptyState, ErrorState, useToast } from '@/components/ui'
import { ExposureGraph as ExposureGraphCanvas, NODE_HEX } from '@/components/ExposureGraph'
import { TriageTable } from './TriageTable'
import { AttackPaths } from './AttackPaths'
import styles from './exposure.module.css'

type Lens = 'triage' | 'map' | 'paths'

const LENSES: Array<{ value: Lens; label: string; icon: typeof ListTree }> = [
  { value: 'triage', label: 'Triage', icon: ListTree },
  { value: 'map', label: 'Map', icon: Radar },
  { value: 'paths', label: 'Attack paths', icon: GitBranch },
]

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

const NODE_LABELS: Record<string, string> = {
  domain: 'Domains',
  web_target: 'Web targets',
  model_artifact: 'Model artifacts',
  model_supply_chain: 'Supply chain',
  endpoint: 'Endpoints',
  api_surface: 'APIs',
  auth_role: 'Auth roles',
  third_party_js: 'Third-party JS',
  cloud_hint: 'Cloud hints',
  ai_target: 'AI surfaces',
  mcp_tool: 'MCP tools',
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
  model_supply_chain: 'Model supply chain',
  vendor: 'Vendor',
  attack_chain: 'Attack chain',
}

const NODE_STYLES: Record<string, string> = {
  domain: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-200',
  web_target: 'border-blue-500/30 bg-blue-500/10 text-blue-200',
  model_artifact: 'border-teal-500/30 bg-teal-500/10 text-teal-200',
  model_supply_chain: 'border-slate-400/30 bg-slate-400/10 text-slate-200',
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
    ['origin', 'Origin'],
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
  if (type === 'model_supply_chain') return <Package className={className} />
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

function PostureSummary({ metrics }: { metrics: ExposureAssetMetrics | null }) {
  const items = [
    { label: 'Web', value: metrics?.web_targets ?? 0, tone: 'text-blue-300' },
    { label: 'AI', value: metrics?.ai_surfaces ?? 0, tone: 'text-purple-300' },
    { label: 'Models', value: metrics?.model_artifacts ?? 0, tone: 'text-teal-300' },
    { label: 'Public', value: metrics?.public_assets ?? 0, tone: 'text-cyan-300' },
    { label: 'Internal', value: metrics?.internal_assets ?? 0, tone: 'text-slate-300' },
    { label: 'Unscanned', value: metrics?.unscanned_assets ?? 0, tone: 'text-red-300' },
    { label: 'Stale', value: metrics?.stale_assets ?? 0, tone: 'text-yellow-300' },
    { label: 'Incomplete', value: metrics?.incomplete_scans ?? 0, tone: 'text-amber-300' },
    { label: 'Prod AI', value: metrics?.prod_ai_surfaces ?? 0, tone: 'text-fuchsia-300' },
    { label: 'High blast AI', value: metrics?.high_blast_ai_surfaces ?? 0, tone: 'text-orange-300' },
  ]

  return (
    <Panel className="p-3">
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
        <div className="mr-1 shrink-0">
          <div className={`${styles.displayTitle} text-xs uppercase tracking-wide text-gray-400`}>Exposure posture</div>
          <div className="text-[11px] text-gray-600">{metrics?.needs_action ?? 0} assets need action</div>
        </div>
        {items.map((item) => (
          <div key={item.label} className="min-w-0">
            <div className={`text-sm font-semibold ${item.tone}`}>{item.value}</div>
            <div className="text-[10px] uppercase tracking-wide text-gray-600">{item.label}</div>
          </div>
        ))}
      </div>
    </Panel>
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
  const [lens, setLens] = useState<Lens>('triage')
  const [focusId, setFocusId] = useState<string | null>(null)
  const [selectedNode, setSelectedNode] = useState<ExposureNode | null>(null)
  const [depth, setDepth] = useState(1)
  const [showEndpoints, setShowEndpoints] = useState(false)
  const [highlightType, setHighlightType] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [refetching, setRefetching] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [searchIndex, setSearchIndex] = useState<ExposureSearchNode[]>([])
  const [searchQuery, setSearchQuery] = useState('')
  const [searchOpen, setSearchOpen] = useState(false)
  const hasLoadedRef = useRef(false)

  // Triage lens
  const [assets, setAssets] = useState<ExposureAsset[]>([])
  const [assetMetrics, setAssetMetrics] = useState<ExposureAssetMetrics | null>(null)
  const [assetsLoading, setAssetsLoading] = useState(true)
  const [assetsError, setAssetsError] = useState<string | null>(null)
  const [newCount, setNewCount] = useState(0)
  const [scanningIds, setScanningIds] = useState<Set<string>>(new Set())
  const graphKeyRef = useRef<string | null>(null)
  const pathsKeyRef = useRef<string | null>(null)

  // Attack paths lens
  const [paths, setPaths] = useState<ExposureAttackPath[]>([])
  const [pathsLoading, setPathsLoading] = useState(true)
  const [pathsError, setPathsError] = useState<string | null>(null)

  const toast = useToast()

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
        includeEndpoints: Boolean(focusId) && showEndpoints,
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

  async function loadAssets() {
    setAssetsLoading(true)
    try {
      const res = await getExposureAssets({ root_domain: domain || undefined })
      setAssets(res.assets || [])
      setAssetMetrics(res.metrics || null)
      setNewCount(res.new_count || 0)
      setAssetsError(null)
    } catch (err) {
      setAssetsError(err instanceof Error ? err.message : 'Failed to load assets')
    } finally {
      setAssetsLoading(false)
    }
  }

  async function loadPaths() {
    setPathsLoading(true)
    try {
      const res = await getExposureAttackPaths({ root_domain: domain || undefined })
      setPaths(res.attack_paths || [])
      setPathsError(null)
    } catch (err) {
      setPathsError(err instanceof Error ? err.message : 'Failed to load attack paths')
    } finally {
      setPathsLoading(false)
    }
  }

  useEffect(() => {
    getDomains().then((payload) => setDomains(payload.domains || [])).catch(() => {})
  }, [])

  // Assets power the default triage lens and the "new" badge; load up front.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    loadAssets()
  }, [domain])

  // Attack paths load lazily the first time that lens is opened, then once per
  // scope change — not on every switch back to the lens.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (lens !== 'paths') return
    if (pathsKeyRef.current === domain) return
    pathsKeyRef.current = domain
    loadPaths()
  }, [lens, domain])

  // Search index: refetched whenever the domain/resolved scope changes.
  useEffect(() => {
    getExposureNodes({ root_domain: domain || undefined, includeResolved })
      .then((payload) => setSearchIndex(payload.nodes || []))
      .catch(() => setSearchIndex([]))
  }, [domain, includeResolved])

  // The graph is only needed for the Map lens — load it lazily when that lens
  // is active, and skip redundant reloads when scope/focus haven't changed.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (lens !== 'map') return
    const key = `${domain}|${includeResolved}|${focusId}|${depth}|${showEndpoints}`
    if (graphKeyRef.current === key) return
    graphKeyRef.current = key
    loadGraph()
  }, [lens, domain, includeResolved, focusId, depth, showEndpoints])

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
    setLens('map')
  }

  function focusById(id: string) {
    setFocusId(id)
    setSelectedNode(null)
    setHighlightType(null)
    setLens('map')
  }

  function handleClear() {
    setSelectedNode(null)
    setFocusId(null)
    setShowEndpoints(false)
  }

  async function handleScan(asset: ExposureAsset) {
    setScanningIds((prev) => new Set(prev).add(asset.id))
    try {
      const res = await scanTarget(asset.id, { scan_type: 'quick' })
      const scanId = res?.scan_id || res?.id
      toast.success('Quick scan started', scanId ? { link: { href: `/scans/${scanId}`, label: 'View scan' } } : undefined)
    } catch {
      toast.error(`Failed to start scan for ${asset.label}`)
    } finally {
      setScanningIds((prev) => {
        const next = new Set(prev)
        next.delete(asset.id)
        return next
      })
    }
  }

  function refreshActiveLens() {
    if (lens === 'triage') loadAssets()
    else if (lens === 'paths') loadPaths()
    else loadGraph()
  }

  const searchMatches = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q) return []
    return searchIndex.filter((n) => n.label.toLowerCase().includes(q)).slice(0, 12)
  }, [searchQuery, searchIndex])

  const byId = useMemo(() => new Map((graph?.nodes || []).map((node) => [node.id, node])), [graph])
  const summary = graph?.summary
  const nodeTypeCounts = summary?.node_type_counts || {}
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

  const graphIsEmpty = !loading && (graph?.nodes?.length ?? 0) === 0
  const renderedNodes = summary?.rendered_node_count ?? graph?.nodes?.length ?? 0
  const totalNodes = summary?.node_count ?? renderedNodes
  const lensBusy = lens === 'triage' ? assetsLoading : lens === 'paths' ? pathsLoading : loading || refetching

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
          <h1 className={`${styles.displayTitle} mt-1.5 text-2xl font-bold text-white`}>Attack Surface</h1>
          <p className="mt-1 text-sm text-gray-400">
            {lens === 'triage' && 'Risk-ranked inventory of every asset — scan, triage, and drill in.'}
            {lens === 'map' && 'Connected view — click a node to explore its blast radius.'}
            {lens === 'paths' && 'Correlated exploit paths across your attack surface.'}
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
          <Button onClick={refreshActiveLens} disabled={lensBusy}>
            <RefreshCw className={`h-4 w-4 ${lensBusy ? 'animate-spin' : ''}`} aria-hidden="true" />
            Refresh
          </Button>
        </div>
      </div>

      <div className={`flex flex-wrap items-center gap-1 ${styles.rise} ${styles.d1}`} role="tablist" aria-label="Exposure lens">
        {LENSES.map((l) => (
          <button
            key={l.value}
            type="button"
            role="tab"
            id={`lens-tab-${l.value}`}
            aria-selected={lens === l.value}
            aria-controls={`lens-panel-${l.value}`}
            onClick={() => setLens(l.value)}
            className={`inline-flex items-center gap-2 rounded-md px-3.5 py-2 text-sm transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
              lens === l.value ? 'bg-teal-500/15 text-teal-200' : 'text-gray-400 hover:bg-gray-800/60 hover:text-white'
            }`}
          >
            <l.icon className="h-4 w-4" aria-hidden="true" />
            {l.label}
            {l.value === 'triage' && newCount > 0 && (
              <span className="rounded-full bg-teal-400/20 px-1.5 py-0.5 text-[10px] font-semibold text-teal-200">{newCount} new</span>
            )}
          </button>
        ))}
      </div>

      <div className={`grid gap-4 md:grid-cols-2 xl:grid-cols-4 ${styles.rise} ${styles.d2}`}>
        <StatPanel label="Assets" value={assetMetrics?.asset_count ?? '--'} icon={<Layers className="h-5 w-5" />} />
        <StatPanel
          label="Need Action"
          value={assetMetrics?.needs_action ?? '--'}
          icon={<Radar className="h-5 w-5" />}
          alert={Boolean(assetMetrics && (assetMetrics.needs_action || 0) > 0)}
        />
        <StatPanel
          label="Active Critical"
          value={assetMetrics?.active_critical ?? '--'}
          icon={<AlertTriangle className="h-5 w-5" />}
          alert={Boolean(assetMetrics && assetMetrics.active_critical > 0)}
        />
        <StatPanel label="Active High" value={assetMetrics?.active_high ?? '--'} icon={<ShieldAlert className="h-5 w-5" />} />
      </div>

      <div className={`${styles.rise} ${styles.d2}`}>
        <PostureSummary metrics={assetMetrics} />
      </div>

      {lens === 'triage' && (
        <div role="tabpanel" id="lens-panel-triage" aria-labelledby="lens-tab-triage" className={`${styles.rise} ${styles.d3}`}>
          <TriageTable
            assets={assets}
            metrics={assetMetrics}
            loading={assetsLoading}
            error={assetsError}
            onRetry={loadAssets}
            onExplore={focusById}
            onScan={handleScan}
            scanningIds={scanningIds}
          />
        </div>
      )}

      {lens === 'paths' && (
        <div role="tabpanel" id="lens-panel-paths" aria-labelledby="lens-tab-paths" className={`${styles.rise} ${styles.d3}`}>
          <AttackPaths
            paths={paths}
            loading={pathsLoading}
            error={pathsError}
            onRetry={loadPaths}
            onExploreAsset={focusById}
          />
        </div>
      )}

      {lens === 'map' && (
      <div role="tabpanel" id="lens-panel-map" aria-labelledby="lens-tab-map" className="space-y-4">
      {error && <ErrorState message={error} onRetry={() => void loadGraph()} />}
      <div className="grid gap-6 xl:grid-cols-[1.4fr_0.6fr]">
        <Panel className={`overflow-hidden ${styles.rise} ${styles.d4}`}>
          <div className={`flex flex-col gap-3 p-4 md:flex-row md:items-center md:justify-between ${styles.moduleHeader}`}>
            <div>
              <h2 className={`${styles.displayTitle} text-sm text-white`}>{focusId ? 'Focused neighborhood' : 'Risk overview'}</h2>
              <p className="mt-1 text-sm text-gray-500">
                {focusId
                  ? `${renderedNodes} connected nodes${summary?.truncated ? ' · riskiest shown' : ''}`
                  : `Showing the ${renderedNodes} riskiest of ${totalNodes} nodes · search or click to explore more`}
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
                  className={`px-3 py-2 text-sm text-white ${styles.input}`}
                >
                  <option value={1}>Depth 1</option>
                  <option value={2}>Depth 2</option>
                  <option value={3}>Depth 3</option>
                </select>
              )}
              {focusId && (
                <label className={`flex items-center gap-2 px-3 py-2 text-xs text-gray-300 ${styles.input}`}>
                  <input
                    type="checkbox"
                    checked={showEndpoints}
                    onChange={(event) => setShowEndpoints(event.target.checked)}
                    className="rounded border-gray-700 bg-gray-800"
                  />
                  All endpoints
                </label>
              )}
              <label className={`flex items-center gap-2 px-3 py-2 text-xs text-gray-300 ${styles.input}`}>
                <input
                  type="checkbox"
                  checked={includeResolved}
                  onChange={(event) => changeScope(() => setIncludeResolved(event.target.checked))}
                  className="rounded border-gray-700 bg-gray-800"
                />
                Include resolved
              </label>
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
          ) : (
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
                          onClick={() => setHighlightType(active ? null : type)}
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
      )}
      </div>
    </div>
  )
}
