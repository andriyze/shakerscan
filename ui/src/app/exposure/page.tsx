'use client'

import { Suspense, useEffect, useMemo, useRef, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
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
  getAgentTwoTierFindings,
  getDomains,
  getExposureAssets,
  getExposureAttackPaths,
  getExposureGraph,
  getExposureNodes,
  rescanModelIntakeTarget,
  scanAITarget,
  scanTarget,
  type AgentTwoTierFindings,
  type AIEnvironment,
  type ExposureAsset,
  type ExposureAssetKind,
  type ExposureAssetMetrics,
  type ExposureAttackPath,
  type ExposureGraph,
  type ExposureNode,
  type ExposureNodeType,
  type ExposureSearchNode,
} from '@/lib/api'
import { SEVERITY_BADGE_STYLES, type SeverityLevel } from '@/lib/constants'
import { useUrlFilters } from '@/lib/useUrlFilters'
import { Button, CardSkeleton, EmptyState, ErrorState, useToast } from '@/components/ui'
import { ExposureGraph as ExposureGraphCanvas, NODE_HEX } from '@/components/ExposureGraph'
import { TriageTable, PriorityBadge, riskDot, isProductionAIAsset, postureMatches, POSTURE_FILTERS, type PostureFilter, type TriageSort } from './TriageTable'
import { ChangesStrip } from './ChangesStrip'
import { AttackPaths } from './AttackPaths'
import styles from './exposure.module.css'

type Lens = 'triage' | 'map' | 'paths'

const LENSES: Array<{ value: Lens; label: string; icon: typeof ListTree }> = [
  { value: 'triage', label: 'Triage', icon: ListTree },
  { value: 'map', label: 'Map', icon: Radar },
  { value: 'paths', label: 'Attack paths', icon: GitBranch },
]

const KIND_ABBR: Record<ExposureAssetKind, string> = { web: 'Web', ai: 'AI', model: 'Model' }

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

function PostureSummary({
  metrics,
  kind,
  posture,
  onKind,
  onPosture,
}: {
  metrics: ExposureAssetMetrics | null
  kind: 'all' | ExposureAssetKind
  posture: PostureFilter
  onKind: (kind: 'all' | ExposureAssetKind) => void
  onPosture: (posture: PostureFilter) => void
}) {
  // The single, canonical filter bar for the asset inventory — priority, kind,
  // and scan-hygiene posture in one place (TriageTable no longer repeats these).
  // Lead with priority; hide always-zero counts so the bar self-trims by dataset.
  const priorityItems: Array<{ label: string; value: number; tone: string; posture: PostureFilter }> = [
    { label: 'P1', value: metrics?.p1_count ?? 0, tone: 'text-red-300', posture: 'p1' },
    { label: 'P2', value: metrics?.p2_count ?? 0, tone: 'text-orange-300', posture: 'p2' },
    { label: 'P3', value: metrics?.p3_count ?? 0, tone: 'text-slate-300', posture: 'p3' },
  ]
  const kindItems: Array<{ label: string; value: number; tone: string; kind: ExposureAssetKind }> = [
    { label: 'Web', value: metrics?.web_targets ?? 0, tone: 'text-blue-300', kind: 'web' },
    { label: 'AI', value: metrics?.ai_surfaces ?? 0, tone: 'text-purple-300', kind: 'ai' },
    { label: 'Models', value: metrics?.model_artifacts ?? 0, tone: 'text-teal-300', kind: 'model' },
  ]
  // Scan-hygiene + internal exposure: each isolates an actionable, *narrow*
  // slice. "Public" is deliberately omitted — it selects ~two thirds of assets,
  // so it triages nothing; "Internal" is the rarer, more useful exposure cut.
  const postureItemsAll: Array<{ label: string; value: number; tone: string; posture: PostureFilter }> = [
    // Validation leads with the rare, actionable signal (assets with *proven*
    // risk) rather than the ~98%-noisy "needs verification" inverse.
    { label: 'Proven risk', value: metrics?.verified_assets ?? 0, tone: 'text-red-300', posture: 'verified' },
    { label: 'Verified', value: metrics?.investigator_verified_assets ?? 0, tone: 'text-emerald-300', posture: 'investigator_verified' },
    { label: 'Suspected', value: metrics?.investigator_suspected_assets ?? 0, tone: 'text-amber-300', posture: 'investigator_suspected' },
    // The high-impact slice of "needs verification" (unreviewed findings on an
    // asset that also has critical/high risk) — the raw inverse is ~all assets.
    { label: 'Unverified high', value: metrics?.unverified_high_assets ?? 0, tone: 'text-orange-300', posture: 'unverified_high' },
    { label: 'Unowned', value: metrics?.unowned_assets ?? 0, tone: 'text-amber-200', posture: 'unowned' },
    { label: 'Internal', value: metrics?.internal_assets ?? 0, tone: 'text-slate-300', posture: 'internal' },
    { label: 'Unscanned', value: metrics?.unscanned_assets ?? 0, tone: 'text-red-300', posture: 'unscanned' },
    { label: 'Failed', value: metrics?.failed_scans ?? 0, tone: 'text-red-200', posture: 'failed' },
    { label: 'Stale', value: metrics?.stale_assets ?? 0, tone: 'text-yellow-300', posture: 'stale' },
    { label: 'Incomplete', value: metrics?.incomplete_scans ?? 0, tone: 'text-amber-300', posture: 'incomplete' },
  ]
  const postureItems = postureItemsAll.filter((item) => item.value > 0)
  const filtered = kind !== 'all' || posture !== 'all'

  const tile = (key: string, label: string, value: number, tone: string, active: boolean, onClick: () => void) => (
    <button
      key={key}
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={`min-w-0 rounded px-2 py-1 text-left transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
        active ? 'bg-teal-500/15 ring-1 ring-teal-400/40' : 'hover:bg-gray-800/60'
      }`}
    >
      <div className={`text-sm font-semibold ${tone}`}>{value}</div>
      <div className="text-[10px] uppercase tracking-wide text-gray-600">{label}</div>
    </button>
  )

  return (
    <Panel className="p-3">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <div className="mr-1 shrink-0">
          <div className={`${styles.displayTitle} text-xs uppercase tracking-wide text-gray-400`}>Filter inventory</div>
          <div className="text-[11px] text-gray-600">{metrics?.needs_action ?? 0} of {metrics?.asset_count ?? 0} need action · click to filter</div>
        </div>
        {priorityItems.map((item) => tile(item.label, item.label, item.value, item.tone, posture === item.posture, () => onPosture(posture === item.posture ? 'all' : item.posture)))}
        <span className="h-8 w-px bg-gray-800" aria-hidden="true" />
        {kindItems.map((item) => tile(item.label, item.label, item.value, item.tone, kind === item.kind, () => onKind(kind === item.kind ? 'all' : item.kind)))}
        {postureItems.length > 0 && <span className="h-8 w-px bg-gray-800" aria-hidden="true" />}
        {postureItems.map((item) => tile(item.label, item.label, item.value, item.tone, posture === item.posture, () => onPosture(posture === item.posture ? 'all' : item.posture)))}
        {filtered && (
          <button
            type="button"
            onClick={() => { onKind('all'); onPosture('all') }}
            className="ml-auto inline-flex shrink-0 items-center gap-1 rounded px-2 py-1 text-[11px] text-gray-400 hover:bg-gray-800/60 hover:text-gray-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            <X className="h-3 w-3" aria-hidden="true" /> Clear
          </button>
        )}
      </div>
    </Panel>
  )
}

// The two-tier Hunt findings for a selected web target: VERIFIED (proven by
// the moat) vs SUSPECTED (agent leads). Renders nothing until it has findings, so
// it stays out of the way for targets the hunter hasn't touched.
function AgentFindingsSection({ targetId }: { targetId: string }) {
  const [data, setData] = useState<AgentTwoTierFindings | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    getAgentTwoTierFindings(targetId)
      .then((d) => { if (!cancelled) setData(d) })
      .catch(() => { if (!cancelled) setData(null) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [targetId])

  const verified = data?.verified ?? []
  const suspected = data?.suspected ?? []
  if (loading || (!verified.length && !suspected.length)) return null

  const row = (finding: { id: string; title: string; severity: string }) => (
    <Link
      key={finding.id}
      href={`/findings/${finding.id}`}
      className="flex items-center gap-2 rounded-lg border border-gray-800 bg-gray-950 px-2.5 py-1.5 hover:bg-gray-800/50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
    >
      <span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] uppercase ${severityClass(finding.severity)}`}>{finding.severity}</span>
      <span className="min-w-0 truncate text-xs text-gray-200">{finding.title}</span>
    </Link>
  )

  return (
    <div>
      <div className="mb-2 flex items-center gap-2 text-xs uppercase tracking-wide text-gray-500">
        <span>Hunt findings</span>
        <Link
          href={`/hunt?target=${encodeURIComponent(targetId)}`}
          className="ml-auto rounded text-[11px] normal-case text-blue-400 hover:text-blue-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          Open Hunt →
        </Link>
      </div>
      {verified.length > 0 && (
        <div className="mb-2">
          <div className="mb-1 flex items-center gap-1.5 text-[11px] text-emerald-300">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" aria-hidden="true" /> Verified ({verified.length})
          </div>
          <div className="space-y-1">{verified.slice(0, 6).map(row)}</div>
        </div>
      )}
      {suspected.length > 0 && (
        <div>
          <div className="mb-1 flex items-center gap-1.5 text-[11px] text-amber-300">
            <span className="h-1.5 w-1.5 rounded-full bg-amber-400" aria-hidden="true" /> Suspected ({suspected.length})
          </div>
          <div className="space-y-1">{suspected.slice(0, 6).map(row)}</div>
        </div>
      )}
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

        {node.type === 'web_target' && node.id.startsWith('target:') && (
          <AgentFindingsSection key={node.id} targetId={node.id.slice('target:'.length)} />
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
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full border border-dashed border-slate-400" aria-hidden="true" /> Dashed = internal
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full border border-dotted border-amber-400" aria-hidden="true" /> Dotted = unscanned
        </span>
        <span className="ml-auto">Hover for details · scroll to zoom · click to focus</span>
      </div>
    </div>
  )
}

const POSTURE_VALUES = new Set<string>(POSTURE_FILTERS.map((f) => f.value))

const AI_SCAN_ENVIRONMENTS: AIEnvironment[] = ['preview', 'staging', 'development', 'production']

// Named operational views: each is just a triage filter combination, so the
// URL stays the single source of truth and every view is shareable.
const PRESET_VIEWS: Array<{ label: string; kind: 'all' | ExposureAssetKind; posture: PostureFilter; sort: TriageSort }> = [
  { label: 'Public critical', kind: 'all', posture: 'public_critical', sort: 'critical' },
  { label: 'Failed scans', kind: 'all', posture: 'failed', sort: 'priority' },
  { label: 'Prod AI', kind: 'ai', posture: 'prod', sort: 'priority' },
  { label: 'New this week', kind: 'all', posture: 'new', sort: 'priority' },
  { label: 'Unverified high-impact', kind: 'all', posture: 'unverified_high', sort: 'priority' },
  { label: 'Unowned assets', kind: 'all', posture: 'unowned', sort: 'priority' },
]

export default function ExposurePage() {
  // useUrlFilters reads useSearchParams, which the App Router requires to sit
  // under a Suspense boundary.
  return (
    <Suspense fallback={null}>
      <ExposureView />
    </Suspense>
  )
}

function ExposureView() {
  const router = useRouter()
  const [graph, setGraph] = useState<ExposureGraph | null>(null)
  const [domains, setDomains] = useState<string[]>([])
  const [selectedNode, setSelectedNode] = useState<ExposureNode | null>(null)
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
  const [assetTotal, setAssetTotal] = useState(0)
  const [assetsLoading, setAssetsLoading] = useState(true)
  const [assetsError, setAssetsError] = useState<string | null>(null)
  const [newCount, setNewCount] = useState(0)
  const [scanningIds, setScanningIds] = useState<Set<string>>(new Set())
  const [selectedAsset, setSelectedAsset] = useState<ExposureAsset | null>(null)

  // Lens + triage filters live in the URL so views are shareable, survive
  // reloads, and back/forward steps through filter changes.
  const { filters, setFilter, setFilters } = useUrlFilters()
  const domain = typeof filters.domain === 'string' ? filters.domain : ''
  const lens: Lens = filters.lens === 'map' || filters.lens === 'paths' ? filters.lens : 'triage'
  const triageKind: 'all' | ExposureAssetKind =
    filters.kind === 'web' || filters.kind === 'ai' || filters.kind === 'model' ? filters.kind : 'all'
  const triagePosture: PostureFilter =
    typeof filters.posture === 'string' && POSTURE_VALUES.has(filters.posture) ? (filters.posture as PostureFilter) : 'all'
  const triageSort: TriageSort = filters.sort === 'critical' || filters.sort === 'stale' ? filters.sort : 'priority'
  // Committed inventory text filter (?q=...) — distinct from the typeahead,
  // which only jumps to a node in the map.
  const triageQuery = typeof filters.q === 'string' ? filters.q : ''
  // Map investigation state lives in the URL too, so a focused neighborhood
  // (node + depth + endpoints + resolved scope + highlight) is shareable.
  const focusId = typeof filters.focus === 'string' && filters.focus ? filters.focus : null
  const depth = filters.depth === '2' ? 2 : filters.depth === '3' ? 3 : 1
  const showEndpoints = filters.endpoints === '1'
  const includeResolved = filters.resolved === '1'
  const highlightType = typeof filters.highlight === 'string' && filters.highlight ? filters.highlight : null
  // Optional day window for the "new" posture (?posture=new&window=30) so the
  // change strip's links select the same slice they counted; defaults to the
  // server's 7-day is_new flag when absent.
  const windowValue = Number(filters.window)
  const triageNewWindow = Number.isInteger(windowValue) && windowValue > 0 ? windowValue : undefined

  const setLens = (next: Lens) => setFilter('lens', next === 'triage' ? undefined : next)

  // Triage filter updates go through one setFilters call: sequential setFilter
  // calls in a handler would clobber each other (each reads the same URL
  // snapshot). Defaults are stored as absent params to keep URLs clean. Any
  // update also returns to the triage lens, where these filters apply.
  function applyTriage(updates: { kind?: 'all' | ExposureAssetKind; posture?: PostureFilter; sort?: TriageSort; query?: string }) {
    const next: Record<string, string | undefined> = { lens: undefined }
    if (updates.kind !== undefined) next.kind = updates.kind === 'all' ? undefined : updates.kind
    if (updates.posture !== undefined) {
      next.posture = updates.posture === 'all' ? undefined : updates.posture
      // The ?window= cohort arrives via change-strip links scoped to one
      // posture; a manual posture switch leaves that cohort context.
      next.window = undefined
    }
    if (updates.sort !== undefined) next.sort = updates.sort === 'priority' ? undefined : updates.sort
    if (updates.query !== undefined) next.q = updates.query.trim() || undefined
    setFilters(next)
  }
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
      setAssetTotal(res.total ?? res.assets?.length ?? 0)
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

  // Scope changes (domain / resolved) reset map focus back to the overview.
  // All params go through one setFilters call so they don't clobber each other.
  function changeScope(updates: Record<string, string | undefined>) {
    setSelectedNode(null)
    setSelectedAsset(null)
    setFilters({ focus: undefined, highlight: undefined, endpoints: undefined, ...updates })
  }

  function handleFocus(node: ExposureNode) {
    setSelectedNode(node)
    // Grouped findings are synthetic (not addressable by the backend), so show
    // their detail without re-focusing the graph.
    if (node.type === 'finding_group') return
    setFilters({ lens: 'map', focus: node.id, highlight: undefined })
  }

  function focusById(id: string) {
    setSelectedNode(null)
    setFilters({ lens: 'map', focus: id, highlight: undefined })
  }

  function handleClear() {
    setSelectedNode(null)
    setFilters({ focus: undefined, endpoints: undefined })
  }

  // Every scan action actually queues a scan for its asset kind — web quick
  // scan, AI Gate smoke probe, or model intake re-check — rather than dropping
  // the user on a settings page.
  async function triggerScan(asset: ExposureAsset): Promise<string | undefined> {
    if (asset.kind === 'web') {
      const res = await scanTarget(asset.id, { scan_type: 'quick' })
      return res?.scan_id || res?.id
    }
    if (asset.kind === 'ai') {
      // Scan environment follows the asset's declared environment (the same
      // signal the "prod" posture uses), not just the production_mode flag —
      // so an asset with metadata environment "production" is scanned (and
      // confirmed) as production, not silently probed as preview.
      const declared = AI_SCAN_ENVIRONMENTS.includes(asset.environment as AIEnvironment)
        ? (asset.environment as AIEnvironment)
        : undefined
      const prod = isProductionAIAsset(asset)
      const res = await scanAITarget(asset.id, {
        probe_pack: 'shaker-ai-smoke',
        scan_profile: 'smoke',
        environment: declared ?? (prod ? 'production' : 'preview'),
        confirm_production: prod,
      })
      return res.scan_id
    }
    const res = await rescanModelIntakeTarget(asset.id)
    return res.scan_id
  }

  const SCAN_QUEUED_LABEL: Record<ExposureAssetKind, string> = {
    web: 'Scan started',
    ai: 'AI Gate smoke scan queued',
    model: 'Model intake re-check queued',
  }

  // The API hard-requires confirm_production for production AI surfaces; ask
  // the user before sending it instead of silently auto-confirming.
  function confirmProductionScan(toScan: ExposureAsset[]): boolean {
    const prodAI = toScan.filter(isProductionAIAsset)
    if (prodAI.length === 0) return true
    const names = prodAI.map((asset) => asset.label).join(', ')
    return window.confirm(
      `This runs AI Gate probes against ${prodAI.length === 1 ? 'a production AI surface' : `${prodAI.length} production AI surfaces`} (${names}). Continue?`
    )
  }

  async function handleScan(asset: ExposureAsset) {
    if (!confirmProductionScan([asset])) return
    setScanningIds((prev) => new Set(prev).add(asset.id))
    try {
      const scanId = await triggerScan(asset)
      toast.success(SCAN_QUEUED_LABEL[asset.kind], scanId ? { link: { href: `/scans/${scanId}`, label: 'View scan' } } : undefined)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : `Failed to start scan for ${asset.label}`)
    } finally {
      setScanningIds((prev) => {
        const next = new Set(prev)
        next.delete(asset.id)
        return next
      })
    }
  }

  async function handleAutonomousInvestigation(asset: ExposureAsset): Promise<void> {
    if (asset.kind !== 'web') throw new Error('Hunt is only available for registered web targets.')
    router.push(`/hunt?target=${encodeURIComponent(asset.id)}`)
  }

  // Bulk variant of handleScan: fire kind-appropriate scans concurrently and
  // report one summary toast instead of one per asset. Returns whether at
  // least one scan was queued so the caller can keep the selection on total
  // failure (or cancel) for an easy retry.
  async function handleBulkScan(toScan: ExposureAsset[]): Promise<boolean> {
    // No window.confirm here — the TriageTable bulk dialog is the confirmation
    // (including the production-AI warning) for this path.
    if (toScan.length === 0) return false
    setScanningIds((prev) => new Set([...prev, ...toScan.map((asset) => asset.id)]))
    try {
      const results = await Promise.allSettled(toScan.map((asset) => triggerScan(asset)))
      const ok = results.filter((result) => result.status === 'fulfilled').length
      const failed = results.length - ok
      if (ok > 0) {
        toast.success(`Queued ${ok} scan${ok === 1 ? '' : 's'}${failed > 0 ? ` · ${failed} failed` : ''}`, {
          link: { href: '/scans', label: 'View scans' },
        })
      } else {
        const firstError = results.find((result): result is PromiseRejectedResult => result.status === 'rejected')
        toast.error(firstError?.reason instanceof Error ? firstError.reason.message : 'Failed to queue the selected scans')
      }
      return ok > 0
    } finally {
      setScanningIds((prev) => {
        const next = new Set(prev)
        toScan.forEach((asset) => next.delete(asset.id))
        return next
      })
    }
  }

  function refreshActiveLens() {
    if (lens === 'triage') loadAssets()
    else if (lens === 'paths') loadPaths()
    else loadGraph()
  }

  // Preset chips show how many assets each view selects, so users never click
  // into an empty view blind; zero-count presets are dimmed and disabled.
  const presetCounts = useMemo(
    () =>
      PRESET_VIEWS.map(
        (preset) =>
          assets.filter(
            (asset) => (preset.kind === 'all' || asset.kind === preset.kind) && postureMatches(asset, preset.posture)
          ).length
      ),
    [assets]
  )

  const searchMatches = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    if (!q) return []
    return searchIndex.filter((n) => n.label.toLowerCase().includes(q)).slice(0, 12)
  }, [searchQuery, searchIndex])

  const byId = useMemo(() => new Map((graph?.nodes || []).map((node) => [node.id, node])), [graph])

  // Restore the selected-node panel from a deep-linked ?focus= once the graph
  // arrives. Never clobbers an interactive selection (handleFocus sets that).
  useEffect(() => {
    if (!focusId || !graph) return
    setSelectedNode((prev) => prev ?? byId.get(focusId) ?? null)
  }, [focusId, graph, byId])
  const summary = graph?.summary
  const nodeTypeCounts = summary?.node_type_counts || {}

  // The Map's priority panel reuses the triage action ranking so the two lenses
  // agree on what's urgent. `assets` arrives pre-sorted by action_score desc, so
  // we take the top action-needing assets (graph hotspots ranked by raw finding
  // count instead — domains/chains — which disagreed with triage's P1/P2 view).
  const priorityAssets = useMemo(
    () => assets.filter((a) => a.needs_action).slice(0, 8),
    [assets]
  )

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
    <div className={styles.page}>
      <div className={styles.pageGlow} aria-hidden="true" />
      <div className={`${styles.content} space-y-6`}>
      <div className={`flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between ${styles.rise} ${styles.d1}`}>
        <div>
          <div className="flex items-center gap-2.5">
            <span className={styles.liveDot} aria-hidden="true" />
            <span className={styles.kicker}>Exposure · live</span>
          </div>
          <h1 className={`${styles.displayTitle} mt-1.5 text-2xl font-bold text-white`}>Exposure</h1>
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
              onKeyDown={(event) => {
                if (event.key === 'Enter') {
                  applyTriage({ query: searchQuery })
                  setSearchOpen(false)
                } else if (event.key === 'Escape') {
                  setSearchOpen(false)
                }
              }}
              placeholder="Search assets & findings…"
              aria-label="Search exposure nodes"
              className={`w-56 py-2 pl-8 pr-3 text-sm text-white placeholder:text-gray-500 ${styles.input}`}
            />
            {searchOpen && searchMatches.length > 0 && (
              <div className={`absolute z-20 mt-1 max-h-72 w-72 overflow-auto py-1 shadow-xl ${styles.input}`}>
                <div className="border-b border-gray-800 px-3 py-1.5 text-[10px] uppercase tracking-wide text-gray-500">
                  Click — open in map · Enter — filter inventory
                </div>
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
            onChange={(event) => changeScope({ domain: event.target.value || undefined })}
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
          label="P1 Priorities"
          value={assetMetrics?.p1_count ?? '--'}
          icon={<Radar className="h-5 w-5" />}
          alert={Boolean(assetMetrics && (assetMetrics.p1_count || 0) > 0)}
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
        <PostureSummary
          metrics={assetMetrics}
          kind={triageKind}
          posture={triagePosture}
          onKind={(k) => applyTriage({ kind: k })}
          onPosture={(p) => applyTriage({ posture: p })}
        />
      </div>

      {lens === 'triage' && (
        <div role="tabpanel" id="lens-panel-triage" aria-labelledby="lens-tab-triage" className={`${styles.rise} ${styles.d3} space-y-3`}>
          <ChangesStrip rootDomain={domain || undefined} />
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] uppercase tracking-wide text-gray-600">Views</span>
            {PRESET_VIEWS.map((preset, index) => {
              const active = triageKind === preset.kind && triagePosture === preset.posture && triageSort === preset.sort
              const count = presetCounts[index] ?? 0
              const empty = count === 0 && !active
              return (
                <button
                  key={preset.label}
                  type="button"
                  aria-pressed={active}
                  disabled={empty}
                  title={empty ? 'No matching assets right now' : undefined}
                  onClick={() =>
                    active
                      ? applyTriage({ kind: 'all', posture: 'all', sort: 'priority' })
                      : applyTriage({ kind: preset.kind, posture: preset.posture, sort: preset.sort })
                  }
                  className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                    active
                      ? 'border-teal-400/40 bg-teal-500/15 text-teal-200'
                      : empty
                        ? 'border-gray-800/60 text-gray-600'
                        : 'border-gray-800 text-gray-400 hover:border-gray-700 hover:text-gray-200'
                  }`}
                >
                  {preset.label}
                  <span className={`rounded-full px-1.5 text-[10px] ${active ? 'bg-teal-400/20 text-teal-100' : 'bg-gray-800 text-gray-500'}`}>
                    {count}
                  </span>
                </button>
              )
            })}
          </div>
          <TriageTable
            assets={assets}
            metrics={assetMetrics}
            total={assetTotal}
            loading={assetsLoading}
            error={assetsError}
            onRetry={loadAssets}
            onExplore={focusById}
            onScan={handleScan}
            onInvestigate={handleAutonomousInvestigation}
            onDetails={setSelectedAsset}
            scanningIds={scanningIds}
            selectedAsset={selectedAsset}
            onCloseDetails={() => setSelectedAsset(null)}
            kind={triageKind}
            posture={triagePosture}
            sort={triageSort}
            onKindChange={(k) => applyTriage({ kind: k })}
            onPostureChange={(p) => applyTriage({ posture: p })}
            onSortChange={(s) => applyTriage({ sort: s })}
            onBulkScan={handleBulkScan}
            newWindowDays={triageNewWindow}
            query={triageQuery}
            onQueryChange={(q) => { applyTriage({ query: q }); setSearchQuery(q) }}
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
                  onChange={(event) => setFilter('depth', event.target.value === '1' ? undefined : event.target.value)}
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
                    onChange={(event) => setFilter('endpoints', event.target.checked ? '1' : undefined)}
                    className="rounded border-gray-700 bg-gray-800"
                  />
                  All endpoints
                </label>
              )}
              <label className={`flex items-center gap-2 px-3 py-2 text-xs text-gray-300 ${styles.input}`}>
                <input
                  type="checkbox"
                  checked={includeResolved}
                  onChange={(event) => changeScope({ resolved: event.target.checked ? '1' : undefined })}
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
              <div className={`relative h-[420px] w-full sm:h-[560px] ${styles.graphBackdrop}`}>
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
                    onClick={() => setFilter('highlight', undefined)}
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
                  <p className="mt-1 text-xs text-gray-500">Same action ranking as triage — click to explore</p>
                </div>
                <div className="divide-y divide-gray-800/60">
                  {priorityAssets.length === 0 ? (
                    <div className="p-4 text-sm text-gray-500">No assets need action right now.</div>
                  ) : (
                    priorityAssets.map((asset, index) => (
                      <button
                        key={asset.node_id}
                        type="button"
                        onClick={() => focusById(asset.node_id)}
                        className="flex w-full gap-3 p-4 text-left hover:bg-gray-800/40 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                      >
                        <span className={`${styles.rank} pt-1`}>{String(index + 1).padStart(2, '0')}</span>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <span className={`h-2 w-2 shrink-0 rounded-full ${riskDot(asset)}`} aria-hidden="true" />
                            <span className="truncate text-sm text-gray-100">{asset.label}</span>
                            <PriorityBadge priority={asset.action_priority} />
                          </div>
                          <div className="mt-1.5 flex flex-wrap items-center gap-x-2.5 gap-y-1 text-[11px] text-gray-500">
                            <span className="uppercase tracking-wide text-gray-600">{KIND_ABBR[asset.kind]}</span>
                            {asset.active_critical > 0 && <span className="text-red-400">{asset.active_critical}C</span>}
                            {asset.active_high > 0 && <span className="text-orange-400">{asset.active_high}H</span>}
                            {asset.grade && <span>Grade {asset.grade}</span>}
                            {asset.kind === 'ai' && asset.blast_radius_tier && <span className="text-purple-300">{asset.blast_radius_tier} blast</span>}
                          </div>
                        </div>
                      </button>
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
                          onClick={() => setFilter('highlight', active ? undefined : type)}
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
