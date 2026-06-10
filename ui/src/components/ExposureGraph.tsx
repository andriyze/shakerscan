'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import dynamic from 'next/dynamic'
import type { ExposureEdge, ExposureNode, ExposureNodeType } from '@/lib/api'

const ForceGraph2D = dynamic(() => import('./ExposureForceGraphClient'), {
  ssr: false,
}) as unknown as React.ComponentType<Record<string, unknown>>

// Canvas needs hex, not Tailwind classes. Keyed to the node-type palette.
export const NODE_HEX: Record<string, string> = {
  domain: '#22d3ee',
  web_target: '#60a5fa',
  model_artifact: '#5eead4',
  model_supply_chain: '#94a3b8',
  endpoint: '#0ea5e9',
  api_surface: '#818cf8',
  auth_role: '#a3e635',
  third_party_js: '#facc15',
  cloud_hint: '#14b8a6',
  ai_target: '#c084fc',
  mcp_tool: '#e879f9',
  scan: '#34d399',
  finding: '#fb923c',
  finding_group: '#fb923c',
  vendor: '#fbbf24',
  attack_chain: '#f87171',
}

const SEVERITY_HEX: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
}

const ASSET_TYPES = new Set<ExposureNodeType>(['domain', 'web_target', 'model_artifact', 'ai_target'])

function nodeRadius(node: ExposureNode): number {
  if (node.type === 'finding_group') {
    const count = Number((node.meta?.count as number) || 2)
    return 7 + Math.min(9, Math.sqrt(count) * 1.6)
  }
  let r = ASSET_TYPES.has(node.type) ? 6 : 4
  const findings = Number((node.meta?.active_findings_count as number) || 0)
  if (findings > 0) r += Math.min(6, Math.sqrt(findings))
  const sev = String(node.severity || '').toLowerCase()
  if (sev === 'critical') r += 3
  else if (sev === 'high') r += 2
  return r
}

interface GraphNode extends ExposureNode {
  __r: number
  __sev: string | null
  x?: number
  y?: number
  vx?: number
  vy?: number
}

interface GraphLink {
  source: string
  target: string
  type: string
  severity?: string | null
}

interface ForceGraphInstance {
  zoomToFit: (ms?: number, padding?: number) => void
  centerAt: (x?: number, y?: number, ms?: number) => void
  zoom: (z?: number, ms?: number) => void
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string))
}

export function ExposureGraph({
  nodes,
  edges,
  focusId,
  highlightType,
  onNodeClick,
  height = 560,
}: {
  nodes: ExposureNode[]
  edges: ExposureEdge[]
  focusId?: string | null
  highlightType?: string | null
  onNodeClick: (node: ExposureNode) => void
  height?: number
}) {
  const containerRef = useRef<HTMLDivElement>(null)
  const fgRef = useRef<ForceGraphInstance | null>(null)
  // Persist node objects across refetches so the force layout keeps positions
  // instead of exploding and resettling on every focus change.
  const nodeCacheRef = useRef<Map<string, GraphNode>>(new Map())
  const firstFitRef = useRef(true)
  const [width, setWidth] = useState(800)
  const [hoverId, setHoverId] = useState<string | null>(null)

  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const update = () => setWidth(el.clientWidth)
    update()
    const observer = new ResizeObserver(update)
    observer.observe(el)
    return () => observer.disconnect()
  }, [])

  const graphData = useMemo(() => {
    const cache = nodeCacheRef.current
    const incomingIds = new Set(nodes.map((n) => n.id))

    const neighborById = new Map<string, string[]>()
    const addNeighbor = (a: string, b: string) => {
      const list = neighborById.get(a)
      if (list) list.push(b)
      else neighborById.set(a, [b])
    }
    for (const e of edges) {
      addNeighbor(e.source, e.target)
      addNeighbor(e.target, e.source)
    }

    const graphNodes: GraphNode[] = nodes.map((n) => {
      const r = nodeRadius(n)
      const sev = n.severity ? String(n.severity).toLowerCase() : null
      const existing = cache.get(n.id)
      if (existing) {
        existing.label = n.label
        existing.type = n.type
        existing.subtitle = n.subtitle
        existing.severity = n.severity
        existing.status = n.status
        existing.href = n.href
        existing.meta = n.meta
        existing.__r = r
        existing.__sev = sev
        return existing
      }
      const fresh: GraphNode = { ...n, __r: r, __sev: sev }
      const seed = (neighborById.get(n.id) || []).map((id) => cache.get(id)).find((c) => c && c.x != null)
      if (seed && seed.x != null && seed.y != null) {
        fresh.x = seed.x + (Math.random() * 40 - 20)
        fresh.y = seed.y + (Math.random() * 40 - 20)
      }
      cache.set(n.id, fresh)
      return fresh
    })

    // Bound the position cache: across a long session of focus changes it
    // would otherwise retain every node ever seen. Once large, keep only the
    // nodes currently on screen (their positions still carry continuity).
    if (cache.size > 1500) {
      for (const id of cache.keys()) {
        if (!incomingIds.has(id)) cache.delete(id)
      }
    }

    const links: GraphLink[] = edges
      .filter((e) => incomingIds.has(e.source) && incomingIds.has(e.target))
      .map((e) => ({ source: e.source, target: e.target, type: e.type, severity: e.severity }))
    return { nodes: graphNodes, links }
  }, [nodes, edges])

  const handleEngineStop = useCallback(() => {
    const fg = fgRef.current
    if (!fg) return
    if (firstFitRef.current) {
      fg.zoomToFit(500, 60)
      firstFitRef.current = false
      return
    }
    if (focusId) {
      const fn = nodeCacheRef.current.get(focusId)
      if (fn && fn.x != null && fn.y != null) {
        fg.centerAt(fn.x, fn.y, 700)
        fg.zoom(2.2, 700)
        return
      }
    }
    fg.zoomToFit(500, 60)
  }, [focusId])

  const paintNode = useCallback(
    (node: GraphNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const x = node.x ?? 0
      const y = node.y ?? 0
      const r = node.__r
      const isFocus = node.id === focusId
      const isHover = node.id === hoverId
      const dimmed = !!highlightType && node.type !== highlightType && !isFocus && !isHover

      ctx.globalAlpha = dimmed ? 0.15 : 1

      // Phosphor glow for severe nodes — reads as "hot" on the radar backdrop.
      const glow = !dimmed && (node.__sev === 'critical' || node.__sev === 'high')
      if (glow) {
        ctx.shadowColor = SEVERITY_HEX[node.__sev as string]
        ctx.shadowBlur = node.__sev === 'critical' ? 14 : 9
      }

      ctx.beginPath()
      ctx.arc(x, y, r, 0, 2 * Math.PI)
      ctx.fillStyle = NODE_HEX[node.type] ?? '#9ca3af'
      ctx.fill()
      ctx.shadowBlur = 0

      if (node.__sev && SEVERITY_HEX[node.__sev]) {
        ctx.lineWidth = Math.max(1, r * 0.3)
        ctx.strokeStyle = SEVERITY_HEX[node.__sev]
        ctx.stroke()
      }

      // Grouped findings get an inner ring + count to read as "many".
      if (node.type === 'finding_group') {
        ctx.beginPath()
        ctx.arc(x, y, r * 0.55, 0, 2 * Math.PI)
        ctx.lineWidth = 1 / globalScale
        ctx.strokeStyle = 'rgba(10,10,10,0.85)'
        ctx.stroke()
        const count = Number(node.meta?.count || 0)
        if (count && globalScale > 0.8) {
          ctx.fillStyle = '#0a0a0a'
          ctx.font = `${Math.min(r, 7 / globalScale + r * 0.4)}px 'Spline Sans Mono', ui-monospace, monospace`
          ctx.textAlign = 'center'
          ctx.textBaseline = 'middle'
          ctx.fillText(String(count), x, y)
        }
      }

      if (isFocus || isHover) {
        ctx.beginPath()
        ctx.arc(x, y, r + 3, 0, 2 * Math.PI)
        ctx.lineWidth = 1.5
        ctx.strokeStyle = isFocus ? '#ffffff' : 'rgba(255,255,255,0.5)'
        ctx.stroke()
      }

      const showLabel = isFocus || isHover || globalScale > 3.5
      if (showLabel) {
        const label = node.label || node.id
        const text = label.length > 22 ? `${label.slice(0, 21)}…` : label
        const fontSize = 12 / globalScale
        ctx.font = `${fontSize}px 'Spline Sans Mono', ui-monospace, monospace`
        ctx.textAlign = 'center'
        ctx.textBaseline = 'top'
        const labelY = y + r + 4 / globalScale
        ctx.lineWidth = 3 / globalScale
        ctx.strokeStyle = 'rgba(10,10,10,0.9)'
        ctx.strokeText(text, x, labelY)
        ctx.fillStyle = '#e5e7eb'
        ctx.fillText(text, x, labelY)
      }

      ctx.globalAlpha = 1
    },
    [focusId, hoverId, highlightType]
  )

  const paintPointerArea = useCallback((node: GraphNode, color: string, ctx: CanvasRenderingContext2D) => {
    ctx.fillStyle = color
    ctx.beginPath()
    ctx.arc(node.x ?? 0, node.y ?? 0, node.__r + 3, 0, 2 * Math.PI)
    ctx.fill()
  }, [])

  const nodeTooltip = useCallback((node: GraphNode) => {
    const color = NODE_HEX[node.type] ?? '#9ca3af'
    const sevColor = node.__sev ? SEVERITY_HEX[node.__sev] : null
    const typeLabel = node.type.replace(/_/g, ' ')
    const sevRow = node.severity
      ? `<div style="color:${sevColor};text-transform:uppercase;font-size:10px;font-weight:600">${escapeHtml(String(node.severity))}</div>`
      : ''
    const detail =
      node.type === 'finding_group'
        ? `${node.meta?.count ?? ''} similar findings`
        : node.subtitle || ''
    return `<div style="background:rgba(8,11,19,0.95);border:1px solid rgba(94,234,212,0.25);border-radius:2px;padding:8px 10px;max-width:280px;font-family:'Spline Sans Mono',ui-monospace,monospace;box-shadow:0 0 24px rgba(0,0,0,0.6)">
      <div style="display:flex;align-items:center;gap:6px">
        <span style="width:8px;height:8px;border-radius:50%;background:${color};display:inline-block"></span>
        <span style="color:#9ca3af;font-size:10px;text-transform:uppercase;letter-spacing:.04em">${escapeHtml(typeLabel)}</span>
      </div>
      <div style="color:#f3f4f6;font-size:13px;font-weight:500;margin-top:3px;word-break:break-word">${escapeHtml(node.label)}</div>
      ${detail ? `<div style="color:#6b7280;font-size:11px;margin-top:2px">${escapeHtml(String(detail))}</div>` : ''}
      ${sevRow}
      <div style="color:#5eead4;font-size:10px;margin-top:4px;letter-spacing:.08em;text-transform:uppercase">Click to focus</div>
    </div>`
  }, [])

  return (
    <div ref={containerRef} className="h-full w-full">
      <ForceGraph2D
        ref={fgRef}
        graphData={graphData}
        width={width}
        height={height}
        backgroundColor="rgba(0,0,0,0)"
        nodeRelSize={1}
        nodeCanvasObject={paintNode}
        nodePointerAreaPaint={paintPointerArea}
        nodeLabel={nodeTooltip}
        linkColor={(link: GraphLink) =>
          link.severity && SEVERITY_HEX[String(link.severity).toLowerCase()]
            ? SEVERITY_HEX[String(link.severity).toLowerCase()]
            : 'rgba(148,163,184,0.22)'
        }
        linkWidth={(link: GraphLink) => (link.severity ? 1.5 : 0.6)}
        warmupTicks={20}
        cooldownTicks={90}
        onEngineStop={handleEngineStop}
        onNodeClick={(node: GraphNode) => onNodeClick(node)}
        onNodeHover={(node: GraphNode | null) => setHoverId(node?.id ?? null)}
      />
    </div>
  )
}
