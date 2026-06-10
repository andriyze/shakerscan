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
  endpoint: '#38bdf8',
  api_surface: '#818cf8',
  auth_role: '#a3e635',
  third_party_js: '#facc15',
  cloud_hint: '#2dd4bf',
  ai_target: '#c084fc',
  mcp_tool: '#e879f9',
  scan: '#34d399',
  finding: '#fb923c',
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
}

interface GraphLink {
  source: string
  target: string
  type: string
  severity?: string | null
}

interface ForceGraphInstance {
  zoomToFit: (ms?: number, padding?: number) => void
}

export function ExposureGraph({
  nodes,
  edges,
  focusId,
  onNodeClick,
  height = 560,
}: {
  nodes: ExposureNode[]
  edges: ExposureEdge[]
  focusId?: string | null
  onNodeClick: (node: ExposureNode) => void
  height?: number
}) {
  const containerRef = useRef<HTMLDivElement>(null)
  const fgRef = useRef<ForceGraphInstance | null>(null)
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
    const graphNodes: GraphNode[] = nodes.map((n) => ({
      ...n,
      __r: nodeRadius(n),
      __sev: n.severity ? String(n.severity).toLowerCase() : null,
    }))
    const ids = new Set(graphNodes.map((n) => n.id))
    const links: GraphLink[] = edges
      .filter((e) => ids.has(e.source) && ids.has(e.target))
      .map((e) => ({ source: e.source, target: e.target, type: e.type, severity: e.severity }))
    return { nodes: graphNodes, links }
  }, [nodes, edges])

  const handleEngineStop = useCallback(() => {
    fgRef.current?.zoomToFit(400, 60)
  }, [])

  const paintNode = useCallback(
    (node: GraphNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const x = node.x ?? 0
      const y = node.y ?? 0
      const r = node.__r
      const isFocus = node.id === focusId
      const isHover = node.id === hoverId

      ctx.beginPath()
      ctx.arc(x, y, r, 0, 2 * Math.PI)
      ctx.fillStyle = NODE_HEX[node.type] ?? '#9ca3af'
      ctx.fill()

      if (node.__sev && SEVERITY_HEX[node.__sev]) {
        ctx.lineWidth = Math.max(1, r * 0.3)
        ctx.strokeStyle = SEVERITY_HEX[node.__sev]
        ctx.stroke()
      }

      if (isFocus || isHover) {
        ctx.beginPath()
        ctx.arc(x, y, r + 3, 0, 2 * Math.PI)
        ctx.lineWidth = 1.5
        ctx.strokeStyle = isFocus ? '#ffffff' : 'rgba(255,255,255,0.5)'
        ctx.stroke()
      }

      // Only label the focused node and whatever is hovered by default; show
      // every label only once the user has zoomed well in. Keeps dense finding
      // clusters from collapsing into an unreadable pile of overlapping text.
      const showLabel = isFocus || isHover || globalScale > 3.5
      if (showLabel) {
        const label = node.label || node.id
        const text = label.length > 22 ? `${label.slice(0, 21)}…` : label
        // Constant on-screen size (~12px) regardless of zoom level.
        const fontSize = 12 / globalScale
        ctx.font = `${fontSize}px system-ui, sans-serif`
        ctx.textAlign = 'center'
        ctx.textBaseline = 'top'
        const labelY = y + r + 4 / globalScale
        ctx.lineWidth = 3 / globalScale
        ctx.strokeStyle = 'rgba(10,10,10,0.9)'
        ctx.strokeText(text, x, labelY)
        ctx.fillStyle = '#e5e7eb'
        ctx.fillText(text, x, labelY)
      }
    },
    [focusId, hoverId]
  )

  const paintPointerArea = useCallback(
    (node: GraphNode, color: string, ctx: CanvasRenderingContext2D) => {
      ctx.fillStyle = color
      ctx.beginPath()
      ctx.arc(node.x ?? 0, node.y ?? 0, node.__r + 3, 0, 2 * Math.PI)
      ctx.fill()
    },
    []
  )

  return (
    <div ref={containerRef} className="h-full w-full">
      <ForceGraph2D
        ref={fgRef}
        graphData={graphData}
        width={width}
        height={height}
        backgroundColor="#0a0a0a"
        nodeRelSize={1}
        nodeCanvasObject={paintNode}
        nodePointerAreaPaint={paintPointerArea}
        linkColor={(link: GraphLink) =>
          link.severity && SEVERITY_HEX[String(link.severity).toLowerCase()]
            ? SEVERITY_HEX[String(link.severity).toLowerCase()]
            : 'rgba(148,163,184,0.22)'
        }
        linkWidth={(link: GraphLink) => (link.severity ? 1.5 : 0.6)}
        cooldownTicks={100}
        onEngineStop={handleEngineStop}
        onNodeClick={(node: GraphNode) => onNodeClick(node)}
        onNodeHover={(node: GraphNode | null) => setHoverId(node?.id ?? null)}
      />
    </div>
  )
}
