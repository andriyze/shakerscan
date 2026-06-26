'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import {
  getApplicationGraph,
  type ApplicationGraph,
  type ApplicationGraphNode,
} from '@/lib/api'
import { SectionCard, ErrorState } from '@/components/ui'

function nodeLabel(node: ApplicationGraphNode): string {
  return node.label || node.node_key.replace(/^(route|object|principal):/, '')
}

function keyLabel(key: string): string {
  return key.replace(/^(route|object|principal):/, '')
}

function asStringList(value: unknown): string[] {
  if (Array.isArray(value)) return value.map((x) => String(x))
  if (typeof value === 'string' && value) return [value]
  return []
}

function GraphContent() {
  const params = useParams()
  const targetId = params.id as string
  const [graph, setGraph] = useState<ApplicationGraph | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [nodeType, setNodeType] = useState('all')
  const [edgeType, setEdgeType] = useState('all')
  const [selectedNodeKey, setSelectedNodeKey] = useState<string | null>(null)

  const fetchGraph = useCallback(async () => {
    try {
      const data = await getApplicationGraph(targetId)
      setGraph(data)
      setError(null)
    } catch {
      setError('Failed to load application graph')
    } finally {
      setLoading(false)
    }
  }, [targetId])

  useEffect(() => {
    fetchGraph()
  }, [fetchGraph])

  const visibleNodes = useMemo(() => {
    const q = search.trim().toLowerCase()
    return (graph?.nodes || []).filter((node) => {
      if (nodeType !== 'all' && node.node_type !== nodeType) return false
      if (!q) return true
      const haystack = [
        node.node_type,
        node.node_key,
        node.label,
        JSON.stringify(node.attributes || {}),
      ].join(' ').toLowerCase()
      return haystack.includes(q)
    })
  }, [graph, nodeType, search])
  const visibleNodeKeys = useMemo(() => new Set(visibleNodes.map((node) => node.node_key)), [visibleNodes])
  const visibleEdges = useMemo(() => {
    const q = search.trim().toLowerCase()
    return (graph?.edges || []).filter((edge) => {
      if (edgeType !== 'all' && edge.edge_type !== edgeType) return false
      if (!visibleNodeKeys.has(edge.src_key) && !visibleNodeKeys.has(edge.dst_key)) return false
      if (!q) return true
      const haystack = [
        edge.edge_type,
        edge.src_key,
        edge.dst_key,
        JSON.stringify(edge.attributes || {}),
      ].join(' ').toLowerCase()
      return haystack.includes(q) || visibleNodeKeys.has(edge.src_key) || visibleNodeKeys.has(edge.dst_key)
    })
  }, [edgeType, graph, search, visibleNodeKeys])
  const routes = useMemo(
    () => visibleNodes.filter((n) => n.node_type === 'route'),
    [visibleNodes]
  )
  const objects = useMemo(
    () => visibleNodes.filter((n) => n.node_type === 'object'),
    [visibleNodes]
  )
  const otherNodes = useMemo(
    () => visibleNodes.filter((n) => n.node_type !== 'route' && n.node_type !== 'object'),
    [visibleNodes]
  )
  const authBoundaries = useMemo(
    () => visibleEdges.filter((e) => e.edge_type === 'auth_boundary'),
    [visibleEdges]
  )
  const selectedNode = useMemo(
    () => (graph?.nodes || []).find((node) => node.node_key === selectedNodeKey) || null,
    [graph, selectedNodeKey]
  )
  const selectedNodeEdges = useMemo(
    () => (graph?.edges || []).filter((edge) => edge.src_key === selectedNodeKey || edge.dst_key === selectedNodeKey),
    [graph, selectedNodeKey]
  )

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
      </div>
    )
  }

  if (error || !graph) {
    return (
      <ErrorState
        message={error || 'Application graph not found'}
        onRetry={() => {
          setLoading(true)
          fetchGraph()
        }}
      />
    )
  }

  const summary = graph.summary

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link href="/targets" className="text-gray-400 hover:text-white">
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
        </Link>
        <h1 className="text-2xl font-bold text-white">Application Graph</h1>
      </div>

      <SectionCard title="Summary">
        <div className="flex flex-wrap gap-2 text-xs">
          <span className="px-2 py-1 rounded bg-gray-800 text-gray-300">{summary.node_count} nodes</span>
          <span className="px-2 py-1 rounded bg-gray-800 text-gray-300">{summary.edge_count} edges</span>
          {Object.entries(summary.by_node_type || {}).map(([k, v]) => (
            <span key={`n-${k}`} className="px-2 py-1 rounded bg-blue-900/40 text-blue-300">
              {v} {k}
            </span>
          ))}
          {Object.entries(summary.by_edge_type || {}).map(([k, v]) => (
            <span key={`e-${k}`} className="px-2 py-1 rounded bg-purple-900/40 text-purple-300">
              {v} {k}
            </span>
          ))}
        </div>
        {summary.edge_count === 0 && (
          <p className="text-xs text-gray-500 mt-3">
            Producer/consumer and auth-boundary edges populate from a dual-user (BOLA) scan. Run one
            with two auth contexts to enrich the graph with object ownership and cross-principal access.
          </p>
        )}
      </SectionCard>

      <SectionCard title="Filters">
        <div className="grid gap-3 md:grid-cols-[1fr_0.3fr_0.3fr]">
          <label className="grid gap-1 text-sm text-gray-300">
            Search
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none"
              placeholder="route, object, principal, field"
            />
          </label>
          <label className="grid gap-1 text-sm text-gray-300">
            Node type
            <select
              value={nodeType}
              onChange={(e) => setNodeType(e.target.value)}
              className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="all">All nodes</option>
              {Object.keys(summary.by_node_type || {}).map((type) => <option key={type} value={type}>{type}</option>)}
            </select>
          </label>
          <label className="grid gap-1 text-sm text-gray-300">
            Edge type
            <select
              value={edgeType}
              onChange={(e) => setEdgeType(e.target.value)}
              className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="all">All edges</option>
              {Object.keys(summary.by_edge_type || {}).map((type) => <option key={type} value={type}>{type}</option>)}
            </select>
          </label>
        </div>
        <div className="mt-3 text-xs text-gray-500">
          Showing {visibleNodes.length} of {summary.node_count} nodes and {visibleEdges.length} of {summary.edge_count} edges.
        </div>
      </SectionCard>

      {selectedNode && (
        <SectionCard
          title="Selected Node"
          actions={
            <button type="button" onClick={() => setSelectedNodeKey(null)} className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800">
              Clear
            </button>
          }
        >
          <div className="space-y-3">
            <div>
              <div className="font-mono text-sm text-gray-200 break-all">{nodeLabel(selectedNode)}</div>
              <div className="mt-1 text-xs text-gray-500">{selectedNode.node_type} · {selectedNode.node_key}</div>
            </div>
            {selectedNode.attributes && Object.keys(selectedNode.attributes).length > 0 && (
              <pre className="max-h-56 overflow-auto rounded border border-gray-800 bg-gray-950 p-2 text-xs text-gray-300">
                {JSON.stringify(selectedNode.attributes, null, 2)}
              </pre>
            )}
            <div className="space-y-1">
              <div className="text-xs font-medium text-gray-400">Connected edges ({selectedNodeEdges.length})</div>
              {selectedNodeEdges.length === 0 ? (
                <div className="text-xs text-gray-500">No connected edges yet.</div>
              ) : (
                selectedNodeEdges.slice(0, 12).map((edge) => (
                  <div key={edge.id} className="rounded border border-gray-800 bg-gray-950 px-2 py-1 text-xs text-gray-300">
                    <span className="text-purple-300">{edge.edge_type}</span>{' '}
                    <span className="font-mono break-all">{keyLabel(edge.src_key)}</span>
                    <span className="mx-1 text-gray-500">→</span>
                    <span className="font-mono break-all">{keyLabel(edge.dst_key)}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </SectionCard>
      )}

      {authBoundaries.length > 0 && (
        <SectionCard title="Auth boundaries (cross-principal access surface)">
          <div className="space-y-2">
            {authBoundaries.map((e) => {
              const attrs = e.attributes || {}
              const sensitive = asStringList(attrs.sensitive_fields)
              return (
                <div key={e.id} className="bg-gray-800/60 rounded-lg p-3 space-y-1">
                  <div className="flex items-center gap-2 text-sm flex-wrap">
                    <span className="font-mono text-gray-200 break-all">{keyLabel(e.src_key)}</span>
                    <span className="text-amber-400">→</span>
                    <span className="font-mono text-gray-200 break-all">{keyLabel(e.dst_key)}</span>
                  </div>
                  <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-400">
                    {attrs.object_id_key ? (
                      <span>
                        object: <span className="text-gray-300 font-mono">{String(attrs.object_id_key)}</span>
                      </span>
                    ) : null}
                    {attrs.source_principal ? (
                      <span>
                        owner: <span className="text-gray-300">{String(attrs.source_principal)}</span>
                      </span>
                    ) : null}
                    {attrs.excluded_principal ? (
                      <span>
                        excluded: <span className="text-gray-300">{String(attrs.excluded_principal)}</span>
                      </span>
                    ) : null}
                    {sensitive.length > 0 ? (
                      <span>
                        sensitive: <span className="text-amber-300">{sensitive.join(', ')}</span>
                      </span>
                    ) : null}
                  </div>
                </div>
              )
            })}
          </div>
        </SectionCard>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SectionCard title={`Routes (${routes.length})`}>
          {routes.length === 0 ? (
            <p className="text-xs text-gray-500">No routes yet — run a scan to populate.</p>
          ) : (
            <div className="space-y-1 max-h-96 overflow-y-auto">
              {routes.map((n) => (
                <button
                  type="button"
                  key={n.id}
                  onClick={() => setSelectedNodeKey(n.node_key)}
                  className="flex w-full items-center justify-between gap-2 border-b border-gray-800/60 py-1 text-left text-xs hover:bg-gray-800/40"
                >
                  <span className="font-mono text-gray-300 break-all">{nodeLabel(n)}</span>
                  {n.attributes?.role ? (
                    <span className="shrink-0 px-1.5 py-0.5 rounded bg-gray-800 text-gray-400">
                      {String(n.attributes.role)}
                    </span>
                  ) : null}
                </button>
              ))}
            </div>
          )}
        </SectionCard>

        <SectionCard title={`Objects (${objects.length})`}>
          {objects.length === 0 ? (
            <p className="text-xs text-gray-500">No object nodes — these come from a BOLA scan.</p>
          ) : (
            <div className="space-y-1 max-h-96 overflow-y-auto">
              {objects.map((n) => {
                const sensitive = asStringList(n.attributes?.sensitive_fields)
                return (
                  <button
                    type="button"
                    key={n.id}
                    onClick={() => setSelectedNodeKey(n.node_key)}
                    className="w-full border-b border-gray-800/60 py-1 text-left text-xs hover:bg-gray-800/40"
                  >
                    <span className="font-mono text-gray-300">{nodeLabel(n)}</span>
                    {sensitive.length > 0 ? (
                      <span className="ml-2 text-amber-300">[{sensitive.join(', ')}]</span>
                    ) : null}
                  </button>
                )
              })}
            </div>
          )}
        </SectionCard>
      </div>

      {otherNodes.length > 0 && (
        <SectionCard title={`Other Nodes (${otherNodes.length})`}>
          <div className="grid gap-1 sm:grid-cols-2">
            {otherNodes.map((node) => (
              <button
                key={node.id}
                type="button"
                onClick={() => setSelectedNodeKey(node.node_key)}
                className="rounded border border-gray-800 bg-gray-950 px-2 py-1 text-left text-xs hover:bg-gray-800/60"
              >
                <span className="text-gray-500">{node.node_type}</span>{' '}
                <span className="font-mono text-gray-300 break-all">{nodeLabel(node)}</span>
              </button>
            ))}
          </div>
        </SectionCard>
      )}

      <SectionCard title={`Edges (${visibleEdges.length})`}>
        {visibleEdges.length === 0 ? (
          <p className="text-xs text-gray-500">
            {summary.edge_count === 0
              ? 'No edges yet — producer/consumer and auth-boundary edges populate from a dual-user (BOLA) scan.'
              : 'No edges match the current filters.'}
          </p>
        ) : (
          <div className="space-y-1 max-h-[32rem] overflow-y-auto">
            {visibleEdges.map((edge) => (
              <div key={edge.id} className="rounded border border-gray-800 bg-gray-950 p-2 text-xs">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="rounded bg-purple-900/40 px-1.5 py-0.5 text-purple-200">{edge.edge_type}</span>
                  <button type="button" onClick={() => setSelectedNodeKey(edge.src_key)} className="font-mono text-gray-200 hover:text-blue-300 break-all">
                    {keyLabel(edge.src_key)}
                  </button>
                  <span className="text-gray-500">→</span>
                  <button type="button" onClick={() => setSelectedNodeKey(edge.dst_key)} className="font-mono text-gray-200 hover:text-blue-300 break-all">
                    {keyLabel(edge.dst_key)}
                  </button>
                </div>
                {edge.attributes && Object.keys(edge.attributes).length > 0 && (
                  <pre className="mt-2 max-h-40 overflow-auto rounded bg-gray-900 p-2 text-gray-400">
                    {JSON.stringify(edge.attributes, null, 2)}
                  </pre>
                )}
              </div>
            ))}
          </div>
        )}
      </SectionCard>
    </div>
  )
}

export default function ApplicationGraphPage() {
  return <GraphContent />
}
