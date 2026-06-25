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

  const routes = useMemo(
    () => (graph?.nodes || []).filter((n) => n.node_type === 'route'),
    [graph]
  )
  const objects = useMemo(
    () => (graph?.nodes || []).filter((n) => n.node_type === 'object'),
    [graph]
  )
  const authBoundaries = useMemo(
    () => (graph?.edges || []).filter((e) => e.edge_type === 'auth_boundary'),
    [graph]
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
                <div
                  key={n.id}
                  className="flex items-center justify-between gap-2 text-xs py-1 border-b border-gray-800/60"
                >
                  <span className="font-mono text-gray-300 break-all">{nodeLabel(n)}</span>
                  {n.attributes?.role ? (
                    <span className="shrink-0 px-1.5 py-0.5 rounded bg-gray-800 text-gray-400">
                      {String(n.attributes.role)}
                    </span>
                  ) : null}
                </div>
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
                  <div key={n.id} className="text-xs py-1 border-b border-gray-800/60">
                    <span className="font-mono text-gray-300">{nodeLabel(n)}</span>
                    {sensitive.length > 0 ? (
                      <span className="ml-2 text-amber-300">[{sensitive.join(', ')}]</span>
                    ) : null}
                  </div>
                )
              })}
            </div>
          )}
        </SectionCard>
      </div>
    </div>
  )
}

export default function ApplicationGraphPage() {
  return <GraphContent />
}
