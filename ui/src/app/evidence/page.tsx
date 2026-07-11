'use client'

import { useCallback, useEffect, useState, Suspense } from 'react'
import Link from 'next/link'
import { getEvidenceInstances, formatDate, type EvidenceInstance } from '@/lib/api'
import { useUrlFilters } from '@/lib/useUrlFilters'
import {
  Card,
  EmptyState,
  ErrorState,
  LastUpdated,
  ProofStateBadge,
  RetentionClassBadge,
  SectionCard,
  TableSkeleton,
} from '@/components/ui'
import EvidenceRetentionPanel from '@/components/EvidenceRetentionPanel'
import EvidenceObjectModal from '@/components/EvidenceObjectModal'

interface EvidenceFilters {
  [key: string]: string | number | undefined
  finding_id?: string
  tool_receipt_id?: string
}

function EvidenceContent() {
  const { filters, setFilter } = useUrlFilters<EvidenceFilters>()

  const [instances, setInstances] = useState<EvidenceInstance[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [modalObjectId, setModalObjectId] = useState<string | null>(null)
  const [findingInput, setFindingInput] = useState<string>(filters.finding_id || '')

  const findingFilter = (filters.finding_id || '').trim()
  const toolReceiptFilter = (filters.tool_receipt_id || '').trim()

  const load = useCallback(async () => {
    try {
      const res = await getEvidenceInstances({
        finding_id: findingFilter || undefined,
        tool_receipt_id: toolReceiptFilter || undefined,
        limit: 200,
      })
      setInstances(res.evidence_instances || [])
      setLoadError(false)
      setLastUpdated(new Date())
    } catch {
      setLoadError(true)
    } finally {
      setLoading(false)
    }
  }, [findingFilter, toolReceiptFilter])

  useEffect(() => {
    setLoading(true)
    load()
  }, [load])

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Evidence</h1>
          <p className="mt-1 text-gray-400">
            Content-addressed evidence instances split from findings, plus content-free export manifests, bundles, and retention sweeps.
          </p>
        </div>
        <LastUpdated updatedAt={lastUpdated} onRefresh={load} />
      </div>

      <Card className="p-4">
        <div className="flex flex-col gap-3 md:flex-row md:items-end">
          <div className="flex-1">
            <label htmlFor="ev-finding" className="mb-1 block text-xs font-medium text-gray-400">Filter by finding ID or fingerprint</label>
            <div className="flex gap-2">
              <input
                id="ev-finding"
                type="text"
                value={findingInput}
                onChange={(e) => setFindingInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') setFilter('finding_id', findingInput.trim() || undefined) }}
                placeholder="Finding UUID / fingerprint (optional)"
                className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-600 focus:border-blue-500 focus:outline-none"
              />
              <button
                type="button"
                onClick={() => setFilter('finding_id', findingInput.trim() || undefined)}
                className="rounded-lg bg-blue-600 px-3 py-2 text-sm text-white hover:bg-blue-500"
              >
                Apply
              </button>
              {findingFilter && (
                <button
                  type="button"
                  onClick={() => { setFindingInput(''); setFilter('finding_id', undefined) }}
                  className="rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800"
                >
                  Clear
                </button>
              )}
            </div>
          </div>
        </div>
      </Card>

      <SectionCard title={`Evidence instances${instances.length ? ` (${instances.length})` : ''}`}>
        {loadError ? (
          <ErrorState message="Failed to load evidence instances." onRetry={load} />
        ) : loading ? (
          <TableSkeleton rows={5} />
        ) : instances.length === 0 ? (
          <EmptyState
            message="No evidence instances"
            hint="Concrete evidence instances are recorded when proof-backed findings and tool receipts are split into durable evidence."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-800 text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wide text-gray-500">
                  <th className="px-3 py-2">Instance</th>
                  <th className="px-3 py-2">Proof</th>
                  <th className="px-3 py-2">Retention</th>
                  <th className="px-3 py-2">Finding</th>
                  <th className="px-3 py-2">Created</th>
                  <th className="px-3 py-2"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {instances.map((inst) => (
                  <tr key={inst.id} className="hover:bg-gray-800/40">
                    <td className="px-3 py-2">
                      <span className="font-mono text-xs text-gray-300">{inst.id.slice(0, 12)}…</span>
                      {inst.concrete_url && <p className="mt-0.5 max-w-xs truncate text-xs text-gray-500" title={inst.concrete_url}>{inst.concrete_url}</p>}
                    </td>
                    <td className="px-3 py-2">
                      {inst.proof_state ? <ProofStateBadge proofState={inst.proof_state as 'verified'} /> : <span className="text-xs text-gray-600">—</span>}
                    </td>
                    <td className="px-3 py-2"><RetentionClassBadge retentionClass={inst.retention_policy} /></td>
                    <td className="px-3 py-2">
                      {inst.finding_id ? (
                        <Link href={`/findings/${inst.finding_id}`} className="text-xs text-blue-400 hover:text-blue-300">
                          {inst.finding_id.slice(0, 10)}…
                        </Link>
                      ) : <span className="text-xs text-gray-600">—</span>}
                    </td>
                    <td className="px-3 py-2 text-gray-500">{inst.created_at ? formatDate(inst.created_at) : '—'}</td>
                    <td className="px-3 py-2 text-right">
                      {inst.evidence_object_id && (
                        <button
                          type="button"
                          onClick={() => setModalObjectId(inst.evidence_object_id!)}
                          className="text-xs text-blue-400 hover:text-blue-300"
                        >
                          View object
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>

      <EvidenceRetentionPanel findingId={findingFilter || undefined} />

      <EvidenceObjectModal objectId={modalObjectId} onClose={() => setModalObjectId(null)} />
    </div>
  )
}

export default function EvidencePage() {
  return (
    <Suspense fallback={
      <div className="flex h-32 items-center justify-center">
        <div className="h-6 w-6 animate-spin rounded-full border-b-2 border-blue-500"></div>
      </div>
    }>
      <EvidenceContent />
    </Suspense>
  )
}
