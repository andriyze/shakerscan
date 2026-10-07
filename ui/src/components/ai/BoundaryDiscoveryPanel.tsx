'use client'

import { useEffect, useRef, useState } from 'react'
import {
  discoverBoundaryDrafts, prepareBoundaryCandidate,
  type BoundaryDiscovery, type BoundaryDiscoveryDraft,
} from '@/lib/aiBoundary'

export function BoundaryDiscoveryPanel({ huntId, canPrepare, targetEndpoint, onPrepared }: {
  huntId: string
  canPrepare: boolean
  targetEndpoint?: string
  onPrepared: (candidateId: string, draft: BoundaryDiscoveryDraft) => void
}) {
  const [result, setResult] = useState<BoundaryDiscovery | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [prepared, setPrepared] = useState<string[]>([])
  const generation = useRef(0)
  useEffect(() => {
    generation.current += 1
    setResult(null)
    setError('')
    setPrepared([])
    setBusy(false)
  }, [huntId, targetEndpoint])
  // A service match is needed for relative fixture paths. Shared origin still
  // does not establish an agent/resource delegation relationship.
  function matches(draft: BoundaryDiscoveryDraft) {
    try {
      const endpoint = new URL(targetEndpoint || '')
      return endpoint.origin === draft.origin && draft.agent_paths.includes(endpoint.pathname)
    } catch { return false }
  }
  async function discover() {
    const current = generation.current
    setBusy(true)
    setError('')
    try {
      const value = await discoverBoundaryDrafts(huntId)
      if (current === generation.current) setResult(value)
    } catch (cause) {
      if (current === generation.current) setError(cause instanceof Error ? cause.message : 'Discovery failed')
    } finally {
      if (current === generation.current) setBusy(false)
    }
  }
  async function prepare(draft: BoundaryDiscoveryDraft) {
    const current = generation.current
    setBusy(true)
    setError('')
    try {
      const value = await prepareBoundaryCandidate(huntId, draft)
      if (current === generation.current) {
        setPrepared((ids) => [...ids, draft.draft_id])
        onPrepared(value.candidate.id, draft)
      }
    } catch (cause) {
      if (current === generation.current) setError(cause instanceof Error ? cause.message : 'Preparation failed')
    } finally {
      if (current === generation.current) setBusy(false)
    }
  }
  const button = 'rounded-lg border border-blue-500/50 px-3 py-2 text-sm text-blue-100 disabled:opacity-40'
  return <div className="space-y-3 rounded-lg border border-gray-700 p-3">
    <h3 className="font-medium text-white">Discover from Hunt traffic</h3>
    <p className="text-sm text-gray-400">Review possible read boundaries from stored captures. Confirm the application relationship, controlled fixtures and principal facts before verification.</p>
    <button className={button} disabled={!huntId || busy} onClick={discover}>Discover boundary drafts</button>
    {error && <p role="alert" className="text-sm text-red-300">{error}</p>}
    {result && <p className="text-xs text-gray-400">
      {result.coverage.captures_read} captures inspected · {result.coverage.structure_unavailable} without usable structure.
      {(result.coverage.captures_truncated || result.coverage.drafts_truncated || result.coverage.action_leads_truncated) && ' Bounded results; coverage is partial.'}
      {' Historical captures are not backfilled.'}
      {result.drafts.length === 0 && ' No compatible resource pair found.'}
    </p>}
    {(result?.action_leads?.length || 0) > 0 && <details className="rounded-lg border border-gray-800 bg-gray-950 p-3 text-sm text-gray-300">
      <summary className="cursor-pointer font-medium">Observed non-GET workflow leads · {result?.action_leads?.length}</summary>
      <p className="mt-2 text-xs text-gray-500">These are observations only. ShakerScan has not established that they change state, are forbidden, or can be replayed safely.</p>
      <div className="mt-2 space-y-2">
        {result?.action_leads?.map((lead, index) => <div key={`${lead.method}:${lead.origin}${lead.path}:${lead.principal_slot || ''}:${index}`} className="rounded border border-gray-800 p-2 text-xs">
          <p className="break-all">{lead.method} {lead.origin}{lead.path}{lead.principal_slot ? ` · ${lead.principal_slot}` : ''}</p>
          <p className="mt-1 text-amber-300">Needs: {lead.missing_facts.join(', ')}</p>
        </div>)}
      </div>
    </details>}
    {result?.drafts.map((draft) => <div key={draft.draft_id} className="space-y-2 rounded-lg bg-gray-950 p-3 text-sm text-gray-300">
      <p className="break-all">{draft.origin}{String((draft.fixture_prefill.resource as Record<string, unknown>).path)}</p>
      <p>Primary resource: {draft.fixture_prefill.owner.resource_id} · Secondary resource: {draft.fixture_prefill.attacker.resource_id}</p>
      <p className="text-xs text-amber-300">Missing or unverified: {draft.missing_facts.join(', ')}</p>
      <details className="text-xs"><summary className="cursor-pointer">Field evidence</summary>
        {Object.entries(draft.field_provenance).map(([field, sources]) => <p key={field} className="mt-1 break-all">{field}: {sources.map((source) => `${source.capture_id} (action ${source.action_id})`).join(', ')}</p>)}
      </details>
      {!matches(draft) && <p className="text-xs text-amber-300">Select the configured AI endpoint observed on this exact service: {draft.agent_paths.join(', ') || 'agent endpoint evidence missing'}.</p>}
      <button className={button} disabled={busy || !canPrepare || !matches(draft) || prepared.includes(draft.draft_id)} onClick={() => prepare(draft)}>
        {prepared.includes(draft.draft_id) ? 'Candidate prepared' : 'Prepare candidate and fixture'}
      </button>
    </div>)}
    <p className="text-xs text-gray-500">Discovery sends no target traffic. Preparation saves an unverified candidate using the Hunt candidate budget; verification is queued separately. Preparation requires an active Hunt.</p>
  </div>
}
