'use client'

import { useCallback, useEffect, useState } from 'react'
import Link from 'next/link'
import {
  formatDate,
  getInvestigationCandidates,
  type InvestigationCandidate,
  type InvestigationCandidateStatus,
} from '@/lib/api'
import {
  Card,
  EmptyState,
  ErrorState,
  PageHeader,
  SeverityBadge,
  TableSkeleton,
  buttonClasses,
} from '@/components/ui'

const OPEN_STATUSES: InvestigationCandidateStatus[] = [
  'new', 'verification_queued', 'verifying', 'inconclusive', 'blocked',
]

export default function InvestigationCandidatesPage() {
  const [candidates, setCandidates] = useState<InvestigationCandidate[]>([])
  const [plane, setPlane] = useState<'' | 'web' | 'device'>('')
  const [showTerminal, setShowTerminal] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError(false)
    try {
      const requests = showTerminal
        ? [getInvestigationCandidates({ plane: plane || undefined, limit: 500 })]
        : OPEN_STATUSES.map(status => getInvestigationCandidates({
            plane: plane || undefined,
            status,
            limit: 500,
          }))
      const results = await Promise.all(requests)
      const unique = new Map<string, InvestigationCandidate>()
      for (const result of results) {
        for (const candidate of result.candidates || []) unique.set(candidate.id, candidate)
      }
      setCandidates([...unique.values()].sort(
        (left, right) => Date.parse(right.last_seen_at) - Date.parse(left.last_seen_at),
      ))
    } catch {
      setError(true)
    } finally {
      setLoading(false)
    }
  }, [plane, showTerminal])

  useEffect(() => { void load() }, [load])

  return (
    <div className="space-y-6">
      <PageHeader
        title="Investigation candidates"
        description="Evidence-backed Deep Hunt and Device Hunt claims awaiting deterministic proof. Candidates are not findings and never carry promotion authority."
        backHref="/findings"
        backLabel="Back to verified findings"
      />

      <Card className="flex flex-wrap items-center gap-4 p-4">
        <label className="flex items-center gap-2 text-sm text-gray-400">
          Plane
          <select
            value={plane}
            onChange={event => setPlane(event.target.value as '' | 'web' | 'device')}
            className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-gray-200"
          >
            <option value="">Web and devices</option>
            <option value="web">Deep Hunt</option>
            <option value="device">Device Hunt</option>
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm text-gray-400">
          <input
            type="checkbox"
            checked={showTerminal}
            onChange={event => setShowTerminal(event.target.checked)}
            className="rounded border-gray-700 bg-gray-900"
          />
          Include verified, refuted, and expired
        </label>
        <span className="ml-auto text-xs text-gray-500">{candidates.length} visible</span>
      </Card>

      {loading ? <TableSkeleton rows={8} /> : error ? (
        <ErrorState message="Candidates could not be loaded." onRetry={() => void load()} />
      ) : candidates.length === 0 ? (
        <EmptyState message="No investigation candidates" hint="New hunt claims will appear here before they become verified findings." />
      ) : (
        <div className="space-y-3">
          {candidates.map(candidate => {
            const sourceHref = candidate.plane === 'device'
              ? `/devices/${candidate.device_target_id}/agent`
              : `/deep-hunt?target_id=${encodeURIComponent(candidate.target_id || '')}`
            return (
              <Card key={candidate.id} className="p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={candidate.claimed_severity} />
                      <span className="rounded bg-amber-500/10 px-2 py-1 text-xs text-amber-300">
                        {candidate.status.replace(/_/g, ' ')}
                      </span>
                      <span className="rounded bg-gray-800 px-2 py-1 text-xs text-gray-400">
                        {candidate.plane === 'device' ? 'Device Hunt' : 'Deep Hunt'}
                      </span>
                    </div>
                    <h2 className="mt-3 font-medium text-gray-100">{candidate.title}</h2>
                    <p className="mt-1 text-sm text-gray-400">{candidate.claim}</p>
                    <p className="mt-2 text-xs text-gray-500">
                      {candidate.family.replace(/_/g, ' ')} · {candidate.verifier_contract_id || 'no verifier available'} · observed {candidate.observation_count || 1} time{(candidate.observation_count || 1) === 1 ? '' : 's'} · last {formatDate(candidate.last_seen_at)}
                    </p>
                  </div>
                  <Link href={sourceHref} className={buttonClasses('secondary', 'sm')}>
                    Open {candidate.plane === 'device' ? 'Device Hunt' : 'Deep Hunt'}
                  </Link>
                </div>
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}
