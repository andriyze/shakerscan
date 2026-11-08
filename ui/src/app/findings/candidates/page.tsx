'use client'

import { useCallback, useEffect, useState } from 'react'
import Link from '@/components/WorkspaceLink'
import {
  formatDate,
  getInvestigationCandidates,
  type InvestigationCandidate,
  type InvestigationCandidateStatus,
} from '@/lib/api'
import {
  candidatePageRange,
  groupCandidatesByTarget,
} from '@/lib/candidateGroups.mjs'
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

const PAGE_SIZE = 50

export default function InvestigationCandidatesPage() {
  const [candidates, setCandidates] = useState<InvestigationCandidate[]>([])
  const [total, setTotal] = useState(0)
  const [unversioned, setUnversioned] = useState(0)
  const [offset, setOffset] = useState(0)
  const [plane, setPlane] = useState<'' | 'web' | 'device'>('')
  const [showTerminal, setShowTerminal] = useState(false)
  const [showUnversioned, setShowUnversioned] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError(false)
    try {
      const filter = {
        plane: plane || undefined,
        status: showTerminal ? undefined : OPEN_STATUSES,
      }
      const [page, hidden] = await Promise.all([
        getInvestigationCandidates({
          ...filter,
          unversioned_advisories: showUnversioned ? 'include' : 'exclude',
          limit: PAGE_SIZE,
          offset,
        }),
        getInvestigationCandidates({ ...filter, unversioned_advisories: 'only', limit: 1 }),
      ])
      setCandidates(page.candidates || [])
      setTotal(page.total || 0)
      setUnversioned(hidden.total || 0)
    } catch {
      setError(true)
    } finally {
      setLoading(false)
    }
  }, [plane, showTerminal, showUnversioned, offset])

  useEffect(() => { void load() }, [load])

  const groups = groupCandidatesByTarget(candidates)
  const pager = total > PAGE_SIZE && (
    <nav aria-label="Candidate pages" className="flex flex-wrap items-center justify-between gap-3 text-sm text-gray-400">
      <span>{candidatePageRange({ offset, count: candidates.length, total })}</span>
      <span className="flex gap-2">
        <button
          type="button"
          className={buttonClasses('secondary', 'sm')}
          disabled={offset === 0 || loading}
          onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
        >
          Previous
        </button>
        <button
          type="button"
          className={buttonClasses('secondary', 'sm')}
          disabled={offset + PAGE_SIZE >= total || loading}
          onClick={() => setOffset(offset + PAGE_SIZE)}
        >
          Next
        </button>
      </span>
    </nav>
  )

  return (
    <div className="space-y-6">
      <PageHeader
        title="Investigation candidates"
        description="Evidence-backed Hunt claims awaiting deterministic proof. Candidates are not findings and never carry promotion authority."
        backHref="/findings"
        backLabel="Back to verified findings"
      />

      <Card className="flex flex-wrap items-center gap-4 p-4">
        <label className="flex items-center gap-2 text-sm text-gray-400">
          Plane
          <select
            value={plane}
            onChange={event => { setPlane(event.target.value as '' | 'web' | 'device'); setOffset(0) }}
            className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-gray-200"
          >
            <option value="">Web and devices</option>
            <option value="web">Hunt · web/API</option>
            <option value="device">Hunt · device</option>
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm text-gray-400">
          <input
            type="checkbox"
            checked={showTerminal}
            onChange={event => { setShowTerminal(event.target.checked); setOffset(0) }}
            className="rounded-sm border-gray-700 bg-gray-900"
          />
          Include verified, refuted, and expired
        </label>
        {(unversioned > 0 || showUnversioned) && (
          <label className="flex items-center gap-2 text-sm text-gray-400">
            <input
              type="checkbox"
              checked={showUnversioned}
              onChange={event => { setShowUnversioned(event.target.checked); setOffset(0) }}
              className="rounded-sm border-gray-700 bg-gray-900"
            />
            Show {unversioned} advisory match{unversioned === 1 ? '' : 'es'} without a version
          </label>
        )}
        <span className="ml-auto text-xs text-gray-500" data-testid="candidate-total">
          {total} candidate{total === 1 ? '' : 's'}
          {!showUnversioned && unversioned > 0 ? ` · ${unversioned} advisory match${unversioned === 1 ? '' : 'es'} without a version hidden` : ''}
        </span>
      </Card>

      {loading ? <TableSkeleton rows={8} /> : error ? (
        <ErrorState message="Candidates could not be loaded." onRetry={() => void load()} />
      ) : candidates.length === 0 ? (
        <EmptyState
          message="No investigation candidates"
          hint={!showUnversioned && unversioned > 0
            ? `${unversioned} advisory match${unversioned === 1 ? '' : 'es'} without a known product version ${unversioned === 1 ? 'is' : 'are'} hidden.`
            : 'New hunt claims will appear here before they become verified findings.'}
        />
      ) : (
        <div className="space-y-6">
          {pager}
          {groups.map(group => (
            <section key={group.key} aria-label={`Candidates on ${group.label}`} className="space-y-3">
              <h2 className="flex flex-wrap items-baseline gap-2 text-sm font-semibold text-gray-200">
                <span className="break-all">{group.label}</span>
                <span className="text-xs font-normal text-gray-500">
                  {group.candidates.length} on this page
                </span>
              </h2>
              {group.candidates.map(candidate => {
                const sourceHref = candidate.plane === 'device'
                  ? `/devices/${candidate.device_target_id}/agent`
                  : `/hunt?target_id=${encodeURIComponent(candidate.target_id || '')}`
                return (
                  <Card key={candidate.id} className="p-4" data-testid="candidate-card">
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <SeverityBadge severity={candidate.claimed_severity} />
                          <span className="rounded-sm bg-amber-500/10 px-2 py-1 text-xs text-amber-300">
                            {candidate.status.replace(/_/g, ' ')}
                          </span>
                          <span className="rounded-sm bg-gray-800 px-2 py-1 text-xs text-gray-400">
                            {candidate.plane === 'device' ? 'Hunt · device' : 'Hunt · web/API'}
                          </span>
                          <span className="break-all text-xs text-gray-400">on {group.label}</span>
                        </div>
                        <h3 className="mt-3 break-words font-medium text-gray-100">{candidate.title}</h3>
                        {candidate.claim.trim().toLowerCase() !== candidate.title.trim().toLowerCase() && (
                          <p className="mt-1 break-words text-sm text-gray-400">{candidate.claim}</p>
                        )}
                        <p className="mt-2 break-words text-xs text-gray-500">
                          {candidate.family.replace(/_/g, ' ')} · {candidate.verifier_contract_id || 'no verifier available'} · observed {candidate.observation_count || 1} time{(candidate.observation_count || 1) === 1 ? '' : 's'} · last {formatDate(candidate.last_seen_at)}
                        </p>
                      </div>
                      <Link href={sourceHref} className={buttonClasses('secondary', 'sm')}>
                        Open Hunt
                      </Link>
                    </div>
                  </Card>
                )
              })}
            </section>
          ))}
          {pager}
        </div>
      )}
    </div>
  )
}
