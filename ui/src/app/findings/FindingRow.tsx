'use client'

import Link from '@/components/WorkspaceLink'
import { formatDate, type Finding } from '@/lib/api'
import { SEVERITY_RAIL_CLASSES, type FindingSourceType, type SeverityLevel } from '@/lib/constants'
import { cn } from '@/lib/cn'
import {
  FindingStatusBadge,
  ProofStateBadge,
  RetestVerdictBadge,
  SeverityBadge,
  SourceTypeBadge,
} from '@/components/ui'

/**
 * One finding in the list. The 3px left rail carries the severity color so a page of rows
 * reads as the shape of the backlog. The checkbox column only exists in selection mode;
 * investigation candidates are never selectable.
 */
export function FindingRow({
  finding,
  href,
  sourceType,
  selecting,
  selected,
  onToggle,
}: {
  finding: Finding
  href: string
  sourceType: FindingSourceType
  selecting: boolean
  selected: boolean
  onToggle: (checked: boolean) => void
}) {
  const rail = SEVERITY_RAIL_CLASSES[finding.severity as SeverityLevel] ?? SEVERITY_RAIL_CLASSES.info
  const selectable = selecting && !finding.is_candidate
  const hasCvss = finding.cvss_score !== undefined && finding.cvss_score !== null
  const facts = [
    finding.tool,
    finding.cwe,
    hasCvss ? `CVSS ${finding.cvss_score}` : undefined,
  ].filter((fact): fact is string => Boolean(fact))

  return (
    // Per-side border colors on purpose: a parent `divide-*` color utility would outrank the
    // rail color on every row after the first.
    <div className={cn('flex items-stretch border-t border-t-gray-800 border-l-[3px] transition-colors first:border-t-0', rail, selected && 'bg-blue-500/5')}>
      {selecting && (
        <div className="flex w-10 shrink-0 items-start justify-center pt-[18px]">
          {selectable && (
            <input
              type="checkbox"
              aria-label={`Select finding ${finding.title}`}
              checked={selected}
              onChange={(event) => onToggle(event.target.checked)}
              className="h-4 w-4 rounded border-gray-600 bg-gray-900 text-blue-600 focus:ring-blue-500"
            />
          )}
        </div>
      )}
      <Link
        href={href}
        className={cn(
          'block min-w-0 flex-1 py-3.5 pr-4 transition-colors hover:bg-gray-800/50',
          'focus:outline-none focus-visible:bg-gray-800/50 focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-500',
          selecting ? 'pl-1' : 'pl-4'
        )}
      >
        <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:gap-3">
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <ProofStateBadge proofState={finding.proof_state} />
            <SourceTypeBadge type={sourceType} />
          </div>
          <div className="min-w-0 flex-1">
            <h3 className="text-sm font-medium text-white">{finding.title}</h3>
            {facts.length > 0 && (
              <p className="mt-1 flex flex-wrap items-center gap-x-1.5 text-xs text-gray-500 tabular-nums">
                {facts.map((fact, index) => (
                  <span key={fact} className="contents">
                    {index > 0 && <span aria-hidden="true">·</span>}
                    <span>{fact}</span>
                  </span>
                ))}
              </p>
            )}
            <p className="mt-0.5 text-xs text-gray-500">
              First seen {formatDate(finding.first_seen_at)}
              <span aria-hidden="true"> · </span>
              Last seen {formatDate(finding.last_seen_at)}
            </p>
            {finding.url && <p className="mt-1 truncate text-xs text-gray-600">{finding.url}</p>}
          </div>
          <div className="flex shrink-0 flex-wrap items-center gap-2 sm:ml-auto">
            {finding.latest_retest_verdict && <RetestVerdictBadge verdict={finding.latest_retest_verdict} />}
            <FindingStatusBadge status={finding.status} />
          </div>
        </div>
      </Link>
    </div>
  )
}
