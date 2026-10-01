'use client'

import Link from '@/components/WorkspaceLink'
import { type Finding } from '@/lib/api'
import { SEVERITY_RAIL_CLASSES, type FindingSourceType, type SeverityLevel } from '@/lib/constants'
import { cn } from '@/lib/cn'
import { formatRelativeTime } from '@/lib/format'
import { findingHost, findingLocation, findingSubject, retestSignal } from '@/lib/findingGroups'
import {
  FindingStatusBadge,
  ProofStateBadge,
  SeverityBadge,
} from '@/components/ui'

const RETEST_TONES = {
  danger: 'text-red-300',
  success: 'text-emerald-300',
  muted: 'text-gray-400',
} as const

/** Tool, CWE and CVSS belong to the detail page; the row keeps them as a hover hint. */
export function findingFacts(finding: Finding): string {
  const hasCvss = finding.cvss_score !== undefined && finding.cvss_score !== null
  return [finding.tool, finding.cwe, hasCvss ? `CVSS ${finding.cvss_score}` : undefined]
    .filter((fact): fact is string => Boolean(fact))
    .join(' · ')
}

function absoluteTime(value: string | null | undefined): string | undefined {
  if (!value) return undefined
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? undefined : `Last seen ${date.toLocaleString()}`
}

/** The latest retest, rendered only when it adds something the row does not already say. */
export function RetestNote({ finding }: { finding: Finding }) {
  const signal = retestSignal(finding.latest_retest_verdict, finding.status)
  if (!signal) return null
  return (
    <span className={cn('shrink-0 text-xs font-medium', RETEST_TONES[signal.tone])} title={signal.title}>
      {signal.label}
    </span>
  )
}

/** Where it is: the subject (host, AI endpoint or device) muted, the route readable. */
export function FindingWhere({ finding, sourceType, more = 0 }: {
  finding: Finding
  sourceType?: FindingSourceType
  /** Further locations of the same group, shown as "+N". */
  more?: number
}) {
  const subject = findingSubject(finding)
  const location = findingLocation(finding)
  const source = sourceType && sourceType !== 'DAST' ? sourceType : ''
  if (!subject && !location && !source) return null
  // A host and its route read as one address; an AI target or device name is set apart.
  const joined = Boolean(subject && location && subject === findingHost(finding))
  return (
    <span className="min-w-0 truncate text-xs" title={finding.url || subject || undefined}>
      {source && <span className="text-gray-500">{source}{(subject || location) && ' · '}</span>}
      {subject && <span className="text-gray-500">{subject}{location && !joined ? ' · ' : ''}</span>}
      {location && <span className="font-mono text-gray-300">{location}</span>}
      {more > 0 && <span className="text-gray-500">{` +${more} more`}</span>}
    </span>
  )
}

export function LastSeen({ value }: { value: string | null | undefined }) {
  return (
    <time
      dateTime={value || undefined}
      title={absoluteTime(value)}
      className="w-16 shrink-0 text-right text-xs tabular-nums text-gray-500"
    >
      {formatRelativeTime(value)}
    </time>
  )
}

/**
 * One finding on one line: severity and proof in a fixed column so titles align, the title,
 * where it was observed, and when. The 3px left rail carries the severity color so a page of
 * rows reads as the shape of the backlog. The checkbox column only exists in selection mode;
 * investigation candidates are never selectable. Status shows only in a mixed-status view.
 */
export function FindingRow({
  finding,
  href,
  sourceType,
  selecting,
  selected,
  onToggle,
  showStatus = true,
}: {
  finding: Finding
  href: string
  sourceType: FindingSourceType
  selecting: boolean
  selected: boolean
  onToggle: (checked: boolean) => void
  showStatus?: boolean
}) {
  const rail = SEVERITY_RAIL_CLASSES[finding.severity as SeverityLevel] ?? SEVERITY_RAIL_CLASSES.info
  const selectable = selecting && !finding.is_candidate
  const facts = findingFacts(finding)

  return (
    // Per-side border colors on purpose: a parent `divide-*` color utility would outrank the
    // rail color on every row after the first.
    <div className={cn('flex items-stretch border-t border-t-gray-800 border-l-[3px] transition-colors first:border-t-0', rail, selected && 'bg-blue-500/5')}>
      {selecting && (
        <div className="flex w-10 shrink-0 items-center justify-center">
          {selectable && (
            <input
              type="checkbox"
              aria-label={`Select finding ${finding.title}`}
              checked={selected}
              onChange={(event) => onToggle(event.target.checked)}
              className="h-4 w-4 rounded-sm border-gray-600 bg-gray-900 text-blue-600 focus:ring-blue-500"
            />
          )}
        </div>
      )}
      <Link
        href={href}
        className={cn(
          'flex min-w-0 flex-1 flex-col gap-1 py-2 pr-4 transition-colors hover:bg-gray-800/50 sm:flex-row sm:items-center sm:gap-3',
          'focus:outline-hidden focus-visible:bg-gray-800/50 focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-500',
          selecting ? 'pl-1' : 'pl-3'
        )}
      >
        <span className="flex shrink-0 items-center gap-1.5 sm:w-44">
          <SeverityBadge severity={finding.severity} />
          <ProofStateBadge proofState={finding.proof_state} />
        </span>
        {/* Same width as a group row's chevron, so every title starts in one column. */}
        <span className="flex min-w-0 flex-1 items-center gap-2">
          <span className="hidden w-3.5 shrink-0 sm:block" aria-hidden="true" />
          <span className="line-clamp-2 text-sm font-medium text-gray-100 sm:truncate" title={facts || undefined}>
            {finding.title}
          </span>
        </span>
        <span className="flex min-w-0 items-center gap-3 sm:max-w-[48%]">
          <FindingWhere finding={finding} sourceType={sourceType} />
          <RetestNote finding={finding} />
          {showStatus && <FindingStatusBadge status={finding.status} />}
          <LastSeen value={finding.last_seen_at} />
        </span>
      </Link>
    </div>
  )
}
