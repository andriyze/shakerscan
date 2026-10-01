'use client'

import { useEffect, useId, useRef, useState } from 'react'
import { ChevronRight } from 'lucide-react'
import Link from '@/components/WorkspaceLink'
import { type Finding } from '@/lib/api'
import { SEVERITY_RAIL_CLASSES, type FindingSourceType, type SeverityLevel } from '@/lib/constants'
import { cn } from '@/lib/cn'
import { formatRelativeTime } from '@/lib/format'
import { findingLocation, type FindingGroup } from '@/lib/findingGroups'
import { FindingStatusBadge, ProofStateBadge, SeverityBadge } from '@/components/ui'
import { FindingRow, FindingWhere, LastSeen, RetestNote, findingFacts } from '@/app/findings/FindingRow'

function GroupCheckbox({ label, checked, indeterminate, onChange }: {
  label: string
  checked: boolean
  indeterminate: boolean
  onChange: (checked: boolean) => void
}) {
  const ref = useRef<HTMLInputElement>(null)
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = indeterminate
  }, [indeterminate])
  return (
    <input
      ref={ref}
      type="checkbox"
      aria-label={label}
      checked={checked}
      onChange={(event) => onChange(event.target.checked)}
      className="h-4 w-4 rounded-sm border-gray-600 bg-gray-900 text-blue-600 focus:ring-blue-500"
    />
  )
}

/**
 * One issue observed at several locations of one subject, in one proof and triage state. A group
 * of one is a plain row. A larger group is a single line with a count that expands in place to
 * its locations, each linking to its own finding. Selecting the group selects every member.
 */
export function FindingGroupRow({
  group,
  hrefFor,
  sourceType,
  selecting,
  selectedIds,
  onToggle,
  showStatus,
}: {
  group: FindingGroup<Finding>
  hrefFor: (finding: Finding) => string
  sourceType: FindingSourceType
  selecting: boolean
  selectedIds: ReadonlySet<string>
  onToggle: (ids: string[], checked: boolean) => void
  showStatus: boolean
}) {
  const [expanded, setExpanded] = useState(false)
  const membersId = useId()
  const { lead, members } = group

  if (members.length === 1) {
    return (
      <FindingRow
        finding={lead}
        href={hrefFor(lead)}
        sourceType={sourceType}
        selecting={selecting}
        selected={selectedIds.has(lead.id)}
        onToggle={(checked) => onToggle([lead.id], checked)}
        showStatus={showStatus}
      />
    )
  }

  const rail = SEVERITY_RAIL_CLASSES[lead.severity as SeverityLevel] ?? SEVERITY_RAIL_CLASSES.info
  const selectable = members.filter((member) => !member.is_candidate)
  const selectedCount = selectable.filter((member) => selectedIds.has(member.id)).length
  const facts = findingFacts(lead)

  return (
    <div className="border-t border-t-gray-800 first:border-t-0">
      <div className={cn('flex items-stretch border-l-[3px]', rail, selectedCount > 0 && 'bg-blue-500/5')}>
        {selecting && (
          <div className="flex w-10 shrink-0 items-center justify-center">
            {selectable.length > 0 && (
              <GroupCheckbox
                label={`Select ${selectable.length} findings: ${lead.title}`}
                checked={selectedCount === selectable.length}
                indeterminate={selectedCount > 0 && selectedCount < selectable.length}
                onChange={(checked) => onToggle(selectable.map((member) => member.id), checked)}
              />
            )}
          </div>
        )}
        <button
          type="button"
          aria-expanded={expanded}
          aria-controls={membersId}
          onClick={() => setExpanded((open) => !open)}
          className={cn(
            'flex min-w-0 flex-1 flex-col gap-1 py-2 pr-4 text-left transition-colors hover:bg-gray-800/50 sm:flex-row sm:items-center sm:gap-3',
            'focus:outline-hidden focus-visible:bg-gray-800/50 focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-500',
            selecting ? 'pl-1' : 'pl-3'
          )}
        >
          <span className="flex shrink-0 items-center gap-1.5 sm:w-44">
            <SeverityBadge severity={lead.severity} />
            <ProofStateBadge proofState={lead.proof_state} />
          </span>
          <span className="flex min-w-0 flex-1 items-center gap-2">
            <ChevronRight
              className={cn('h-3.5 w-3.5 shrink-0 text-gray-500 transition-transform', expanded && 'rotate-90')}
              aria-hidden="true"
            />
            <span className="line-clamp-2 text-sm font-medium text-gray-100 sm:truncate" title={facts || undefined}>{lead.title}</span>
            <span className="shrink-0 rounded-sm bg-gray-800 px-1.5 text-xs font-semibold tabular-nums text-gray-300">
              ×{members.length}
            </span>
          </span>
          <span className="flex min-w-0 items-center gap-3 text-xs sm:max-w-[48%]">
            <FindingWhere finding={lead} sourceType={sourceType} more={members.length - 1} />
            {showStatus && <FindingStatusBadge status={lead.status} />}
            <LastSeen value={group.lastSeenAt} />
          </span>
        </button>
      </div>
      {expanded && (
        <ul id={membersId} aria-label={`${members.length} locations of ${lead.title}`} className="border-l-[3px] border-l-transparent bg-gray-950/40">
          {members.map((member) => {
            const location = findingLocation(member) || member.url || 'no route recorded'
            const memberSelectable = selecting && !member.is_candidate
            return (
              <li key={member.id} className="flex items-stretch border-t border-t-gray-800/70">
                {selecting && (
                  <div className="flex w-10 shrink-0 items-center justify-center">
                    {memberSelectable && (
                      <input
                        type="checkbox"
                        aria-label={`Select finding ${member.title} at ${location}`}
                        checked={selectedIds.has(member.id)}
                        onChange={(event) => onToggle([member.id], event.target.checked)}
                        className="h-4 w-4 rounded-sm border-gray-600 bg-gray-900 text-blue-600 focus:ring-blue-500"
                      />
                    )}
                  </div>
                )}
                <Link
                  href={hrefFor(member)}
                  title={member.url || undefined}
                  className={cn(
                    'flex min-w-0 flex-1 items-center gap-3 py-1.5 pr-4 text-xs transition-colors hover:bg-gray-800/50',
                    'focus:outline-hidden focus-visible:bg-gray-800/50 focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-500',
                    selecting ? 'pl-1 sm:pl-[13.375rem]' : 'pl-3 sm:pl-[13.875rem]'
                  )}
                >
                  <span className="min-w-0 flex-1 truncate font-mono text-gray-300">{location}</span>
                  <RetestNote finding={member} />
                  <time
                    dateTime={member.last_seen_at || undefined}
                    className="w-16 shrink-0 text-right tabular-nums text-gray-500"
                  >
                    {formatRelativeTime(member.last_seen_at)}
                  </time>
                </Link>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
