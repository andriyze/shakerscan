'use client'

import { useCallback, useEffect, useState, Suspense } from 'react'
import Link from 'next/link'
import { getMissionTimeline, formatDate, type TimelineEvent } from '@/lib/api'
import { useUrlFilters } from '@/lib/useUrlFilters'
import {
  Card,
  EmptyState,
  ErrorState,
  LastUpdated,
  RiskTierBadge,
  SectionCard,
  TableSkeleton,
  TimelineStatusBadge,
} from '@/components/ui'

const PAGE_SIZE = 100
const REFRESH_MS = 15000

// Each toggle maps a UI label to the GET /timeline include_* query flag. All
// default ON server-side; the URL only carries a flag when a category is OFF.
const KIND_TOGGLES: Array<{ key: string; label: string }> = [
  { key: 'include_campaign_actions', label: 'Campaign actions' },
  { key: 'include_scans', label: 'Scans' },
  { key: 'include_schedules', label: 'Schedules' },
  { key: 'include_evidence', label: 'Evidence' },
  { key: 'include_refuters', label: 'Refuters' },
  { key: 'include_exports', label: 'Exports' },
]

interface TimelineFilters {
  [key: string]: string | number | undefined
  target?: string
  include_campaign_actions?: string
  include_scans?: string
  include_schedules?: string
  include_evidence?: string
  include_refuters?: string
  include_exports?: string
}

function eventTitle(event: TimelineEvent): string {
  const raw = event.action_name || event.command || event.kind
  return raw.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase())
}

// Prefer an explicit next_action deep link, then a linked scan/campaign.
function eventHref(event: TimelineEvent): string | null {
  if (event.next_action && event.next_action.startsWith('/')) return event.next_action
  if (event.scan_id) return `/scans/${event.scan_id}`
  const campaignId = event.campaign_id || event.mission_campaign_id
  if (campaignId) return `/campaigns/${campaignId}`
  return null
}

function EventRow({ event }: { event: TimelineEvent }) {
  const href = eventHref(event)
  const timestamp = event.next_eligible_at || event.created_at
  return (
    <div className="flex flex-col gap-2 border-b border-gray-800 py-3 last:border-b-0 md:flex-row md:items-start md:justify-between">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <TimelineStatusBadge status={event.status} />
          <RiskTierBadge tier={event.risk_tier} />
          <span className="text-sm font-medium text-white">{eventTitle(event)}</span>
          <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-gray-400">
            {event.kind.replace(/_/g, ' ')}
          </span>
          {event.dry_run && (
            <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">dry run</span>
          )}
        </div>
        {event.operator_message && (
          <p className="mt-1 truncate text-sm text-gray-300" title={event.operator_message}>
            {event.operator_message}
          </p>
        )}
        <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-gray-500">
          {event.target_url && <span className="truncate max-w-xs">{event.target_url}</span>}
          {Array.isArray(event.blocked_by) && event.blocked_by.length > 0 && (
            <span className="text-amber-400">blocked by: {event.blocked_by.join(', ')}</span>
          )}
          {Array.isArray(event.finding_ids) && event.finding_ids.length > 0 && (
            <span>{event.finding_ids.length} finding{event.finding_ids.length === 1 ? '' : 's'}</span>
          )}
          {Array.isArray(event.evidence_object_ids) && event.evidence_object_ids.length > 0 && (
            <span>{event.evidence_object_ids.length} evidence</span>
          )}
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-3 text-xs text-gray-500">
        {timestamp && <span title={timestamp}>{formatDate(timestamp)}</span>}
        {href && (
          <Link href={href} className="text-blue-400 hover:text-blue-300">
            Open →
          </Link>
        )}
      </div>
    </div>
  )
}

function TimelineContent() {
  const { filters, setFilter } = useUrlFilters<TimelineFilters>()

  const [data, setData] = useState<{ events: TimelineEvent[]; upcoming: TimelineEvent[] } | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [targetInput, setTargetInput] = useState<string>(filters.target || '')

  const targetFilter = (filters.target || '').trim()

  const load = useCallback(async () => {
    try {
      const params: Parameters<typeof getMissionTimeline>[0] = { limit: PAGE_SIZE }
      if (targetFilter) params.target_id = targetFilter
      for (const { key } of KIND_TOGGLES) {
        if (filters[key] === 'false') {
          ;(params as Record<string, unknown>)[key] = false
        }
      }
      const res = await getMissionTimeline(params)
      setData({ events: res.events || [], upcoming: res.upcoming || [] })
      setLoadError(false)
      setLastUpdated(new Date())
    } catch {
      setLoadError(true)
    } finally {
      setLoading(false)
    }
  }, [targetFilter, filters])

  useEffect(() => {
    setLoading(true)
    load()
    const interval = setInterval(load, REFRESH_MS)
    return () => clearInterval(interval)
  }, [load])

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white">Mission Timeline</h1>
          <p className="mt-1 text-gray-400">
            Cross-product feed of command results, scans, schedules, evidence bindings, refuters, and exports.
          </p>
        </div>
        <LastUpdated updatedAt={lastUpdated} onRefresh={load} />
      </div>

      <Card className="p-4">
        <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
          <div className="flex-1">
            <label htmlFor="timeline-target" className="mb-1 block text-xs font-medium text-gray-400">
              Filter by target ID
            </label>
            <div className="flex gap-2">
              <input
                id="timeline-target"
                type="text"
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') setFilter('target', targetInput.trim() || undefined) }}
                placeholder="Target UUID (optional)"
                className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-600 focus:border-blue-500 focus:outline-none"
              />
              <button
                type="button"
                onClick={() => setFilter('target', targetInput.trim() || undefined)}
                className="rounded-lg bg-blue-600 px-3 py-2 text-sm text-white hover:bg-blue-500"
              >
                Apply
              </button>
              {targetFilter && (
                <button
                  type="button"
                  onClick={() => { setTargetInput(''); setFilter('target', undefined) }}
                  className="rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800"
                >
                  Clear
                </button>
              )}
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {KIND_TOGGLES.map(({ key, label }) => {
              const enabled = filters[key] !== 'false'
              return (
                <button
                  key={key}
                  type="button"
                  aria-pressed={enabled}
                  onClick={() => setFilter(key, enabled ? 'false' : undefined)}
                  className={`rounded-full border px-3 py-1 text-xs transition-colors ${
                    enabled
                      ? 'border-blue-500 bg-blue-600/20 text-blue-300'
                      : 'border-gray-700 text-gray-500 hover:bg-gray-800'
                  }`}
                >
                  {label}
                </button>
              )
            })}
          </div>
        </div>
      </Card>

      {loadError ? (
        <ErrorState message="Failed to load the mission timeline." onRetry={load} />
      ) : loading && !data ? (
        <TableSkeleton rows={8} />
      ) : (
        <>
          {data && data.upcoming.length > 0 && (
            <SectionCard title={`Upcoming (${data.upcoming.length})`}>
              <div className="px-1">
                {data.upcoming.map((event) => (
                  <EventRow key={event.event_id} event={event} />
                ))}
              </div>
            </SectionCard>
          )}
          <SectionCard title={`Recent activity${data ? ` (${data.events.length})` : ''}`}>
            {data && data.events.length > 0 ? (
              <div className="px-1">
                {data.events.map((event) => (
                  <EventRow key={event.event_id} event={event} />
                ))}
              </div>
            ) : (
              <EmptyState
                message="No timeline events"
                hint="Command results, scans, and scheduled work will appear here as they happen."
              />
            )}
          </SectionCard>
        </>
      )}
    </div>
  )
}

export default function TimelinePage() {
  return (
    <Suspense fallback={
      <div className="flex h-32 items-center justify-center">
        <div className="h-6 w-6 animate-spin rounded-full border-b-2 border-blue-500"></div>
      </div>
    }>
      <TimelineContent />
    </Suspense>
  )
}
