'use client'

import { Suspense, useCallback, useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { Search } from 'lucide-react'

import {
  Card, EmptyState, ErrorState, Field, Input, PageHeader, Select, TableSkeleton,
  buttonClasses,
} from '@/components/ui'
import { formatDate, formatDuration } from '@/lib/api'
import { huntStatusLabel } from '@/lib/labels'
import { listHuntsV2, type HuntSortField, type HuntV2 } from '@/lib/huntV2'
import { useUrlFilters } from '@/lib/useUrlFilters'

const PAGE_SIZE = 50
const SEARCH_DEBOUNCE_MS = 300
const REFRESH_MS = 10_000

const STATUSES = [
  'active', 'awaiting_planner', 'completed', 'cancelled', 'failed', 'budget_exhausted',
] as const

const SORT_OPTIONS: Array<{ value: HuntSortField; label: string }> = [
  { value: 'created_at', label: 'Started' },
  { value: 'updated_at', label: 'Last activity' },
  { value: 'completed_at', label: 'Finished' },
  { value: 'target_url', label: 'Target' },
  { value: 'status', label: 'Status' },
]

interface HuntFilters {
  [key: string]: string | number | undefined
  status?: string
  kind?: string
  search?: string
  sort?: string
  order?: string
  page?: number
}

function statusClass(status: string): string {
  if (status === 'active' || status === 'awaiting_planner') return 'bg-blue-500/10 text-blue-300'
  if (status === 'completed') return 'bg-emerald-500/10 text-emerald-300'
  if (status === 'failed') return 'bg-red-500/10 text-red-300'
  if (status === 'budget_exhausted') return 'bg-amber-500/10 text-amber-300'
  return 'bg-gray-700/40 text-gray-300'
}

/** Elapsed for a run still open, total for one that finished. */
function huntDuration(hunt: HuntV2): string | null {
  if (!hunt.created_at) return null
  const start = new Date(hunt.created_at).getTime()
  const end = hunt.completed_at ? new Date(hunt.completed_at).getTime() : Date.now()
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return null
  return formatDuration(Math.round((end - start) / 1000))
}

function targetLabel(hunt: HuntV2): string {
  return hunt.target_url || hunt.target_name || hunt.target_id || 'unknown target'
}

function HuntsContent() {
  const { filters, setFilter, buildUrl } = useUrlFilters<HuntFilters>({
    defaults: { page: 1 },
  })
  const [hunts, setHunts] = useState<HuntV2[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [searchInput, setSearchInput] = useState(filters.search || '')
  const debounce = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  const status = filters.status || ''
  const kind = filters.kind || ''
  const sort = (filters.sort || 'created_at') as HuntSortField
  const order = filters.order === 'asc' ? 'asc' : 'desc'
  const search = filters.search || ''
  const page = Math.max(1, filters.page || 1)

  // Mirror the URL when it changes from outside this input, such as browser-back.
  useEffect(() => { setSearchInput(filters.search || '') }, [filters.search])

  useEffect(() => {
    if (searchInput === search) return
    if (debounce.current) clearTimeout(debounce.current)
    debounce.current = setTimeout(() => setFilter('search', searchInput || undefined), SEARCH_DEBOUNCE_MS)
    return () => { if (debounce.current) clearTimeout(debounce.current) }
  }, [searchInput, search, setFilter])

  const load = useCallback(async (isPolling = false) => {
    if (!isPolling) setLoading(true)
    try {
      const result = await listHuntsV2({
        status: (status || undefined) as HuntV2['status'] | undefined,
        targetKind: (kind || undefined) as HuntV2['target_kind'] | undefined,
        search: search || undefined,
        sortBy: sort,
        sortOrder: order,
        limit: PAGE_SIZE,
        offset: (page - 1) * PAGE_SIZE,
      })
      setHunts(result.hunts)
      setTotal(result.total)
      setLoadError(null)
    } catch (error) {
      // A background refresh must not wipe rows the operator is reading; only a
      // foreground load surfaces the failure.
      if (!isPolling) setLoadError(error instanceof Error ? error.message : 'Failed to load Hunts')
    } finally {
      if (!isPolling) setLoading(false)
    }
  }, [status, kind, search, sort, order, page])

  useEffect(() => {
    load()
    const timer = setInterval(() => load(true), REFRESH_MS)
    return () => clearInterval(timer)
  }, [load])

  const maxPage = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const filtered = Boolean(status || kind || search)
  const first = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1
  const last = Math.min(page * PAGE_SIZE, total)

  return (
    <div className="p-6 lg:p-8">
      <PageHeader
        title="Hunts"
        description="Every investigation, across targets."
        actions={<Link href="/hunt" className={buttonClasses('primary')}>New Hunt</Link>}
      />

      <Card className="mb-4 p-4">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Status">
            <Select value={status} onChange={(event) => setFilter('status', event.target.value || undefined)}>
              <option value="">All statuses</option>
              {STATUSES.map((value) => (
                <option key={value} value={value}>{huntStatusLabel(value)}</option>
              ))}
            </Select>
          </Field>
          <Field label="Target kind">
            <Select value={kind} onChange={(event) => setFilter('kind', event.target.value || undefined)}>
              <option value="">All kinds</option>
              {['web', 'api', 'device', 'network'].map((value) => (
                <option key={value} value={value}>{value}</option>
              ))}
            </Select>
          </Field>
          <Field label="Sort by">
            <Select
              value={`${sort}:${order}`}
              onChange={(event) => {
                const [nextSort, nextOrder] = event.target.value.split(':')
                setFilter('sort', nextSort)
                setFilter('order', nextOrder)
              }}
            >
              {SORT_OPTIONS.flatMap((option) => ([
                <option key={`${option.value}:desc`} value={`${option.value}:desc`}>{option.label} (newest)</option>,
                <option key={`${option.value}:asc`} value={`${option.value}:asc`}>{option.label} (oldest)</option>,
              ]))}
            </Select>
          </Field>
          <Field label="Search">
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
              <Input
                className="pl-9"
                aria-label="Search hunts by target or objective"
                placeholder="Target or objective"
                value={searchInput}
                onChange={(event) => setSearchInput(event.target.value)}
              />
            </div>
          </Field>
        </div>
      </Card>

      {loadError && <ErrorState message={loadError} onRetry={() => load()} />}

      {!loadError && (
        <p className="mb-3 text-sm text-gray-500">
          {total === 0
            ? 'No hunts'
            : total <= PAGE_SIZE
              ? `Showing ${total} hunt${total === 1 ? '' : 's'}`
              : `Showing ${first}-${last} of ${total}`}
        </p>
      )}

      {loading ? (
        <TableSkeleton rows={8} cols={5} />
      ) : hunts.length === 0 && !loadError ? (
        <EmptyState
          message={filtered ? 'No hunts match these filters' : 'No hunts yet'}
          hint={filtered
            ? 'Try clearing a filter or widening the search.'
            : 'Start one from a target to investigate it with an agent session.'}
        />
      ) : (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-sm 2xl:min-w-full">
              <thead className="border-b border-gray-800 text-xs uppercase tracking-wide text-gray-500">
                <tr>
                  <th scope="col" className="px-4 py-3">Target</th>
                  <th scope="col" className="px-4 py-3">Objective</th>
                  <th scope="col" className="px-4 py-3">Status</th>
                  <th scope="col" className="px-4 py-3">Calls</th>
                  <th scope="col" className="px-4 py-3">Started</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {hunts.map((hunt) => {
                  const duration = huntDuration(hunt)
                  return (
                    <tr key={hunt.hunt_id} className="hover:bg-gray-800/40">
                      <td className="px-4 py-3">
                        <Link
                          href={buildUrl(`/hunt?target=${encodeURIComponent(hunt.target_id)}&run=${encodeURIComponent(hunt.hunt_id)}`)}
                          className="font-medium text-blue-400 hover:text-blue-300"
                        >
                          {targetLabel(hunt)}
                        </Link>
                        <p className="mt-0.5 text-xs text-gray-500">{hunt.target_kind} · {hunt.budget_profile}</p>
                      </td>
                      <td className="max-w-md px-4 py-3 text-gray-300">
                        <span className="line-clamp-2">{hunt.objective}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`rounded px-2 py-1 text-xs ${statusClass(hunt.status)}`}>
                          {huntStatusLabel(hunt.status)}
                        </span>
                        {hunt.stop_reason && hunt.stop_reason !== 'completed' && (
                          <p className="mt-1 text-xs text-gray-500">{hunt.stop_reason.replaceAll('_', ' ')}</p>
                        )}
                      </td>
                      <td className="px-4 py-3 text-gray-400">
                        {hunt.budget_used?.agent_actions || 0}
                      </td>
                      <td className="px-4 py-3 text-gray-400">
                        {hunt.created_at ? formatDate(hunt.created_at) : '-'}
                        {duration && <p className="mt-0.5 text-xs text-gray-600">{duration}</p>}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {total > PAGE_SIZE && (
        <div className="mt-4 flex items-center justify-between">
          <button
            type="button"
            className={buttonClasses('secondary')}
            disabled={page <= 1}
            onClick={() => setFilter('page', page - 1)}
          >
            Previous
          </button>
          <span className="text-sm text-gray-500">Page {page} of {maxPage}</span>
          <button
            type="button"
            className={buttonClasses('secondary')}
            disabled={page >= maxPage}
            onClick={() => setFilter('page', page + 1)}
          >
            Next
          </button>
        </div>
      )}
    </div>
  )
}

export default function HuntsPage() {
  return (
    <Suspense fallback={<div className="p-6 lg:p-8"><TableSkeleton rows={8} cols={5} /></div>}>
      <HuntsContent />
    </Suspense>
  )
}
