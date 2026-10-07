'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { X } from 'lucide-react'

import { Button, EmptyState, ErrorState, SearchInput, Select, TableSkeleton, Toolbar, tableStyles } from '@/components/ui'
import { huntStatusLabel } from '@/lib/labels'
import { listHuntsV2, type HuntSortField, type HuntV2 } from '@/lib/huntV2'
import { huntTargetTitle } from '@/lib/huntListModel.mjs'
import { useUrlFilters } from '@/lib/useUrlFilters'
import { HuntRunList } from './HuntRunList'

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
  target_id?: string
  search?: string
  sort?: string
  order?: string
  page?: number
}

/** Every Hunt across targets, filtered and paged through the URL. */
export function HuntHistoryList() {
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
  const targetId = filters.target_id || ''
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
        targetId: targetId || undefined,
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
  }, [status, kind, targetId, search, sort, order, page])

  useEffect(() => {
    load()
    const timer = setInterval(() => load(true), REFRESH_MS)
    return () => clearInterval(timer)
  }, [load])

  const maxPage = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const filtered = Boolean(status || kind || targetId || search)
  // The target a target-scoped link selected, named from the rows once they load.
  const scopedTarget = targetId ? (hunts.find((hunt) => hunt.target_id === targetId) || null) : null
  const first = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1
  const last = Math.min(page * PAGE_SIZE, total)

  return (
    <div>

      <Toolbar>
        <SearchInput
          wrapperClassName="min-w-[220px] flex-1 sm:max-w-sm"
          aria-label="Search hunts by target or objective"
          placeholder="Search target or objective…"
          value={searchInput}
          onValueChange={setSearchInput}
        />
        <Select
          fullWidth={false}
          aria-label="Filter by status"
          value={status}
          onChange={(event) => setFilter('status', event.target.value || undefined)}
        >
          <option value="">All statuses</option>
          {STATUSES.map((value) => (
            <option key={value} value={value}>{huntStatusLabel(value)}</option>
          ))}
        </Select>
        <Select
          fullWidth={false}
          aria-label="Filter by target kind"
          value={kind}
          onChange={(event) => setFilter('kind', event.target.value || undefined)}
        >
          <option value="">All target kinds</option>
          {['web', 'api', 'device', 'network'].map((value) => (
            <option key={value} value={value}>{value}</option>
          ))}
        </Select>
        <Select
          fullWidth={false}
          aria-label="Sort hunts"
          value={`${sort}:${order}`}
          onChange={(event) => {
            const [nextSort, nextOrder] = event.target.value.split(':')
            setFilter('sort', nextSort)
            setFilter('order', nextOrder)
          }}
        >
          {SORT_OPTIONS.flatMap((option) => ([
            <option key={`${option.value}:desc`} value={`${option.value}:desc`}>Sort: {option.label} (newest)</option>,
            <option key={`${option.value}:asc`} value={`${option.value}:asc`}>Sort: {option.label} (oldest)</option>,
          ]))}
        </Select>
        {targetId && (
          <span
            className="inline-flex items-center gap-1.5 rounded-lg border border-gray-700 bg-gray-900 px-2.5 py-1 text-xs text-gray-300"
            data-testid="hunts-target-filter"
          >
            <span className="text-gray-500">Target</span>
            {scopedTarget ? huntTargetTitle(scopedTarget) : targetId}
            <button
              type="button"
              onClick={() => setFilter('target_id', undefined)}
              className="rounded-sm text-gray-500 hover:text-white focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
              aria-label="Show Hunts for every target"
            >
              <X className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </span>
        )}
      </Toolbar>

      {loadError && <div className="mb-4"><ErrorState message={loadError} onRetry={() => load()} /></div>}

      {!loadError && !loading && (
        <p className="mb-3 text-xs tabular-nums text-gray-400">
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
        <div className={tableStyles.container}>
          <div className="hidden grid-cols-[8.5rem_minmax(0,2.2fr)_minmax(0,1fr)_8rem] gap-4 border-b border-gray-800 px-4 py-2.5 text-xs font-medium text-gray-400 lg:grid">
            <span>Status</span><span>Objective &amp; target</span><span>Activity</span><span className="text-right">Started</span>
          </div>
          <HuntRunList runs={hunts} />
        </div>
      )}

      {total > PAGE_SIZE && (
        <div className="mt-3 flex items-center justify-between">
          <Button
            variant="secondary"
            size="sm"
            disabled={page <= 1}
            onClick={() => setFilter('page', page - 1)}
          >
            Previous
          </Button>
          <span className="text-xs tabular-nums text-gray-400">Page {page} of {maxPage}</span>
          <Button
            variant="secondary"
            size="sm"
            disabled={page >= maxPage}
            onClick={() => setFilter('page', page + 1)}
          >
            Next
          </Button>
        </div>
      )}
    </div>
  )
}
