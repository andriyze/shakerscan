'use client'

import { useEffect, useState, useCallback, useRef, Suspense } from 'react'
import Link from 'next/link'
import { getScans, cancelScan, getDomains, getGradeColor, formatDate, formatDuration, submitScan, type Scan } from '@/lib/api'
import { useUrlFilters } from '@/lib/useUrlFilters'
import { SCAN_STATUSES, SCAN_TYPES, type ScanType } from '@/lib/constants'
import { Card, ConfirmDialog, ErrorState, LastUpdated, ScanStatusBadge, TableSkeleton, useToast } from '@/components/ui'

const PAGE_SIZE = 50
const SEARCH_DEBOUNCE_MS = 300
const LIVE_DURATION_REFRESH_MS = 5000
const AUTH_OPTION_KEYS = [
  'auth_header',
  'auth_cookies',
  'auth_headers_json',
  'auth_scenario_json',
  'login_username',
  'login_password',
  'user2_header',
  'user2_cookies'
]

function hasConfiguredValue(value: unknown): boolean {
  if (value === null || value === undefined) return false
  if (typeof value === 'string') return value.trim().length > 0
  if (typeof value === 'number') return true
  if (typeof value === 'boolean') return value
  if (Array.isArray(value)) return value.length > 0
  if (typeof value === 'object') return Object.keys(value as Record<string, unknown>).length > 0
  return false
}

function isAuthenticatedScan(scan: Scan): boolean {
  const { options } = scan
  if (!options || typeof options !== 'object' || Array.isArray(options)) return false
  const optionMap = options as Record<string, unknown>
  return AUTH_OPTION_KEYS.some((key) => hasConfiguredValue(optionMap[key]))
}

function formatScanTypeLabel(scan: Scan): string {
  if (scan.scan_type === 'ai_gate' || scan.run_kind?.startsWith('ai_')) {
    return 'AI Gate'
  }
  return scan.scan_type
    .split('_')
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ')
}

function isParallelParent(scan: Scan): boolean {
  return scan.scan_role === 'parent' || Boolean(scan.options?.parallel_strategy)
}

function formatAITargetType(value?: string | null): string | null {
  if (!value) return null
  const labels: Record<string, string> = {
    api_chat: 'API chat',
    mcp_trace: 'MCP trace',
    rag_knowledge: 'RAG knowledge'
  }
  return labels[value] || value.replace(/_/g, ' ')
}

interface ScansFilters {
  [key: string]: string | number | undefined
  status?: string
  domain?: string
  search?: string
  page?: number
}

function ScansContent() {
  const { filters, setFilter, setFilters, buildUrl } = useUrlFilters<ScansFilters>({
    defaults: { page: 1 }
  })
  const toast = useToast()

  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const [searchInput, setSearchInput] = useState<string>(filters.search || '')
  const [domains, setDomains] = useState<string[]>([])
  const [cancelling, setCancelling] = useState<Set<string>>(new Set())
  const [confirmCancelId, setConfirmCancelId] = useState<string | null>(null)
  const [total, setTotal] = useState(0)
  const [openScanMenu, setOpenScanMenu] = useState<string | null>(null)
  const [durationTickMs, setDurationTickMs] = useState<number>(Date.now())
  const searchTimeout = useRef<NodeJS.Timeout | null>(null)
  const scanMenuRef = useRef<HTMLDivElement>(null)

  const statusFilter = filters.status || ''
  const domainFilter = filters.domain || ''
  const searchQuery = filters.search || ''
  // Time cohort (?within=7) — exposure "What changed" links use it so the
  // destination shows the same windowed slice the tile counted.
  const withinFilter = filters.within ? Number(filters.within) : 0
  // Page is 1-based in URL (page=1 is first page), clamped to valid range
  const rawPage = Math.max(1, filters.page || 1)

  useEffect(() => {
    getDomains().then(data => setDomains(data.domains || [])).catch(() => {})
  }, [])

  // Close scan menu when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (scanMenuRef.current && !scanMenuRef.current.contains(event.target as Node)) {
        setOpenScanMenu(null)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  // Close scan menu on Escape
  useEffect(() => {
    if (!openScanMenu) return
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setOpenScanMenu(null)
      }
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [openScanMenu])

  // Sync searchInput with URL when filters change externally (e.g., browser back)
  useEffect(() => {
    setSearchInput(searchQuery)
  }, [searchQuery])

  // Debounce search input → URL update
  useEffect(() => {
    if (searchTimeout.current) {
      clearTimeout(searchTimeout.current)
    }
    searchTimeout.current = setTimeout(() => {
      if (searchInput !== searchQuery) {
        setFilter('search', searchInput || undefined)
      }
    }, SEARCH_DEBOUNCE_MS)
    return () => {
      if (searchTimeout.current) {
        clearTimeout(searchTimeout.current)
      }
    }
  }, [searchInput, searchQuery, setFilter])

  const fetchScans = useCallback(async (isPolling = false): Promise<boolean> => {
    // Only show loading skeleton on initial load, not polling refreshes
    if (!isPolling) {
      setLoading(true)
    }
    try {
      const data = await getScans({
        status: statusFilter || undefined,
        root_domain: domainFilter || undefined,
        target: searchQuery || undefined,
        created_within_days: withinFilter || undefined,
        limit: PAGE_SIZE,
        offset: (rawPage - 1) * PAGE_SIZE
      })
      const fetchedTotal = data.total || 0
      const maxPage = Math.max(1, Math.ceil(fetchedTotal / PAGE_SIZE))

      // If page is out of range and there are results, redirect to last valid page
      if (rawPage > maxPage && fetchedTotal > 0) {
        // Don't update state - keep loading while redirecting
        setFilter('page', maxPage > 1 ? maxPage : undefined)
        return true
      }

      setScans(data.scans || [])
      setTotal(fetchedTotal)
      setLoadError(false)
      setLastUpdated(new Date())
      setLoading(false)
      return true
    } catch (err) {
      console.error('Failed to fetch scans:', err)
      // Background poll failures keep existing rows; only non-polling loads surface the error state
      if (!isPolling) {
        setLoadError(true)
        setLoading(false)
      }
      return false
    }
  }, [statusFilter, domainFilter, searchQuery, withinFilter, rawPage, setFilter])

  useEffect(() => {
    fetchScans()
    const interval = setInterval(() => fetchScans(true), 5000)
    return () => clearInterval(interval)
  }, [fetchScans])

  // Keep running scan elapsed durations fresh without per-second churn.
  useEffect(() => {
    const interval = setInterval(() => setDurationTickMs(Date.now()), LIVE_DURATION_REFRESH_MS)
    return () => clearInterval(interval)
  }, [])

  const getDurationLabel = useCallback((scan: Scan): string => {
    if (scan.status === 'running') {
      const startedAt = scan.started_at || scan.created_at
      const startedAtMs = Date.parse(startedAt)
      if (!Number.isNaN(startedAtMs)) {
        const elapsedSeconds = Math.max(0, Math.floor((durationTickMs - startedAtMs) / 1000))
        return formatDuration(elapsedSeconds)
      }
    }
    return scan.duration_seconds ? formatDuration(scan.duration_seconds) : '-'
  }, [durationTickMs])

  async function handleManualRefresh() {
    setRefreshing(true)
    const ok = await fetchScans(true)
    setRefreshing(false)
    if (!ok) {
      toast.error('Failed to refresh scans')
    }
  }

  async function handleCancel(scanId: string) {
    setCancelling(prev => new Set(prev).add(scanId))
    try {
      await cancelScan(scanId)
      setConfirmCancelId(null)
      toast.success('Scan cancelled')
      fetchScans(true)
    } catch (err) {
      console.error('Failed to cancel scan:', err)
      setConfirmCancelId(null)
      toast.error('Failed to cancel scan')
    } finally {
      setCancelling(prev => {
        const next = new Set(prev)
        next.delete(scanId)
        return next
      })
    }
  }

  async function handleScan(targetUrl: string, scanType: ScanType) {
    const type = SCAN_TYPES.find(t => t.value === scanType)
    if (!type) return
    try {
      const result = await submitScan(targetUrl, {
        ...type.options,
        scan_type: scanType
      })
      setOpenScanMenu(null)
      toast.success(
        result?.auto_sharded ? 'Auto-sharded scan started' : result?.parallel ? 'Parallel scan started' : 'Scan started',
        result?.scan_id
          ? { link: { href: `/scans/${result.scan_id}`, label: 'View scan' } }
          : undefined
      )
      fetchScans(true)
    } catch (err) {
      console.error('Failed to start scan:', err)
      toast.error('Failed to start scan')
    }
  }

  const totalPages = Math.ceil(total / PAGE_SIZE)

  // Clamp page to valid range for display
  const page = Math.min(rawPage, Math.max(1, totalPages))

  const PaginationControls = () => (
    totalPages > 1 ? (
      <div className="flex items-center gap-2">
        <button
          onClick={() => setFilter('page', page > 1 ? page - 1 : undefined)}
          disabled={page <= 1}
          className="px-3 py-1.5 bg-gray-800 text-gray-400 rounded-lg text-sm hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Previous
        </button>
        <span className="px-3 py-1.5 text-sm text-gray-400">
          Page {page} of {totalPages}
        </span>
        <button
          onClick={() => setFilter('page', page + 1)}
          disabled={page >= totalPages}
          className="px-3 py-1.5 bg-gray-800 text-gray-400 rounded-lg text-sm hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Next
        </button>
      </div>
    ) : null
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Scans</h1>
          <p className="text-gray-400 mt-1">View all security scans</p>
        </div>
        <div className="flex items-center gap-4">
          <LastUpdated updatedAt={lastUpdated} onRefresh={handleManualRefresh} refreshing={refreshing} />
          <Link
            href="/scan/new"
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            New Scan
          </Link>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-4 flex-wrap">
        {/* Status Filter */}
        <div className="flex items-center gap-3">
          <label className="text-sm text-gray-400">Status:</label>
          <select
            value={statusFilter}
            onChange={(e) => setFilter('status', e.target.value || undefined)}
            aria-label="Filter by scan status"
            className="px-3 py-2 bg-gray-900 border border-gray-800 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
          >
            <option value="">All statuses</option>
            {SCAN_STATUSES.map((status) => (
              <option key={status} value={status}>{status}</option>
            ))}
          </select>
        </div>

        {/* Domain Filter */}
        {domains.length > 0 && (
          <div className="flex items-center gap-3">
            <label className="text-sm text-gray-400">Domain:</label>
            <select
              value={domainFilter}
              onChange={(e) => setFilter('domain', e.target.value || undefined)}
              aria-label="Filter by domain"
              className="px-3 py-2 bg-gray-900 border border-gray-800 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
            >
              <option value="">All domains</option>
              {domains.map((domain) => (
                <option key={domain} value={domain}>{domain}</option>
              ))}
            </select>
          </div>
        )}

        {/* Search */}
        <div className="relative flex-1 min-w-[200px]">
          <input
            type="text"
            placeholder="Search by target URL..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            aria-label="Search scans by target URL"
            className="w-full px-4 py-2 bg-gray-900 border border-gray-800 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
          <svg className="absolute right-3 top-2.5 w-5 h-5 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        </div>

        {/* Time cohort chip (deep-linked from exposure "What changed") */}
        {withinFilter > 0 && (
          <button
            type="button"
            onClick={() => setFilter('within', undefined)}
            aria-label={`Remove filter: last ${withinFilter} days`}
            className="inline-flex items-center gap-1.5 self-center rounded-lg border border-blue-500/30 bg-blue-500/10 px-2.5 py-1 text-xs text-blue-300 hover:bg-blue-500/20 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
          >
            Last {withinFilter}d
            <span aria-hidden="true">×</span>
          </button>
        )}
      </div>

      {/* Top Pagination */}
      {total > 0 && (
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-400">
            {total <= PAGE_SIZE
              ? `Showing ${total} scan${total !== 1 ? 's' : ''}`
              : `Showing ${(page - 1) * PAGE_SIZE + 1}-${Math.min(page * PAGE_SIZE, total)} of ${total}`
            }
          </span>
          <PaginationControls />
        </div>
      )}

      {/* Load Error */}
      {loadError && (
        <ErrorState onRetry={() => fetchScans()} />
      )}

      {/* Scans Table */}
      {!(loadError && scans.length === 0) && (
      <Card>
        {loading ? (
          <TableSkeleton rows={8} cols={6} />
        ) : scans.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            {searchQuery || domainFilter || statusFilter ? 'No scans found matching your filters.' : 'No scans found. Start a new scan to get started.'}
          </div>
        ) : (
          <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] 2xl:min-w-full">
            <thead className="bg-gray-800/50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Target</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Type</th>
                <th className="hidden 2xl:table-cell px-4 py-3 text-center text-xs font-medium text-gray-400 uppercase">Auth</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Score</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Findings</th>
                <th className="hidden xl:table-cell px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Duration</th>
                <th className="hidden 2xl:table-cell px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Date</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {scans.map((scan) => {
                const isAIScan = scan.scan_type === 'ai_gate' || scan.run_kind?.startsWith('ai_')
                const authenticated = isAuthenticatedScan(scan)
                const aiTargetType = formatAITargetType(scan.ai_target_type)
                const scanTypeLabel = formatScanTypeLabel(scan)
                const parallelParent = isParallelParent(scan)
                const asmBatch = scan.scan_role === 'asm_batch'
                const asmRecon = scan.scan_role === 'asm_recon'
                return (
                <tr key={scan.id} className="hover:bg-gray-800/50 transition-colors">
                  <td className="px-4 py-3 max-w-[20rem]">
                    <Link
                      href={buildUrl(`/scans/${scan.id}`, {
                        return_status: statusFilter,
                        return_domain: domainFilter,
                        return_search: searchQuery,
                        return_page: page > 1 ? page : undefined
                      })}
                      className="block truncate text-sm text-blue-400 hover:text-blue-300"
                      title={scan.target_url}
                    >
                      {scan.target_url}
                    </Link>
                  </td>
                  <td className="hidden xl:table-cell px-4 py-3">
                    <div className="min-w-0">
                      <span className="text-sm text-gray-300">{scanTypeLabel}</span>
                      {(asmBatch || asmRecon || parallelParent || aiTargetType || authenticated) && (
                        <div className="mt-0.5 truncate text-xs text-gray-500">
                          {asmBatch ? 'ASM batch' : asmRecon ? 'ASM recon' : parallelParent ? 'Parallel' : aiTargetType || 'Authenticated'}
                        </div>
                      )}
                    </div>
                  </td>
                  <td className="hidden 2xl:table-cell px-4 py-3 text-center">
                    {authenticated ? (
                      <span
                        className="inline-flex items-center justify-center text-green-400"
                        title="Authenticated scan"
                        aria-label="Authenticated scan"
                      >
                        <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c1.657 0 3-1.343 3-3V7a3 3 0 10-6 0v1c0 1.657 1.343 3 3 3zm0 0v2m-7 2h14a2 2 0 002-2v-1a2 2 0 00-2-2H5a2 2 0 00-2 2v1a2 2 0 002 2z" />
                        </svg>
                      </span>
                    ) : (
                      <span
                        className="inline-flex items-center justify-center text-gray-500"
                        title="No authentication configured"
                        aria-label="No authentication configured"
                      >
                        <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 11V7a4 4 0 10-8 0m8 4H8m8 0a2 2 0 012 2v1a2 2 0 01-2 2H8a2 2 0 01-2-2v-1a2 2 0 012-2m8 0V9" />
                        </svg>
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <ScanStatusBadge status={scan.status} />
                  </td>
                  <td className="px-4 py-3">
                    {scan.grade ? (
                      <div className="flex items-center gap-2">
                        <span className={`text-lg font-bold ${getGradeColor(scan.grade)}`}>{scan.grade}</span>
                        <span className="text-sm text-gray-500">{scan.score}/100</span>
                      </div>
                    ) : (
                      <span className="text-gray-500">-</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {(scan.findings_count || 0) > 0 ? (
                      <Link
                        href={`/findings?scan_id=${scan.id}`}
                        className="text-sm text-blue-400 hover:text-blue-300"
                      >
                        {scan.findings_count}
                      </Link>
                    ) : (
                      <span className="text-sm text-gray-400">0</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-gray-400">
                      {getDurationLabel(scan)}
                    </span>
                  </td>
                  <td className="hidden 2xl:table-cell px-4 py-3">
                    <span className="text-sm text-gray-500">{formatDate(scan.created_at)}</span>
                  </td>
                  <td className="px-4 py-3">
                    {(scan.status === 'running' || scan.status === 'pending' || scan.status === 'queued') ? (
                      <button
                        onClick={() => setConfirmCancelId(scan.id)}
                        disabled={cancelling.has(scan.id)}
                        className="px-2 py-1 bg-red-600/20 hover:bg-red-600/40 text-red-400 rounded text-xs font-medium transition-colors disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500"
                      >
                        {cancelling.has(scan.id) ? 'Cancelling...' : 'Cancel'}
                      </button>
                    ) : isAIScan ? (
                      <Link
                        href="/settings/ai-gate"
                        className="px-2 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-medium transition-colors"
                      >
                        AI Gate
                      </Link>
                    ) : (
                      <div className={`relative ${openScanMenu === scan.id ? 'z-[100]' : ''}`} ref={openScanMenu === scan.id ? scanMenuRef : null}>
                        <button
                          onClick={() => setOpenScanMenu(openScanMenu === scan.id ? null : scan.id)}
                          aria-haspopup="menu"
                          aria-expanded={openScanMenu === scan.id}
                          className="flex items-center gap-1 px-2 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                        >
                          Scan
                          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                          </svg>
                        </button>
                        {openScanMenu === scan.id && (
                          <div role="menu" className="absolute right-0 mt-1 w-56 bg-gray-800 border border-gray-700 rounded-lg shadow-xl py-1">
                            {SCAN_TYPES.map((type) => (
                              <button
                                key={type.value}
                                role="menuitem"
                                onClick={() => handleScan(scan.target_url, type.value)}
                                className="w-full px-3 py-2 text-left hover:bg-gray-700 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-500"
                              >
                                <div className="flex items-center justify-between">
                                  <span className="text-sm text-white font-medium">{type.label}</span>
                                  {type.requiresPermission && (
                                    <span className="text-xs text-yellow-500">Active</span>
                                  )}
                                </div>
                                <p className="text-xs text-gray-400 mt-0.5">
                                  {type.duration ? `${type.duration} - ` : ''}{type.description}
                                </p>
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              )})}
            </tbody>
          </table>
          </div>
        )}
      </Card>
      )}

      {/* Bottom Pagination */}
      {total > 0 && (
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-400">
            {total <= PAGE_SIZE
              ? `Showing ${total} scan${total !== 1 ? 's' : ''}`
              : `Showing ${(page - 1) * PAGE_SIZE + 1}-${Math.min(page * PAGE_SIZE, total)} of ${total}`
            }
          </span>
          <PaginationControls />
        </div>
      )}

      <ConfirmDialog
        open={confirmCancelId !== null}
        title="Cancel scan?"
        message="The scan will be stopped and cannot be resumed."
        confirmLabel="Cancel scan"
        cancelLabel="Keep running"
        danger
        busy={confirmCancelId !== null && cancelling.has(confirmCancelId)}
        onConfirm={() => { if (confirmCancelId) handleCancel(confirmCancelId) }}
        onCancel={() => setConfirmCancelId(null)}
      />
    </div>
  )
}

export default function ScansPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center h-32">
        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500"></div>
      </div>
    }>
      <ScansContent />
    </Suspense>
  )
}
