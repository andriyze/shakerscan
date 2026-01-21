'use client'

import { useEffect, useState, useCallback, useRef, Suspense } from 'react'
import Link from 'next/link'
import { getScans, cancelScan, getDomains, getGradeColor, formatDate, formatDuration, type Scan } from '@/lib/api'
import { useUrlFilters } from '@/lib/useUrlFilters'
import { SCAN_STATUSES } from '@/lib/constants'

const PAGE_SIZE = 50
const SEARCH_DEBOUNCE_MS = 300

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

  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [searchInput, setSearchInput] = useState<string>(filters.search || '')
  const [domains, setDomains] = useState<string[]>([])
  const [cancelling, setCancelling] = useState<Set<string>>(new Set())
  const [total, setTotal] = useState(0)
  const searchTimeout = useRef<NodeJS.Timeout | null>(null)

  const statusFilter = filters.status || ''
  const domainFilter = filters.domain || ''
  const searchQuery = filters.search || ''
  // Page is 1-based in URL (page=1 is first page), clamped to valid range
  const rawPage = Math.max(1, filters.page || 1)

  useEffect(() => {
    getDomains().then(data => setDomains(data.domains || [])).catch(() => {})
  }, [])

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

  const fetchScans = useCallback(async (isPolling = false) => {
    // Only show loading spinner on initial load, not polling refreshes
    if (!isPolling) {
      setLoading(true)
    }
    try {
      const data = await getScans({
        status: statusFilter || undefined,
        root_domain: domainFilter || undefined,
        target: searchQuery || undefined,
        limit: PAGE_SIZE,
        offset: (rawPage - 1) * PAGE_SIZE
      })
      const fetchedTotal = data.total || 0
      const maxPage = Math.max(1, Math.ceil(fetchedTotal / PAGE_SIZE))

      // If page is out of range and there are results, redirect to last valid page
      if (rawPage > maxPage && fetchedTotal > 0) {
        // Don't update state - keep loading while redirecting
        setFilter('page', maxPage > 1 ? maxPage : undefined)
        return
      }

      setScans(data.scans || [])
      setTotal(fetchedTotal)
      setLoading(false)
    } catch (err) {
      console.error('Failed to fetch scans:', err)
      setLoading(false)
    }
  }, [statusFilter, domainFilter, searchQuery, rawPage, setFilter])

  useEffect(() => {
    fetchScans()
    const interval = setInterval(() => fetchScans(true), 5000)
    return () => clearInterval(interval)
  }, [fetchScans])

  async function handleCancel(scanId: string) {
    setCancelling(prev => new Set(prev).add(scanId))
    try {
      await cancelScan(scanId)
      fetchScans()
    } catch (err) {
      console.error('Failed to cancel scan:', err)
    } finally {
      setCancelling(prev => {
        const next = new Set(prev)
        next.delete(scanId)
        return next
      })
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

      {/* Filters */}
      <div className="flex gap-4 flex-wrap">
        {/* Status Filter */}
        <div className="flex items-center gap-3">
          <label className="text-sm text-gray-400">Status:</label>
          <select
            value={statusFilter}
            onChange={(e) => setFilter('status', e.target.value || undefined)}
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
            className="w-full px-4 py-2 bg-gray-900 border border-gray-800 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
          <svg className="absolute right-3 top-2.5 w-5 h-5 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        </div>
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

      {/* Scans Table */}
      <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-32">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500"></div>
          </div>
        ) : scans.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            {searchQuery || domainFilter || statusFilter ? 'No scans found matching your filters.' : 'No scans found. Start a new scan to get started.'}
          </div>
        ) : (
          <table className="w-full">
            <thead className="bg-gray-800/50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Target</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Type</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Score</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Findings</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Duration</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Date</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {scans.map((scan) => (
                <tr key={scan.id} className="hover:bg-gray-800/50 transition-colors">
                  <td className="px-4 py-3">
                    <Link
                      href={buildUrl(`/scans/${scan.id}`, {
                        return_status: statusFilter,
                        return_domain: domainFilter,
                        return_search: searchQuery,
                        return_page: page > 1 ? page : undefined
                      })}
                      className="text-sm text-blue-400 hover:text-blue-300"
                    >
                      {scan.target_url}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-gray-400 capitalize">{scan.scan_type}</span>
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={scan.status} />
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
                      {scan.duration_seconds ? formatDuration(scan.duration_seconds) : '-'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-gray-500">{formatDate(scan.created_at)}</span>
                  </td>
                  <td className="px-4 py-3">
                    {(scan.status === 'running' || scan.status === 'pending' || scan.status === 'queued') && (
                      <button
                        onClick={() => handleCancel(scan.id)}
                        disabled={cancelling.has(scan.id)}
                        className="px-2 py-1 bg-red-600/20 hover:bg-red-600/40 text-red-400 rounded text-xs font-medium transition-colors disabled:opacity-50"
                      >
                        {cancelling.has(scan.id) ? 'Cancelling...' : 'Cancel'}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

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
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    pending: 'bg-gray-500/20 text-gray-400',
    queued: 'bg-gray-500/20 text-gray-400',
    running: 'bg-blue-500/20 text-blue-400',
    completed: 'bg-green-500/20 text-green-400',
    failed: 'bg-red-500/20 text-red-400',
    cancelled: 'bg-orange-500/20 text-orange-400'
  }

  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 text-xs font-medium rounded ${styles[status] || styles.pending}`}>
      {status === 'running' && (
        <span className="w-1.5 h-1.5 bg-blue-400 rounded-full animate-pulse"></span>
      )}
      {status}
    </span>
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
