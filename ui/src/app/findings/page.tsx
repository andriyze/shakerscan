'use client'

import { useEffect, useState, useRef, Suspense } from 'react'
import Link from 'next/link'
import { getFindings, updateFinding, getDomains, getSeverityBg, formatDate, type Finding } from '@/lib/api'
import { useUrlFilters } from '@/lib/useUrlFilters'
import { SEVERITY_LEVELS, FINDING_STATUSES, SORT_OPTIONS, type SortOption, type SortOrder } from '@/lib/constants'

const PAGE_SIZE = 50
const SEARCH_DEBOUNCE_MS = 300

interface FindingsFilters {
  [key: string]: string | number | undefined
  severity?: string
  status?: string
  domain?: string
  scan_id?: string
  target_id?: string
  search?: string
  sort_by?: string
  sort_order?: string
  page?: number
}

function FindingsContent() {
  const { filters, setFilter, buildUrl } = useUrlFilters<FindingsFilters>({
    defaults: { sort_by: 'severity', sort_order: 'desc', page: 1 }
  })

  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [domains, setDomains] = useState<string[]>([])
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
  const [total, setTotal] = useState(0)
  const [searchInput, setSearchInput] = useState<string>(filters.search || '')
  const searchTimeout = useRef<NodeJS.Timeout | null>(null)

  const severityFilter = filters.severity || ''
  const statusFilter = filters.status || ''
  const domainFilter = filters.domain || ''
  const scanIdFilter = filters.scan_id || ''
  const targetIdFilter = filters.target_id || ''
  const searchQuery = filters.search || ''
  const sortBy = (filters.sort_by || 'severity') as SortOption
  const sortOrder = (filters.sort_order || 'desc') as SortOrder
  // Page is 1-based in URL (page=1 is first page)
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

  useEffect(() => {
    fetchFindings()
  }, [severityFilter, statusFilter, domainFilter, scanIdFilter, targetIdFilter, searchQuery, rawPage, sortBy, sortOrder])

  async function fetchFindings() {
    try {
      setLoading(true)
      const data = await getFindings({
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
        root_domain: domainFilter || undefined,
        scan_id: scanIdFilter || undefined,
        target_id: targetIdFilter || undefined,
        search: searchQuery || undefined,
        sort_by: sortBy,
        sort_order: sortOrder,
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

      setFindings(data.findings || [])
      setTotal(fetchedTotal)
      setLoading(false)
    } catch (err) {
      console.error('Failed to fetch findings:', err)
      setLoading(false)
    }
  }

  async function handleStatusChange(findingId: string, newStatus: string, scanId?: string) {
    try {
      await updateFinding(findingId, newStatus, undefined, scanId)
      await fetchFindings()
      setSelectedFinding(null)
    } catch (err) {
      console.error('Failed to update finding:', err)
    }
  }

  const totalPages = Math.ceil(total / PAGE_SIZE)

  // Clamp page to valid range for display
  const page = Math.min(rawPage, Math.max(1, totalPages))

  // Build detail URL with return params to preserve filter context
  const buildDetailUrl = (findingId: string) => {
    const params = new URLSearchParams()
    if (severityFilter) params.set('return_severity', severityFilter)
    if (statusFilter) params.set('return_status', statusFilter)
    if (domainFilter) params.set('return_domain', domainFilter)
    if (scanIdFilter) params.set('return_scan_id', scanIdFilter)
    if (targetIdFilter) params.set('return_target_id', targetIdFilter)
    if (searchQuery) params.set('return_search', searchQuery)
    if (sortBy !== 'severity') params.set('return_sort_by', sortBy)
    if (sortOrder !== 'desc') params.set('return_sort_order', sortOrder)
    if (page > 1) params.set('return_page', String(page))
    const queryString = params.toString()
    return queryString ? `/findings/${findingId}?${queryString}` : `/findings/${findingId}`
  }

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
      <div>
        <h1 className="text-2xl font-bold text-white">Findings</h1>
        <p className="text-gray-400 mt-1">
          Vulnerability findings across all scans
          {scanIdFilter && <span className="text-blue-400"> (filtered by scan)</span>}
          {targetIdFilter && <span className="text-blue-400"> (filtered by target)</span>}
        </p>
      </div>

      {/* Filters Row */}
      <div className="flex flex-wrap items-center gap-4">
        {/* Domain Filter */}
        {domains.length > 0 && (
          <div className="flex items-center gap-2">
            <label className="text-sm text-gray-400">Domain:</label>
            <select
              value={domainFilter}
              onChange={(e) => setFilter('domain', e.target.value || undefined)}
              className="px-3 py-1.5 bg-gray-900 border border-gray-800 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
            >
              <option value="">All domains</option>
              {domains.map((domain) => (
                <option key={domain} value={domain}>{domain}</option>
              ))}
            </select>
          </div>
        )}

        {/* Sort Options */}
        <div className="flex items-center gap-2">
          <label className="text-sm text-gray-400">Sort by:</label>
          <select
            value={sortBy}
            onChange={(e) => setFilter('sort_by', e.target.value)}
            className="px-3 py-1.5 bg-gray-900 border border-gray-800 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
          >
            {SORT_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
          <button
            onClick={() => setFilter('sort_order', sortOrder === 'desc' ? 'asc' : 'desc')}
            className="px-2 py-1.5 bg-gray-900 border border-gray-800 rounded-lg text-white text-sm hover:bg-gray-800 focus:outline-none focus:border-blue-500"
            title={sortOrder === 'desc' ? 'Descending (newest/highest first)' : 'Ascending (oldest/lowest first)'}
          >
            {sortOrder === 'desc' ? '\u2193' : '\u2191'}
          </button>
        </div>

        {/* Search */}
        <div className="relative flex-1 min-w-[200px]">
          <input
            type="text"
            placeholder="Search by title or URL..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            className="w-full px-4 py-1.5 bg-gray-900 border border-gray-800 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 text-sm"
          />
          <svg className="absolute right-3 top-2 w-4 h-4 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        </div>

        {/* Clear Filters */}
        {(scanIdFilter || targetIdFilter) && (
          <button
            onClick={() => {
              setFilter('scan_id', undefined)
              setFilter('target_id', undefined)
            }}
            className="px-3 py-1.5 bg-gray-800 text-gray-400 rounded-lg text-sm hover:bg-gray-700"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Severity Filter */}
      <div className="flex gap-2 flex-wrap">
        {SEVERITY_LEVELS.map((sev) => (
          <button
            key={sev}
            onClick={() => setFilter('severity', severityFilter === sev ? undefined : sev)}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors capitalize ${
              severityFilter === sev
                ? getSeverityBg(sev)
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            {sev}
          </button>
        ))}
      </div>

      {/* Status Filter */}
      <div className="flex gap-2">
        <button
          onClick={() => setFilter('status', undefined)}
          className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
            !statusFilter
              ? 'bg-blue-600 text-white'
              : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
          }`}
        >
          all
        </button>
        {FINDING_STATUSES.map((status) => (
          <button
            key={status}
            onClick={() => setFilter('status', status)}
            className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
              statusFilter === status
                ? 'bg-blue-600 text-white'
                : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
            }`}
          >
            {status.replace('_', ' ')}
          </button>
        ))}
      </div>

      {/* Top Pagination */}
      {total > 0 && (
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-400">
            {total <= PAGE_SIZE
              ? `Showing ${total} finding${total !== 1 ? 's' : ''}`
              : `Showing ${(page - 1) * PAGE_SIZE + 1}-${Math.min(page * PAGE_SIZE, total)} of ${total}`
            }
          </span>
          <PaginationControls />
        </div>
      )}

      {/* Findings List */}
      <div className="bg-gray-900 rounded-lg border border-gray-800">
        {loading ? (
          <div className="flex items-center justify-center h-32">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500"></div>
          </div>
        ) : findings.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            No findings found matching your filters.
          </div>
        ) : (
          <div className="divide-y divide-gray-800">
            {findings.map((finding) => (
              <div
                key={finding.id}
                className="p-4 hover:bg-gray-800/50 transition-colors cursor-pointer"
                onClick={() => setSelectedFinding(finding)}
              >
                <div className="flex items-start gap-3">
                  <span className={`px-2 py-0.5 text-xs font-medium rounded shrink-0 ${getSeverityBg(finding.severity)}`}>
                    {finding.severity}
                  </span>
                  <div className="flex-1 min-w-0">
                    <h3 className="text-sm font-medium text-white">{finding.title}</h3>
                    <div className="flex items-center gap-4 mt-1 text-xs text-gray-500">
                      {finding.tool && <span>Tool: {finding.tool}</span>}
                      {finding.cwe && <span>CWE: {finding.cwe}</span>}
                      {finding.cvss_score && <span>CVSS: {finding.cvss_score}</span>}
                    </div>
                    <div className="flex items-center gap-4 mt-1 text-xs text-gray-500">
                      <span>First seen: {formatDate(finding.first_seen_at)}</span>
                      <span>Last seen: {formatDate(finding.last_seen_at)}</span>
                    </div>
                    {finding.url && (
                      <p className="text-xs text-gray-600 truncate mt-1">{finding.url}</p>
                    )}
                  </div>
                  <StatusBadge status={finding.status} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Bottom Pagination */}
      {total > 0 && (
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-400">
            {total <= PAGE_SIZE
              ? `Showing ${total} finding${total !== 1 ? 's' : ''}`
              : `Showing ${(page - 1) * PAGE_SIZE + 1}-${Math.min(page * PAGE_SIZE, total)} of ${total}`
            }
          </span>
          <PaginationControls />
        </div>
      )}

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 rounded-lg border border-gray-800 max-w-2xl w-full max-h-[80vh] overflow-auto">
            <div className="p-4 border-b border-gray-800 flex items-center justify-between">
              <h2 className="font-medium text-white">Finding Details</h2>
              <div className="flex items-center gap-3">
                <Link
                  href={buildDetailUrl(selectedFinding.id)}
                  className="text-xs text-blue-400 hover:text-blue-300"
                >
                  Open full view
                </Link>
                <button
                  onClick={() => setSelectedFinding(null)}
                  className="text-gray-400 hover:text-white"
                >
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>
            <div className="p-4 space-y-4">
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 text-xs font-medium rounded ${getSeverityBg(selectedFinding.severity)}`}>
                  {selectedFinding.severity}
                </span>
                <StatusBadge status={selectedFinding.status} />
              </div>
              <h3 className="text-lg font-medium text-white">{selectedFinding.title}</h3>
              {selectedFinding.description && (
                <p className="text-sm text-gray-400">{selectedFinding.description}</p>
              )}
              <div className="grid grid-cols-2 gap-4 text-sm">
                {selectedFinding.tool && (
                  <div>
                    <span className="text-gray-500">Tool:</span>
                    <span className="ml-2 text-white">{selectedFinding.tool}</span>
                  </div>
                )}
                {selectedFinding.cwe && (
                  <div>
                    <span className="text-gray-500">CWE:</span>
                    <span className="ml-2 text-white">{selectedFinding.cwe}</span>
                  </div>
                )}
                {selectedFinding.owasp && (
                  <div>
                    <span className="text-gray-500">OWASP:</span>
                    <span className="ml-2 text-white">{selectedFinding.owasp}</span>
                  </div>
                )}
                {selectedFinding.cvss_score && (
                  <div>
                    <span className="text-gray-500">CVSS:</span>
                    <span className="ml-2 text-white">{selectedFinding.cvss_score}</span>
                  </div>
                )}
                <div>
                  <span className="text-gray-500">First seen:</span>
                  <span className="ml-2 text-white">{formatDate(selectedFinding.first_seen_at)}</span>
                </div>
                <div>
                  <span className="text-gray-500">Last seen:</span>
                  <span className="ml-2 text-white">{formatDate(selectedFinding.last_seen_at)}</span>
                </div>
              </div>
              {selectedFinding.url && (
                <div>
                  <span className="text-gray-500 text-sm">URL:</span>
                  <p className="text-sm text-blue-400 break-all mt-1">{selectedFinding.url}</p>
                </div>
              )}
              <div className="pt-4 border-t border-gray-800">
                <span className="text-sm text-gray-500">Change Status:</span>
                <div className="flex gap-2 mt-2">
                  {FINDING_STATUSES.map((status) => (
                    <button
                      key={status}
                      onClick={() => handleStatusChange(selectedFinding.id, status, selectedFinding.scan_id)}
                      disabled={selectedFinding.status === status}
                      className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                        selectedFinding.status === status
                          ? 'bg-blue-600 text-white cursor-default'
                          : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                      }`}
                    >
                      {status.replace('_', ' ')}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    active: 'bg-yellow-500/20 text-yellow-400',
    resolved: 'bg-green-500/20 text-green-400',
    false_positive: 'bg-gray-500/20 text-gray-400',
    accepted_risk: 'bg-purple-500/20 text-purple-400'
  }

  return (
    <span className={`px-2 py-0.5 text-xs font-medium rounded ${styles[status] || styles.active}`}>
      {status.replace('_', ' ')}
    </span>
  )
}

export default function FindingsPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center h-32">
        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500"></div>
      </div>
    }>
      <FindingsContent />
    </Suspense>
  )
}
