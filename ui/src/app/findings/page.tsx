'use client'

import { useEffect, useState, useRef, Suspense } from 'react'
import Link from 'next/link'
import { getFindings, cleanupFindings, getDomains, getSeverityBg, formatDate, type Finding } from '@/lib/api'
import { useUrlFilters } from '@/lib/useUrlFilters'
import { SEVERITY_LEVELS, FINDING_STATUSES, SORT_OPTIONS, LAST_SEEN_OPTIONS, CLEANUP_AGE_OPTIONS, type SortOption, type SortOrder } from '@/lib/constants'

const PAGE_SIZE = 50
const SEARCH_DEBOUNCE_MS = 300

interface FindingsFilters {
  [key: string]: string | number | undefined
  severity?: string
  status?: string
  source_type?: string
  domain?: string
  scan_id?: string
  target_id?: string
  search?: string
  last_seen?: number
  verification_verdict?: string
  verification_mode?: string
  verified_only?: string
  sort_by?: string
  sort_order?: string
  page?: number
}

const VERIFICATION_VERDICTS = [
  'exploited',
  'likely_vulnerable',
  'blocked_by_security',
  'out_of_scope_internal',
  'false_positive',
  'likely_fixed',
  'inconclusive',
  'error'
] as const

const SOURCE_TYPE_OPTIONS = [
  { value: '', label: 'All' },
  { value: 'dast', label: 'DAST' },
  { value: 'ai', label: 'AI' }
] as const

function getFindingSourceType(finding: Finding): 'AI' | 'DAST' {
  if (finding.source === 'ai_gate' || finding.source === 'ai_session' || finding.ai_target_id) {
    return 'AI'
  }
  return 'DAST'
}

function getSourceTypeClass(type: 'AI' | 'DAST'): string {
  if (type === 'AI') return 'bg-purple-500/20 text-purple-300'
  return 'bg-blue-500/20 text-blue-300'
}

function getSortOrderLabel(sortBy: SortOption, sortOrder: SortOrder): string {
  if (sortBy === 'last_seen' || sortBy === 'first_seen') {
    return sortOrder === 'desc' ? 'Newest first' : 'Oldest first'
  }
  if (sortBy === 'cvss') {
    return sortOrder === 'desc' ? 'Highest first' : 'Lowest first'
  }
  return sortOrder === 'desc' ? 'Critical first' : 'Info first'
}

function FindingsContent() {
  const { filters, setFilter, buildUrl } = useUrlFilters<FindingsFilters>({
    defaults: { sort_by: 'severity', sort_order: 'desc', page: 1 }
  })

  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [domains, setDomains] = useState<string[]>([])
  const [total, setTotal] = useState(0)
  const [searchInput, setSearchInput] = useState<string>(filters.search || '')
  const searchTimeout = useRef<NodeJS.Timeout | null>(null)
  const [showCleanup, setShowCleanup] = useState(false)
  const [cleanupDays, setCleanupDays] = useState(90)
  const [cleanupStatus, setCleanupStatus] = useState('')
  const [cleanupDomain, setCleanupDomain] = useState('')
  const [cleanupPreview, setCleanupPreview] = useState<number | null>(null)
  const [cleanupLoading, setCleanupLoading] = useState(false)

  const severityFilter = filters.severity || ''
  const statusFilter = filters.status || ''
  const sourceTypeFilter = filters.source_type || ''
  const domainFilter = filters.domain || ''
  const scanIdFilter = filters.scan_id || ''
  const targetIdFilter = filters.target_id || ''
  const searchQuery = filters.search || ''
  const lastSeenFilter = filters.last_seen ? Number(filters.last_seen) : 0
  const verificationVerdictFilter = filters.verification_verdict || ''
  const verificationModeFilter = filters.verification_mode || ''
  const verifiedOnlyFilter = filters.verified_only === 'true'
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
  }, [severityFilter, statusFilter, sourceTypeFilter, domainFilter, scanIdFilter, targetIdFilter, searchQuery, lastSeenFilter, verificationVerdictFilter, verificationModeFilter, verifiedOnlyFilter, rawPage, sortBy, sortOrder])

  async function fetchFindings() {
    try {
      setLoading(true)
      const data = await getFindings({
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
        source_type: sourceTypeFilter ? (sourceTypeFilter as 'dast' | 'ai') : undefined,
        root_domain: domainFilter || undefined,
        scan_id: scanIdFilter || undefined,
        target_id: targetIdFilter || undefined,
        search: searchQuery || undefined,
        seen_within_days: lastSeenFilter || undefined,
        verification_verdict: verificationVerdictFilter ? (verificationVerdictFilter as 'exploited' | 'likely_vulnerable' | 'blocked_by_security' | 'out_of_scope_internal' | 'false_positive' | 'likely_fixed' | 'inconclusive' | 'error') : undefined,
        verification_mode: verificationModeFilter ? (verificationModeFilter as 'deterministic' | 'ai_driven') : undefined,
        verified_only: verifiedOnlyFilter || undefined,
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

  async function handleCleanupPreview() {
    setCleanupLoading(true)
    try {
      const result = await cleanupFindings({
        older_than_days: cleanupDays,
        status: cleanupStatus || undefined,
        root_domain: cleanupDomain || undefined,
        dry_run: true
      })
      setCleanupPreview(result.would_delete ?? 0)
    } catch (err) {
      console.error('Cleanup preview failed:', err)
    } finally {
      setCleanupLoading(false)
    }
  }

  async function handleCleanupDelete() {
    if (cleanupPreview === null || cleanupPreview === 0) return
    if (!confirm(`Delete ${cleanupPreview} finding${cleanupPreview !== 1 ? 's' : ''} permanently?`)) return
    setCleanupLoading(true)
    try {
      await cleanupFindings({
        older_than_days: cleanupDays,
        status: cleanupStatus || undefined,
        root_domain: cleanupDomain || undefined,
        dry_run: false
      })
      setShowCleanup(false)
      setCleanupPreview(null)
      await fetchFindings()
    } catch (err) {
      console.error('Cleanup failed:', err)
    } finally {
      setCleanupLoading(false)
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
    if (sourceTypeFilter) params.set('return_source_type', sourceTypeFilter)
    if (domainFilter) params.set('return_domain', domainFilter)
    if (scanIdFilter) params.set('return_scan_id', scanIdFilter)
    if (targetIdFilter) params.set('return_target_id', targetIdFilter)
    if (searchQuery) params.set('return_search', searchQuery)
    if (verificationVerdictFilter) params.set('return_verification_verdict', verificationVerdictFilter)
    if (verificationModeFilter) params.set('return_verification_mode', verificationModeFilter)
    if (verifiedOnlyFilter) params.set('return_verified_only', 'true')
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
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Findings</h1>
          <p className="text-gray-400 mt-1">
            Vulnerability findings across all scans
            {scanIdFilter && <span className="text-blue-400"> (filtered by scan)</span>}
            {targetIdFilter && <span className="text-blue-400"> (filtered by target)</span>}
          </p>
        </div>
        <button
          onClick={() => { setShowCleanup(!showCleanup); setCleanupPreview(null) }}
          className="px-3 py-1.5 bg-gray-800 text-gray-400 rounded-lg text-sm hover:bg-gray-700 shrink-0"
        >
          Cleanup old findings
        </button>
      </div>

      {/* Cleanup Panel */}
      {showCleanup && (
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4 space-y-4">
          <h3 className="text-sm font-medium text-white">Cleanup Old Findings</h3>
          <div className="flex flex-wrap items-end gap-4">
            <div>
              <label className="text-xs text-gray-400 block mb-1">Not seen in</label>
              <select
                value={cleanupDays}
                onChange={(e) => { setCleanupDays(Number(e.target.value)); setCleanupPreview(null) }}
                className="px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
              >
                {CLEANUP_AGE_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-xs text-gray-400 block mb-1">Status (optional)</label>
              <select
                value={cleanupStatus}
                onChange={(e) => { setCleanupStatus(e.target.value); setCleanupPreview(null) }}
                className="px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
              >
                <option value="">Any status</option>
                {FINDING_STATUSES.map((s) => (
                  <option key={s} value={s}>{s.replace('_', ' ')}</option>
                ))}
              </select>
            </div>
            {domains.length > 0 && (
              <div>
                <label className="text-xs text-gray-400 block mb-1">Domain (optional)</label>
                <select
                  value={cleanupDomain}
                  onChange={(e) => { setCleanupDomain(e.target.value); setCleanupPreview(null) }}
                  className="px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
                >
                  <option value="">All domains</option>
                  {domains.map((d) => (
                    <option key={d} value={d}>{d}</option>
                  ))}
                </select>
              </div>
            )}
            <button
              onClick={handleCleanupPreview}
              disabled={cleanupLoading}
              className="px-3 py-1.5 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700 disabled:opacity-50"
            >
              {cleanupLoading ? 'Checking...' : 'Preview'}
            </button>
            {cleanupPreview !== null && (
              <>
                <span className="text-sm text-gray-400">
                  {cleanupPreview === 0
                    ? 'No findings match'
                    : `${cleanupPreview} finding${cleanupPreview !== 1 ? 's' : ''} will be deleted`}
                </span>
                {cleanupPreview > 0 && (
                  <button
                    onClick={handleCleanupDelete}
                    disabled={cleanupLoading}
                    className="px-3 py-1.5 bg-red-900/50 text-red-400 rounded-lg text-sm hover:bg-red-900/80 disabled:opacity-50"
                  >
                    Delete
                  </button>
                )}
              </>
            )}
          </div>
        </div>
      )}

      {/* Filters Row */}
      <div className="flex flex-wrap items-center gap-4">
        {/* Source Type Filter */}
        <div className="flex items-center gap-2">
          <label className="text-sm text-gray-400">Type:</label>
          <div className="inline-flex rounded-lg border border-gray-800 bg-gray-900 p-0.5">
            {SOURCE_TYPE_OPTIONS.map((option) => (
              <button
                key={option.label}
                type="button"
                onClick={() => setFilter('source_type', option.value || undefined)}
                className={`px-3 py-1 text-sm rounded-md transition-colors ${
                  sourceTypeFilter === option.value
                    ? 'bg-blue-600 text-white'
                    : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
                }`}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>

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

        {/* Last Seen Filter */}
        <div className="flex items-center gap-2">
          <label className="text-sm text-gray-400">Last seen:</label>
          <select
            value={lastSeenFilter || ''}
            onChange={(e) => setFilter('last_seen', e.target.value ? Number(e.target.value) : undefined)}
            className="px-3 py-1.5 bg-gray-900 border border-gray-800 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
          >
            <option value="">All time</option>
            {LAST_SEEN_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>

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
            className="px-3 py-1.5 bg-gray-900 border border-gray-800 rounded-lg text-white text-sm hover:bg-gray-800 focus:outline-none focus:border-blue-500"
            title={`Toggle sort direction: ${getSortOrderLabel(sortBy, sortOrder)}`}
          >
            {getSortOrderLabel(sortBy, sortOrder)}
          </button>
        </div>

        {/* Verification Verdict Filter */}
        <div className="flex items-center gap-2">
          <label className="text-sm text-gray-400">Verdict:</label>
          <select
            value={verificationVerdictFilter}
            onChange={(e) => setFilter('verification_verdict', e.target.value || undefined)}
            className="px-3 py-1.5 bg-gray-900 border border-gray-800 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
          >
            <option value="">All</option>
            {VERIFICATION_VERDICTS.map((verdict) => (
              <option key={verdict} value={verdict}>{verdict.replaceAll('_', ' ')}</option>
            ))}
          </select>
        </div>

        {/* Verification Mode Filter */}
        <div className="flex items-center gap-2">
          <label className="text-sm text-gray-400">Mode:</label>
          <select
            value={verificationModeFilter}
            onChange={(e) => setFilter('verification_mode', e.target.value || undefined)}
            className="px-3 py-1.5 bg-gray-900 border border-gray-800 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
          >
            <option value="">All</option>
            <option value="deterministic">deterministic</option>
            <option value="ai_driven">ai driven</option>
          </select>
        </div>

        {/* Verified Only */}
        <label className="flex items-center gap-2 text-sm text-gray-300">
          <input
            type="checkbox"
            checked={verifiedOnlyFilter}
            onChange={(e) => setFilter('verified_only', e.target.checked ? 'true' : undefined)}
            className="h-4 w-4 rounded border-gray-700 bg-gray-900 text-blue-600 focus:ring-blue-500"
          />
          exploited only
        </label>

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
            {findings.map((finding) => {
              const sourceType = getFindingSourceType(finding)
              return (
                <Link
                  key={finding.id}
                  href={buildDetailUrl(finding.id)}
                  className="block p-4 hover:bg-gray-800/50 transition-colors"
                >
                  <div className="flex items-start gap-3">
                    <span className={`px-2 py-0.5 text-xs font-medium rounded shrink-0 ${getSeverityBg(finding.severity)}`}>
                      {finding.severity}
                    </span>
                    <span className={`px-2 py-0.5 text-xs font-medium rounded shrink-0 ${getSourceTypeClass(sourceType)}`}>
                      {sourceType}
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
                </Link>
              )
            })}
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
