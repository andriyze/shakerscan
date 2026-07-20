'use client'

import { useEffect, useState, useCallback, useMemo, useRef, Suspense } from 'react'
import Link from 'next/link'
import { getScans, cancelScan, getCampaigns, getDomains, getGradeColor, formatDate, formatDuration, submitScan, type Campaign, type Scan } from '@/lib/api'
import { useUrlFilters } from '@/lib/useUrlFilters'
import { SCAN_STATUSES, SCAN_TYPES, type ScanType } from '@/lib/constants'
import { Plus, Search } from 'lucide-react'
import { buttonClasses, Card, ConfirmDialog, ErrorState, Input, LastUpdated, PageHeader, ScanStatusBadge, Select, TableSkeleton, useToast } from '@/components/ui'
import { episodesStarted, findingCount, RunStatusBadge, runState } from '@/components/hunt'

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

function huntTargetUrl(campaign: Campaign): string {
  const url = campaign.target_scope?.url
  return typeof url === 'string' && url.trim() ? url : ''
}

function huntTargetLabel(campaign: Campaign): string {
  return huntTargetUrl(campaign) || campaign.name || 'Target-bound autonomous hunt'
}

function huntMatchesFilters(campaign: Campaign, status: string, domain: string, search: string): boolean {
  if (status && !['active', 'running', 'pending', 'queued'].includes(status.toLowerCase())) return false
  const target = huntTargetUrl(campaign).toLowerCase()
  if (domain && !target.includes(domain.toLowerCase())) return false
  const query = search.trim().toLowerCase()
  return !query || `${campaign.name || ''} ${target}`.toLowerCase().includes(query)
}

interface ScansFilters {
  [key: string]: string | number | undefined
  status?: string
  domain?: string
  search?: string
  page?: number
  include_internal?: string
}

function ScansContent() {
  const { filters, setFilter, setFilters, buildUrl } = useUrlFilters<ScansFilters>({
    defaults: { page: 1 }
  })
  const toast = useToast()

  const [scans, setScans] = useState<Scan[]>([])
  const [activeHunts, setActiveHunts] = useState<Campaign[]>([])
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
  // Continuous-ASM batch/recon scans are hidden from this list by default (they
  // are internal coverage work, not user-initiated scans). This opt-in surfaces
  // them so an "active ASM scan" is reachable here too.
  const includeInternal = filters.include_internal === 'true'
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
        include_internal: includeInternal || undefined,
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
  }, [statusFilter, domainFilter, searchQuery, withinFilter, includeInternal, rawPage, setFilter])

  const fetchActiveHunts = useCallback(async (): Promise<boolean> => {
    try {
      const data = await getCampaigns({ status: 'active', limit: 50 })
      setActiveHunts((data.campaigns || []).filter((campaign) => campaign.campaign_type === 'autonomous_research'))
      return true
    } catch (err) {
      console.error('Failed to fetch active autonomous hunts:', err)
      return false
    }
  }, [])

  useEffect(() => {
    fetchScans()
    fetchActiveHunts()
    const interval = setInterval(() => {
      fetchScans(true)
      fetchActiveHunts()
    }, 5000)
    return () => clearInterval(interval)
  }, [fetchActiveHunts, fetchScans])

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
    const [scansOk, huntsOk] = await Promise.all([fetchScans(true), fetchActiveHunts()])
    setRefreshing(false)
    if (!scansOk || !huntsOk) {
      toast.error('Some work could not be refreshed')
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
  const visibleHunts = useMemo(
    () => activeHunts.filter((campaign) => huntMatchesFilters(campaign, statusFilter, domainFilter, searchQuery)),
    [activeHunts, statusFilter, domainFilter, searchQuery],
  )

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
      <PageHeader
        title="Scans"
        description="Scans and active autonomous testing in one place"
        actions={
          <>
            <LastUpdated updatedAt={lastUpdated} onRefresh={handleManualRefresh} refreshing={refreshing} />
            <Link href="/scan/new" className={buttonClasses('primary')}>
              <Plus className="h-4 w-4" aria-hidden="true" />
              New Scan
            </Link>
          </>
        }
      />

      {/* Filters */}
      <div className="flex gap-4 flex-wrap">
        {/* Status Filter */}
        <div className="flex items-center gap-3">
          <label className="text-sm text-gray-400">Status:</label>
          <Select
            fullWidth={false}
            value={statusFilter}
            onChange={(e) => setFilter('status', e.target.value || undefined)}
            aria-label="Filter by scan status"
          >
            <option value="">All statuses</option>
            {SCAN_STATUSES.map((status) => (
              <option key={status} value={status}>{status}</option>
            ))}
          </Select>
        </div>

        {/* Domain Filter */}
        {domains.length > 0 && (
          <div className="flex items-center gap-3">
            <label className="text-sm text-gray-400">Domain:</label>
            <Select
              fullWidth={false}
              value={domainFilter}
              onChange={(e) => setFilter('domain', e.target.value || undefined)}
              aria-label="Filter by domain"
            >
              <option value="">All domains</option>
              {domains.map((domain) => (
                <option key={domain} value={domain}>{domain}</option>
              ))}
            </Select>
          </div>
        )}

        {/* Search */}
        <div className="relative flex-1 min-w-[200px]">
          <Input
            type="text"
            placeholder="Search by target URL..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            aria-label="Search scans by target URL"
            className="pr-10"
          />
          <Search className="pointer-events-none absolute right-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" aria-hidden="true" />
        </div>

        {/* Show Continuous-ASM batch/recon scans (hidden by default) */}
        <label className="flex items-center gap-2 self-center text-sm text-gray-400 cursor-pointer">
          <input
            type="checkbox"
            checked={includeInternal}
            onChange={(e) => setFilter('include_internal', e.target.checked ? 'true' : undefined)}
            aria-label="Show ASM and internal scans"
            className="h-4 w-4 rounded border-gray-700 bg-gray-900 text-blue-600 focus:ring-blue-500"
          />
          Show ASM/internal scans
        </label>

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
            {visibleHunts.length > 0 ? ` · ${visibleHunts.length} active hunt${visibleHunts.length === 1 ? '' : 's'}` : ''}
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
        ) : scans.length === 0 && visibleHunts.length === 0 ? (
          <div className="p-8 text-center">
            <p className="text-gray-500">
              {searchQuery || domainFilter || statusFilter ? 'No scans found matching your filters.' : 'No scans yet.'}
            </p>
            <p className="mt-1 text-sm text-gray-600">
              {searchQuery || domainFilter || statusFilter ? 'Try clearing your filters.' : 'Start a new scan to get started.'}
            </p>
          </div>
        ) : (
          <>
          {/* Mobile / tablet card layout (below lg): the desktop table scrolls
              the important columns off-screen on a phone, so render each scan as
              a stacked card with everything visible in the first viewport. */}
          <div className="lg:hidden space-y-3 p-3">
            {visibleHunts.map((campaign) => {
              const progress = episodesStarted(campaign)
              const found = findingCount(campaign)
              const createdAtMs = Date.parse(campaign.created_at)
              const duration = Number.isNaN(createdAtMs)
                ? '-'
                : formatDuration(Math.max(0, Math.floor((durationTickMs - createdAtMs) / 1000)))
              return (
                <div key={`hunt-${campaign.id}`} className="rounded-lg border border-blue-500/30 bg-blue-500/[0.04] p-4">
                  <div className="flex items-start justify-between gap-3">
                    <Link
                      href={`/settings/research-agent/runs/${campaign.id}`}
                      className="min-w-0 flex-1 truncate text-sm font-medium text-blue-300 hover:text-blue-200"
                      title={huntTargetLabel(campaign)}
                    >
                      {huntTargetLabel(campaign)}
                    </Link>
                    <RunStatusBadge state={runState(campaign)} />
                  </div>
                  <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
                    <span className="text-gray-400">No score yet</span>
                    <span className={found > 0 ? 'text-emerald-300' : 'text-gray-400'}>
                      {found} active finding{found === 1 ? '' : 's'}
                    </span>
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-gray-500">
                    <span className="text-blue-300">Verifier · legacy</span>
                    {progress.max > 0 ? (
                      <span className="rounded bg-gray-800 px-1.5 py-0.5 text-gray-400">
                        Episode {progress.started}/{progress.max}
                      </span>
                    ) : null}
                    <span aria-hidden="true">·</span>
                    <span>{duration}</span>
                    <span aria-hidden="true">·</span>
                    <span>{formatDate(campaign.created_at)}</span>
                  </div>
                  <div className="mt-3">
                    <Link
                      href={`/settings/research-agent/runs/${campaign.id}`}
                      className="inline-flex rounded bg-blue-600 px-2 py-1 text-xs font-medium text-white hover:bg-blue-700"
                    >
                      View hunt
                    </Link>
                  </div>
                </div>
              )
            })}
            {scans.map((scan) => {
              const isAIScan = scan.scan_type === 'ai_gate' || scan.run_kind?.startsWith('ai_')
              const authenticated = isAuthenticatedScan(scan)
              const aiTargetType = formatAITargetType(scan.ai_target_type)
              const scanTypeLabel = formatScanTypeLabel(scan)
              const parallelParent = isParallelParent(scan)
              const asmBatch = scan.scan_role === 'asm_batch'
              const asmRecon = scan.scan_role === 'asm_recon'
              const variantLabel = asmBatch
                ? 'ASM batch'
                : asmRecon
                  ? 'ASM recon'
                  : parallelParent
                    ? 'Parallel'
                    : aiTargetType || (authenticated ? 'Authenticated' : null)
              const canCancel = scan.status === 'running' || scan.status === 'pending' || scan.status === 'queued'
              return (
                <div key={scan.id} className="rounded-lg border border-gray-800 bg-gray-900 p-4">
                  <div className="flex items-start justify-between gap-3">
                    <Link
                      href={buildUrl(`/scans/${scan.id}`, {
                        return_status: statusFilter,
                        return_domain: domainFilter,
                        return_search: searchQuery,
                        return_page: page > 1 ? page : undefined,
                        return_include_internal: includeInternal ? 'true' : undefined
                      })}
                      className="min-w-0 flex-1 truncate text-sm font-medium text-blue-400 hover:text-blue-300"
                      title={scan.target_url}
                    >
                      {scan.target_url}
                    </Link>
                    <ScanStatusBadge status={scan.status} />
                  </div>
                  <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
                    {scan.grade ? (
                      <div className="flex items-center gap-1.5">
                        <span className={`text-lg font-bold ${getGradeColor(scan.grade)}`}>{scan.grade}</span>
                        <span className="text-gray-500">{scan.score}/100</span>
                      </div>
                    ) : (
                      <span className="text-gray-500">No score</span>
                    )}
                    {(scan.findings_count || 0) > 0 ? (
                      <Link
                        href={`/findings?scan_id=${scan.id}`}
                        className="text-blue-400 hover:text-blue-300"
                      >
                        {scan.findings_count} finding{scan.findings_count === 1 ? '' : 's'}
                      </Link>
                    ) : (
                      <span className="text-gray-400">0 findings</span>
                    )}
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-gray-500">
                    <span className="text-gray-300">{scanTypeLabel}</span>
                    {variantLabel && (
                      <span className="rounded bg-gray-800 px-1.5 py-0.5 text-gray-400">{variantLabel}</span>
                    )}
                    <span aria-hidden="true">·</span>
                    <span>{getDurationLabel(scan)}</span>
                    <span aria-hidden="true">·</span>
                    <span>{formatDate(scan.created_at)}</span>
                  </div>
                  {(canCancel || isAIScan) && (
                    <div className="mt-3 flex items-center gap-2">
                      {canCancel ? (
                        <button
                          onClick={() => setConfirmCancelId(scan.id)}
                          disabled={cancelling.has(scan.id)}
                          className="px-2 py-1 bg-red-600/20 hover:bg-red-600/40 text-red-400 rounded text-xs font-medium transition-colors disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500"
                        >
                          {cancelling.has(scan.id) ? 'Cancelling...' : 'Cancel'}
                        </button>
                      ) : isAIScan ? (
                        <Link
                          href="/ai-gate"
                          className="px-2 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-medium transition-colors"
                        >
                          AI Gate
                        </Link>
                      ) : null}
                    </div>
                  )}
                </div>
              )
            })}
          </div>

          {/* Desktop table layout (lg and up) */}
          <div className="hidden lg:block overflow-x-auto">
          <table className="w-full min-w-[760px] 2xl:min-w-full">
            <thead className="bg-gray-800/50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Target</th>
                <th className="hidden xl:table-cell px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Type</th>
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
              {visibleHunts.map((campaign) => {
                const progress = episodesStarted(campaign)
                const found = findingCount(campaign)
                const createdAtMs = Date.parse(campaign.created_at)
                const duration = Number.isNaN(createdAtMs)
                  ? '-'
                  : formatDuration(Math.max(0, Math.floor((durationTickMs - createdAtMs) / 1000)))
                return (
                  <tr key={`hunt-${campaign.id}`} className="bg-blue-500/[0.035] transition-colors hover:bg-blue-500/[0.07]">
                    <td className="max-w-[20rem] px-4 py-3">
                      <Link
                        href={`/settings/research-agent/runs/${campaign.id}`}
                        className="block truncate text-sm text-blue-300 hover:text-blue-200"
                        title={huntTargetLabel(campaign)}
                      >
                        {huntTargetLabel(campaign)}
                      </Link>
                    </td>
                    <td className="hidden px-4 py-3 xl:table-cell">
                      <span className="text-sm text-blue-300">Verifier · legacy</span>
                      {progress.max > 0 ? <div className="mt-0.5 text-xs text-gray-500">Episode {progress.started}/{progress.max}</div> : null}
                    </td>
                    <td className="hidden px-4 py-3 text-center text-gray-600 2xl:table-cell">—</td>
                    <td className="px-4 py-3"><RunStatusBadge state={runState(campaign)} /></td>
                    <td className="px-4 py-3 text-gray-600">—</td>
                    <td className="px-4 py-3">
                      {found > 0 && campaign.target_id ? (
                        <Link href={`/findings?target_id=${campaign.target_id}&status=active`} className="text-sm text-emerald-300 hover:text-emerald-200">{found}</Link>
                      ) : <span className="text-sm text-gray-400">{found}</span>}
                    </td>
                    <td className="hidden px-4 py-3 text-sm text-gray-400 xl:table-cell">{duration}</td>
                    <td className="hidden px-4 py-3 text-sm text-gray-500 2xl:table-cell">{formatDate(campaign.created_at)}</td>
                    <td className="px-4 py-3">
                      <Link
                        href={`/settings/research-agent/runs/${campaign.id}`}
                        className="inline-flex rounded bg-blue-600 px-2 py-1 text-xs font-medium text-white hover:bg-blue-700"
                      >
                        View
                      </Link>
                    </td>
                  </tr>
                )
              })}
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
                        return_page: page > 1 ? page : undefined,
                        return_include_internal: includeInternal ? 'true' : undefined
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
                  <td className="hidden xl:table-cell px-4 py-3">
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
                        href="/ai-gate"
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
          </>
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
            {visibleHunts.length > 0 ? ` · ${visibleHunts.length} active hunt${visibleHunts.length === 1 ? '' : 's'}` : ''}
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
    <Suspense fallback={<Card><TableSkeleton rows={8} cols={6} /></Card>}>
      <ScansContent />
    </Suspense>
  )
}
