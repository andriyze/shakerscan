'use client'
import { featureEnabled } from '@/lib/workspaceCapabilities'

import { useEffect, useState, useCallback, useMemo, useRef, Suspense } from 'react'
import Link from '@/components/WorkspaceLink'
import { getScans, cancelScan, getCampaigns, getDomains, getGradeColor, formatDate, formatDuration, submitScanV2, type Campaign, type Scan } from '@/lib/api'
import { assuranceClass, scanAssurance } from '@/lib/assurance.mjs'
import { useUrlFilters } from '@/lib/useUrlFilters'
import { SCAN_STATUSES } from '@/lib/constants'
import { Plus, X } from 'lucide-react'
import { Button, buttonClasses, Card, ConfirmDialog, ErrorState, LastUpdated, PageHeader, ROW_ACTION_REVEAL, ScanStatusBadge, SearchInput, Select, tableStyles, TableSkeleton, Toolbar, useToast } from '@/components/ui'
import { episodesStarted, findingCount, RunStatusBadge, runState } from '@/components/hunt'
import { boundedTargetDisplay } from '@/lib/targetChoices'

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

// A grade alone cannot say whether a clean result came from a thorough scan or one that
// barely ran. The examination strength sits next to the letter, not in its own column, so the
// two are read together.
function AssuranceChip({ scan }: { scan: Scan }) {
  const assurance = scanAssurance(scan)
  if (!assurance) {
    return (
      <span className="text-xs text-amber-200">
        Examination strength unavailable
      </span>
    )
  }
  return (
    <span
      className={`text-xs ${assuranceClass(assurance.band)}`}
      title={`Examination strength ${assurance.score}/100 - ${assurance.label}`}
    >
      {assurance.label} · {assurance.score}/100
    </span>
  )
}

function ObservedPosture({ scan, compact = false }: { scan: Scan; compact?: boolean }) {
  if (scan.status !== 'completed') {
    return <span className="text-sm text-gray-500">Not available</span>
  }
  if (scan.risk_assessment_state === 'not_examined' || scan.application_observed === false) {
    return <span className="text-sm text-amber-200">Application not examined</span>
  }
  if (!scan.grade) {
    return <span className="text-sm text-gray-500">No observed posture</span>
  }
  const assurance = scanAssurance(scan)
  const weak = assurance && ['none', 'weak', 'limited'].includes(String(assurance.band || 'none'))
  return (
    <div className="min-w-0">
      {/* The table's column header names the value; the stacked mobile card names it here. */}
      {compact && <div className="text-xs text-gray-500">Observed posture</div>}
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
        <span className="inline-flex items-baseline gap-1 whitespace-nowrap">
          <span
            className={`text-base font-semibold ${weak ? 'text-gray-200' : getGradeColor(scan.grade)}`}
            title={scan.grade.includes('*') ? 'The asterisk marks assurance limitations; this is not a clean bill of health.' : 'Risk observed by this run; this is not an overall safety score.'}
          >
            {scan.grade}
          </span>
          <span className="text-xs tabular-nums text-gray-500">{scan.score}/100</span>
        </span>
        <AssuranceChip scan={scan} />
      </div>
    </div>
  )
}

// Every row is a Scan, so the table names only the budget profile ("Thorough"); other run
// kinds (AI Gate, legacy types) keep their full label.
function scanProfileLabel(label: string): string {
  return label.startsWith('Scan · ') ? label.slice('Scan · '.length) : label
}

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
  const options = scan.options && typeof scan.options === 'object' ? scan.options : {}
  if (options.scan_generation === 'v2' && !options.legacy_scan_type) {
    const budget = typeof options.budget_profile === 'string' ? options.budget_profile : 'balanced'
    return `Scan · ${budget.charAt(0).toUpperCase()}${budget.slice(1)}`
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
  return boundedTargetDisplay({
    url: huntTargetUrl(campaign) || campaign.name,
  }) || 'Autonomous run'
}

function scanTargetLabel(scan: Scan): string {
  return boundedTargetDisplay({ url: scan.target_url }) || 'Unknown target'
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
  target_id?: string
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
  const [durationTickMs, setDurationTickMs] = useState<number>(Date.now())
  const searchTimeout = useRef<NodeJS.Timeout | null>(null)

  const statusFilter = filters.status || ''
  const domainFilter = filters.domain || ''
  const searchQuery = filters.search || ''
  // Time cohort (?within=7) — exposure "What changed" links use it so the
  // destination shows the same windowed slice the tile counted.
  const withinFilter = filters.within ? Number(filters.within) : 0
  const targetIdFilter = filters.target_id || ''
  // Continuous-ASM batch/recon scans are hidden from this list by default (they
  // are internal coverage work, not user-initiated scans). This opt-in surfaces
  // them so an "active ASM scan" is reachable here too.
  const includeInternal = filters.include_internal === 'true'
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

  const fetchScans = useCallback(async (isPolling = false): Promise<boolean> => {
    // Only show loading skeleton on initial load, not polling refreshes
    if (!isPolling) {
      setLoading(true)
    }
    try {
      const data = await getScans({
        status: statusFilter || undefined,
        root_domain: domainFilter || undefined,
        target_id: targetIdFilter || undefined,
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
  }, [statusFilter, domainFilter, targetIdFilter, searchQuery, withinFilter, includeInternal, rawPage, setFilter])

  const fetchActiveHunts = useCallback(async (): Promise<boolean> => {
    if (!featureEnabled('hunt')) return true
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

  async function handleScan(targetUrl: string) {
    try {
      const result = await submitScanV2({ target: targetUrl, budget_profile: 'balanced' })
      const started = result?.auto_sharded ? 'Auto-sharded scan started' : result?.parallel ? 'Parallel scan started' : 'Scan started'
      toast[result?.notice ? 'info' : 'success'](
        result?.notice ? `${started}. ${result.notice}` : started,
        result?.scan_id
          ? { link: { href: `/scans/${result.scan_id}`, label: 'View scan' } }
          : undefined
      )
      fetchScans(true)
    } catch (err) {
      console.error('Failed to start scan:', err)
      toast.error(err instanceof Error ? err.message : 'Failed to start scan')
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
        <Button
          variant="secondary"
          size="sm"
          onClick={() => setFilter('page', page > 1 ? page - 1 : undefined)}
          disabled={page <= 1}
        >
          Previous
        </Button>
        <span className="px-1 text-xs tabular-nums text-gray-400">
          Page {page} of {totalPages}
        </span>
        <Button
          variant="secondary"
          size="sm"
          onClick={() => setFilter('page', page + 1)}
          disabled={page >= totalPages}
        >
          Next
        </Button>
      </div>
    ) : null
  )

  const showingLabel = (
    <span className="text-xs tabular-nums text-gray-400">
      {total <= PAGE_SIZE
        ? `Showing ${total} scan${total !== 1 ? 's' : ''}`
        : `Showing ${(page - 1) * PAGE_SIZE + 1}-${Math.min(page * PAGE_SIZE, total)} of ${total}`
      }
      {visibleHunts.length > 0 ? ` · ${visibleHunts.length} active hunt${visibleHunts.length === 1 ? '' : 's'}` : ''}
    </span>
  )
  const filterChipClass =
    'inline-flex items-center gap-1.5 rounded-lg border border-gray-700 bg-gray-900 px-2.5 py-1 text-xs text-gray-300 ' +
    'hover:border-gray-600 hover:bg-gray-800 hover:text-white focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500'

  return (
    <div>
      <PageHeader
        title="Scans"
        description="Deterministic DAST runs and their coverage."
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

      <Toolbar>
        <SearchInput
          wrapperClassName="min-w-[220px] flex-1 sm:max-w-sm"
          placeholder="Search by target URL…"
          value={searchInput}
          onValueChange={setSearchInput}
          aria-label="Search scans by target URL"
        />
        <Select
          fullWidth={false}
          value={statusFilter}
          onChange={(e) => setFilter('status', e.target.value || undefined)}
          aria-label="Filter by scan status"
        >
          <option value="">All statuses</option>
          {SCAN_STATUSES.map((status) => (
            <option key={status} value={status}>{status.charAt(0).toUpperCase() + status.slice(1)}</option>
          ))}
        </Select>
        {domains.length > 0 && (
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
        )}

        {/* Target chip (deep-linked from a target's scan history) */}
        {targetIdFilter && (
          <button
            type="button"
            onClick={() => setFilter('target_id', undefined)}
            aria-label="Remove filter: one target"
            data-testid="scans-target-filter"
            className={filterChipClass}
          >
            {scans.find((scan) => scan.target_id === targetIdFilter)?.target_url || 'One target'}
            <X className="h-3.5 w-3.5 text-gray-500" aria-hidden="true" />
          </button>
        )}

        {/* Time cohort chip (deep-linked from exposure "What changed") */}
        {withinFilter > 0 && (
          <button
            type="button"
            onClick={() => setFilter('within', undefined)}
            aria-label={`Remove filter: last ${withinFilter} days`}
            className={filterChipClass}
          >
            Last {withinFilter}d
            <X className="h-3.5 w-3.5 text-gray-500" aria-hidden="true" />
          </button>
        )}

        {/* Show Continuous-ASM batch/recon scans (hidden by default) */}
        <label className="ml-auto flex cursor-pointer items-center gap-2 whitespace-nowrap text-xs text-gray-400">
          <input
            type="checkbox"
            checked={includeInternal}
            onChange={(e) => setFilter('include_internal', e.target.checked ? 'true' : undefined)}
            aria-label="Show ASM and internal scans"
            className="h-3.5 w-3.5 accent-blue-500"
          />
          Show ASM/internal scans
        </label>
      </Toolbar>

      {/* Top Pagination */}
      {total > 0 && (
        <div className="mb-3 flex min-h-8 items-center justify-between gap-3">
          {showingLabel}
          <PaginationControls />
        </div>
      )}

      {/* Load Error */}
      {loadError && (
        <div className="mb-4"><ErrorState onRetry={() => fetchScans()} /></div>
      )}

      {/* Scans Table */}
      {!(loadError && scans.length === 0) && (
      <div className={tableStyles.container}>
        {loading ? (
          <TableSkeleton rows={8} cols={6} />
        ) : scans.length === 0 && visibleHunts.length === 0 ? (
          <div className="p-8 text-center">
            <p className="text-sm font-medium text-gray-300">
              {searchQuery || domainFilter || statusFilter ? 'No scans found matching your filters.' : 'No scans yet.'}
            </p>
            <p className="mt-1 text-sm text-gray-500">
              {searchQuery || domainFilter || statusFilter ? 'Try clearing your filters.' : 'Start a new scan to get started.'}
            </p>
          </div>
        ) : (
          <>
          {/* Mobile / tablet card layout (below lg): the desktop table scrolls
              the important columns off-screen on a phone, so render each scan as
              a stacked card with everything visible in the first viewport. */}
          <div className="divide-y divide-gray-800 lg:hidden">
            {visibleHunts.map((campaign) => {
              const progress = episodesStarted(campaign)
              const found = findingCount(campaign)
              const createdAtMs = Date.parse(campaign.created_at)
              const duration = Number.isNaN(createdAtMs)
                ? '-'
                : formatDuration(Math.max(0, Math.floor((durationTickMs - createdAtMs) / 1000)))
              return (
                <div key={`hunt-${campaign.id}`} className="p-4">
                  <div className="flex items-start justify-between gap-3">
                    <Link
                      href={`/deep-hunt/runs/${campaign.id}`}
                      className="min-w-0 flex-1 truncate text-sm font-medium text-gray-100 hover:text-blue-300"
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
                    <span className="text-gray-400">Verifier · legacy</span>
                    {progress.max > 0 ? (
                      <span className="rounded-sm bg-gray-800 px-1.5 py-0.5 text-gray-400">
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
                      href={`/deep-hunt/runs/${campaign.id}`}
                      className={buttonClasses('secondary', 'sm')}
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
                <div key={scan.id} className="p-4">
                  <div className="flex items-start justify-between gap-3">
                    <Link
                      href={buildUrl(`/scans/${scan.id}`, {
                        return_status: statusFilter,
                        return_domain: domainFilter,
                        return_search: searchQuery,
                        return_target_id: targetIdFilter || undefined,
                        return_within: withinFilter || undefined,
                        return_page: page > 1 ? page : undefined,
                        return_include_internal: includeInternal ? 'true' : undefined
                      })}
                      className="min-w-0 flex-1 truncate text-sm font-medium text-gray-100 hover:text-blue-300"
                      title={scanTargetLabel(scan)}
                    >
                      {scanTargetLabel(scan)}
                    </Link>
                    <ScanStatusBadge status={scan.status} />
                  </div>
                  <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
                    <ObservedPosture scan={scan} compact />
                    {(scan.findings_count || 0) > 0 ? (
                      <Link
                        href={`/findings?scan_id=${scan.id}&freshness=all`}
                        className="tabular-nums text-gray-100 hover:text-blue-300"
                      >
                        {scan.findings_count} finding{scan.findings_count === 1 ? '' : 's'}
                      </Link>
                    ) : (
                      <span className="text-gray-500">0 findings</span>
                    )}
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-gray-500">
                    <span className="text-gray-300">{scanTypeLabel}</span>
                    {variantLabel && (
                      <span className="rounded-sm bg-gray-800 px-1.5 py-0.5 text-gray-400">{variantLabel}</span>
                    )}
                    <span aria-hidden="true">·</span>
                    <span>{getDurationLabel(scan)}</span>
                    <span aria-hidden="true">·</span>
                    <span>{formatDate(scan.created_at)}</span>
                  </div>
                  {(canCancel || isAIScan) && (
                    <div className="mt-3 flex items-center gap-2">
                      {canCancel ? (
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={() => setConfirmCancelId(scan.id)}
                          disabled={cancelling.has(scan.id)}
                          className="text-red-300 hover:text-red-200"
                        >
                          {cancelling.has(scan.id) ? 'Cancelling...' : 'Cancel'}
                        </Button>
                      ) : isAIScan ? (
                        <Link
                          href="/ai-gate"
                          className={buttonClasses('secondary', 'sm')}
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
          <div className={`hidden lg:block ${tableStyles.scroll}`}>
          <table className={`${tableStyles.table} min-w-[760px] 2xl:min-w-full`}>
            <thead className={tableStyles.head}>
              <tr>
                <th scope="col" className={tableStyles.headerCell}>Target</th>
                <th scope="col" className={`hidden xl:table-cell ${tableStyles.headerCell}`}>Type</th>
                <th scope="col" className={`hidden 2xl:table-cell text-center ${tableStyles.headerCell}`}>Auth</th>
                <th scope="col" className={tableStyles.headerCell}>Status</th>
                <th scope="col" className={tableStyles.headerCell}>Observed posture</th>
                <th scope="col" className={`text-right ${tableStyles.headerCell}`}>Findings</th>
                <th scope="col" className={`hidden xl:table-cell text-right ${tableStyles.headerCell}`}>Duration</th>
                <th scope="col" className={`hidden 2xl:table-cell ${tableStyles.headerCell}`}>Date</th>
                <th scope="col" className={tableStyles.headerCell}><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {visibleHunts.map((campaign) => {
                const progress = episodesStarted(campaign)
                const found = findingCount(campaign)
                const createdAtMs = Date.parse(campaign.created_at)
                const duration = Number.isNaN(createdAtMs)
                  ? '-'
                  : formatDuration(Math.max(0, Math.floor((durationTickMs - createdAtMs) / 1000)))
                return (
                  <tr key={`hunt-${campaign.id}`} className={tableStyles.row}>
                    <td className={`max-w-[20rem] ${tableStyles.cell}`}>
                      <Link
                        href={`/deep-hunt/runs/${campaign.id}`}
                        className="block truncate font-medium text-gray-100 hover:text-blue-300"
                        title={huntTargetLabel(campaign)}
                      >
                        {huntTargetLabel(campaign)}
                      </Link>
                    </td>
                    <td className={`hidden xl:table-cell ${tableStyles.cell}`}>
                      <span className="whitespace-nowrap text-gray-300">Verifier · legacy</span>
                      {progress.max > 0 ? <div className="mt-0.5 text-xs text-gray-500">Episode {progress.started}/{progress.max}</div> : null}
                    </td>
                    <td className={`hidden 2xl:table-cell text-center text-gray-600 ${tableStyles.cell}`}>—</td>
                    <td className={tableStyles.cell}><RunStatusBadge state={runState(campaign)} /></td>
                    <td className={`text-gray-600 ${tableStyles.cell}`}>—</td>
                    <td className={`text-right tabular-nums ${tableStyles.cell}`}>
                      {found > 0 && campaign.target_id ? (
                        <Link href={`/findings?target_id=${campaign.target_id}&status=active&freshness=all`} className="font-medium text-gray-100 hover:text-blue-300">{found}</Link>
                      ) : <span className="text-gray-500">{found}</span>}
                    </td>
                    <td className={`hidden xl:table-cell whitespace-nowrap text-right tabular-nums text-gray-400 ${tableStyles.cell}`}>{duration}</td>
                    <td className={`hidden 2xl:table-cell whitespace-nowrap text-gray-500 ${tableStyles.cell}`}>{formatDate(campaign.created_at)}</td>
                    <td className={`text-right ${tableStyles.cell}`}>
                      <Link
                        href={`/deep-hunt/runs/${campaign.id}`}
                        className={buttonClasses('secondary', 'sm')}
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
                <tr key={scan.id} className={tableStyles.row}>
                  <td className={`max-w-[20rem] ${tableStyles.cell}`}>
                    <Link
                      href={buildUrl(`/scans/${scan.id}`, {
                        return_status: statusFilter,
                        return_domain: domainFilter,
                        return_search: searchQuery,
                        return_target_id: targetIdFilter || undefined,
                        return_within: withinFilter || undefined,
                        return_page: page > 1 ? page : undefined,
                        return_include_internal: includeInternal ? 'true' : undefined
                      })}
                      className="block truncate font-medium text-gray-100 hover:text-blue-300"
                      title={scanTargetLabel(scan)}
                    >
                      {scanTargetLabel(scan)}
                    </Link>
                  </td>
                  <td className={`hidden xl:table-cell ${tableStyles.cell}`}>
                    <div className="min-w-0">
                      <span className="whitespace-nowrap text-gray-300" title={scanTypeLabel}>{scanProfileLabel(scanTypeLabel)}</span>
                      {(asmBatch || asmRecon || parallelParent || aiTargetType || authenticated) && (
                        <div className="mt-0.5 truncate text-xs text-gray-500">
                          {asmBatch ? 'ASM batch' : asmRecon ? 'ASM recon' : parallelParent ? 'Parallel' : aiTargetType || 'Authenticated'}
                        </div>
                      )}
                    </div>
                  </td>
                  <td className={`hidden 2xl:table-cell text-center ${tableStyles.cell}`}>
                    {authenticated ? (
                      <span
                        className="inline-flex items-center justify-center text-emerald-400"
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
                  <td className={tableStyles.cell}>
                    <ScanStatusBadge status={scan.status} />
                  </td>
                  <td className={tableStyles.cell}>
                    <ObservedPosture scan={scan} />
                  </td>
                  <td className={`text-right tabular-nums ${tableStyles.cell}`}>
                    {(scan.findings_count || 0) > 0 ? (
                      <Link
                        href={`/findings?scan_id=${scan.id}&freshness=all`}
                        className="font-medium text-gray-100 hover:text-blue-300"
                      >
                        {scan.findings_count}
                      </Link>
                    ) : (
                      <span className="text-gray-500">0</span>
                    )}
                  </td>
                  <td className={`hidden xl:table-cell whitespace-nowrap text-right tabular-nums text-gray-400 ${tableStyles.cell}`}>
                    {getDurationLabel(scan)}
                  </td>
                  <td className={`hidden 2xl:table-cell whitespace-nowrap text-gray-500 ${tableStyles.cell}`}>
                    {formatDate(scan.created_at)}
                  </td>
                  <td className={`text-right ${tableStyles.cell}`}>
                    {(scan.status === 'running' || scan.status === 'pending' || scan.status === 'queued') ? (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setConfirmCancelId(scan.id)}
                        disabled={cancelling.has(scan.id)}
                        className="text-red-300 hover:text-red-200"
                      >
                        {cancelling.has(scan.id) ? 'Cancelling...' : 'Cancel'}
                      </Button>
                    ) : isAIScan ? (
                      <Link
                        href="/ai-gate"
                        className={buttonClasses('ghost', 'sm')}
                      >
                        AI Gate
                      </Link>
                    ) : (
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => handleScan(scan.target_url)}
                        className={`whitespace-nowrap ${ROW_ACTION_REVEAL}`}
                      >
                        Scan again
                      </Button>
                    )}
                  </td>
                </tr>
              )})}
            </tbody>
          </table>
          </div>
          </>
        )}
      </div>
      )}

      {/* Bottom Pagination */}
      {total > PAGE_SIZE && (
        <div className="mt-3 flex min-h-8 items-center justify-between gap-3">
          {showingLabel}
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
