'use client'

import { useEffect, useState, useRef, Suspense } from 'react'
import Link from 'next/link'
import { getFindings, cleanupFindings, getDomains, getSeverityBg, formatDate, getFindingResearchProvenance, type Finding } from '@/lib/api'
import { useUrlFilters } from '@/lib/useUrlFilters'
import { SEVERITY_LEVELS, FINDING_STATUSES, SORT_OPTIONS, LAST_SEEN_OPTIONS, CLEANUP_AGE_OPTIONS, type FindingSourceType, type SortOption, type SortOrder } from '@/lib/constants'
import {
  Button,
  Card,
  ConfirmDialog,
  EmptyState,
  ErrorState,
  FindingStatusBadge,
  Input,
  PageHeader,
  ProofStateBadge,
  RetestVerdictBadge,
  SeverityBadge,
  SourceTypeBadge,
  TableSkeleton,
  useToast,
  buttonClasses,
} from '@/components/ui'

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
  ai_target_id?: string
  device_target_id?: string
  driven_by?: string
  research_campaign_id?: string
  search?: string
  last_seen?: number
  first_seen_within?: number
  resolved_within?: number
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
  { value: 'device', label: 'Device' },
  { value: 'deep_hunt', label: 'Hunt' },
  { value: 'ai_gate', label: 'AI Gate' },
  { value: 'ai_session', label: 'Interactive' },
  { value: 'model_intake', label: 'Model Intake' },
  { value: 'asm', label: 'ASM' },
  { value: 'manual', label: 'Manual' },
] as const

type FindingSourceTypeFilter = 'dast' | 'device' | 'ai' | 'ai_gate' | 'ai_session' | 'deep_hunt' | 'autonomous' | 'model_intake' | 'asm' | 'manual'

function getFindingSourceType(finding: Finding): FindingSourceType {
  if (finding.source === 'device') {
    return 'Device'
  }
  if (finding.source === 'model_intake' || finding.tool === 'model_intake') {
    return 'Model Intake'
  }
  if (finding.source === 'ai_gate' || finding.ai_target_id) {
    return 'AI Gate'
  }
  if (finding.source === 'ai_session') {
    return 'Interactive'
  }
  if (finding.source === 'autonomous' || finding.tool === 'autonomous_workflow' || getFindingResearchProvenance(finding)) {
    return 'Hunt'
  }
  if (finding.source === 'asm') {
    return 'ASM'
  }
  if (finding.source === 'manual') {
    return 'Manual'
  }
  return 'DAST'
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

function DeepLinkFilterChip({ label, onClear }: { label: string; onClear: () => void }) {
  return (
    <button
      type="button"
      onClick={onClear}
      aria-label={`Remove filter: ${label}`}
      className="inline-flex items-center gap-1.5 rounded-lg border border-blue-500/30 bg-blue-500/10 px-2.5 py-1 text-xs text-blue-300 hover:bg-blue-500/20 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
    >
      <span className="max-w-64 truncate">{label}</span>
      <span aria-hidden="true">×</span>
    </button>
  )
}

function FindingsContent() {
  const { filters, setFilter, buildUrl } = useUrlFilters<FindingsFilters>({
    defaults: { sort_by: 'severity', sort_order: 'desc', page: 1 }
  })
  const toast = useToast()

  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(false)
  const hasLoadedRef = useRef(false)
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
  const [cleanupConfirmOpen, setCleanupConfirmOpen] = useState(false)

  const severityFilter = filters.severity || ''
  const statusFilter = filters.status || ''
  const sourceTypeFilter = filters.source_type || ''
  const domainFilter = filters.domain || ''
  const scanIdFilter = filters.scan_id || ''
  const targetIdFilter = filters.target_id || ''
  const aiTargetIdFilter = filters.ai_target_id || ''
  const deviceTargetIdFilter = filters.device_target_id || ''
  const drivenByFilter = filters.driven_by || ''
  const researchCampaignFilter = filters.research_campaign_id || ''
  const searchQuery = filters.search || ''
  const lastSeenFilter = filters.last_seen ? Number(filters.last_seen) : 0
  const firstSeenWithinFilter = filters.first_seen_within ? Number(filters.first_seen_within) : 0
  const resolvedWithinFilter = filters.resolved_within ? Number(filters.resolved_within) : 0
  const verificationVerdictFilter = filters.verification_verdict || ''
  const verificationModeFilter = filters.verification_mode || ''
  const verifiedOnlyFilter = filters.verified_only === 'true'
  const sortBy = (filters.sort_by || 'severity') as SortOption
  const sortOrder = (filters.sort_order || 'desc') as SortOrder
  // Page is 1-based in URL (page=1 is first page)
  const rawPage = Math.max(1, filters.page || 1)

  const hasActiveFilters = Boolean(
    severityFilter || statusFilter || sourceTypeFilter || domainFilter ||
    scanIdFilter || targetIdFilter || aiTargetIdFilter || deviceTargetIdFilter || drivenByFilter || researchCampaignFilter ||
    searchQuery || lastSeenFilter ||
    firstSeenWithinFilter || resolvedWithinFilter ||
    verificationVerdictFilter || verificationModeFilter || verifiedOnlyFilter
  )

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
  }, [severityFilter, statusFilter, sourceTypeFilter, domainFilter, scanIdFilter, targetIdFilter, aiTargetIdFilter, deviceTargetIdFilter, drivenByFilter, researchCampaignFilter, searchQuery, lastSeenFilter, firstSeenWithinFilter, resolvedWithinFilter, verificationVerdictFilter, verificationModeFilter, verifiedOnlyFilter, rawPage, sortBy, sortOrder])

  async function fetchFindings() {
    try {
      const data = await getFindings({
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
        source_type: sourceTypeFilter ? (sourceTypeFilter as FindingSourceTypeFilter) : undefined,
        root_domain: domainFilter || undefined,
        scan_id: scanIdFilter || undefined,
        target_id: targetIdFilter || undefined,
        ai_target_id: aiTargetIdFilter || undefined,
        device_target_id: deviceTargetIdFilter || undefined,
        search: searchQuery || undefined,
        seen_within_days: lastSeenFilter || undefined,
        first_seen_within_days: firstSeenWithinFilter || undefined,
        resolved_within_days: resolvedWithinFilter || undefined,
        verification_verdict: verificationVerdictFilter ? (verificationVerdictFilter as 'exploited' | 'likely_vulnerable' | 'blocked_by_security' | 'out_of_scope_internal' | 'false_positive' | 'likely_fixed' | 'inconclusive' | 'error') : undefined,
        verification_mode: verificationModeFilter ? (verificationModeFilter as 'deterministic' | 'ai_driven') : undefined,
        verified_only: verifiedOnlyFilter || undefined,
        driven_by: drivenByFilter === 'autonomous_research' ? 'autonomous_research' : undefined,
        research_campaign_id: researchCampaignFilter || undefined,
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
      setLoadError(false)
      hasLoadedRef.current = true
      setLoading(false)
    } catch (err) {
      console.error('Failed to fetch findings:', err)
      if (hasLoadedRef.current) {
        // Keep existing data on background refresh failures
        toast.error('Failed to refresh findings')
      } else {
        setLoadError(true)
      }
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
      toast.error('Failed to preview cleanup')
    } finally {
      setCleanupLoading(false)
    }
  }

  async function handleCleanupDelete() {
    if (cleanupPreview === null || cleanupPreview === 0) return
    setCleanupLoading(true)
    try {
      const result = await cleanupFindings({
        older_than_days: cleanupDays,
        status: cleanupStatus || undefined,
        root_domain: cleanupDomain || undefined,
        dry_run: false
      })
      const deletedCount = result.deleted ?? cleanupPreview
      setCleanupConfirmOpen(false)
      setShowCleanup(false)
      setCleanupPreview(null)
      toast.success(`Deleted ${deletedCount} finding${deletedCount !== 1 ? 's' : ''}`)
      await fetchFindings()
    } catch (err) {
      console.error('Cleanup failed:', err)
      toast.error('Failed to delete findings')
    } finally {
      setCleanupLoading(false)
    }
  }

  const totalPages = Math.ceil(total / PAGE_SIZE)

  // Clamp page to valid range for display
  const page = Math.min(rawPage, Math.max(1, totalPages))

  // Build detail URL with return params to preserve filter context
  const buildDetailUrl = (finding: Finding) => {
    if (finding.is_candidate) return '/findings/candidates'
    const params = new URLSearchParams()
    if (severityFilter) params.set('return_severity', severityFilter)
    if (statusFilter) params.set('return_status', statusFilter)
    if (sourceTypeFilter) params.set('return_source_type', sourceTypeFilter)
    if (domainFilter) params.set('return_domain', domainFilter)
    if (scanIdFilter) params.set('return_scan_id', scanIdFilter)
    if (targetIdFilter) params.set('return_target_id', targetIdFilter)
    if (aiTargetIdFilter) params.set('return_ai_target_id', aiTargetIdFilter)
    if (firstSeenWithinFilter) params.set('return_first_seen_within', String(firstSeenWithinFilter))
    if (resolvedWithinFilter) params.set('return_resolved_within', String(resolvedWithinFilter))
    if (searchQuery) params.set('return_search', searchQuery)
    if (verificationVerdictFilter) params.set('return_verification_verdict', verificationVerdictFilter)
    if (verificationModeFilter) params.set('return_verification_mode', verificationModeFilter)
    if (verifiedOnlyFilter) params.set('return_verified_only', 'true')
    if (sortBy !== 'severity') params.set('return_sort_by', sortBy)
    if (sortOrder !== 'desc') params.set('return_sort_order', sortOrder)
    if (page > 1) params.set('return_page', String(page))
    const queryString = params.toString()
    return queryString ? `/findings/${finding.id}?${queryString}` : `/findings/${finding.id}`
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
      <PageHeader
        title="Findings"
        description={
          <>
            Vulnerability findings across all scans
            {scanIdFilter && <span className="text-blue-400"> (filtered by scan)</span>}
            {targetIdFilter && <span className="text-blue-400"> (filtered by target)</span>}
          </>
        }
        actions={
          <>
            <Link href="/findings/candidates" className={buttonClasses('secondary')}>
              Investigation candidates
            </Link>
            <Button variant="secondary" onClick={() => { setShowCleanup(!showCleanup); setCleanupPreview(null) }}>
              Advanced cleanup
            </Button>
          </>
        }
      />

      {/* Legend: Severity / Proof / Retest / Status render as look-alike badges on each row.
          Spell out that they are four different questions so newcomers don't conflate them. */}
      <details className="group rounded-lg border border-gray-800 bg-gray-900/50">
        <summary className="flex cursor-pointer list-none items-center justify-between px-4 py-2.5 text-sm text-gray-400 hover:text-gray-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded-lg">
          <span>What do the badges mean?</span>
          <span aria-hidden="true" className="text-gray-600 transition-transform group-open:rotate-180">▾</span>
        </summary>
        <div className="grid gap-3 border-t border-gray-800 p-4 sm:grid-cols-2">
          <div className="flex items-start gap-3">
            <SeverityBadge severity="high" />
            <p className="text-xs leading-5 text-gray-400"><span className="font-medium text-gray-200">Severity</span> — how serious it would be if real, from Critical down to Info.</p>
          </div>
          <div className="flex items-start gap-3">
            <div className="shrink-0"><ProofStateBadge proofState="verified" /></div>
            <p className="text-xs leading-5 text-gray-400"><span className="font-medium text-gray-200">Proof</span> — how sure ShakerScan is it is real: <span className="text-gray-200">Proven</span> (evidence captured), <span className="text-gray-200">Suspected</span> (a lead, not confirmed), Refuted, or Inconclusive.</p>
          </div>
          <div className="flex items-start gap-3">
            <div className="shrink-0"><RetestVerdictBadge verdict="likely_vulnerable" /></div>
            <p className="text-xs leading-5 text-gray-400"><span className="font-medium text-gray-200">Retest</span> — what the most recent automated re-check found.</p>
          </div>
          <div className="flex items-start gap-3">
            <FindingStatusBadge status="active" />
            <p className="text-xs leading-5 text-gray-400"><span className="font-medium text-gray-200">Status</span> — your triage decision: active, resolved, false positive, or accepted risk.</p>
          </div>
        </div>
      </details>

      {/* Cleanup Panel */}
      {showCleanup && (
        <Card className="p-4 space-y-4">
          <h3 className="text-sm font-medium text-white">Cleanup Old Findings</h3>
          <div className="flex flex-wrap items-end gap-4">
            <div>
              <label className="text-xs text-gray-400 block mb-1">Not seen in</label>
              <select
                value={cleanupDays}
                onChange={(e) => { setCleanupDays(Number(e.target.value)); setCleanupPreview(null) }}
                aria-label="Cleanup findings not seen in"
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
                aria-label="Cleanup status filter"
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
                  aria-label="Cleanup domain filter"
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
                    onClick={() => setCleanupConfirmOpen(true)}
                    disabled={cleanupLoading}
                    className="px-3 py-1.5 bg-red-900/50 text-red-400 rounded-lg text-sm hover:bg-red-900/80 disabled:opacity-50"
                  >
                    Delete
                  </button>
                )}
              </>
            )}
          </div>
        </Card>
      )}

      <ConfirmDialog
        open={cleanupConfirmOpen}
        title="Delete old findings"
        message={`Delete ${cleanupPreview ?? 0} finding${cleanupPreview !== 1 ? 's' : ''} permanently? This cannot be undone.`}
        confirmLabel="Delete"
        danger
        busy={cleanupLoading}
        onConfirm={handleCleanupDelete}
        onCancel={() => setCleanupConfirmOpen(false)}
      />

      <div className="relative">
        <Input
          type="text"
          placeholder="Search findings by title or URL..."
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          aria-label="Search findings by title or URL"
        />
      </div>

      {/* Secondary filters stay available without competing with the primary
          search, severity, and lifecycle controls. */}
      <details className="rounded-lg border border-gray-800 bg-gray-950/30">
        <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-gray-400 hover:text-gray-200">
          More filters and sorting
        </summary>
        <div className="flex flex-wrap items-center gap-4 border-t border-gray-800 p-4">
        {/* User-facing finding source. Hunt includes direct AI claims and
            DAST work launched as part of a hunt. */}
        <div className="flex items-center gap-2">
          <label className="text-sm text-gray-400">Source:</label>
          <div className="flex max-w-full flex-wrap gap-1 rounded-lg border border-gray-800 bg-gray-900 p-0.5">
            {SOURCE_TYPE_OPTIONS.map((option) => (
              <button
                key={option.label}
                type="button"
                onClick={() => setFilter('source_type', option.value || undefined)}
                className={`px-2.5 py-1 text-sm rounded-md transition-colors sm:px-3 ${
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
              aria-label="Filter by domain"
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
            aria-label="Filter by last seen"
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
            aria-label="Sort by"
            className="px-3 py-1.5 bg-gray-900 border border-gray-800 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
          >
            {SORT_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
          <button
            onClick={() => setFilter('sort_order', sortOrder === 'desc' ? 'asc' : 'desc')}
            className="px-3 py-1.5 bg-gray-900 border border-gray-800 rounded-lg text-white text-sm hover:bg-gray-800 focus:outline-none focus:border-blue-500"
            aria-label={`Toggle sort direction: ${getSortOrderLabel(sortBy, sortOrder)}`}
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
            aria-label="Filter by verification verdict"
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
            aria-label="Filter by verification mode"
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
          verified only
        </label>

        </div>
      </details>

      {/* Deep-link filters (arrive via links from scans/targets/exposure and
          have no visible control above) — surface each as a removable chip so
          the active scope is obvious and individually clearable. */}
      {(scanIdFilter || targetIdFilter || aiTargetIdFilter || deviceTargetIdFilter || researchCampaignFilter || firstSeenWithinFilter > 0 || resolvedWithinFilter > 0) && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-gray-500">Filtered by:</span>
          {scanIdFilter && (
            <DeepLinkFilterChip label={`Scan ${scanIdFilter.slice(0, 8)}…`} onClear={() => setFilter('scan_id', undefined)} />
          )}
          {researchCampaignFilter && (
            <DeepLinkFilterChip label={`Hunt run ${researchCampaignFilter.slice(0, 8)}…`} onClear={() => setFilter('research_campaign_id', undefined)} />
          )}
          {targetIdFilter && (
            <DeepLinkFilterChip
              label={`Target: ${findings[0]?.target_name || findings[0]?.target_url || `${targetIdFilter.slice(0, 8)}…`}`}
              onClear={() => setFilter('target_id', undefined)}
            />
          )}
          {aiTargetIdFilter && (
            <DeepLinkFilterChip
              label={`AI target: ${findings[0]?.ai_target_name || `${aiTargetIdFilter.slice(0, 8)}…`}`}
              onClear={() => setFilter('ai_target_id', undefined)}
            />
          )}
          {deviceTargetIdFilter && (
            <DeepLinkFilterChip
              label={`Device: ${findings[0]?.target_name || findings[0]?.target_url || `${deviceTargetIdFilter.slice(0, 8)}…`}`}
              onClear={() => setFilter('device_target_id', undefined)}
            />
          )}
          {firstSeenWithinFilter > 0 && (
            <DeepLinkFilterChip label={`First seen ≤ ${firstSeenWithinFilter}d`} onClear={() => setFilter('first_seen_within', undefined)} />
          )}
          {resolvedWithinFilter > 0 && (
            <DeepLinkFilterChip label={`Resolved ≤ ${resolvedWithinFilter}d`} onClear={() => setFilter('resolved_within', undefined)} />
          )}
        </div>
      )}

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
      {loading && !loadError ? (
        <Card>
          <TableSkeleton />
        </Card>
      ) : loadError ? (
        <ErrorState
          message="Failed to load findings. Is the API running?"
          onRetry={() => { setLoading(true); setLoadError(false); fetchFindings() }}
        />
      ) : findings.length === 0 ? (
        hasActiveFilters ? (
          <EmptyState message="No findings found matching your filters." />
        ) : (
          <EmptyState
            message="No findings yet."
            hint="Run a scan to discover vulnerabilities."
            action={{ label: 'New Scan', href: '/scan/new' }}
          />
        )
      ) : (
        <Card>
          <div className="divide-y divide-gray-800">
            {findings.map((finding) => {
              const sourceType = getFindingSourceType(finding)
              return (
                <Link
                  key={finding.id}
                  href={buildDetailUrl(finding)}
                  className="block p-4 hover:bg-gray-800/50 transition-colors"
                >
                  <div className="flex items-start gap-3">
                    <div className="flex items-center gap-3 shrink-0">
                      <SeverityBadge severity={finding.severity} />
                      <ProofStateBadge proofState={finding.proof_state} />
                      <SourceTypeBadge type={sourceType} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="text-sm font-medium text-white">{finding.title}</h3>
                      <div className="flex items-center gap-4 mt-1 text-xs text-gray-500">
                        {finding.tool && <span>Tool: {finding.tool}</span>}
                        {finding.cwe && <span>CWE: {finding.cwe}</span>}
                        {finding.cvss_score !== undefined && finding.cvss_score !== null && <span>CVSS: {finding.cvss_score}</span>}
                      </div>
                      <div className="flex items-center gap-4 mt-1 text-xs text-gray-500">
                        <span>First seen: {formatDate(finding.first_seen_at)}</span>
                        <span>Last seen: {formatDate(finding.last_seen_at)}</span>
                      </div>
                      {finding.url && (
                        <p className="text-xs text-gray-600 truncate mt-1">{finding.url}</p>
                      )}
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {finding.last_verification_verdict && (
                        <RetestVerdictBadge verdict={finding.last_verification_verdict} />
                      )}
                      <FindingStatusBadge status={finding.status} />
                    </div>
                  </div>
                </Link>
              )
            })}
          </div>
        </Card>
      )}

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

export default function FindingsPage() {
  return (
    <Suspense fallback={
      <Card>
        <TableSkeleton />
      </Card>
    }>
      <FindingsContent />
    </Suspense>
  )
}
