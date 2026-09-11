'use client'
import { featureEnabled } from '@/lib/workspaceCapabilities'
import { RecordDeletionDialog } from '@/components/lifecycle/DeleteRecordsButton'
import { previewRecordDeletion, type DeletionPreview } from '@/lib/dataLifecycle'

import { useEffect, useState, useRef, Suspense } from 'react'
import Link from '@/components/WorkspaceLink'
import { getFindings, getDomains, bulkUpdateFindings, getFindingResearchProvenance, type Finding } from '@/lib/api'
import { useUrlFilters } from '@/lib/useUrlFilters'
import {
  FINDING_STATUSES,
  FINDING_STATUS_LABELS,
  CLEANUP_AGE_OPTIONS,
  type FindingSourceType,
  type FindingStatus,
  type SortOption,
  type SortOrder,
} from '@/lib/constants'
import { cn } from '@/lib/cn'
import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  Field,
  PageHeader,
  Select,
  TableSkeleton,
  useToast,
  buttonClasses,
} from '@/components/ui'
import { BadgeLegendModal } from './BadgeLegendModal'
import { FindingRow } from './FindingRow'
import { FindingsToolbar } from './FindingsToolbar'
import { TriageDock } from './TriageDock'
import { triageOutcomeMessage } from './triage'

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
  const { filters, setFilter, setFilters } = useUrlFilters<FindingsFilters>({
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
  const [legendOpen, setLegendOpen] = useState(false)
  const [showCleanup, setShowCleanup] = useState(false)
  const [cleanupDays, setCleanupDays] = useState(90)
  const [cleanupStatus, setCleanupStatus] = useState('')
  const [cleanupDomain, setCleanupDomain] = useState('')
  const [cleanupPreview, setCleanupPreview] = useState<DeletionPreview | null>(null)
  const [cleanupLoading, setCleanupLoading] = useState(false)
  // A cleanup preview is bound to the exact filters it was requested with; a late response for
  // stale filters must never replace the current one (the filter onChange handlers clear it too).
  const cleanupFilterKey = JSON.stringify({ cleanupDays, cleanupStatus, cleanupDomain })
  const latestCleanupKey = useRef(cleanupFilterKey)
  latestCleanupKey.current = cleanupFilterKey
  const [cleanupConfirmOpen, setCleanupConfirmOpen] = useState(false)

  // Selection is local state, not URL state: it serves triage first and never survives a refetch.
  const [selecting, setSelecting] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [triageBusy, setTriageBusy] = useState(false)
  const [deletePreview, setDeletePreview] = useState<DeletionPreview | null>(null)
  const [deleteBusy, setDeleteBusy] = useState(false)
  const deleteRequestKey = useRef<string | null>(null)
  const selectButtonRef = useRef<HTMLButtonElement>(null)

  // Record deletion is an admin-only lifecycle action, never a front-line triage control.
  // Same double gate as Advanced cleanup; the dock renders no menu at all when it is off.
  const canDeleteRecords = featureEnabled('record_deletion') && featureEnabled('engine_admin')

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
    const requestedKey = cleanupFilterKey
    setCleanupLoading(true)
    try {
      const result = await previewRecordDeletion({
        kind: 'findings',
        older_than_days: cleanupDays,
        status: cleanupStatus || undefined,
        root_domain: cleanupDomain || undefined,
      })
      // Ignore a late preview if the filters changed while it was pending.
      if (latestCleanupKey.current === requestedKey) setCleanupPreview(result)
    } catch (err) {
      if (latestCleanupKey.current === requestedKey) {
        console.error('Cleanup preview failed:', err)
        toast.error(err instanceof Error ? err.message : 'Failed to preview cleanup')
      }
    } finally {
      setCleanupLoading(false)
    }
  }

  // A fresh result set invalidates any selection made against the old one.
  useEffect(() => { setSelectedIds(new Set()) }, [findings])

  // A deletion preview is only valid for the exact selection it was requested with.
  const selectedKey = [...selectedIds].sort().join(',')
  useEffect(() => {
    if (deleteRequestKey.current !== null && deleteRequestKey.current !== selectedKey) {
      deleteRequestKey.current = null
      setDeletePreview(null)
    }
  }, [selectedKey])

  const selectableFindings = findings.filter((finding) => !finding.is_candidate)
  const allOnPageSelected = selectableFindings.length > 0 && selectableFindings.every((finding) => selectedIds.has(finding.id))

  // The dock unmounts with the selection, so focus returns to the control that started it.
  function clearSelection() {
    setSelectedIds(new Set())
    selectButtonRef.current?.focus()
  }

  function toggleSelecting() {
    if (selecting) {
      setSelecting(false)
      setSelectedIds(new Set())
    } else {
      setSelecting(true)
    }
  }

  function toggleFinding(id: string, checked: boolean) {
    setSelectedIds((current) => {
      const next = new Set(current)
      if (checked) next.add(id); else next.delete(id)
      return next
    })
  }

  async function handleBulkTriage(status: FindingStatus) {
    const ids = [...selectedIds]
    if (!ids.length || triageBusy) return
    setTriageBusy(true)
    try {
      const result = await bulkUpdateFindings(ids, status)
      toast.success(triageOutcomeMessage(result.updated, status, result.not_found))
      clearSelection()
      await fetchFindings()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to update findings')
    } finally {
      setTriageBusy(false)
    }
  }

  async function handleDeleteSelected() {
    const ids = [...selectedIds]
    if (!ids.length || deleteBusy) return
    const requestedKey = [...ids].sort().join(',')
    deleteRequestKey.current = requestedKey
    setDeleteBusy(true)
    try {
      const preview = await previewRecordDeletion({ kind: 'findings', finding_ids: ids })
      // Ignore a late preview if the selection changed while it was pending.
      if (deleteRequestKey.current === requestedKey) setDeletePreview(preview)
    } catch (err) {
      if (deleteRequestKey.current === requestedKey) {
        toast.error(err instanceof Error ? err.message : 'Could not preview deletion')
      }
    } finally {
      setDeleteBusy(false)
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
        <Button
          variant="secondary"
          size="sm"
          onClick={() => setFilter('page', page > 1 ? page - 1 : undefined)}
          disabled={page <= 1}
        >
          Previous
        </Button>
        <span className="px-1 text-sm text-gray-400 tabular-nums">
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

  const rangeStart = (page - 1) * PAGE_SIZE + 1
  const rangeEnd = Math.min(page * PAGE_SIZE, total)
  const dockVisible = selectedIds.size > 0

  return (
    <div className={cn('space-y-5', dockVisible && 'pb-40 sm:pb-28')}>
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
            {canDeleteRecords && <Button variant="secondary" onClick={() => { setShowCleanup(!showCleanup); setCleanupPreview(null) }}>
              Advanced cleanup
            </Button>}
          </>
        }
      />

      {/* Cleanup Panel (admin-only age-based deletion, previewed and approved) */}
      {canDeleteRecords && showCleanup && (
        <Card className="space-y-4 p-4">
          <div>
            <h3 className="text-sm font-medium text-white">Clean up old findings</h3>
            <p className="mt-1 text-xs text-gray-500">Permanently deletes finding records not seen within the chosen window. Always previewed and approved first.</p>
          </div>
          <div className="flex flex-wrap items-end gap-4">
            <Field label="Not seen in">
              <Select fullWidth={false} value={cleanupDays} onChange={(e) => { setCleanupDays(Number(e.target.value)); setCleanupPreview(null) }}>
                {CLEANUP_AGE_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </Select>
            </Field>
            <Field label="Status (optional)">
              <Select fullWidth={false} value={cleanupStatus} onChange={(e) => { setCleanupStatus(e.target.value); setCleanupPreview(null) }}>
                <option value="">Any status</option>
                {FINDING_STATUSES.map((s) => (
                  <option key={s} value={s}>{FINDING_STATUS_LABELS[s]}</option>
                ))}
              </Select>
            </Field>
            {domains.length > 0 && (
              <Field label="Domain (optional)">
                <Select fullWidth={false} value={cleanupDomain} onChange={(e) => { setCleanupDomain(e.target.value); setCleanupPreview(null) }}>
                  <option value="">All domains</option>
                  {domains.map((d) => (
                    <option key={d} value={d}>{d}</option>
                  ))}
                </Select>
              </Field>
            )}
            <Button onClick={handleCleanupPreview} loading={cleanupLoading}>
              {cleanupLoading ? 'Checking…' : 'Preview'}
            </Button>
            {cleanupPreview !== null && (
              <>
                <span className="text-sm text-gray-400 tabular-nums">
                  {cleanupPreview.would_delete === 0
                    ? 'No findings match'
                    : `${cleanupPreview.would_delete} finding${cleanupPreview.would_delete !== 1 ? 's' : ''} will be deleted`}
                </span>
                {cleanupPreview.would_delete > 0 && (
                  <Button variant="danger" onClick={() => setCleanupConfirmOpen(true)} disabled={cleanupLoading}>
                    Delete
                  </Button>
                )}
              </>
            )}
          </div>
        </Card>
      )}

      <RecordDeletionDialog preview={cleanupConfirmOpen ? cleanupPreview : null} subject="findings"
        onClose={() => setCleanupConfirmOpen(false)} onDeleted={() => {
          setShowCleanup(false); setCleanupPreview(null); void fetchFindings()
        }} />

      <FindingsToolbar
        searchInput={searchInput}
        onSearchInputChange={setSearchInput}
        values={{
          status: statusFilter,
          severity: severityFilter,
          sourceType: sourceTypeFilter,
          domain: domainFilter,
          lastSeen: lastSeenFilter,
          verificationVerdict: verificationVerdictFilter,
          verificationMode: verificationModeFilter,
          verifiedOnly: verifiedOnlyFilter,
          sortBy,
          sortOrder,
        }}
        setFilter={setFilter}
        setFilters={setFilters}
        domains={domains}
      />

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

      {/* Results line: count, legend, selection toggle, pagination */}
      {total > 0 && (
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-sm text-gray-400 tabular-nums" aria-live="polite">
            <span className="font-medium text-gray-200">{total.toLocaleString()}</span>
            {` finding${total !== 1 ? 's' : ''}`}
            {total > PAGE_SIZE && <span className="text-gray-500">{` · showing ${rangeStart}–${rangeEnd}`}</span>}
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="ghost" size="sm" onClick={() => setLegendOpen(true)}>
              What the badges mean
            </Button>
            {selectableFindings.length > 0 && (
              <Button
                ref={selectButtonRef}
                variant={selecting ? 'primary' : 'ghost'}
                size="sm"
                aria-pressed={selecting}
                onClick={toggleSelecting}
              >
                Select
              </Button>
            )}
            <PaginationControls />
          </div>
        </div>
      )}

      <BadgeLegendModal open={legendOpen} onClose={() => setLegendOpen(false)} />

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
        <Card className="overflow-hidden">
          {selecting && (
            <div className="flex items-center gap-3 border-b border-gray-800 px-4 py-2.5">
              <label className="flex items-center gap-2 text-sm text-gray-300">
                <input
                  type="checkbox"
                  aria-label="Select findings on this page"
                  className="h-4 w-4 rounded border-gray-600 bg-gray-900 text-blue-600 focus:ring-blue-500"
                  checked={allOnPageSelected}
                  onChange={(event) => setSelectedIds(new Set(event.target.checked ? selectableFindings.map((finding) => finding.id) : []))}
                />
                Select this page
              </label>
              <span className="text-xs text-gray-500 tabular-nums">{selectableFindings.length} on this page</span>
            </div>
          )}
          <div>
            {findings.map((finding) => (
              <FindingRow
                key={finding.id}
                finding={finding}
                href={buildDetailUrl(finding)}
                sourceType={getFindingSourceType(finding)}
                selecting={selecting}
                selected={selectedIds.has(finding.id)}
                onToggle={(checked) => toggleFinding(finding.id, checked)}
              />
            ))}
          </div>
        </Card>
      )}

      {/* Bottom Pagination */}
      {total > PAGE_SIZE && (
        <div className="flex flex-wrap items-center justify-between gap-3">
          <span className="text-sm text-gray-500 tabular-nums">
            {`Showing ${rangeStart}–${rangeEnd} of ${total.toLocaleString()}`}
          </span>
          <PaginationControls />
        </div>
      )}

      {dockVisible && (
        <TriageDock
          count={selectedIds.size}
          busy={triageBusy || deleteBusy}
          hideStatus={statusFilter || undefined}
          onTriage={handleBulkTriage}
          onClear={clearSelection}
          onDelete={canDeleteRecords ? handleDeleteSelected : undefined}
        />
      )}

      <RecordDeletionDialog preview={deletePreview} subject="selected findings"
        onClose={() => { deleteRequestKey.current = null; setDeletePreview(null) }}
        onDeleted={() => { clearSelection(); void fetchFindings() }} />
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
