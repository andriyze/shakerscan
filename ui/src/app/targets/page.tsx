'use client'

import { useEffect, useState, useRef, useCallback, Suspense } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { getTargetsGrouped, createTarget, scanTarget, discoverSubdomains, dedupeTargets, type Target, type GroupedDomain } from '@/lib/api'
import { DISCOVERY_SOURCES, GRADES, TARGET_SORT_OPTIONS, type SortOrder } from '@/lib/constants'
import { useUrlFilters } from '@/lib/useUrlFilters'
import { ArrowDown, ArrowUp, Plus, Search } from 'lucide-react'
import { Button, Card, CardSkeleton, ConfirmDialog, EmptyState, ErrorState, Field, Input, Modal, PageHeader, Select, useToast } from '@/components/ui'
import { boundedDisplayText, boundedTargetDisplay } from '@/lib/targetChoices'

const SEARCH_DEBOUNCE_MS = 300

type TargetIdentityKind = 'registrable_domain' | 'ip_address' | 'internal_service' | 'host'

export function classifyTargetGroupIdentity(value: string): { kind: TargetIdentityKind; label: string; canDiscoverSubdomains: boolean; internal: boolean } {
  const host = value.trim().toLowerCase().replace(/^\[|\]$/g, '')
  const ipv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)
  const ipv6 = host.includes(':') && /^[0-9a-f:]+$/i.test(host)
  const decimalAddress = /^\d+$/.test(host)
  if (ipv4 || ipv6 || decimalAddress) {
    return { kind: 'ip_address', label: decimalAddress ? 'Numeric IP form' : 'IP address', canDiscoverSubdomains: false, internal: false }
  }
  const internal = host === 'localhost'
    || host.endsWith('.local')
    || host.endsWith('.internal')
    || host.endsWith('.localhost')
    || host.includes('host.docker.internal')
    || !host.includes('.')
  if (internal) return { kind: 'internal_service', label: 'Internal service', canDiscoverSubdomains: false, internal: true }
  const labels = host.split('.').filter(Boolean)
  const registrable = labels.length >= 2 && /^[a-z]{2,63}$/i.test(labels.at(-1) || '')
  if (registrable) return { kind: 'registrable_domain', label: 'Domain', canDiscoverSubdomains: true, internal: false }
  return { kind: 'host', label: 'Host', canDiscoverSubdomains: false, internal: false }
}

function isPlausibleTargetUrl(value: string): boolean {
  const candidate = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(value) ? value : `https://${value}`
  let url: URL
  try {
    url = new URL(candidate)
  } catch {
    return false
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false
  const host = url.hostname
  if (!host) return false
  if (host === 'localhost') return true
  if (host.startsWith('[') && host.endsWith(']')) return true
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true
  return /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/.test(host)
}

function configureScanHref(targets: string[], forceBatch = false): string {
  const uniqueTargets = Array.from(new Set(targets.map((target) => target.trim()).filter(Boolean)))
  const params = new URLSearchParams()
  if (forceBatch || uniqueTargets.length > 1) params.set('targets', uniqueTargets.join('\n'))
  else if (uniqueTargets[0]) params.set('target', uniqueTargets[0])
  return `/scan/new?${params.toString()}`
}

function scanHistoryHref(rootDomain: string, targetUrl: string): string {
  const params = new URLSearchParams({
    domain: rootDomain,
    search: targetUrl,
  })
  return `/scans?${params.toString()}`
}

interface TargetsFilters {
  [key: string]: string | number | undefined
  search?: string
  discovery_source?: string
  grade?: string
  has_findings?: string
  sort_by?: string
  sort_order?: string
}

function TargetsContent() {
  const { filters, setFilter, setFilters } = useUrlFilters<TargetsFilters>({
    defaults: { sort_by: 'root_domain', sort_order: 'asc' }
  })

  const router = useRouter()
  const toast = useToast()

  const [domains, setDomains] = useState<GroupedDomain[]>([])
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState(false)
  const [showAddModal, setShowAddModal] = useState(false)
  const [newTargetUrl, setNewTargetUrl] = useState('')
  const [newTargetName, setNewTargetName] = useState('')
  const [newTargetCohort, setNewTargetCohort] = useState<'production' | 'staging' | 'lab' | 'demo' | 'calibration' | 'internal' | ''>('')
  const [urlError, setUrlError] = useState('')
  const [adding, setAdding] = useState(false)
  const [expandedDomains, setExpandedDomains] = useState<Set<string>>(new Set())
  const [openScanMenu, setOpenScanMenu] = useState<string | null>(null)
  const [openScanAllMenu, setOpenScanAllMenu] = useState<string | null>(null)
  const [scanningDomains, setScanningDomains] = useState<Set<string>>(new Set())
  const [discoveringDomains, setDiscoveringDomains] = useState<Set<string>>(new Set())
  const [searchInput, setSearchInput] = useState<string>(filters.search || '')
  const [totalRootDomains, setTotalRootDomains] = useState(0)
  const [totalTargets, setTotalTargets] = useState(0)
  const [dedupePreview, setDedupePreview] = useState<{ groups_found: number; targets_merged: number } | null>(null)
  const [dedupeLoading, setDedupeLoading] = useState(false)
  const [dedupeExecuting, setDedupeExecuting] = useState(false)
  const [scanAllPending, setScanAllPending] = useState<{ domain: GroupedDomain } | null>(null)
  const scanMenuRef = useRef<HTMLDivElement>(null)
  const scanAllMenuRef = useRef<HTMLDivElement>(null)
  const searchTimeout = useRef<NodeJS.Timeout | null>(null)
  const discoverTimeouts = useRef<Set<NodeJS.Timeout>>(new Set())

  const searchQuery = filters.search || ''
  const discoverySourceFilter = filters.discovery_source || ''
  const gradeFilter = filters.grade || ''
  const hasFindingsFilter = filters.has_findings || ''
  const sortBy = filters.sort_by || 'root_domain'
  const sortOrder = (filters.sort_order || 'asc') as SortOrder

  // Check if any filters are active
  const hasActiveFilters = !!(searchQuery || discoverySourceFilter || gradeFilter || hasFindingsFilter || sortBy !== 'root_domain' || sortOrder !== 'asc')

  // Close scan menus when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (scanMenuRef.current && !scanMenuRef.current.contains(event.target as Node)) {
        setOpenScanMenu(null)
      }
      if (scanAllMenuRef.current && !scanAllMenuRef.current.contains(event.target as Node)) {
        setOpenScanAllMenu(null)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  // Clear any pending discovery-refresh timers on unmount so they don't
  // fire setState on an unmounted component.
  useEffect(() => {
    const timeouts = discoverTimeouts.current
    return () => {
      timeouts.forEach(clearTimeout)
      timeouts.clear()
    }
  }, [])

  // Sync searchInput with URL when filters change externally (e.g., browser back)
  useEffect(() => {
    setSearchInput(searchQuery)
  }, [searchQuery])

  // Debounce search input -> URL update
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

  const fetchTargets = useCallback(async () => {
    setLoading(true)
    try {
      const hasFindingsBool = hasFindingsFilter === 'true' ? true : hasFindingsFilter === 'false' ? false : undefined
      const data = await getTargetsGrouped({
        search: searchQuery || undefined,
        discovery_source: discoverySourceFilter || undefined,
        grade: gradeFilter || undefined,
        has_findings: hasFindingsBool,
        sort_by: sortBy,
        sort_order: sortOrder
      })
      setDomains(data.domains || [])
      setTotalRootDomains(data.total_root_domains || 0)
      setTotalTargets(data.total_targets || 0)
      setFetchError(false)
      // Keep large inventories scannable. Search results are expanded because
      // the user is looking for a specific match; the normal inventory is not.
      setExpandedDomains(searchQuery
        ? new Set((data.domains || []).filter(d => d.subdomain_count > 0).map(d => d.root_domain))
        : new Set())
    } catch (err) {
      console.error('Failed to fetch targets:', err)
      setFetchError(true)
    } finally {
      setLoading(false)
    }
  }, [searchQuery, discoverySourceFilter, gradeFilter, hasFindingsFilter, sortBy, sortOrder])

  useEffect(() => {
    fetchTargets()
  }, [fetchTargets])

  function closeAddModal() {
    setShowAddModal(false)
    setUrlError('')
  }

  async function handleAddTarget(e: React.FormEvent) {
    e.preventDefault()
    const url = newTargetUrl.trim()
    if (!url) return
    if (!isPlausibleTargetUrl(url)) {
      setUrlError('Enter a valid URL or hostname, e.g. https://example.com')
      return
    }

    setAdding(true)
    try {
      await createTarget(url, newTargetName.trim() || undefined, newTargetCohort || undefined)
      setNewTargetUrl('')
      setNewTargetName('')
      setNewTargetCohort('')
      setUrlError('')
      setShowAddModal(false)
      toast.success('Target added')
      fetchTargets()
    } catch (err) {
      console.error('Failed to add target:', err)
      toast.error('Failed to add target')
    } finally {
      setAdding(false)
    }
  }

  async function handleScan(targetId: string) {
    setOpenScanMenu(null)
    try {
      const res = await scanTarget(targetId, { budget_profile: 'balanced' })
      const scanId = res?.scan_id
      toast.success(
        'Scan started',
        scanId ? { link: { href: `/scans/${scanId}`, label: 'View scan' } } : undefined
      )
      router.push('/scans')
    } catch (err) {
      console.error('Failed to start scan:', err)
      toast.error('Failed to start scan')
    }
  }

  function confirmScanAll() {
    if (!scanAllPending) return
    const { domain } = scanAllPending
    setScanAllPending(null)
    handleScanDomainSet(domain)
  }

  async function handleScanDomainSet(domain: GroupedDomain) {
    const allTargets: Target[] = []
    if (domain.root_target) {
      allTargets.push(domain.root_target)
    }
    allTargets.push(...domain.subdomains)

    if (allTargets.length === 0) {
      toast.info('No targets to scan')
      return
    }

    setScanningDomains(prev => new Set(prev).add(domain.root_domain))
    setOpenScanAllMenu(null)

    try {
      // Submit scans for all targets, tolerating per-target failures.
      const results = await Promise.allSettled(allTargets.map(target => scanTarget(target.id, { budget_profile: 'balanced' })))
      const succeeded = results.filter((r): r is PromiseFulfilledResult<{ scan_id?: string }> => r.status === 'fulfilled')
      const failedCount = results.length - succeeded.length

      if (succeeded.length === 0) {
        console.error('Failed to start domain set scan:', results.find(r => r.status === 'rejected'))
        toast.error(`Failed to start scans for ${domain.root_domain}`)
        setScanningDomains(prev => {
          const next = new Set(prev)
          next.delete(domain.root_domain)
          return next
        })
        return
      }

      const scanId = allTargets.length === 1 ? succeeded[0]?.value?.scan_id : undefined
      const message = failedCount > 0
        ? `Started ${succeeded.length} of ${allTargets.length} scans for ${domain.root_domain}`
        : `Started ${allTargets.length} scan${allTargets.length !== 1 ? 's' : ''} for ${domain.root_domain}`
      if (failedCount > 0) {
        toast.info(message)
      } else {
        toast.success(
          message,
          scanId ? { link: { href: `/scans/${scanId}`, label: 'View scan' } } : undefined
        )
      }
      router.push('/scans')
    } catch (err) {
      console.error('Failed to start domain set scan:', err)
      toast.error(`Failed to start scans for ${domain.root_domain}`)
      setScanningDomains(prev => {
        const next = new Set(prev)
        next.delete(domain.root_domain)
        return next
      })
    }
  }

  async function handleDiscover(rootDomain: string) {
    setDiscoveringDomains(prev => new Set(prev).add(rootDomain))
    try {
      await discoverSubdomains(rootDomain)
      toast.success(`Subdomain discovery started for ${rootDomain}`)
      // Refresh targets after a short delay to allow discovery to start.
      // Track the timer so it can be cleared if the component unmounts first.
      const timeoutId = setTimeout(() => {
        discoverTimeouts.current.delete(timeoutId)
        fetchTargets()
        setDiscoveringDomains(prev => {
          const next = new Set(prev)
          next.delete(rootDomain)
          return next
        })
      }, 2000)
      discoverTimeouts.current.add(timeoutId)
    } catch (err) {
      console.error('Failed to start discovery:', err)
      toast.error(`Failed to start discovery for ${rootDomain}`)
      setDiscoveringDomains(prev => {
        const next = new Set(prev)
        next.delete(rootDomain)
        return next
      })
    }
  }

  async function handleFindDuplicates() {
    setDedupeLoading(true)
    try {
      const preview = await dedupeTargets(true)
      if (preview.groups_found === 0) {
        toast.success('No duplicate targets found')
        setDedupePreview(null)
      } else {
        setDedupePreview({ groups_found: preview.groups_found, targets_merged: preview.targets_merged })
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to check for duplicates')
    } finally {
      setDedupeLoading(false)
    }
  }

  async function handleExecuteDedupe() {
    setDedupeExecuting(true)
    try {
      const res = await dedupeTargets(false)
      toast.success(`Merged ${res.targets_merged} duplicate target(s) across ${res.groups_executed} group(s)`)
      setDedupePreview(null)
      fetchTargets()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to merge duplicates')
    } finally {
      setDedupeExecuting(false)
    }
  }

  function toggleExpand(rootDomain: string) {
    setExpandedDomains(prev => {
      const next = new Set(prev)
      if (next.has(rootDomain)) {
        next.delete(rootDomain)
      } else {
        next.add(rootDomain)
      }
      return next
    })
  }

  function getSourceBadge(source: string) {
    const styles: Record<string, string> = {
      'manual': 'bg-blue-500/20 text-blue-400',
      'subfinder': 'bg-purple-500/20 text-purple-400',
      'gungnir-monitor': 'bg-green-500/20 text-green-400',
      'import': 'bg-gray-500/20 text-gray-400',
      'model-intake': 'bg-cyan-500/20 text-cyan-300',
    }
    return styles[source] || styles['manual']
  }

  function clearFilters() {
    setSearchInput('')
    setFilters({
      search: undefined,
      discovery_source: undefined,
      grade: undefined,
      has_findings: undefined,
      sort_by: undefined,
      sort_order: undefined
    })
  }

  function toggleSortOrder() {
    setFilter('sort_order', sortOrder === 'asc' ? 'desc' : 'asc')
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Targets"
        description="Manage your scan targets"
        actions={
          <>
            <Button
              variant="secondary"
              onClick={handleFindDuplicates}
              loading={dedupeLoading}
              title="Find and merge scheme/trailing-slash duplicate targets"
            >
              {dedupeLoading ? 'Checking…' : 'Find duplicates'}
            </Button>
            <Button onClick={() => setShowAddModal(true)}>
              <Plus className="h-4 w-4" aria-hidden="true" />
              Add Target
            </Button>
          </>
        }
      />

      <ConfirmDialog
        open={dedupePreview !== null}
        title="Merge duplicate targets?"
        message={
          dedupePreview
            ? `Found ${dedupePreview.groups_found} duplicate group(s) covering ${dedupePreview.targets_merged} target(s). Merging reassigns their scans, findings, endpoints, and schedules to one survivor and deletes the duplicates. This cannot be undone.`
            : ''
        }
        confirmLabel="Merge duplicates"
        danger
        busy={dedupeExecuting}
        onConfirm={handleExecuteDedupe}
        onCancel={() => setDedupePreview(null)}
      />

      <ConfirmDialog
        open={scanAllPending !== null}
        title={scanAllPending ? `Scan all of ${scanAllPending.domain.root_domain}?` : ''}
        message={
          scanAllPending
            ? (() => {
                const count = (scanAllPending.domain.root_target ? 1 : 0) + scanAllPending.domain.subdomain_count
                return `This queues the balanced Scan policy for ${count} target${count !== 1 ? 's' : ''} (root + subdomains) in this domain set.`
              })()
            : ''
        }
        confirmLabel="Start scans"
        danger={false}
        onConfirm={confirmScanAll}
        onCancel={() => setScanAllPending(null)}
      />

      {/* Filters */}
      <div className="flex gap-4 flex-wrap">
        {/* Discovery Source Filter */}
        <div className="flex items-center gap-3">
          <label htmlFor="targets-source-filter" className="text-sm text-gray-400">Source:</label>
          <Select
            id="targets-source-filter"
            fullWidth={false}
            value={discoverySourceFilter}
            onChange={(e) => setFilter('discovery_source', e.target.value || undefined)}
          >
            <option value="">All sources</option>
            {DISCOVERY_SOURCES.filter((source) => source !== 'model-intake').map((source) => (
              <option key={source} value={source}>{source}</option>
            ))}
          </Select>
        </div>

        {/* Grade Filter */}
        <div className="flex items-center gap-3">
          <label htmlFor="targets-grade-filter" className="text-sm text-gray-400">Grade:</label>
          <Select
            id="targets-grade-filter"
            fullWidth={false}
            value={gradeFilter}
            onChange={(e) => setFilter('grade', e.target.value || undefined)}
          >
            <option value="">All grades</option>
            {GRADES.map((grade) => (
              <option key={grade} value={grade}>{grade}</option>
            ))}
          </Select>
        </div>

        {/* Has Findings Filter */}
        <div className="flex items-center gap-3">
          <label htmlFor="targets-findings-filter" className="text-sm text-gray-400">Findings:</label>
          <Select
            id="targets-findings-filter"
            fullWidth={false}
            value={hasFindingsFilter}
            onChange={(e) => setFilter('has_findings', e.target.value || undefined)}
          >
            <option value="">All</option>
            <option value="true">With findings</option>
            <option value="false">No findings</option>
          </Select>
        </div>

        {/* Sort By */}
        <div className="flex items-center gap-3">
          <label htmlFor="targets-sort-filter" className="text-sm text-gray-400">Sort:</label>
          <Select
            id="targets-sort-filter"
            fullWidth={false}
            value={sortBy}
            onChange={(e) => setFilter('sort_by', e.target.value || undefined)}
          >
            {TARGET_SORT_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>{option.label}</option>
            ))}
          </Select>
          <Button
            variant="secondary"
            onClick={toggleSortOrder}
            title={sortOrder === 'asc' ? 'Ascending' : 'Descending'}
            aria-label={sortOrder === 'asc' ? 'Sort ascending' : 'Sort descending'}
          >
            {sortOrder === 'asc' ? <ArrowUp className="h-4 w-4" aria-hidden="true" /> : <ArrowDown className="h-4 w-4" aria-hidden="true" />}
          </Button>
        </div>

        {/* Search */}
        <div className="relative flex-1 min-w-[200px]">
          <Input
            type="text"
            aria-label="Search targets by URL or domain"
            placeholder="Search by URL or domain..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            className="pr-10"
          />
          <Search className="pointer-events-none absolute right-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" aria-hidden="true" />
        </div>
      </div>

      {/* Summary with Clear Filters */}
      <div className="flex items-center justify-between">
        <span className="text-sm text-gray-400">
          {totalRootDomains} asset group{totalRootDomains !== 1 ? 's' : ''} · {totalTargets} target{totalTargets !== 1 ? 's' : ''}
        </span>
        {hasActiveFilters && (
          <button
            onClick={clearFilters}
            className="text-sm text-blue-400 hover:text-blue-300"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Targets List - Hierarchical */}
      {loading ? (
        <CardSkeleton count={4} />
      ) : fetchError ? (
        <ErrorState message="Failed to load targets. Is the API running?" onRetry={fetchTargets} />
      ) : domains.length === 0 ? (
        <EmptyState
          message={hasActiveFilters ? 'No targets found matching your filters.' : 'No targets yet.'}
          hint={hasActiveFilters ? 'Try clearing your filters.' : 'Add a target to get started.'}
          action={
            hasActiveFilters
              ? { label: 'Clear filters', onClick: clearFilters }
              : { label: 'Add target', onClick: () => setShowAddModal(true) }
          }
        />
      ) : (
        <div className="space-y-3">
          {domains.map((domain) => {
            const identity = classifyTargetGroupIdentity(domain.root_domain)
            const domainInfo = (
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="block max-w-full truncate font-medium text-white">{boundedDisplayText(domain.root_domain, 96)}</span>
                  <span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wide ${
                    identity.internal ? 'bg-amber-500/10 text-amber-300' : 'bg-gray-800 text-gray-400'
                  }`}>{identity.label}</span>
                  <span className="shrink-0 rounded bg-violet-500/10 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-violet-300">{domain.root_target?.cohort || domain.subdomains[0]?.cohort || 'unclassified'}</span>
                  {domain.subdomain_count > 0 && (
                    <span className="px-1.5 py-0.5 bg-gray-800 text-gray-400 text-xs rounded">
                      +{domain.subdomain_count} subdomain{domain.subdomain_count !== 1 ? 's' : ''}
                    </span>
                  )}
                </div>
                {domain.root_target && (
                  <p className="text-xs text-gray-500 truncate">{boundedTargetDisplay(domain.root_target)}</p>
                )}
                {identity.internal && (
                  <p className="mt-1 text-xs text-amber-300/80">Internal/private identity · runtime destination policy is checked before execution.</p>
                )}
              </div>
            )
            return (
            <Card key={domain.root_domain}>
              {/* Root Domain Header */}
              <div className="flex flex-col gap-3 p-4 transition-colors hover:bg-gray-800/50 md:flex-row md:items-center">
                {domain.subdomain_count > 0 ? (
                  <button
                    type="button"
                    onClick={() => toggleExpand(domain.root_domain)}
                    aria-expanded={expandedDomains.has(domain.root_domain)}
                    className="flex w-full flex-1 min-w-0 items-center gap-3 text-left rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
                  >
                    {/* Expand/Collapse Icon */}
                    <span className="text-gray-500 hover:text-white">
                      <svg
                        className={`w-4 h-4 transition-transform ${expandedDomains.has(domain.root_domain) ? 'rotate-90' : ''}`}
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                      >
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                      </svg>
                    </span>
                    {domainInfo}
                  </button>
                ) : (
                  <div className="flex w-full flex-1 min-w-0 items-center gap-3">
                    <div className="w-4" />
                    {domainInfo}
                  </div>
                )}

                {/* Root Target Stats */}
                {domain.root_target && (
                  <>
                    <div className="hidden items-center gap-4 text-sm text-gray-500 lg:flex">
                      <Link
                        href={scanHistoryHref(domain.root_domain, domain.root_target.url)}
                        onClick={(e) => e.stopPropagation()}
                        className="hover:text-blue-400 transition-colors"
                      >
                        {domain.root_target.total_scans} completed scans
                      </Link>
                      {domain.root_target.active_findings_count > 0 && (
                        <Link
                          href={`/findings?target_id=${domain.root_target.id}&status=active`}
                          onClick={(e) => e.stopPropagation()}
                          className="text-yellow-500 hover:text-yellow-400 transition-colors"
                        >
                          {domain.root_target.active_findings_count} findings
                        </Link>
                      )}
                      {(domain.root_target.investigator_verified_count || 0) > 0 && (
                        <Link
                          href={`/hunt?target=${domain.root_target.id}`}
                          onClick={(e) => e.stopPropagation()}
                          className="text-emerald-400 transition-colors hover:text-emerald-300"
                          title="Deterministically verified investigator findings"
                        >
                          {domain.root_target.investigator_verified_count} verified
                        </Link>
                      )}
                      {(domain.root_target.investigator_suspected_count || 0) > 0 && (
                        <Link
                          href={`/hunt?target=${domain.root_target.id}`}
                          onClick={(e) => e.stopPropagation()}
                          className="text-amber-400 transition-colors hover:text-amber-300"
                          title="Evidence-backed investigator leads awaiting deterministic proof"
                        >
                          {domain.root_target.investigator_suspected_count} suspected
                        </Link>
                      )}
                      {domain.root_target.asm_coverage && (
                        <Link
                          href={`/asm?target_id=${domain.root_target.id}`}
                          onClick={(e) => e.stopPropagation()}
                          className="text-blue-400 hover:text-blue-300 transition-colors"
                          title="Attack surface coverage"
                        >
                          {(domain.root_target.asm_coverage.coverage * 100).toFixed(0)}% covered
                        </Link>
                      )}
                      <Link
                        href={`/targets/${domain.root_target.id}/graph`}
                        onClick={(e) => e.stopPropagation()}
                        className="text-purple-400 hover:text-purple-300 transition-colors"
                        title="Application graph"
                      >
                        graph
                      </Link>
                    </div>
                    {domain.root_target.last_grade && (
                      <span
                        className="hidden text-xs text-gray-400 sm:inline"
                        title="Historical posture observed by the latest scan. Review that scan's examination strength before relying on it."
                      >
                        Observed {domain.root_target.last_grade} · review coverage
                      </span>
                    )}
                    {/* Schedule Button */}
                    <Link
                      href={`/schedules?create=true&target_id=${domain.root_target!.id}`}
                      onClick={(e) => e.stopPropagation()}
                      className="hidden p-1 text-gray-500 transition-colors hover:text-blue-400 md:inline-flex"
                      title="Create schedule"
                      aria-label={`Create schedule for ${domain.root_domain}`}
                    >
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    </Link>
                    {/* Scan Menu */}
                    <div className={`relative ${openScanMenu === domain.root_target!.id ? 'z-[100]' : ''}`} ref={openScanMenu === domain.root_target!.id ? scanMenuRef : null}>
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          setOpenScanMenu(openScanMenu === domain.root_target!.id ? null : domain.root_target!.id)
                        }}
                        aria-expanded={openScanMenu === domain.root_target!.id}
                        aria-haspopup="menu"
                        className="flex items-center gap-1 px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-medium transition-colors"
                      >
                        Scan
                        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                        </svg>
                      </button>
                      {openScanMenu === domain.root_target!.id && (
                        <div role="menu" className="absolute right-0 mt-1 w-64 bg-gray-800 border border-gray-700 rounded-lg shadow-xl py-1">
                          <button role="menuitem" onClick={(e) => { e.stopPropagation(); handleScan(domain.root_target!.id) }} className="w-full px-3 py-2 text-left hover:bg-gray-700 transition-colors">
                            <span className="text-sm text-white font-medium">Run Scan</span>
                            <p className="text-xs text-gray-400 mt-0.5">Balanced budget · passive policy</p>
                          </button>
                          <Link
                            role="menuitem"
                            href={configureScanHref([domain.root_target!.url])}
                            onClick={(event) => { event.stopPropagation(); setOpenScanMenu(null) }}
                            className="block w-full border-t border-gray-700 px-3 py-2 text-left hover:bg-gray-700"
                          >
                            <span className="text-sm font-medium text-white">Customize Scan…</span>
                            <span className="mt-0.5 block text-xs text-gray-400">Choose budget, permissions, credentials, and coverage</span>
                          </Link>
                        </div>
                      )}
                    </div>
                  </>
                )}
                {/* Scan All Menu - scan entire domain set */}
                {domain.total_count > 0 && (
                  <div className={`relative ${openScanAllMenu === domain.root_domain ? 'z-[100]' : ''}`} ref={openScanAllMenu === domain.root_domain ? scanAllMenuRef : null}>
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        setOpenScanAllMenu(openScanAllMenu === domain.root_domain ? null : domain.root_domain)
                      }}
                      aria-expanded={openScanAllMenu === domain.root_domain}
                      aria-haspopup="menu"
                      disabled={scanningDomains.has(domain.root_domain)}
                      className="flex items-center gap-1 px-3 py-1 bg-green-600 hover:bg-green-700 disabled:bg-green-600/50 text-white rounded text-xs font-medium transition-colors"
                      title={`Scan all ${domain.total_count} target${domain.total_count !== 1 ? 's' : ''} in this asset group`}
                    >
                      {scanningDomains.has(domain.root_domain) ? (
                        <>
                          <div className="animate-spin rounded-full h-3 w-3 border-b-2 border-white"></div>
                          <span>Starting...</span>
                        </>
                      ) : (
                        <>
                          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                          </svg>
                          <span>Scan All ({domain.total_count})</span>
                          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                          </svg>
                        </>
                      )}
                    </button>
                    {openScanAllMenu === domain.root_domain && (
                      <div role="menu" className="absolute right-0 mt-1 w-72 bg-gray-800 border border-gray-700 rounded-lg shadow-xl py-1">
                        <div className="px-3 py-2 border-b border-gray-700">
                          <p className="text-xs text-gray-400">
                            Scan {domain.root_target ? '1 root + ' : ''}{domain.subdomain_count} subdomain{domain.subdomain_count !== 1 ? 's' : ''}
                          </p>
                        </div>
                        <button role="menuitem" onClick={(e) => { e.stopPropagation(); setOpenScanAllMenu(null); setScanAllPending({ domain }) }} className="w-full px-3 py-2 text-left hover:bg-gray-700 transition-colors">
                          <span className="text-sm text-white font-medium">Run Scan</span>
                          <p className="text-xs text-gray-400 mt-0.5">Balanced budget · passive policy</p>
                        </button>
                        <Link
                          role="menuitem"
                          href={configureScanHref([
                            ...(domain.root_target ? [domain.root_target.url] : []),
                            ...domain.subdomains.map((target) => target.url),
                          ], true)}
                          onClick={(event) => { event.stopPropagation(); setOpenScanAllMenu(null) }}
                          className="block w-full border-t border-gray-700 px-3 py-2 text-left hover:bg-gray-700"
                        >
                          <span className="text-sm font-medium text-white">Customize batch…</span>
                          <span className="mt-0.5 block text-xs text-gray-400">Review every target and choose shared budget and permissions</span>
                        </Link>
                      </div>
                    )}
                  </div>
                )}
                {/* Subdomain discovery only applies to registrable domain identities. */}
                {identity.canDiscoverSubdomains && (
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    handleDiscover(domain.root_domain)
                  }}
                  disabled={discoveringDomains.has(domain.root_domain)}
                  className="flex items-center justify-center gap-1 rounded border border-gray-700 bg-gray-800 px-3 py-1 text-xs font-medium text-gray-200 transition-colors hover:bg-gray-700 disabled:opacity-50"
                  title="Discover subdomains"
                >
                  {discoveringDomains.has(domain.root_domain) ? (
                    <>
                      <div className="animate-spin rounded-full h-3 w-3 border-b-2 border-white"></div>
                      <span>Discovering...</span>
                    </>
                  ) : (
                    <>
                      <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                      </svg>
                      <span>Discover</span>
                    </>
                  )}
                </button>
                )}
                {!domain.root_target && (
                  <span className="text-xs text-gray-600 italic">Grouped targets · no exact root record</span>
                )}
              </div>

              {/* Subdomains List */}
              {expandedDomains.has(domain.root_domain) && domain.subdomains.length > 0 && (
                <div className="border-t border-gray-800">
                  {domain.subdomains.map((subdomain) => (
                    <div
                      key={subdomain.id}
                      className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-2 border-b border-gray-800/50 px-3 py-3 transition-colors last:border-b-0 hover:bg-gray-800/30 sm:flex sm:gap-3 sm:px-4 sm:pl-12"
                    >
                      {/* Tree connector */}
                      <span className="text-gray-700">&#x2514;</span>

                      {/* Subdomain Info */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm text-gray-300 truncate">
                            {subdomain.url.replace(/^https?:\/\//, '')}
                          </span>
                          <span className={`px-1.5 py-0.5 text-xs rounded ${getSourceBadge(subdomain.discovery_source)}`}>
                            {subdomain.discovery_source}
                          </span>
                        </div>
                      </div>

                      {/* Subdomain Stats */}
                      <div className="hidden items-center gap-4 text-sm text-gray-500 lg:flex">
                        <Link
                          href={scanHistoryHref(domain.root_domain, subdomain.url)}
                          className="hover:text-blue-400 transition-colors"
                        >
                          {subdomain.total_scans} completed scans
                        </Link>
                        {subdomain.active_findings_count > 0 && (
                          <Link
                            href={`/findings?target_id=${subdomain.id}&status=active`}
                            className="text-yellow-500 hover:text-yellow-400 transition-colors"
                          >
                            {subdomain.active_findings_count} findings
                          </Link>
                        )}
                        {(subdomain.investigator_verified_count || 0) > 0 && (
                          <Link
                            href={`/hunt?target=${subdomain.id}`}
                            className="text-emerald-400 transition-colors hover:text-emerald-300"
                            title="Deterministically verified investigator findings"
                          >
                            {subdomain.investigator_verified_count} verified
                          </Link>
                        )}
                        {(subdomain.investigator_suspected_count || 0) > 0 && (
                          <Link
                            href={`/hunt?target=${subdomain.id}`}
                            className="text-amber-400 transition-colors hover:text-amber-300"
                            title="Evidence-backed investigator leads awaiting deterministic proof"
                          >
                            {subdomain.investigator_suspected_count} suspected
                          </Link>
                        )}
                        {subdomain.asm_coverage && (
                          <Link
                            href={`/asm?target_id=${subdomain.id}`}
                            className="text-blue-400 hover:text-blue-300 transition-colors"
                            title="Attack surface coverage"
                          >
                            {(subdomain.asm_coverage.coverage * 100).toFixed(0)}% covered
                          </Link>
                        )}
                        <Link
                          href={`/targets/${subdomain.id}/graph`}
                          className="text-purple-400 hover:text-purple-300 transition-colors"
                          title="Application graph"
                        >
                          graph
                        </Link>
                      </div>

                      {subdomain.last_grade && (
                        <span
                          className="hidden text-xs text-gray-400 sm:inline"
                          title="Historical posture observed by the latest scan. Review that scan's examination strength before relying on it."
                        >
                          Observed {subdomain.last_grade} · review coverage
                        </span>
                      )}

                      {/* Schedule Button for Subdomain */}
                      <Link
                        href={`/schedules?create=true&target_id=${subdomain.id}`}
                        className="hidden p-1 text-gray-500 transition-colors hover:text-blue-400 md:inline-flex"
                        title="Create schedule"
                        aria-label={`Create schedule for ${subdomain.url.replace(/^https?:\/\//, '')}`}
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                      </Link>
                      {/* Scan Menu for Subdomain */}
                      <div className={`relative ${openScanMenu === subdomain.id ? 'z-[100]' : ''}`} ref={openScanMenu === subdomain.id ? scanMenuRef : null}>
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            setOpenScanMenu(openScanMenu === subdomain.id ? null : subdomain.id)
                          }}
                          aria-expanded={openScanMenu === subdomain.id}
                          aria-haspopup="menu"
                          className="flex items-center gap-1 px-2 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-medium transition-colors"
                        >
                          Scan
                          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                          </svg>
                        </button>
                        {openScanMenu === subdomain.id && (
                          <div role="menu" className="absolute right-0 mt-1 w-64 bg-gray-800 border border-gray-700 rounded-lg shadow-xl py-1">
                            <button role="menuitem" onClick={(e) => { e.stopPropagation(); handleScan(subdomain.id) }} className="w-full px-3 py-2 text-left hover:bg-gray-700 transition-colors">
                              <span className="text-sm text-white font-medium">Run Scan</span>
                              <p className="text-xs text-gray-400 mt-0.5">Balanced budget · passive policy</p>
                            </button>
                            <Link
                              role="menuitem"
                              href={configureScanHref([subdomain.url])}
                              onClick={(event) => { event.stopPropagation(); setOpenScanMenu(null) }}
                              className="block w-full border-t border-gray-700 px-3 py-2 text-left hover:bg-gray-700"
                            >
                              <span className="text-sm font-medium text-white">Customize Scan…</span>
                              <span className="mt-0.5 block text-xs text-gray-400">Choose budget, permissions, credentials, and coverage</span>
                            </Link>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Card>
            )
          })}
        </div>
      )}

      <Modal open={showAddModal} title="Add Target" onClose={closeAddModal}>
        <form onSubmit={handleAddTarget} className="space-y-4">
          <Field label="URL" error={urlError || undefined}>
            <Input
              type="text"
              value={newTargetUrl}
              onChange={(e) => {
                setNewTargetUrl(e.target.value)
                if (urlError) setUrlError('')
              }}
              placeholder="https://example.com"
              error={Boolean(urlError)}
              required
            />
          </Field>
          <Field label="Name (optional)">
            <Input
              type="text"
              value={newTargetName}
              onChange={(e) => setNewTargetName(e.target.value)}
              placeholder="My Website"
            />
          </Field>
          <Field label="Cohort">
            <Select value={newTargetCohort} onChange={(event) => setNewTargetCohort(event.target.value as typeof newTargetCohort)}>
              <option value="">Unclassified</option>
              <option value="production">Production</option>
              <option value="staging">Staging</option>
              <option value="lab">Lab</option>
              <option value="demo">Demo</option>
              <option value="calibration">Calibration</option>
              <option value="internal">Internal</option>
            </Select>
          </Field>
          <div className="flex gap-3">
            <Button type="button" variant="secondary" onClick={closeAddModal} className="flex-1">
              Cancel
            </Button>
            <Button type="submit" loading={adding} className="flex-1">
              {adding ? 'Adding…' : 'Add Target'}
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  )
}

export default function TargetsPage() {
  return (
    <Suspense fallback={<CardSkeleton count={4} />}>
      <TargetsContent />
    </Suspense>
  )
}
