'use client'

import { useEffect, useState, useRef, useCallback, Suspense } from 'react'
import Link from 'next/link'
import { getTargetsGrouped, createTarget, scanTarget, discoverSubdomains, getGradeColor, formatDate, type Target, type GroupedDomain } from '@/lib/api'
import { SCAN_TYPES, getScanOptions, DISCOVERY_SOURCES, GRADES, TARGET_SORT_OPTIONS, type ScanType, type SortOrder } from '@/lib/constants'
import { useUrlFilters } from '@/lib/useUrlFilters'

const SEARCH_DEBOUNCE_MS = 300

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

  const [domains, setDomains] = useState<GroupedDomain[]>([])
  const [loading, setLoading] = useState(true)
  const [showAddModal, setShowAddModal] = useState(false)
  const [newTargetUrl, setNewTargetUrl] = useState('')
  const [newTargetName, setNewTargetName] = useState('')
  const [adding, setAdding] = useState(false)
  const [expandedDomains, setExpandedDomains] = useState<Set<string>>(new Set())
  const [openScanMenu, setOpenScanMenu] = useState<string | null>(null)
  const [openScanAllMenu, setOpenScanAllMenu] = useState<string | null>(null)
  const [scanningDomains, setScanningDomains] = useState<Set<string>>(new Set())
  const [discoveringDomains, setDiscoveringDomains] = useState<Set<string>>(new Set())
  const [searchInput, setSearchInput] = useState<string>(filters.search || '')
  const [totalRootDomains, setTotalRootDomains] = useState(0)
  const [totalTargets, setTotalTargets] = useState(0)
  const scanMenuRef = useRef<HTMLDivElement>(null)
  const scanAllMenuRef = useRef<HTMLDivElement>(null)
  const searchTimeout = useRef<NodeJS.Timeout | null>(null)

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
      // Auto-expand domains with subdomains
      const toExpand = new Set<string>()
      data.domains?.forEach(d => {
        if (d.subdomain_count > 0) toExpand.add(d.root_domain)
      })
      setExpandedDomains(toExpand)
    } catch (err) {
      console.error('Failed to fetch targets:', err)
    } finally {
      setLoading(false)
    }
  }, [searchQuery, discoverySourceFilter, gradeFilter, hasFindingsFilter, sortBy, sortOrder])

  useEffect(() => {
    fetchTargets()
  }, [fetchTargets])

  async function handleAddTarget(e: React.FormEvent) {
    e.preventDefault()
    if (!newTargetUrl.trim()) return

    setAdding(true)
    try {
      await createTarget(newTargetUrl.trim(), newTargetName.trim() || undefined)
      setNewTargetUrl('')
      setNewTargetName('')
      setShowAddModal(false)
      fetchTargets()
    } catch (err) {
      console.error('Failed to add target:', err)
    } finally {
      setAdding(false)
    }
  }

  async function handleScan(targetId: string, scanType: ScanType) {
    try {
      const options = getScanOptions(scanType)
      await scanTarget(targetId, options)
      setOpenScanMenu(null)
      window.location.href = '/scans'
    } catch (err) {
      console.error('Failed to start scan:', err)
    }
  }

  async function handleScanDomainSet(domain: GroupedDomain, scanType: ScanType) {
    const allTargets: Target[] = []
    if (domain.root_target) {
      allTargets.push(domain.root_target)
    }
    allTargets.push(...domain.subdomains)

    if (allTargets.length === 0) {
      console.error('No targets to scan')
      return
    }

    setScanningDomains(prev => new Set(prev).add(domain.root_domain))
    setOpenScanAllMenu(null)

    try {
      const options = getScanOptions(scanType)
      // Submit scans for all targets in parallel
      await Promise.all(allTargets.map(target => scanTarget(target.id, options)))
      window.location.href = '/scans'
    } catch (err) {
      console.error('Failed to start domain set scan:', err)
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
      // Refresh targets after a short delay to allow discovery to start
      setTimeout(() => {
        fetchTargets()
        setDiscoveringDomains(prev => {
          const next = new Set(prev)
          next.delete(rootDomain)
          return next
        })
      }, 2000)
    } catch (err) {
      console.error('Failed to start discovery:', err)
      setDiscoveringDomains(prev => {
        const next = new Set(prev)
        next.delete(rootDomain)
        return next
      })
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
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Targets</h1>
          <p className="text-gray-400 mt-1">Manage your scan targets</p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Add Target
        </button>
      </div>

      {/* Filters */}
      <div className="flex gap-4 flex-wrap">
        {/* Discovery Source Filter */}
        <div className="flex items-center gap-3">
          <label className="text-sm text-gray-400">Source:</label>
          <select
            value={discoverySourceFilter}
            onChange={(e) => setFilter('discovery_source', e.target.value || undefined)}
            className="px-3 py-2 bg-gray-900 border border-gray-800 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
          >
            <option value="">All sources</option>
            {DISCOVERY_SOURCES.map((source) => (
              <option key={source} value={source}>{source}</option>
            ))}
          </select>
        </div>

        {/* Grade Filter */}
        <div className="flex items-center gap-3">
          <label className="text-sm text-gray-400">Grade:</label>
          <select
            value={gradeFilter}
            onChange={(e) => setFilter('grade', e.target.value || undefined)}
            className="px-3 py-2 bg-gray-900 border border-gray-800 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
          >
            <option value="">All grades</option>
            {GRADES.map((grade) => (
              <option key={grade} value={grade}>{grade}</option>
            ))}
          </select>
        </div>

        {/* Has Findings Filter */}
        <div className="flex items-center gap-3">
          <label className="text-sm text-gray-400">Findings:</label>
          <select
            value={hasFindingsFilter}
            onChange={(e) => setFilter('has_findings', e.target.value || undefined)}
            className="px-3 py-2 bg-gray-900 border border-gray-800 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
          >
            <option value="">All</option>
            <option value="true">With findings</option>
            <option value="false">No findings</option>
          </select>
        </div>

        {/* Sort By */}
        <div className="flex items-center gap-3">
          <label className="text-sm text-gray-400">Sort:</label>
          <select
            value={sortBy}
            onChange={(e) => setFilter('sort_by', e.target.value || undefined)}
            className="px-3 py-2 bg-gray-900 border border-gray-800 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
          >
            {TARGET_SORT_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>{option.label}</option>
            ))}
          </select>
          <button
            onClick={toggleSortOrder}
            className="px-3 py-2 bg-gray-900 border border-gray-800 rounded-lg text-white text-sm hover:bg-gray-800 focus:outline-none focus:border-blue-500"
            title={sortOrder === 'asc' ? 'Ascending' : 'Descending'}
          >
            {sortOrder === 'asc' ? (
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
              </svg>
            ) : (
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
              </svg>
            )}
          </button>
        </div>

        {/* Search */}
        <div className="relative flex-1 min-w-[200px]">
          <input
            type="text"
            placeholder="Search by URL or domain..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            className="w-full px-4 py-2 bg-gray-900 border border-gray-800 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
          <svg className="absolute right-3 top-2.5 w-5 h-5 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        </div>
      </div>

      {/* Summary with Clear Filters */}
      <div className="flex items-center justify-between">
        <span className="text-sm text-gray-400">
          {totalRootDomains} domain{totalRootDomains !== 1 ? 's' : ''} - {totalTargets} target{totalTargets !== 1 ? 's' : ''}
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
        <div className="flex items-center justify-center h-32">
          <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500"></div>
        </div>
      ) : domains.length === 0 ? (
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-8 text-center">
          <svg className="w-12 h-12 text-gray-600 mx-auto mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9" />
          </svg>
          <p className="text-gray-500">
            {hasActiveFilters ? 'No targets found matching your filters.' : 'No targets yet. Add a target to get started.'}
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {domains.map((domain) => (
            <div
              key={domain.root_domain}
              className="bg-gray-900 rounded-lg border border-gray-800"
            >
              {/* Root Domain Header */}
              <div
                className="flex items-center gap-3 p-4 cursor-pointer hover:bg-gray-800/50 transition-colors"
                onClick={() => domain.subdomain_count > 0 && toggleExpand(domain.root_domain)}
              >
                {/* Expand/Collapse Icon */}
                {domain.subdomain_count > 0 ? (
                  <button className="text-gray-500 hover:text-white">
                    <svg
                      className={`w-4 h-4 transition-transform ${expandedDomains.has(domain.root_domain) ? 'rotate-90' : ''}`}
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                  </button>
                ) : (
                  <div className="w-4" />
                )}

                {/* Domain Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-white">{domain.root_domain}</span>
                    {domain.subdomain_count > 0 && (
                      <span className="px-1.5 py-0.5 bg-gray-800 text-gray-400 text-xs rounded">
                        +{domain.subdomain_count} subdomain{domain.subdomain_count !== 1 ? 's' : ''}
                      </span>
                    )}
                  </div>
                  {domain.root_target && (
                    <p className="text-xs text-gray-500 truncate">{domain.root_target.url}</p>
                  )}
                </div>

                {/* Root Target Stats */}
                {domain.root_target && (
                  <>
                    <div className="flex items-center gap-4 text-sm text-gray-500">
                      <Link
                        href={`/scans?domain=${domain.root_domain}`}
                        onClick={(e) => e.stopPropagation()}
                        className="hover:text-blue-400 transition-colors"
                      >
                        {domain.root_target.total_scans} scans
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
                    </div>
                    {domain.root_target.last_grade && (
                      <span className={`text-xl font-bold ${getGradeColor(domain.root_target.last_grade)}`}>
                        {domain.root_target.last_grade}
                      </span>
                    )}
                    {/* Schedule Button */}
                    <Link
                      href={`/schedules?create=true&target_id=${domain.root_target!.id}`}
                      onClick={(e) => e.stopPropagation()}
                      className="p-1 text-gray-500 hover:text-blue-400 transition-colors"
                      title="Create schedule"
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
                        className="flex items-center gap-1 px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-medium transition-colors"
                      >
                        Scan
                        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                        </svg>
                      </button>
                      {openScanMenu === domain.root_target!.id && (
                        <div className="absolute right-0 mt-1 w-56 bg-gray-800 border border-gray-700 rounded-lg shadow-xl py-1">
                          {SCAN_TYPES.map((type) => (
                            <button
                              key={type.value}
                              onClick={(e) => {
                                e.stopPropagation()
                                handleScan(domain.root_target!.id, type.value)
                              }}
                              className="w-full px-3 py-2 text-left hover:bg-gray-700 transition-colors"
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
                      disabled={scanningDomains.has(domain.root_domain)}
                      className="flex items-center gap-1 px-3 py-1 bg-green-600 hover:bg-green-700 disabled:bg-green-600/50 text-white rounded text-xs font-medium transition-colors"
                      title={`Scan all ${domain.total_count} target${domain.total_count !== 1 ? 's' : ''} in this domain`}
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
                      <div className="absolute right-0 mt-1 w-64 bg-gray-800 border border-gray-700 rounded-lg shadow-xl py-1">
                        <div className="px-3 py-2 border-b border-gray-700">
                          <p className="text-xs text-gray-400">
                            Scan {domain.root_target ? '1 root + ' : ''}{domain.subdomain_count} subdomain{domain.subdomain_count !== 1 ? 's' : ''}
                          </p>
                        </div>
                        {SCAN_TYPES.map((type) => (
                          <button
                            key={type.value}
                            onClick={(e) => {
                              e.stopPropagation()
                              handleScanDomainSet(domain, type.value)
                            }}
                            className="w-full px-3 py-2 text-left hover:bg-gray-700 transition-colors"
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
                {/* Discover Button - always show for root domains */}
                <button
                  onClick={(e) => {
                    e.stopPropagation()
                    handleDiscover(domain.root_domain)
                  }}
                  disabled={discoveringDomains.has(domain.root_domain)}
                  className="flex items-center gap-1 px-3 py-1 bg-purple-600 hover:bg-purple-700 disabled:bg-purple-600/50 text-white rounded text-xs font-medium transition-colors"
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
                {!domain.root_target && (
                  <span className="text-xs text-gray-600 italic">No root target</span>
                )}
              </div>

              {/* Subdomains List */}
              {expandedDomains.has(domain.root_domain) && domain.subdomains.length > 0 && (
                <div className="border-t border-gray-800">
                  {domain.subdomains.map((subdomain) => (
                    <div
                      key={subdomain.id}
                      className="flex items-center gap-3 px-4 py-3 pl-12 hover:bg-gray-800/30 transition-colors border-b border-gray-800/50 last:border-b-0"
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
                      <div className="flex items-center gap-4 text-sm text-gray-500">
                        <Link
                          href={`/scans?domain=${domain.root_domain}`}
                          className="hover:text-blue-400 transition-colors"
                        >
                          {subdomain.total_scans} scans
                        </Link>
                        {subdomain.active_findings_count > 0 && (
                          <Link
                            href={`/findings?target_id=${subdomain.id}&status=active`}
                            className="text-yellow-500 hover:text-yellow-400 transition-colors"
                          >
                            {subdomain.active_findings_count}
                          </Link>
                        )}
                      </div>

                      {subdomain.last_grade && (
                        <span className={`text-lg font-bold ${getGradeColor(subdomain.last_grade)}`}>
                          {subdomain.last_grade}
                        </span>
                      )}

                      {/* Schedule Button for Subdomain */}
                      <Link
                        href={`/schedules?create=true&target_id=${subdomain.id}`}
                        className="p-1 text-gray-500 hover:text-blue-400 transition-colors"
                        title="Create schedule"
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
                          className="flex items-center gap-1 px-2 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs font-medium transition-colors"
                        >
                          Scan
                          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                          </svg>
                        </button>
                        {openScanMenu === subdomain.id && (
                          <div className="absolute right-0 mt-1 w-56 bg-gray-800 border border-gray-700 rounded-lg shadow-xl py-1">
                            {SCAN_TYPES.map((type) => (
                              <button
                                key={type.value}
                                onClick={(e) => {
                                  e.stopPropagation()
                                  handleScan(subdomain.id, type.value)
                                }}
                                className="w-full px-3 py-2 text-left hover:bg-gray-700 transition-colors"
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
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Add Target Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-900 rounded-lg border border-gray-800 max-w-md w-full">
            <div className="p-4 border-b border-gray-800 flex items-center justify-between">
              <h2 className="font-medium text-white">Add Target</h2>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-gray-400 hover:text-white"
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <form onSubmit={handleAddTarget} className="p-4 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">URL</label>
                <input
                  type="text"
                  value={newTargetUrl}
                  onChange={(e) => setNewTargetUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Name (optional)</label>
                <input
                  type="text"
                  value={newTargetName}
                  onChange={(e) => setNewTargetName(e.target.value)}
                  placeholder="My Website"
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>
              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="flex-1 px-4 py-2 bg-gray-800 hover:bg-gray-700 text-white rounded-lg text-sm font-medium transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={adding}
                  className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-600/50 text-white rounded-lg text-sm font-medium transition-colors"
                >
                  {adding ? 'Adding...' : 'Add Target'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

export default function TargetsPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center h-32">
        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500"></div>
      </div>
    }>
      <TargetsContent />
    </Suspense>
  )
}
