'use client'

import { useEffect, useState, useRef } from 'react'
import { getTargetsGrouped, createTarget, scanTarget, discoverSubdomains, getGradeColor, formatDate, type Target, type GroupedDomain } from '@/lib/api'

type ScanType = 'quick' | 'standard' | 'deep' | 'full' | 'smart' | 'aggressive'

const SCAN_TYPES: { value: ScanType; label: string; description: string; requiresPermission?: boolean }[] = [
  { value: 'quick', label: 'Quick', description: '1-2 min • DNS, TLS, headers' },
  { value: 'standard', label: 'Standard', description: '5-10 min • + Nuclei, cookies, CORS' },
  { value: 'deep', label: 'Deep', description: '30-60 min • + Full Nuclei, ports' },
  { value: 'full', label: 'Full', description: '1-2 hrs • + Active XSS/SQLi', requiresPermission: true },
  { value: 'aggressive', label: 'Aggressive', description: '2+ hrs • Maximum coverage', requiresPermission: true },
  { value: 'smart', label: 'Smart', description: 'Adaptive intelligent scan', requiresPermission: true },
]

export default function TargetsPage() {
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
  const scanMenuRef = useRef<HTMLDivElement>(null)
  const scanAllMenuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    fetchTargets()
  }, [])

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

  async function fetchTargets() {
    try {
      const data = await getTargetsGrouped()
      setDomains(data.domains || [])
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
  }

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
      const options: Record<string, boolean | string> = {}
      switch (scanType) {
        case 'quick':
          options.quick = true
          break
        case 'standard':
          // Default scan, no special options
          break
        case 'deep':
          options.thorough = true
          break
        case 'full':
          options.thorough = true
          options.active = true
          break
        case 'aggressive':
          options.scan_type = 'aggressive'
          break
        case 'smart':
          options.scan_type = 'smart'
          break
      }
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
      const options: Record<string, boolean | string> = {}
      switch (scanType) {
        case 'quick':
          options.quick = true
          break
        case 'standard':
          break
        case 'deep':
          options.thorough = true
          break
        case 'full':
          options.thorough = true
          options.active = true
          break
        case 'aggressive':
          options.scan_type = 'aggressive'
          break
        case 'smart':
          options.scan_type = 'smart'
          break
      }

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
    }
    return styles[source] || styles['manual']
  }

  const totalTargets = domains.reduce((sum, d) => sum + d.total_count, 0)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Targets</h1>
          <p className="text-gray-400 mt-1">
            {domains.length} domain{domains.length !== 1 ? 's' : ''} • {totalTargets} target{totalTargets !== 1 ? 's' : ''}
          </p>
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
          <p className="text-gray-500">No targets yet. Add a target to get started.</p>
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
                      <span>{domain.root_target.total_scans} scans</span>
                      {domain.root_target.active_findings_count > 0 && (
                        <span className="text-yellow-500">{domain.root_target.active_findings_count} findings</span>
                      )}
                    </div>
                    {domain.root_target.last_grade && (
                      <span className={`text-xl font-bold ${getGradeColor(domain.root_target.last_grade)}`}>
                        {domain.root_target.last_grade}
                      </span>
                    )}
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
                              <p className="text-xs text-gray-400 mt-0.5">{type.description}</p>
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
                            <p className="text-xs text-gray-400 mt-0.5">{type.description}</p>
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
                      <span className="text-gray-700">└</span>

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
                        <span>{subdomain.total_scans} scans</span>
                        {subdomain.active_findings_count > 0 && (
                          <span className="text-yellow-500">{subdomain.active_findings_count}</span>
                        )}
                      </div>

                      {subdomain.last_grade && (
                        <span className={`text-lg font-bold ${getGradeColor(subdomain.last_grade)}`}>
                          {subdomain.last_grade}
                        </span>
                      )}

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
                                <p className="text-xs text-gray-400 mt-0.5">{type.description}</p>
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
