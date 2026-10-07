'use client'

import { Select, SearchInput, Stat, StatGroup, Toolbar } from '@/components/ui'
import type { InventoryFacets } from '@/lib/targetAssetApi'
import { activeFilterCount, FILTER_DEFAULTS } from '@/lib/targetInventoryModel.mjs'

export type InventoryFilters = typeof FILTER_DEFAULTS

/** Headline counts that double as one-click filters; the active one is underlined. */
export function InventorySummary({ facets, filters, onChange }: {
  facets: InventoryFacets | null; filters: InventoryFilters; onChange: (next: Partial<InventoryFilters>) => void
}) {
  const count = (value: number | undefined) => (facets ? (value ?? 0).toLocaleString() : '–')
  const only = (patch: Partial<InventoryFilters>) => {
    const key = Object.keys(patch)[0] as keyof InventoryFilters
    onChange(filters[key] === patch[key] ? { [key]: '' } : patch)
  }
  const critical = facets?.findings.critical_high ?? 0
  return <StatGroup columns={5} className="mb-5" ariaLabel="Target summary">
    <Stat label="Targets" value={count(facets?.total)}
      active={activeFilterCount(filters) === 0} onClick={() => onChange({ environment: '', authorization: '', findings: '', activity: '', asset_type: '', archived: false })} />
    <Stat label="Not authorized"
      value={count(facets?.authorization.unauthorized)} active={filters.authorization === 'unauthorized'} onClick={() => only({ authorization: 'unauthorized' })} />
    <Stat label="Critical or high findings" value={count(facets?.findings.critical_high)} tone={critical > 0 ? 'danger' : 'default'}
      active={filters.findings === 'critical_high'} onClick={() => only({ findings: 'critical_high' })} />
    <Stat label="Never scanned" value={count(facets?.activity.never)}
      active={filters.activity === 'never'} onClick={() => only({ activity: 'never' })} />
    <Stat label="Scanning now" value={count(facets?.activity.scanning)}
      active={filters.activity === 'scanning'} onClick={() => only({ activity: 'scanning' })} />
  </StatGroup>
}

function withCount(label: string, value: number | undefined, facets: InventoryFacets | null) {
  return facets && value !== undefined ? `${label} (${value.toLocaleString()})` : label
}

export function InventoryToolbar({ filters, facets, onChange, searchRef }: {
  filters: InventoryFilters; facets: InventoryFacets | null
  onChange: (next: Partial<InventoryFilters>) => void; searchRef?: React.Ref<HTMLInputElement>
}) {
  const environments = Object.entries(facets?.environment || {}).sort(([left], [right]) => left.localeCompare(right))
  if (filters.environment && !environments.some(([name]) => name === filters.environment)) environments.push([filters.environment, 0])
  const filtered = activeFilterCount(filters)
  const filterClass = 'max-w-full'
  return <Toolbar>
    <SearchInput ref={searchRef} aria-label="Search targets by URL or domain" placeholder="Search domains, hosts, URLs…" value={filters.search}
      onValueChange={search => onChange({ search })} shortcutHint="/" wrapperClassName="w-full sm:w-60" />
    <Select fullWidth={false} aria-label="Environment" value={filters.environment} onChange={event => onChange({ environment: event.target.value })} className={filterClass}>
      <option value="">All environments</option>
      {environments.map(([name, total]) => <option key={name} value={name}>{withCount(name.charAt(0).toUpperCase() + name.slice(1), total, facets)}</option>)}
    </Select>
    <Select fullWidth={false} aria-label="Authorization" value={filters.authorization} onChange={event => onChange({ authorization: event.target.value })} className={filterClass}>
      <option value="">Any authorization</option>
      <option value="authorized">{withCount('Authorized', facets?.authorization.authorized, facets)}</option>
      <option value="unauthorized">{withCount('Not authorized', facets?.authorization.unauthorized, facets)}</option>
    </Select>
    <Select fullWidth={false} aria-label="Findings" value={filters.findings} onChange={event => onChange({ findings: event.target.value })} className={filterClass}>
      <option value="">Any findings</option>
      <option value="critical_high">{withCount('Critical or high', facets?.findings.critical_high, facets)}</option>
      <option value="any">{withCount('Has open findings', facets?.findings.any, facets)}</option>
      <option value="none">{withCount('No open findings', facets?.findings.none, facets)}</option>
    </Select>
    <Select fullWidth={false} aria-label="Scan activity" value={filters.activity} onChange={event => onChange({ activity: event.target.value })} className={filterClass}>
      <option value="">Any scan activity</option>
      <option value="scanned">{withCount('Scanned', facets?.activity.scanned, facets)}</option>
      <option value="never">{withCount('Never scanned', facets?.activity.never, facets)}</option>
      <option value="scanning">{withCount('Scanning now', facets?.activity.scanning, facets)}</option>
    </Select>
    {(filtered > 0 || filters.search) && <button type="button" onClick={() => onChange({ ...FILTER_DEFAULTS, sort: filters.sort })}
      className="rounded-md px-2 py-1.5 text-sm font-medium text-blue-400 hover:bg-blue-500/10 hover:text-blue-300">Clear all{filtered ? ` (${filtered})` : ''}</button>}
  </Toolbar>
}

/** The line above the table: what is listed, which surfaces, and how it is ordered. */
export function InventoryListBar({ filters, facets, onChange, summary }: {
  filters: InventoryFilters; facets: InventoryFacets | null
  onChange: (next: Partial<InventoryFilters>) => void; summary: React.ReactNode
}) {
  return <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
    <p className="text-sm text-gray-400" aria-live="polite">{summary}</p>
    <div className="flex flex-wrap items-center gap-3">
      <Select fullWidth={false} aria-label="Surface" value={filters.asset_type} onChange={event => onChange({ asset_type: event.target.value })} className="h-8 py-1 text-sm">
        <option value="">Web and network</option>
        <option value="web">{withCount('Web apps', facets?.asset_type.web, facets)}</option>
        <option value="network">{withCount('Network & devices', facets?.asset_type.network, facets)}</option>
      </Select>
      <label className="flex shrink-0 cursor-pointer items-center gap-2 whitespace-nowrap text-sm text-gray-400">
        <input type="checkbox" className="h-3.5 w-3.5 accent-blue-500" checked={filters.archived} onChange={event => onChange({ archived: event.target.checked })} />
        Show archived
      </label>
      <Select fullWidth={false} aria-label="Sort targets" value={filters.sort} onChange={event => onChange({ sort: event.target.value })} className="h-8 py-1 text-sm">
        <option value="name">Sort: Name</option>
        <option value="risk">Sort: Highest risk</option>
        <option value="recent">Sort: Recently scanned</option>
        <option value="created">Sort: Newest</option>
      </Select>
    </div>
  </div>
}
