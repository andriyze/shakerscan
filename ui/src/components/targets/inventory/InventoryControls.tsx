'use client'

import type { ReactNode } from 'react'
import { AlertTriangle, Clock, Layers3, Radar, Search, ShieldOff, X } from 'lucide-react'
import { Input, Select } from '@/components/ui'
import type { InventoryFacets } from '@/lib/targetAssetApi'
import { activeFilterCount, FILTER_DEFAULTS } from '@/lib/targetInventoryModel.mjs'

export type InventoryFilters = typeof FILTER_DEFAULTS

function Tile({ icon, label, value, hint, active, tone, onClick }: {
  icon: ReactNode; label: string; value: ReactNode; hint?: string; active: boolean
  tone: 'blue' | 'amber' | 'red' | 'gray' | 'cyan'; onClick: () => void
}) {
  const tones = {
    blue: 'text-blue-300 bg-blue-500/10', amber: 'text-amber-300 bg-amber-500/10', red: 'text-red-300 bg-red-500/10',
    gray: 'text-gray-300 bg-gray-700/40', cyan: 'text-cyan-300 bg-cyan-500/10',
  }
  return <button type="button" onClick={onClick} aria-pressed={active}
    className={`group flex min-w-0 items-center gap-3 rounded-xl border p-3.5 text-left transition-all ${active
      ? 'border-blue-400/50 bg-blue-500/[0.07] shadow-[0_0_0_1px_rgba(96,165,250,0.15)]'
      : 'border-gray-800 bg-gray-900/60 hover:border-gray-700 hover:bg-gray-900'}`}>
    <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${tones[tone]} [&>svg]:h-4.5 [&>svg]:w-4.5`} aria-hidden="true">{icon}</span>
    <span className="min-w-0">
      <span className="block text-xl font-semibold leading-6 tabular-nums text-white">{value}</span>
      <span className="block truncate text-xs text-gray-400">{label}{hint && <span className="text-gray-500"> · {hint}</span>}</span>
    </span>
  </button>
}

export function InventorySummary({ facets, filters, onChange }: {
  facets: InventoryFacets | null; filters: InventoryFilters; onChange: (next: Partial<InventoryFilters>) => void
}) {
  const count = (value: number | undefined) => (facets ? (value ?? 0).toLocaleString() : '–')
  const only = (patch: Partial<InventoryFilters>) => {
    const key = Object.keys(patch)[0] as keyof InventoryFilters
    onChange(filters[key] === patch[key] ? { [key]: '' } : patch)
  }
  return <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
    <Tile icon={<Layers3 />} tone="blue" label="Targets" value={count(facets?.total)}
      active={activeFilterCount(filters) === 0} onClick={() => onChange({ environment: '', authorization: '', findings: '', activity: '', asset_type: '', archived: false })} />
    <Tile icon={<ShieldOff />} tone="gray" label="Not authorized"
      value={count(facets?.authorization.unauthorized)} active={filters.authorization === 'unauthorized'} onClick={() => only({ authorization: 'unauthorized' })} />
    <Tile icon={<AlertTriangle />} tone="red" label="Critical or high findings" value={count(facets?.findings.critical_high)}
      active={filters.findings === 'critical_high'} onClick={() => only({ findings: 'critical_high' })} />
    <Tile icon={<Clock />} tone="amber" label="Never scanned" value={count(facets?.activity.never)}
      active={filters.activity === 'never'} onClick={() => only({ activity: 'never' })} />
    <Tile icon={<Radar />} tone="cyan" label="Scanning now" value={count(facets?.activity.scanning)}
      active={filters.activity === 'scanning'} onClick={() => only({ activity: 'scanning' })} />
  </div>
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
  const selectClass = 'h-9 w-full py-1.5 text-sm'
  const filterClass = `${selectClass} sm:w-auto sm:min-w-44`
  return <div className="mb-4 rounded-xl border border-gray-800 bg-gray-900/60 p-3">
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
      <div className="relative min-w-0 flex-1">
        <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-gray-500" aria-hidden="true" />
        <Input ref={searchRef} aria-label="Search targets by URL or domain" placeholder="Search domains, hosts, URLs…" value={filters.search}
          onChange={event => onChange({ search: event.target.value })} className="h-9 w-full pl-9 pr-14" />
        {filters.search
          ? <button type="button" aria-label="Clear search" onClick={() => onChange({ search: '' })}
              className="absolute right-2 top-2 rounded p-0.5 text-gray-500 hover:text-gray-200"><X className="h-4 w-4" /></button>
          : <kbd className="pointer-events-none absolute right-2.5 top-2 hidden rounded border border-gray-700 px-1.5 text-[11px] leading-5 text-gray-500 sm:block">/</kbd>}
      </div>
      <div className="flex shrink-0 items-center gap-3">
        <Select aria-label="Sort targets" value={filters.sort} onChange={event => onChange({ sort: event.target.value })} className={`${selectClass} sm:w-52`}>
          <option value="name">Sort: Name</option>
          <option value="risk">Sort: Highest risk</option>
          <option value="recent">Sort: Recently scanned</option>
          <option value="created">Sort: Newest</option>
        </Select>
        <label className="flex shrink-0 cursor-pointer items-center gap-2 whitespace-nowrap text-xs text-gray-400">
          <input type="checkbox" className="h-3.5 w-3.5 accent-blue-500" checked={filters.archived} onChange={event => onChange({ archived: event.target.checked })} />
          Show archived
        </label>
      </div>
    </div>
    <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-gray-800/70 pt-3">
      <span className="mr-1 text-xs font-medium text-gray-500">Filter</span>
      <Select aria-label="Environment" value={filters.environment} onChange={event => onChange({ environment: event.target.value })} className={filterClass}>
        <option value="">All environments</option>
        {environments.map(([name, total]) => <option key={name} value={name}>{withCount(name.charAt(0).toUpperCase() + name.slice(1), total, facets)}</option>)}
      </Select>
      <Select aria-label="Authorization" value={filters.authorization} onChange={event => onChange({ authorization: event.target.value })} className={filterClass}>
        <option value="">Any authorization</option>
        <option value="authorized">{withCount('Authorized', facets?.authorization.authorized, facets)}</option>
        <option value="unauthorized">{withCount('Not authorized', facets?.authorization.unauthorized, facets)}</option>
      </Select>
      <Select aria-label="Findings" value={filters.findings} onChange={event => onChange({ findings: event.target.value })} className={filterClass}>
        <option value="">Any findings</option>
        <option value="critical_high">{withCount('Critical or high', facets?.findings.critical_high, facets)}</option>
        <option value="any">{withCount('Has open findings', facets?.findings.any, facets)}</option>
        <option value="none">{withCount('No open findings', facets?.findings.none, facets)}</option>
      </Select>
      <Select aria-label="Scan activity" value={filters.activity} onChange={event => onChange({ activity: event.target.value })} className={filterClass}>
        <option value="">Any scan activity</option>
        <option value="scanned">{withCount('Scanned', facets?.activity.scanned, facets)}</option>
        <option value="never">{withCount('Never scanned', facets?.activity.never, facets)}</option>
        <option value="scanning">{withCount('Scanning now', facets?.activity.scanning, facets)}</option>
      </Select>
      <Select aria-label="Surface" value={filters.asset_type} onChange={event => onChange({ asset_type: event.target.value })} className={filterClass}>
        <option value="">Web and network</option>
        <option value="web">{withCount('Web apps', facets?.asset_type.web, facets)}</option>
        <option value="network">{withCount('Network & devices', facets?.asset_type.network, facets)}</option>
      </Select>
      {(filtered > 0 || filters.search) && <button type="button" onClick={() => onChange({ ...FILTER_DEFAULTS, sort: filters.sort })}
        className="ml-auto rounded-md px-2 py-1 text-xs font-medium text-blue-300 hover:bg-blue-500/10 hover:text-blue-200">Clear all{filtered ? ` (${filtered})` : ''}</button>}
    </div>
  </div>
}
