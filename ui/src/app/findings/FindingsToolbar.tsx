'use client'

import { useState } from 'react'
import { ArrowDownWideNarrow, ArrowUpNarrowWide, SlidersHorizontal } from 'lucide-react'
import { cn } from '@/lib/cn'
import {
  SEVERITY_LEVELS,
  SORT_OPTIONS,
  LAST_SEEN_OPTIONS,
  type SortOption,
  type SortOrder,
} from '@/lib/constants'
import { STALE_AFTER_DAYS } from '@/lib/findingFreshness'
import type { StatusView } from '@/lib/findingGroups'
import { listFilterValues, toggleListFilterValue } from '@/lib/listFilterValues'
import { Button, Card, Field, SearchInput, Select, Tabs, Toggle } from '@/components/ui'
import { countActiveSecondaryFilters } from './triage'

export const VERIFICATION_VERDICTS = [
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

// Open work first: the list used to default to every historical row, burying open findings
// among resolved and dismissed ones. "All" is the last choice, not the starting point.
const STATUS_TAB_ITEMS: { key: StatusView; label: string }[] = [
  { key: 'active', label: 'Open' },
  { key: 'resolved', label: 'Resolved' },
  { key: 'false_positive', label: 'False positive' },
  { key: 'accepted_risk', label: 'Accepted risk' },
  { key: 'all', label: 'All' },
]

export type FreshnessView = 'current' | 'stale' | 'all'

const FRESHNESS_TAB_ITEMS: { key: FreshnessView; label: string }[] = [
  { key: 'current', label: `Seen in ${STALE_AFTER_DAYS} days` },
  { key: 'stale', label: 'Not seen recently' },
  { key: 'all', label: 'Any time' },
]

const SOURCE_TAB_ITEMS = SOURCE_TYPE_OPTIONS.map((option) => ({ key: option.value || 'all', label: option.label }))

// Severity is a property you narrow by, so it gets toggle chips (each with the row badge's
// color as a dot); status is a partition of your work, so it gets the segmented Tabs control.
// Different shapes for different questions.
// The list's proof badges, as filters: the server's projection, the same field the badge shows.
const PROOF_FILTERS = [
  { key: 'verified', label: 'Proven', hint: 'Deterministic proof confirmed these', dot: 'bg-emerald-400' },
  { key: 'suspected', label: 'Suspected', hint: 'Leads that are not proven yet', dot: 'bg-amber-400' },
] as const
const PROOF_ORDER = ['verified', 'suspected', 'unverified'] as const

const SEVERITY_DOTS: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-400',
  low: 'bg-blue-400',
  info: 'bg-gray-500',
}

// Quiet toggle chips: neutral outline at rest, a filled neutral chip when on (aria-pressed).
const FILTER_CHIP_BASE =
  'inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors ' +
  'focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500'
const FILTER_CHIP_IDLE = 'border-gray-800 text-gray-400 hover:border-gray-700 hover:text-gray-200'
const FILTER_CHIP_ACTIVE = 'border-gray-600 bg-gray-800 text-white'

export function getSortOrderLabel(sortBy: SortOption, sortOrder: SortOrder): string {
  if (sortBy === 'last_seen' || sortBy === 'first_seen') {
    return sortOrder === 'desc' ? 'Newest first' : 'Oldest first'
  }
  if (sortBy === 'cvss') {
    return sortOrder === 'desc' ? 'Highest first' : 'Lowest first'
  }
  return sortOrder === 'desc' ? 'Critical first' : 'Info first'
}

export interface FindingsToolbarValues {
  /** The status view in effect (the URL may leave the default out). */
  status: StatusView
  /** The freshness view in effect, and whether the URL chose it explicitly. */
  freshness: FreshnessView
  freshnessExplicit: boolean
  /** Comma list; several severities may be selected. */
  severity: string
  /** Comma list of server proof states (verified, suspected). */
  proofState: string
  sourceType: string
  domain: string
  lastSeen: number
  verificationVerdict: string
  verificationMode: string
  verifiedOnly: boolean
  sortBy: SortOption
  sortOrder: SortOrder
}

type FilterUpdates = Record<string, string | number | undefined>

/**
 * Search leads; secondary filters fold away behind a counted Filters button; sort stays in
 * reach because sort order is a primary triage control. Status tabs partition the work,
 * severity pills narrow it. URL state stays in the page's single useUrlFilters instance.
 */
export function FindingsToolbar({
  searchInput,
  onSearchInputChange,
  values,
  setFilter,
  setFilters,
  onStatusChange,
  onFreshnessChange,
  domains,
}: {
  searchInput: string
  onSearchInputChange: (value: string) => void
  values: FindingsToolbarValues
  setFilter: (key: string, value: string | number | undefined) => void
  setFilters: (updates: FilterUpdates) => void
  onStatusChange: (view: StatusView) => void
  onFreshnessChange: (view: FreshnessView) => void
  domains: string[]
}) {
  const [filtersOpen, setFiltersOpen] = useState(false)
  const secondaryFilterCount = countActiveSecondaryFilters([
    values.freshnessExplicit && !values.lastSeen ? values.freshness : '',
    values.sourceType, values.domain, values.lastSeen, values.verificationVerdict, values.verificationMode, values.verifiedOnly,
  ])
  const SortDirectionIcon = values.sortOrder === 'desc' ? ArrowDownWideNarrow : ArrowUpNarrowWide
  const sortDirectionLabel = getSortOrderLabel(values.sortBy, values.sortOrder)

  return (
    <div className="space-y-3">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
        <SearchInput
          wrapperClassName="flex-1"
          placeholder="Search findings by title or URL…"
          value={searchInput}
          onValueChange={onSearchInputChange}
          aria-label="Search findings by title or URL"
        />
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="secondary"
            aria-expanded={filtersOpen}
            aria-controls="findings-more-filters"
            onClick={() => setFiltersOpen((open) => !open)}
          >
            <SlidersHorizontal className="h-4 w-4" aria-hidden="true" />
            Filters
            {secondaryFilterCount > 0 && (
              <span className="rounded-full bg-blue-600 px-1.5 text-[10px] font-semibold tabular-nums text-white">
                {secondaryFilterCount}<span className="sr-only"> active</span>
              </span>
            )}
          </Button>
          <span className="text-xs text-gray-500" aria-hidden="true">Sort</span>
          <Select
            fullWidth={false}
            value={values.sortBy}
            onChange={(e) => setFilter('sort_by', e.target.value)}
            aria-label="Sort by"
          >
            {SORT_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </Select>
          <Button
            variant="secondary"
            onClick={() => setFilter('sort_order', values.sortOrder === 'desc' ? 'asc' : 'desc')}
            aria-label={`Toggle sort direction: ${sortDirectionLabel}`}
            title={`Toggle sort direction: ${sortDirectionLabel}`}
          >
            <SortDirectionIcon className="h-4 w-4" aria-hidden="true" />
            {sortDirectionLabel}
          </Button>
        </div>
      </div>

      {filtersOpen && (
        <Card id="findings-more-filters" className="space-y-4 p-4">
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-xs font-medium text-gray-400">Seen</span>
            {/* What is still there vs. what no recent scan reached. Not seen recently is not
                the same as fixed; the count line says what the default leaves out. */}
            <Tabs
              ariaLabel="Finding freshness"
              items={FRESHNESS_TAB_ITEMS}
              active={values.lastSeen ? 'all' : values.freshness}
              onChange={(key) => onFreshnessChange(key as FreshnessView)}
            />
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-xs font-medium text-gray-400">Source</span>
            {/* User-facing finding source. Hunt includes direct AI claims and
                DAST work launched as part of a hunt. */}
            <Tabs
              ariaLabel="Filter by source"
              items={SOURCE_TAB_ITEMS}
              active={values.sourceType || 'all'}
              onChange={(key) => setFilter('source_type', key === 'all' ? undefined : key)}
            />
          </div>
          <div className="flex flex-wrap items-end gap-4">
            {domains.length > 0 && (
              <Field label="Domain">
                <Select fullWidth={false} value={values.domain} onChange={(e) => setFilter('domain', e.target.value || undefined)}>
                  <option value="">All domains</option>
                  {domains.map((domain) => (
                    <option key={domain} value={domain}>{domain}</option>
                  ))}
                </Select>
              </Field>
            )}
            <Field label="Last seen">
              <Select fullWidth={false} value={values.lastSeen || ''} onChange={(e) => setFilter('last_seen', e.target.value ? Number(e.target.value) : undefined)}>
                <option value="">All time</option>
                {LAST_SEEN_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </Select>
            </Field>
            <Field label="Retest verdict">
              <Select fullWidth={false} value={values.verificationVerdict} onChange={(e) => setFilter('verification_verdict', e.target.value || undefined)}>
                <option value="">All</option>
                {VERIFICATION_VERDICTS.map((verdict) => (
                  <option key={verdict} value={verdict}>{verdict.replaceAll('_', ' ')}</option>
                ))}
              </Select>
            </Field>
            <Field label="Retest mode">
              <Select fullWidth={false} value={values.verificationMode} onChange={(e) => setFilter('verification_mode', e.target.value || undefined)}>
                <option value="">All</option>
                <option value="deterministic">Deterministic</option>
                <option value="ai_driven">AI driven</option>
              </Select>
            </Field>
            <div className="flex items-center gap-2 pb-2">
              <Toggle
                label="Verified only"
                checked={values.verifiedOnly}
                onChange={(checked) => setFilter('verified_only', checked ? 'true' : undefined)}
              />
              <span aria-hidden="true" className="text-sm text-gray-300">Verified only</span>
            </div>
            {secondaryFilterCount > 0 && (
              <Button
                variant="ghost"
                size="sm"
                className="mb-1"
                onClick={() => setFilters({
                  freshness: undefined,
                  source_type: undefined,
                  domain: undefined,
                  last_seen: undefined,
                  verification_verdict: undefined,
                  verification_mode: undefined,
                  verified_only: undefined,
                })}
              >
                Clear these filters
              </Button>
            )}
          </div>
        </Card>
      )}

      {/* Status partitions the work; severity narrows it. Two shapes for two questions. */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <Tabs
          ariaLabel="Filter by status"
          items={STATUS_TAB_ITEMS}
          active={values.status}
          onChange={(key) => onStatusChange(key as StatusView)}
        />
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <div role="group" aria-label="Filter by proof" className="flex flex-wrap gap-1">
          {PROOF_FILTERS.map((proof) => {
            const active = listFilterValues(values.proofState).includes(proof.key)
            return (
              <button
                key={proof.key}
                type="button"
                aria-pressed={active}
                title={proof.hint}
                onClick={() => setFilter('proof_state', toggleListFilterValue(values.proofState, proof.key, PROOF_ORDER))}
                className={cn(FILTER_CHIP_BASE, active ? FILTER_CHIP_ACTIVE : FILTER_CHIP_IDLE)}
              >
                <span className={cn('h-1.5 w-1.5 rounded-full', proof.dot)} aria-hidden="true" />
                {proof.label}
              </button>
            )
          })}
        </div>
        {/* Several severities may be selected (critical and high together). */}
        <div role="group" aria-label="Filter by severity" className="flex flex-wrap gap-1">
          {SEVERITY_LEVELS.map((sev) => {
            const active = listFilterValues(values.severity).includes(sev)
            return (
              <button
                key={sev}
                type="button"
                aria-pressed={active}
                onClick={() => setFilter('severity', toggleListFilterValue(values.severity, sev, SEVERITY_LEVELS))}
                className={cn(FILTER_CHIP_BASE, 'capitalize', active ? FILTER_CHIP_ACTIVE : FILTER_CHIP_IDLE)}
              >
                <span className={cn('h-1.5 w-1.5 rounded-full', SEVERITY_DOTS[sev] || 'bg-gray-500')} aria-hidden="true" />
                {sev}
              </button>
            )
          })}
        </div>
        </div>
      </div>
    </div>
  )
}
