'use client'

import { useState } from 'react'
import { ArrowDownWideNarrow, ArrowUpNarrowWide, SlidersHorizontal } from 'lucide-react'
import { getSeverityBg } from '@/lib/api'
import { cn } from '@/lib/cn'
import {
  SEVERITY_LEVELS,
  FINDING_STATUSES,
  FINDING_STATUS_LABELS,
  SORT_OPTIONS,
  LAST_SEEN_OPTIONS,
  type SortOption,
  type SortOrder,
} from '@/lib/constants'
import { Button, Card, Field, Input, Select, Tabs, Toggle } from '@/components/ui'
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

const STATUS_TAB_ITEMS = [
  { key: 'all', label: 'All' },
  ...FINDING_STATUSES.map((status) => ({ key: status, label: FINDING_STATUS_LABELS[status] })),
]

const SOURCE_TAB_ITEMS = SOURCE_TYPE_OPTIONS.map((option) => ({ key: option.value || 'all', label: option.label }))

// Severity is a property you narrow by, so it gets free uppercase pills (echoing the row badge);
// status is a partition of your work, so it gets the segmented Tabs control. Different shapes
// for different questions.
const SEVERITY_PILL_BASE =
  'rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-wide transition-colors ' +
  'focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500'

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
  status: string
  severity: string
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
  domains,
}: {
  searchInput: string
  onSearchInputChange: (value: string) => void
  values: FindingsToolbarValues
  setFilter: (key: string, value: string | number | undefined) => void
  setFilters: (updates: FilterUpdates) => void
  domains: string[]
}) {
  const [filtersOpen, setFiltersOpen] = useState(false)
  const secondaryFilterCount = countActiveSecondaryFilters([
    values.sourceType, values.domain, values.lastSeen, values.verificationVerdict, values.verificationMode, values.verifiedOnly,
  ])
  const SortDirectionIcon = values.sortOrder === 'desc' ? ArrowDownWideNarrow : ArrowUpNarrowWide
  const sortDirectionLabel = getSortOrderLabel(values.sortBy, values.sortOrder)

  return (
    <div className="space-y-3">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
        <div className="min-w-0 flex-1">
          <Input
            type="search"
            placeholder="Search findings by title or URL…"
            value={searchInput}
            onChange={(e) => onSearchInputChange(e.target.value)}
            aria-label="Search findings by title or URL"
          />
        </div>
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
          active={values.status || 'all'}
          onChange={(key) => setFilter('status', key === 'all' ? undefined : key)}
        />
        <div role="group" aria-label="Filter by severity" className="flex flex-wrap gap-1.5">
          {SEVERITY_LEVELS.map((sev) => {
            const active = values.severity === sev
            return (
              <button
                key={sev}
                type="button"
                aria-pressed={active}
                onClick={() => setFilter('severity', active ? undefined : sev)}
                className={cn(
                  SEVERITY_PILL_BASE,
                  active
                    ? `${getSeverityBg(sev)} ring-1 ring-inset ring-white/10`
                    : 'bg-gray-800/60 text-gray-500 hover:bg-gray-800 hover:text-gray-300'
                )}
              >
                {sev}
              </button>
            )
          })}
        </div>
      </div>
    </div>
  )
}
