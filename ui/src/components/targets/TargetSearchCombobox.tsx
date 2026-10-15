'use client'

import { useEffect, useMemo } from 'react'
import { Combobox, type ComboboxOption } from '@/components/ui'
import { targetSearchNote } from '@/lib/pickerOptions'
import { boundedTargetDisplay } from '@/lib/targetChoices'
import type { TargetAsset } from '@/lib/targetAssetApi'
import { useTargetSearch } from '@/lib/useTargetSearch'

/**
 * A single target picker that searches the inventory on the server (one bounded page per
 * debounced query) instead of loading a capped first page of every target. The selected target
 * is read on its own when it is not among the matches, and reported through `onSelectedAsset`.
 */
export function TargetSearchCombobox({
  id, value, onChange, accept, includeServices = true, noneLabel, placeholder = 'Choose a target',
  'aria-label': ariaLabel, onSelectedAsset, disabled,
}: {
  id?: string
  value: string
  onChange: (value: string) => void
  /** Which matches are choices (active web targets, ...). */
  accept?: (asset: TargetAsset) => boolean
  /** Search every target row, web origins included, not only top-level assets. Default true. */
  includeServices?: boolean
  noneLabel?: string
  placeholder?: string
  'aria-label'?: string
  onSelectedAsset?: (asset: TargetAsset | undefined) => void
  disabled?: boolean
}) {
  const search = useTargetSearch({ selectedIds: [value], includeServices, accept })
  const options = useMemo<ComboboxOption[]>(() => search.assets
    .filter((asset) => !accept || accept(asset))
    .map((asset) => ({
      value: asset.id,
      label: boundedTargetDisplay(asset),
      description: asset.name ? boundedTargetDisplay({ url: asset.url }) : undefined,
      keywords: `${asset.url} ${asset.root_domain || ''}`,
    })), [accept, search.assets])
  const selected = value ? search.byId(value) : undefined
  useEffect(() => { onSelectedAsset?.(selected) }, [onSelectedAsset, selected])
  return <Combobox id={id} value={value} onChange={onChange} options={options} noneLabel={noneLabel}
    placeholder={placeholder} searchPlaceholder="Search targets by name or host…" aria-label={ariaLabel}
    onQueryChange={search.setQuery} loading={search.loading} footerNote={targetSearchNote(search)} disabled={disabled} />
}
