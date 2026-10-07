'use client'

import { ChevronDown, ChevronRight, Globe, Server, SlidersHorizontal } from 'lucide-react'
import type { TargetAsset, TargetAssetGroup } from '@/lib/targetAssetApi'
import { featureEnabled } from '@/lib/workspaceCapabilities'
import { configureScanHref, scanUrls } from '@/lib/targetInventoryModel.mjs'
import { boundedDisplayText } from '@/lib/targetChoices'
import { TargetDomainDiscovery } from '../TargetDomainDiscovery'
import { DeleteRecordsButton } from '@/components/lifecycle/DeleteRecordsButton'
import { MenuItem, MenuSeparator, RowMenu } from './RowMenu'
import { ROW_GRID, SeverityPills, TargetRow, type RowActions } from './TargetRow'

type Selection = { selected: Set<string>; toggle: (ids: string[], selected: boolean) => void }

function combinedSeverity(targets: TargetAsset[]) {
  const total: Record<string, number> = {}
  for (const asset of targets) for (const [severity, count] of Object.entries(asset.severity_counts || {})) {
    total[severity] = (total[severity] || 0) + Number(count || 0)
  }
  return total
}

function GroupCheckbox({ targets, selection, label }: { targets: TargetAsset[]; selection: Selection; label: string }) {
  const ids = targets.map(asset => asset.id)
  const chosen = ids.filter(id => selection.selected.has(id)).length
  return <input type="checkbox" aria-label={label} checked={chosen > 0 && chosen === ids.length}
    ref={element => { if (element) element.indeterminate = chosen > 0 && chosen < ids.length }}
    onChange={event => selection.toggle(ids, event.target.checked)}
    className="h-4 w-4 cursor-pointer rounded border-gray-600 bg-gray-900 accent-blue-500" />
}

/**
 * Every group (a domain, or the IP and local-host group) is a band inside the one inventory table.
 * Its first header or row carries the top hairline, which also separates it from the column header.
 */
const GROUP = 'block'
const GROUP_HEADER = 'flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-gray-800 bg-gray-950/50 px-4 py-2'

export function ColumnHeader() {
  return <div role="row" className={`hidden px-4 py-2.5 text-xs font-medium text-gray-400 ${ROW_GRID}`}>
    <span role="columnheader"><span className="sr-only">Select</span></span>
    <span role="columnheader">Target</span>
    <span role="columnheader">Authorization</span>
    <span role="columnheader">Web apps &amp; services</span>
    <span role="columnheader">Open findings</span>
    <span role="columnheader">Last scan</span>
    <span role="columnheader" className="text-right"><span className="sr-only">Actions</span></span>
  </div>
}

export function DomainGroup({ group, open, onToggle, onDiscovered, onDomainDeleted, selection, actions, busy }: {
  group: TargetAssetGroup; open: boolean; onToggle: () => void; onDiscovered: () => void
  selection: Selection; actions: RowActions; busy: string | null
  /** The whole domain group was deleted; reload the inventory. */
  onDomainDeleted?: () => void
}) {
  const root = group.targets.find(asset => asset.locator === group.root_domain)
  const children = group.targets.filter(asset => asset !== root)
  const row = (asset: TargetAsset, nested = false) => <TargetRow key={asset.id} asset={asset} nested={nested}
    selected={selection.selected.has(asset.id)} onSelect={value => selection.toggle([asset.id], value)}
    actions={actions} busy={busy === asset.id} />
  const discovery = featureEnabled('discovery')
  const domain = boundedDisplayText(group.root_domain, 120)
  const batch = [...new Set(group.targets.filter(asset => asset.is_active).flatMap(asset => scanUrls(asset)))]
  // A domain with nothing beneath it reads as one row, with discovery in its menu.
  if (root && !children.length) {
    return <section data-testid="target-domain-group" aria-label={`Targets in ${domain}`} className={GROUP}>
      <div role="rowgroup"><TargetRow asset={root} selected={selection.selected.has(root.id)} onSelect={value => selection.toggle([root.id], value)}
        actions={actions} busy={busy === root.id} discoverDomain={group.root_domain} /></div>
    </section>
  }
  const deletable = Boolean(onDomainDeleted && group.root_domain.includes('.'))
  return <section data-testid="target-domain-group" aria-label={`Targets in ${domain}`} className={GROUP}>
    <div className={GROUP_HEADER}>
      <GroupCheckbox targets={group.targets} selection={selection} label={`Select all targets in ${domain}`} />
      {children.length > 0
        ? <button type="button" onClick={onToggle} aria-expanded={open} aria-label={`Subdomains of ${domain}`}
            className="flex min-w-0 items-center gap-1.5 rounded-md text-left text-sm font-semibold text-gray-100 hover:text-white">
            {open ? <ChevronDown className="h-4 w-4 shrink-0 text-gray-500" aria-hidden="true" /> : <ChevronRight className="h-4 w-4 shrink-0 text-gray-500" aria-hidden="true" />}
            <span className="truncate">{domain}</span>
          </button>
        : <span className="flex min-w-0 items-center gap-2 text-sm font-semibold text-gray-100"><Globe className="h-4 w-4 shrink-0 text-gray-500" aria-hidden="true" /><span className="truncate">{domain}</span></span>}
      <span className="text-xs tabular-nums text-gray-500">
        {group.targets.length} target{group.targets.length === 1 ? '' : 's'}{children.length ? ` · ${children.length} subdomain${children.length === 1 ? '' : 's'}` : ''}
      </span>
      {!open && children.length > 0 && <SeverityPills compact counts={combinedSeverity(group.targets)} />}
      {(batch.length > 1 || discovery || deletable) && <span className="ml-auto">
        <RowMenu label={`Actions for ${domain}`}>
          {batch.length > 1 && <MenuItem icon={<SlidersHorizontal />} href={configureScanHref(batch, true)}
            description="Open New Scan with every web app in this domain">Customize batch…</MenuItem>}
          {discovery && <TargetDomainDiscovery domain={group.root_domain} menuItem onSettled={onDiscovered} />}
          {deletable && onDomainDeleted && <>
            <MenuSeparator />
            <DeleteRecordsButton
              selection={{ kind: 'domain', domain: group.root_domain }} label="Delete domain…" variant="ghost"
              subject={`${domain} and all its subdomains`} onDeleted={onDomainDeleted}
              className="w-full justify-start px-3! text-red-300 hover:bg-red-500/10" />
          </>}
        </RowMenu>
      </span>}
    </div>
    <div role="rowgroup">
      {root && row(root)}
      {(open || !root) && children.map(asset => row(asset, Boolean(root)))}
    </div>
  </section>
}

export function NetworkGroup({ targets, selection, actions, busy }: {
  targets: TargetAsset[]; selection: Selection; actions: RowActions; busy: string | null
}) {
  if (!targets.length) return null
  return <section data-testid="target-network-group" aria-label="IP addresses and local hosts" className={GROUP}>
    <div className={GROUP_HEADER}>
      <GroupCheckbox targets={targets} selection={selection} label="Select all IP addresses and local hosts" />
      <span className="flex items-center gap-2 text-sm font-semibold text-gray-100"><Server className="h-4 w-4 text-gray-500" aria-hidden="true" />IP addresses &amp; local hosts</span>
      <span className="text-xs tabular-nums text-gray-500">{targets.length} target{targets.length === 1 ? '' : 's'}</span>
      <span className="ml-auto hidden text-xs text-gray-500 md:block">Internal names and addresses: the runtime destination policy is checked before execution.</span>
    </div>
    <div role="rowgroup">
      {targets.map(asset => <TargetRow key={asset.id} asset={asset}
        selected={selection.selected.has(asset.id)} onSelect={value => selection.toggle([asset.id], value)}
        actions={actions} busy={busy === asset.id} />)}
    </div>
  </section>
}
