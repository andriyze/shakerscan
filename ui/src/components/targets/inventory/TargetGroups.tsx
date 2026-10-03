'use client'

import { ChevronDown, ChevronRight, Globe, Server, SlidersHorizontal } from 'lucide-react'
import Link from '@/components/WorkspaceLink'
import type { TargetAsset, TargetAssetGroup } from '@/lib/targetAssetApi'
import { featureEnabled } from '@/lib/workspaceCapabilities'
import { configureScanHref, scanUrls } from '@/lib/targetInventoryModel.mjs'
import { boundedDisplayText } from '@/lib/targetChoices'
import { TargetDomainDiscovery } from '../TargetDomainDiscovery'
import { DeleteRecordsButton } from '@/components/lifecycle/DeleteRecordsButton'
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

/** Each top-level group (a domain, or the IP and local-host group) is its own card. */
const GROUP_CARD = 'overflow-hidden rounded-xl border border-gray-800 bg-gray-900/40 shadow-sm shadow-black/20'

export function ColumnHeader() {
  return <div role="row" className={`hidden px-[17px] pb-1 text-[11px] font-medium uppercase tracking-wider text-gray-500 ${ROW_GRID}`}>
    <span role="columnheader"><span className="sr-only">Select</span></span>
    <span role="columnheader">Target</span>
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
    return <section data-testid="target-domain-group" aria-label={`Targets in ${domain}`} className={GROUP_CARD}>
      <div role="rowgroup"><TargetRow asset={root} selected={selection.selected.has(root.id)} onSelect={value => selection.toggle([root.id], value)}
        actions={actions} busy={busy === root.id} discoverDomain={group.root_domain} /></div>
    </section>
  }
  return <section data-testid="target-domain-group" aria-label={`Targets in ${domain}`} className={GROUP_CARD}>
    <div className="flex flex-wrap items-center gap-3 bg-gray-900/70 px-4 py-2.5">
      <GroupCheckbox targets={group.targets} selection={selection} label={`Select all targets in ${domain}`} />
      {children.length > 0
        ? <button type="button" onClick={onToggle} aria-expanded={open} aria-label={`Subdomains of ${domain}`}
            className="flex min-w-0 items-center gap-2 rounded-md text-left text-sm font-semibold text-white hover:text-blue-200">
            {open ? <ChevronDown className="h-4 w-4 shrink-0 text-gray-400" aria-hidden="true" /> : <ChevronRight className="h-4 w-4 shrink-0 text-gray-400" aria-hidden="true" />}
            <Globe className="h-4 w-4 shrink-0 text-blue-300/80" aria-hidden="true" />
            <span className="truncate">{domain}</span>
          </button>
        : <span className="flex min-w-0 items-center gap-2 text-sm font-semibold text-white"><Globe className="h-4 w-4 shrink-0 text-blue-300/80" aria-hidden="true" /><span className="truncate">{domain}</span></span>}
      <span className="rounded-full bg-gray-800 px-2 py-0.5 text-[11px] text-gray-400">
        {group.targets.length} target{group.targets.length === 1 ? '' : 's'}{children.length ? ` · ${children.length} subdomain${children.length === 1 ? '' : 's'}` : ''}
      </span>
      {!open && children.length > 0 && <SeverityPills compact counts={combinedSeverity(group.targets)} />}
      <span className="ml-auto flex items-center gap-2">
        {batch.length > 1 && <Link href={configureScanHref(batch, true)} title="Open New Scan with every web app in this domain"
          className="inline-flex items-center gap-1.5 rounded-lg px-2 py-1 text-xs font-medium text-gray-300 hover:bg-gray-800 hover:text-white">
          <SlidersHorizontal className="h-3.5 w-3.5" aria-hidden="true" />Customize batch…</Link>}
        {discovery && <TargetDomainDiscovery domain={group.root_domain} onSettled={onDiscovered} />}
        {onDomainDeleted && group.root_domain.includes('.') && <DeleteRecordsButton
          selection={{ kind: 'domain', domain: group.root_domain }} label="Delete domain" variant="ghost"
          subject={`${domain} and all its subdomains`} onDeleted={onDomainDeleted}
          className="px-2 py-1 text-xs text-red-300 hover:text-red-200" />}
      </span>
    </div>
    <div role="rowgroup" className="divide-y divide-gray-800/60">
      {root && row(root)}
      {(open || !root) && children.map(asset => row(asset, Boolean(root)))}
    </div>
  </section>
}

export function NetworkGroup({ targets, selection, actions, busy }: {
  targets: TargetAsset[]; selection: Selection; actions: RowActions; busy: string | null
}) {
  if (!targets.length) return null
  return <section data-testid="target-network-group" aria-label="IP addresses and local hosts" className={GROUP_CARD}>
    <div className="flex flex-wrap items-center gap-3 bg-gray-900/70 px-4 py-2.5">
      <GroupCheckbox targets={targets} selection={selection} label="Select all IP addresses and local hosts" />
      <span className="flex items-center gap-2 text-sm font-semibold text-white"><Server className="h-4 w-4 text-cyan-300/80" aria-hidden="true" />IP addresses &amp; local hosts</span>
      <span className="rounded-full bg-gray-800 px-2 py-0.5 text-[11px] text-gray-400">{targets.length} target{targets.length === 1 ? '' : 's'}</span>
      <span className="ml-auto hidden text-[11px] text-gray-500 md:block">Internal names and addresses: the runtime destination policy is checked before execution.</span>
    </div>
    <div role="rowgroup" className="divide-y divide-gray-800/60">
      {targets.map(asset => <TargetRow key={asset.id} asset={asset}
        selected={selection.selected.has(asset.id)} onSelect={value => selection.toggle([asset.id], value)}
        actions={actions} busy={busy === asset.id} />)}
    </div>
  </section>
}
