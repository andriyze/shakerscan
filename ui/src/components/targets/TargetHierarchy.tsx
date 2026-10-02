'use client'

import type { ReactNode } from 'react'
import { ChevronDown, ChevronRight, Globe, Network } from 'lucide-react'
import { Card } from '@/components/ui'
import type { TargetAsset, TargetAssetGroup } from '@/lib/targetAssetApi'
import { featureEnabled } from '@/lib/workspaceCapabilities'
import { TargetDomainDiscovery } from './TargetDomainDiscovery'

export function TargetHierarchy({ groups, searching, expanded, onToggle, onDiscoverySettled, renderAsset }: {
  groups: TargetAssetGroup[]
  searching: boolean
  expanded: Set<string>
  onToggle: (domain: string) => void
  onDiscoverySettled: (domain: string) => void
  renderAsset: (asset: TargetAsset) => ReactNode
}) {
  return <div className="space-y-4">{groups.map(group => {
    const roots = group.targets.filter(asset => asset.locator === group.root_domain)
    const children = group.targets.filter(asset => asset.locator !== group.root_domain)
    const open = searching || expanded.has(group.root_domain)
    const host = group.root_domain.includes(':') || /^\d+(\.\d+){3}$/.test(group.root_domain) || !group.root_domain.includes('.') || /\.(local|internal|localhost)$/.test(group.root_domain)
    return <Card key={group.root_domain} className="overflow-hidden rounded-xl border-gray-800/80 p-0 shadow-sm transition-colors hover:border-gray-700" data-testid="target-domain-group">
      {!host && <div className="flex flex-wrap items-center gap-3 border-b border-gray-800/80 bg-gray-800/20 px-4 py-3">
        <Globe className="h-4 w-4 shrink-0 text-blue-300/80" />
        {children.length ? <button className="flex min-w-[min(100%,14rem)] flex-1 items-center gap-2 text-left font-medium text-white" aria-expanded={open} aria-label={`Subdomains of ${group.root_domain}`} onClick={() => onToggle(group.root_domain)}>
          {open ? <ChevronDown className="h-4 w-4 shrink-0" /> : <ChevronRight className="h-4 w-4 shrink-0" />}
          <span className="break-all">{group.root_domain}</span>
          <span className="shrink-0 rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">{children.length} subdomain{children.length === 1 ? '' : 's'}</span>
        </button> : <span className="min-w-0 flex-1 break-all font-medium text-white">{group.root_domain}</span>}
        {!host && featureEnabled('discovery') && <div className="ml-auto shrink-0"><TargetDomainDiscovery domain={group.root_domain} onSettled={() => onDiscoverySettled(group.root_domain)} /></div>}
      </div>}
      <div className="overflow-x-auto"><table aria-label={`Targets in ${group.root_domain}`} className="w-full min-w-[640px] text-left text-sm">
        <thead className="sr-only"><tr><th>Target</th><th>Inventory</th><th>Actions</th></tr></thead>
        <tbody className="divide-y divide-gray-800/70 [&>tr]:transition-colors [&>tr:hover]:bg-gray-800/25">{roots.map(renderAsset)}{(open || !roots.length && children.length === 1) && children.map(renderAsset)}</tbody>
      </table></div>
    </Card>
  })}</div>
}
