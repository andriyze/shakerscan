'use client'

import { useState, type ReactNode } from 'react'
import { ChevronDown, ChevronRight, Globe, Network } from 'lucide-react'
import { Card } from '@/components/ui'
import type { TargetAsset, TargetAssetGroup } from '@/lib/targetAssetApi'

export function TargetHierarchy({ groups, searching, renderAsset }: {
  groups: TargetAssetGroup[]
  searching: boolean
  renderAsset: (asset: TargetAsset) => ReactNode
}) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  return <div className="space-y-4">{groups.map(group => {
    const roots = group.targets.filter(asset => asset.locator === group.root_domain)
    const children = group.targets.filter(asset => asset.locator !== group.root_domain)
    const open = searching || expanded.has(group.root_domain)
    const host = group.root_domain.includes(':') || /^\d+(\.\d+){3}$/.test(group.root_domain) || !group.root_domain.includes('.') || /\.(local|internal|localhost)$/.test(group.root_domain)
    return <Card key={group.root_domain} className="overflow-hidden p-0" data-testid="target-domain-group">
      <div className="flex items-center gap-3 border-b border-gray-800 bg-gray-900/70 px-4 py-3">
        {host ? <Network className="h-4 w-4 shrink-0 text-cyan-300" /> : <Globe className="h-4 w-4 shrink-0 text-blue-300" />}
        {children.length ? <button className="flex min-w-0 flex-1 items-center gap-2 text-left font-medium text-white" aria-expanded={open} aria-label={`Subdomains of ${group.root_domain}`} onClick={() => setExpanded(current => {
          const next = new Set(current)
          if (next.has(group.root_domain)) next.delete(group.root_domain)
          else next.add(group.root_domain)
          return next
        })}>
          {open ? <ChevronDown className="h-4 w-4 shrink-0" /> : <ChevronRight className="h-4 w-4 shrink-0" />}
          <span className="break-all">{group.root_domain}</span>
          <span className="shrink-0 rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">{children.length} subdomain{children.length === 1 ? '' : 's'}</span>
        </button> : <span className="break-all font-medium text-white">{group.root_domain}</span>}
      </div>
      <div className="overflow-x-auto"><table className="w-full text-left text-sm">
        <thead className="text-xs uppercase text-gray-500"><tr><th className="px-4 py-3">Target</th><th className="px-4 py-3">Applications</th><th className="px-4 py-3">Known services</th><th className="px-4 py-3">Active findings</th><th className="px-4 py-3">View / action</th></tr></thead>
        <tbody className="divide-y divide-gray-800">{roots.map(renderAsset)}{(open || !roots.length && children.length === 1) && children.map(renderAsset)}</tbody>
      </table></div>
    </Card>
  })}</div>
}
