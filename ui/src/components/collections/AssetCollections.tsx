'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { Braces, Eye, Link2, Plus, Search, X } from 'lucide-react'
import Link from '@/components/WorkspaceLink'
import { Button, Card } from '@/components/ui'
import { getRequestCollection, type RequestCollectionDetail } from '@/lib/requestCollectionApi'
import type { AssetDetail, AssetOrigin } from '@/lib/targetAssetApi'
import type { CollectionApi } from '@/lib/collectionViewModel.mjs'
import { CollectionViewer, collectionManagerHref } from './CollectionViewer'

type Summary = AssetDetail['request_collections'][number]

/**
 * A target's request collections, per API: which application origins each collection is bound to,
 * filterable by API, with the requests one click away. Documents stay encrypted; only the
 * redacted index and binding metadata are shown.
 */
export function AssetCollections({ assetId, assetLocator, origins, collections, onChanged }: {
  assetId: string
  assetLocator: string
  origins: AssetOrigin[]
  collections: Summary[]
  onChanged: () => void
}) {
  const [details, setDetails] = useState<Record<string, RequestCollectionDetail>>({})
  const [query, setQuery] = useState('')
  const [api, setApi] = useState<string>('')
  const [viewing, setViewing] = useState<string | null>(null)
  const [version, setVersion] = useState(0)

  const apis = useMemo<CollectionApi[]>(() => [
    { id: assetId, url: `host://${assetLocator}`, label: assetLocator, kind: 'host' },
    ...origins.filter(origin => origin.is_active && origin.current_membership)
      .map(origin => ({ id: origin.id, url: origin.url, label: origin.url, kind: 'origin' as const })),
  ], [assetId, assetLocator, origins])

  const active = useMemo(() => collections.filter(item => item.is_active), [collections])
  useEffect(() => {
    let cancelled = false
    // Bindings live on each collection; small asset inventories load them together.
    void Promise.all(active.map(item => getRequestCollection(item.id).then(detail => [item.id, detail] as const).catch(() => null)))
      .then(rows => { if (!cancelled) setDetails(Object.fromEntries(rows.filter((row): row is readonly [string, RequestCollectionDetail] => row !== null))) })
    return () => { cancelled = true }
  }, [active, version])

  const boundTo = useCallback((id: string) => {
    const bindings = (details[id]?.bindings || []).filter(item => item.is_active)
    return apis.filter(item => bindings.some(binding => binding.target_id === item.id))
  }, [details, apis])

  const visible = active.filter(item => {
    const words = query.toLowerCase().split(/\s+/).filter(Boolean)
    const text = `${item.name} ${item.format}`.toLowerCase()
    if (!words.every(word => text.includes(word))) return false
    if (!api) return true
    if (api === 'unbound') return details[item.id] !== undefined && boundTo(item.id).length === 0
    return boundTo(item.id).some(entry => entry.id === api)
  })
  const counts = (id: string) => active.filter(item => boundTo(item.id).some(entry => entry.id === id)).length

  return <Card className="p-0">
    <div className="flex flex-wrap items-center gap-3 border-b border-gray-800 p-4">
      <h3 className="flex items-center gap-2 font-medium text-white"><Braces className="h-4 w-4 text-blue-300" aria-hidden="true" />Request collections
        <span className="rounded-full bg-gray-800 px-2 py-0.5 text-xs text-gray-400">{active.length}</span></h3>
      <div className="relative ml-auto min-w-48 flex-1 sm:max-w-xs">
        <Search className="pointer-events-none absolute left-3 top-2 h-4 w-4 text-gray-500" aria-hidden="true" />
        <input aria-label="Search collections" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search collections…"
          className="h-8 w-full rounded-lg border border-gray-700 bg-gray-800 pl-9 pr-7 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-hidden" />
        {query && <button type="button" aria-label="Clear collection search" onClick={() => setQuery('')} className="absolute right-2 top-2 text-gray-500 hover:text-gray-200"><X className="h-4 w-4" /></button>}
      </div>
      <Link href={`/request-collections?${new URLSearchParams({ target_id: assetId, upload: '1' })}`}
        className="inline-flex items-center gap-1.5 rounded-lg border border-gray-700 px-2.5 py-1.5 text-sm text-gray-200 hover:bg-gray-800"><Plus className="h-4 w-4" aria-hidden="true" />Upload</Link>
      <Link href={`/request-collections?${new URLSearchParams({ target_id: assetId })}`} className="text-sm text-blue-300 hover:text-blue-200">Manage</Link>
    </div>
    {active.length > 0 && apis.length > 1 && <div role="group" aria-label="Filter by API" className="flex flex-wrap gap-1.5 border-b border-gray-800 px-4 py-2.5">
      {[{ id: '', label: 'All APIs', count: active.length }, ...apis.filter(item => item.kind === 'origin').map(item => ({ id: item.id, label: item.label, count: counts(item.id) })),
        { id: 'unbound', label: 'Not bound', count: active.filter(item => details[item.id] && !boundTo(item.id).length).length }].map(item =>
        <button key={item.id || 'all'} type="button" aria-pressed={api === item.id} onClick={() => setApi(api === item.id && item.id ? '' : item.id)}
          className={`inline-flex max-w-full items-center gap-1.5 rounded-lg px-2.5 py-1 text-xs ${api === item.id ? 'bg-blue-500/15 text-blue-200 ring-1 ring-inset ring-blue-400/30' : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'}`}>
          <span className={`truncate ${item.id && item.id !== 'unbound' ? 'font-mono' : ''}`}>{item.label}</span><span className="text-gray-500">{item.count}</span>
        </button>)}
    </div>}
    {!active.length ? <p className="p-6 text-sm text-gray-500">No request collections. Upload a Postman, HAR, OpenAPI or Swagger document once, then bind it to each API that should replay it.</p>
      : !visible.length ? <p className="p-6 text-sm text-gray-500">No collections match.</p>
      : <ul className="divide-y divide-gray-800/70" aria-label="Request collections">
        {visible.map(item => {
          const detail = details[item.id]
          const bound = boundTo(item.id)
          const selections = (detail?.selections || []).filter(selection => selection.is_active).length
          return <li key={item.id} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
            <span className="min-w-0 flex-1 basis-64">
              <button type="button" onClick={() => setViewing(item.id)} className="block max-w-full truncate text-left text-sm font-medium text-gray-100 hover:text-blue-300">{item.name}</button>
              <code className="block select-all truncate font-mono text-[11px] text-gray-600" title="Opaque reference used by Scan and Hunt requests">{item.id}</code>
              <span className="mt-1 flex flex-wrap items-center gap-1.5 text-[11px] text-gray-500">
                <span className="rounded bg-gray-800 px-1.5 py-0.5">{item.format}</span>
                <span>{item.request_count} request{item.request_count === 1 ? '' : 's'}</span>
                {item.potentially_mutating_request_count > 0 && <span className="text-amber-300/80">· {item.potentially_mutating_request_count} may change state</span>}
                {detail && <span>· {selections} selection{selections === 1 ? '' : 's'}</span>}
                {item.home_target_id !== assetId && <span className="text-violet-300">· from a service of this target</span>}
              </span>
            </span>
            <span className="flex min-w-0 flex-wrap items-center gap-1.5">
              {!detail ? <span className="text-xs text-gray-600">Loading APIs…</span>
                : bound.length ? bound.map(entry => <span key={entry.id} title={entry.label} className="inline-flex max-w-64 items-center gap-1 rounded-md bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[11px] text-emerald-300">
                    <Link2 className="h-3 w-3 shrink-0" aria-hidden="true" /><span className="truncate">{entry.label.replace(/^https?:\/\//, '')}</span></span>)
                : <span className="text-xs text-amber-300/80">Not bound to an API</span>}
            </span>
            <span className="flex shrink-0 items-center gap-2">
              <Button size="sm" variant="secondary" onClick={() => setViewing(item.id)} aria-label={`View ${item.name}`}><Eye className="h-3.5 w-3.5" aria-hidden="true" />View</Button>
              <Link href={collectionManagerHref({ id: item.id, target_id: item.home_target_id })} className="text-xs text-blue-300 hover:text-blue-200">Manage</Link>
            </span>
          </li>
        })}
      </ul>}
    <CollectionViewer collectionId={viewing} apis={apis} onClose={() => setViewing(null)} onChanged={() => { setVersion(value => value + 1); onChanged() }} />
  </Card>
}
