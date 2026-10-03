'use client'

import { useEffect, useState } from 'react'
import { Braces, Eye, Link2, Search, X } from 'lucide-react'
import { Button, Card, EmptyState, ErrorState, Skeleton } from '@/components/ui'
import { listRequestCollectionLibrary, type LibraryRequestCollection } from '@/lib/requestCollectionApi'
import { relativeTime } from '@/lib/targetInventoryModel.mjs'
import { CollectionViewer } from './CollectionViewer'

const PAGE = 50

/** Every request collection, searchable by name, format or owner, before choosing an owner. */
export function CollectionLibrary({ onManage }: { onManage: (collection: LibraryRequestCollection) => void }) {
  const [query, setQuery] = useState('')
  const [debounced, setDebounced] = useState('')
  const [offset, setOffset] = useState(0)
  const [rows, setRows] = useState<LibraryRequestCollection[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [viewing, setViewing] = useState<string | null>(null)

  useEffect(() => {
    const timer = setTimeout(() => { setDebounced(query); setOffset(0) }, 250)
    return () => clearTimeout(timer)
  }, [query])
  useEffect(() => {
    let cancelled = false
    setLoading(true)
    listRequestCollectionLibrary({ search: debounced, limit: PAGE, offset })
      .then(result => { if (!cancelled) { setRows(result.collections || []); setTotal(result.total ?? result.count); setError(null) } })
      .catch(cause => { if (!cancelled) setError(cause instanceof Error ? cause.message : 'Could not load request collections') })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [debounced, offset])

  return <Card className="p-0">
    <div className="flex flex-wrap items-center gap-3 border-b border-gray-800 p-4">
      <h2 className="flex items-center gap-2 font-medium text-white"><Braces className="h-4 w-4 text-blue-300" aria-hidden="true" />All collections
        {!loading && <span className="rounded-full bg-gray-800 px-2 py-0.5 text-xs text-gray-400">{total}</span>}</h2>
      <div className="relative ml-auto min-w-56 flex-1 sm:max-w-md">
        <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-gray-500" aria-hidden="true" />
        <input aria-label="Search all collections" value={query} onChange={event => setQuery(event.target.value)}
          placeholder="Search by name, format or owner target…"
          className="h-9 w-full rounded-lg border border-gray-700 bg-gray-800 pl-9 pr-8 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-hidden" />
        {query && <button type="button" aria-label="Clear search" onClick={() => setQuery('')} className="absolute right-2 top-2.5 text-gray-500 hover:text-gray-200"><X className="h-4 w-4" /></button>}
      </div>
    </div>
    {error ? <div className="p-4"><ErrorState message={error} /></div>
      : loading && !rows.length ? <div className="space-y-2 p-4">{Array.from({ length: 4 }, (_, index) => <Skeleton key={index} className="h-12 w-full rounded-lg" />)}</div>
      : !rows.length ? <div className="p-4"><EmptyState message={debounced ? 'No collections match' : 'No request collections yet'}
          hint={debounced ? 'Try a collection name, a format such as openapi, or the owner target.' : 'Choose a target above, then upload a Postman, HAR, OpenAPI or Swagger document.'} /></div>
      : <div className={loading ? 'opacity-60' : ''}>
        <div className="hidden grid-cols-[minmax(0,2fr)_minmax(0,1.5fr)_7rem_6rem_11rem] gap-4 px-4 py-2 text-[11px] font-medium uppercase tracking-wider text-gray-500 lg:grid">
          <span>Collection</span><span>Owner</span><span>Requests</span><span>Bound APIs</span><span className="text-right">Updated</span>
        </div>
        <ul className="divide-y divide-gray-800/70" aria-label="All request collections">
          {rows.map(row => <li key={row.id} className="grid gap-x-4 gap-y-1 px-4 py-3 lg:grid-cols-[minmax(0,2fr)_minmax(0,1.5fr)_7rem_6rem_11rem] lg:items-center">
            <span className="min-w-0">
              <button type="button" onClick={() => setViewing(row.id)} className="block max-w-full truncate text-left text-sm font-medium text-gray-100 hover:text-blue-300">{row.name}</button>
              <span className="text-[11px] text-gray-500"><span className="rounded bg-gray-800 px-1.5 py-0.5">{row.format}</span>{row.selection_count ? ` · ${row.selection_count} selection${row.selection_count === 1 ? '' : 's'}` : ''}</span>
            </span>
            <span className="min-w-0 text-sm">
              <span className="block truncate text-gray-300">{row.owner_name || row.owner_locator || 'Unknown owner'}</span>
              {row.owner_locator && <span className="block truncate font-mono text-[11px] text-gray-500">{row.owner_locator}</span>}
            </span>
            <span className="text-xs text-gray-400">{row.request_count}{row.potentially_mutating_request_count ? <span className="text-amber-300/80"> · {row.potentially_mutating_request_count} mutating</span> : ''}</span>
            <span className={`inline-flex items-center gap-1 text-xs ${row.binding_count ? 'text-emerald-300' : 'text-amber-300/80'}`}><Link2 className="h-3.5 w-3.5" aria-hidden="true" />{row.binding_count || 'none'}</span>
            <span className="flex items-center justify-start gap-2 lg:justify-end">
              <span className="whitespace-nowrap text-xs text-gray-500" title={new Date(row.updated_at).toLocaleString()}>{relativeTime(row.updated_at)}</span>
              <Button size="sm" variant="ghost" aria-label={`View ${row.name}`} onClick={() => setViewing(row.id)}><Eye className="h-3.5 w-3.5" aria-hidden="true" /></Button>
              <Button size="sm" variant="secondary" onClick={() => onManage(row)}>Manage</Button>
            </span>
          </li>)}
        </ul>
        {total > PAGE && <div className="flex items-center justify-between border-t border-gray-800 px-4 py-3 text-xs text-gray-500">
          <Button size="sm" variant="secondary" disabled={offset === 0 || loading} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</Button>
          <span>{offset + 1}–{Math.min(total, offset + rows.length)} of {total}</span>
          <Button size="sm" variant="secondary" disabled={offset + PAGE >= total || loading} onClick={() => setOffset(offset + PAGE)}>Next</Button>
        </div>}
      </div>}
    <CollectionViewer collectionId={viewing} onClose={() => setViewing(null)} />
  </Card>
}
