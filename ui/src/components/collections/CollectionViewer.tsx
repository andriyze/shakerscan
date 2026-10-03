'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { Braces, Link2, Lock, Search, SlidersHorizontal, X } from 'lucide-react'
import Link from '@/components/WorkspaceLink'
import { Button, Modal, Select, Tabs, useToast } from '@/components/ui'
import {
  getRequestCollection, listRequestCollectionInventory, upsertRequestCollectionBinding,
  type RequestCollectionDetail, type RequestCollectionInventoryItem,
} from '@/lib/requestCollectionApi'
import { boundApis, filterRequests, methodCounts, originOf, type CollectionApi } from '@/lib/collectionViewModel.mjs'

const PAGE = 200
const METHOD_STYLE: Record<string, string> = {
  GET: 'text-emerald-300 bg-emerald-500/10', HEAD: 'text-emerald-300 bg-emerald-500/10', OPTIONS: 'text-emerald-300 bg-emerald-500/10',
  POST: 'text-amber-300 bg-amber-500/10', PUT: 'text-orange-300 bg-orange-500/10', PATCH: 'text-orange-300 bg-orange-500/10',
  DELETE: 'text-red-300 bg-red-500/10',
}

export function MethodBadge({ method }: { method: string }) {
  const value = String(method || 'GET').toUpperCase()
  return <span className={`inline-flex w-16 shrink-0 justify-center rounded-md px-1.5 py-0.5 font-mono text-[11px] font-semibold ${METHOD_STYLE[value] || 'bg-gray-800 text-gray-300'}`}>{value}</span>
}

/** Manager deep link with the owner and this collection preselected. */
export function collectionManagerHref(detail: { id: string; target_id?: string | null }) {
  const params = new URLSearchParams({ collection: detail.id })
  if (detail.target_id) params.set('target_id', detail.target_id)
  return `/request-collections?${params}`
}

/**
 * Read a collection's requests, which of an asset's APIs it is bound to, and its named selections,
 * and bind it to one more API without leaving the page. Documents stay encrypted: the inventory is
 * the server's redacted index.
 */
export function CollectionViewer({ collectionId, apis = [], onClose, onChanged }: {
  collectionId: string | null
  /** The asset's host and application origins, for the per-API view. */
  apis?: CollectionApi[]
  onClose: () => void
  onChanged?: () => void
}) {
  const toast = useToast()
  const [detail, setDetail] = useState<RequestCollectionDetail | null>(null)
  const [requests, setRequests] = useState<RequestCollectionInventoryItem[]>([])
  const [total, setTotal] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [loadingMore, setLoadingMore] = useState(false)
  const [tab, setTab] = useState('requests')
  const [query, setQuery] = useState('')
  const [method, setMethod] = useState('')
  const [bindAs, setBindAs] = useState<'web' | 'api'>('web')
  const [binding, setBinding] = useState<string | null>(null)

  const load = useCallback(async (id: string) => {
    setError(null)
    try {
      const [next, inventory] = await Promise.all([getRequestCollection(id), listRequestCollectionInventory(id, { limit: PAGE, offset: 0 })])
      setDetail(next)
      setRequests(inventory.requests || [])
      setTotal(inventory.total || 0)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not load this collection')
    }
  }, [])

  useEffect(() => {
    setDetail(null); setRequests([]); setTotal(0); setQuery(''); setMethod(''); setTab('requests')
    if (collectionId) void load(collectionId)
  }, [collectionId, load])

  async function loadMore() {
    if (!collectionId) return
    setLoadingMore(true)
    try {
      const page = await listRequestCollectionInventory(collectionId, { limit: PAGE, offset: requests.length })
      setRequests(current => [...current, ...(page.requests || [])])
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Could not load more requests')
    } finally { setLoadingMore(false) }
  }

  async function bind(api: CollectionApi) {
    if (!detail) return
    setBinding(api.id)
    try {
      // One application origin: the binding admits exactly that scheme, host and port.
      await upsertRequestCollectionBinding(detail.collection.id, {
        target_kind: bindAs, target_id: api.id, allowed_origins: [originOf(api.url)],
      })
      toast.success(`${detail.collection.name} is now bound to ${api.label}`)
      await load(detail.collection.id)
      onChanged?.()
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Could not bind the collection')
    } finally { setBinding(null) }
  }

  const visible = useMemo(() => filterRequests(requests, { query, method }), [requests, query, method])
  const methods = useMemo(() => methodCounts(requests), [requests])
  const perApi = useMemo(() => boundApis(detail?.bindings || [], apis), [detail, apis])
  const otherBindings = (detail?.bindings || []).filter(item => item.is_active && !apis.some(api => api.id === item.target_id))
  const selections = (detail?.selections || []).filter(item => item.is_active)
  const collection = detail?.collection

  return <Modal open={collectionId !== null} title={collection?.name || 'Request collection'} size="xl" onClose={onClose}
    footer={collection ? <div className="flex w-full flex-wrap items-center justify-between gap-3">
      <span className="flex items-center gap-1.5 text-xs text-emerald-300/90"><Lock className="h-3.5 w-3.5" aria-hidden="true" />Encrypted document · digest {collection.payload_sha256.slice(0, 12)}</span>
      <div className="flex gap-2">
        <Link href={collectionManagerHref(collection)} className="inline-flex items-center gap-1.5 rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-200 hover:bg-gray-800">
          <SlidersHorizontal className="h-4 w-4" aria-hidden="true" />Selections &amp; environments
        </Link>
        <Button onClick={onClose}>Done</Button>
      </div>
    </div> : undefined}>
    {error ? <p role="alert" className="text-sm text-red-300">{error}</p> : !collection ? <p role="status" className="py-10 text-center text-sm text-gray-400">Loading collection…</p> : <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-xs text-gray-400">
        <span className="inline-flex items-center gap-1.5 rounded-md bg-gray-800 px-2 py-1"><Braces className="h-3.5 w-3.5" aria-hidden="true" />{collection.format}</span>
        <span className="rounded-md bg-gray-800 px-2 py-1">{collection.request_count} requests</span>
        <span className="rounded-md bg-emerald-500/10 px-2 py-1 text-emerald-300">{collection.safe_request_count} safe</span>
        {collection.potentially_mutating_request_count > 0 && <span className="rounded-md bg-amber-500/10 px-2 py-1 text-amber-300">{collection.potentially_mutating_request_count} may change state</span>}
        <span className="rounded-md bg-gray-800 px-2 py-1">{selections.length} selection{selections.length === 1 ? '' : 's'}</span>
      </div>
      <Tabs ariaLabel="Collection views" active={tab} onChange={setTab} items={[
        { key: 'requests', label: 'Requests', badge: total },
        { key: 'apis', label: 'APIs', badge: (detail?.bindings || []).filter(item => item.is_active).length },
        { key: 'selections', label: 'Selections', badge: selections.length },
      ]} />

      {tab === 'requests' && <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-56 flex-1">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-gray-500" aria-hidden="true" />
            <input aria-label="Search requests" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search name, path, folder or tag…"
              className="h-9 w-full rounded-lg border border-gray-700 bg-gray-800 pl-9 pr-8 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-hidden" />
            {query && <button type="button" aria-label="Clear request search" onClick={() => setQuery('')} className="absolute right-2 top-2 text-gray-500 hover:text-gray-200"><X className="h-4 w-4" /></button>}
          </div>
          <div role="group" aria-label="Filter by method" className="flex flex-wrap gap-1">
            <button type="button" aria-pressed={!method} onClick={() => setMethod('')} className={`rounded-md px-2 py-1 text-xs ${!method ? 'bg-blue-500/15 text-blue-200' : 'text-gray-400 hover:bg-gray-800'}`}>All</button>
            {methods.map(item => <button key={item.method} type="button" aria-pressed={method === item.method} onClick={() => setMethod(method === item.method ? '' : item.method)}
              className={`rounded-md px-2 py-1 font-mono text-xs ${method === item.method ? 'bg-blue-500/15 text-blue-200' : 'text-gray-400 hover:bg-gray-800'}`}>{item.method} {item.count}</button>)}
          </div>
        </div>
        <div className="max-h-[50vh] overflow-y-auto rounded-xl border border-gray-800">
          {!visible.length ? <p className="p-6 text-center text-sm text-gray-500">{requests.length ? 'No requests match' : 'This collection has no indexed requests'}</p>
            : <ul className="divide-y divide-gray-800/70" aria-label="Requests">
              {visible.map(item => <li key={item.request_id} className="flex items-start gap-3 px-3 py-2.5">
                <MethodBadge method={item.method} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm text-gray-100">{item.name || item.normalized_path || item.redacted_url}</span>
                  <span className="block truncate font-mono text-xs text-gray-500">{item.normalized_path || item.redacted_url}</span>
                </span>
                <span className="flex shrink-0 flex-wrap justify-end gap-1 text-[11px]">
                  {item.folder && <span className="rounded bg-gray-800 px-1.5 py-0.5 text-gray-400">{item.folder}</span>}
                  {item.auth_type && <span className="rounded bg-blue-500/10 px-1.5 py-0.5 text-blue-300">auth: {item.auth_type}</span>}
                  {!item.safe_method && <span className="rounded bg-amber-500/10 px-1.5 py-0.5 text-amber-300">changes state</span>}
                  {!item.supported && <span className="rounded bg-gray-800 px-1.5 py-0.5 text-gray-500">not replayable</span>}
                </span>
              </li>)}
            </ul>}
        </div>
        <div className="flex items-center justify-between text-xs text-gray-500">
          <span>{visible.length} shown · {requests.length} of {total} loaded</span>
          {requests.length < total && <Button size="sm" variant="secondary" loading={loadingMore} onClick={() => void loadMore()}>Load more</Button>}
        </div>
      </div>}

      {tab === 'apis' && <div className="space-y-3">
        <p className="text-xs leading-5 text-gray-500">A collection replays only against the exact origins it is bound to. Bind it to each API that should use it.</p>
        {perApi.length > 0 && <div className="flex items-center gap-2 text-xs text-gray-400">
          New application bindings use the collection as
          <Select fullWidth={false} aria-label="Bind application origins as" value={bindAs} onChange={event => setBindAs(event.target.value as 'web' | 'api')} className="h-8 py-1 text-xs">
            <option value="web">Web application</option><option value="api">API</option>
          </Select>
        </div>}
        <ul className="divide-y divide-gray-800/70 rounded-xl border border-gray-800" aria-label="APIs of this target">
          {perApi.map(api => <li key={api.id} className="flex flex-wrap items-center gap-3 px-3 py-2.5">
            <Link2 className={`h-4 w-4 shrink-0 ${api.bound ? 'text-emerald-300' : 'text-gray-600'}`} aria-hidden="true" />
            <span className="min-w-0 flex-1">
              <span className="block truncate font-mono text-sm text-gray-100">{api.label}</span>
              <span className="text-xs text-gray-500">{api.kind === 'host' ? 'Host' : 'Application origin'}{api.binding ? ` · ${api.binding.target_kind} · ${api.binding.allowed_origins.join(', ')}${api.binding.environment_id ? ' · environment attached' : ''}` : ''}</span>
            </span>
            {api.bound ? <span className="rounded-md bg-emerald-500/10 px-2 py-1 text-xs text-emerald-300">Bound</span>
              : api.kind === 'host'
                // A host binding names its origins explicitly; the manager collects them.
                ? <Link href={collectionManagerHref(collection!)} className="text-xs text-blue-300 hover:text-blue-200">Bind host…</Link>
                : <Button size="sm" variant="secondary" loading={binding === api.id} onClick={() => void bind(api)} aria-label={`Bind to ${api.label}`}>Bind</Button>}
          </li>)}
          {otherBindings.map(item => <li key={item.id} className="flex items-center gap-3 px-3 py-2.5">
            <Link2 className="h-4 w-4 shrink-0 text-emerald-300" aria-hidden="true" />
            <span className="min-w-0 flex-1"><span className="block truncate font-mono text-sm text-gray-100">{item.allowed_origins.join(', ')}</span>
              <span className="text-xs text-gray-500">{item.target_kind} binding{apis.length ? ' on another target' : ''}</span></span>
            <span className="rounded-md bg-emerald-500/10 px-2 py-1 text-xs text-emerald-300">Bound</span>
          </li>)}
          {!perApi.length && !otherBindings.length && <li className="p-6 text-center text-sm text-gray-500">Not bound to any API yet. Open its owner&apos;s target to bind it.</li>}
        </ul>
      </div>}

      {tab === 'selections' && <div className="space-y-3">
        <p className="text-xs leading-5 text-gray-500">A selection is an immutable subset of requests attached to Scan or Hunt by ID.</p>
        {selections.length ? <ul className="divide-y divide-gray-800/70 rounded-xl border border-gray-800" aria-label="Selections">
          {selections.map(item => <li key={item.id} className="flex flex-wrap items-center gap-3 px-3 py-2.5">
            <span className="min-w-0 flex-1"><span className="block truncate text-sm text-gray-100">{item.name}</span>
              <span className="font-mono text-xs text-gray-500">digest {item.selection_digest.slice(0, 12)}</span></span>
            <span className="text-xs text-gray-400">{item.selected_request_count} requests{item.selected_mutating_count ? ` · ${item.selected_mutating_count} change state` : ''}</span>
            <span className="rounded-md bg-gray-800 px-2 py-1 text-xs text-gray-300">{item.replay_policy.replaceAll('_', ' ')}</span>
          </li>)}
        </ul> : <p className="rounded-xl border border-gray-800 p-6 text-center text-sm text-gray-500">No selections yet. Create one from Selections &amp; environments.</p>}
      </div>}
    </div>}
  </Modal>
}
