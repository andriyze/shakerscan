'use client'

import { useEffect, useState, type ReactNode } from 'react'
import { Link2 } from 'lucide-react'
import {
  Button, EmptyState, ErrorState, ROW_ACTION_REVEAL, SearchInput, Skeleton, Table, TableCell, TableContainer, TableHead, TableHeaderCell, TableRow, Toolbar,
} from '@/components/ui'
import { listRequestCollectionLibrary, type LibraryRequestCollection } from '@/lib/requestCollectionApi'
import { relativeTime } from '@/lib/targetInventoryModel.mjs'
import { CollectionViewer } from './CollectionViewer'

const PAGE = 50

/**
 * Every request collection, searchable by name, format or owner, before choosing an owner.
 * `toolbar` holds the page's scope controls, so they share one row with this list's search.
 */
export function CollectionLibrary({ onManage, toolbar }: {
  onManage: (collection: LibraryRequestCollection) => void
  toolbar?: ReactNode
}) {
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

  return <>
    <Toolbar>
      {toolbar}
      <SearchInput aria-label="Search all collections" value={query} onValueChange={setQuery}
        placeholder="Search by name, format or owner target…" wrapperClassName="min-w-60 flex-1" />
      {!loading && <span className="whitespace-nowrap text-xs tabular-nums text-gray-500">{total} collection{total === 1 ? '' : 's'}</span>}
    </Toolbar>
    {error ? <ErrorState message={error} />
      : loading && !rows.length ? <div className="space-y-2">{Array.from({ length: 4 }, (_, index) => <Skeleton key={index} className="h-12 w-full rounded-lg" />)}</div>
      : !rows.length ? <EmptyState message={debounced ? 'No collections match' : 'No request collections yet'}
          hint={debounced ? 'Try a collection name, a format such as openapi, or the owner target.' : 'Choose a target above, then upload a Postman, HAR, OpenAPI or Swagger document.'} />
      : <TableContainer className={loading ? 'opacity-60' : ''}>
        <Table aria-label="All request collections">
          <TableHead>
            <tr>
              <TableHeaderCell>Collection</TableHeaderCell>
              <TableHeaderCell>Owner</TableHeaderCell>
              <TableHeaderCell className="text-right">Requests</TableHeaderCell>
              <TableHeaderCell>Bound APIs</TableHeaderCell>
              <TableHeaderCell>Updated</TableHeaderCell>
              <TableHeaderCell><span className="sr-only">Actions</span></TableHeaderCell>
            </tr>
          </TableHead>
          <tbody>
            {rows.map(row => <TableRow key={row.id}>
              <TableCell className="max-w-md">
                <button type="button" onClick={() => setViewing(row.id)} aria-label={`View ${row.name}`}
                  className="block max-w-full truncate text-left font-medium text-gray-100 hover:text-blue-300">{row.name}</button>
                <span className="text-xs text-gray-500">{row.format.replaceAll('_', ' ')}{row.selection_count ? ` · ${row.selection_count} selection${row.selection_count === 1 ? '' : 's'}` : ''}</span>
              </TableCell>
              <TableCell className="max-w-xs">
                <span className="block truncate text-gray-300">{row.owner_name || row.owner_locator || 'Unknown owner'}</span>
                {row.owner_locator && <span className="block truncate font-mono text-xs text-gray-500">{row.owner_locator}</span>}
              </TableCell>
              <TableCell className="whitespace-nowrap text-right tabular-nums">
                {row.request_count}
                {row.potentially_mutating_request_count ? <span className="block text-xs text-amber-300/80">{row.potentially_mutating_request_count} mutating</span> : null}
              </TableCell>
              <TableCell className="whitespace-nowrap">
                <span className={`inline-flex items-center gap-1 text-xs tabular-nums ${row.binding_count ? 'text-gray-300' : 'text-amber-300/80'}`}>
                  <Link2 className="h-3.5 w-3.5 text-gray-500" aria-hidden="true" />{row.binding_count || 'none'}
                </span>
              </TableCell>
              <TableCell className="whitespace-nowrap text-xs text-gray-400">
                <span title={new Date(row.updated_at).toLocaleString()}>{relativeTime(row.updated_at)}</span>
              </TableCell>
              <TableCell className="text-right">
                <Button size="sm" variant="secondary" className={ROW_ACTION_REVEAL} onClick={() => onManage(row)}>Manage</Button>
              </TableCell>
            </TableRow>)}
          </tbody>
        </Table>
        {total > PAGE && <div className="flex items-center justify-between border-t border-gray-800 px-4 py-3 text-xs text-gray-500">
          <Button size="sm" variant="secondary" disabled={offset === 0 || loading} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</Button>
          <span className="tabular-nums">{offset + 1}–{Math.min(total, offset + rows.length)} of {total}</span>
          <Button size="sm" variant="secondary" disabled={offset + PAGE >= total || loading} onClick={() => setOffset(offset + PAGE)}>Next</Button>
        </div>}
      </TableContainer>}
    <CollectionViewer collectionId={viewing} onClose={() => setViewing(null)} />
  </>
}
