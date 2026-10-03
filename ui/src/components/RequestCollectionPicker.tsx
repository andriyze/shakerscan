'use client'

import Link from '@/components/WorkspaceLink'
import { useEffect, useMemo, useState } from 'react'
import { Search } from 'lucide-react'
import { CollectionViewer } from '@/components/collections/CollectionViewer'
import {
  getRequestCollection,
  listRequestCollections,
  type RequestCollectionDetail,
  type RequestCollectionReplayPolicy,
  type RequestCollectionTargetKind,
} from '@/lib/requestCollectionApi'

export type RequestCollectionSelectionMetadata = Record<string, {
  replayPolicy: RequestCollectionReplayPolicy
  name: string
}>

type Props = {
  targetId?: string
  targetKind: RequestCollectionTargetKind
  selectedIds: string[]
  onChange: (selectionIds: string[]) => void
  onMetadataChange?: (metadata: RequestCollectionSelectionMetadata) => void
  allowConfirmedActive?: boolean
  disabled?: boolean
}

export function RequestCollectionPicker({
  targetId,
  targetKind,
  selectedIds,
  onChange,
  onMetadataChange,
  allowConfirmedActive = false,
  disabled = false,
}: Props) {
  const [details, setDetails] = useState<RequestCollectionDetail[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [viewing, setViewing] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    onChange([])
    onMetadataChange?.({})
    setDetails([])
    setError(null)
    if (!targetId) return () => { cancelled = true }
    setLoading(true)
    listRequestCollections(targetId)
      .then(({ collections }) => Promise.all(
        collections.map((collection) => getRequestCollection(collection.id)),
      ))
      .then((rows) => { if (!cancelled) setDetails(rows) })
      .catch((cause) => {
        if (!cancelled) {
          setError(cause instanceof Error ? cause.message : 'Failed to load request selections')
        }
      })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  // Reset selected IDs whenever the exact target authority changes.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targetId, targetKind])

  const choices = useMemo(() => details.flatMap((detail) => {
    const bindingIds = new Set(detail.bindings.filter((binding) => (
      binding.target_kind === targetKind && binding.target_id === targetId
    )).map((binding) => binding.id))
    return detail.selections
      .filter((selection) => bindingIds.has(selection.binding_id))
      .map((selection) => ({ collection: detail.collection, selection }))
  }), [details, targetId, targetKind])

  useEffect(() => {
    onMetadataChange?.(Object.fromEntries(choices.map(({ collection, selection }) => [
      selection.id,
      {
        replayPolicy: selection.replay_policy,
        name: `${collection.name} · ${selection.name}`,
      },
    ])))
  }, [choices, onMetadataChange])

  const words = query.toLowerCase().split(/\s+/).filter(Boolean)
  const shown = choices.filter(({ collection, selection }) => {
    const text = `${collection.name} ${selection.name} ${selection.replay_policy}`.toLowerCase()
    return words.every((word) => text.includes(word)) || selectedIds.includes(selection.id)
  })

  function toggle(selectionId: string, checked: boolean) {
    const next = checked
      ? Array.from(new Set([...selectedIds, selectionId]))
      : selectedIds.filter((value) => value !== selectionId)
    onChange(next)
  }

  return (
    <div className="space-y-3 rounded-lg border border-gray-800 bg-gray-950 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-medium text-white">Request collection selections</h3>
          <p className="mt-1 text-xs text-gray-500">
            Attach saved, exact-origin selections. Only opaque selection IDs enter the job.
          </p>
        </div>
        <Link href="/request-collections" className="text-xs text-blue-300 hover:text-blue-200">
          Manage collections
        </Link>
      </div>
      {!targetId ? (
        <p className="text-xs text-gray-500">Choose an existing target before attaching collections.</p>
      ) : loading ? (
        <p className="text-xs text-gray-500">Loading saved selections…</p>
      ) : error ? (
        <p className="text-xs text-amber-300">{error}</p>
      ) : choices.length === 0 ? (
        <p className="text-xs text-gray-500">
          No saved selections are bound to this target and target kind.
        </p>
      ) : (
        <div className="space-y-2">
          {choices.length > 4 && (
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-gray-500" aria-hidden="true" />
              <input aria-label="Search request selections" value={query} onChange={(event) => setQuery(event.target.value)}
                placeholder={`Search ${choices.length} selections…`}
                className="h-9 w-full rounded-lg border border-gray-700 bg-gray-900 pl-9 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-hidden" />
            </div>
          )}
          {!shown.length && <p className="text-xs text-gray-500">No selections match.</p>}
          {shown.map(({ collection, selection }) => {
            const activeUnavailable = (
              selection.replay_policy === 'confirmed_active' && !allowConfirmedActive
            )
            return (
              <label
                key={selection.id}
                className={`flex items-start gap-3 rounded border border-gray-800 p-3 text-sm ${
                  activeUnavailable ? 'text-gray-600' : 'text-gray-300'
                }`}
              >
                <input
                  className="mt-1"
                  type="checkbox"
                  checked={selectedIds.includes(selection.id)}
                  disabled={disabled || activeUnavailable}
                  onChange={(event) => toggle(selection.id, event.target.checked)}
                />
                <span className="min-w-0">
                  <span className="block font-medium text-white">
                    {collection.name} · {selection.name}
                  </span>
                  <span className="mt-1 block text-xs text-gray-500">
                    {selection.selected_request_count} requests · {selection.replay_policy.replaceAll('_', ' ')} · digest {selection.selection_digest.slice(0, 12)}
                    {' · '}
                    <button type="button" className="text-blue-300 hover:text-blue-200" onClick={(event) => { event.preventDefault(); setViewing(collection.id) }}>
                      View requests
                    </button>
                  </span>
                  {activeUnavailable && (
                    <span className="mt-1 block text-xs text-amber-400">
                      Enable active testing and state-changing HTTP to attach this selection.
                    </span>
                  )}
                </span>
              </label>
            )
          })}
        </div>
      )}
      <p className="text-xs text-gray-600">
        Collection documents and environment values remain encrypted and are resolved only by the worker.
      </p>
      <CollectionViewer collectionId={viewing} onClose={() => setViewing(null)} />
    </div>
  )
}
