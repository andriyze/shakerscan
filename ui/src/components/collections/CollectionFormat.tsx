import { captureSummary, formatLabel } from '@/lib/collectionViewModel.mjs'
import type { SharedRequestCollection } from '@/lib/requestCollectionApi'

/** A collection's format chip; a browser capture also shows whether it is still recording. */
export function CollectionFormat({ collection, counts = false }: {
  collection: Pick<SharedRequestCollection, 'format' | 'capture' | 'request_count'>
  counts?: boolean
}) {
  const capture = captureSummary(collection)
  return <>
    <span className="rounded bg-gray-800 px-1.5 py-0.5">{formatLabel(collection)}</span>
    {capture && <span className={`rounded px-1.5 py-0.5 ${capture.open ? 'bg-emerald-500/10 text-emerald-300' : 'bg-gray-800 text-gray-400'}`}>{capture.state}</span>}
    {capture && counts && <span>{capture.counts}</span>}
  </>
}
