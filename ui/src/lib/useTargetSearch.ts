'use client'

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { isAbortError } from './fetchLayer.mjs'
import { getTargetAsset, searchTargetAssets, type TargetAsset } from './targetAssetApi'
import { collectAcceptedTargets } from './targetSearchModel.mjs'

export const TARGET_SEARCH_DEBOUNCE_MS = 250
export const TARGET_SEARCH_LIMIT = 25

export interface TargetSearch {
  /** The current matches plus every selected asset, in that order, without duplicates. */
  assets: TargetAsset[]
  /** Every asset this picker has seen (matches and resolved selections), by id. */
  byId: (id: string) => TargetAsset | undefined
  query: string
  setQuery: (query: string) => void
  /** The (trimmed) query the current matches answer; differs from `query` while a search is due. */
  answeredQuery: string | null
  /** A search is due or in flight: the matches may belong to an older query. */
  loading: boolean
  error: string | null
  /** More assets match than were returned: say so and ask for a narrower search. */
  hasMore: boolean
  /** Inventory rows read for the current answer (more than `assets` when `accept` filtered). */
  scanned: number
  /** Whether an `accept` filter narrowed the rows read. */
  filtered: boolean
  /** True once the first page answered (an empty inventory is then really empty). */
  ready: boolean
  /** Add an asset the page already holds (just created, read from a link) to the known set. */
  remember: (asset: TargetAsset) => void
}

/**
 * A server-side target typeahead. Each keystroke (debounced) asks the inventory for one bounded
 * page matching the text, instead of loading every target into the browser. Selected ids that are
 * not among the matches are read individually so the picker can still show them.
 */
export function useTargetSearch({
  selectedIds = [], includeServices = false, includeInactive = false, enabled = true,
  limit = TARGET_SEARCH_LIMIT, accept, webOnly = false,
}: {
  selectedIds?: ReadonlyArray<string | null | undefined>
  includeServices?: boolean
  includeInactive?: boolean
  enabled?: boolean
  limit?: number
  /** Narrow the matches the picker offers (active web targets only, ...). */
  accept?: (asset: TargetAsset) => boolean
  /** Ask the server for active http(s) web targets only, so `accept` rarely rejects a row. */
  webOnly?: boolean
} = {}): TargetSearch {
  const [query, setQuery] = useState('')
  const [debounced, setDebounced] = useState('')
  const [matches, setMatches] = useState<TargetAsset[]>([])
  const [hasMore, setHasMore] = useState(false)
  const [scanned, setScanned] = useState(0)
  const [answeredQuery, setAnsweredQuery] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [ready, setReady] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // The query whose search failed: answered (with an error), so not "due", but any other text is.
  const [failedQuery, setFailedQuery] = useState<string | null>(null)
  const [known, setKnown] = useState<Map<string, TargetAsset>>(() => new Map())
  const knownRef = useRef(known)
  knownRef.current = known
  const acceptRef = useRef(accept)
  acceptRef.current = accept

  const remember = useCallback((asset: TargetAsset) => {
    setKnown((current) => {
      if (current.get(asset.id) === asset) return current
      const next = new Map(current)
      next.set(asset.id, asset)
      return next
    })
  }, [])

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(query.trim()), TARGET_SEARCH_DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [query])

  useEffect(() => {
    if (!enabled) {
      setLoading(false)
      return
    }
    const controller = new AbortController()
    setLoading(true)
    // A filter the inventory cannot express runs here, reading on (bounded) while it rejects
    // rows, so a page of rejected rows never reads as "no targets".
    collectAcceptedTargets({
      fetchPage: (position: string | number | null) => searchTargetAssets(
        { search: debounced, limit, includeServices, includeInactive, webOnly, position }, controller.signal),
      accept: acceptRef.current,
      limit,
    })
      .then((result) => {
        if (controller.signal.aborted) return
        setMatches(result.matches)
        setHasMore(result.hasMore)
        setScanned(result.scanned)
        setAnsweredQuery(debounced)
        setFailedQuery(null)
        setError(null)
        setReady(true)
        setKnown((current) => {
          const next = new Map(current)
          for (const asset of result.matches) next.set(asset.id, asset)
          return next
        })
      })
      .catch((cause) => {
        if (isAbortError(cause) || controller.signal.aborted) return
        setError(cause instanceof Error ? cause.message : 'Target search failed')
        // The previous matches answer an older query: offer none rather than let Enter pick one.
        setMatches([])
        setHasMore(false)
        setFailedQuery(debounced)
        setReady(true)
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => {
      controller.abort()
      // Disabled (or superseded) mid-request: nothing is in flight for this hook any more; the
      // next run, if any, sets it again.
      setLoading(false)
    }
  }, [debounced, enabled, includeInactive, includeServices, limit, webOnly])

  // A selection the current matches do not hold (a link, a saved choice): read just that asset.
  const missing = useMemo(
    () => [...new Set(selectedIds.filter((id): id is string => Boolean(id) && !known.has(id as string)))],
    [known, selectedIds],
  )
  const missingKey = missing.join(',')
  useEffect(() => {
    if (!enabled || !missing.length) return
    const controller = new AbortController()
    for (const id of missing) {
      getTargetAsset(id, controller.signal)
        .then((detail) => {
          // The id may name one of the asset's web origins rather than the asset itself.
          const origin = detail.origins?.find((item) => item.id === id)
          const exact: TargetAsset = origin
            ? { ...detail.target, ...origin, id: origin.id, asset_id: detail.target.id, locator: origin.url }
            : detail.target
          if (!knownRef.current.has(exact.id)) remember(exact)
        })
        .catch(() => undefined)
    }
    return () => controller.abort()
    // missingKey stands for `missing`.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, missingKey, remember])

  const assets = useMemo(() => {
    const seen = new Set<string>()
    const list: TargetAsset[] = []
    for (const asset of matches) if (!seen.has(asset.id)) { seen.add(asset.id); list.push(asset) }
    for (const id of selectedIds) {
      const asset = id ? known.get(id) : undefined
      if (asset && !seen.has(asset.id)) { seen.add(asset.id); list.push(asset) }
    }
    return list
  }, [known, matches, selectedIds])

  const byId = useCallback((id: string) => known.get(id), [known])
  // Typed but not yet answered (debounce pending or the request in flight) counts as loading, so
  // a picker never acts on results that belong to an older query -- also after a failed search:
  // only the exact text that failed counts as answered (with its error).
  const typed = query.trim()
  const due = enabled && typed !== (answeredQuery ?? '') && typed !== failedQuery
  return {
    assets, byId, query, setQuery, answeredQuery, loading: enabled && (loading || due), error, hasMore,
    scanned, filtered: Boolean(accept), ready, remember,
  }
}
