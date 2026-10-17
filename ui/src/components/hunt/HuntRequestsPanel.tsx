'use client'

import { pathSegment } from '@/lib/apiPath.mjs'
import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ArrowUpDown, ChevronDown, ChevronRight, Search, X } from 'lucide-react'
import { API_URL } from '@/lib/api'
import { bodyWithheldLabel } from '@/lib/archiveBodies.mjs'
import { busyNotice, fetchRetryingBusy } from '@/lib/busyRetry.mjs'
import { planPageMerge, resyncWindows } from '@/lib/huntArchiveSync.mjs'
import { Button, Card, ErrorState } from '@/components/ui'
import { MethodBadge } from '@/components/collections/CollectionViewer'

interface Message { headers?: Record<string, string>; body?: string | null; bytes?: number | null; sha256?: string | null }
export interface HuntTransaction {
  id: string
  capability_name?: string | null
  adapter?: string | null
  principal_slot?: string | null
  method?: string | null
  url?: string | null
  status_code?: number | null
  started_at?: string | null
  elapsed_ms?: number | null
  error?: string | null
  truncated?: boolean
  hunt_action_id?: string | null
  request?: Message
  response?: Message
  /** Bodies this export left out, and why: withheld, not absent. */
  payload_omitted?: string[] | null
  payload_omitted_reasons?: Record<string, string> | null
}
interface Archive { fidelity: string; fidelity_detail: string; total: number; transactions: HuntTransaction[] }

const PAGE = 250
/** A live Hunt's archive is re-read at most this often, however fast its version moves. */
export const ARCHIVE_REFRESH_MIN_MS = 5000
const STATUS_CLASSES = ['2xx', '3xx', '4xx', '5xx', 'error'] as const

function statusClass(transaction: HuntTransaction): (typeof STATUS_CLASSES)[number] {
  const code = transaction.status_code
  if (!code) return 'error'
  return `${Math.floor(code / 100)}xx` as (typeof STATUS_CLASSES)[number]
}

function statusTone(transaction: HuntTransaction): string {
  const kind = statusClass(transaction)
  if (kind === '2xx') return 'text-emerald-300'
  if (kind === '3xx') return 'text-sky-300'
  if (kind === '4xx') return 'text-amber-300'
  return 'text-red-300'
}

function splitUrl(url?: string | null): { host: string; path: string } {
  try {
    const parsed = new URL(String(url))
    return { host: parsed.host, path: `${parsed.pathname}${parsed.search}` || '/' }
  } catch {
    return { host: '', path: String(url || 'URL unavailable') }
  }
}

function prettyBody(body?: string | null): string {
  if (!body) return ''
  try { return JSON.stringify(JSON.parse(body), null, 2) } catch { return body }
}

function MessageView({ title, message, withheld = null }: { title: string; message?: Message; withheld?: string | null }) {
  const headers = Object.entries(message?.headers || {})
  const body = prettyBody(message?.body)
  return <div className="min-w-0">
    <p className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-gray-500">{title}
      <span className="ml-2 font-normal normal-case text-gray-600">{message?.bytes ?? 0} bytes</span></p>
    {headers.length > 0 && <dl className="mb-2 grid grid-cols-[minmax(0,10rem)_minmax(0,1fr)] gap-x-3 gap-y-0.5 rounded-md bg-black/30 p-2 font-mono text-[11px]">
      {headers.map(([key, value]) => <Fragment key={key}><dt className="truncate text-gray-500">{key}</dt><dd className="break-all text-gray-300">{value}</dd></Fragment>)}
    </dl>}
    <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-md bg-black/30 p-2 font-mono text-[11px] text-gray-300">{body || <span className="text-gray-600">{withheld ?? 'No body recorded'}</span>}</pre>
  </div>
}

export interface HuntArchive {
  rows: HuntTransaction[]
  total: number
  fidelity: { value: string; detail: string } | null
  loading: boolean
  error: string | null
  /** A notice while the archive is busy and the page waits to retry. */
  busy: string | null
  loadMore: () => Promise<void>
}

/**
 * The Hunt's redacted request archive, one page (PAGE rows) at a time; `loadMore` reads the next.
 * `version` changes when the run records more work. The archive is ordered oldest first, so new
 * requests append: an operator who has read to the end gets only the new tail (offset = rows read);
 * one who has not gets a one-row read that refreshes the total. Version-driven reads are throttled
 * (ARCHIVE_REFRESH_MIN_MS), skipped while the tab is hidden (caught up when it shows) and aborted on
 * unmount or a different Hunt. A total below the rows held (a purge) reloads the first page.
 */
export function useHuntTransactions(huntId: string, version: number): HuntArchive {
  const [rows, setRows] = useState<HuntTransaction[]>([])
  const [total, setTotal] = useState(0)
  const [fidelity, setFidelity] = useState<{ value: string; detail: string } | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const rowsRef = useRef<HuntTransaction[]>([])
  const totalRef = useRef(0)
  const loadedOnce = useRef(false)
  const lastRefreshAt = useRef(0)
  const controllers = useRef(new Set<AbortController>())

  const apply = useCallback((nextRows: HuntTransaction[], nextTotal: number) => {
    rowsRef.current = nextRows
    totalRef.current = nextTotal
    setRows(nextRows)
    setTotal(nextTotal)
  }, [])

  // Filters run in the browser over redacted rows: a server-side URL search would match the raw stored
  // URL and could confirm a value the redacted view masks.
  const fetchPage = useCallback(async (offset: number, limit: number, signal: AbortSignal) => {
    const params = new URLSearchParams({ format: 'transactions', redaction: 'redacted', limit: String(limit), offset: String(offset) })
    const response = await fetchRetryingBusy(`${API_URL}/hunts/${pathSegment(huntId)}/http-transactions?${params}`, { cache: 'no-store', signal },
      { onBusy: seconds => { if (!signal.aborted) setBusy(busyNotice(seconds)) } })
    if (!response.ok) {
      const detail = await response.json().catch(() => null)
      throw new Error(typeof detail?.detail === 'string' ? detail.detail : `Request archive unavailable (${response.status})`)
    }
    return response.json() as Promise<Archive>
  }, [huntId])

  const track = useCallback(() => {
    const controller = new AbortController()
    controllers.current.add(controller)
    return { signal: controller.signal, done: () => controllers.current.delete(controller) }
  }, [])

  const loadFirst = useCallback(async (signal: AbortSignal) => {
    const archive = await fetchPage(0, PAGE, signal)
    if (signal.aborted) return
    setFidelity({ value: archive.fidelity, detail: archive.fidelity_detail })
    apply(archive.transactions || [], archive.total || 0)
    setError(null)
    loadedOnce.current = true
  }, [apply, fetchPage])

  // A different Hunt: forget the rows and read its first page.
  useEffect(() => {
    const live = controllers.current
    const { signal, done } = track()
    loadedOnce.current = false
    lastRefreshAt.current = Date.now()
    apply([], 0)
    setLoading(true)
    setError(null)
    loadFirst(signal)
      .catch((cause) => { if (!signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not load requests') })
      .finally(() => { done(); if (!signal.aborted) setLoading(false) })
    return () => { for (const controller of live) controller.abort(); live.clear() }
  }, [apply, huntId, loadFirst, track])

  // Re-read the window the operator holds from the start and replace it (server order). Rows
  // archived out of order (an overlapping action's requests land mid-list) make an offset read
  // at the tail unreliable; see lib/huntArchiveSync.mjs.
  const resync = useCallback(async (signal: AbortSignal) => {
    const collected: HuntTransaction[] = []
    let archive: Archive | null = null
    for (const span of resyncWindows(rowsRef.current.length, { page: PAGE })) {
      archive = await fetchPage(span.offset, span.limit, signal)
      if (signal.aborted) return
      const batch = archive.transactions || []
      collected.push(...batch)
      if (batch.length < span.limit) break
    }
    if (!archive) return
    const seen = new Set<string>()
    setFidelity({ value: archive.fidelity, detail: archive.fidelity_detail })
    apply(collected.filter(row => (seen.has(row.id) ? false : (seen.add(row.id), true))), archive.total || 0)
    setError(null)
  }, [apply, fetchPage])

  // A read at the tail (offset = rows held): append only when the plan says the rows add up.
  const readTail = useCallback(async (signal: AbortSignal) => {
    const held = rowsRef.current
    const archive = await fetchPage(held.length, PAGE, signal)
    if (signal.aborted) return
    const nextTotal = archive.total || 0
    setFidelity({ value: archive.fidelity, detail: archive.fidelity_detail })
    const plan = planPageMerge({ held: rowsRef.current, page: archive.transactions || [], limit: PAGE, total: nextTotal })
    if (plan.action === 'reload') { await loadFirst(signal); return }
    if (plan.action === 'resync') { await resync(signal); return }
    apply(plan.rows.length ? [...rowsRef.current, ...plan.rows] : rowsRef.current, nextTotal)
    setError(null)
  }, [apply, fetchPage, loadFirst, resync])

  const refresh = useCallback(async () => {
    if (!loadedOnce.current) return
    lastRefreshAt.current = Date.now()
    const { signal, done } = track()
    try {
      if (rowsRef.current.length >= totalRef.current) {
        // At the tail: the new requests themselves.
        await readTail(signal)
        return
      }
      // Not at the tail: one row, for the new total. Rows that arrived mid-list are caught by the
      // next tail read (Load more), which resyncs when the counts no longer add up.
      const archive = await fetchPage(0, 1, signal)
      if (signal.aborted) return
      const nextTotal = archive.total || 0
      setFidelity({ value: archive.fidelity, detail: archive.fidelity_detail })
      if (nextTotal < rowsRef.current.length) { await loadFirst(signal); return }
      apply(rowsRef.current, nextTotal)
      setError(null)
    } catch {
      // A background refresh keeps the rows being read; the next version change tries again.
    } finally {
      done()
    }
  }, [apply, fetchPage, loadFirst, readTail, track])

  // The run recorded more work: refresh, at most once per ARCHIVE_REFRESH_MIN_MS and only while visible.
  const firstVersion = useRef(true)
  useEffect(() => {
    if (firstVersion.current) { firstVersion.current = false; return }
    let timer: ReturnType<typeof setTimeout> | null = null
    const run = () => {
      // Hidden when due (also when the throttle timer fires in a hidden tab): wait for the tab to
      // show again, then refresh, so the final requests and total are never left unread.
      if (document.visibilityState === 'hidden') { document.addEventListener('visibilitychange', run); return }
      document.removeEventListener('visibilitychange', run)
      const wait = lastRefreshAt.current + ARCHIVE_REFRESH_MIN_MS - Date.now()
      if (wait > 0) { timer = setTimeout(run, wait); return }
      void refresh()
    }
    if (document.visibilityState === 'hidden') document.addEventListener('visibilitychange', run)
    else run()
    return () => { if (timer) clearTimeout(timer); document.removeEventListener('visibilitychange', run) }
  }, [refresh, version])

  // Load more reads at the tail with the same plan, so it always makes progress: rows it already
  // holds coming back (an insert before the offset) resync the window instead of appending nothing.
  const loadMore = useCallback(async () => {
    setLoading(true)
    const { signal, done } = track()
    try {
      await readTail(signal)
    } catch (cause) { if (!signal.aborted) setError(cause instanceof Error ? cause.message : 'Could not load more requests') }
    finally { done(); if (!signal.aborted) setLoading(false) }
  }, [readTail, track])

  return { rows, total, fidelity, loading, error, busy, loadMore }
}

/** One request: a summary line that expands to the masked request and response. */
export function RequestRow({ row, index, expanded, onToggle, showCapability = true }: {
  row: HuntTransaction; index: number; expanded: boolean; onToggle: () => void; showCapability?: boolean
}) {
  const { host, path } = splitUrl(row.url)
  // Rendering cost scales with what is on screen, not with the rows loaded: the browser skips
  // layout and paint for rows outside the viewport (dependency-free virtualization).
  return <li className="[content-visibility:auto] [contain-intrinsic-size:auto_44px]">
    <button type="button" onClick={onToggle} aria-expanded={expanded}
      className={`grid w-full grid-cols-[1rem_4rem_3rem_minmax(0,1fr)] items-center gap-3 px-4 py-2 text-left hover:bg-gray-800/30 ${showCapability ? 'lg:grid-cols-[1rem_4rem_3rem_minmax(0,1fr)_12rem_5rem]' : 'lg:grid-cols-[1rem_4rem_3rem_minmax(0,1fr)_5rem]'}`}>
      {expanded ? <ChevronDown className="h-4 w-4 text-gray-500" aria-hidden="true" /> : <ChevronRight className="h-4 w-4 text-gray-500" aria-hidden="true" />}
      <MethodBadge method={row.method || 'GET'} />
      <span className={`font-mono text-xs font-semibold ${statusTone(row)}`}>{row.status_code ?? 'ERR'}</span>
      <span className="min-w-0">
        <span className="block truncate font-mono text-xs text-gray-100" title={row.url || undefined}>{path}</span>
        <span className="block truncate text-[11px] text-gray-500">{host}{row.error ? ` · ${row.error}` : ''}{row.truncated ? ' · body truncated' : ''}</span>
      </span>
      {showCapability && <span className="hidden truncate text-xs text-gray-400 lg:block" title={row.capability_name || row.adapter || undefined}>
        {row.capability_name || row.adapter || 'unattributed'}{row.principal_slot ? <span className="text-gray-600"> · {row.principal_slot}</span> : null}
      </span>}
      <span className="hidden text-right text-xs text-gray-500 lg:block">{row.elapsed_ms != null ? `${row.elapsed_ms} ms` : ''}</span>
    </button>
    {expanded && <div className="grid gap-4 border-t border-gray-800/70 bg-gray-950/40 px-4 py-3 lg:grid-cols-2">
      <p className="select-all break-all rounded-md bg-black/30 px-2 py-1.5 font-mono text-xs text-gray-200 lg:col-span-2">{(row.method || 'GET').toUpperCase()} {row.url || 'URL unavailable'}</p>
      <MessageView title={`#${index + 1} request`} message={row.request} withheld={bodyWithheldLabel(row, 'request')} />
      <MessageView title="Response" message={row.response} withheld={bodyWithheldLabel(row, 'response')} />
      <p className="text-[11px] text-gray-500 lg:col-span-2">
        {row.capability_name || row.adapter || 'Unattributed'}{row.principal_slot ? ` · ${row.principal_slot} principal` : ''}
        {row.started_at ? ` · ${new Date(row.started_at).toLocaleString()}` : ''}
        {row.request?.sha256 ? ` · request SHA-256 ${row.request.sha256.slice(0, 16)}…` : ''}
      </p>
    </div>}
  </li>
}

export function useExpandedSet() {
  const [open, setOpen] = useState<Set<string>>(new Set())
  const toggle = useCallback((id: string) => setOpen(current => {
    const next = new Set(current)
    if (next.has(id)) next.delete(id); else next.add(id)
    return next
  }), [])
  return { open, toggle }
}

/**
 * Every HTTP request a Hunt sent: method, status, path, the capability that sent it, and the masked
 * request and response on demand. Reads the redacted archive; never the raw HAR.
 */
export function HuntRequestsPanel({ archive }: { archive: HuntArchive }) {
  const { rows, total, fidelity, loading, error, busy, loadMore } = archive
  const [query, setQuery] = useState('')
  const [search, setSearch] = useState('')
  const [method, setMethod] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [capability, setCapability] = useState('')
  const { open, toggle } = useExpandedSet()

  useEffect(() => {
    const timer = setTimeout(() => setSearch(query.trim().toLowerCase()), 200)
    return () => clearTimeout(timer)
  }, [query])

  const capabilityOf = (row: HuntTransaction) => row.capability_name || row.adapter || 'unattributed'
  const capabilities = useMemo(() => [...new Set(rows.map(capabilityOf))].sort(), [rows])
  const methods = useMemo(() => [...new Set(rows.map(row => (row.method || 'GET').toUpperCase()))].sort(), [rows])
  const visible = useMemo(() => rows.filter(row => (!method || (row.method || 'GET').toUpperCase() === method)
    && (!statusFilter || statusClass(row) === statusFilter)
    && (!capability || capabilityOf(row) === capability)
    && (!search || [row.url, row.method, row.status_code, capabilityOf(row), row.principal_slot, row.error]
      .some(value => String(value ?? '').toLowerCase().includes(search)))), [rows, method, statusFilter, capability, search])
  const counts = useMemo(() => Object.fromEntries(STATUS_CLASSES.map(kind => [kind, rows.filter(row => statusClass(row) === kind).length])), [rows])

  return <Card className="p-0">
    <div className="flex flex-wrap items-center gap-3 border-b border-gray-800 p-4">
      <h2 className="flex items-center gap-2 font-medium text-white"><ArrowUpDown className="h-4 w-4 text-blue-300" aria-hidden="true" />HTTP requests
        <span className="rounded-full bg-gray-800 px-2 py-0.5 text-xs text-gray-400">{total}</span></h2>
      {fidelity && <span title={fidelity.detail}
        className={`rounded-md px-2 py-0.5 text-xs ${fidelity.value === 'complete' ? 'bg-emerald-500/10 text-emerald-300' : fidelity.value === 'partial' ? 'bg-amber-500/10 text-amber-300' : 'bg-gray-800 text-gray-400'}`}>
        {fidelity.value === 'complete' ? 'complete capture' : `${fidelity.value} capture`}</span>}
      <span className="text-xs text-gray-500">Masked for display; secrets and session values are redacted.</span>
      {fidelity && fidelity.value !== 'complete' && fidelity.detail && <p className="basis-full text-xs text-amber-200/80">{fidelity.detail}</p>}
      {busy && <p role="status" className="basis-full text-xs text-amber-300">{busy}</p>}
    </div>
    <div className="flex flex-wrap items-center gap-2 border-b border-gray-800 px-4 py-3">
      <div className="relative min-w-56 flex-1">
        <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-gray-500" aria-hidden="true" />
        <input aria-label="Search requests" value={query} onChange={event => setQuery(event.target.value)} placeholder="Search path, host, status or capability…"
          className="h-9 w-full rounded-lg border border-gray-700 bg-gray-800 pl-9 pr-8 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-hidden" />
        {query && <button type="button" aria-label="Clear request search" onClick={() => setQuery('')} className="absolute right-2 top-2.5 text-gray-500 hover:text-gray-200"><X className="h-4 w-4" /></button>}
      </div>
      <div role="group" aria-label="Filter by method" className="flex flex-wrap gap-1">
        {(methods.length > 1 ? ['', ...methods] : []).map(value => <button key={value || 'all'} type="button" aria-pressed={method === value} onClick={() => setMethod(value)}
          className={`rounded-md px-2 py-1 font-mono text-xs ${method === value ? 'bg-blue-500/15 text-blue-200' : 'text-gray-400 hover:bg-gray-800'}`}>{value || 'All'}</button>)}
      </div>
      <div role="group" aria-label="Filter by status" className="flex flex-wrap gap-1">
        {STATUS_CLASSES.filter(kind => counts[kind]).map(kind => <button key={kind} type="button" aria-pressed={statusFilter === kind} onClick={() => setStatusFilter(statusFilter === kind ? '' : kind)}
          className={`rounded-md px-2 py-1 text-xs ${statusFilter === kind ? 'bg-blue-500/15 text-blue-200' : 'text-gray-400 hover:bg-gray-800'}`}>{kind} {counts[kind]}</button>)}
      </div>
      {capabilities.length > 1 && <select aria-label="Filter by capability" value={capability} onChange={event => setCapability(event.target.value)}
        className="h-8 rounded-lg border border-gray-700 bg-gray-800 px-2 text-xs text-gray-200">
        <option value="">Every capability</option>
        {capabilities.map(name => <option key={name} value={name}>{name}</option>)}
      </select>}
    </div>
    {error ? <div className="p-4"><ErrorState message={error} /></div>
      : loading && !rows.length ? <p role="status" className="p-6 text-center text-sm text-gray-400">Loading requests…</p>
      : !visible.length ? <p className="p-6 text-center text-sm text-gray-500">{rows.length ? 'No requests match these filters.' : 'This Hunt recorded no HTTP requests.'}</p>
      : <ol className="divide-y divide-gray-800/70" aria-label="HTTP requests">
        {visible.map((row, index) => <RequestRow key={row.id} row={row} index={index} expanded={open.has(row.id)} onToggle={() => toggle(row.id)} />)}
      </ol>}
    {rows.length > 0 && <div className="flex items-center justify-between border-t border-gray-800 px-4 py-2.5 text-xs text-gray-500">
      <span>{visible.length} shown{rows.length < total ? ` · filtering the first ${rows.length} of ${total}` : ''}</span>
      {rows.length < total && <Button size="sm" variant="secondary" loading={loading} onClick={() => void loadMore()}>Load more</Button>}
    </div>}
  </Card>
}
