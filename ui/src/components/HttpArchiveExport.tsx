'use client'

import { useState } from 'react'
import { Download, Search } from 'lucide-react'
import { API_URL } from '@/lib/api'
import { Button, Card, Input, Select, useToast } from '@/components/ui'

type ArchiveFormat = 'transactions' | 'har'
type DownloadKind = ArchiveFormat | 'hunt-record'

interface ArchivedTransaction {
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
  request?: { headers?: Record<string, string>; body?: string | null; sha256?: string | null; bytes?: number | null }
  response?: { headers?: Record<string, string>; body?: string | null; sha256?: string | null; bytes?: number | null }
}

interface ArchiveDocument {
  fidelity: 'complete' | 'partial' | 'unknown' | 'unavailable'
  fidelity_detail: string
  total: number
  archive_total?: number
  transactions: ArchivedTransaction[]
}

const PAGE_SIZE = 25

function fidelityClass(fidelity?: string): string {
  if (fidelity === 'complete') return 'bg-emerald-500/10 text-emerald-300'
  if (fidelity === 'partial') return 'bg-amber-500/10 text-amber-300'
  if (fidelity === 'unavailable') return 'bg-gray-800 text-gray-400'
  return 'bg-blue-500/10 text-blue-300'
}

function pretty(value: unknown): string {
  if (value === null || value === undefined || value === '') return 'None recorded'
  if (typeof value === 'string') return value
  return JSON.stringify(value, null, 2)
}

function TransactionDetail({ transaction }: { transaction: ArchivedTransaction }) {
  const status = transaction.status_code ?? (transaction.error ? 'error' : '—')
  return (
    <details className="rounded-lg border border-gray-800 bg-gray-950/60">
      <summary className="flex cursor-pointer list-none items-center gap-3 px-3 py-2 text-xs">
        <span className="w-14 shrink-0 rounded bg-blue-500/10 px-1.5 py-0.5 text-center font-mono text-blue-300">
          {transaction.method || 'HTTP'}
        </span>
        <span className="w-10 shrink-0 font-mono text-gray-400">{status}</span>
        <span className="min-w-0 flex-1 truncate font-mono text-gray-300">{transaction.url || 'URL unavailable'}</span>
        {transaction.elapsed_ms !== null && transaction.elapsed_ms !== undefined && (
          <span className="shrink-0 text-gray-600">{transaction.elapsed_ms} ms</span>
        )}
      </summary>
      <div className="grid gap-3 border-t border-gray-800 p-3 lg:grid-cols-2">
        <div className="min-w-0">
          <p className="mb-1 text-[11px] font-medium uppercase tracking-wide text-gray-500">Request</p>
          <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded bg-black/30 p-2 text-[11px] text-gray-300">
            {pretty({ headers: transaction.request?.headers || {}, body: transaction.request?.body ?? null })}
          </pre>
          <p className="mt-1 break-all text-[10px] text-gray-600">
            {transaction.request?.bytes ?? 0} bytes{transaction.request?.sha256 ? ` · SHA-256 ${transaction.request.sha256}` : ''}
          </p>
        </div>
        <div className="min-w-0">
          <p className="mb-1 text-[11px] font-medium uppercase tracking-wide text-gray-500">Response</p>
          <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded bg-black/30 p-2 text-[11px] text-gray-300">
            {pretty({ headers: transaction.response?.headers || {}, body: transaction.response?.body ?? null })}
          </pre>
          <p className="mt-1 break-all text-[10px] text-gray-600">
            {transaction.response?.bytes ?? 0} bytes{transaction.response?.sha256 ? ` · SHA-256 ${transaction.response.sha256}` : ''}
          </p>
        </div>
        <p className="text-[11px] text-gray-500 lg:col-span-2">
          {transaction.capability_name || transaction.adapter || 'Unattributed adapter'}
          {transaction.principal_slot ? ` · ${transaction.principal_slot} principal` : ''}
          {transaction.started_at ? ` · ${new Date(transaction.started_at).toLocaleString()}` : ''}
          {transaction.truncated ? ' · stored body was truncated' : ''}
          {transaction.error ? ` · ${transaction.error}` : ''}
        </p>
      </div>
    </details>
  )
}

export default function HttpArchiveExport({
  ownerKind,
  ownerId,
  compact = false,
}: {
  ownerKind: 'scan' | 'hunt'
  ownerId: string
  compact?: boolean
}) {
  const toast = useToast()
  const [downloading, setDownloading] = useState<DownloadKind | null>(null)
  const [loading, setLoading] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const [archive, setArchive] = useState<ArchiveDocument | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [method, setMethod] = useState('')
  const [statusCode, setStatusCode] = useState('')
  const [offset, setOffset] = useState(0)
  const ownerPath = ownerKind === 'scan' ? 'scans' : 'hunts'

  const archiveUrl = (format: ArchiveFormat, pageOffset = 0) => {
    const params = new URLSearchParams({
      format,
      redaction: 'redacted',
      limit: String(format === 'transactions' ? PAGE_SIZE : 10_000),
      offset: String(pageOffset),
    })
    if (search.trim()) params.set('search', search.trim())
    if (method) params.set('method', method)
    if (statusCode.trim()) params.set('status_code', statusCode.trim())
    return `${API_URL}/${ownerPath}/${encodeURIComponent(ownerId)}/http-transactions?${params}`
  }

  const load = async (nextOffset = 0) => {
    setLoading(true)
    try {
      const response = await fetch(archiveUrl('transactions', nextOffset))
      if (!response.ok) {
        const detail = await response.json().catch(() => null)
        throw new Error(detail?.detail || `Archive request failed (${response.status})`)
      }
      setArchive(await response.json() as ArchiveDocument)
      setOffset(nextOffset)
      setLoaded(true)
      setError(null)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not load request archive')
    } finally {
      setLoading(false)
    }
  }

  const download = async (format: ArchiveFormat) => {
    if (format === 'har' && !window.confirm(
      'Raw HAR contains verbatim URLs, authentication headers, cookies, request bodies, and response data. Treat the downloaded file as sensitive. Continue?',
    )) return
    setDownloading(format)
    try {
      const response = await fetch(archiveUrl(format, 0))
      if (!response.ok) {
        const detail = await response.json().catch(() => null)
        throw new Error(detail?.detail || `Export failed (${response.status})`)
      }
      const blob = await response.blob()
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `shakerscan-${ownerId}.${format === 'har' ? 'RAW.har' : 'json'}`
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
      URL.revokeObjectURL(url)
      toast.success(format === 'har' ? 'Raw HAR export downloaded' : 'Request archive downloaded')
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Could not export request archive')
    } finally {
      setDownloading(null)
    }
  }

  const downloadHuntRecord = async () => {
    setDownloading('hunt-record')
    try {
      const response = await fetch(`${API_URL}/hunts/${encodeURIComponent(ownerId)}/record`)
      if (!response.ok) {
        const detail = await response.json().catch(() => null)
        throw new Error(detail?.detail || `Hunt record export failed (${response.status})`)
      }
      const blob = await response.blob()
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `shakerscan-hunt-${ownerId}.json`
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
      URL.revokeObjectURL(url)
      toast.success('Full Hunt record downloaded')
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Could not export the Hunt record')
    } finally {
      setDownloading(null)
    }
  }

  const body = (
    <>
      <div className="flex flex-wrap items-start gap-3">
        <div className="min-w-0 flex-1">
          <h2 className="text-sm font-semibold text-gray-200">HTTP request archive</h2>
          <p className="mt-1 text-xs text-gray-500">
            Browse masked JSON or download the raw replay-ready HAR recorded during this {ownerKind}. Fidelity states when capture was partial.
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          {ownerKind === 'hunt' && (
            <Button size="sm" variant="secondary" onClick={downloadHuntRecord} disabled={downloading !== null}>
              <Download className="h-4 w-4" />{downloading === 'hunt-record' ? 'Preparing…' : 'Full Hunt record'}
            </Button>
          )}
          <Button size="sm" variant="secondary" onClick={() => download('transactions')} disabled={downloading !== null}>
            <Download className="h-4 w-4" />{downloading === 'transactions' ? 'Preparing…' : 'Requests JSON'}
          </Button>
          <Button size="sm" variant="secondary" onClick={() => download('har')} disabled={downloading !== null}>
            <Download className="h-4 w-4" />{downloading === 'har' ? 'Preparing…' : 'Raw HAR 1.2'}
          </Button>
        </div>
      </div>
      <details className="mt-3 rounded-lg border border-gray-800 bg-gray-950/30" onToggle={(event) => { if (event.currentTarget.open && !loaded && !loading) void load(0) }}>
        <summary className="cursor-pointer px-3 py-2 text-xs font-medium text-blue-300">Browse recorded calls</summary>
        <div className="border-t border-gray-800 p-3">
          <form className="grid gap-2 sm:grid-cols-[minmax(12rem,1fr)_8rem_8rem_auto]" onSubmit={(event) => { event.preventDefault(); void load(0) }}>
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-600" />
              <Input aria-label="Search archived calls" className="pl-9" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="URL, capability, or adapter" />
            </div>
            <Select aria-label="Filter archived calls by method" value={method} onChange={(event) => setMethod(event.target.value)}>
              <option value="">All methods</option>
              {['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].map((value) => <option key={value}>{value}</option>)}
            </Select>
            <Input aria-label="Filter archived calls by status" inputMode="numeric" value={statusCode} onChange={(event) => setStatusCode(event.target.value.replace(/\D/g, '').slice(0, 3))} placeholder="Status" />
            <Button size="sm" variant="secondary" type="submit" loading={loading}>Apply</Button>
          </form>

          {error && <p role="alert" className="mt-3 text-xs text-red-300">{error}</p>}
          {loading && !archive && <p className="mt-3 text-xs text-gray-500">Loading recorded calls…</p>}
          {archive && (
            <>
              <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-gray-500">
                <span className={`rounded px-2 py-0.5 ${fidelityClass(archive.fidelity)}`}>{archive.fidelity} capture</span>
                <span>{archive.fidelity_detail}</span>
                <span>· {archive.total} match{archive.total === 1 ? '' : 'es'} in {archive.archive_total ?? archive.total} recorded call{(archive.archive_total ?? archive.total) === 1 ? '' : 's'}</span>
              </div>
              {archive.transactions.length === 0 ? (
                <p className="mt-3 rounded bg-gray-950 p-3 text-xs text-gray-500">
                  {archive.fidelity === 'unavailable' ? 'No request archive is available for this historical run.' : 'No recorded calls match these filters.'}
                </p>
              ) : (
                <div className="mt-3 space-y-2">{archive.transactions.map((transaction) => <TransactionDetail key={transaction.id} transaction={transaction} />)}</div>
              )}
              {archive.total > PAGE_SIZE && (
                <div className="mt-3 flex items-center justify-between">
                  <Button size="sm" variant="ghost" disabled={loading || offset === 0} onClick={() => void load(Math.max(0, offset - PAGE_SIZE))}>Previous</Button>
                  <span className="text-xs text-gray-600">{offset + 1}-{Math.min(offset + PAGE_SIZE, archive.total)} of {archive.total}</span>
                  <Button size="sm" variant="ghost" disabled={loading || offset + PAGE_SIZE >= archive.total} onClick={() => void load(offset + PAGE_SIZE)}>Next</Button>
                </div>
              )}
            </>
          )}
        </div>
      </details>
    </>
  )

  if (compact) return <div className="rounded-lg border border-gray-800 bg-gray-950 p-3">{body}</div>
  return <Card className="mb-6 p-4">{body}</Card>
}
