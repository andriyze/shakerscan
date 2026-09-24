'use client'

import { useEffect, useState } from 'react'
import { API_URL } from '@/lib/apiConfig'

type Observation = {
  validation_id: string; request_id: string | null; revision: number; checked_at: string
  state: string; reason_code: string; identity_matched: boolean; role_matched: boolean | null
}

function Receipt({ requestId }: { requestId: string }) {
  const [open, setOpen] = useState(false)
  const [value, setValue] = useState<{ status: string; budget_reserved: Record<string, number>;
    budget_consumed: Record<string, number> | null; receipt: { receipt_hash: string } | null } | null>(null)
  const [failed, setFailed] = useState(false)
  const [refresh, setRefresh] = useState(0)
  useEffect(() => {
    if (!open) return
    const controller = new AbortController()
    setFailed(false); setValue(null)
    void fetch(`${API_URL}/authenticated-scan-profiles/validations/${encodeURIComponent(requestId)}`, { signal: controller.signal, cache: 'no-store' })
      .then(async response => {
        if (!response.ok) throw new Error()
        const data = await response.json()
        if (!controller.signal.aborted) setValue(data)
      }).catch(() => { if (!controller.signal.aborted) setFailed(true) })
    return () => controller.abort()
  }, [open, requestId, refresh])
  return <div className="mt-1">
    <button type="button" className="underline focus:ring-2 focus:ring-blue-400" aria-expanded={open} onClick={() => setOpen(!open)}>Execution receipt</button>
    {open && <div className="mt-1 rounded border border-gray-700 p-2">
      <button type="button" className="mb-1 underline focus:ring-2 focus:ring-blue-400" onClick={() => setRefresh(value => value + 1)}>Refresh receipt</button>
      {failed ? <p role="status">Receipt unavailable. Try refreshing it.</p> : !value ? <p role="status">Loading receipt…</p> : <>
        <p>Execution: {value.status}</p>
        <dl>{[['http_requests', 'HTTP requests'], ['hosts_attempted', 'Hosts attempted'], ['tool_wall_seconds', 'Tool seconds']].map(([key, label]) =>
          <div key={key}><dt className="inline">{label}: </dt><dd className="inline">reserved {value.budget_reserved[key] ?? 0}; consumed {value.budget_consumed ? value.budget_consumed[key] ?? 0 : 'not settled'}</dd></div>)}</dl>
        {value.receipt && <p className="break-all text-xs text-gray-400">Receipt hash: {value.receipt.receipt_hash}</p>}
      </>}
    </div>}
  </div>
}

export default function AuthenticationHistory({ profileId }: { profileId: string }) {
  const [open, setOpen] = useState(false)
  const [records, setRecords] = useState<Observation[]>([])
  const [cursor, setCursor] = useState<string | null>(null)
  const [page, setPage] = useState<string | null>(null)
  const [refresh, setRefresh] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    if (!open) return
    const controller = new AbortController()
    setLoading(true); setError('')
    const suffix = page ? `?before=${encodeURIComponent(page)}` : ''
    void fetch(`${API_URL}/authenticated-scan-profiles/${encodeURIComponent(profileId)}/history${suffix}`, { signal: controller.signal, cache: 'no-store' })
      .then(async response => {
        if (!response.ok) throw new Error()
        const data = await response.json()
        if (controller.signal.aborted) return
        setRecords(previous => page ? [...previous, ...data.records.filter((item: Observation) => !previous.some(value => value.validation_id === item.validation_id))] : data.records)
        setCursor(data.next_cursor)
      }).catch(() => { if (!controller.signal.aborted) setError('Validation history is unavailable. Try refreshing it.') })
      .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [profileId, open, page, refresh])
  return <div className="mt-2 text-sm">
    <button type="button" className="underline focus:ring-2 focus:ring-blue-400" aria-expanded={open} onClick={() => setOpen(!open)}>Validation history</button>
    {open && <div className="mt-2 rounded border border-gray-700 p-3">
      <p className="text-gray-400">Historical checks are individual observations. They do not prove authentication between checks.</p>
      <button type="button" className="my-2 underline focus:ring-2 focus:ring-blue-400" disabled={loading} onClick={() => { setPage(null); setRefresh(value => value + 1) }}>Refresh history</button>
      {error && <p role="alert">{error}</p>}
      <ol className="divide-y divide-gray-800">{records.map(record => <li key={record.validation_id} className="py-2">
        <p><time dateTime={record.checked_at}>{new Date(record.checked_at).toLocaleString()}</time> · revision {record.revision}</p>
        <p>{record.state === 'valid' ? 'Valid at this check' : record.state} · {record.reason_code.replaceAll('_', ' ')}</p>
        <p className="text-gray-400">Identity matched: {record.identity_matched ? 'yes' : 'no'} · role matched: {record.role_matched === null ? 'not established' : record.role_matched ? 'yes' : 'no'}</p>
        {record.request_id && <Receipt requestId={record.request_id} />}
      </li>)}</ol>
      {loading && <p role="status">Loading history…</p>}
      {!loading && !error && records.length === 0 && <p>No validation observations recorded.</p>}
      {cursor && <button type="button" disabled={loading} className="mt-2 underline focus:ring-2 focus:ring-blue-400" onClick={() => setPage(cursor)}>Load earlier checks</button>}
    </div>}
  </div>
}
