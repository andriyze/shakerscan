'use client'

import { useEffect, useState } from 'react'
import { API_URL } from '@/lib/apiConfig'
import { createTargetPolicyApprovalReceipt } from '@/lib/api'

export default function AuthenticationValidation({ profileId, revision, targetId, origin, path, onUpdated }: {
  profileId: string; revision: number; targetId: string; origin: string; path: string; onUpdated: () => void
}) {
  const [open, setOpen] = useState(false)
  const [reviewed, setReviewed] = useState(false)
  const [insecure, setInsecure] = useState(false)
  const [lab, setLab] = useState(false)
  const [busy, setBusy] = useState(false)
  const [requestId, setRequestId] = useState<string | null>(null)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const needsTransportReview = origin.startsWith('http://')

  useEffect(() => {
    if (!requestId) return
    let cancelled = false
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout>
    const check = async () => {
      try {
        const response = await fetch(`${API_URL}/authenticated-scan-profiles/validations/${requestId}`, { signal: controller.signal, cache: 'no-store' })
        if (!response.ok) throw new Error()
        const status = await response.json()
        if (cancelled) return
        if (['queued', 'running'].includes(status.status)) {
          setMessage(status.status === 'queued' ? 'Waiting for a worker…' : 'Checking the reviewed health resource…')
          timer = setTimeout(check, 1000)
        } else {
          setMessage(`${status.status}: ${(status.reason_code || 'validation_unavailable').replaceAll('_', ' ')}`)
          setRequestId(null)
          onUpdated()
        }
      } catch {
        if (!cancelled) {
          setError('The validation status is unavailable. Reload the profile to check the recorded outcome.')
          setRequestId(null)
          onUpdated()
        }
      }
    }
    void check()
    return () => { cancelled = true; controller.abort(); clearTimeout(timer) }
  }, [requestId, onUpdated])

  async function validate() {
    if (!reviewed || (needsTransportReview && !insecure)) return
    setBusy(true); setError(''); setMessage('')
    try {
      const approval = await createTargetPolicyApprovalReceipt({ targetId, targetUrl: origin,
        actionName: 'authentication.validate', riskTier: 'credential', ttlMinutes: 5,
        environment: lab ? 'lab' : 'production' })
      const response = await fetch(`${API_URL}/authenticated-scan-profiles/${profileId}/validate`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ expected_revision: revision, approval_receipt_id: approval.approvalReceiptId,
          reviewed: true, allow_insecure_transport: insecure }),
      })
      if (!response.ok) {
        setError(response.status === 429 ? 'A validation was recently requested. Wait for it to finish before trying again.'
          : 'Validation could not start. Reload and review the profile, credential, and target authorization.')
        return
      }
      const result = await response.json()
      setRequestId(result.request_id); setOpen(false); setReviewed(false)
      onUpdated()
    } catch {
      setError('Validation could not start. Check the target scope and approval availability.')
    } finally { setBusy(false) }
  }

  async function cancel() {
    setError('')
    try {
      const response = await fetch(`${API_URL}/authenticated-scan-profiles/validations/${requestId}/cancel`, { method: 'POST' })
      if (!response.ok) throw new Error()
      setMessage('Cancellation requested. A request already sent cannot be undone.')
    } catch { setError('Cancellation could not be confirmed. The check remains bounded by its timeout.') }
  }

  return <div className="mt-2 text-sm">
    {!requestId && <button type="button" className="underline focus:ring-2 focus:ring-blue-400" onClick={() => setOpen(!open)}>Validate identity</button>}
    {requestId && <button type="button" className="underline focus:ring-2 focus:ring-blue-400" onClick={cancel}>Cancel validation</button>}
    {message && <p role="status" className="mt-2">{message}</p>}
    {error && <p role="alert" className="mt-2 text-amber-300">{error}</p>}
    {open && <div className="mt-2 space-y-2 rounded border border-gray-700 p-3">
      <p className="break-all">One GET to {origin}{path}, using saved credentials. Redirects are not followed.</p>
      <p>This observation expires. It does not prove continuous authentication or authorize a Scan.</p>
      <label className="flex items-start gap-2"><input type="checkbox" checked={reviewed} onChange={e => setReviewed(e.target.checked)} className="mt-1" />I authorize this identity check and confirm the owner-provided resource is read-only.</label>
      {needsTransportReview && <label className="flex items-start gap-2"><input type="checkbox" checked={insecure} onChange={e => setInsecure(e.target.checked)} className="mt-1" />I approve sending this test credential over unencrypted HTTP to the displayed destination.</label>}
      <label className="flex items-start gap-2"><input type="checkbox" checked={lab} onChange={e => setLab(e.target.checked)} className="mt-1" />This is an isolated lab environment (allow private lab scope review).</label>
      <button type="button" disabled={busy || !reviewed || (needsTransportReview && !insecure)} onClick={validate} className="rounded bg-blue-700 px-3 py-2 disabled:opacity-40 focus:ring-2 focus:ring-blue-400">{busy ? 'Requesting…' : 'Run reviewed identity check'}</button>
    </div>}
  </div>
}
