'use client'

import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'next/navigation'
import { listReviewProposals, readInvestigation, type InvestigationReview } from '@/lib/huntReview'
import { assessmentText, candidateHistoryText, isReviewId, reconcileReviewSelection } from '@/lib/huntReviewModel'

function Review({ huntId }: { huntId: string }) {
  const [ids, setIds] = useState<string[]>([])
  const [cursor, setCursor] = useState<string | null>(null)
  const [selected, setSelected] = useState('')
  const [review, setReview] = useState<InvestigationReview | null>(null)
  const [loading, setLoading] = useState(true)
  const [reading, setReading] = useState(false)
  const [supported, setSupported] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [readError, setReadError] = useState<string | null>(null)
  const [revision, setRevision] = useState(0)
  const listRequest = useRef<AbortController | null>(null)
  const readRequest = useRef<AbortController | null>(null)
  const listing = useRef(false)

  async function loadPage(next: string | null) {
    if (listing.current) return
    listing.current = true
    const controller = new AbortController()
    listRequest.current = controller
    setLoading(true)
    setError(null)
    try {
      const page = await listReviewProposals(huntId, next, controller.signal)
      if (controller.signal.aborted) return
      setSupported(page.supported)
      setIds(current => Array.from(new Set([...(next ? current : []), ...page.ids])))
      setCursor(page.nextCursor)
      if (next === null) {
        // History replacement invalidates an in-flight read even if the selected
        // ID survives. Re-fetch retained evidence rather than showing stale state.
        readRequest.current?.abort()
        setReview(null)
        setReadError(null)
        setReading(false)
        setSelected(current => reconcileReviewSelection(current, page.ids))
        setRevision(value => value + 1)
      } else {
        setSelected(current => current || page.ids[0] || '')
      }
    } catch (cause) {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Investigation history unavailable')
    } finally {
      if (listRequest.current === controller) {
        listing.current = false
        if (!controller.signal.aborted) setLoading(false)
      }
    }
  }

  useEffect(() => {
    void loadPage(null)
    return () => {
      listRequest.current?.abort()
      listing.current = false
    }
    // The keyed component is recreated when the Hunt reference changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [huntId])

  useEffect(() => {
    setReview(null)
    setReadError(null)
    setReading(false)
    if (!selected) return
    const controller = new AbortController()
    readRequest.current = controller
    setReading(true)
    readInvestigation(huntId, selected, controller.signal)
      .then(result => { if (!controller.signal.aborted) setReview(result) })
      .catch(cause => { if (!controller.signal.aborted) setReadError(cause instanceof Error ? cause.message : 'Saved evidence unavailable') })
      .finally(() => { if (!controller.signal.aborted) setReading(false) })
    return () => controller.abort()
  }, [huntId, selected, revision])

  if (!supported) return null
  const history = review?.candidate_history || (review?.candidate ? [review.candidate] : [])
  return (
    <section aria-label="Investigation review" className="mb-6 space-y-4 rounded-xl border border-gray-700 bg-gray-900 p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-white">Investigation review</h2>
          <p className="mt-1 text-sm text-gray-400">Saved evidence, uncertainty, and retained leads. This view sends no target traffic.</p>
        </div>
        <button type="button" disabled={loading} onClick={() => void loadPage(null)} className="rounded border border-gray-600 px-3 py-2 text-sm text-gray-200 disabled:opacity-50">Refresh history</button>
      </div>
      {error && <p role="alert" className="text-sm text-amber-300">{error}</p>}
      {loading && <p role="status" className="text-sm text-gray-400">Reading investigation history…</p>}
      {!loading && !error && ids.length === 0 && <p className="text-sm text-gray-400">No saved authorization proposals for this Hunt. This does not mean the target has been examined.</p>}
      {ids.length > 0 && (
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex min-w-0 flex-1 flex-col gap-1 text-sm text-gray-300">
            Saved investigation
            <select value={selected} onChange={event => setSelected(event.target.value)} className="rounded border border-gray-600 bg-gray-950 p-2 text-white">
              {ids.map(id => <option key={id} value={id}>{id}</option>)}
            </select>
          </label>
          <button type="button" disabled={reading} onClick={() => setRevision(value => value + 1)} className="rounded border border-gray-600 px-3 py-2 text-sm text-gray-200 disabled:opacity-50">Refresh evidence</button>
        </div>
      )}
      {cursor && <button type="button" disabled={loading} onClick={() => void loadPage(cursor)} className="text-sm text-blue-300 disabled:opacity-50">Load more investigations — history is not yet complete</button>}
      {reading && <p role="status" className="text-sm text-gray-400">Reading saved evidence…</p>}
      {readError && <p role="alert" className="text-sm text-amber-300">{readError}</p>}
      {review && (
        <div className="space-y-4">
          <div className="rounded-lg bg-gray-950 p-4">
            <p className="text-xs uppercase tracking-wide text-gray-500">Latest assessment</p>
            <p className="mt-1 font-medium text-white">{assessmentText(review.authorization_assessment)}</p>
            <code className="mt-2 block break-all text-sm text-gray-300">{review.route}</code>
            <p className="mt-2 text-sm text-gray-300">{review.explanation}</p>
            <p className="mt-2 text-xs text-gray-400">Declared access expectation: {review.expected_access || 'unknown'} — operator context, not proof.</p>
            <p className="mt-1 text-xs text-gray-400">Selected request examined: {review.selected_request_examined ? 'yes' : 'not established'}.</p>
            {review.deferral_recorded && <p className="mt-2 text-sm text-amber-200">A deferral is recorded. It does not cancel previously admitted work.</p>}
          </div>
          <div>
            <h3 className="font-medium text-gray-200">Retained leads</h3>
            <p className="mt-1 text-sm text-gray-400">{candidateHistoryText(review.candidate_relation)}</p>
            {history.map(candidate => (
              <p key={`${candidate.id}:${candidate.created_from_attempt}`} className="mt-2 break-all rounded bg-gray-950 p-3 text-sm text-gray-300">
                Candidate <code>{candidate.id}</code> · recorded from attempt {candidate.created_from_attempt} · store status: {candidate.status}
              </p>
            ))}
          </div>
          {(review.resume?.open_questions || []).length > 0 && (
            <div><h3 className="font-medium text-gray-200">Recorded unresolved questions</h3>
              {(review.resume?.open_questions || []).map((question, index) => <p key={index} className="mt-1 text-sm text-gray-400">{question}</p>)}
            </div>
          )}
          <details className="rounded border border-gray-700 p-3">
            <summary className="cursor-pointer text-sm text-gray-200">Attempt history and evidence references ({review.attempts.length})</summary>
            {review.attempts.map(attempt => (
              <div key={attempt.action_id} className="mt-3 space-y-1 border-t border-gray-800 pt-3 text-sm text-gray-300">
                <p>Attempt {attempt.attempt} · {attempt.execution_status} · server proof state: {attempt.proof_state || 'not reported'}</p>
                <p>{attempt.reason}</p>
                <p className="break-all text-xs text-gray-400">Action: {attempt.action_id} · Receipt: {attempt.receipt_id || 'not available'}</p>
                {(attempt.transaction_ids || []).map(id => <p key={id} className="break-all text-xs text-gray-500">Transaction: {id}</p>)}
              </div>
            ))}
          </details>
          <details className="rounded border border-gray-700 p-3">
            <summary className="cursor-pointer text-sm text-gray-200">Evidence requirements and supported-request limitations</summary>
            {[...(review.evidence_needed || []), ...(review.limitations || [])].map((text, index) => <p key={index} className="mt-2 text-sm text-gray-400">{text}</p>)}
          </details>
          <p className="text-xs text-gray-500">A conclusion covers the tested object and principal pair, not every object on the route. Candidate association and human interpretation never set technical proof.</p>
        </div>
      )}
    </section>
  )
}

export default function InvestigationReviewPanel() {
  const searchParams = useSearchParams()
  const huntId = searchParams.get('run')
  return isReviewId(huntId) ? <Review key={huntId} huntId={huntId} /> : null
}
