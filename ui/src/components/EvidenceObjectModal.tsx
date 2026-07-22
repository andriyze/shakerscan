'use client'

import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { X } from 'lucide-react'
import { getEvidenceObject, type EvidenceObject } from '@/lib/api'
import { ProofStateBadge, RetentionClassBadge, useModalA11y } from '@/components/ui'

function Field({ label, value }: { label: string; value?: React.ReactNode }) {
  if (value === undefined || value === null || value === '') return null
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-xs text-gray-500">{label}</span>
      <span className="break-all text-sm text-gray-200">{value}</span>
    </div>
  )
}

export default function EvidenceObjectModal({
  objectId,
  onClose,
}: {
  objectId: string | null
  onClose: () => void
}) {
  const panelRef = useRef<HTMLDivElement>(null)
  const [obj, setObj] = useState<EvidenceObject | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const open = objectId !== null
  useModalA11y(open, panelRef, onClose)

  useEffect(() => {
    if (!objectId) { setObj(null); setError(null); return }
    let cancelled = false
    setLoading(true)
    setError(null)
    getEvidenceObject(objectId)
      .then((data) => { if (!cancelled) setObj(data) })
      .catch((err) => { if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load evidence') })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [objectId])

  if (!open || typeof document === 'undefined') return null

  const contentString = obj?.content == null
    ? null
    : typeof obj.content === 'string'
      ? obj.content
      : JSON.stringify(obj.content, null, 2)

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={onClose}>
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label="Evidence object"
        tabIndex={-1}
        className="flex max-h-[85vh] w-full max-w-2xl flex-col overflow-hidden rounded-lg border border-gray-800 bg-gray-900 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-gray-800 p-4">
          <h2 className="text-lg font-semibold text-white">Evidence object</h2>
          <button type="button" onClick={onClose} aria-label="Close" className="rounded p-1 text-gray-400 hover:bg-gray-800 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="overflow-y-auto p-4">
          {loading ? (
            <p className="text-sm text-gray-500">Loading…</p>
          ) : error ? (
            <p className="text-sm text-red-400">{error}</p>
          ) : obj ? (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center gap-2">
                {obj.retention_class && <RetentionClassBadge retentionClass={obj.retention_class} />}
                {obj.proof_state && <ProofStateBadge proofState={obj.proof_state as 'verified'} />}
                {obj.object_type && (
                  <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-gray-400">
                    {obj.object_type}
                  </span>
                )}
              </div>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <Field label="ID" value={obj.id} />
                <Field label="Hash" value={obj.hash || obj.content_sha256} />
                <Field label="Redaction profile" value={obj.redaction_profile} />
                <Field label="Storage" value={obj.storage_uri || obj.storage_backend} />
                <Field label="Integrity" value={obj.integrity_status} />
                <Field label="Finding" value={obj.finding_id} />
                <Field label="Scan" value={obj.scan_id} />
                <Field label="Created" value={obj.created_at} />
              </div>
              {contentString != null && (
                <div>
                  <p className="mb-1 text-xs text-gray-500">Content (redaction-profiled)</p>
                  <pre className="max-h-64 overflow-auto rounded-lg border border-gray-800 bg-gray-950 p-3 text-xs text-gray-300">
                    {contentString}
                  </pre>
                </div>
              )}
            </div>
          ) : null}
        </div>
      </div>
    </div>,
    document.body
  )
}
