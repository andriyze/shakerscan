'use client'

import { useEffect, useRef, useState } from 'react'
import { Button, ConfirmDialog, useToast } from '@/components/ui'
import { featureEnabled } from '@/lib/workspaceCapabilities'
import {
  approveRecordDeletion, executeRecordDeletion, previewRecordDeletion,
  type DeletionPreview, type DeletionResult, type DeletionSelection,
} from '@/lib/dataLifecycle'

interface Props {
  selection: DeletionSelection
  label?: string
  subject: string
  onDeleted: (result: DeletionResult) => void
  disabled?: boolean
}

export function RecordDeletionDialog({ preview, subject, onClose, onDeleted }: {
  preview: DeletionPreview | null
  subject: string
  onClose: () => void
  onDeleted: (result: DeletionResult) => void
}) {
  const toast = useToast()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const inFlight = useRef(false)
  const approval = useRef<string | null>(null)
  useEffect(() => { approval.current = null; setError(null) }, [preview?.preview_id])

  async function remove() {
    if (!preview || inFlight.current || preview.blockers.length || !preview.root_ids.length) return
    inFlight.current = true
    setBusy(true)
    setError(null)
    try {
      // Keep the same receipt on a network retry: a committed operation is replayed,
      // never reapproved with a different identity after an uncertain response.
      approval.current ??= await approveRecordDeletion(preview)
      const result = await executeRecordDeletion(preview, approval.current)
      onDeleted(result)
      onClose()
      toast.success('Records deleted. Historical scans and external files were retained.')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Deletion failed')
    } finally {
      inFlight.current = false
      setBusy(false)
    }
  }

  return <ConfirmDialog
    open={Boolean(preview)} title={`Delete ${subject}`} danger busy={busy}
    confirmDisabled={!preview || Boolean(preview.blockers.length) || !preview.root_ids.length}
    confirmLabel="Approve and delete records" onConfirm={remove} onCancel={onClose}
    message={preview && <div className="max-h-[60vh] space-y-3 overflow-y-auto">
      <p>This permanently removes the following database records. This cannot be undone.</p>
      <dl className="grid grid-cols-2 gap-x-3 gap-y-1">
        {Object.entries(preview.records.delete).map(([table, value]) => <div key={table} className="contents">
          <dt className="break-words">{table.replaceAll('_', ' ')}</dt><dd>{value.count}</dd>
        </div>)}
      </dl>
      <p className="font-medium text-gray-200">Not a complete data erasure</p>
      {preview.retained.map(text => <p key={text}>{text}</p>)}
      <p>Only the selected IDs are affected. Subdomains and sibling targets are not recursively deleted.</p>
      {preview.blockers.map(text => <p role="alert" key={text} className="text-amber-300">{text}</p>)}
      {error && <p role="alert" className="text-red-300">{error} Close and preview again for changed or expired records.</p>}
    </div>}
  />
}

export function DeleteRecordsButton({ selection, label = 'Delete', subject, onDeleted, disabled }: Props) {
  const toast = useToast()
  const [preview, setPreview] = useState<DeletionPreview | null>(null)
  const [loading, setLoading] = useState(false)
  const loadingRef = useRef(false)
  const alive = useRef(true)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  if (!featureEnabled('record_deletion')) return null
  async function open() {
    if (loadingRef.current) return
    loadingRef.current = true
    setLoading(true)
    try {
      const result = await previewRecordDeletion(selection)
      if (alive.current) setPreview(result)
    } catch (cause) {
      if (alive.current) toast.error(cause instanceof Error ? cause.message : 'Could not preview deletion')
    } finally {
      loadingRef.current = false
      if (alive.current) setLoading(false)
    }
  }
  return <span onClick={event => event.stopPropagation()}>
    <Button variant="danger" disabled={disabled || loading} onClick={open} aria-label={`Delete ${subject}`}>
      {loading ? 'Previewing…' : label}
    </Button>
    <RecordDeletionDialog preview={preview} subject={subject} onClose={() => setPreview(null)} onDeleted={onDeleted} />
  </span>
}
