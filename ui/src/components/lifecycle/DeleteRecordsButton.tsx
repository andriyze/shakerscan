'use client'

import { useEffect, useRef, useState } from 'react'
import { Button, ConfirmDialog, useToast } from '@/components/ui'
import { featureEnabled } from '@/lib/workspaceCapabilities'
import {
  approveRecordDeletion, executeRecordDeletion, previewRecordDeletion, archiveRecordTarget,
  type DeletionPreview, type DeletionResult, type DeletionSelection,
} from '@/lib/dataLifecycle'

interface Props {
  selection: DeletionSelection
  label?: string
  subject: string
  onDeleted: (result: DeletionResult) => void
  onArchived?: () => void
  disabled?: boolean
}

export function RecordDeletionDialog({ preview, subject, onClose, onDeleted, onArchived }: {
  preview: DeletionPreview | null
  subject: string
  onClose: () => void
  onDeleted: (result: DeletionResult) => void
  onArchived?: () => void
}) {
  const toast = useToast()
  const [busy, setBusy] = useState(false)
  const [archiveMode, setArchiveMode] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const inFlight = useRef(false)
  const approval = useRef<string | null>(null)
  useEffect(() => { approval.current = null; setError(null); setArchiveMode(false) }, [preview?.preview_id])

  async function archive() {
    if (!preview || preview.kind !== 'target' || preview.root_ids.length !== 1 || inFlight.current) return
    inFlight.current = true
    setBusy(true)
    setError(null)
    try {
      await archiveRecordTarget(preview.root_ids[0])
      onArchived?.()
      onClose()
      toast.success('Target archived. Future schedules paused; history and admitted work retained.')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Archive failed')
    } finally {
      inFlight.current = false
      setBusy(false)
    }
  }

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
    open={Boolean(preview)} title={`${archiveMode ? 'Archive' : 'Delete'} ${subject}`} danger={!archiveMode} busy={busy}
    confirmDisabled={!preview || (!archiveMode && Boolean(preview.blockers.length)) || !preview.root_ids.length}
    confirmLabel={archiveMode ? 'Archive target' : 'Approve and delete records'} onConfirm={archiveMode ? archive : remove} onCancel={onClose}
    message={preview && (archiveMode ? <div className="space-y-3">
      <p>Hide this target and pause its future automatic schedules. All records, evidence, holds, and original ownership remain intact.</p>
      <p>Already-admitted or running work is not cancelled. Use its cancellation controls separately.</p>
      {error && <p role="alert" className="text-red-300">{error}</p>}
    </div> : <div className="max-h-[60vh] space-y-3 overflow-y-auto">
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
      {preview.kind === 'target' && preview.root_ids.length === 1 && onArchived && (
        <Button disabled={busy} onClick={() => { setArchiveMode(true); setError(null) }}>Archive target instead</Button>
      )}
      {error && <p role="alert" className="text-red-300">{error} Close and preview again for changed or expired records.</p>}
    </div>)}
  />
}

export function DeleteRecordsButton({ selection, label = 'Delete', subject, onDeleted, onArchived, disabled }: Props) {
  const toast = useToast()
  const [preview, setPreview] = useState<DeletionPreview | null>(null)
  const [loading, setLoading] = useState(false)
  const loadingRef = useRef(false)
  const alive = useRef(true)
  // A preview is only valid for the exact selection it was requested with. Bind each request
  // and stored preview to a stable value-identity so a delayed response for an older selection
  // can never be shown — or confirmed — against the current one.
  const selectionKey = JSON.stringify(selection)
  const latestKey = useRef(selectionKey)
  latestKey.current = selectionKey
  const previewKey = useRef<string | null>(null)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  // Drop a stored preview the moment the selection changes, is cleared, or the control is disabled,
  // so the confirm dialog can never act on a set the operator no longer has selected.
  useEffect(() => {
    if (previewKey.current !== null && (disabled || previewKey.current !== selectionKey)) {
      previewKey.current = null
      setPreview(null)
    }
  }, [selectionKey, disabled])
  if (!featureEnabled('record_deletion')) return null
  async function open() {
    if (loadingRef.current) return
    loadingRef.current = true
    const requestedKey = selectionKey
    setLoading(true)
    try {
      const result = await previewRecordDeletion(selection)
      // Ignore a late response if the operator changed the selection while it was pending.
      if (alive.current && latestKey.current === requestedKey) {
        previewKey.current = requestedKey
        setPreview(result)
      }
    } catch (cause) {
      if (alive.current && latestKey.current === requestedKey) {
        toast.error(cause instanceof Error ? cause.message : 'Could not preview deletion')
      }
    } finally {
      loadingRef.current = false
      if (alive.current) setLoading(false)
    }
  }
  return <span onClick={event => event.stopPropagation()}>
    <Button variant="danger" disabled={disabled || loading} onClick={open} aria-label={`Delete ${subject}`}>
      {loading ? 'Previewing…' : label}
    </Button>
    <RecordDeletionDialog preview={preview} subject={subject} onClose={() => { previewKey.current = null; setPreview(null) }} onDeleted={onDeleted} onArchived={onArchived} />
  </span>
}
