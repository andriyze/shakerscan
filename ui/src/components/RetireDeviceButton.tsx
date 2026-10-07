'use client'

import { useState } from 'react'
import { Archive } from 'lucide-react'
import { API_URL, getApiErrorMessage } from '@/lib/apiConfig'
import { Button, ConfirmDialog, useToast } from '@/components/ui'

export function RetireDeviceButton({ deviceId, name, onRetired, menuItem = false }: {
  deviceId: string
  name: string
  onRetired: () => void
  /** Render as an entry of a row's ActionMenu; the confirmation dialog is the same. */
  menuItem?: boolean
}) {
  const toast = useToast()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function retire() {
    if (busy) return
    setBusy(true)
    setError(null)
    try {
      const response = await fetch(`${API_URL}/devices/${encodeURIComponent(deviceId)}`, { method: 'DELETE' })
      if (!response.ok) throw new Error(await getApiErrorMessage(response, 'Could not retire device'))
      setOpen(false)
      toast.success('Device retired')
      onRetired()
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Could not retire device')
    } finally {
      setBusy(false)
    }
  }

  const openConfirm = () => { setError(null); setOpen(true) }
  return <>
    {menuItem
      ? <button type="button" role="menuitem" onClick={openConfirm} aria-label={`Retire ${name}`}
          className="flex w-full items-start gap-2.5 rounded-md px-2.5 py-1.5 text-left text-sm text-red-300 transition-colors hover:bg-red-500/10 focus:bg-red-500/10 focus:outline-none">
          <Archive className="mt-0.5 h-4 w-4 text-gray-400" aria-hidden="true" />
          <span><span className="block">Retire…</span><span className="mt-0.5 block text-xs leading-4 text-gray-500">Remove from the active inventory; results are kept</span></span>
        </button>
      : <Button size="sm" variant="secondary" onClick={openConfirm} aria-label={`Retire ${name}`}>
          <Archive className="h-4 w-4" /> Retire
        </Button>}
    <ConfirmDialog open={open} title="Retire connected device?" confirmLabel="Retire device"
      danger busy={busy} onConfirm={() => { void retire() }} onCancel={() => setOpen(false)}
      message={<><p>Retire {name} from the active device inventory? Existing scan results and evidence are kept. This does not erase credentials or cancel already-running work.</p>{error && <p role="alert" className="mt-3 text-red-300">{error}</p>}</>} />
  </>
}
