'use client'

import { useState } from 'react'
import { Archive } from 'lucide-react'
import { API_URL, getApiErrorMessage } from '@/lib/apiConfig'
import { Button, ConfirmDialog, useToast } from '@/components/ui'

export function RetireDeviceButton({ deviceId, name, onRetired }: {
  deviceId: string
  name: string
  onRetired: () => void
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

  return <>
    <Button size="sm" variant="secondary" onClick={() => { setError(null); setOpen(true) }} aria-label={`Retire ${name}`}>
      <Archive className="h-4 w-4" /> Retire
    </Button>
    <ConfirmDialog open={open} title="Retire connected device?" confirmLabel="Retire device"
      danger busy={busy} onConfirm={() => { void retire() }} onCancel={() => setOpen(false)}
      message={<><p>Retire {name} from the active device inventory? Existing scan results and evidence are kept. This does not erase credentials or cancel already-running work.</p>{error && <p role="alert" className="mt-3 text-red-300">{error}</p>}</>} />
  </>
}
