'use client'

import { useState } from 'react'
import { ShieldCheck } from 'lucide-react'
import { Button, Field, Input, Modal } from '@/components/ui'
import { authorizeTargetAsset, type TargetAsset } from '@/lib/targetAssetApi'

/** Record standing authorization for one or more assets; each host covers its linked web apps. */
export function AuthorizeDialog({ assets, onClose, onDone }: {
  assets: TargetAsset[]; onClose: () => void; onDone: (authorized: number, failures: string[]) => void
}) {
  const [approvedBy, setApprovedBy] = useState('operator')
  const [busy, setBusy] = useState(false)
  const pending = assets.filter(asset => !asset.authorized && asset.is_active)
  async function confirm() {
    setBusy(true)
    const failures: string[] = []
    let authorized = 0
    for (const asset of pending) {
      try { await authorizeTargetAsset(asset.id, approvedBy.trim(), asset.environment); authorized++ }
      catch (cause) { failures.push(`${asset.locator}: ${cause instanceof Error ? cause.message : 'not authorized'}`) }
    }
    setBusy(false)
    onDone(authorized, failures)
  }
  const label = pending.length === 1 ? pending[0].name || pending[0].locator : `${pending.length} targets`
  return <Modal open={assets.length > 0} title="Authorize testing" onClose={() => { if (!busy) onClose() }}
    footer={<div className="flex w-full justify-end gap-2">
      <Button variant="secondary" disabled={busy} onClick={onClose}>Cancel</Button>
      <Button loading={busy} disabled={!pending.length || !approvedBy.trim()} onClick={() => void confirm()}><ShieldCheck className="h-4 w-4" aria-hidden="true" />Authorize {label}</Button>
    </div>}>
    <div className="space-y-4">
      {pending.length
        ? <p className="text-sm leading-6 text-gray-300">Confirm that you own or are authorized to test <strong className="font-medium text-white break-all">{label}</strong>. One standing authorization per host covers its linked web apps and services, and it covers the credentials attached to this target (to each target, when you authorize several). Scans and Hunts reuse it without asking again, and you can revoke it from the target menu.</p>
        : <p className="text-sm text-gray-400">Everything selected is already authorized.</p>}
      {pending.length > 1 && <ul className="max-h-40 overflow-y-auto rounded-lg border border-gray-800 bg-gray-950/40 p-2 font-mono text-xs text-gray-300">
        {pending.map(asset => <li key={asset.id} className="truncate px-1 py-0.5">{asset.locator}</li>)}
      </ul>}
      {pending.length > 0 && <Field label="Approved by" hint="Recorded on the authorization receipt."><Input value={approvedBy} maxLength={120} onChange={event => setApprovedBy(event.target.value)} /></Field>}
    </div>
  </Modal>
}
