'use client'

import { useEffect, useMemo, useState } from 'react'
import { Share2, X } from 'lucide-react'
import { Button, Field, Modal, Select } from '@/components/ui'
import { useToast } from '@/components/ui'
import { createTargetPolicyApprovalReceipt } from '@/lib/api'
import {
  grantCredentialProfile,
  listCredentialCapabilities,
  listCredentialGrants,
  revokeCredentialGrant,
  type CredentialGrant,
  type CredentialProfile,
  type CredentialTargetKind,
} from '@/lib/credentialApi'

export interface ShareTargetChoice {
  id: string
  kind: CredentialTargetKind
  label: string
  detail: string
  /** Whether the target has a web or API origin; undefined when the inventory did not say. */
  servesHttp?: boolean
}

const ASSET_KINDS: CredentialTargetKind[] = ['web', 'api', 'network', 'device']

// All physical-target kinds are views; sharing still needs an explicit target grant.
function sharesAsset(profileKind: CredentialTargetKind, targetKind: CredentialTargetKind): boolean {
  return profileKind === targetKind || (ASSET_KINDS.includes(profileKind) && ASSET_KINDS.includes(targetKind))
}

// The credential's protocol needs something to authenticate to: SSH a host or device, every
// other kind a web or API origin. The server enforces the same rule on the grant.
export function protocolFits(authKind: string, target: ShareTargetChoice): boolean {
  if (authKind.startsWith('ssh_')) return target.kind === 'network' || target.kind === 'device'
  return target.servesHttp !== false
}

/**
 * Where a credential is used, and sharing it with more targets. A share makes the credential
 * selectable on that target; Scans and Hunts there still need the target's own authorization.
 */
export function ShareCredentialDialog({
  profile,
  targets,
  onClose,
  onChanged,
}: {
  profile: CredentialProfile | null
  targets: ShareTargetChoice[]
  onClose: () => void
  onChanged: () => void
}) {
  const toast = useToast()
  const [grants, setGrants] = useState<CredentialGrant[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [targetId, setTargetId] = useState('')
  const [approveActive, setApproveActive] = useState(false)
  const [activeCapabilities, setActiveCapabilities] = useState<string[]>([])
  const [busy, setBusy] = useState(false)

  const profileId = profile?.id
  useEffect(() => {
    if (!profile) return
    let current = true
    setLoading(true)
    setError(null)
    setTargetId('')
    setApproveActive(false)
    Promise.all([
      listCredentialGrants(profile.id),
      listCredentialCapabilities({ target_kind: profile.target_kind, auth_kind: profile.auth_kind }).catch(() => null),
    ])
      .then(([grantResult, catalog]) => {
        if (!current) return
        setGrants(grantResult.grants || [])
        const active = new Set((catalog?.capabilities || []).filter((item) => item.requires_active_approval).map((item) => item.name))
        // An unknown capability is treated as the stricter case, as the server does.
        const known = new Set((catalog?.capabilities || []).map((item) => item.name))
        setActiveCapabilities(profile.allowed_capabilities.filter((name) => active.has(name) || !known.has(name)))
      })
      .catch((cause) => { if (current) setError(cause instanceof Error ? cause.message : 'Failed to load shares') })
      .finally(() => { if (current) setLoading(false) })
    return () => { current = false }
    // The profile's identity decides what to load; its other fields do not change while open.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profileId])

  const used = useMemo(() => new Set(grants.filter((grant) => grant.active).map((grant) => grant.target_id)), [grants])
  const choices = useMemo(() => (profile ? targets.filter((target) =>
    sharesAsset(profile.target_kind, target.kind) && protocolFits(profile.auth_kind, target)
    && target.id !== profile.target_id && !used.has(target.id)) : []),
  [profile, targets, used])
  const chosen = choices.find((target) => target.id === targetId)
  const needsApproval = activeCapabilities.length > 0

  if (!profile) return null
  const home = grants.find((grant) => grant.home)
  const homeName = home?.target_name || profile.home_target_name || 'its own target'

  async function reload() {
    if (!profile) return
    const result = await listCredentialGrants(profile.id)
    setGrants(result.grants || [])
    onChanged()
  }

  async function share() {
    if (!profile || !chosen) return
    setBusy(true)
    setError(null)
    try {
      const approval = needsApproval
        ? await createTargetPolicyApprovalReceipt({
            targetId: chosen.id,
            targetUrl: chosen.detail,
            riskTier: 'credential',
            environment: chosen.kind === 'device' || chosen.kind === 'network' ? 'lab' : 'production',
          })
        : null
      await grantCredentialProfile(profile.id, {
        target_kind: chosen.kind,
        target_id: chosen.id,
        approval_receipt_id: approval?.approvalReceiptId,
      })
      toast.success(`Shared with ${chosen.label}`)
      setTargetId('')
      setApproveActive(false)
      await reload()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Failed to share credential')
    } finally {
      setBusy(false)
    }
  }

  async function stopSharing(grant: CredentialGrant) {
    if (!profile) return
    setBusy(true)
    setError(null)
    try {
      await revokeCredentialGrant(profile.id, grant.target_id)
      toast.success(`Stopped sharing with ${grant.target_name || 'that target'}`)
      await reload()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Failed to stop sharing')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      title={`Share ${profile.name}`}
      onClose={() => { if (!busy) onClose() }}
      footer={<Button variant="secondary" disabled={busy} onClick={onClose}>Done</Button>}
    >
      <p className="text-sm text-gray-300">
        Targets it is shared with can select this credential for Scans and Hunts. Each still needs
        its own authorization, and the credential is only sent to that target.
      </p>
      <p className="mt-1 text-xs text-gray-500">
        It belongs to {homeName}: rotating or deactivating it there changes it everywhere, and deleting
        that target deletes it.
      </p>

      {error && <div role="alert" className="mt-4 rounded-sm border border-red-900/60 bg-red-950/30 p-3 text-sm text-red-300">{error}</div>}

      <h3 className="mt-5 text-xs font-semibold uppercase tracking-wide text-gray-500">Used by</h3>
      {loading ? (
        <p className="mt-2 text-sm text-gray-500">Loading…</p>
      ) : (
        <ul className="mt-2 divide-y divide-gray-800 rounded-md border border-gray-800" data-testid="credential-grants">
          {grants.filter((grant) => grant.active).map((grant) => (
            <li key={grant.target_id} className="flex items-center justify-between gap-3 px-3 py-2 text-sm">
              <span className="min-w-0">
                <span className="block truncate text-gray-100">{grant.target_name || grant.target_id}</span>
                {grant.target_locator && <span className="block truncate font-mono text-xs text-gray-500">{grant.target_locator}</span>}
              </span>
              {grant.home ? (
                <span className="shrink-0 rounded-sm bg-gray-800 px-2 py-0.5 text-xs text-gray-300">owner</span>
              ) : (
                <Button size="sm" variant="ghost" disabled={busy} onClick={() => void stopSharing(grant)} aria-label={`Stop sharing with ${grant.target_name || grant.target_id}`}>
                  <X className="h-4 w-4" /> Stop sharing
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}

      <div className="mt-5 grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
        <Field label="Share with target">
          <Select value={targetId} onChange={(event) => { setTargetId(event.target.value); setApproveActive(false) }} disabled={busy || loading}>
            <option value="">{choices.length ? 'Choose a target…' : 'No other target of this kind'}</option>
            {choices.map((target) => <option key={target.id} value={target.id}>{target.label} — {target.detail}</option>)}
          </Select>
        </Field>
        <Button onClick={() => void share()} disabled={!chosen || busy || (needsApproval && !approveActive)} loading={busy}>
          <Share2 className="h-4 w-4" /> Share
        </Button>
      </div>
      {needsApproval && chosen && (
        <label className="mt-3 flex items-start gap-2 rounded-sm border border-amber-700/50 bg-amber-500/10 p-2 text-xs text-amber-100">
          <input type="checkbox" checked={approveActive} onChange={(event) => setApproveActive(event.target.checked)} className="mt-0.5" />
          This credential allows active capabilities ({activeCapabilities.join(', ')}). I approve them for {chosen.label}.
        </label>
      )}
    </Modal>
  )
}
