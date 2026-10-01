'use client'

import { useState } from 'react'
import { Button, Modal, fieldClasses } from '@/components/ui'
import type { PolicyProfile } from '@/lib/api'

export interface ExceptionFormValues {
  owner: string
  approver: string
  reason: string
  compensating_controls: string
  policy_id: string
  expires_days: string
}

export const EMPTY_EXCEPTION_FORM: ExceptionFormValues = {
  owner: '',
  approver: '',
  reason: '',
  compensating_controls: '',
  policy_id: '',
  expires_days: '30',
}

// Accepting risk records a time-limited policy exception the release gate honours. It is a
// deliberate act, so it lives in a dialog rather than an always-open form on the page.
export function ExceptionDialog({
  open,
  policyProfiles,
  saving,
  onClose,
  onSubmit,
}: {
  open: boolean
  policyProfiles: PolicyProfile[]
  saving: boolean
  onClose: () => void
  /** Resolves true when the exception was created. */
  onSubmit: (values: ExceptionFormValues) => Promise<boolean>
}) {
  const [form, setForm] = useState<ExceptionFormValues>(EMPTY_EXCEPTION_FORM)
  const set = (key: keyof ExceptionFormValues) => (event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) =>
    setForm((prev) => ({ ...prev, [key]: event.target.value }))

  async function submit(event: React.FormEvent) {
    event.preventDefault()
    if (await onSubmit(form)) {
      setForm(EMPTY_EXCEPTION_FORM)
      onClose()
    }
  }

  const activeProfiles = policyProfiles.filter((profile) => profile.is_active)
  const label = 'grid gap-1 text-sm text-gray-300'

  return (
    <Modal
      open={open}
      title="Accept risk with a policy exception"
      onClose={onClose}
      size="lg"
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={saving}>Cancel</Button>
          <Button type="submit" form="finding-exception-form" loading={saving} disabled={!form.policy_id}>
            {saving ? 'Creating...' : 'Create Exception'}
          </Button>
        </>
      }
    >
      <form id="finding-exception-form" onSubmit={submit} className="space-y-3">
        <p className="text-sm text-gray-400">
          The release gate stops blocking on this finding until the exception expires. The finding stays open; its status does not change.
        </p>
        <div className="grid gap-3 md:grid-cols-2">
          <label className={label}>
            Owner
            <input value={form.owner} onChange={set('owner')} className={fieldClasses()} placeholder="team or person" required />
          </label>
          <label className={label}>
            Approver
            <input value={form.approver} onChange={set('approver')} className={fieldClasses()} placeholder="security approver" required />
          </label>
          <label className={label}>
            Policy
            <select value={form.policy_id} onChange={set('policy_id')} className={fieldClasses()} required>
              <option value="">Select an exact policy…</option>
              {activeProfiles.map((profile) => (
                <option key={profile.id} value={profile.id}>{profile.name} ({profile.environment})</option>
              ))}
            </select>
          </label>
          <label className={label}>
            Expires in days
            <input value={form.expires_days} onChange={set('expires_days')} className={fieldClasses()} inputMode="numeric" min="1" required />
          </label>
        </div>
        <label className={label}>
          Reason
          <textarea value={form.reason} onChange={set('reason')} className={`min-h-20 ${fieldClasses()}`} placeholder="Risk acceptance rationale" required />
        </label>
        <label className={label}>
          Compensating controls
          <textarea value={form.compensating_controls} onChange={set('compensating_controls')} className={`min-h-20 ${fieldClasses()}`} placeholder="Controls, monitoring, or rollout constraints" required />
        </label>
      </form>
    </Modal>
  )
}
