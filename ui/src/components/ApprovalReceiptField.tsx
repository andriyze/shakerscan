'use client'

import { useEffect, useState } from 'react'
import { createTargetPolicyApprovalReceipt } from '@/lib/api'
import { Button, Field } from '@/components/ui'

export function ApprovalReceiptField({
  targetId,
  targetUrl,
  authorizationConfirmed,
  receiptId,
  onReceiptIdChange,
  onScopeReceiptIdChange,
  environment,
  onEnvironmentChange,
  ttlMinutes,
  riskTier = 'active',
  required = false,
  disabledReason,
}: {
  targetId?: string
  targetUrl: string
  authorizationConfirmed: boolean
  receiptId: string
  onReceiptIdChange: (receiptId: string) => void
  onScopeReceiptIdChange?: (scopeReceiptId: string) => void
  environment?: 'production' | 'lab'
  onEnvironmentChange?: (environment: 'production' | 'lab') => void
  ttlMinutes: number
  riskTier?: 'active' | 'credential'
  required?: boolean
  disabledReason?: string
}) {
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [expiresAt, setExpiresAt] = useState<string | null>(null)
  const [localEnvironment, setLocalEnvironment] = useState<'production' | 'lab'>('production')
  const scopeEnvironment = environment ?? localEnvironment
  const missingTarget = !targetUrl.trim()
  const createDisabledReason = disabledReason
    || (missingTarget ? 'Choose one target first.' : null)
    || (!authorizationConfirmed ? 'Confirm that you are authorized to test this target first.' : null)

  useEffect(() => {
    setLocalEnvironment('production')
    onEnvironmentChange?.('production')
    setExpiresAt(null)
    setError(null)
  }, [targetId, targetUrl, onEnvironmentChange])

  async function createReceipt() {
    if (createDisabledReason) return
    setCreating(true)
    setError(null)
    try {
      const receipt = await createTargetPolicyApprovalReceipt({
        targetId,
        targetUrl,
        ttlMinutes,
        riskTier,
        environment: scopeEnvironment,
      })
      onReceiptIdChange(receipt.approvalReceiptId)
      onScopeReceiptIdChange?.(receipt.scopeReceiptId)
      setExpiresAt(receipt.expiresAt)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Failed to create approval receipt')
    } finally {
      setCreating(false)
    }
  }

  return (
    <div className="space-y-2 rounded-lg border border-gray-800 bg-gray-950 p-4">
      <Field
        label={`Approval receipt ID${required ? ' (required)' : ' (optional)'}`}
        hint="Use an existing target-bound receipt, or create one here after confirming authorization."
        required={required}
      >
        <input
          value={receiptId}
          onChange={(event) => {
            onReceiptIdChange(event.target.value)
            setExpiresAt(null)
          }}
          placeholder="Paste an existing receipt UUID"
          className="w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-white placeholder:text-gray-600"
        />
      </Field>
      <Field
        label="Approval scope environment"
        hint="Production blocks private and loopback destinations. Choose Lab/test only for an owned local fixture or device."
      >
        <select
          aria-label="Approval scope environment"
          value={scopeEnvironment}
          onChange={(event) => {
            const nextEnvironment = event.target.value as 'production' | 'lab'
            setLocalEnvironment(nextEnvironment)
            onEnvironmentChange?.(nextEnvironment)
            onReceiptIdChange('')
            onScopeReceiptIdChange?.('')
            setExpiresAt(null)
            setError(null)
          }}
          className="w-full rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-white"
        >
          <option value="production">Production / public target</option>
          <option value="lab">Lab / owned private target</option>
        </select>
      </Field>
      <div className="flex flex-wrap items-center gap-3">
        <Button type="button" variant="secondary" onClick={() => void createReceipt()} loading={creating} disabled={Boolean(createDisabledReason)}>
          Create approval for this target
        </Button>
        <span className="text-xs text-gray-500">
          Valid for about {Math.max(5, ttlMinutes)} minutes and bound to this target.
        </span>
      </div>
      {createDisabledReason && <p className="text-xs text-amber-300">{createDisabledReason}</p>}
      {expiresAt && <p role="status" className="text-xs text-emerald-300">Approval created. Expires {new Date(expiresAt).toLocaleString()}.</p>}
      {error && <p role="alert" className="text-xs text-red-300">{error}</p>}
    </div>
  )
}
