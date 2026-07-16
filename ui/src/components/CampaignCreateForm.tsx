'use client'

import { useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { createCampaign, type Campaign } from '@/lib/api'
import { Button, useModalA11y } from '@/components/ui'
import { CAMPAIGN_TYPE_LABELS, RISK_TIERS } from '@/lib/constants'

const CAMPAIGN_TYPES = Object.keys(CAMPAIGN_TYPE_LABELS)

export default function CampaignCreateForm({
  open,
  onClose,
  onCreated,
}: {
  open: boolean
  onClose: () => void
  onCreated: (campaign: Campaign) => void
}) {
  const panelRef = useRef<HTMLDivElement>(null)
  const [objective, setObjective] = useState('')
  const [campaignType, setCampaignType] = useState(CAMPAIGN_TYPES[0])
  const [name, setName] = useState('')
  const [targetId, setTargetId] = useState('')
  const [riskTier, setRiskTier] = useState('read_only')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useModalA11y(open, panelRef, () => { if (!submitting) onClose() })

  if (!open || typeof document === 'undefined') return null

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!objective.trim()) { setError('Objective is required.'); return }
    setSubmitting(true)
    setError(null)
    try {
      const res = await createCampaign({
        objective: objective.trim(),
        campaign_type: campaignType,
        name: name.trim() || undefined,
        target_id: targetId.trim() || undefined,
        risk_tier: riskTier,
      })
      onCreated(res.campaign)
      // Reset for next open.
      setObjective(''); setName(''); setTargetId(''); setRiskTier('read_only')
      setCampaignType(CAMPAIGN_TYPES[0])
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create campaign')
    } finally {
      setSubmitting(false)
    }
  }

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      onClick={submitting ? undefined : onClose}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label="New campaign"
        className="w-full max-w-lg rounded-lg border border-gray-800 bg-gray-900 p-6 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 className="text-lg font-semibold text-white">New campaign</h2>
        <p className="mt-1 text-sm text-gray-400">
          Records a campaign for bookkeeping and deployment-impact rollup. Creating a campaign queues no scan work.
        </p>
        <form onSubmit={handleSubmit} className="mt-4 space-y-4">
          <div>
            <label htmlFor="campaign-objective" className="mb-1 block text-xs font-medium text-gray-400">
              Objective <span className="text-red-400">*</span>
            </label>
            <input
              id="campaign-objective"
              type="text"
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              placeholder="e.g. Validate authenticated BOLA coverage on the API"
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-600 focus:border-blue-500 focus:outline-none"
            />
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label htmlFor="campaign-type" className="mb-1 block text-xs font-medium text-gray-400">Type</label>
              <select
                id="campaign-type"
                value={campaignType}
                onChange={(e) => setCampaignType(e.target.value)}
                className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
              >
                {CAMPAIGN_TYPES.map((t) => (
                  <option key={t} value={t}>{CAMPAIGN_TYPE_LABELS[t]}</option>
                ))}
              </select>
            </div>
            <div>
              <label htmlFor="campaign-risk" className="mb-1 block text-xs font-medium text-gray-400">Risk tier</label>
              <select
                id="campaign-risk"
                value={riskTier}
                onChange={(e) => setRiskTier(e.target.value)}
                className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none"
              >
                {RISK_TIERS.map((t) => (
                  <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label htmlFor="campaign-name" className="mb-1 block text-xs font-medium text-gray-400">Name (optional)</label>
            <input
              id="campaign-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-600 focus:border-blue-500 focus:outline-none"
            />
          </div>
          <div>
            <label htmlFor="campaign-target" className="mb-1 block text-xs font-medium text-gray-400">Target ID (optional)</label>
            <input
              id="campaign-target"
              type="text"
              value={targetId}
              onChange={(e) => setTargetId(e.target.value)}
              placeholder="Target UUID"
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder-gray-600 focus:border-blue-500 focus:outline-none"
            />
          </div>
          {error && <p className="text-sm text-red-400">{error}</p>}
          <div className="flex justify-end gap-3">
            <Button variant="secondary" onClick={onClose} disabled={submitting}>Cancel</Button>
            <Button type="submit" disabled={submitting}>{submitting ? 'Creating…' : 'Create campaign'}</Button>
          </div>
        </form>
      </div>
    </div>,
    document.body
  )
}
