'use client'

import { useState } from 'react'
import { getApiUrl } from '@/lib/api'
import { useToast } from '@/components/ui'

const API_URL = getApiUrl()

type RemediationStatus = 'open' | 'in_progress' | 'remediated' | 'false_positive' | 'accepted_risk'

// Map UI status to backend status
const STATUS_TO_BACKEND: Record<RemediationStatus, string> = {
  'open': 'active',
  'in_progress': 'active',
  'remediated': 'resolved',
  'false_positive': 'false_positive',
  'accepted_risk': 'accepted_risk'
}

type Props = {
  scanId: string
  findingId: string
  currentStatus: RemediationStatus
  currentNotes: string
  onStatusChange: (status: RemediationStatus, notes: string) => void
}

const STATUS_OPTIONS: { value: RemediationStatus; label: string; color: string }[] = [
  { value: 'open', label: 'Open', color: 'text-red-400' },
  { value: 'in_progress', label: 'In Progress', color: 'text-yellow-400' },
  { value: 'remediated', label: 'Remediated', color: 'text-green-400' },
  { value: 'false_positive', label: 'False Positive', color: 'text-blue-400' },
  { value: 'accepted_risk', label: 'Accepted Risk', color: 'text-purple-400' }
]

export default function FindingActions({
  scanId,
  findingId,
  currentStatus,
  currentNotes,
  onStatusChange
}: Props) {
  const [status, setStatus] = useState<RemediationStatus>(currentStatus)
  const [notes, setNotes] = useState(currentNotes)
  const [isExpanded, setIsExpanded] = useState(false)
  const [saving, setSaving] = useState(false)
  const toast = useToast()

  const handleSave = async () => {
    setSaving(true)
    try {
      // Use backend API to update finding status (pass scanId for precise scoping)
      const backendStatus = STATUS_TO_BACKEND[status]
      const url = `${API_URL}/findings/${findingId}?scan_id=${scanId}`
      const res = await fetch(url, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: backendStatus, notes })
      })
      if (res.ok) {
        onStatusChange(status, notes)
        setIsExpanded(false)
        toast.success('Finding status updated')
      } else {
        toast.error('Failed to update finding status')
      }
    } catch (err) {
      console.error('Failed to save remediation:', err)
      toast.error('Failed to update finding status')
    } finally {
      setSaving(false)
    }
  }

  const currentOption = STATUS_OPTIONS.find(o => o.value === status)

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-3">
        <span className="text-gray-500 text-xs">Status:</span>
        <select
          value={status}
          disabled={saving}
          onChange={(e) => {
            setStatus(e.target.value as RemediationStatus)
            setIsExpanded(true)
          }}
          aria-label="Finding status"
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs focus:outline-none focus:border-blue-500 focus-visible:ring-2 focus-visible:ring-blue-500 disabled:opacity-50"
        >
          {STATUS_OPTIONS.map(option => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
        <button
          type="button"
          onClick={() => setIsExpanded(!isExpanded)}
          aria-expanded={isExpanded}
          className="rounded text-gray-500 text-xs hover:text-gray-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
        >
          {isExpanded ? 'Hide' : 'Add notes'}
        </button>
      </div>

      {isExpanded && (
        <div className="space-y-2 pl-4">
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Add notes about this finding..."
            className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-300 placeholder-gray-500 focus:outline-none focus:border-blue-500 resize-none"
            rows={2}
          />
          <div className="flex gap-2">
            <button
              type="button"
              onClick={handleSave}
              disabled={saving}
              className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-xs rounded disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              {saving ? 'Saving...' : 'Save'}
            </button>
            <button
              type="button"
              onClick={() => {
                setStatus(currentStatus)
                setNotes(currentNotes)
                setIsExpanded(false)
              }}
              disabled={saving}
              className="px-3 py-1 bg-gray-700 hover:bg-gray-600 text-gray-300 text-xs rounded disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
