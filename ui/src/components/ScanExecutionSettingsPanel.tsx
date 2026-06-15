'use client'

import { useEffect, useState } from 'react'
import {
  getScanExecutionSettings,
  updateScanExecutionSettings,
  type ScanExecutionSettings
} from '@/lib/api'
import { Button, Card, useToast } from '@/components/ui'

export default function ScanExecutionSettingsPanel() {
  const toast = useToast()
  const [settings, setSettings] = useState<ScanExecutionSettings | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const data = await getScanExecutionSettings()
        if (!cancelled) {
          setSettings(data)
          setError(null)
        }
      } catch {
        if (!cancelled) setError('Scan execution settings unavailable')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => {
      cancelled = true
    }
  }, [])

  async function toggleAutoSharding() {
    if (!settings || saving) return
    const nextEnabled = !settings.auto_sharding_enabled
    setSaving(true)
    try {
      const result = await updateScanExecutionSettings({ auto_sharding_enabled: nextEnabled })
      setSettings(result.settings)
      toast.success(nextEnabled ? 'Auto-sharding enabled' : 'Auto-sharding disabled')
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to update scan execution settings')
    } finally {
      setSaving(false)
    }
  }

  const eligibleTypes = settings?.eligible_scan_types?.join(', ') || 'smart, full, aggressive'
  const workerText = settings?.running_workers == null
    ? 'worker count unavailable'
    : `${settings.running_workers} worker${settings.running_workers === 1 ? '' : 's'} running`

  return (
    <Card className="p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-medium text-white">Scan Execution</h2>
          <p className="mt-1 text-sm text-gray-400">
            Auto-shard eligible scans across workers. Quick and passive scans stay single-worker unless endpoints are provided.
          </p>
        </div>
        <Button
          variant={settings?.auto_sharding_enabled ? 'primary' : 'secondary'}
          onClick={toggleAutoSharding}
          disabled={loading || saving || !settings}
        >
          {settings?.auto_sharding_enabled ? 'On' : 'Off'}
        </Button>
      </div>

      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-500">
        {loading ? (
          <span>Loading execution settings...</span>
        ) : error ? (
          <span className="text-red-400">{error}</span>
        ) : (
          <>
            <span>Eligible: {eligibleTypes}</span>
            <span>{workerText}</span>
            <span>Explicit Normal or Parallel on New Scan still overrides this setting.</span>
          </>
        )}
      </div>
    </Card>
  )
}
