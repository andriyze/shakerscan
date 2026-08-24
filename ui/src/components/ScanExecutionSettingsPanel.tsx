'use client'

import { useEffect, useState } from 'react'
import {
  getAutomationSettings,
  updateAutomationSettings,
  type AsmAutomationConfig,
  type AutomationSettings,
  type AutomationSettingsUpdate,
} from '@/lib/api'
import { Button, Card, ToggleField, useToast } from '@/components/ui'

const ASM_PRESETS: Array<{
  label: string
  description: string
  config: Partial<AsmAutomationConfig>
}> = [
  {
    label: 'Safe',
    description: 'Small batches, weekly recon',
    config: {
      batch_size: 50,
      stale_days: 30,
      min_interval_minutes: 60,
      daily_endpoint_cap: 2000,
      recon_interval_hours: 168,
      max_requests_per_hour_per_domain: 1000,
    },
  },
  {
    label: 'Quieter',
    description: 'Lower request pressure',
    config: {
      batch_size: 25,
      stale_days: 45,
      min_interval_minutes: 180,
      daily_endpoint_cap: 500,
      recon_interval_hours: 168,
      max_requests_per_hour_per_domain: 250,
    },
  },
  {
    label: 'Wider',
    description: 'More endpoint coverage',
    config: {
      batch_size: 100,
      stale_days: 14,
      min_interval_minutes: 30,
      daily_endpoint_cap: 5000,
      recon_interval_hours: 24,
      max_requests_per_hour_per_domain: 2500,
    },
  },
]

function countLabel(value: number, unit: string) {
  return `${value.toLocaleString()} ${unit}${value === 1 ? '' : 's'}`
}

function isCurrentPreset(config: AsmAutomationConfig | undefined, preset: Partial<AsmAutomationConfig>) {
  if (!config) return false
  return Object.entries(preset).every(([key, value]) => config[key as keyof AsmAutomationConfig] === value)
}

export default function ScanExecutionSettingsPanel() {
  const toast = useToast()
  const [settings, setSettings] = useState<AutomationSettings | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function load() {
    try {
      const data = await getAutomationSettings()
      setSettings(data)
      setError(null)
    } catch {
      setError('Automation settings unavailable')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    let cancelled = false
    async function loadIfMounted() {
      try {
        const data = await getAutomationSettings()
        if (!cancelled) {
          setSettings(data)
          setError(null)
        }
      } catch {
        if (!cancelled) setError('Automation settings unavailable')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    loadIfMounted()
    return () => {
      cancelled = true
    }
  }, [])

  async function save(update: AutomationSettingsUpdate, successMessage: string) {
    if (saving) return
    setSaving(true)
    try {
      const result = await updateAutomationSettings(update)
      setSettings(result.settings)
      toast.success(successMessage)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to update automation settings')
    } finally {
      setSaving(false)
    }
  }

  const scan = settings?.scan_execution
  const asm = settings?.default_continuous_asm
  const safety = settings?.safety_boundaries
  const research = settings?.research_agent
  const asmConfig = asm?.config
  const eligibleTypes = scan?.eligible_scan_types?.join(', ') || 'smart, full, aggressive'
  const workerText = scan?.running_workers == null
    ? 'worker count unavailable'
    : `${scan.running_workers} worker${scan.running_workers === 1 ? '' : 's'} running`

  return (
    <Card className="p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-medium text-white">Automation defaults</h2>
          <p className="mt-1 text-sm text-gray-400">
            Safe defaults for parallel scans and Continuous ASM. Per-scan Normal/Parallel and per-target ASM policy still override these defaults.
          </p>
        </div>
        <Button variant="ghost" size="sm" onClick={load} disabled={loading || saving}>
          Refresh
        </Button>
      </div>

      <div className="mt-4 grid gap-3 md:grid-cols-2">
        <ToggleField
          label="Auto-shard eligible scans"
          description={`${eligibleTypes}; ${workerText}`}
          checked={Boolean(scan?.auto_sharding_enabled)}
          disabled={loading || saving || !scan}
          onChange={(next) => save(
            { auto_sharding_enabled: next },
            next ? 'Auto-sharding enabled' : 'Auto-sharding disabled'
          )}
          className="p-3"
        >
          {scan && (
            <span className="mt-3 flex flex-wrap gap-2 text-[11px] text-gray-500">
              <span className="rounded border border-gray-800 px-2 py-1">Strategy: {scan.auto_sharding_strategy}</span>
              <span className="rounded border border-gray-800 px-2 py-1">Max shards: {scan.auto_sharding_max_shards}</span>
              <span className="rounded border border-gray-800 px-2 py-1">Min workers: {scan.auto_sharding_min_workers}</span>
            </span>
          )}
        </ToggleField>

        <ToggleField
          label="Continuous ASM for new web targets"
          description="New model-intake targets stay excluded. Existing targets keep their own policy."
          checked={Boolean(asm?.enabled_for_new_web_targets)}
          disabled={loading || saving || !asm}
          onChange={(next) => save(
            { default_asm_enabled: next },
            next ? 'Default Continuous ASM enabled' : 'Default Continuous ASM disabled'
          )}
          className="p-3"
        >
          {asmConfig && (
            <span className="mt-3 flex flex-wrap gap-2 text-[11px] text-gray-500">
              <span className="rounded border border-gray-800 px-2 py-1">{countLabel(asmConfig.batch_size, 'endpoint')} per batch</span>
              <span className="rounded border border-gray-800 px-2 py-1">Retest after {countLabel(asmConfig.stale_days, 'day')}</span>
              <span className="rounded border border-gray-800 px-2 py-1">{countLabel(asmConfig.daily_endpoint_cap, 'endpoint')}/day cap</span>
              <span className="rounded border border-gray-800 px-2 py-1">{countLabel(asmConfig.max_requests_per_hour_per_domain, 'request')}/hour/domain</span>
            </span>
          )}
        </ToggleField>
      </div>

      <details className="group mt-4 rounded-lg border border-gray-800 bg-gray-950/30">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-4 px-3 py-3 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-500 [&::-webkit-details-marker]:hidden">
          <div>
            <h3 className="text-sm font-medium text-gray-200">Advanced automation controls</h3>
            <p className="mt-1 text-xs text-gray-500">
              Hunt planner selection and approval-receipt enforcement.
            </p>
          </div>
          <span className="shrink-0 text-xs font-medium text-blue-400">
            <span className="group-open:hidden">Show</span>
            <span className="hidden group-open:inline">Hide</span>
          </span>
        </summary>

        <div className="space-y-3 border-t border-gray-800 p-3">
          <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-3">
            <div>
              <h3 className="text-sm font-medium text-gray-100">Default Hunt planner</h3>
              <p className="mt-1 text-xs text-gray-500">
                Sets who chooses each bounded research action. Individual hunts can override this.
              </p>
            </div>
            <div className="mt-3 grid gap-2 md:grid-cols-3">
              {([
                {
                  mode: 'agent' as const,
                  label: 'Current coding agent',
                  description: 'Default for clean installs; no separate provider key.',
                },
                {
                  mode: 'local_codex' as const,
                  label: 'Isolated local Codex',
                  description: 'Separate ephemeral codex exec planner processes.',
                },
                {
                  mode: 'configured_ai' as const,
                  label: 'Stored AI provider',
                  description: 'Unattended server autopilot using AI Settings.',
                },
              ]).map((option) => {
                const active = research?.default_planner_mode === option.mode
                return (
                  <button
                    key={option.mode}
                    type="button"
                    onClick={() => save(
                      { default_research_planner_mode: option.mode },
                      `Default Hunt planner set to ${option.label}`,
                    )}
                    disabled={loading || saving || !research}
                    className={`rounded-lg border px-3 py-2 text-left transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                      active
                        ? 'border-blue-500 bg-blue-600/15 text-blue-100'
                        : 'border-gray-800 bg-gray-950/40 text-gray-300 hover:bg-gray-800/70'
                    }`}
                  >
                    <div className="text-sm font-medium">{option.label}</div>
                    <div className="mt-1 text-xs leading-5 text-gray-500">{option.description}</div>
                  </button>
                )
              })}
            </div>
          </div>

          <ToggleField
            label="Require approval receipts"
            description="Enforce scope and approval receipts before queueing scans, ASM actions, AI Gate runs, Model Intake scans, or retests."
            checked={Boolean(safety?.approval_receipts_required_for_state_changing_actions)}
            disabled={loading || saving || !safety}
            onChange={(next) => save(
              { approval_receipts_required_for_state_changing_actions: next },
              next ? 'Approval receipt requirement enabled' : 'Approval receipt requirement disabled'
            )}
            className="p-3"
          >
            <span className="mt-3 flex flex-wrap gap-2 text-[11px] text-gray-500">
              <span className="rounded border border-gray-800 px-2 py-1">Scope preview required</span>
              <span className="rounded border border-gray-800 px-2 py-1">Approval receipt required</span>
              <span className="rounded border border-gray-800 px-2 py-1">Legacy mode: {safety?.approval_receipts_required_for_state_changing_actions ? 'blocked' : 'allowed'}</span>
            </span>
          </ToggleField>
        </div>
      </details>

      {asmConfig && (
        <div className="mt-4">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-xs font-medium uppercase tracking-wide text-gray-500">Default ASM Preset</h3>
            <span className="text-xs text-gray-500">Global exploit depth is locked off here</span>
          </div>
          <div className="grid gap-2 md:grid-cols-3">
            {ASM_PRESETS.map((preset) => {
              const active = isCurrentPreset(asmConfig, preset.config)
              return (
                <button
                  key={preset.label}
                  type="button"
                  onClick={() => save(
                    { default_asm_config: preset.config },
                    `Default ASM preset set to ${preset.label}`
                  )}
                  disabled={saving}
                  className={`rounded-lg border px-3 py-2 text-left transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                    active
                      ? 'border-blue-500 bg-blue-600/15 text-blue-100'
                      : 'border-gray-800 bg-gray-950/40 text-gray-300 hover:bg-gray-800/70'
                  }`}
                >
                  <div className="text-sm font-medium">{preset.label}</div>
                  <div className="mt-1 text-xs text-gray-500">{preset.description}</div>
                </button>
              )
            })}
          </div>
        </div>
      )}

      <div className="mt-4 flex flex-wrap gap-2 text-xs">
        <span className="rounded-full border border-green-500/30 bg-green-500/10 px-2 py-1 text-green-200">
          Safe automation bounded
        </span>
        <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-amber-200">
          Lab/deep requires explicit action
        </span>
        <span className="rounded-full border border-gray-700 px-2 py-1 text-gray-400">
          High-risk planned families fail closed
        </span>
      </div>

      <div className="mt-3 text-xs text-gray-500">
        {loading ? 'Loading automation settings...' : error ? <span className="text-red-400">{error}</span> : 'Explicit scan and target settings remain authoritative.'}
      </div>
    </Card>
  )
}
