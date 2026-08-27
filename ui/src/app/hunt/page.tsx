'use client'

import { Suspense, useEffect, useMemo, useState } from 'react'
import { HUNT_SESSION_NON_AUTONOMOUS_NOTICE, huntStatusLabel } from '@/lib/labels'
import { useSearchParams } from 'next/navigation'
import Link from 'next/link'
import { Compass, ShieldCheck } from 'lucide-react'
import {
  getDevices,
  getDeviceAgentSession,
  getTargets,
  type DeviceAgentShellPlan,
  type DeviceAgentSession,
  type DeviceTarget,
  type Target,
} from '@/lib/api'
import {
  listCredentialProfiles,
  type CredentialPrincipalSlot,
  type CredentialProfile,
} from '@/lib/credentialApi'
import {
  cancelHuntV2,
  confirmHuntShellPlan,
  getHuntV2,
  listHuntsV2,
  startHuntV2Native,
  type HuntBudgetProfile,
  type HuntTargetKind,
  type HuntV2,
} from '@/lib/huntV2'
import {
  HUNT_BUDGET_DIMENSIONS,
  HUNT_BUDGET_PROFILES,
  type HuntZeroableBudgetDimension,
} from '@/lib/huntContract.generated'
import { Button, Card, EmptyState, Field, Select, Textarea, useToast } from '@/components/ui'
import { LegacyDeviceInvestigation } from '@/components/history/LegacyDeviceInvestigation'
import { RequestCollectionPicker } from '@/components/RequestCollectionPicker'
import { ApprovalReceiptField } from '@/components/ApprovalReceiptField'
import { usableWebTargets } from '@/lib/targetChoices'

type TargetChoice = {
  id: string
  sourceKind: 'web' | 'device'
  label: string
  detail: string
}

const CREDENTIAL_SLOT_LABELS: Record<CredentialPrincipalSlot, string> = {
  primary: 'Primary identity',
  secondary: 'Secondary identity',
  service: 'Service identity',
  ssh: 'SSH identity',
}

function splitIds(value: string): string[] {
  return Array.from(new Set(value.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean)))
}

function positiveInteger(value: string): number | undefined {
  if (!value.trim()) return undefined
  if (!/^\d+$/.test(value.trim())) return undefined
  const parsed = Number(value)
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : undefined
}

function huntActionStatusClass(status: string): string {
  if (status === 'completed') return 'bg-emerald-500/10 text-emerald-300'
  if (status === 'partial') return 'bg-amber-500/10 text-amber-300'
  if (status === 'blocked' || status === 'cancelled') return 'bg-gray-700 text-gray-300'
  if (status === 'failed') return 'bg-red-500/10 text-red-300'
  return 'bg-blue-500/10 text-blue-300'
}

function HuntHistory({
  targetId,
  runs,
  loading,
}: {
  targetId: string
  runs: HuntV2[]
  loading: boolean
}) {
  return (
    <Card className="p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="font-medium text-white">Recent Hunts for this target</h2>
          <p className="mt-1 text-xs text-gray-500">Open a durable run to inspect its policy, budget use, capabilities, scans, and outcome.</p>
        </div>
        <span className="text-xs text-gray-500">{runs.length} shown</span>
      </div>
      {loading ? (
        <p className="mt-4 text-sm text-gray-500">Loading Hunt history…</p>
      ) : runs.length === 0 ? (
        <p className="mt-4 text-sm text-gray-500">No canonical Hunts have been recorded for this target.</p>
      ) : (
        <div className="mt-4 divide-y divide-gray-800 rounded-lg border border-gray-800">
          {runs.map((run) => (
            <Link
              key={run.hunt_id}
              href={`/hunt?target=${encodeURIComponent(targetId)}&run=${encodeURIComponent(run.hunt_id)}`}
              className="block px-4 py-3 hover:bg-gray-800/60"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-sm font-medium text-gray-200">{run.objective}</span>
                <span className="rounded bg-gray-800 px-2 py-1 text-xs text-gray-300">{huntStatusLabel(run.status)}</span>
              </div>
              <p className="mt-1 text-xs text-gray-500">
                {run.target_kind} · {run.budget_profile} · {run.budget_used.agent_actions || 0} capability calls
                {run.created_at ? ` · ${new Date(run.created_at).toLocaleString()}` : ''}
              </p>
            </Link>
          ))}
        </div>
      )}
    </Card>
  )
}

const ZEROABLE_BUDGETS = HUNT_BUDGET_DIMENSIONS.filter((item) => item.zeroable)

function HuntContent() {
  const searchParams = useSearchParams()
  const toast = useToast()
  const [webTargets, setWebTargets] = useState<Target[]>([])
  const [devices, setDevices] = useState<DeviceTarget[]>([])
  const [targetId, setTargetId] = useState('')
  const [webTargetKind, setWebTargetKind] = useState<Exclude<HuntTargetKind, 'device'>>('web')
  const [objective, setObjective] = useState(
    'Find exploitable vulnerabilities and record evidence-backed candidates.',
  )
  const [budget, setBudget] = useState<HuntBudgetProfile>('balanced')
  const [maxDurationSeconds, setMaxDurationSeconds] = useState('')
  const [maxHttpRequests, setMaxHttpRequests] = useState('')
  const [zeroableBudgets, setZeroableBudgets] = useState<
    Partial<Record<HuntZeroableBudgetDimension, string>>
  >({})
  const [activeTesting, setActiveTesting] = useState(false)
  const [networkDiscovery, setNetworkDiscovery] = useState(false)
  const [allowStateChanging, setAllowStateChanging] = useState(false)
  const [allowOobInteractions, setAllowOobInteractions] = useState(false)
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false)
  const [scopeReceipt, setScopeReceipt] = useState('')
  const [approvalReceipt, setApprovalReceipt] = useState('')
  const [capabilityIds, setCapabilityIds] = useState('')
  const [requestCollectionIds, setRequestCollectionIds] = useState<string[]>([])
  const [credentialProfiles, setCredentialProfiles] = useState<CredentialProfile[]>([])
  const [credentialIds, setCredentialIds] = useState<Record<CredentialPrincipalSlot, string>>({
    primary: '',
    secondary: '',
    service: '',
    ssh: '',
  })
  const [credentialsLoading, setCredentialsLoading] = useState(false)
  const [credentialError, setCredentialError] = useState<string | null>(null)
  const [hunt, setHunt] = useState<HuntV2 | null>(null)
  const [huntHistory, setHuntHistory] = useState<HuntV2[]>([])
  const [huntHistoryLoading, setHuntHistoryLoading] = useState(false)
  const [legacyDeviceRun, setLegacyDeviceRun] = useState<DeviceAgentSession | null>(null)
  const [legacyRunLoading, setLegacyRunLoading] = useState(false)
  const [loading, setLoading] = useState(true)
  const [starting, setStarting] = useState(false)
  const [confirmingPlanId, setConfirmingPlanId] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    Promise.all([
      getTargets(),
      getDevices({ limit: 200 }).catch(() => ({ devices: [] as DeviceTarget[] })),
    ])
      .then(([targetRows, deviceRows]) => {
        if (cancelled) return
        const targets = Array.isArray(targetRows?.targets)
          ? targetRows.targets
          : Array.isArray(targetRows)
            ? targetRows
            : []
        setWebTargets(usableWebTargets(targets))
        setDevices(deviceRows.devices || [])
        const requested = searchParams.get('target') || searchParams.get('target_id')
        if (requested) setTargetId(requested)
        const requestedObjective = searchParams.get('objective')
        if (requestedObjective) setObjective(requestedObjective)
      })
      .catch((cause) => setError(cause instanceof Error ? cause.message : 'Failed to load targets'))
      .finally(() => setLoading(false))
    return () => { cancelled = true }
  }, [searchParams])

  useEffect(() => {
    const legacyRunId = searchParams.get('legacy_run')
    if (!legacyRunId) {
      setLegacyDeviceRun(null)
      setLegacyRunLoading(false)
      return
    }
    let cancelled = false
    setLegacyRunLoading(true)
    setError(null)
    getDeviceAgentSession(legacyRunId)
      .then((run) => {
        if (cancelled) return
        setLegacyDeviceRun(run)
        setTargetId(run.device_target_id)
      })
      .catch((cause) => {
        if (!cancelled) setError(cause instanceof Error ? cause.message : 'Failed to load legacy device investigation')
      })
      .finally(() => { if (!cancelled) setLegacyRunLoading(false) })
    return () => { cancelled = true }
  }, [searchParams])

  useEffect(() => {
    const runId = searchParams.get('run')
    if (!runId) return
    let cancelled = false
    setError(null)
    getHuntV2(runId)
      .then((run) => {
        if (cancelled) return
        setHunt(run)
        setTargetId(run.target_id)
      })
      .catch((cause) => {
        if (!cancelled) setError(cause instanceof Error ? cause.message : 'Failed to load Hunt')
      })
    return () => { cancelled = true }
  }, [searchParams])

  const choices = useMemo<TargetChoice[]>(() => [
    ...webTargets.map((target) => ({
      id: target.id,
      sourceKind: 'web' as const,
      label: target.name || target.url,
      detail: target.url,
    })),
    ...devices.filter((device) => device.is_active).map((device) => ({
      id: device.id,
      sourceKind: 'device' as const,
      label: device.name,
      detail: device.primary_locator,
    })),
  ], [webTargets, devices])
  const selectedChoice = choices.find((choice) => choice.id === targetId)
  const targetKind: HuntTargetKind = selectedChoice?.sourceKind === 'device'
    ? 'device'
    : webTargetKind

  useEffect(() => {
    let cancelled = false
    setHuntHistory([])
    if (!selectedChoice) {
      setHuntHistoryLoading(false)
      return () => { cancelled = true }
    }
    setHuntHistoryLoading(true)
    listHuntsV2({ targetId: selectedChoice.id, limit: 12 })
      .then(({ hunts }) => { if (!cancelled) setHuntHistory(hunts) })
      .catch(() => { if (!cancelled) setHuntHistory([]) })
      .finally(() => { if (!cancelled) setHuntHistoryLoading(false) })
    return () => { cancelled = true }
  }, [selectedChoice?.id])

  useEffect(() => {
    let cancelled = false
    setCredentialIds({ primary: '', secondary: '', service: '', ssh: '' })
    setCredentialProfiles([])
    setCredentialError(null)
    if (!selectedChoice) return () => { cancelled = true }
    setCredentialsLoading(true)
    listCredentialProfiles({
      target_kind: targetKind,
      target_id: selectedChoice.id,
    })
      .then(({ profiles }) => {
        if (!cancelled) {
          setCredentialProfiles(
            profiles.filter((profile) => profile.execution_compatible),
          )
        }
      })
      .catch((cause) => {
        if (!cancelled) {
          setCredentialProfiles([])
          setCredentialError(cause instanceof Error ? cause.message : 'Failed to load credential profiles')
        }
      })
      .finally(() => { if (!cancelled) setCredentialsLoading(false) })
    return () => { cancelled = true }
  }, [selectedChoice?.id, targetKind])

  useEffect(() => {
    if (!hunt || !['active', 'awaiting_planner'].includes(hunt.status)) return
    let cancelled = false
    const refresh = () => getHuntV2(hunt.hunt_id)
      .then((current) => { if (!cancelled) setHunt(current) })
      .catch(() => undefined)
    const timer = window.setInterval(refresh, 5000)
    return () => { cancelled = true; window.clearInterval(timer) }
  }, [hunt?.hunt_id, hunt?.status])

  const shellPlans = useMemo<DeviceAgentShellPlan[]>(() => {
    const deviceState = hunt?.context_pack?.device_state
    if (!deviceState || typeof deviceState !== 'object' || Array.isArray(deviceState)) return []
    const plans = (deviceState as { shell_plans?: unknown }).shell_plans
    return Array.isArray(plans)
      ? plans.filter((plan): plan is DeviceAgentShellPlan => Boolean(
          plan && typeof plan === 'object' && 'plan_id' in plan,
        ))
      : []
  }, [hunt?.context_pack])

  const selectedCredentialCount = Object.values(credentialIds).filter(Boolean).length
  const privileged = activeTesting || networkDiscovery || allowStateChanging || allowOobInteractions || selectedCredentialCount > 0
  const configuredDuration = positiveInteger(maxDurationSeconds)
  const approvalTtlMinutes = Math.ceil((configuredDuration ?? HUNT_BUDGET_PROFILES[budget].max_duration_seconds) / 60) + 15
  const startBlockedReason = !targetId
    ? 'Choose a target to continue.'
    : !objective.trim()
      ? 'Describe what the Hunt should investigate.'
      : privileged && !authorizationConfirmed
        ? 'Confirm that you are authorized to use the selected capabilities.'
        : privileged && !approvalReceipt.trim()
          ? 'Create or paste a target-bound approval receipt.'
          : null
  const visibleCredentialSlots: CredentialPrincipalSlot[] = targetKind === 'network'
    ? ['ssh']
    : targetKind === 'device'
      ? ['primary', 'secondary', 'service', 'ssh']
      : ['primary', 'secondary', 'service']

  useEffect(() => {
    if (targetKind === 'network') setRequestCollectionIds([])
  }, [targetKind])

  async function start() {
    if (!targetId || !selectedChoice) return
    setStarting(true)
    setError(null)
    try {
      if (networkDiscovery && !activeTesting) {
        throw new Error('Network discovery requires active testing.')
      }
      if (allowStateChanging && !activeTesting) {
        throw new Error('State-changing HTTP requires active testing.')
      }
      if (allowOobInteractions && !activeTesting) {
        throw new Error('Out-of-band interactions require active testing.')
      }
      if (privileged && !authorizationConfirmed) {
        throw new Error('Confirm that you own or are authorized to test this target.')
      }
      if (privileged && !approvalReceipt.trim()) {
        throw new Error('Privileged Hunt capabilities require a target-bound approval receipt.')
      }

      const duration = positiveInteger(maxDurationSeconds)
      const requests = positiveInteger(maxHttpRequests)
      if (maxDurationSeconds.trim() && duration === undefined) {
        throw new Error('Maximum duration must be a positive whole number.')
      }
      if (maxHttpRequests.trim() && requests === undefined) {
        throw new Error('Maximum HTTP requests must be a positive whole number.')
      }
      const budgets: Record<string, number> = {
        ...(duration ? { max_duration_seconds: duration } : {}),
        ...(requests ? { max_http_requests: requests } : {}),
      }
      for (const definition of ZEROABLE_BUDGETS) {
        const raw = zeroableBudgets[definition.name]
        if (!raw?.trim()) continue
        if (!/^\d+$/.test(raw.trim())) {
          throw new Error(`${definition.label} must be zero or a positive whole number.`)
        }
        const parsed = Number(raw)
        if (!Number.isSafeInteger(parsed) || parsed > HUNT_BUDGET_PROFILES[budget][definition.name]) {
          throw new Error(`${definition.label} exceeds the ${budget} profile ceiling.`)
        }
        budgets[definition.name] = parsed
      }
      const credentialRefs: Record<string, string> = {
        ...(credentialIds.primary
          ? { primary_credential_profile_id: credentialIds.primary }
          : {}),
        ...(credentialIds.secondary
          ? { secondary_credential_profile_id: credentialIds.secondary }
          : {}),
        ...(credentialIds.service
          ? { service_credential_profile_id: credentialIds.service }
          : {}),
        ...(credentialIds.ssh
          ? { ssh_credential_profile_id: credentialIds.ssh }
          : {}),
      }
      const created = await startHuntV2Native({
        targetId,
        targetKind,
        goal: objective.trim(),
        budgetProfile: budget,
        budgets,
        policy: {
          activeTesting,
          allowStateChangingHttp: allowStateChanging,
          networkDiscovery,
          allowOobInteractions,
          authorizationConfirmed,
          approvalReceiptId: approvalReceipt.trim() || undefined,
          scopeReceiptId: scopeReceipt.trim() || undefined,
        },
        credentialRefs,
        capabilities: splitIds(capabilityIds),
        requestCollectionIds,
      })
      setHunt(created)
      window.history.pushState(
        null,
        '',
        `/hunt?target=${encodeURIComponent(created.target_id)}&run=${encodeURIComponent(created.hunt_id)}`,
      )
      toast.success('Agent Hunt Session opened through the V2 policy contract')
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : 'Failed to start Hunt'
      setError(message)
      toast.error(message)
    } finally {
      setStarting(false)
    }
  }

  async function confirmShellPlan(plan: DeviceAgentShellPlan) {
    if (!hunt) return
    setConfirmingPlanId(plan.plan_id)
    try {
      setHunt(await confirmHuntShellPlan(hunt.hunt_id, plan))
      toast.success('Exact SSH command plan queued')
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Failed to confirm SSH command plan')
    } finally {
      setConfirmingPlanId(null)
    }
  }

  async function cancel() {
    if (!hunt) return
    try {
      setHunt(await cancelHuntV2(hunt.hunt_id))
      toast.success('Agent Hunt Session cancelled')
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : 'Failed to cancel Hunt')
    }
  }

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div className="flex items-start gap-3">
        <div className="rounded-lg bg-violet-500/10 p-2 text-violet-300">
          <Compass className="h-6 w-6" />
        </div>
        <div>
          <h1 className="text-2xl font-semibold text-white">Agent Hunt Session</h1>
          <p className="mt-1 text-sm text-gray-400">
            An evidence-driven capability session your coding agent drives for web, API, network, and connected-device targets. It does not investigate on its own — the agent proposes each permitted capability call and the runtime executes and proves it.
          </p>
        </div>
      </div>

      {legacyRunLoading ? (
        <Card className="p-5 text-sm text-gray-400">Loading historical device investigation…</Card>
      ) : legacyDeviceRun ? (
        <LegacyDeviceInvestigation run={legacyDeviceRun} />
      ) : !hunt ? (
        <>
          <Card className="space-y-5 p-5">
          {loading ? <p className="text-sm text-gray-400">Loading targets…</p> : choices.length === 0 ? (
            <EmptyState message="No targets available" hint="Add a web or connected-device target first." />
          ) : (
            <>
              <Field label="Target">
                <Select value={targetId} onChange={(event) => setTargetId(event.target.value)}>
                  <option value="">Choose a target</option>
                  {choices.map((choice) => (
                    <option key={`${choice.sourceKind}:${choice.id}`} value={choice.id}>
                      {choice.sourceKind === 'device' ? 'Device' : 'Web asset'} · {choice.label} · {choice.detail}
                    </option>
                  ))}
                </Select>
              </Field>

              {selectedChoice?.sourceKind === 'web' && (
                <Field label="Hunt target kind">
                  <Select
                    value={webTargetKind}
                    onChange={(event) => setWebTargetKind(event.target.value as typeof webTargetKind)}
                  >
                    <option value="web">Web application</option>
                    <option value="api">API</option>
                    <option value="network">Network scope</option>
                  </Select>
                </Field>
              )}

              <Field label="Objective">
                <Textarea rows={4} value={objective} onChange={(event) => setObjective(event.target.value)} />
              </Field>

              <Field label="Budget profile">
                <Select value={budget} onChange={(event) => setBudget(event.target.value as HuntBudgetProfile)}>
                  <option value="fast">Fast</option>
                  <option value="balanced">Balanced</option>
                  <option value="thorough">Thorough</option>
                </Select>
              </Field>

              <div className="grid gap-4 md:grid-cols-2">
                <label className="text-sm text-gray-300">
                  Optional maximum duration (seconds)
                  <input
                    type="number"
                    min="1"
                    value={maxDurationSeconds}
                    onChange={(event) => setMaxDurationSeconds(event.target.value)}
                    className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-white"
                  />
                </label>
                <label className="text-sm text-gray-300">
                  Optional maximum HTTP requests
                  <input
                    type="number"
                    min="1"
                    value={maxHttpRequests}
                    onChange={(event) => setMaxHttpRequests(event.target.value)}
                    className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-white"
                  />
                </label>
              </div>

              <details className="rounded-lg border border-gray-800 bg-gray-950 p-4">
                <summary className="cursor-pointer text-sm font-medium text-white">
                  Optional hard ceilings (zero disables a dimension)
                </summary>
                <div className="mt-4 grid gap-4 md:grid-cols-2">
                  {ZEROABLE_BUDGETS.map((definition) => (
                    <label key={definition.name} className="text-sm text-gray-300">
                      {definition.label}
                      <input
                        type="number"
                        min="0"
                        max={HUNT_BUDGET_PROFILES[budget][definition.name]}
                        value={zeroableBudgets[definition.name] ?? ''}
                        onChange={(event) => setZeroableBudgets((current) => ({
                          ...current,
                          [definition.name]: event.target.value,
                        }))}
                        placeholder={`Profile ceiling: ${HUNT_BUDGET_PROFILES[budget][definition.name]}`}
                        className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-white"
                      />
                    </label>
                  ))}
                </div>
              </details>

              <div className="space-y-3 rounded-lg border border-gray-800 bg-gray-950 p-4">
                <div>
                  <h2 className="text-sm font-medium text-white">Runtime authority</h2>
                  <p className="mt-1 text-xs text-gray-500">
                    These controls are persisted and enforced independently of the AI planner.
                  </p>
                </div>
                <label className="flex items-start gap-3 text-sm text-gray-300">
                  <input
                    className="mt-1"
                    type="checkbox"
                    checked={activeTesting}
                    onChange={(event) => {
                      setActiveTesting(event.target.checked)
                      if (!event.target.checked) {
                        setNetworkDiscovery(false)
                        setAllowStateChanging(false)
                        setAllowOobInteractions(false)
                        setRequestCollectionIds([])
                      }
                    }}
                  />
                  <span>Allow bounded active testing</span>
                </label>
                <label className={`flex items-start gap-3 text-sm ${activeTesting ? 'text-gray-300' : 'text-gray-600'}`}>
                  <input
                    className="mt-1"
                    type="checkbox"
                    disabled={!activeTesting}
                    checked={networkDiscovery}
                    onChange={(event) => setNetworkDiscovery(event.target.checked)}
                  />
                  <span>Allow TCP service discovery and fingerprinting</span>
                </label>
                <label className={`flex items-start gap-3 text-sm ${activeTesting ? 'text-gray-300' : 'text-gray-600'}`}>
                  <input
                    className="mt-1"
                    type="checkbox"
                    disabled={!activeTesting}
                    checked={allowStateChanging}
                    onChange={(event) => {
                      setAllowStateChanging(event.target.checked)
                      if (!event.target.checked) setRequestCollectionIds([])
                    }}
                  />
                  <span>Allow explicitly selected state-changing HTTP requests</span>
                </label>
                <label className={`flex items-start gap-3 text-sm ${activeTesting ? 'text-gray-300' : 'text-gray-600'}`}>
                  <input
                    className="mt-1"
                    type="checkbox"
                    disabled={!activeTesting}
                    checked={allowOobInteractions}
                    onChange={(event) => setAllowOobInteractions(event.target.checked)}
                  />
                  <span>Allow bounded out-of-band callbacks when a registered verifier requires them</span>
                </label>
                {privileged && (
                  <label className="flex items-start gap-3 rounded-lg border border-amber-800/70 bg-amber-950/20 p-3 text-sm text-amber-100">
                    <input
                      className="mt-1"
                      type="checkbox"
                      checked={authorizationConfirmed}
                      onChange={(event) => setAuthorizationConfirmed(event.target.checked)}
                    />
                    <span>I own or have explicit authorization to test this target with the selected capabilities.</span>
                  </label>
                )}
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <label className="text-sm text-gray-300">
                  Scope receipt ID (optional)
                  <input
                    value={scopeReceipt}
                    onChange={(event) => setScopeReceipt(event.target.value)}
                    className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-white"
                  />
                </label>
              </div>
              {(privileged || approvalReceipt) && (
                <ApprovalReceiptField
                  targetId={selectedChoice?.id}
                  targetUrl={selectedChoice?.detail || ''}
                  authorizationConfirmed={authorizationConfirmed}
                  receiptId={approvalReceipt}
                  onReceiptIdChange={setApprovalReceipt}
                  onScopeReceiptIdChange={setScopeReceipt}
                  ttlMinutes={approvalTtlMinutes}
                  riskTier={selectedCredentialCount > 0 ? 'credential' : 'active'}
                  required={privileged}
                />
              )}

              <div className="space-y-4 rounded-lg border border-gray-800 bg-gray-950 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h2 className="text-sm font-medium text-white">Bound credential profiles</h2>
                    <p className="mt-1 text-xs text-gray-500">
                      Select encrypted identities for this exact target. The planner receives only profile metadata.
                    </p>
                  </div>
                  <Link href="/credentials" className="text-xs text-blue-300 hover:text-blue-200">
                    Manage credentials
                  </Link>
                </div>
                {credentialsLoading ? (
                  <p className="text-xs text-gray-500">Loading credential profiles…</p>
                ) : (
                  <div className="grid gap-4 md:grid-cols-2">
                    {visibleCredentialSlots.map((slot) => {
                      const candidates = credentialProfiles.filter((profile) => profile.principal_slot === slot)
                      return (
                        <Field key={slot} label={`${CREDENTIAL_SLOT_LABELS[slot]} (optional)`}>
                          <Select
                            value={credentialIds[slot]}
                            onChange={(event) => setCredentialIds((current) => ({
                              ...current,
                              [slot]: event.target.value,
                            }))}
                          >
                            <option value="">{slot === 'ssh' ? 'No SSH command proposals' : `No ${slot} identity`}</option>
                            {candidates.map((profile) => (
                              <option key={profile.id} value={profile.id}>
                                {profile.name} · {profile.auth_kind.replaceAll('_', ' ')} · v{profile.current_version}
                              </option>
                            ))}
                          </Select>
                        </Field>
                      )
                    })}
                  </div>
                )}
                {credentialError && <p className="text-xs text-amber-300">{credentialError}</p>}
                <p className="text-xs text-gray-500">
                  Credential use requires a target-bound approval receipt. No SSH command runs until you separately confirm the exact immutable plan.
                </p>
              </div>

              {targetKind !== 'network' && (
                <RequestCollectionPicker
                  targetId={selectedChoice?.id}
                  targetKind={targetKind}
                  selectedIds={requestCollectionIds}
                  onChange={setRequestCollectionIds}
                  allowConfirmedActive={activeTesting && allowStateChanging}
                />
              )}

              <Field
                label="Capability allowlist (optional)"
                hint="Leave empty for the server-defined capabilities allowed by this target and policy."
              >
                <input
                  value={capabilityIds}
                  onChange={(event) => setCapabilityIds(event.target.value)}
                  placeholder="web.probe, web.crawl, templates.scan"
                  className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white"
                />
              </Field>

              {error && (
                <p role="alert" className="rounded-lg border border-red-800 bg-red-950/30 p-3 text-sm text-red-300">
                  {error}
                </p>
              )}
              <div className="flex flex-wrap items-center justify-between gap-3">
                <p id="hunt-start-guidance" className={`text-xs ${startBlockedReason ? 'text-amber-300' : 'text-gray-500'}`}>
                  {startBlockedReason || 'Ready to start. The runtime will enforce the target, policy, and budget shown above.'}
                </p>
                <Button onClick={start} loading={starting} disabled={Boolean(startBlockedReason)} aria-describedby="hunt-start-guidance">
                  Open agent session
                </Button>
              </div>
            </>
          )}
          </Card>
          {selectedChoice && (
            <HuntHistory
              targetId={selectedChoice.id}
              runs={huntHistory}
              loading={huntHistoryLoading}
            />
          )}
        </>
      ) : (
        <div className="grid gap-5 lg:grid-cols-[1fr_1.4fr]">
          <div className="space-y-5">
            <Card className="space-y-4 p-5">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-xs uppercase tracking-wide text-gray-500">{hunt.target_kind} Hunt</p>
                  <h2 className="mt-1 font-medium text-white">{hunt.objective}</h2>
                </div>
                <span className="rounded bg-blue-500/10 px-2 py-1 text-xs text-blue-300">{huntStatusLabel(hunt.status)}</span>
              </div>
              <div className="grid grid-cols-2 gap-3 text-sm">
                <div className="rounded bg-gray-950 p-3">
                  <span className="block text-xs text-gray-500">Budget</span>
                  <span className="text-white">{hunt.budget_profile}</span>
                </div>
                <div className="rounded bg-gray-950 p-3">
                  <span className="block text-xs text-gray-500">Capability calls</span>
                  <span className="text-white">
                    {hunt.budget_used.agent_actions || 0} / {hunt.budget.max_capability_calls || 0}
                  </span>
                </div>
                <div className="col-span-2 rounded bg-gray-950 p-3">
                  <span className="block text-xs text-gray-500">Run ID</span>
                  <code className="break-all text-xs text-gray-300">{hunt.hunt_id}</code>
                </div>
              </div>
              {hunt.created_at && <p className="text-xs text-gray-500">Started {new Date(hunt.created_at).toLocaleString()}</p>}
              {hunt.status === 'active' && (
                <p className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 text-xs text-blue-100/80">
                  {HUNT_SESSION_NON_AUTONOMOUS_NOTICE}
                </p>
              )}
              {hunt.stop_reason && <p className="text-sm text-amber-200">Stopped: {hunt.stop_reason.replaceAll('_', ' ')}</p>}
              {hunt.queued_scan?.scan_id && (
                <Link href={`/scans/${hunt.queued_scan.scan_id}`} className="block rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 text-sm text-blue-200 hover:bg-blue-500/10">
                  Open queued Scan {hunt.queued_scan.scan_id.slice(0, 8)} · {hunt.queued_scan.status}
                </Link>
              )}
              {hunt.final_debrief?.summary && (
                <div className="rounded-lg border border-gray-800 bg-gray-950 p-3">
                  <p className="text-xs uppercase tracking-wide text-gray-500">Final debrief</p>
                  <p className="mt-2 text-sm text-gray-300">{hunt.final_debrief.summary}</p>
                  {hunt.final_debrief.next_actions && hunt.final_debrief.next_actions.length > 0 && (
                    <ul className="mt-2 list-disc space-y-1 pl-5 text-xs text-gray-400">
                      {hunt.final_debrief.next_actions.map((action) => <li key={action}>{action}</li>)}
                    </ul>
                  )}
                </div>
              )}
              <div className="flex items-start gap-2 rounded-lg border border-gray-800 bg-gray-950 p-3 text-xs text-gray-400">
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
                The runtime binds every capability to this target and the persisted V2 policy. Candidates cannot self-promote into verified findings.
              </div>
              {['active', 'awaiting_planner'].includes(hunt.status) && (
                <Button variant="danger" onClick={cancel}>Cancel session</Button>
              )}
              <Link href={`/hunt?target=${encodeURIComponent(hunt.target_id)}`} className="text-sm text-blue-300 hover:text-blue-200">
                Back to launcher and history
              </Link>
            </Card>

            {hunt.target_kind === 'device' && shellPlans.length > 0 && (
              <Card className="space-y-4 p-5">
                <div>
                  <h2 className="font-medium text-white">SSH command plans</h2>
                  <p className="mt-1 text-xs text-gray-500">
                    Review every command. Plans are immutable, host-key pinned, and expire after 30 minutes.
                  </p>
                </div>
                {shellPlans.map((plan) => (
                  <div key={plan.plan_id} className="space-y-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-4">
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-sm font-medium text-amber-100">Port {plan.ssh_port} · {plan.status}</span>
                      <span className="text-xs text-gray-500">Expires {new Date(plan.expires_at).toLocaleString()}</span>
                    </div>
                    <p className="text-xs text-gray-300">{plan.purpose}</p>
                    <pre className="overflow-x-auto whitespace-pre-wrap rounded bg-gray-950 p-3 text-xs text-blue-200">
                      {plan.commands.join('\n')}
                    </pre>
                    <div className="space-y-1 text-xs text-gray-400">
                      <p><span className="text-gray-500">Risk:</span> {plan.risk_summary}</p>
                      <p className="break-all"><span className="text-gray-500">Pinned host key:</span> {plan.expected_host_key_fingerprint}</p>
                      <p className="break-all"><span className="text-gray-500">Plan digest:</span> {plan.plan_digest}</p>
                    </div>
                    {plan.status === 'proposed' && (
                      <Button onClick={() => confirmShellPlan(plan)} loading={confirmingPlanId === plan.plan_id}>
                        Confirm and queue these exact remote commands
                      </Button>
                    )}
                    {plan.scan_id && <p className="text-xs text-emerald-300">Queued scan: {plan.scan_id}</p>}
                  </div>
                ))}
              </Card>
            )}
          </div>

          <div className="space-y-5">
            <Card className="p-5">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="font-medium text-white">Capability action ledger</h2>
                  <p className="mt-1 text-xs text-gray-500">
                    Canonical receipts and content-safe outcomes for every capability call in this run.
                  </p>
                </div>
                <span className="text-xs text-gray-500">{(hunt.actions || []).length} recorded</span>
              </div>
              {(hunt.actions || []).length === 0 ? (
                <p className="mt-4 text-sm text-gray-500">No capability actions were recorded.</p>
              ) : (
                <div className="mt-4 space-y-3">
                  {(hunt.actions || []).map((action) => {
                    const references = action.result.reference_ids
                    const budget = Object.entries(action.result.budget_consumed)
                    return (
                      <div key={action.action_id} className="rounded-lg border border-gray-800 bg-gray-950 p-3">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <code className="text-sm text-blue-300">{action.capability_name}</code>
                          <span className={`rounded px-2 py-1 text-xs ${huntActionStatusClass(action.status)}`}>
                            {action.status.replaceAll('_', ' ')}
                          </span>
                        </div>
                        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-400">
                          <span>{action.result.observation_count} observations</span>
                          {action.started_at && <span>Started {new Date(action.started_at).toLocaleString()}</span>}
                          {action.completed_at && <span>Finished {new Date(action.completed_at).toLocaleString()}</span>}
                        </div>
                        {budget.length > 0 && (
                          <p className="mt-2 text-xs text-gray-500">
                            Used {budget.map(([dimension, amount]) => `${amount} ${dimension.replaceAll('_', ' ')}`).join(' · ')}
                          </p>
                        )}
                        {(references.scan_ids.length > 0 || references.finding_ids.length > 0) && (
                          <div className="mt-3 flex flex-wrap gap-3">
                            {references.scan_ids.map((scanId) => (
                              <Link key={scanId} href={`/scans/${scanId}`} className="text-xs text-blue-300 hover:text-blue-200">
                                Open scan {scanId.slice(0, 8)}
                              </Link>
                            ))}
                            {references.finding_ids.map((findingId) => (
                              <Link key={findingId} href={`/findings/${findingId}`} className="text-xs text-blue-300 hover:text-blue-200">
                                Open finding {findingId.slice(0, 8)}
                              </Link>
                            ))}
                          </div>
                        )}
                        <details className="mt-3 text-xs text-gray-500">
                          <summary className="cursor-pointer text-gray-400 hover:text-gray-300">Audit identifiers</summary>
                          <dl className="mt-2 space-y-1">
                            <div><dt className="inline">Action: </dt><dd className="inline break-all font-mono">{action.action_id}</dd></div>
                            <div><dt className="inline">Receipt: </dt><dd className="inline break-all font-mono">{action.receipt_id || 'not recorded'}</dd></div>
                            <div><dt className="inline">Input digest: </dt><dd className="inline break-all font-mono">{action.input_digest || 'not recorded'}</dd></div>
                          </dl>
                        </details>
                      </div>
                    )
                  })}
                </div>
              )}
            </Card>

            <Card className="p-5">
              <h2 className="font-medium text-white">Available capabilities</h2>
              <p className="mt-1 text-xs text-gray-500">
                Your coding agent can query context and call only this persisted allowlist.
              </p>
              <div className="mt-4 space-y-2">
                {(hunt.capabilities || []).map((capability) => (
                  <div key={capability.name} className="rounded-lg border border-gray-800 bg-gray-950 p-3">
                    <div className="flex items-center justify-between gap-3">
                      <code className="text-sm text-blue-300">{capability.name}</code>
                      <span className="text-xs text-gray-500">{capability.risk_tier}</span>
                    </div>
                    <p className="mt-1 text-xs text-gray-400">{capability.description}</p>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </div>
      )}
    </div>
  )
}

export default function HuntPage() {
  return (
    <Suspense fallback={<p className="text-sm text-gray-400">Loading Hunt…</p>}>
      <HuntContent />
    </Suspense>
  )
}
