'use client'

import { Suspense, useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'next/navigation'
import Link from '@/components/WorkspaceLink'
import { Compass, Plus } from 'lucide-react'
import {
  authorizeTarget,
  getDeviceAgentSession,
  getTarget,
  getTargetAuthorization,
  type DeviceAgentSession,
} from '@/lib/api'
import {
  listCredentialProfiles,
  type CredentialPrincipalSlot,
  type CredentialProfile,
} from '@/lib/credentialApi'
import { defaultHuntCredentialIds } from '@/lib/credentialDefaults'
import {
  getHuntV2,
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
import { Button, Card, Combobox, EmptyState, Field, Select, Textarea, useToast } from '@/components/ui'
import { credentialOptions, targetOptions } from '@/lib/pickerOptions'
import { LegacyDeviceInvestigation } from '@/components/history/LegacyDeviceInvestigation'
import { RequestCollectionPicker } from '@/components/RequestCollectionPicker'
import { managedTargetAuthorizationIsAutomatic } from '@/lib/workspaceCapabilities'
import { HuntHistoryList } from '@/components/hunt/HuntHistoryList'
import { HuntRunView } from '@/components/hunt/HuntRunView'
import { cleanTargetLocator, huntTargetTitle } from '@/lib/huntListModel.mjs'
import { getAllTargetAssets, type TargetAsset } from '@/lib/targetAssetApi'
import { TargetSkillEditor } from '@/components/targets/TargetSkillEditor'

type TargetChoice = {
  id: string
  sourceKind: 'web' | 'network' | 'device'
  label: string
  detail: string
  authorized?: boolean
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

const ZEROABLE_BUDGETS = HUNT_BUDGET_DIMENSIONS.filter((item) => item.zeroable)

function HuntContent() {
  const searchParams = useSearchParams()
  const toast = useToast()
  const [assets, setAssets] = useState<TargetAsset[]>([])
  const [authorizedTargetId, setAuthorizedTargetId] = useState<string | null>(null)
  const [authorizationLoading, setAuthorizationLoading] = useState(false)
  const [authorizationError, setAuthorizationError] = useState<string | null>(null)
  const [authorizationRetry, setAuthorizationRetry] = useState(0)
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
  // The launcher opens from New Hunt, or straight away when a target was preselected by a link.
  const [launcherOpen, setLauncherOpen] = useState(() => Boolean(searchParams.get('target') && !searchParams.get('run')))
  const [legacyDeviceRun, setLegacyDeviceRun] = useState<DeviceAgentSession | null>(null)
  const [legacyRunLoading, setLegacyRunLoading] = useState(false)
  const [loading, setLoading] = useState(true)
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    getAllTargetAssets(undefined, true)
      .then((targets) => {
        if (cancelled) return
        setAssets(targets.filter(target => target.is_active && /^(https?|host):\/\//i.test(target.url)))
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
    // Leaving a run (the Hunts link, back navigation, or deleting it) returns to the list.
    if (!runId) { setHunt(null); return }
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

  const choices = useMemo<TargetChoice[]>(() => assets.map((target) => ({
      id: target.id,
      sourceKind: target.connected_device ? 'device' : target.url.startsWith('host://') ? 'network' : 'web',
      label: target.name || target.url,
      detail: target.url,
    })), [assets])
  const selectedChoice = choices.find((choice) => choice.id === targetId)
  // The run detail carries no target name. Inactive targets are not launch choices, so read those directly.
  const [runTargetRecord, setRunTargetRecord] = useState<{ id: string; name?: string; url?: string } | null>(null)
  const runTargetId = hunt?.target_id
  const runTargetKnown = Boolean(runTargetId && assets.some((target) => target.id === runTargetId))
  useEffect(() => {
    if (!runTargetId || runTargetKnown) return
    let cancelled = false
    getTarget(runTargetId).then((target) => { if (!cancelled) setRunTargetRecord({ id: target.id, name: target.name, url: target.url }) }).catch(() => undefined)
    return () => { cancelled = true }
  }, [runTargetId, runTargetKnown])
  const runTarget = hunt ? (() => {
    const known = assets.find((target) => target.id === hunt.target_id) || (runTargetRecord?.id === hunt.target_id ? runTargetRecord : undefined)
    const named = { target_name: hunt.target_name || known?.name, target_url: hunt.target_url || known?.url, target_id: hunt.target_id }
    return { title: huntTargetTitle(named), locator: cleanTargetLocator(named.target_url) }
  })() : null
  const targetOptionList = useMemo(() => targetOptions(assets), [assets])
  const targetKind: HuntTargetKind = selectedChoice?.sourceKind === 'device'
    ? 'device'
    : selectedChoice?.sourceKind === 'network' ? 'network' : webTargetKind

  useEffect(() => {
    let cancelled = false
    setAuthorizedTargetId(null)
    setAuthorizationConfirmed(false)
    setApprovalReceipt('')
    setScopeReceipt('')
    setAuthorizationError(null)
    setAuthorizationLoading(Boolean(selectedChoice))
    if (selectedChoice) getTargetAuthorization(selectedChoice.id)
      .then(authorization => { if (!cancelled && authorization?.standing) setAuthorizedTargetId(selectedChoice.id) })
      .catch(cause => { if (!cancelled) setAuthorizationError(cause instanceof Error ? cause.message : 'Failed to read target authorization') })
      .finally(() => { if (!cancelled) setAuthorizationLoading(false) })
    return () => {cancelled = true}
  }, [selectedChoice?.id, authorizationRetry])

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
          const usable = profiles.filter((profile) => profile.execution_compatible)
          setCredentialProfiles(usable)
          // A new Hunt starts with the target's credentials (its own before shared ones) in each
          // slot; the operator can clear any of them before starting.
          setCredentialIds(defaultHuntCredentialIds(usable))
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

  const selectedCredentialCount = Object.values(credentialIds).filter(Boolean).length
  const privileged = activeTesting || networkDiscovery || allowStateChanging || allowOobInteractions || selectedCredentialCount > 0
  // Revalidated server-side at submission and before worker decryption.
  const automaticAuthorization = targetKind !== 'device' && managedTargetAuthorizationIsAutomatic()
  const standingAuthorized = Boolean(selectedChoice && authorizedTargetId === selectedChoice.id)
    || automaticAuthorization
  const effectiveAuthorization = authorizationConfirmed || standingAuthorized
  const startBlockedReason = !targetId
    ? 'Choose a target to continue.'
    : !objective.trim()
      ? 'Describe what the Hunt should investigate.'
      : credentialsLoading
        ? 'Loading this target’s saved identities…'
        : privileged && !automaticAuthorization && authorizationLoading
          ? 'Checking this target’s saved authorization…'
          : privileged && !automaticAuthorization && authorizationError
            ? 'Target authorization could not be read. Retry before starting.'
            : privileged && !effectiveAuthorization
              ? 'Confirm that you are authorized to use the selected capabilities.'
              : null
  const visibleCredentialSlots: CredentialPrincipalSlot[] = ['primary', 'secondary', 'service', 'ssh']

  async function start() {
    if (!targetId || !selectedChoice) return
    setStarting(true)
    setError(null)
    try {
      if (privileged && !effectiveAuthorization) {
        throw new Error('Confirm that you own or are authorized to test this target.')
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
      // Reuse the current standing authorization. The ownership confirmation records it once;
      // the server resolves and revalidates it for every Hunt, including selected identities.
      if (privileged && !automaticAuthorization && !approvalReceipt.trim()) {
        let authorization = await getTargetAuthorization(selectedChoice.id)
        if (!authorization?.standing) {
          if (!authorizationConfirmed) {
            setAuthorizedTargetId(null)
            throw new Error('This target’s authorization changed. Confirm authorization again before starting.')
          }
          authorization = await authorizeTarget(selectedChoice.id, 'interactive-ui')
        }
        if (!authorization?.standing || !authorization.approval_receipt_id) {
          throw new Error('Target authorization could not be saved. Try again before starting.')
        }
        setAuthorizedTargetId(selectedChoice.id)
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
          authorizationConfirmed: effectiveAuthorization,
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

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      {!hunt && !searchParams.get('run') && (
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="rounded-lg bg-violet-500/10 p-2 text-violet-300"><Compass className="h-6 w-6" /></div>
            <div>
              <h1 className="text-2xl font-semibold text-white">Hunts</h1>
              <p className="mt-1 max-w-2xl text-sm text-gray-400">
                Evidence-driven sessions your coding agent drives for web, API, network and device targets. The agent proposes each permitted capability call; the runtime executes and proves it.
              </p>
            </div>
          </div>
          {!launcherOpen && <Button onClick={() => setLauncherOpen(true)}><Plus className="h-4 w-4" aria-hidden="true" />New Hunt</Button>}
        </div>
      )}

      {legacyRunLoading ? (
        <Card className="p-5 text-sm text-gray-400">Loading historical device investigation…</Card>
      ) : legacyDeviceRun ? (
        <LegacyDeviceInvestigation run={legacyDeviceRun} />
      ) : !hunt && searchParams.get('run') && !error ? (
        <p role="status" className="text-sm text-gray-400">Loading Hunt…</p>
      ) : !hunt ? (
        <>
          {launcherOpen && <Card className="space-y-5 p-5">
          <div className="flex items-center justify-between gap-3">
            <h2 className="font-medium text-white">New Hunt</h2>
            <Button size="sm" variant="ghost" onClick={() => setLauncherOpen(false)}>Close</Button>
          </div>
          {loading ? <p className="text-sm text-gray-400">Loading targets…</p> : choices.length === 0 ? (
            <EmptyState message="No targets available" hint="Add a hostname, IP address, or application target first." />
          ) : (
            <>
              <Field label="Target">
                <Combobox value={targetId} onChange={setTargetId} options={targetOptionList}
                  placeholder="Choose a target" searchPlaceholder="Search targets by name, host or environment…" />
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

              {selectedChoice && <TargetSkillEditor key={selectedChoice.id} targetId={selectedChoice.id} targetName={selectedChoice.label} />}

              <Field label="Budget profile">
                <Select value={budget} onChange={(event) => setBudget(event.target.value as HuntBudgetProfile)}>
                  <option value="fast">Fast</option>
                  <option value="balanced">Balanced</option>
                  <option value="thorough">Thorough</option>
                </Select>
              </Field>

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
                <label className="flex items-start gap-3 text-sm text-gray-300">
                  <input
                    className="mt-1"
                    type="checkbox"
                    checked={networkDiscovery}
                    onChange={(event) => { setNetworkDiscovery(event.target.checked); if (event.target.checked) setActiveTesting(true) }}
                  />
                  <span>Allow TCP service discovery and fingerprinting</span>
                </label>
                <label className="flex items-start gap-3 text-sm text-gray-300">
                  <input
                    className="mt-1"
                    type="checkbox"
                    checked={allowStateChanging}
                    onChange={(event) => {
                      setAllowStateChanging(event.target.checked)
                      if (event.target.checked) setActiveTesting(true)
                      if (!event.target.checked) setRequestCollectionIds([])
                    }}
                  />
                  <span>Allow explicitly selected state-changing HTTP requests</span>
                </label>
                <label className="flex items-start gap-3 text-sm text-gray-300">
                  <input
                    className="mt-1"
                    type="checkbox"
                    checked={allowOobInteractions}
                    onChange={(event) => { setAllowOobInteractions(event.target.checked); if (event.target.checked) setActiveTesting(true) }}
                  />
                  <span>Allow bounded out-of-band callbacks when a registered verifier requires them</span>
                </label>
                {privileged && !standingAuthorized && !authorizationLoading && !authorizationError && (
                  <label className="flex items-start gap-3 rounded-lg border border-amber-800/70 bg-amber-950/20 p-3 text-sm text-amber-100">
                    <input
                      className="mt-1"
                      type="checkbox"
                      checked={authorizationConfirmed}
                      onChange={(event) => setAuthorizationConfirmed(event.target.checked)}
                    />
                    <span>I own or have explicit authorization to test this target with the selected capabilities.
                      <span className="mt-1 block text-xs text-gray-400">Saved once when you start. Future Hunts and scans reuse this authorization until you revoke it.</span>
                    </span>
                  </label>
                )}
                {standingAuthorized && <p role="status" className="text-xs text-emerald-300">Testing is authorized for this target. Hunts and scans reuse its saved authorization.</p>}
                {!automaticAuthorization && authorizationError && <div role="alert" className="space-y-2 text-sm text-red-300">
                  <p>{authorizationError}</p>
                  <Button variant="secondary" size="sm" onClick={() => setAuthorizationRetry(value => value + 1)}>Retry authorization check</Button>
                </div>}
              </div>

              <div className="space-y-4 rounded-lg border border-gray-800 bg-gray-950 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <h2 className="text-sm font-medium text-white">Bound credential profiles</h2>
                    <p className="mt-1 text-xs text-gray-500">
                      Select encrypted identities this target owns or that are shared with it. The planner receives only profile metadata.
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
                          <Combobox
                            value={credentialIds[slot]}
                            onChange={(value) => setCredentialIds((current) => ({ ...current, [slot]: value }))}
                            options={credentialOptions(candidates)}
                            noneLabel={slot === 'ssh' ? 'No SSH identity' : `No ${slot} identity`}
                            searchPlaceholder="Search credentials…"
                            emptyMessage={candidates.length ? 'No matching credentials' : 'No credentials in this slot for this target'}
                          />
                        </Field>
                      )
                    })}
                  </div>
                )}
                {credentialError && <p className="text-xs text-amber-300">{credentialError}</p>}
                <p className="text-xs text-gray-500">
                  This target&apos;s credentials start selected; clear any you do not want. Saved target authorization covers the identities you select. HTTP, untrusted HTTPS, and SSH are supported. Remote SSH commands use the target&apos;s saved SSH permission.
                </p>
              </div>

              {(
                <RequestCollectionPicker
                  targetId={selectedChoice?.id}
                  targetKind={targetKind === 'network' ? 'web' : targetKind}
                  selectedIds={requestCollectionIds}
                  onChange={setRequestCollectionIds}
                  allowConfirmedActive={activeTesting && allowStateChanging}
                />
              )}

              <details className="rounded-lg border border-gray-800 bg-gray-950 p-4">
                <summary className="cursor-pointer text-sm font-medium text-white">Advanced: limits, scope receipt and capability allowlist</summary>
                <div className="mt-4 space-y-4">
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
                <div className="grid gap-4 md:grid-cols-2">
                  <label className="text-sm text-gray-300">
                    Approval receipt ID (optional override)
                    <input
                      value={approvalReceipt}
                      onChange={(event) => setApprovalReceipt(event.target.value)}
                      className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-white"
                    />
                  </label>
                  <label className="text-sm text-gray-300">
                    Scope receipt ID (optional)
                    <input
                      value={scopeReceipt}
                      onChange={(event) => setScopeReceipt(event.target.value)}
                      className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-white"
                    />
                  </label>
                </div>
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
                </div>
              </details>

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
          </Card>}
          <HuntHistoryList />
        </>
      ) : (
        <HuntRunView hunt={hunt} onChange={setHunt} target={runTarget} />
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
