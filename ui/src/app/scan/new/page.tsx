'use client'

import { useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import {
  getTargets,
  getScanPublicContract,
  getWorkers,
  submitBatchV2,
  submitScanV2,
  type ScanBudgetProfile,
  type ScanPublicContract,
  type Target,
} from '@/lib/api'
import { listCredentialProfiles, type CredentialProfile } from '@/lib/credentialApi'
import { Button, Card, Field, useToast } from '@/components/ui'
import {
  RequestCollectionPicker,
  type RequestCollectionSelectionMetadata,
} from '@/components/RequestCollectionPicker'
import { ApprovalReceiptField } from '@/components/ApprovalReceiptField'
import { validateScanTarget } from '@/lib/targetValidation'
import { usableWebTargets } from '@/lib/targetChoices'

const BUDGETS: Array<{ value: ScanBudgetProfile; label: string; description: string; limits: string }> = [
  { value: 'fast', label: 'Fast', description: 'Quick feedback for routine checks.', limits: '5 min · 1,000 requests' },
  { value: 'balanced', label: 'Balanced', description: 'The default coverage and runtime.', limits: '20 min · 5,000 requests' },
  { value: 'thorough', label: 'Thorough', description: 'Deeper release and staging coverage.', limits: '60 min · 20,000 requests' },
]

const ADVANCED_LIMITS = [
  ['max_duration_seconds', 'Maximum duration (seconds)'],
  ['max_http_requests', 'Maximum HTTP requests'],
  ['max_state_changing_requests', 'Maximum state-changing requests'],
  ['max_endpoints', 'Maximum endpoints'],
  ['max_hosts', 'Maximum hosts'],
  ['max_browser_actions', 'Maximum browser actions'],
  ['max_tcp_ports', 'Maximum TCP ports'],
  ['max_tool_wall_seconds', 'Maximum tool runtime (seconds)'],
  ['max_workers', 'Maximum workers'],
] as const

type FamilyMode = 'default' | 'include' | 'exclude'

function formatLimit(value: number | undefined): string {
  return Number.isFinite(value) ? Number(value).toLocaleString() : 'server default'
}

export default function NewScanPage() {
  const router = useRouter()
  const toast = useToast()
  const [target, setTarget] = useState('')
  const [batchMode, setBatchMode] = useState(false)
  const [batchTargets, setBatchTargets] = useState('')
  const [existingTargets, setExistingTargets] = useState<Target[]>([])
  const [targetKind, setTargetKind] = useState<'web' | 'api'>('web')
  const [budgetProfile, setBudgetProfile] = useState<ScanBudgetProfile>('balanced')
  const [activeTesting, setActiveTesting] = useState(false)
  const [authorized, setAuthorized] = useState(false)
  const [subdomainDiscovery, setSubdomainDiscovery] = useState(false)
  const [networkDiscovery, setNetworkDiscovery] = useState(false)
  const [allowStateChanging, setAllowStateChanging] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [approvalReceipt, setApprovalReceipt] = useState('')
  const [credentialProfiles, setCredentialProfiles] = useState<CredentialProfile[]>([])
  const [primaryCredentialId, setPrimaryCredentialId] = useState('')
  const [secondaryCredentialId, setSecondaryCredentialId] = useState('')
  const [requestCollectionIds, setRequestCollectionIds] = useState<string[]>([])
  const [requestCollectionMetadata, setRequestCollectionMetadata] = useState<RequestCollectionSelectionMetadata>({})
  const [scanContract, setScanContract] = useState<ScanPublicContract | null>(null)
  const [scanContractError, setScanContractError] = useState<string | null>(null)
  const [familyModes, setFamilyModes] = useState<Record<string, FamilyMode>>({})
  const [credentialsLoading, setCredentialsLoading] = useState(false)
  const [credentialError, setCredentialError] = useState<string | null>(null)
  const [customEndpoints, setCustomEndpoints] = useState('')
  const [limits, setLimits] = useState<Record<string, string>>({})
  const [workerStats, setWorkerStats] = useState<Awaited<ReturnType<typeof getWorkers>> | null>(null)
  const [staleWorkers, setStaleWorkers] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const requestedParams = new URLSearchParams(window.location.search)
    const requestedTargets = (requestedParams.get('targets') || '')
      .split(/\r?\n/)
      .map((value) => value.trim())
      .filter(Boolean)
    const requestedTarget = requestedParams.get('target')?.trim()
    if (requestedTargets.length > 0) {
      setBatchMode(true)
      setBatchTargets(Array.from(new Set(requestedTargets)).join('\n'))
    } else if (requestedTarget) {
      setTarget(requestedTarget)
    }
    let cancelled = false
    getTargets()
      .then((rows) => {
        if (cancelled) return
        const list = Array.isArray(rows?.targets) ? rows.targets : Array.isArray(rows) ? rows : []
        setExistingTargets(usableWebTargets(list))
      })
      .catch(() => undefined)
    getWorkers()
      .then((workers) => { if (!cancelled) { setWorkerStats(workers); setStaleWorkers(workers.stale_workers?.length ?? 0) } })
      .catch(() => undefined)
    getScanPublicContract()
      .then((contract) => {
        if (cancelled) return
        setScanContract(contract)
        setFamilyModes(Object.fromEntries(contract.families.map((family) => [family.name, 'default'])))
      })
      .catch((cause) => {
        if (!cancelled) {
          setScanContractError(cause instanceof Error ? cause.message : 'Failed to load the Scan contract')
        }
      })
    return () => { cancelled = true }
  }, [])

  const targets = useMemo(
    () => Array.from(new Set(batchTargets.split(/\r?\n/).map((value) => value.trim()).filter(Boolean))),
    [batchTargets],
  )
  const selectedRegisteredTarget = useMemo(
    () => existingTargets.find((item) => item.url === target.trim()),
    [existingTargets, target],
  )
  const selectedCredentialIds = [primaryCredentialId, secondaryCredentialId].filter(Boolean)
  const credentialUse = selectedCredentialIds.length > 0
  const approvalRequired = networkDiscovery || credentialUse || allowStateChanging
  const active_worker_count = workerStats?.execution_capacity?.total_available ?? workerStats?.current_count ?? workerStats?.count ?? 0
  const customDuration = Number(limits.max_duration_seconds)
  const approvalTtlMinutes = Math.ceil((
    Number.isSafeInteger(customDuration) && customDuration > 0
      ? customDuration
      : scanContract?.budget_profiles[budgetProfile]?.max_duration_seconds ?? 7200
  ) / 60) + 15
  const includeFamilies = Object.entries(familyModes).filter(([, mode]) => mode === 'include').map(([name]) => name)
  const excludeFamilies = Object.entries(familyModes).filter(([, mode]) => mode === 'exclude').map(([name]) => name)

  function credentialCompatibility(
    profile: CredentialProfile,
    lane: 'primary' | 'secondary',
  ): { compatible: boolean; reason?: string } {
    if (!profile.execution_compatible) return { compatible: false, reason: `profile is ${profile.status}` }
    if (!scanContract) return { compatible: false, reason: 'Scan contract is unavailable' }
    if (!scanContract.credentials.supported_auth_kinds.includes(profile.auth_kind)) {
      return { compatible: false, reason: `${profile.auth_kind.replaceAll('_', ' ')} is not executable by Scan` }
    }
    if (lane === 'primary' && !['primary', 'service'].includes(profile.principal_slot)) {
      return { compatible: false, reason: `stored in the ${profile.principal_slot} slot` }
    }
    if (lane === 'secondary') {
      if (profile.principal_slot !== 'secondary') {
        return { compatible: false, reason: `stored in the ${profile.principal_slot} slot` }
      }
      if (!scanContract.credentials.secondary_auth_kinds.includes(profile.auth_kind)) {
        return { compatible: false, reason: 'this authentication kind cannot be a comparison identity' }
      }
    }
    if (profile.auth_kind === 'oauth_password' && !profile.configuration.client_id_configured) {
      return { compatible: false, reason: 'OAuth client ID is not configured' }
    }
    const allowed = new Set(profile.allowed_capabilities)
    if (!allowed.size) return { compatible: true }
    if (includeFamilies.includes('bola') && !allowed.has('authz.verify')) {
      return { compatible: false, reason: 'does not allow the selected BOLA / IDOR verifier' }
    }
    const interactive = scanContract.credentials.interactive_auth_kinds.includes(profile.auth_kind)
    if (interactive && !allowed.has('auth.session.establish')) {
      return { compatible: false, reason: 'does not allow auth session establishment' }
    }
    if (!interactive && !scanContract.credentials.semantic_capabilities.some((name) => allowed.has(name))) {
      return { compatible: false, reason: 'does not allow a Scan action capability' }
    }
    return { compatible: true }
  }

  function removeConfirmedActiveSelections() {
    setRequestCollectionIds((current) => current.filter(
      (selectionId) => requestCollectionMetadata[selectionId]?.replayPolicy !== 'confirmed_active',
    ))
  }

  useEffect(() => {
    let cancelled = false
    setPrimaryCredentialId('')
    setSecondaryCredentialId('')
    setCredentialProfiles([])
    setCredentialError(null)
    setCredentialsLoading(false)
    if (batchMode || !selectedRegisteredTarget) return () => { cancelled = true }
    setCredentialsLoading(true)
    listCredentialProfiles({
      target_kind: targetKind,
      target_id: selectedRegisteredTarget.id,
    })
      .then(({ profiles }) => {
        if (!cancelled) {
          setCredentialProfiles(profiles)
        }
      })
      .catch((cause) => {
        if (!cancelled) {
          setCredentialError(cause instanceof Error ? cause.message : 'Failed to load credential profiles')
        }
      })
      .finally(() => { if (!cancelled) setCredentialsLoading(false) })
    return () => { cancelled = true }
  }, [batchMode, selectedRegisteredTarget?.id, targetKind])

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    setError(null)
    const submittedTargets = batchMode ? targets : [target.trim()]
    if (submittedTargets.length === 0 || !submittedTargets[0]) {
      setError('Enter at least one target URL.')
      return
    }
    if (submittedTargets.length > 50) {
      setError('Batch submission supports at most 50 unique targets.')
      return
    }
    const invalid = submittedTargets.map(validateScanTarget).find(Boolean)
    if (invalid) {
      setError(invalid)
      return
    }
    if ((activeTesting || credentialUse) && !authorized) {
      setError('Confirm that you own or are authorized to test every target with the selected permissions and identities.')
      return
    }
    if (networkDiscovery && (!activeTesting || !approvalReceipt.trim())) {
      setError('Network discovery requires active testing, authorization confirmation, and a target-bound approval receipt ID.')
      return
    }
    if (credentialUse && batchMode) {
      setError('Credential profiles are exact-target-bound and cannot be shared across a batch.')
      return
    }
    if (credentialUse && !approvalReceipt.trim()) {
      setError('Credential use requires a target-bound approval receipt ID.')
      return
    }
    if (requestCollectionIds.length && (batchMode || !selectedRegisteredTarget)) {
      setError('Request collection selections are exact-target-bound and require one registered target.')
      return
    }
    if (allowStateChanging && (!activeTesting || !approvalReceipt.trim())) {
      setError('State-changing collection replay requires active testing and a target-bound approval receipt ID.')
      return
    }
    const includedActiveFamily = scanContract?.families.find(
      (family) => includeFamilies.includes(family.name) && family.requires_active_testing,
    )
    if (includedActiveFamily && !activeTesting) {
      setError(`${includedActiveFamily.label} is an active family. Enable active testing or return it to Default.`)
      return
    }
    if (includeFamilies.includes('bola') && selectedCredentialIds.length !== 2) {
      setError('Explicit BOLA / IDOR coverage requires two distinct authenticated principals.')
      return
    }
    const incompatibleActiveSelection = requestCollectionIds.find(
      (selectionId) => requestCollectionMetadata[selectionId]?.replayPolicy === 'confirmed_active',
    )
    if (incompatibleActiveSelection && (!activeTesting || !allowStateChanging)) {
      setError('Confirmed-active request selections require active testing and state-changing HTTP permission.')
      return
    }

    const advanced: Record<string, number> = {}
    for (const [key, rawValue] of Object.entries(limits)) {
      const value = rawValue.trim()
      if (!value) continue
      if (!/^\d+$/.test(value)) {
        setError(`${ADVANCED_LIMITS.find(([name]) => name === key)?.[1] || key} must be a whole number.`)
        return
      }
      const parsed = Number(value)
      const definition = scanContract?.advanced_limits.find((item) => item.name === key)
      const minimum = definition?.minimum ?? (key === 'max_state_changing_requests' ? 0 : 1)
      const profileCeiling = definition?.profile_ceilings[budgetProfile]
      if (!Number.isSafeInteger(parsed) || parsed < minimum) {
        setError(`${ADVANCED_LIMITS.find(([name]) => name === key)?.[1] || key} must be at least ${minimum}.`)
        return
      }
      if (definition && parsed > definition.maximum) {
        setError(`${ADVANCED_LIMITS.find(([name]) => name === key)?.[1] || key} cannot exceed ${definition.maximum.toLocaleString()}.`)
        return
      }
      if (profileCeiling !== undefined && parsed > profileCeiling) {
        setError(`${ADVANCED_LIMITS.find(([name]) => name === key)?.[1] || key} cannot exceed the ${budgetProfile} ceiling of ${profileCeiling.toLocaleString()}.`)
        return
      }
      advanced[key] = parsed
    }
    const endpointList = customEndpoints.split(/\r?\n/).map((value) => value.trim()).filter(Boolean)
    const common = {
      target_kind: targetKind,
      budget_profile: budgetProfile,
      policy: {
        active_testing: activeTesting,
        allow_state_changing_http: allowStateChanging,
        subdomain_discovery: subdomainDiscovery,
        network_discovery: networkDiscovery,
        include_families: includeFamilies,
        exclude_families: excludeFamilies,
      },
      request_collections: requestCollectionIds.map((id) => ({
        id,
        ...(requestCollectionMetadata[id]?.replayPolicy
          ? { replay_policy: requestCollectionMetadata[id].replayPolicy }
          : {}),
      })),
      credential_profile_ids: selectedCredentialIds,
      advanced,
      approval_receipt_id: approvalReceipt.trim() || undefined,
      options: {
        ...(endpointList.length ? { custom_endpoints: endpointList } : {}),
        require_current_workers: activeTesting,
      },
    }

    setLoading(true)
    try {
      if (batchMode) {
        const result = await submitBatchV2({ targets: submittedTargets, ...common })
        if (result.queued_count === 0) throw new Error(`No scans were queued (${result.failed_count} rejected).`)
        toast.success(`${result.queued_count} scan${result.queued_count === 1 ? '' : 's'} queued`)
        router.push('/scans')
      } else {
        const result = await submitScanV2({ target: submittedTargets[0], ...common })
        toast.success('Scan queued')
        router.push(`/scans/${result.scan_id}`)
      }
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : 'Failed to submit scan'
      setError(message)
      toast.error(message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">New Scan</h1>
        <p className="mt-1 text-sm text-gray-400">One deterministic scan pipeline. Choose its resource budget and testing permissions.</p>
      </div>

      <form
        noValidate
        onSubmit={handleSubmit}
        onChange={() => { if (error) setError(null) }}
        className="space-y-6"
      >
        <Card className="p-5 space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h2 className="font-medium text-white">Target</h2>
              <p className="text-xs text-gray-500">Web URL or hostname in your authorized scope.</p>
            </div>
            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input type="checkbox" checked={batchMode} onChange={(event) => {
                setBatchMode(event.target.checked)
                if (event.target.checked) {
                  setPrimaryCredentialId('')
                  setSecondaryCredentialId('')
                  setRequestCollectionIds([])
                }
              }} />
              Multiple targets
            </label>
          </div>
          {batchMode ? (
            <Field label="Target URLs (one per line)" required>
              <textarea value={batchTargets} onChange={(event) => setBatchTargets(event.target.value)} rows={6} placeholder={'https://app.example.com\nhttps://api.example.com'} className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder:text-gray-600" />
            </Field>
          ) : (
            <Field label="Target URL or hostname" required>
              <input value={target} onChange={(event) => {
                setTarget(event.target.value)
                setPrimaryCredentialId('')
                setSecondaryCredentialId('')
              }} list="known-targets" placeholder="https://example.com" className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder:text-gray-600" />
            </Field>
          )}
          <datalist id="known-targets">{existingTargets.map((item) => <option key={item.id} value={item.url} />)}</datalist>
          <label className="block text-sm text-gray-300">
            Target kind
            <select value={targetKind} onChange={(event) => setTargetKind(event.target.value as 'web' | 'api')} className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-white">
              <option value="web">Web application</option>
              <option value="api">API</option>
            </select>
          </label>
        </Card>

        <Card className="p-5">
          <h2 className="font-medium text-white">Budget</h2>
          <p className="mt-1 text-xs text-gray-500">Budgets are hard ceilings, not separate scan modes.</p>
          <div className="mt-4 grid gap-3 md:grid-cols-3" role="group" aria-label="Scan budget">
            {BUDGETS.map((budget) => {
              const serverLimits = scanContract?.budget_profiles[budget.value]
              return (
                <button key={budget.value} type="button" aria-pressed={budgetProfile === budget.value} onClick={() => { setBudgetProfile(budget.value); setError(null) }} className={`rounded-lg border p-4 text-left transition-colors ${budgetProfile === budget.value ? 'border-blue-500 bg-blue-500/10' : 'border-gray-700 bg-gray-950 hover:border-gray-600'}`}>
                  <span className="font-medium text-white">{budget.label}</span>
                  <span className="mt-1 block text-sm text-gray-400">{budget.description}</span>
                  <span className="mt-3 block text-xs text-gray-500">
                    {serverLimits
                      ? `${Math.round(serverLimits.max_duration_seconds / 60)} min · ${formatLimit(serverLimits.max_http_requests)} requests`
                      : budget.limits}
                  </span>
                </button>
              )
            })}
          </div>
          {scanContractError && <p className="mt-3 text-xs text-amber-300">{scanContractError}. Server validation still applies.</p>}
        </Card>

        {workerStats?.fleet?.enabled && <Card className="p-4">
          <h2 className="font-medium text-white">Automatic placement</h2>
          <p className="mt-1 text-sm text-gray-400">ShakerScan will place and shard this Scan across {active_worker_count} compatible {active_worker_count === 1 ? 'worker' : 'workers'} within the selected budget.</p>
        </Card>}

        <Card className="p-5 space-y-4">
          <div>
            <h2 className="font-medium text-white">Testing policy</h2>
            <p className="mt-1 text-xs text-gray-500">
              {scanContract?.passive_coverage.description || 'Loading the server-defined passive coverage manifest…'}
            </p>
          </div>
          <label className="flex items-start gap-3 rounded-lg border border-gray-700 bg-gray-950 p-4">
            <input className="mt-1" type="checkbox" checked={activeTesting} onChange={(event) => { setActiveTesting(event.target.checked); if (!event.target.checked) { if (!credentialUse) setAuthorized(false); setNetworkDiscovery(false); setAllowStateChanging(false); removeConfirmedActiveSelections() } }} />
            <span>
              <span className="block text-sm font-medium text-white">Allow active testing</span>
              <span className="block text-xs text-gray-500">Permit bounded XSS, SQL injection, authorization, and other proof-oriented probes.</span>
            </span>
          </label>
          {(activeTesting || credentialUse) && (
            <label className="flex items-start gap-3 rounded-lg border border-amber-800/70 bg-amber-950/20 p-4 text-sm text-amber-100">
              <input className="mt-1" type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} />
              <span>I own or have explicit authorization to test every submitted target with the selected permissions and identities.</span>
            </label>
          )}
          <div className="grid gap-3 md:grid-cols-2">
            <label className="flex items-center gap-3 text-sm text-gray-300"><input type="checkbox" checked={subdomainDiscovery} onChange={(event) => setSubdomainDiscovery(event.target.checked)} />Discover subdomains</label>
            <label className={`flex items-center gap-3 text-sm ${activeTesting ? 'text-gray-300' : 'text-gray-600'}`}><input type="checkbox" disabled={!activeTesting} checked={networkDiscovery} onChange={(event) => setNetworkDiscovery(event.target.checked)} />Discover network services (approval receipt required)</label>
            <label className={`flex items-center gap-3 text-sm ${activeTesting ? 'text-gray-300' : 'text-gray-600'}`}><input type="checkbox" disabled={!activeTesting} checked={allowStateChanging} onChange={(event) => { setAllowStateChanging(event.target.checked); if (!event.target.checked) removeConfirmedActiveSelections() }} />Allow explicitly selected state-changing HTTP requests</label>
          </div>
          {(activeTesting || credentialUse || approvalReceipt) && (
            <ApprovalReceiptField
              targetId={selectedRegisteredTarget?.id}
              targetUrl={batchMode ? '' : target.trim()}
              authorizationConfirmed={authorized}
              receiptId={approvalReceipt}
              onReceiptIdChange={setApprovalReceipt}
              ttlMinutes={approvalTtlMinutes}
              riskTier={credentialUse ? 'credential' : 'active'}
              required={approvalRequired}
              disabledReason={batchMode ? 'Create approvals from a single-target Scan; receipts are target-bound.' : undefined}
            />
          )}
          {scanContract && (
            <div className="rounded-lg border border-gray-800 bg-gray-950 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h3 className="text-sm font-medium text-gray-200">Coverage families</h3>
                  <p className="mt-1 text-xs text-gray-500">Default follows the server policy. Include requires that family; Exclude removes it.</p>
                </div>
                <span className="text-[11px] text-gray-600">{scanContract.action_plan_schema}</span>
              </div>
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                {scanContract.families.map((family) => (
                  <label key={family.name} className="rounded border border-gray-800 p-3 text-xs text-gray-400">
                    <span className="flex items-start justify-between gap-3">
                      <span>
                        <span className="block text-sm font-medium text-gray-200">{family.label}</span>
                        <span className="mt-1 block text-gray-500">{family.description}</span>
                      </span>
                      <select
                        aria-label={`${family.label} family policy`}
                        value={familyModes[family.name] || 'default'}
                        onChange={(event) => setFamilyModes((current) => ({
                          ...current,
                          [family.name]: event.target.value as FamilyMode,
                        }))}
                        className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-xs text-white"
                      >
                        <option value="default">Default</option>
                        <option value="include">Include</option>
                        <option value="exclude">Exclude</option>
                      </select>
                    </span>
                    <span className="mt-2 block text-[11px] text-gray-600">
                      {family.requires_active_testing ? 'Active permission required · ' : ''}
                      {family.requires_credentials ? 'Two principals required · ' : ''}
                      {family.capabilities.join(' · ')}
                    </span>
                  </label>
                ))}
              </div>
            </div>
          )}
          {activeTesting && staleWorkers > 0 && (
            <p className="rounded-lg border border-amber-800/70 bg-amber-950/20 p-3 text-sm text-amber-200">
              {staleWorkers} worker{staleWorkers === 1 ? '' : 's'} are not on the current build. Rebuild and restart the scanner, then refresh this page before submitting active work.
              {workerStats?.fleet?.enabled && <> <Link href="/fleet" className="font-medium underline">Open Fleet</Link>.</>}
            </p>
          )}
        </Card>

        <Card className="overflow-hidden">
          <button type="button" aria-expanded={showAdvanced} aria-controls="advanced-scan-options" onClick={() => setShowAdvanced((value) => !value)} className="flex w-full items-center justify-between p-5 text-left">
            <span><span className="block font-medium text-white">Advanced</span><span className="block text-xs text-gray-500">Authentication, known endpoints, approval, and custom ceilings.</span></span>
            <span className="text-gray-500">{showAdvanced ? '−' : '+'}</span>
          </button>
          {showAdvanced && (
            <div id="advanced-scan-options" className="space-y-5 border-t border-gray-800 p-5">
              <div>
                <h3 className="text-sm font-medium text-gray-300">Authenticated principals</h3>
                <p className="mt-1 text-xs text-gray-500">Select encrypted profiles bound to this exact registered target. Add a distinct second user to enable cross-user BOLA/IDOR comparisons.</p>
              </div>
              {batchMode ? (
                <p className="rounded-lg border border-gray-800 bg-gray-950 p-3 text-xs text-gray-500">Exact-target credentials are unavailable for multi-target batches.</p>
              ) : !selectedRegisteredTarget ? (
                <p className="rounded-lg border border-gray-800 bg-gray-950 p-3 text-xs text-gray-500">Choose an existing target URL exactly as registered before attaching credentials.</p>
              ) : credentialsLoading ? (
                <p className="text-xs text-gray-500">Loading credential profiles…</p>
              ) : (
                <div className="grid gap-4 md:grid-cols-2">
                  <label className="text-sm text-gray-300">
                    Primary identity
                    <select value={primaryCredentialId} onChange={(event) => setPrimaryCredentialId(event.target.value)} className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-white">
                      <option value="">Anonymous</option>
                      {credentialProfiles.map((profile) => {
                        const compatibility = credentialCompatibility(profile, 'primary')
                        return (
                          <option key={profile.id} value={profile.id} disabled={!compatibility.compatible}>
                            {profile.name} · {profile.auth_kind.replaceAll('_', ' ')} · v{profile.current_version}{compatibility.reason ? ` — unavailable: ${compatibility.reason}` : ''}
                          </option>
                        )
                      })}
                    </select>
                  </label>
                  <label className="text-sm text-gray-300">
                    Secondary identity
                    <select value={secondaryCredentialId} onChange={(event) => setSecondaryCredentialId(event.target.value)} className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-white">
                      <option value="">No comparator</option>
                      {credentialProfiles.map((profile) => {
                        const compatibility = credentialCompatibility(profile, 'secondary')
                        return (
                          <option key={profile.id} value={profile.id} disabled={!compatibility.compatible}>
                            {profile.name} · {profile.auth_kind.replaceAll('_', ' ')} · v{profile.current_version}{compatibility.reason ? ` — unavailable: ${compatibility.reason}` : ''}
                          </option>
                        )
                      })}
                    </select>
                  </label>
                </div>
              )}
              {credentialError && <p className="text-xs text-amber-300">{credentialError}</p>}
              <p className="text-xs text-gray-500">Only opaque IDs enter the Scan request and queue. The worker revalidates approval and decrypts the selected version immediately before execution. <Link href="/credentials" className="text-blue-300 hover:text-blue-200">Manage credentials</Link></p>
              <RequestCollectionPicker
                targetId={batchMode ? undefined : selectedRegisteredTarget?.id}
                targetKind={targetKind}
                selectedIds={requestCollectionIds}
                onChange={setRequestCollectionIds}
                onMetadataChange={setRequestCollectionMetadata}
                allowConfirmedActive={activeTesting && allowStateChanging}
                disabled={batchMode}
              />
              <label className="block text-sm text-gray-300">Known endpoints (one per line)<textarea value={customEndpoints} onChange={(event) => setCustomEndpoints(event.target.value)} rows={4} placeholder={'GET /api/users\nPOST /api/login username,password'} className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-white" /></label>
              <div>
                <h3 className="text-sm font-medium text-gray-300">Custom budget ceilings</h3>
                <p className="mt-1 text-xs text-gray-500">Whole numbers only. Zero is an explicit deny ceiling where the server contract permits it.</p>
                <div className="mt-3 grid gap-3 md:grid-cols-2">
                  {ADVANCED_LIMITS.map(([key, label]) => {
                    const definition = scanContract?.advanced_limits.find((item) => item.name === key)
                    const minimum = definition?.minimum ?? (key === 'max_state_changing_requests' ? 0 : 1)
                    const maximum = definition?.profile_ceilings[budgetProfile] ?? definition?.maximum
                    return (
                      <label key={key} className="text-xs text-gray-400">
                        {label}
                        <input type="number" min={minimum} max={maximum} step="1" value={limits[key] || ''} onChange={(event) => setLimits((current) => ({ ...current, [key]: event.target.value }))} className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white" />
                        {maximum !== undefined && <span className="mt-1 block text-[11px] text-gray-600">{budgetProfile} ceiling: {formatLimit(maximum)}{minimum === 0 ? ' · zero allowed' : ''}</span>}
                      </label>
                    )
                  })}
                </div>
              </div>
            </div>
          )}
        </Card>

        {error && <p role="alert" className="rounded-lg border border-red-800 bg-red-950/30 p-3 text-sm text-red-300">{error}</p>}
        <div className="flex items-center justify-end gap-3">
          <Button type="button" variant="secondary" onClick={() => router.back()}>Cancel</Button>
          <Button type="submit" loading={loading}>Run Scan</Button>
        </div>
      </form>
    </div>
  )
}
