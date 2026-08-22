'use client'

import { useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import {
  getTargets,
  getWorkers,
  listCredentialProfiles,
  submitBatchV2,
  submitScanV2,
  type CredentialProfile,
  type Target,
} from '@/lib/api'
import { Button, Card, useToast } from '@/components/ui'
import { RequestCollectionPicker } from '@/components/RequestCollectionPicker'
import { validateScanTarget } from '@/lib/targetValidation'

type BudgetProfile = 'fast' | 'balanced' | 'thorough'

const BUDGETS: Array<{ value: BudgetProfile; label: string; description: string; limits: string }> = [
  { value: 'fast', label: 'Fast', description: 'Quick feedback for routine checks.', limits: '5 min · 1,000 requests' },
  { value: 'balanced', label: 'Balanced', description: 'The default coverage and runtime.', limits: '20 min · 5,000 requests' },
  { value: 'thorough', label: 'Thorough', description: 'Deeper release and staging coverage.', limits: '60 min · 20,000 requests' },
]

const ADVANCED_LIMITS = [
  ['max_duration_seconds', 'Maximum duration (seconds)'],
  ['max_http_requests', 'Maximum HTTP requests'],
  ['max_endpoints', 'Maximum endpoints'],
  ['max_browser_actions', 'Maximum browser actions'],
  ['max_tcp_ports', 'Maximum TCP ports'],
  ['max_tool_wall_seconds', 'Maximum tool runtime (seconds)'],
  ['max_workers', 'Maximum workers'],
] as const

export default function NewScanPage() {
  const router = useRouter()
  const toast = useToast()
  const [target, setTarget] = useState('')
  const [batchMode, setBatchMode] = useState(false)
  const [batchTargets, setBatchTargets] = useState('')
  const [existingTargets, setExistingTargets] = useState<Target[]>([])
  const [targetKind, setTargetKind] = useState<'web' | 'api'>('web')
  const [budgetProfile, setBudgetProfile] = useState<BudgetProfile>('balanced')
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
  const [credentialsLoading, setCredentialsLoading] = useState(false)
  const [credentialError, setCredentialError] = useState<string | null>(null)
  const [customEndpoints, setCustomEndpoints] = useState('')
  const [limits, setLimits] = useState<Record<string, string>>({})
  const [workerStats, setWorkerStats] = useState<Awaited<ReturnType<typeof getWorkers>> | null>(null)
  const [staleWorkers, setStaleWorkers] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const requestedTarget = new URLSearchParams(window.location.search).get('target')?.trim()
    if (requestedTarget) setTarget(requestedTarget)
    let cancelled = false
    getTargets()
      .then((rows) => {
        if (cancelled) return
        const list = Array.isArray(rows?.targets) ? rows.targets : Array.isArray(rows) ? rows : []
        setExistingTargets(list)
      })
      .catch(() => undefined)
    getWorkers()
      .then((workers) => { if (!cancelled) { setWorkerStats(workers); setStaleWorkers(workers.stale_workers?.length ?? 0) } })
      .catch(() => undefined)
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
  const active_worker_count = workerStats?.execution_capacity?.total_available ?? workerStats?.current_count ?? workerStats?.count ?? 0

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
          setCredentialProfiles(profiles.filter((profile) => (
            profile.execution_compatible
            && (!profile.allowed_capabilities.length || profile.allowed_capabilities.includes('scan.execute'))
            && (profile.auth_kind !== 'oauth_password' || profile.configuration.client_id_configured)
          )))
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

    const advanced = Object.fromEntries(
      Object.entries(limits)
        .filter(([, value]) => value.trim() !== '')
        .map(([key, value]) => [key, Number.parseInt(value, 10)])
        .filter(([, value]) => Number.isFinite(value as number) && Number(value) > 0),
    )
    const endpointList = customEndpoints.split(/\r?\n/).map((value) => value.trim()).filter(Boolean)
    const common = {
      target_kind: targetKind,
      budget_profile: budgetProfile,
      policy: {
        active_testing: activeTesting,
        allow_state_changing_http: allowStateChanging,
        subdomain_discovery: subdomainDiscovery,
        network_discovery: networkDiscovery,
      },
      request_collections: requestCollectionIds.map((id) => ({ id })),
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

      <form onSubmit={handleSubmit} className="space-y-6">
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
            <textarea value={batchTargets} onChange={(event) => setBatchTargets(event.target.value)} rows={6} placeholder={'https://app.example.com\nhttps://api.example.com'} className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder:text-gray-600" />
          ) : (
            <>
              <input value={target} onChange={(event) => {
                setTarget(event.target.value)
                setPrimaryCredentialId('')
                setSecondaryCredentialId('')
              }} list="known-targets" placeholder="https://example.com" className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder:text-gray-600" />
              <datalist id="known-targets">{existingTargets.map((item) => <option key={item.id} value={item.url} />)}</datalist>
            </>
          )}
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
          <div className="mt-4 grid gap-3 md:grid-cols-3">
            {BUDGETS.map((budget) => (
              <button key={budget.value} type="button" onClick={() => setBudgetProfile(budget.value)} className={`rounded-lg border p-4 text-left transition-colors ${budgetProfile === budget.value ? 'border-blue-500 bg-blue-500/10' : 'border-gray-700 bg-gray-950 hover:border-gray-600'}`}>
                <span className="font-medium text-white">{budget.label}</span>
                <span className="mt-1 block text-sm text-gray-400">{budget.description}</span>
                <span className="mt-3 block text-xs text-gray-500">{budget.limits}</span>
              </button>
            ))}
          </div>
        </Card>

        {workerStats?.fleet?.enabled && <Card className="p-4">
          <h2 className="font-medium text-white">Automatic placement</h2>
          <p className="mt-1 text-sm text-gray-400">ShakerScan will place and shard this Scan across {active_worker_count} compatible {active_worker_count === 1 ? 'worker' : 'workers'} within the selected budget.</p>
        </Card>}

        <Card className="p-5 space-y-4">
          <div>
            <h2 className="font-medium text-white">Testing policy</h2>
            <p className="mt-1 text-xs text-gray-500">Passive checks are always included. Opt in to broader discovery or active proof.</p>
          </div>
          <label className="flex items-start gap-3 rounded-lg border border-gray-700 bg-gray-950 p-4">
            <input className="mt-1" type="checkbox" checked={activeTesting} onChange={(event) => { setActiveTesting(event.target.checked); if (!event.target.checked) { if (!credentialUse) setAuthorized(false); setNetworkDiscovery(false); setAllowStateChanging(false); setRequestCollectionIds([]) } }} />
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
            <label className={`flex items-center gap-3 text-sm ${activeTesting ? 'text-gray-300' : 'text-gray-600'}`}><input type="checkbox" disabled={!activeTesting} checked={allowStateChanging} onChange={(event) => { setAllowStateChanging(event.target.checked); if (!event.target.checked) setRequestCollectionIds([]) }} />Allow explicitly selected state-changing HTTP requests</label>
          </div>
          {activeTesting && staleWorkers > 0 && (
            <p className="rounded-lg border border-amber-800/70 bg-amber-950/20 p-3 text-sm text-amber-200">{staleWorkers} worker{staleWorkers === 1 ? '' : 's'} are not on the current build. Active submission will fail closed until they are current.</p>
          )}
        </Card>

        <Card className="overflow-hidden">
          <button type="button" onClick={() => setShowAdvanced((value) => !value)} className="flex w-full items-center justify-between p-5 text-left">
            <span><span className="block font-medium text-white">Advanced</span><span className="block text-xs text-gray-500">Authentication, known endpoints, approval, and custom ceilings.</span></span>
            <span className="text-gray-500">{showAdvanced ? '−' : '+'}</span>
          </button>
          {showAdvanced && (
            <div className="space-y-5 border-t border-gray-800 p-5">
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
                      {credentialProfiles.filter((profile) => ['primary', 'service'].includes(profile.principal_slot)).map((profile) => (
                        <option key={profile.id} value={profile.id}>{profile.name} · {profile.auth_kind.replaceAll('_', ' ')} · v{profile.current_version}</option>
                      ))}
                    </select>
                  </label>
                  <label className="text-sm text-gray-300">
                    Secondary identity
                    <select value={secondaryCredentialId} onChange={(event) => setSecondaryCredentialId(event.target.value)} className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-white">
                      <option value="">No comparator</option>
                      {credentialProfiles.filter((profile) => (
                        profile.principal_slot === 'secondary'
                        && ['authorization_header', 'bearer_token', 'cookie', 'basic_auth', 'form_login'].includes(profile.auth_kind)
                      )).map((profile) => (
                        <option key={profile.id} value={profile.id}>{profile.name} · {profile.auth_kind.replaceAll('_', ' ')} · v{profile.current_version}</option>
                      ))}
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
                allowConfirmedActive={activeTesting && allowStateChanging}
                disabled={batchMode}
              />
              <label className="block text-sm text-gray-300">Known endpoints (one per line)<textarea value={customEndpoints} onChange={(event) => setCustomEndpoints(event.target.value)} rows={4} placeholder={'GET /api/users\nPOST /api/login username,password'} className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-white" /></label>
              <label className="block text-sm text-gray-300">Approval receipt ID<input value={approvalReceipt} onChange={(event) => setApprovalReceipt(event.target.value)} className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-white" /></label>
              <div>
                <h3 className="text-sm font-medium text-gray-300">Custom budget ceilings</h3>
                <div className="mt-3 grid gap-3 md:grid-cols-2">
                  {ADVANCED_LIMITS.map(([key, label]) => (
                    <label key={key} className="text-xs text-gray-400">{label}<input type="number" min="1" value={limits[key] || ''} onChange={(event) => setLimits((current) => ({ ...current, [key]: event.target.value }))} className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white" /></label>
                  ))}
                </div>
              </div>
            </div>
          )}
        </Card>

        {error && <p className="rounded-lg border border-red-800 bg-red-950/30 p-3 text-sm text-red-300">{error}</p>}
        <div className="flex items-center justify-end gap-3">
          <Button type="button" variant="secondary" onClick={() => router.back()}>Cancel</Button>
          <Button type="submit" loading={loading}>Run Scan</Button>
        </div>
      </form>
    </div>
  )
}
