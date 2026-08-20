'use client'

import { useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import { getTargets, getWorkers, submitBatchV2, submitScanV2, type Target } from '@/lib/api'
import { Button, Card, useToast } from '@/components/ui'
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
  const [budgetProfile, setBudgetProfile] = useState<BudgetProfile>('balanced')
  const [activeTesting, setActiveTesting] = useState(false)
  const [authorized, setAuthorized] = useState(false)
  const [subdomainDiscovery, setSubdomainDiscovery] = useState(false)
  const [networkDiscovery, setNetworkDiscovery] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [approvalReceipt, setApprovalReceipt] = useState('')
  const [authHeader, setAuthHeader] = useState('')
  const [authCookies, setAuthCookies] = useState('')
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
  const active_worker_count = workerStats?.execution_capacity?.total_available ?? workerStats?.current_count ?? workerStats?.count ?? 0

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
    if (activeTesting && !authorized) {
      setError('Confirm that you own or are authorized to actively test every target.')
      return
    }

    const advanced = Object.fromEntries(
      Object.entries(limits)
        .filter(([, value]) => value.trim() !== '')
        .map(([key, value]) => [key, Number.parseInt(value, 10)])
        .filter(([, value]) => Number.isFinite(value as number) && Number(value) > 0),
    )
    const endpointList = customEndpoints.split(/\r?\n/).map((value) => value.trim()).filter(Boolean)
    const authentication = {
      ...(authHeader.trim() ? { auth_header: authHeader.trim() } : {}),
      ...(authCookies.trim() ? { auth_cookies: authCookies.trim() } : {}),
    }
    const common = {
      budget_profile: budgetProfile,
      policy: {
        active_testing: activeTesting,
        subdomain_discovery: subdomainDiscovery,
        network_discovery: networkDiscovery,
      },
      authentication,
      advanced,
      approval_receipt_id: approvalReceipt.trim() || undefined,
      options: {
        ...(authHeader.trim() ? { auth_header: authHeader.trim() } : {}),
        ...(authCookies.trim() ? { auth_cookies: authCookies.trim() } : {}),
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
              <input type="checkbox" checked={batchMode} onChange={(event) => setBatchMode(event.target.checked)} />
              Multiple targets
            </label>
          </div>
          {batchMode ? (
            <textarea value={batchTargets} onChange={(event) => setBatchTargets(event.target.value)} rows={6} placeholder={'https://app.example.com\nhttps://api.example.com'} className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder:text-gray-600" />
          ) : (
            <>
              <input value={target} onChange={(event) => setTarget(event.target.value)} list="known-targets" placeholder="https://example.com" className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white placeholder:text-gray-600" />
              <datalist id="known-targets">{existingTargets.map((item) => <option key={item.id} value={item.url} />)}</datalist>
            </>
          )}
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
            <input className="mt-1" type="checkbox" checked={activeTesting} onChange={(event) => { setActiveTesting(event.target.checked); if (!event.target.checked) setAuthorized(false) }} />
            <span>
              <span className="block text-sm font-medium text-white">Allow active testing</span>
              <span className="block text-xs text-gray-500">Permit bounded XSS, SQL injection, authorization, and other proof-oriented probes.</span>
            </span>
          </label>
          {activeTesting && (
            <label className="flex items-start gap-3 rounded-lg border border-amber-800/70 bg-amber-950/20 p-4 text-sm text-amber-100">
              <input className="mt-1" type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} />
              <span>I own or have explicit authorization to actively test every submitted target.</span>
            </label>
          )}
          <div className="grid gap-3 md:grid-cols-2">
            <label className="flex items-center gap-3 text-sm text-gray-300"><input type="checkbox" checked={subdomainDiscovery} onChange={(event) => setSubdomainDiscovery(event.target.checked)} />Discover subdomains</label>
            <label className="flex items-center gap-3 text-sm text-gray-300"><input type="checkbox" checked={networkDiscovery} onChange={(event) => setNetworkDiscovery(event.target.checked)} />Discover network services</label>
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
              <div className="grid gap-4 md:grid-cols-2">
                <label className="text-sm text-gray-300">Authorization header<input value={authHeader} onChange={(event) => setAuthHeader(event.target.value)} placeholder="Bearer …" className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-white" /></label>
                <label className="text-sm text-gray-300">Cookies<input value={authCookies} onChange={(event) => setAuthCookies(event.target.value)} placeholder="session=…" className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-white" /></label>
              </div>
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
