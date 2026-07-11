'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { submitScan, submitBatch, getScanExecutionSettings, getTargets, getWorkers, type Target } from '@/lib/api'
import {
  BUDGET_PROFILES,
  PARALLEL_STRATEGIES,
  SCAN_TYPES,
  getScanOptions,
  supportsParallelFamily,
  type BudgetProfile,
  type ParallelStrategy,
  type ScanType
} from '@/lib/constants'
import { Button, Card, useToast } from '@/components/ui'

const HOSTNAME_PATTERN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i
const IPV4_PATTERN = /^\d{1,3}(\.\d{1,3}){3}$/
type ExecutionMode = 'auto' | 'normal' | 'parallel' | 'coverage'
type ShardSelection = 'auto' | '2' | '3' | '4' | '6' | '12' | '20'
type CoveragePerShardSelection = '50' | '100' | '150' | '250'
type CoverageMaxShardSelection = '32' | '64' | '128'
type CoverageDepth = 'standard' | 'deep'

function validateTarget(value: string): string | null {
  const trimmed = value.trim()
  if (!trimmed) {
    return 'Please enter a target URL'
  }
  if (/\s/.test(trimmed)) {
    return 'Target cannot contain spaces'
  }
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`
  let url: URL
  try {
    url = new URL(candidate)
  } catch {
    return 'Enter a valid URL or domain (e.g., https://example.com)'
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return 'Only http(s) targets are supported'
  }
  const host = url.hostname
  if (!host) {
    return 'Enter a valid URL or domain (e.g., https://example.com)'
  }
  const isLocalhost = host === 'localhost'
  const isIPv6 = host.startsWith('[') || host.includes(':')
  const isIPv4 = IPV4_PATTERN.test(host)
  if (!isLocalhost && !isIPv4 && !isIPv6 && (!HOSTNAME_PATTERN.test(host) || !host.includes('.'))) {
    return 'Enter a valid URL or domain (e.g., https://example.com)'
  }
  return null
}

export default function NewScanPage() {
  const router = useRouter()
  const toast = useToast()
  const [target, setTarget] = useState('')
  const [targetError, setTargetError] = useState<string | null>(null)
  const [batchMode, setBatchMode] = useState(false)
  const [batchTargets, setBatchTargets] = useState('')
  const [existingTargets, setExistingTargets] = useState<Target[]>([])
  const [scanType, setScanType] = useState<ScanType>('quick')
  const [budgetProfile, setBudgetProfile] = useState<BudgetProfile>('balanced')
  const [loading, setLoading] = useState(false)
  const [executionMode, setExecutionMode] = useState<ExecutionMode>('auto')
  const [parallelStrategy, setParallelStrategy] = useState<ParallelStrategy>('auto')
  const [parallelShards, setParallelShards] = useState<ShardSelection>('auto')
  const [coveragePerShardCap, setCoveragePerShardCap] = useState<CoveragePerShardSelection>('50')
  const [coverageMaxShards, setCoverageMaxShards] = useState<CoverageMaxShardSelection>('128')
  const [coverageDepth, setCoverageDepth] = useState<CoverageDepth>('standard')
  const [runningWorkers, setRunningWorkers] = useState<number | null>(null)
  const [staleWorkers, setStaleWorkers] = useState<number>(0)

  useEffect(() => {
    let cancelled = false
    getScanExecutionSettings()
      .then((s) => { if (!cancelled) setRunningWorkers(s.running_workers ?? null) })
      .catch(() => { /* worker count is advisory; ignore failures */ })
    // §2: warn before launching active scans on a build-stale fleet.
    getWorkers()
      .then((w) => { if (!cancelled) setStaleWorkers(w.stale_workers?.length ?? 0) })
      .catch(() => { /* freshness is advisory; ignore failures */ })
    getTargets()
      .then((rows) => {
        if (cancelled) return
        const list = Array.isArray(rows?.targets) ? rows.targets : Array.isArray(rows) ? rows : []
        setExistingTargets(list)
      })
      .catch(() => { /* target suggestions are optional; ignore failures */ })
    return () => { cancelled = true }
  }, [])
  const [customEndpointsText, setCustomEndpointsText] = useState('')

  // Advanced options
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [options, setOptions] = useState({
    active: false,
    nuclei: false,
    subfinder: false,
    enhanced_dns: false,
    js_dependency_scanning: false,
    js_secret_scanning: false
  })
  const [authInputs, setAuthInputs] = useState({
    auth_header: '',
    auth_cookies: '',
    user2_header: '',
    user2_cookies: ''
  })
  const [customBudgetEnabled, setCustomBudgetEnabled] = useState(false)
  const [enforceRequestBudget, setEnforceRequestBudget] = useState(false)
  const [customBudget, setCustomBudget] = useState({
    max_duration_minutes: '',
    discovery_depth: '',
    max_urls: '',
    browser_max_pages: '',
    browser_max_depth: '',
    api_probe_limit: '',
    nuclei_max_targets: '',
    param_discovery_url_limit: '',
    param_discovery_max_params: '',
    phase4_max_seconds: '',
    active_max_seconds: '',
    active_max_endpoints: '',
    active_params_per_endpoint: '',
    active_worklist_max: '',
    request_max: '',
    max_findings_per_family: '',
    smart_bola_max_endpoints: '',
    dom_xss_max_files: '',
    sqli_extract_max: '',
    oob_max_findings: ''
  })

  const customEndpoints = customEndpointsText
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)

  const parallelFamilySupported = supportsParallelFamily(scanType)

  function selectExecutionMode(value: ExecutionMode) {
    setExecutionMode(value)
    if (value === 'coverage') {
      setParallelStrategy('coverage')
      setParallelShards('auto')
      setBudgetProfile('exhaustive')
      if (!supportsParallelFamily(scanType)) {
        setScanType('smart')
      }
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    let batchList: string[] = []
    if (batchMode) {
      batchList = batchTargets.split(/\n/).map((s) => s.trim()).filter(Boolean)
      if (batchList.length === 0) {
        setTargetError('Enter at least one target URL (one per line).')
        return
      }
      const firstInvalid = batchList.map((t) => validateTarget(t)).find(Boolean)
      if (firstInvalid) {
        setTargetError(firstInvalid)
        return
      }
    } else {
      const validationError = validateTarget(target)
      if (validationError) {
        setTargetError(validationError)
        return
      }
    }

    setLoading(true)
    setTargetError(null)

    try {
      const isCoverageMode = executionMode === 'coverage'
      const isParallelMode = executionMode === 'parallel' || isCoverageMode
      const resolvedParallelStrategy = isCoverageMode ? 'coverage' : parallelStrategy

      if (isParallelMode) {
        const hasScopeEndpoints = customEndpoints.length >= 2
        if (resolvedParallelStrategy === 'scope' && !hasScopeEndpoints) {
          toast.error('Endpoint scope sharding needs at least two custom endpoints.')
          setLoading(false)
          return
        }
        if (resolvedParallelStrategy !== 'scope' && !hasScopeEndpoints && !parallelFamilySupported) {
          toast.error('Parallel coverage and family modes need Smart, Full, or Aggressive scan type unless custom endpoints are provided.')
          setLoading(false)
          return
        }
      }

      // Combine scan type options with advanced options
      const customBudgetPayload = Object.fromEntries(
        Object.entries(customBudget)
          .filter(([, value]) => value.trim() !== '')
          .map(([key, value]) => [key, Number.parseInt(value, 10)])
          .filter(([, value]) => Number.isFinite(value as number))
      )
      // Coverage breadth (test every endpoint) is decoupled from depth. Standard
      // coverage stays broad-but-sane; Deep adds exhaustive budget + exploit-depth.
      const isDeepCoverage = isCoverageMode && coverageDepth === 'deep'
      const coverageBudgetPayload = isCoverageMode
        ? {
            active_worklist_max: 50000,
            param_discovery_url_limit: 500,
            param_discovery_max_params: 100,
            ...(isDeepCoverage
              ? {
                  active_params_per_endpoint: 20,
                  max_findings_per_family: -1,
                  sqli_extract_max: 25,
                  oob_max_findings: 25
                }
              : {})
          }
        : {}
      const effectiveCustomBudget = {
        ...coverageBudgetPayload,
        ...(showAdvanced && customBudgetEnabled ? customBudgetPayload : {})
      }
      const authPayload = Object.fromEntries(
        Object.entries(authInputs)
          .map(([key, value]) => [key, value.trim()])
          .filter(([, value]) => value !== '')
      )
      const shardAuthStates = isCoverageMode && Object.keys(authPayload).length > 0
      const scanOptions: Record<string, unknown> = {
        ...getScanOptions(scanType),
        budget_profile: isCoverageMode ? (isDeepCoverage ? 'exhaustive' : 'thorough') : budgetProfile,
        request_budget_mode: enforceRequestBudget ? 'enforce' : 'compatibility',
        ...(isParallelMode && customEndpoints.length > 0 ? { custom_endpoints: customEndpoints } : {}),
        ...(executionMode === 'normal' ? { parallel: false } : {}),
        ...(isParallelMode
          ? {
              parallel: true,
              shards: parallelShards === 'auto' ? 'auto' : Number.parseInt(parallelShards, 10),
              shard_strategy: resolvedParallelStrategy,
              ...(resolvedParallelStrategy === 'coverage'
                ? {
                    coverage_per_shard_cap: Number.parseInt(coveragePerShardCap, 10),
                    coverage_max_shards: Number.parseInt(coverageMaxShards, 10),
                    ...(isDeepCoverage ? { exploit_depth: true } : {})
                  }
                : {})
            }
          : {}),
        ...(shardAuthStates ? { auth_state_shards: true } : {}),
        ...authPayload,
        ...(showAdvanced ? options : {}),
        ...(Object.keys(effectiveCustomBudget).length > 0
          ? { custom_budget: effectiveCustomBudget }
          : {})
      }

      if (batchMode) {
        const result = await submitBatch(batchList, scanOptions)
        toast.success(`Queued ${result.count} scan(s)`, { link: { href: '/scans', label: 'View scans' } })
      } else {
        const result = await submitScan(target.trim(), scanOptions)
        toast.success(
          result?.auto_sharded ? 'Auto-sharded scan started' : result?.parallel ? 'Parallel scan started' : 'Scan started',
          result?.scan_id
            ? { link: { href: `/scans/${result.scan_id}`, label: 'View scan' } }
            : undefined
        )
      }
      router.push(`/scans`)
    } catch (err) {
      toast.error(err instanceof Error && err.message ? err.message : 'Failed to submit scan. Is the API running?')
      setLoading(false)
    }
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">New Scan</h1>
        <p className="text-gray-400 mt-1">Start a security scan on a target</p>
      </div>

      {staleWorkers > 0 && (
        <div className="rounded border border-amber-600/50 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">
          ⚠ {staleWorkers} worker{staleWorkers === 1 ? '' : 's'} are running older code than the
          current build. Active scans may use stale detectors — restart workers before validating
          (Dashboard → Workers), or results may not reflect the latest scanner.
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target Input */}
        <Card className="p-4">
          <div className="mb-2 flex items-center justify-between">
            <label htmlFor="scan-target" className="block text-sm font-medium text-gray-400">
              {batchMode ? 'Target URLs (one per line)' : 'Target URL'}
              {!batchMode && existingTargets.length > 0 && (
                <span className="text-gray-500 font-normal"> — type a new URL or pick an existing target</span>
              )}
            </label>
            <label className="flex items-center gap-2 text-xs text-gray-400">
              <input
                type="checkbox"
                checked={batchMode}
                onChange={(e) => { setBatchMode(e.target.checked); setTargetError(null) }}
                className="accent-blue-500"
              />
              Batch (multiple targets)
            </label>
          </div>
          {batchMode ? (
            <textarea
              id="scan-target"
              value={batchTargets}
              onChange={(e) => {
                setBatchTargets(e.target.value)
                if (targetError) setTargetError(null)
              }}
              rows={5}
              placeholder={'https://example.com\nhttps://api.example.com\nhttps://staging.example.com'}
              aria-invalid={targetError ? true : undefined}
              aria-describedby={targetError ? 'scan-target-error' : undefined}
              className={`w-full px-4 py-3 bg-gray-800 border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 font-mono text-sm ${
                targetError ? 'border-red-500/50' : 'border-gray-700'
              }`}
            />
          ) : (
            <input
              id="scan-target"
              type="text"
              list="existing-targets"
              value={target}
              onChange={(e) => {
                setTarget(e.target.value)
                if (targetError) setTargetError(null)
              }}
              placeholder="https://example.com"
              aria-invalid={targetError ? true : undefined}
              aria-describedby={targetError ? 'scan-target-error' : undefined}
              className={`w-full px-4 py-3 bg-gray-800 border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 text-lg ${
                targetError ? 'border-red-500/50' : 'border-gray-700'
              }`}
            />
          )}
          {existingTargets.length > 0 && (
            <datalist id="existing-targets">
              {existingTargets.map((t) => (
                <option key={t.id} value={t.url}>
                  {t.name ? `${t.name} — ${t.url}` : t.url}
                </option>
              ))}
            </datalist>
          )}
          {targetError && (
            <p id="scan-target-error" className="text-sm text-red-400 mt-2">
              {targetError}
            </p>
          )}
          <p className="text-xs text-gray-500 mt-2">
            Enter a URL or domain to scan (e.g., https://example.com or example.com)
          </p>
        </Card>

        {/* Coverage Budget */}
        <Card className="p-4">
          <label className="block text-sm font-medium text-gray-400 mb-3">
            Coverage Budget
          </label>
          <div className="grid grid-cols-2 gap-3">
            {BUDGET_PROFILES.map((profile) => (
              <button
                key={profile.value}
                type="button"
                onClick={() => setBudgetProfile(profile.value)}
                className={`p-3 rounded-lg border text-left transition-colors ${
                  budgetProfile === profile.value
                    ? 'border-blue-500 bg-blue-500/10'
                    : 'border-gray-700 bg-gray-800 hover:border-gray-600'
                }`}
              >
                <div className="font-medium text-white">{profile.label}</div>
                <div className="text-xs text-gray-500 mt-1">{profile.description}</div>
              </button>
            ))}
          </div>
        </Card>

        {/* Scan Type Selection */}
        <Card className="p-4">
          <label className="block text-sm font-medium text-gray-400 mb-3">
            Scan Type
          </label>
          <div className="grid grid-cols-2 gap-3">
            {SCAN_TYPES.map((type) => (
              <button
                key={type.value}
                type="button"
                onClick={() => setScanType(type.value)}
                className={`p-3 rounded-lg border text-left transition-colors ${
                  scanType === type.value
                    ? 'border-blue-500 bg-blue-500/10'
                    : 'border-gray-700 bg-gray-800 hover:border-gray-600'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-medium text-white">{type.label}</span>
                  {type.requiresPermission && (
                    <span className="text-xs text-yellow-500">Active</span>
                  )}
                </div>
                <div className="text-xs text-gray-500 mt-1">
                  {type.duration ? `${type.duration} - ` : ''}{type.description}
                </div>
              </button>
            ))}
          </div>
        </Card>

        {/* Execution Mode */}
        <Card className="p-4">
          <label className="block text-sm font-medium text-gray-400 mb-3">
            Execution
          </label>
          <div className="grid gap-2 sm:grid-cols-4">
            {([
              ['auto', 'Auto', 'Use the global auto-sharding setting.'],
              ['normal', 'Normal', 'Force one worker.'],
              ['parallel', 'Parallel', 'Force shard fan-out.'],
              ['coverage', 'Full Coverage', 'Discover once, test every endpoint — heaviest mode.']
            ] as const).map(([value, label, description]) => (
              <button
                key={value}
                type="button"
                onClick={() => selectExecutionMode(value)}
                className={`p-3 rounded-lg border text-left transition-colors ${
                  executionMode === value
                    ? 'border-blue-500 bg-blue-500/10'
                    : 'border-gray-700 bg-gray-800 hover:border-gray-600'
                }`}
              >
                <div className="font-medium text-white">{label}</div>
                <div className="text-xs text-gray-500 mt-1">{description}</div>
              </button>
            ))}
          </div>

          <p className="mt-3 text-xs text-gray-500">
            Auto follows Settings. Full Coverage is the high-budget path for Smart, Full, and Aggressive scans.
          </p>

          {(executionMode === 'parallel' || executionMode === 'coverage') && (
            <details className="mt-4 border-t border-gray-800 pt-4">
              <summary className="cursor-pointer text-sm text-gray-300 hover:text-white">
                {executionMode === 'coverage' ? 'Full coverage tuning' : 'Parallel tuning'}
              </summary>
              <div className="mt-4 space-y-4">
              <div className={`grid gap-3 ${executionMode === 'parallel' ? 'grid-cols-2' : 'grid-cols-1'}`}>
                {executionMode === 'parallel' ? (
                  <>
                  <label className="space-y-1">
                    <span className="block text-xs text-gray-500">Shards</span>
                    <select
                      value={parallelShards}
                      onChange={(event) => setParallelShards(event.target.value as typeof parallelShards)}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm text-white focus:outline-none focus:border-blue-500"
                    >
                      <option value="auto">Auto</option>
                      <option value="2">2</option>
                      <option value="3">3</option>
                      <option value="4">4</option>
                      <option value="6">6</option>
                      <option value="12">12</option>
                      <option value="20">20</option>
                    </select>
                  </label>
                  <label className="space-y-1">
                    <span className="block text-xs text-gray-500">Strategy</span>
                    <select
                      value={parallelStrategy}
                      onChange={(event) => setParallelStrategy(event.target.value as ParallelStrategy)}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm text-white focus:outline-none focus:border-blue-500"
                    >
                      {PARALLEL_STRATEGIES.map((strategy) => (
                        <option key={strategy.value} value={strategy.value}>{strategy.label}</option>
                      ))}
                    </select>
                  </label>
                  </>
                ) : (
                  <label className="space-y-1">
                    <span className="block text-xs text-gray-500">Strategy</span>
                    <input
                      value="Full coverage"
                      readOnly
                      className="w-full px-3 py-2 bg-gray-900 border border-gray-800 rounded text-sm text-gray-400"
                    />
                  </label>
                )}
              </div>
              {(executionMode === 'coverage' || parallelStrategy === 'coverage') && (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <label className="space-y-1">
                      <span className="block text-xs text-gray-500">Coverage depth</span>
                      <select
                        value={coverageDepth}
                        onChange={(event) => setCoverageDepth(event.target.value as CoverageDepth)}
                        className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm text-white focus:outline-none focus:border-blue-500"
                      >
                        <option value="standard">Standard (broad, thorough budget)</option>
                        <option value="deep">Deep (exhaustive + exploit-depth)</option>
                      </select>
                    </label>
                    <label className="space-y-1">
                      <span className="block text-xs text-gray-500">Target endpoints per shard</span>
                      <select
                        value={coveragePerShardCap}
                        onChange={(event) => setCoveragePerShardCap(event.target.value as CoveragePerShardSelection)}
                        className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm text-white focus:outline-none focus:border-blue-500"
                      >
                        <option value="50">50</option>
                        <option value="100">100</option>
                        <option value="150">150</option>
                        <option value="250">250</option>
                      </select>
                    </label>
                  </div>
                  <label className="space-y-1 block">
                    <span className="block text-xs text-gray-500">Max coverage shards</span>
                    <select
                      value={coverageMaxShards}
                      onChange={(event) => setCoverageMaxShards(event.target.value as CoverageMaxShardSelection)}
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm text-white focus:outline-none focus:border-blue-500"
                    >
                      <option value="32">32</option>
                      <option value="64">64</option>
                      <option value="128">128</option>
                    </select>
                  </label>
                  <p className="text-xs text-amber-400/80">
                    ⚠ Heaviest mode: discovers once, then tests <em>every</em> endpoint across many shards
                    {runningWorkers != null ? ` (currently ${runningWorkers} worker${runningWorkers === 1 ? '' : 's'} — scale workers to match shard count for speed)` : ' — scale workers to match shard count for speed'}.
                    “Target endpoints per shard” is a goal; slices grow to preserve coverage when the worklist is large.
                    {coverageDepth === 'deep' ? ' Deep adds exhaustive budget + exploit-depth — expect very heavy target load.' : ''}
                  </p>
                </div>
              )}
              <label className="space-y-1 block">
                <span className="block text-xs text-gray-500">Known API endpoints for scope sharding</span>
                <textarea
                  value={customEndpointsText}
                  onChange={(event) => setCustomEndpointsText(event.target.value)}
                  rows={4}
                  placeholder={'GET /api/users?id=1\nPOST /api/login username,password'}
                  className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500"
                />
              </label>
              <p className="text-xs text-gray-500">
                Scope is fastest when you provide known endpoints. Full Coverage first discovers endpoints, then partitions the full active worklist across coverage shards.
              </p>
              </div>
            </details>
          )}
        </Card>

        {/* Advanced Options */}
        <Card>
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="w-full p-4 flex items-center justify-between text-left"
          >
            <span className="text-sm font-medium text-gray-400">Advanced Options</span>
            <svg
              className={`w-5 h-5 text-gray-500 transition-transform ${showAdvanced ? 'rotate-180' : ''}`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          {showAdvanced && (
            <div className="p-4 pt-0 space-y-3">
              <OptionToggle
                label="Active Testing"
                description="XSS and SQLi probes (intrusive)"
                checked={options.active}
                onChange={(checked) => setOptions({ ...options, active: checked })}
              />
              <OptionToggle
                label="Nuclei Templates"
                description="5000+ vulnerability templates"
                checked={options.nuclei}
                onChange={(checked) => setOptions({ ...options, nuclei: checked })}
              />
              <OptionToggle
                label="Subdomain Discovery"
                description="Find subdomains via CT logs"
                checked={options.subfinder}
                onChange={(checked) => setOptions({ ...options, subfinder: checked })}
              />
              <OptionToggle
                label="Enhanced DNS"
                description="DKIM, zone transfer, SPF analysis"
                checked={options.enhanced_dns}
                onChange={(checked) => setOptions({ ...options, enhanced_dns: checked })}
              />
              <OptionToggle
                label="JS Dependency Scanning"
                description="Find vulnerable JavaScript libraries"
                checked={options.js_dependency_scanning}
                onChange={(checked) => setOptions({ ...options, js_dependency_scanning: checked })}
              />
              <OptionToggle
                label="JS Secret Scanning"
                description="Detect hardcoded API keys in JS"
                checked={options.js_secret_scanning}
                onChange={(checked) => setOptions({ ...options, js_secret_scanning: checked })}
              />
              <div className="border-t border-gray-800 pt-3">
                <div className="text-xs font-medium uppercase text-gray-500">Authentication</div>
                <div className="mt-3 grid gap-3">
                  <label className="space-y-1">
                    <span className="block text-xs text-gray-500">User 1 auth header</span>
                    <input
                      value={authInputs.auth_header}
                      onChange={(event) => setAuthInputs({ ...authInputs, auth_header: event.target.value })}
                      placeholder="Bearer eyJ..."
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500"
                    />
                  </label>
                  <label className="space-y-1">
                    <span className="block text-xs text-gray-500">User 1 cookies</span>
                    <input
                      value={authInputs.auth_cookies}
                      onChange={(event) => setAuthInputs({ ...authInputs, auth_cookies: event.target.value })}
                      placeholder="session=abc; csrf=..."
                      className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500"
                    />
                  </label>
                  <div className="grid grid-cols-2 gap-3">
                    <label className="space-y-1">
                      <span className="block text-xs text-gray-500">User 2 auth header</span>
                      <input
                        value={authInputs.user2_header}
                        onChange={(event) => setAuthInputs({ ...authInputs, user2_header: event.target.value })}
                        placeholder="Bearer eyJ..."
                        className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500"
                      />
                    </label>
                    <label className="space-y-1">
                      <span className="block text-xs text-gray-500">User 2 cookies</span>
                      <input
                        value={authInputs.user2_cookies}
                        onChange={(event) => setAuthInputs({ ...authInputs, user2_cookies: event.target.value })}
                        placeholder="session=def"
                        className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500"
                      />
                    </label>
                  </div>
                </div>
              </div>
              <OptionToggle
                label="Enforce Request Budget"
                description="Stop outbound target requests at the resolved request limit"
                checked={enforceRequestBudget}
                onChange={setEnforceRequestBudget}
              />
              <OptionToggle
                label="Custom Budget"
                description="Override selected depth and timeout limits"
                checked={customBudgetEnabled}
                onChange={setCustomBudgetEnabled}
              />
              {customBudgetEnabled && (
                <div className="grid grid-cols-2 gap-3 border-t border-gray-800 pt-3">
                  {Object.entries(customBudget).map(([key, value]) => (
                    <label key={key} className="space-y-1">
                      <span className="block text-xs text-gray-500">
                        {key.replaceAll('_', ' ')}
                      </span>
                      <input
                        type="number"
                        min={key === 'max_findings_per_family' ? '-1' : '0'}
                        value={value}
                        onChange={(event) => setCustomBudget({ ...customBudget, [key]: event.target.value })}
                        placeholder="profile default"
                        className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-500"
                      />
                    </label>
                  ))}
                </div>
              )}
            </div>
          )}
        </Card>

        {/* Submit Button */}
        <Button
          type="submit"
          disabled={loading}
          className="w-full py-3 text-base"
        >
          {loading ? (
            <>
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
              Starting Scan...
            </>
          ) : (
            <>
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              {batchMode ? 'Start Batch Scan' : 'Start Scan'}
            </>
          )}
        </Button>

        {/* Warning for Active Testing */}
        {(SCAN_TYPES.find(t => t.value === scanType)?.requiresPermission || options.active) && (
          <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-3 text-yellow-400 text-sm">
            <strong>Warning:</strong> Active testing sends probes that may trigger security alerts.
            Only scan targets you own or have explicit permission to test.
          </div>
        )}
      </form>
    </div>
  )
}

function OptionToggle({
  label,
  description,
  checked,
  onChange
}: {
  label: string
  description: string
  checked: boolean
  onChange: (checked: boolean) => void
}) {
  return (
    <label className="flex items-start gap-3 cursor-pointer">
      <div className="relative mt-0.5">
        <input
          type="checkbox"
          checked={checked}
          onChange={(e) => onChange(e.target.checked)}
          className="sr-only peer"
        />
        <div className="w-9 h-5 bg-gray-700 rounded-full peer-checked:bg-blue-600 transition-colors"></div>
        <div className="absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full peer-checked:translate-x-4 transition-transform"></div>
      </div>
      <div>
        <div className="text-sm text-white">{label}</div>
        <div className="text-xs text-gray-500">{description}</div>
      </div>
    </label>
  )
}
