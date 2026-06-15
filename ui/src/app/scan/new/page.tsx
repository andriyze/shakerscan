'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { submitScan } from '@/lib/api'
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
  const [scanType, setScanType] = useState<ScanType>('quick')
  const [budgetProfile, setBudgetProfile] = useState<BudgetProfile>('balanced')
  const [loading, setLoading] = useState(false)
  const [parallelEnabled, setParallelEnabled] = useState(false)
  const [parallelStrategy, setParallelStrategy] = useState<ParallelStrategy>('auto')
  const [parallelShards, setParallelShards] = useState<'auto' | '2' | '3' | '4' | '6'>('auto')
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
  const [customBudgetEnabled, setCustomBudgetEnabled] = useState(false)
  const [customBudget, setCustomBudget] = useState({
    max_duration_minutes: '',
    discovery_depth: '',
    max_urls: '',
    browser_max_pages: '',
    browser_max_depth: '',
    api_probe_limit: '',
    nuclei_max_targets: '',
    active_max_seconds: '',
    active_max_endpoints: '',
    active_params_per_endpoint: '',
    smart_bola_max_endpoints: '',
    dom_xss_max_files: ''
  })

  const customEndpoints = customEndpointsText
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)

  const parallelFamilySupported = supportsParallelFamily(scanType)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const validationError = validateTarget(target)
    if (validationError) {
      setTargetError(validationError)
      return
    }

    setLoading(true)
    setTargetError(null)

    try {
      if (parallelEnabled) {
        const hasScopeEndpoints = customEndpoints.length >= 2
        if (parallelStrategy === 'scope' && !hasScopeEndpoints) {
          toast.error('Endpoint scope sharding needs at least two custom endpoints.')
          setLoading(false)
          return
        }
        if (parallelStrategy !== 'scope' && !hasScopeEndpoints && !parallelFamilySupported) {
          toast.error('Parallel auto/family mode needs Smart, Full, or Aggressive scan type unless custom endpoints are provided.')
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
      const scanOptions: Record<string, unknown> = {
        ...getScanOptions(scanType),
        budget_profile: budgetProfile,
        ...(customEndpoints.length > 0 ? { custom_endpoints: customEndpoints } : {}),
        ...(parallelEnabled
          ? {
              parallel: true,
              shards: parallelShards === 'auto' ? 'auto' : Number.parseInt(parallelShards, 10),
              shard_strategy: parallelStrategy
            }
          : {}),
        ...(showAdvanced ? options : {}),
        ...(showAdvanced && customBudgetEnabled && Object.keys(customBudgetPayload).length > 0
          ? { custom_budget: customBudgetPayload }
          : {})
      }

      const result = await submitScan(target.trim(), scanOptions)
      toast.success(
        'Scan started',
        result?.scan_id
          ? { link: { href: `/scans/${result.scan_id}`, label: 'View scan' } }
          : undefined
      )
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

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target Input */}
        <Card className="p-4">
          <label htmlFor="scan-target" className="block text-sm font-medium text-gray-400 mb-2">
            Target URL
          </label>
          <input
            id="scan-target"
            type="text"
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
          <div className="grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => setParallelEnabled(false)}
              className={`p-3 rounded-lg border text-left transition-colors ${
                !parallelEnabled
                  ? 'border-blue-500 bg-blue-500/10'
                  : 'border-gray-700 bg-gray-800 hover:border-gray-600'
              }`}
            >
              <div className="font-medium text-white">Normal</div>
              <div className="text-xs text-gray-500 mt-1">One worker handles this scan.</div>
            </button>
            <button
              type="button"
              onClick={() => setParallelEnabled(true)}
              className={`p-3 rounded-lg border text-left transition-colors ${
                parallelEnabled
                  ? 'border-blue-500 bg-blue-500/10'
                  : 'border-gray-700 bg-gray-800 hover:border-gray-600'
              }`}
            >
              <div className="font-medium text-white">Parallel</div>
              <div className="text-xs text-gray-500 mt-1">Fan out work across available workers.</div>
            </button>
          </div>

          {parallelEnabled && (
            <div className="mt-4 space-y-4 border-t border-gray-800 pt-4">
              <div className="grid grid-cols-2 gap-3">
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
              </div>
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
                Endpoint scope sharding is the fastest path when you provide known endpoints.
                Without endpoints, parallel mode is useful for Smart, Full, and Aggressive scans through broad/SQLi/XSS family shards.
              </p>
            </div>
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
                        min="0"
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
              Start Scan
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
