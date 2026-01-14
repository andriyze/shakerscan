'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { submitScan } from '@/lib/api'

export default function NewScanPage() {
  const router = useRouter()
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState<'quick' | 'standard' | 'thorough' | 'full' | 'smart'>('quick')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

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

  const scanTypes = {
    quick: {
      name: 'Quick Scan',
      description: 'DNS, TLS, and security headers only. Fast (~1-2 min)',
      options: { quick: true, public: true }
    },
    standard: {
      name: 'Standard Scan',
      description: 'Full passive reconnaissance with technology detection (~5-10 min)',
      options: { quick: false, public: false }
    },
    thorough: {
      name: 'Thorough Scan',
      description: 'Includes Nuclei templates and deep discovery (~30-60 min)',
      options: { quick: false, thorough: true }
    },
    full: {
      name: 'Full Assessment',
      description: 'All checks including active vulnerability testing (~45-90 min)',
      options: { quick: false, thorough: true, active: true }
    },
    smart: {
      name: 'Smart Scan',
      description: 'Adaptive scanning: staged templates, DBMS-aware SQLi, context-aware XSS',
      options: { scan_type: 'smart' }
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!target.trim()) {
      setError('Please enter a target URL')
      return
    }

    setLoading(true)
    setError(null)

    try {
      // Combine scan type options with advanced options
      const scanOptions = {
        ...scanTypes[scanType].options,
        ...(showAdvanced ? options : {})
      }

      const result = await submitScan(target.trim(), scanOptions)
      router.push(`/scans`)
    } catch (err) {
      setError('Failed to submit scan. Is the API running?')
    } finally {
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
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <label className="block text-sm font-medium text-gray-400 mb-2">
            Target URL
          </label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://example.com"
            className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 text-lg"
          />
          <p className="text-xs text-gray-500 mt-2">
            Enter a URL or domain to scan (e.g., https://example.com or example.com)
          </p>
        </div>

        {/* Scan Type Selection */}
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <label className="block text-sm font-medium text-gray-400 mb-3">
            Scan Type
          </label>
          <div className="grid grid-cols-2 gap-3">
            {(Object.entries(scanTypes) as [keyof typeof scanTypes, typeof scanTypes[keyof typeof scanTypes]][]).map(([key, type]) => (
              <button
                key={key}
                type="button"
                onClick={() => setScanType(key)}
                className={`p-3 rounded-lg border text-left transition-colors ${
                  scanType === key
                    ? 'border-blue-500 bg-blue-500/10'
                    : 'border-gray-700 bg-gray-800 hover:border-gray-600'
                }`}
              >
                <div className="font-medium text-white">{type.name}</div>
                <div className="text-xs text-gray-500 mt-1">{type.description}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Advanced Options */}
        <div className="bg-gray-900 rounded-lg border border-gray-800">
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
            </div>
          )}
        </div>

        {/* Error Message */}
        {error && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 text-red-400 text-sm">
            {error}
          </div>
        )}

        {/* Submit Button */}
        <button
          type="submit"
          disabled={loading}
          className="w-full py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-600/50 text-white rounded-lg font-medium transition-colors flex items-center justify-center gap-2"
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
        </button>

        {/* Warning for Active Testing */}
        {(scanType === 'full' || scanType === 'smart' || options.active) && (
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
