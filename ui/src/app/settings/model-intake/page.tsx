'use client'

import { useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { CheckCircle2, Clipboard, FileJson, PackageCheck, Play, RefreshCw, ShieldCheck, Wand2 } from 'lucide-react'
import {
  getAITestScenarios,
  submitModelIntakeScan,
  type AITestReadinessControl,
  type AITestScenario,
  type ModelIntakePreset,
  type ModelIntakeScanRequest,
} from '@/lib/api'

const inputClass =
  'w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none'
const textareaClass =
  'w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 font-mono text-xs text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none'

function parseOptionalJsonObject(raw: string): Record<string, unknown> | undefined {
  const trimmed = raw.trim()
  if (!trimmed) return undefined
  const parsed = JSON.parse(trimmed)
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Metadata JSON must be a JSON object')
  }
  return parsed as Record<string, unknown>
}

function optionalText(value: string): string | undefined {
  const trimmed = value.trim()
  return trimmed || undefined
}

function hasMetadataKey(metadata: Record<string, unknown> | undefined, keys: string[]) {
  if (!metadata) return false
  return keys.some((key) => {
    const value = metadata[key]
    if (value === undefined || value === null) return false
    if (typeof value === 'string') return value.trim().length > 0
    if (Array.isArray(value)) return value.length > 0
    if (typeof value === 'object') return Object.keys(value as Record<string, unknown>).length > 0
    return Boolean(value)
  })
}

export default function ModelIntakeSettingsPage() {
  const router = useRouter()
  const [artifactUrl, setArtifactUrl] = useState('')
  const [name, setName] = useState('')
  const [metadataUrl, setMetadataUrl] = useState('')
  const [metadataJson, setMetadataJson] = useState('')
  const [expectedSha256, setExpectedSha256] = useState('')
  const [signatureUrl, setSignatureUrl] = useState('')
  const [modelCardUrl, setModelCardUrl] = useState('')
  const [deploymentApproved, setDeploymentApproved] = useState(false)
  const [requireDeploymentApproval, setRequireDeploymentApproval] = useState(true)
  const [requireSignature, setRequireSignature] = useState(true)
  const [requireHash, setRequireHash] = useState(true)
  const [requireModelGovernance, setRequireModelGovernance] = useState(true)
  const [maxDownloadBytes, setMaxDownloadBytes] = useState('10000000')
  const [timeoutSeconds, setTimeoutSeconds] = useState('20')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [scenario, setScenario] = useState<AITestScenario | null>(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    getAITestScenarios()
      .then((payload) => {
        setScenario(payload.scenarios.find((item) => item.id === 'model-intake-pipeline') || null)
      })
      .catch(() => setScenario(null))
  }, [])

  const metadataPreview = useMemo(() => {
    try {
      const parsed = parseOptionalJsonObject(metadataJson)
      return parsed ? Object.keys(parsed).length : 0
    } catch {
      return null
    }
  }, [metadataJson])

  function buildPayload(): ModelIntakeScanRequest {
    const payload: ModelIntakeScanRequest = {
      artifact_url: artifactUrl.trim(),
      name: optionalText(name),
      metadata_url: optionalText(metadataUrl),
      metadata_json: parseOptionalJsonObject(metadataJson),
      expected_sha256: optionalText(expectedSha256),
      signature_url: optionalText(signatureUrl),
      model_card_url: optionalText(modelCardUrl),
      deployment_approved: deploymentApproved,
      require_deployment_approval: requireDeploymentApproval,
      require_signature: requireSignature,
      require_hash: requireHash,
      require_model_governance: requireModelGovernance,
      max_download_bytes: Number(maxDownloadBytes || 10000000),
      timeout_seconds: Number(timeoutSeconds || 20),
    }
    if (!payload.artifact_url) {
      throw new Error('Artifact URL is required')
    }
    return payload
  }

  function applyPreset(preset: ModelIntakePreset) {
    setArtifactUrl(preset.artifact_url || '')
    setName(preset.name || '')
    setMetadataUrl(preset.metadata_url || '')
    setMetadataJson(preset.metadata_json ? JSON.stringify(preset.metadata_json, null, 2) : '')
    setExpectedSha256(preset.expected_sha256 || '')
    setSignatureUrl(preset.signature_url || '')
    setModelCardUrl(preset.model_card_url || '')
    setDeploymentApproved(Boolean(preset.deployment_approved ?? preset.metadata_json?.deployment_approved))
    setRequireDeploymentApproval(preset.require_deployment_approval ?? true)
    setRequireSignature(preset.require_signature ?? true)
    setRequireHash(preset.require_hash ?? true)
    setRequireModelGovernance(preset.require_model_governance ?? true)
    setMaxDownloadBytes(String(preset.max_download_bytes || 10000000))
    setTimeoutSeconds(String(preset.timeout_seconds || 20))
  }

  async function copyPayload() {
    try {
      await navigator.clipboard.writeText(JSON.stringify(buildPayload(), null, 2))
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to copy payload')
    }
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      const result = await submitModelIntakeScan(buildPayload())
      router.push(`/scans/${result.scan_id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to queue model intake scan')
    } finally {
      setSubmitting(false)
    }
  }

  const parsedMetadata = useMemo(() => {
    try {
      return parseOptionalJsonObject(metadataJson) || {}
    } catch {
      return undefined
    }
  }, [metadataJson])
  const readinessMetadata: Record<string, unknown> = {
    ...(parsedMetadata || {}),
    artifact_url: artifactUrl.trim(),
    expected_sha256: expectedSha256.trim() || (metadataUrl.trim() ? 'manifest' : ''),
    signature_url: signatureUrl.trim() || (parsedMetadata?.signature_url as string | undefined),
    model_card_url: modelCardUrl.trim() || (parsedMetadata?.model_card_url as string | undefined),
    deployment_approved: deploymentApproved || parsedMetadata?.deployment_approved,
  }
  const readinessControls: AITestReadinessControl[] = scenario?.readiness_controls || []
  const missingControls = readinessControls.filter((control) => !hasMetadataKey(readinessMetadata, control.keys))
  const presentControls = readinessControls.length - missingControls.length

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <PackageCheck className="h-6 w-6 text-cyan-300" />
            <h1 className="text-2xl font-bold text-white">Model Intake</h1>
          </div>
          <p className="mt-1 text-gray-400">Queue model artifact checks before deployment approval.</p>
        </div>
        <Link href="/settings" className="rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800">
          Settings
        </Link>
      </div>

      {error && <div className="rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-400">{error}</div>}

      {scenario && (
        <section className="rounded-lg border border-gray-800 bg-gray-900 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="flex items-center gap-2 text-white">
                <ShieldCheck className="h-4 w-4 text-cyan-300" />
                <h2 className="text-sm font-semibold">{scenario.title}</h2>
              </div>
              <p className="mt-1 max-w-3xl text-sm text-gray-400">{scenario.summary}</p>
            </div>
            {scenario.honey_contract?.registry_url && (
              <a href={scenario.honey_contract.registry_url} target="_blank" rel="noreferrer" className="rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800">
                Honey registry
              </a>
            )}
          </div>

          <div className="mt-4 grid gap-3 xl:grid-cols-[1.35fr_0.65fr]">
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {(scenario.request_presets || []).map((preset) => (
                <button
                  key={preset.key}
                  type="button"
                  onClick={() => applyPreset(preset)}
                  className="rounded-lg border border-gray-700 bg-gray-950 p-3 text-left hover:border-cyan-500/60 hover:bg-gray-800"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium text-white">{preset.name}</span>
                    <Wand2 className="h-4 w-4 text-cyan-300" />
                  </div>
                  <div className={`mt-2 text-xs ${preset.should_pass ? 'text-green-300' : 'text-orange-300'}`}>
                    {preset.should_pass ? 'expected pass' : `expected ${preset.expected_min_severity || 'finding'}`}
                  </div>
                </button>
              ))}
            </div>

            <div className="rounded-lg border border-gray-800 bg-gray-950 p-3">
              <div className="mb-2 flex items-center justify-between gap-3">
                <div className="text-sm font-medium text-gray-200">Current evidence</div>
                <span className={`rounded px-2 py-1 text-xs ${missingControls.length ? 'bg-yellow-900/50 text-yellow-200' : 'bg-green-900/50 text-green-200'}`}>
                  {presentControls}/{readinessControls.length}
                </span>
              </div>
              <div className="grid gap-1 sm:grid-cols-2">
                {(missingControls.length ? missingControls : readinessControls.slice(0, 8)).slice(0, 8).map((control) => {
                  const present = hasMetadataKey(readinessMetadata, control.keys)
                  return (
                    <div key={control.id} className="flex min-w-0 items-center gap-2 text-xs">
                      <CheckCircle2 className={`h-3.5 w-3.5 shrink-0 ${present ? 'text-green-300' : 'text-gray-600'}`} />
                      <span className={present ? 'truncate text-gray-300' : 'truncate text-yellow-200'}>{control.label}</span>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        </section>
      )}

      <form onSubmit={handleSubmit} className="space-y-5 rounded-lg border border-gray-800 bg-gray-900 p-4">
        <div className="flex items-center gap-2 text-white">
          <Play className="h-4 w-4 text-cyan-300" />
          <h2 className="text-sm font-semibold">Queue Intake Scan</h2>
        </div>

        <div className="grid gap-3 md:grid-cols-[1.3fr_0.7fr]">
          <label className="grid gap-1 text-sm text-gray-300">
            Artifact URL
            <input
              value={artifactUrl}
              onChange={(e) => setArtifactUrl(e.target.value)}
              className={inputClass}
              placeholder="https://honey.shakerscan.com/model-intake/artifacts/safe/model.safetensors"
              required
            />
          </label>
          <label className="grid gap-1 text-sm text-gray-300">
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} className={inputClass} placeholder="Release model v1" />
          </label>
        </div>

        <div className="grid gap-3 md:grid-cols-2">
          <label className="grid gap-1 text-sm text-gray-300">
            Metadata URL
            <input value={metadataUrl} onChange={(e) => setMetadataUrl(e.target.value)} className={inputClass} placeholder="https://.../manifest.json" />
          </label>
          <label className="grid gap-1 text-sm text-gray-300">
            Expected SHA-256
            <input value={expectedSha256} onChange={(e) => setExpectedSha256(e.target.value)} className={inputClass} placeholder="optional digest pin" />
          </label>
        </div>

        <div className="grid gap-3 md:grid-cols-2">
          <label className="grid gap-1 text-sm text-gray-300">
            Signature URL
            <input value={signatureUrl} onChange={(e) => setSignatureUrl(e.target.value)} className={inputClass} placeholder="https://.../model.sig" />
          </label>
          <label className="grid gap-1 text-sm text-gray-300">
            Model Card URL
            <input value={modelCardUrl} onChange={(e) => setModelCardUrl(e.target.value)} className={inputClass} placeholder="https://.../model-card.md" />
          </label>
        </div>

        <div className="grid gap-3 md:grid-cols-[1fr_0.7fr]">
          <label className="grid gap-1 text-sm text-gray-300">
            Metadata JSON
            <textarea
              value={metadataJson}
              onChange={(e) => setMetadataJson(e.target.value)}
              className={textareaClass}
              rows={9}
              placeholder='{"source_repo":"https://github.com/acme/model","commit_sha":"abc123","training_data_ref":"dataset:v1","signed_by":"sigstore","license":"apache-2.0","sbom":{"components":[]},"malware_scan_result":{"status":"clean"},"security_evals":{"status":"passed"},"monitoring_plan":"model-monitoring-v1"}'
            />
            <span className="text-xs text-gray-500">
              {metadataPreview === null ? 'Invalid JSON object' : metadataPreview ? `${metadataPreview} metadata key(s)` : 'Optional inline metadata'}
            </span>
          </label>

          <div className="space-y-3 rounded-lg border border-gray-800 bg-gray-950 p-3">
            <div className="flex items-center gap-2 text-sm font-medium text-gray-200">
              <FileJson className="h-4 w-4 text-cyan-300" />
              Policy controls
            </div>
            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input type="checkbox" checked={requireHash} onChange={(e) => setRequireHash(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
              Require checksum
            </label>
            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input type="checkbox" checked={requireSignature} onChange={(e) => setRequireSignature(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
              Require signature or attestation
            </label>
            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input type="checkbox" checked={requireDeploymentApproval} onChange={(e) => setRequireDeploymentApproval(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
              Require approval
            </label>
            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input type="checkbox" checked={requireModelGovernance} onChange={(e) => setRequireModelGovernance(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
              Require governance evidence
            </label>
            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input type="checkbox" checked={deploymentApproved} onChange={(e) => setDeploymentApproved(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
              Mark request approved
            </label>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="grid gap-1 text-sm text-gray-300">
                Max bytes
                <input value={maxDownloadBytes} onChange={(e) => setMaxDownloadBytes(e.target.value)} className={inputClass} inputMode="numeric" />
              </label>
              <label className="grid gap-1 text-sm text-gray-300">
                Timeout
                <input value={timeoutSeconds} onChange={(e) => setTimeoutSeconds(e.target.value)} className={inputClass} inputMode="numeric" />
              </label>
            </div>
          </div>
        </div>

        <div className="grid gap-2 sm:grid-cols-[1fr_auto]">
          <button type="submit" disabled={submitting} className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-700 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-600 disabled:opacity-50">
            {submitting ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            Queue Model Intake Scan
          </button>
          <button type="button" onClick={copyPayload} className="inline-flex items-center justify-center gap-2 rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:bg-gray-800">
            <Clipboard className="h-4 w-4" />
            {copied ? 'Copied' : 'Copy payload'}
          </button>
        </div>
      </form>
    </div>
  )
}
