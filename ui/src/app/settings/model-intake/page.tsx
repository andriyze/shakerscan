'use client'

import { useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { FileJson, PackageCheck, Play, RefreshCw } from 'lucide-react'
import { submitModelIntakeScan, type ModelIntakeScanRequest } from '@/lib/api'

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
  const [maxDownloadBytes, setMaxDownloadBytes] = useState('10000000')
  const [timeoutSeconds, setTimeoutSeconds] = useState('20')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

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
      max_download_bytes: Number(maxDownloadBytes || 10000000),
      timeout_seconds: Number(timeoutSeconds || 20),
    }
    if (!payload.artifact_url) {
      throw new Error('Artifact URL is required')
    }
    return payload
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
              placeholder='{"source_repo":"https://github.com/acme/model","commit_sha":"abc123","training_data_ref":"dataset:v1","signed_by":"sigstore"}'
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

        <button type="submit" disabled={submitting} className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-700 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-600 disabled:opacity-50">
          {submitting ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
          Queue Model Intake Scan
        </button>
      </form>
    </div>
  )
}
