'use client'

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { Card, CardSkeleton, ErrorState, useToast } from '@/components/ui'
import {
  AlertTriangle,
  CheckCircle2,
  Clipboard,
  Cloud,
  Database,
  FileJson,
  GitBranch,
  Globe2,
  PackageCheck,
  Play,
  RefreshCw,
  Server,
  ShieldCheck,
  Wand2,
} from 'lucide-react'
import {
  getAITestScenarios,
  getPolicyProfiles,
  resolveModelIntakeReference,
  submitModelIntakeScan,
  type AITestReadinessControl,
  type AITestScenario,
  type ModelIntakePlatform,
  type ModelIntakePreset,
  type ModelIntakeResolveResponse,
  type ModelIntakeScanRequest,
  type PolicyProfile as SavedPolicyProfile,
} from '@/lib/api'
import {
  buildModelIntakeTrustPreview,
  inferModelIntakeTrustMode,
  type ModelIntakeTrustMode,
  type ModelIntakeTrustPreviewStatus,
} from '@/lib/modelIntakeTrust'

const inputClass =
  'min-w-0 w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none'
const textareaClass =
  'min-w-0 w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 font-mono text-xs text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none'
const fieldClass = 'grid min-w-0 gap-1 text-sm text-gray-300'

const COMPLETE_METADATA_EXAMPLE = {
  source_repo: 'https://github.com/example/model-release',
  commit_sha: '0123456789abcdef',
  training_data_ref: 'internal-approved-dataset:v1',
  signed_by: 'release-signing-key-v1',
  signature_policy: 'operator-trust-anchor-required',
  attestation_url: 'https://example.com/model-release/attestation.json',
  license: 'apache-2.0',
  sbom: { components: [{ name: 'transformers', version: '4.x' }] },
  malware_scan_result: { status: 'clean', scanned_at: '2026-05-19T00:00:00Z' },
  security_evals: { status: 'passed', eval_set: 'ai-security-regression-v1' },
  deployment_restrictions: ['staging', 'production'],
  monitoring_plan: 'model-monitoring-v1',
  deployment_approved: true,
}

const MINIMAL_METADATA_EXAMPLE = {
  source_repo: 'https://github.com/example/model-release',
  commit_sha: '0123456789abcdef',
  license: 'apache-2.0',
  model_card_url: 'https://example.com/model-card.md',
}

const AUTO_PLATFORM_OPTION = {
  value: 'auto' as const,
  label: 'Auto-detect',
  helper: 'Infer provider from reference',
  placeholder: 'https://huggingface.co/org/model, hf://org/model@rev/file.safetensors, s3://bucket/path/model.onnx, models:/name/Production',
  icon: Wand2,
}

const PLATFORM_OPTIONS: Array<{
  value: Exclude<ModelIntakePlatform, 'auto'>
  label: string
  helper: string
  placeholder: string
  icon: typeof PackageCheck
}> = [
  {
    value: 'huggingface',
    label: 'Hugging Face',
    helper: 'Repo, file URL, or hf:// reference',
    placeholder: 'mistralai/Mistral-7B-v0.1 or https://huggingface.co/org/model',
    icon: PackageCheck,
  },
  {
    value: 'http',
    label: 'HTTP artifact',
    helper: 'Direct model or manifest URL',
    placeholder: 'https://models.example.com/release/model.safetensors',
    icon: Globe2,
  },
  {
    value: 's3',
    label: 'S3',
    helper: 'Public object or signed URL',
    placeholder: 's3://bucket/path/model.safetensors',
    icon: Cloud,
  },
  {
    value: 'gcs',
    label: 'GCS',
    helper: 'Public object or signed URL',
    placeholder: 'gs://bucket/path/model.onnx',
    icon: Database,
  },
  {
    value: 'azure',
    label: 'Azure Blob',
    helper: 'Account/container path or signed URL',
    placeholder: 'azure://account/container/path/model.gguf',
    icon: Cloud,
  },
  {
    value: 'oci',
    label: 'OCI registry',
    helper: 'Containerized model package',
    placeholder: 'oci://registry.example.com/models/ranker:1.2.0',
    icon: Server,
  },
  {
    value: 'mlflow',
    label: 'MLflow',
    helper: 'Registry metadata first',
    placeholder: 'models:/fraud-detector/Production',
    icon: GitBranch,
  },
]

type BuiltinPolicyProfile = 'research' | 'staging' | 'production' | 'strict'

const POLICY_PROFILES: Array<{ value: BuiltinPolicyProfile; label: string; helper: string }> = [
  { value: 'research', label: 'Research', helper: 'Format and provenance review without approval gating' },
  { value: 'staging', label: 'Staging', helper: 'Require checksum, signature evidence, and governance basics' },
  { value: 'production', label: 'Production', helper: 'Require approval, evidence, and deployment controls' },
  { value: 'strict', label: 'Strict', helper: 'Production plus verified signature evidence' },
]

const TRUST_MODE_OPTIONS: Array<{
  value: ModelIntakeTrustMode
  label: string
  helper: string
}> = [
  { value: 'checksum_only', label: 'Checksum only', helper: 'Digest pin or registry hash; no signature trust.' },
  { value: 'signature_url_key_url', label: 'Signature URL + key URL', helper: 'Detached signature and verifier key fetched by URL.' },
  { value: 'inline_signature_key', label: 'Inline signature + key', helper: 'Paste detached signature and public key PEM.' },
  { value: 'trusted_key_fingerprint', label: 'Trusted key fingerprint', helper: 'Require signature plus operator trust anchor.' },
  { value: 'metadata_evidence', label: 'Metadata evidence', helper: 'Publisher claims only; not a trust root.' },
]

const TRUST_PREVIEW_BADGE: Record<ModelIntakeTrustPreviewStatus, string> = {
  pass: 'bg-green-900/50 text-green-200',
  fail: 'bg-red-900/50 text-red-200',
  advisory: 'bg-yellow-900/50 text-yellow-200',
}

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

function optionalList(value: string): string[] | undefined {
  const items = value
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean)
  return items.length ? items : undefined
}

function listFieldText(value: string | string[] | undefined): string {
  if (!value) return ''
  return Array.isArray(value) ? value.join('\n') : value
}

const SHA256_PATTERN = /^[a-f0-9]{64}$/i
const ARTIFACT_PROTOCOLS = ['http:', 'https:', 'hf:', 's3:', 'gs:', 'azure:', 'oci:']

function validateHttpUrlField(raw: string): string | undefined {
  const trimmed = raw.trim()
  if (!trimmed) return undefined
  try {
    const parsed = new URL(trimmed)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return 'Must be an http(s) URL'
    }
  } catch {
    return 'Must be a valid http(s) URL'
  }
  return undefined
}

function validateArtifactUrlField(raw: string): string | undefined {
  const trimmed = raw.trim()
  if (!trimmed) return undefined
  if (trimmed.startsWith('models:/')) return undefined
  try {
    const parsed = new URL(trimmed)
    if (!ARTIFACT_PROTOCOLS.includes(parsed.protocol)) {
      return 'Must be an http(s) URL or supported reference (hf://, s3://, gs://, azure://, oci://, models:/)'
    }
  } catch {
    return 'Must be a valid http(s) URL or supported artifact reference'
  }
  return undefined
}

function validateSha256Field(raw: string): string | undefined {
  const trimmed = raw.trim()
  if (!trimmed) return undefined
  if (!SHA256_PATTERN.test(trimmed)) return 'Must be a 64-character hex SHA-256 digest'
  return undefined
}

function validateSha256ListField(raw: string): string | undefined {
  const values = optionalList(raw)
  if (!values) return undefined
  const invalid = values.find((value) => !SHA256_PATTERN.test(value))
  if (invalid) return 'Each trusted key fingerprint must be a 64-character hex SHA-256 digest'
  return undefined
}

function invalidFieldClass(base: string) {
  return base.replace('border-gray-700', 'border-red-500/50')
}

interface IntakeFormErrors {
  artifactUrl?: string
  metadataUrl?: string
  signatureUrl?: string
  signaturePublicKeyUrl?: string
  signatureTrustedKeySha256?: string
  modelCardUrl?: string
  expectedSha256?: string
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

function formatBytes(value: number | null | undefined) {
  if (!value) return 'size unknown'
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(1)} GB`
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)} MB`
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)} KB`
  return `${value} B`
}

function metadataString(metadata: Record<string, unknown> | undefined, key: string): string {
  const value = metadata?.[key]
  if (value === undefined || value === null) return ''
  if (Array.isArray(value)) return value.join(', ')
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

export default function ModelIntakeSettingsPage() {
  const router = useRouter()
  const toast = useToast()
  const [platform, setPlatform] = useState<ModelIntakePlatform>('auto')
  const [sourceRef, setSourceRef] = useState('')
  const [revision, setRevision] = useState('')
  const [filename, setFilename] = useState('')
  const [resolverResult, setResolverResult] = useState<ModelIntakeResolveResponse | null>(null)
  const [resolving, setResolving] = useState(false)
  const [artifactUrl, setArtifactUrl] = useState('')
  const [name, setName] = useState('')
  const [metadataUrl, setMetadataUrl] = useState('')
  const [metadataJson, setMetadataJson] = useState('')
  const [expectedSha256, setExpectedSha256] = useState('')
  const [trustMode, setTrustMode] = useState<ModelIntakeTrustMode>('checksum_only')
  const [signatureUrl, setSignatureUrl] = useState('')
  const [signaturePublicKeyUrl, setSignaturePublicKeyUrl] = useState('')
  const [signaturePublicKey, setSignaturePublicKey] = useState('')
  const [signatureValue, setSignatureValue] = useState('')
  const [signatureTrustedKeys, setSignatureTrustedKeys] = useState('')
  const [signatureTrustedKeySha256, setSignatureTrustedKeySha256] = useState('')
  const [signatureRsaPadding, setSignatureRsaPadding] = useState('pss')
  const [signatureHash, setSignatureHash] = useState('sha256')
  const [signaturePayload, setSignaturePayload] = useState('artifact')
  const [modelCardUrl, setModelCardUrl] = useState('')
  const [deploymentApproved, setDeploymentApproved] = useState(false)
  const [requireDeploymentApproval, setRequireDeploymentApproval] = useState(true)
  const [requireSignature, setRequireSignature] = useState(true)
  const [requireSignatureVerification, setRequireSignatureVerification] = useState(false)
  const [requireHash, setRequireHash] = useState(true)
  const [requireModelGovernance, setRequireModelGovernance] = useState(true)
  const [maxDownloadBytes, setMaxDownloadBytes] = useState('10000000')
  const [timeoutSeconds, setTimeoutSeconds] = useState('20')
  const [policyProfile, setPolicyProfile] = useState<string>('production')
  const [savedPolicyProfiles, setSavedPolicyProfiles] = useState<SavedPolicyProfile[]>([])
  const [policyProfilesLoading, setPolicyProfilesLoading] = useState(true)
  const [policyProfilesError, setPolicyProfilesError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<IntakeFormErrors>({})
  const [scenario, setScenario] = useState<AITestScenario | null>(null)
  const [scenarioLoading, setScenarioLoading] = useState(true)
  const [scenarioError, setScenarioError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const loadScenario = useCallback(async () => {
    setScenarioLoading(true)
    try {
      const payload = await getAITestScenarios()
      setScenario(payload.scenarios.find((item) => item.id === 'model-intake-pipeline') || null)
      setScenarioError(null)
    } catch (err) {
      setScenario(null)
      setScenarioError(err instanceof Error ? err.message : 'Failed to load model intake presets')
    } finally {
      setScenarioLoading(false)
    }
  }, [])

  const loadPolicyProfiles = useCallback(async () => {
    setPolicyProfilesLoading(true)
    try {
      const payload = await getPolicyProfiles()
      setSavedPolicyProfiles(payload.policy_profiles || [])
      setPolicyProfilesError(null)
    } catch (err) {
      setSavedPolicyProfiles([])
      setPolicyProfilesError(err instanceof Error ? err.message : 'Failed to load saved policy profiles')
    } finally {
      setPolicyProfilesLoading(false)
    }
  }, [])

  useEffect(() => {
    loadScenario()
    loadPolicyProfiles()
  }, [loadScenario, loadPolicyProfiles])

  const selectedPlatform = platform === 'auto'
    ? AUTO_PLATFORM_OPTION
    : PLATFORM_OPTIONS.find((item) => item.value === platform) || PLATFORM_OPTIONS[0]
  const parsedMetadata = useMemo(() => {
    try {
      return parseOptionalJsonObject(metadataJson) || {}
    } catch {
      return undefined
    }
  }, [metadataJson])
  const metadataPreview = parsedMetadata ? Object.keys(parsedMetadata).length : metadataJson.trim() ? null : 0
  const activeSavedPolicyProfiles = useMemo(
    () => savedPolicyProfiles.filter((profile) => profile.is_active),
    [savedPolicyProfiles]
  )

  function applyScanPayload(payload: ModelIntakeScanRequest) {
    setFieldErrors({})
    setArtifactUrl(payload.artifact_url || '')
    setName(payload.name || '')
    setMetadataUrl(payload.metadata_url || '')
    setMetadataJson(payload.metadata_json ? JSON.stringify(payload.metadata_json, null, 2) : '')
    setExpectedSha256(payload.expected_sha256 || '')
    setSignatureUrl(payload.signature_url || '')
    setSignaturePublicKeyUrl(payload.signature_public_key_url || '')
    setSignaturePublicKey(payload.signature_public_key || '')
    setSignatureValue(payload.signature_value || '')
    setSignatureTrustedKeys(listFieldText(payload.signature_trusted_keys))
    setSignatureTrustedKeySha256(listFieldText(payload.signature_trusted_key_sha256))
    setSignatureRsaPadding(payload.signature_rsa_padding || 'pss')
    setSignatureHash(payload.signature_hash || 'sha256')
    setSignaturePayload(payload.signature_payload || 'artifact')
    setModelCardUrl(payload.model_card_url || '')
    setDeploymentApproved(Boolean(payload.deployment_approved ?? payload.metadata_json?.deployment_approved))
    setRequireDeploymentApproval(payload.require_deployment_approval ?? true)
    setRequireSignature(payload.require_signature ?? true)
    setRequireSignatureVerification(payload.require_signature_verification ?? false)
    setRequireHash(payload.require_hash ?? true)
    setRequireModelGovernance(payload.require_model_governance ?? true)
    setMaxDownloadBytes(String(payload.max_download_bytes || 10000000))
    setTimeoutSeconds(String(payload.timeout_seconds || 20))
    if (payload.policy_profile) setPolicyProfile(payload.policy_profile)
    setTrustMode(inferModelIntakeTrustMode({
      expectedSha256: payload.expected_sha256,
      signatureUrl: payload.signature_url,
      signaturePublicKeyUrl: payload.signature_public_key_url,
      signaturePublicKey: payload.signature_public_key,
      signatureValue: payload.signature_value,
      signatureTrustedKeys: listFieldText(payload.signature_trusted_keys),
      signatureTrustedKeySha256: listFieldText(payload.signature_trusted_key_sha256),
      metadata: payload.metadata_json,
    }))
  }

  function applyTrustMode(mode: ModelIntakeTrustMode) {
    setTrustMode(mode)
    if (mode === 'checksum_only') {
      setRequireHash(true)
      setRequireSignature(false)
      setRequireSignatureVerification(false)
      return
    }
    if (mode === 'metadata_evidence') {
      setRequireSignature(true)
      setRequireSignatureVerification(false)
      return
    }
    setRequireSignature(true)
    if (mode === 'trusted_key_fingerprint') {
      setRequireSignatureVerification(true)
    }
  }

  function validateField(field: keyof IntakeFormErrors) {
    setFieldErrors((prev) => ({
      ...prev,
      [field]:
        field === 'artifactUrl'
          ? validateArtifactUrlField(artifactUrl)
          : field === 'metadataUrl'
            ? validateHttpUrlField(metadataUrl)
            : field === 'signatureUrl'
              ? validateHttpUrlField(signatureUrl)
              : field === 'signaturePublicKeyUrl'
                ? validateHttpUrlField(signaturePublicKeyUrl)
                : field === 'signatureTrustedKeySha256'
                  ? validateSha256ListField(signatureTrustedKeySha256)
                  : field === 'modelCardUrl'
                    ? validateHttpUrlField(modelCardUrl)
                    : validateSha256Field(expectedSha256),
    }))
  }

  function validateIntakeForm(): boolean {
    const needsUrlKeyFields = trustMode === 'signature_url_key_url' || trustMode === 'trusted_key_fingerprint'
    const errors: IntakeFormErrors = {
      artifactUrl: validateArtifactUrlField(artifactUrl),
      metadataUrl: validateHttpUrlField(metadataUrl),
      signatureUrl: needsUrlKeyFields ? validateHttpUrlField(signatureUrl) : undefined,
      signaturePublicKeyUrl: needsUrlKeyFields ? validateHttpUrlField(signaturePublicKeyUrl) : undefined,
      signatureTrustedKeySha256: trustMode === 'trusted_key_fingerprint' ? validateSha256ListField(signatureTrustedKeySha256) : undefined,
      modelCardUrl: validateHttpUrlField(modelCardUrl),
      expectedSha256: validateSha256Field(expectedSha256),
    }
    setFieldErrors(errors)
    return !Object.values(errors).some(Boolean)
  }

  function buildPayload(): ModelIntakeScanRequest {
    const maxBytes = Number(maxDownloadBytes || 10000000)
    const timeout = Number(timeoutSeconds || 20)
    const includeUrlSignature = trustMode === 'signature_url_key_url' || trustMode === 'trusted_key_fingerprint'
    const includeInlineSignature = trustMode === 'inline_signature_key' || trustMode === 'trusted_key_fingerprint'
    const includeTrustAnchor = trustMode === 'trusted_key_fingerprint'
    const includeSignatureOptions = trustMode !== 'checksum_only'
    if (!Number.isFinite(maxBytes) || maxBytes < 1024) throw new Error('Download limit must be at least 1024 bytes')
    if (!Number.isFinite(timeout) || timeout < 1) throw new Error('Timeout must be at least 1 second')
    const payload: ModelIntakeScanRequest = {
      artifact_url: artifactUrl.trim(),
      name: optionalText(name),
      metadata_url: optionalText(metadataUrl),
      metadata_json: parseOptionalJsonObject(metadataJson),
      expected_sha256: optionalText(expectedSha256),
      signature_url: includeUrlSignature ? optionalText(signatureUrl) : undefined,
      signature_public_key: includeInlineSignature ? optionalText(signaturePublicKey) : undefined,
      signature_public_key_url: includeUrlSignature ? optionalText(signaturePublicKeyUrl) : undefined,
      signature_value: includeInlineSignature ? optionalText(signatureValue) : undefined,
      signature_rsa_padding: includeSignatureOptions ? optionalText(signatureRsaPadding) : undefined,
      signature_hash: includeSignatureOptions ? optionalText(signatureHash) : undefined,
      signature_payload: includeSignatureOptions ? optionalText(signaturePayload) : undefined,
      signature_trusted_keys: includeTrustAnchor ? optionalText(signatureTrustedKeys) : undefined,
      signature_trusted_key_sha256: includeTrustAnchor ? optionalList(signatureTrustedKeySha256) : undefined,
      model_card_url: optionalText(modelCardUrl),
      deployment_approved: deploymentApproved,
      require_deployment_approval: requireDeploymentApproval,
      require_signature: requireSignature,
      require_signature_verification: requireSignatureVerification,
      require_hash: requireHash,
      require_model_governance: requireModelGovernance,
      policy_profile: policyProfile,
      max_download_bytes: maxBytes,
      timeout_seconds: timeout,
    }
    if (!payload.artifact_url) {
      throw new Error('Resolve or enter an artifact URL before queueing')
    }
    return payload
  }

  function applyPreset(preset: ModelIntakePreset) {
    applyScanPayload({
      artifact_url: preset.artifact_url || '',
      name: preset.name || '',
      metadata_url: preset.metadata_url,
      metadata_json: preset.metadata_json,
      expected_sha256: preset.expected_sha256,
      signature_url: preset.signature_url,
      signature_public_key: preset.signature_public_key,
      signature_public_key_url: preset.signature_public_key_url,
      signature_value: preset.signature_value,
      signature_rsa_padding: preset.signature_rsa_padding,
      signature_hash: preset.signature_hash,
      signature_payload: preset.signature_payload,
      signature_trusted_keys: preset.signature_trusted_keys,
      signature_trusted_key_sha256: preset.signature_trusted_key_sha256,
      model_card_url: preset.model_card_url,
      deployment_approved: preset.deployment_approved,
      require_deployment_approval: preset.require_deployment_approval,
      require_signature: preset.require_signature,
      require_signature_verification: preset.require_signature_verification,
      require_hash: preset.require_hash,
      require_model_governance: preset.require_model_governance,
      policy_profile: preset.policy_profile,
      max_download_bytes: preset.max_download_bytes,
      timeout_seconds: preset.timeout_seconds,
    })
  }

  function applyMetadataExample(example: 'complete' | 'minimal') {
    setMetadataJson(JSON.stringify(example === 'complete' ? COMPLETE_METADATA_EXAMPLE : MINIMAL_METADATA_EXAMPLE, null, 2))
  }

  function applyPolicyProfile(profile: string) {
    setPolicyProfile(profile)
    const saved = activeSavedPolicyProfiles.find((item) => item.environment === profile)
    if (saved) {
      setRequireHash(true)
      setRequireSignature(true)
      setRequireModelGovernance(true)
      setRequireDeploymentApproval(saved.product_area === 'model_intake' || saved.minimum_block_severity !== 'info')
      setRequireSignatureVerification(Boolean(saved.strict_model_intake))
      setMaxDownloadBytes(saved.strict_model_intake ? '50000000' : '10000000')
      return
    }
    if (profile === 'research') {
      setRequireDeploymentApproval(false)
      setRequireSignature(false)
      setRequireSignatureVerification(false)
      setRequireHash(false)
      setRequireModelGovernance(false)
      setMaxDownloadBytes('10000000')
      if (trustMode === 'trusted_key_fingerprint') setTrustMode('signature_url_key_url')
      return
    }
    setRequireHash(true)
    setRequireSignature(true)
    setRequireModelGovernance(true)
    setRequireDeploymentApproval(profile === 'production' || profile === 'strict')
    setRequireSignatureVerification(profile === 'strict')
    setMaxDownloadBytes(profile === 'strict' ? '50000000' : '10000000')
    if (profile === 'strict' && trustMode !== 'trusted_key_fingerprint') {
      setTrustMode('trusted_key_fingerprint')
    }
  }

  function updateMetadataField(key: string, value: string) {
    const current = parsedMetadata || {}
    const next = { ...current }
    if (value.trim()) {
      // deployment_restrictions is a genuine list; training_data_ref is a single
      // reference that may legitimately contain commas, so keep it as a string.
      next[key] = key === 'deployment_restrictions'
        ? value.split(',').map((item) => item.trim()).filter(Boolean)
        : value
    } else {
      delete next[key]
    }
    setMetadataJson(Object.keys(next).length ? JSON.stringify(next, null, 2) : '')
  }

  async function resolveReference(filenameOverride?: string) {
    setResolving(true)
    setError(null)
    try {
      const result = await resolveModelIntakeReference({
        platform,
        ref: sourceRef.trim(),
        revision: optionalText(revision),
        filename: optionalText(filenameOverride || filename),
        metadata_json: parseOptionalJsonObject(metadataJson),
        timeout_seconds: Number(timeoutSeconds || 20),
      })
      setResolverResult(result)
      if (result.scan_payload) {
        applyScanPayload(result.scan_payload)
      } else {
        applyScanPayload({
          artifact_url: '',
          name: result.repository ? `Hugging Face: ${result.repository}` : '',
          metadata_json: result.metadata_json || {},
          model_card_url: metadataString(result.metadata_json, 'model_card_url') || undefined,
          require_deployment_approval: true,
          require_signature: true,
          require_hash: true,
          require_model_governance: true,
          max_download_bytes: 10_000_000,
          timeout_seconds: Number(timeoutSeconds || 20),
        })
      }
      if (result.revision) setRevision(String(result.revision))
      if (result.selected_file?.path) setFilename(result.selected_file.path)
      else if (!result.scan_payload) setFilename('')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to resolve model reference'
      setError(msg)
      toast.error(msg)
    } finally {
      setResolving(false)
    }
  }

  async function copyPayload() {
    try {
      await navigator.clipboard.writeText(JSON.stringify(buildPayload(), null, 2))
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to copy payload'
      setError(msg)
      toast.error(msg)
    }
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault()
    if (!validateIntakeForm()) {
      setError('Fix the highlighted fields before queueing.')
      return
    }
    if (trustPreview.blockingFailures.length > 0) {
      setError('Fix the failed trust preview checks before queueing.')
      return
    }
    setSubmitting(true)
    setError(null)
    try {
      const result = await submitModelIntakeScan(buildPayload())
      toast.success('Model intake scan started', {
        link: { href: `/scans/${result.scan_id}`, label: 'View scan' },
      })
      router.push(`/scans/${result.scan_id}`)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to queue model intake scan'
      setError(msg)
      toast.error(msg)
    } finally {
      setSubmitting(false)
    }
  }

  const readinessMetadata: Record<string, unknown> = {
    ...(parsedMetadata || {}),
    artifact_url: artifactUrl.trim(),
    expected_sha256: expectedSha256.trim() || (metadataUrl.trim() ? 'manifest' : ''),
    signature_url: signatureUrl.trim() || signatureValue.trim() || (parsedMetadata?.signature_url as string | undefined),
    signature_public_key: signaturePublicKey.trim() || signaturePublicKeyUrl.trim() || (parsedMetadata?.signature_public_key as string | undefined),
    signature_trusted_keys: signatureTrustedKeys.trim() || signatureTrustedKeySha256.trim() || (parsedMetadata?.signature_trusted_keys as string | undefined),
    model_card_url: modelCardUrl.trim() || (parsedMetadata?.model_card_url as string | undefined),
    deployment_approved: deploymentApproved || parsedMetadata?.deployment_approved,
  }
  const readinessControls: AITestReadinessControl[] = scenario?.readiness_controls || []
  const missingControls = readinessControls.filter((control) => !hasMetadataKey(readinessMetadata, control.keys))
  const presentControls = readinessControls.length - missingControls.length
  const hasIntakeInput = Boolean(
    artifactUrl.trim() ||
      name.trim() ||
      metadataUrl.trim() ||
      metadataJson.trim() ||
      expectedSha256.trim() ||
      signatureUrl.trim() ||
      signaturePublicKey.trim() ||
      signaturePublicKeyUrl.trim() ||
      signatureValue.trim() ||
      signatureTrustedKeys.trim() ||
      signatureTrustedKeySha256.trim() ||
      modelCardUrl.trim() ||
      deploymentApproved
  )
  const evidenceBadgeClass = !hasIntakeInput
    ? 'bg-gray-800 text-gray-400'
    : missingControls.length
      ? 'bg-yellow-900/50 text-yellow-200'
      : 'bg-green-900/50 text-green-200'
  const evidenceBadgeText = !hasIntakeInput ? 'Not started' : `${presentControls}/${readinessControls.length}`
  const scanBlockedByResolver = Boolean(resolverResult && !resolverResult.scan_payload && !artifactUrl.trim())
  const hasFieldErrors = Object.values(fieldErrors).some(Boolean)
  const previewIncludesUrlSignature = trustMode === 'signature_url_key_url' || trustMode === 'trusted_key_fingerprint'
  const previewIncludesInlineSignature = trustMode === 'inline_signature_key' || trustMode === 'trusted_key_fingerprint'
  const previewIncludesTrustAnchor = trustMode === 'trusted_key_fingerprint'
  const trustPreview = buildModelIntakeTrustPreview({
    mode: trustMode,
    policyProfile,
    requireHash,
    requireSignature,
    requireSignatureVerification,
    requireDeploymentApproval,
    requireModelGovernance,
    deploymentApproved,
    expectedSha256,
    signatureUrl: previewIncludesUrlSignature ? signatureUrl : '',
    signaturePublicKeyUrl: previewIncludesUrlSignature ? signaturePublicKeyUrl : '',
    signaturePublicKey: previewIncludesInlineSignature ? signaturePublicKey : '',
    signatureValue: previewIncludesInlineSignature ? signatureValue : '',
    signatureTrustedKeys: previewIncludesTrustAnchor ? signatureTrustedKeys : '',
    signatureTrustedKeySha256: previewIncludesTrustAnchor ? signatureTrustedKeySha256 : '',
    metadata: parsedMetadata,
    modelCardUrl,
  })
  const hasTrustFailures = trustPreview.blockingFailures.length > 0

  return (
    <div className="min-w-0 max-w-full space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <PackageCheck className="h-6 w-6 text-cyan-300" />
            <h1 className="text-2xl font-bold text-white">Model Intake</h1>
          </div>
          <p className="mt-1 text-gray-400">Resolve model artifacts, collect supply-chain evidence, and queue deployment checks.</p>
        </div>
        <Link href="/settings" className="rounded-lg border border-gray-700 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
          Settings
        </Link>
      </div>

      {error && <div role="alert" className="rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-400">{error}</div>}

      <Card className="min-w-0 p-4">
        <div className="flex items-center gap-2 text-white">
          <Wand2 className="h-4 w-4 text-cyan-300" />
          <h2 className="text-sm font-semibold">1. Model Reference</h2>
        </div>

        <div className="mt-4 grid gap-3 xl:grid-cols-[minmax(0,1fr)_minmax(9rem,0.35fr)_minmax(10rem,0.45fr)_auto]">
          <label className={fieldClass}>
            Model reference
            <input
              value={sourceRef}
              onChange={(e) => {
                setSourceRef(e.target.value)
                setResolverResult(null)
                setFilename('')
              }}
              className={inputClass}
              placeholder={selectedPlatform.placeholder}
            />
          </label>
          <label className={fieldClass}>
            Revision
            <input value={revision} onChange={(e) => setRevision(e.target.value)} className={inputClass} placeholder="main or commit" />
          </label>
          <label className={fieldClass}>
            Artifact file
            <input value={filename} onChange={(e) => setFilename(e.target.value)} className={inputClass} placeholder="optional" />
          </label>
          <button
            type="button"
            onClick={() => resolveReference()}
            disabled={resolving || !sourceRef.trim()}
            className="inline-flex w-full items-center justify-center gap-2 self-end whitespace-nowrap rounded-lg bg-cyan-700 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-600 disabled:opacity-50"
          >
            {resolving ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Wand2 className="h-4 w-4" />}
            Resolve
          </button>
        </div>

        <div className="mt-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
          {[AUTO_PLATFORM_OPTION, ...PLATFORM_OPTIONS].map((option) => {
            const Icon = option.icon
            const active = option.value === platform
            return (
              <button
                key={option.value}
                type="button"
                onClick={() => {
                  setPlatform(option.value)
                  setResolverResult(null)
                }}
                className={`min-w-0 rounded-lg border p-3 text-left transition ${
                  active ? 'border-cyan-500 bg-cyan-950/40' : 'border-gray-800 bg-gray-950 hover:border-gray-700'
                }`}
              >
                <div className="flex min-w-0 items-center gap-2 text-sm font-medium text-white">
                  <Icon className="h-4 w-4 shrink-0 text-cyan-300" />
                  <span className="min-w-0 break-words">{option.label}</span>
                </div>
                <div className="mt-1 break-words text-xs text-gray-500">{option.helper}</div>
              </button>
            )
          })}
        </div>

        {resolverResult && (
          <div className="mt-4 grid gap-3 xl:grid-cols-[minmax(0,0.85fr)_minmax(0,1.15fr)]">
            <div className="min-w-0 rounded-lg border border-gray-800 bg-gray-950 p-3">
              <div className="text-sm font-medium text-white">Resolved artifact</div>
              <div className="mt-2 break-all rounded border border-gray-800 bg-gray-900 px-3 py-2 font-mono text-xs text-gray-300">
                {resolverResult.normalized_ref}
              </div>
              <div className="mt-3 grid min-w-0 gap-2 text-xs text-gray-400 sm:grid-cols-2">
                <div className="min-w-0 break-words">Provider: <span className="text-gray-200">{resolverResult.platform.replace(/_/g, ' ')}</span></div>
                <div className="min-w-0 break-words">Repository: <span className="text-gray-200">{resolverResult.repository || 'not detected'}</span></div>
                <div className="min-w-0 break-words">Revision: <span className="text-gray-200">{resolverResult.revision || 'not pinned'}</span></div>
                <div className="min-w-0 break-words">File: <span className="break-all text-gray-200">{resolverResult.selected_file?.path || 'manual'}</span></div>
                <div className="min-w-0 break-words">License: <span className="text-gray-200">{metadataString(resolverResult.metadata_json, 'license') || 'not found'}</span></div>
                <div className="min-w-0 break-words">Registry SHA: <span className="text-gray-200">{resolverResult.selected_file?.sha256 ? 'available' : 'not found'}</span></div>
                <div className="min-w-0 break-words">Evidence: <span className="text-gray-200">{Object.keys(resolverResult.metadata_json || {}).length} keys</span></div>
              </div>
              {resolverResult.warnings.length > 0 && (
                <div className="mt-3 space-y-2">
                  {resolverResult.warnings.map((warning) => (
                    <div key={warning} className="flex gap-2 rounded border border-yellow-600/30 bg-yellow-950/20 p-2 text-xs text-yellow-200">
                      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                      <span>{warning}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="min-w-0 rounded-lg border border-gray-800 bg-gray-950 p-3">
              <div className="text-sm font-medium text-white">Candidate files</div>
              {resolverResult.candidate_files.length === 0 ? (
                <div className="mt-3 break-words rounded border border-gray-800 bg-gray-900 p-3 text-sm text-gray-500">
                  No artifact list was available. Enter a direct artifact URL or file path before queueing.
                </div>
              ) : (
                <div className="mt-3 grid gap-2">
                  {resolverResult.candidate_files.slice(0, 6).map((file) => {
                    const selected = file.path === resolverResult.selected_file?.path
                    return (
                      <button
                        key={file.path}
                        type="button"
                        onClick={() => resolveReference(file.path)}
                        className={`min-w-0 rounded border px-3 py-2 text-left text-xs ${
                          selected ? 'border-cyan-500 bg-cyan-950/40' : 'border-gray-800 bg-gray-900 hover:border-gray-700'
                        }`}
                      >
                        <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
                          <span className="min-w-0 break-all font-mono text-gray-200">{file.path}</span>
                          <span className={file.risk === 'lower' ? 'text-green-300' : 'text-orange-300'}>
                            {file.risk === 'lower' ? 'lower risk' : 'review'}
                          </span>
                        </div>
                        <div className="mt-1 break-words text-gray-500">
                          {file.extension || 'unknown'} - {formatBytes(file.size_bytes)}{file.sha256 ? ' - registry SHA-256 available' : ''}
                        </div>
                      </button>
                    )
                  })}
                </div>
              )}
            </div>
          </div>
        )}
      </Card>

      <Card className="min-w-0 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-white">
            <ShieldCheck className="h-4 w-4 text-cyan-300" />
            <h2 className="text-sm font-semibold">2. Policy Profile</h2>
          </div>
          <Link href="/settings/policy-profiles" className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800">
            Manage
          </Link>
        </div>
        <div className="mt-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
          {POLICY_PROFILES.map((profile) => (
            <button
              key={profile.value}
              type="button"
              onClick={() => applyPolicyProfile(profile.value)}
              className={`min-w-0 rounded-lg border p-3 text-left ${
                policyProfile === profile.value ? 'border-cyan-500 bg-cyan-950/40' : 'border-gray-800 bg-gray-950 hover:border-gray-700'
              }`}
            >
              <div className="break-words text-sm font-medium text-white">{profile.label}</div>
              <div className="mt-1 break-words text-xs text-gray-500">{profile.helper}</div>
            </button>
          ))}
          {activeSavedPolicyProfiles.map((profile) => (
            <button
              key={profile.id}
              type="button"
              onClick={() => applyPolicyProfile(profile.environment)}
              className={`min-w-0 rounded-lg border p-3 text-left ${
                policyProfile === profile.environment ? 'border-cyan-500 bg-cyan-950/40' : 'border-gray-800 bg-gray-950 hover:border-gray-700'
              }`}
            >
              <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
                <div className="min-w-0 break-words text-sm font-medium text-white">{profile.name}</div>
                <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">{profile.environment}</span>
              </div>
              <div className="mt-1 break-words text-xs text-gray-500">
                Block {profile.minimum_block_severity}+{profile.strict_model_intake ? ' + verified signing' : ''}
              </div>
            </button>
          ))}
        </div>
        {policyProfilesLoading && <div className="mt-3 text-xs text-gray-500">Loading saved profiles...</div>}
        {!policyProfilesLoading && policyProfilesError && (
          <div role="alert" className="mt-3 break-words text-xs text-red-400">
            {policyProfilesError} — showing built-in profiles only.
          </div>
        )}
      </Card>

      <form onSubmit={handleSubmit} className="min-w-0 space-y-5 rounded-lg border border-gray-800 bg-gray-900 p-4">
        <div className="flex items-center gap-2 text-white">
          <Play className="h-4 w-4 text-cyan-300" />
          <h2 className="text-sm font-semibold">3. Review Scan Payload</h2>
        </div>

        <div className="grid gap-3 md:grid-cols-[minmax(0,1.3fr)_minmax(0,0.7fr)]">
          <label className={fieldClass}>
            Artifact URL
            <input
              value={artifactUrl}
              onChange={(e) => setArtifactUrl(e.target.value)}
              onBlur={() => validateField('artifactUrl')}
              aria-invalid={fieldErrors.artifactUrl ? true : undefined}
              className={fieldErrors.artifactUrl ? invalidFieldClass(inputClass) : inputClass}
              placeholder="https://.../model.safetensors"
              required
            />
            {fieldErrors.artifactUrl && <span role="alert" className="text-sm text-red-400">{fieldErrors.artifactUrl}</span>}
            <span className="text-xs text-gray-500">Resolved HTTP(S), hf://, and public cloud object references are supported. Use signed HTTPS URLs for private artifacts.</span>
          </label>
          <label className={fieldClass}>
            Name
            <input value={name} onChange={(e) => setName(e.target.value)} className={inputClass} placeholder="Release model v1" />
          </label>
        </div>

        <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <label className={fieldClass}>
            Metadata URL
            <input
              value={metadataUrl}
              onChange={(e) => setMetadataUrl(e.target.value)}
              onBlur={() => validateField('metadataUrl')}
              aria-invalid={fieldErrors.metadataUrl ? true : undefined}
              className={fieldErrors.metadataUrl ? invalidFieldClass(inputClass) : inputClass}
              placeholder="https://.../manifest.json"
            />
            {fieldErrors.metadataUrl && <span role="alert" className="text-sm text-red-400">{fieldErrors.metadataUrl}</span>}
          </label>
          <label className={fieldClass}>
            Expected SHA-256
            <input
              value={expectedSha256}
              onChange={(e) => setExpectedSha256(e.target.value)}
              onBlur={() => validateField('expectedSha256')}
              aria-invalid={fieldErrors.expectedSha256 ? true : undefined}
              className={fieldErrors.expectedSha256 ? invalidFieldClass(inputClass) : inputClass}
              placeholder="optional digest pin"
            />
            {fieldErrors.expectedSha256 && <span role="alert" className="text-sm text-red-400">{fieldErrors.expectedSha256}</span>}
          </label>
        </div>

        <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)]">
          <label className={fieldClass}>
            Model Card URL
            <input
              value={modelCardUrl}
              onChange={(e) => setModelCardUrl(e.target.value)}
              onBlur={() => validateField('modelCardUrl')}
              aria-invalid={fieldErrors.modelCardUrl ? true : undefined}
              className={fieldErrors.modelCardUrl ? invalidFieldClass(inputClass) : inputClass}
              placeholder="https://.../model-card.md"
            />
            {fieldErrors.modelCardUrl && <span role="alert" className="text-sm text-red-400">{fieldErrors.modelCardUrl}</span>}
          </label>
        </div>

        <div className="min-w-0 space-y-3 rounded-lg border border-gray-800 bg-gray-950 p-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex items-center gap-2 text-sm font-medium text-gray-200">
              <ShieldCheck className="h-4 w-4 text-cyan-300" />
              Trust mode
            </div>
            <span className={`rounded px-2 py-1 text-xs ${TRUST_PREVIEW_BADGE[trustPreview.headlineStatus]}`}>
              {trustPreview.headline}
            </span>
          </div>
          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
            {TRUST_MODE_OPTIONS.map((mode) => (
              <button
                key={mode.value}
                type="button"
                onClick={() => applyTrustMode(mode.value)}
                className={`min-w-0 rounded-lg border p-3 text-left ${
                  trustMode === mode.value ? 'border-cyan-500 bg-cyan-950/40' : 'border-gray-800 bg-gray-900 hover:border-gray-700'
                }`}
              >
                <div className="break-words text-sm font-medium text-white">{mode.label}</div>
                <div className="mt-1 break-words text-xs text-gray-500">{mode.helper}</div>
              </button>
            ))}
          </div>

          {(trustMode === 'signature_url_key_url' || trustMode === 'trusted_key_fingerprint') && (
            <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <label className={fieldClass}>
                Signature URL
                <input
                  value={signatureUrl}
                  onChange={(e) => setSignatureUrl(e.target.value)}
                  onBlur={() => validateField('signatureUrl')}
                  aria-invalid={fieldErrors.signatureUrl ? true : undefined}
                  className={fieldErrors.signatureUrl ? invalidFieldClass(inputClass) : inputClass}
                  placeholder="https://.../model.sig"
                />
                {fieldErrors.signatureUrl && <span role="alert" className="text-sm text-red-400">{fieldErrors.signatureUrl}</span>}
              </label>
              <label className={fieldClass}>
                Public key URL
                <input
                  value={signaturePublicKeyUrl}
                  onChange={(e) => setSignaturePublicKeyUrl(e.target.value)}
                  onBlur={() => validateField('signaturePublicKeyUrl')}
                  aria-invalid={fieldErrors.signaturePublicKeyUrl ? true : undefined}
                  className={fieldErrors.signaturePublicKeyUrl ? invalidFieldClass(inputClass) : inputClass}
                  placeholder="https://.../signing-key.pem"
                />
                {fieldErrors.signaturePublicKeyUrl && <span role="alert" className="text-sm text-red-400">{fieldErrors.signaturePublicKeyUrl}</span>}
              </label>
            </div>
          )}

          {(trustMode === 'inline_signature_key' || trustMode === 'trusted_key_fingerprint') && (
            <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <label className={fieldClass}>
                Public key PEM
                <textarea
                  value={signaturePublicKey}
                  onChange={(e) => setSignaturePublicKey(e.target.value)}
                  className={textareaClass}
                  rows={5}
                  placeholder="-----BEGIN PUBLIC KEY-----"
                />
              </label>
              <label className={fieldClass}>
                Signature value
                <textarea
                  value={signatureValue}
                  onChange={(e) => setSignatureValue(e.target.value)}
                  className={textareaClass}
                  rows={5}
                  placeholder="base64 detached signature"
                />
              </label>
            </div>
          )}

          {trustMode === 'trusted_key_fingerprint' && (
            <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <label className={fieldClass}>
                Trusted key SHA-256
                <input
                  value={signatureTrustedKeySha256}
                  onChange={(e) => setSignatureTrustedKeySha256(e.target.value)}
                  onBlur={() => validateField('signatureTrustedKeySha256')}
                  aria-invalid={fieldErrors.signatureTrustedKeySha256 ? true : undefined}
                  className={fieldErrors.signatureTrustedKeySha256 ? invalidFieldClass(inputClass) : inputClass}
                  placeholder="one or more fingerprints"
                />
                {fieldErrors.signatureTrustedKeySha256 && <span role="alert" className="text-sm text-red-400">{fieldErrors.signatureTrustedKeySha256}</span>}
              </label>
              <label className={fieldClass}>
                Trusted key PEM
                <textarea
                  value={signatureTrustedKeys}
                  onChange={(e) => setSignatureTrustedKeys(e.target.value)}
                  className={textareaClass}
                  rows={4}
                  placeholder="Optional operator trust anchor PEM"
                />
              </label>
            </div>
          )}

          {trustMode === 'metadata_evidence' && (
            <div className="flex gap-2 rounded border border-yellow-600/30 bg-yellow-950/20 p-3 text-sm text-yellow-200">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>Metadata-supplied signing data is treated as evidence of a publisher claim. It cannot establish a trusted signature unless an operator supplies the verifier key and trust anchor.</span>
            </div>
          )}

          {trustMode !== 'checksum_only' && (
            <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,1fr)]">
              <label className={fieldClass}>
                Payload
                <select value={signaturePayload} onChange={(e) => setSignaturePayload(e.target.value)} className={inputClass}>
                  <option value="artifact">Artifact bytes</option>
                  <option value="digest_hex">SHA-256 hex digest</option>
                  <option value="digest_raw">SHA-256 raw digest</option>
                </select>
              </label>
              <label className={fieldClass}>
                Hash
                <select value={signatureHash} onChange={(e) => setSignatureHash(e.target.value)} className={inputClass}>
                  <option value="sha256">SHA-256</option>
                  <option value="sha384">SHA-384</option>
                  <option value="sha512">SHA-512</option>
                </select>
              </label>
              <label className={fieldClass}>
                RSA padding
                <select value={signatureRsaPadding} onChange={(e) => setSignatureRsaPadding(e.target.value)} className={inputClass}>
                  <option value="pss">PSS</option>
                  <option value="pkcs1v15">PKCS#1 v1.5</option>
                </select>
              </label>
            </div>
          )}

          <div className="grid gap-2 lg:grid-cols-5">
            {trustPreview.items.map((previewItem) => (
              <div key={previewItem.id} className="min-w-0 rounded border border-gray-800 bg-gray-900 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="break-words text-xs font-medium text-gray-200">{previewItem.label}</span>
                  <span className={`rounded px-1.5 py-0.5 text-[10px] ${TRUST_PREVIEW_BADGE[previewItem.status]}`}>
                    {previewItem.status}
                  </span>
                </div>
                <div className="mt-1 break-words text-xs text-gray-500">{previewItem.detail}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="grid gap-3 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
          <div className="min-w-0 space-y-3 rounded-lg border border-gray-800 bg-gray-950 p-3">
            <div className="flex items-center gap-2 text-sm font-medium text-gray-200">
              <FileJson className="h-4 w-4 text-cyan-300" />
              Evidence fields
            </div>
            <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <label className={fieldClass}>
                Source repo
                <input value={metadataString(parsedMetadata, 'source_repo')} onChange={(e) => updateMetadataField('source_repo', e.target.value)} className={inputClass} placeholder="https://github.com/org/repo" />
              </label>
              <label className={fieldClass}>
                License
                <input value={metadataString(parsedMetadata, 'license')} onChange={(e) => updateMetadataField('license', e.target.value)} className={inputClass} placeholder="apache-2.0" />
              </label>
              <label className={fieldClass}>
                Base model
                <input value={metadataString(parsedMetadata, 'base_model')} onChange={(e) => updateMetadataField('base_model', e.target.value)} className={inputClass} placeholder="org/base-model" />
              </label>
              <label className={fieldClass}>
                Training data
                <input value={metadataString(parsedMetadata, 'training_data_ref')} onChange={(e) => updateMetadataField('training_data_ref', e.target.value)} className={inputClass} placeholder="internal-approved-dataset:v1" />
              </label>
              <label className={fieldClass}>
                Security evals
                <input value={metadataString(parsedMetadata, 'security_evals')} onChange={(e) => updateMetadataField('security_evals', e.target.value)} className={inputClass} placeholder="eval report URL or suite" />
              </label>
              <label className={fieldClass}>
                Monitoring plan
                <input value={metadataString(parsedMetadata, 'monitoring_plan')} onChange={(e) => updateMetadataField('monitoring_plan', e.target.value)} className={inputClass} placeholder="model-monitoring-v1" />
              </label>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <span className={`text-xs ${metadataPreview === null ? 'text-red-300' : 'text-gray-500'}`}>
                {metadataPreview === null ? 'Invalid JSON object' : metadataPreview ? `${metadataPreview} metadata key(s)` : 'No inline metadata yet'}
              </span>
              <button type="button" onClick={() => applyMetadataExample('complete')} className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800">
                Complete example
              </button>
              <button type="button" onClick={() => applyMetadataExample('minimal')} className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800">
                Minimal example
              </button>
              {metadataJson.trim() && (
                <button type="button" onClick={() => setMetadataJson('')} className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-400 hover:bg-gray-800">
                  Clear
                </button>
              )}
            </div>
          </div>

          <div className="min-w-0 space-y-3 rounded-lg border border-gray-800 bg-gray-950 p-3">
            <div className="flex items-center gap-2 text-sm font-medium text-gray-200">
              <FileJson className="h-4 w-4 text-cyan-300" />
              Requirements and raw metadata
            </div>
            <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <label className="flex min-w-0 items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={requireHash} onChange={(e) => setRequireHash(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
                Require checksum
              </label>
              <label className="flex min-w-0 items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={requireSignature} onChange={(e) => setRequireSignature(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
                Require signature
              </label>
              <label className="flex min-w-0 items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={requireSignatureVerification} onChange={(e) => setRequireSignatureVerification(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
                Verify signature
              </label>
              <label className="flex min-w-0 items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={requireDeploymentApproval} onChange={(e) => setRequireDeploymentApproval(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
                Require approval
              </label>
              <label className="flex min-w-0 items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={requireModelGovernance} onChange={(e) => setRequireModelGovernance(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
                Require governance
              </label>
              <label className="flex min-w-0 items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={deploymentApproved} onChange={(e) => setDeploymentApproved(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
                Mark approved
              </label>
            </div>
            <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <label className={fieldClass}>
                Download limit (bytes)
                <input value={maxDownloadBytes} onChange={(e) => setMaxDownloadBytes(e.target.value)} className={inputClass} inputMode="numeric" />
              </label>
              <label className={fieldClass}>
                Timeout (seconds)
                <input value={timeoutSeconds} onChange={(e) => setTimeoutSeconds(e.target.value)} className={inputClass} inputMode="numeric" />
              </label>
            </div>
            <label className={fieldClass}>
              Metadata JSON
              <textarea
                value={metadataJson}
                onChange={(e) => setMetadataJson(e.target.value)}
                className={textareaClass}
                rows={8}
                placeholder='{"source_repo":"https://github.com/acme/model","commit_sha":"abc123","license":"apache-2.0"}'
              />
            </label>
          </div>
        </div>

        <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto]">
          <button type="submit" disabled={submitting || scanBlockedByResolver || hasFieldErrors || hasTrustFailures} className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-700 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-600 disabled:opacity-50">
            {submitting ? <RefreshCw className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Play className="h-4 w-4" aria-hidden="true" />}
            {scanBlockedByResolver ? 'Resolve an artifact file first' : 'Queue Model Intake Scan'}
          </button>
          <button type="button" onClick={copyPayload} className="inline-flex items-center justify-center gap-2 rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:bg-gray-800">
            <Clipboard className="h-4 w-4" aria-hidden="true" />
            {copied ? 'Copied' : 'Copy payload'}
          </button>
        </div>
        {hasFieldErrors && (
          <p role="alert" className="text-sm text-red-400">Fix the highlighted fields above to queue this scan.</p>
        )}
        {hasTrustFailures && (
          <p role="alert" className="text-sm text-red-400">Fix the failed trust preview checks before queueing this scan.</p>
        )}
      </form>

      {scenarioLoading && <CardSkeleton count={2} />}
      {!scenarioLoading && scenarioError && <ErrorState message={scenarioError} onRetry={loadScenario} />}

      {scenario && (scenario.request_presets || []).length > 0 && (
        <Card className="p-4">
          <div className="flex items-center gap-2 text-white">
            <Wand2 className="h-4 w-4 text-cyan-300" />
            <h2 className="text-sm font-semibold">Starter Presets</h2>
          </div>
          <p className="mt-1 text-sm text-gray-400">Optional quick-fill requests for model intake practice. Review every value before queueing a scan.</p>
          <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
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
        </Card>
      )}

      {scenario && readinessControls.length > 0 && (
        <Card className="p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="flex items-center gap-2 text-white">
                <ShieldCheck className="h-4 w-4 text-cyan-300" />
                <h2 className="text-sm font-semibold">Evidence Checklist</h2>
              </div>
              <p className="mt-1 max-w-3xl text-sm text-gray-400">
                Platform metadata covers public model facts. Your organization still owns approval, SBOM, malware scan, eval, and monitoring evidence.
              </p>
            </div>
            <span className={`rounded px-2 py-1 text-xs ${evidenceBadgeClass}`}>{evidenceBadgeText}</span>
          </div>

          {!hasIntakeInput ? (
            <div className="mt-4 rounded-lg border border-gray-800 bg-gray-950 p-3 text-sm text-gray-500">
              Resolve a platform reference or enter artifact evidence to preview readiness gaps.
            </div>
          ) : (
            <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {(missingControls.length ? missingControls : readinessControls).slice(0, 12).map((control) => {
                const present = hasMetadataKey(readinessMetadata, control.keys)
                return (
                  <div key={control.id} className="flex min-w-0 items-center gap-2 rounded border border-gray-800 bg-gray-950 px-3 py-2 text-xs">
                    <CheckCircle2 className={`h-3.5 w-3.5 shrink-0 ${present ? 'text-green-300' : 'text-gray-600'}`} />
                    <span className={present ? 'truncate text-gray-300' : 'truncate text-yellow-200'}>{control.label}</span>
                  </div>
                )
              })}
            </div>
          )}
        </Card>
      )}
    </div>
  )
}
