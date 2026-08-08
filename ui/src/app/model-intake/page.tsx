'use client'

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'next/navigation'
import Link from 'next/link'
import { Card, CardSkeleton, ErrorState, Modal, useToast } from '@/components/ui'
import {
  AlertTriangle,
  CheckCircle2,
  Clipboard,
  Cloud,
  Database,
  FileJson,
  GitBranch,
  Globe2,
  Info,
  PackageCheck,
  Play,
  RefreshCw,
  Server,
  ShieldCheck,
  Wand2,
} from 'lucide-react'
import {
  getAITestScenarios,
  createModelIntakeTrustAnchor,
  deactivateModelIntakeTrustAnchor,
  getModelIntakeTrustAnchors,
  getModelIntakeAdmissions,
  getModelIntakeOperatorCredential,
  getModelIntakeCheckCatalog,
  getModelIntakeScannerReadiness,
  getModelIntakeRunnerReadiness,
  getModelIntakeRunnerInstallPlan,
  createModelIntakeAutomaticReview,
  listModelIntakeAutomaticReviews,
  downloadModelIntakeAutomaticReport,
  downloadModelIntakeLicenseArtifact,
  downloadModelIntakeSbom,
  getPolicyProfiles,
  listRecentModelIntakeScans,
  resolveModelIntakeReference,
  submitModelIntakeScan,
  MODEL_INTAKE_OPERATOR_TOKEN_KEY,
  type ModelIntakeOperatorCredential,
  type ModelIntakeCheckCatalog,
  type AITestReadinessControl,
  type AITestScenario,
  type ModelIntakePlatform,
  type ModelIntakePreset,
  type ModelIntakeResolveResponse,
  type ModelIntakeScanRequest,
  type ModelIntakeRunnerReadiness,
  type ModelIntakeRunnerInstallPlan,
  type ModelIntakeScanSummary,
  type ModelIntakeScannerReadiness,
  type ModelIntakeTrustAnchor,
  type ModelIntakeAdmission,
  type ModelIntakeAutomaticReview,
  type PolicyProfile as SavedPolicyProfile,
} from '@/lib/api'
import {
  buildModelIntakeTrustPreview,
  inferModelIntakeTrustMode,
  type ModelIntakeTrustMode,
  type ModelIntakeTrustPreviewStatus,
} from '@/lib/modelIntakeTrust'
import { ControlledModelIntakeWorkflow } from './ControlledWorkflow'
import {
  IntakeContextBar,
  IntakePhaseTabs,
  PreflightScanTracker,
  RunnerInstallCard,
  isTerminalScanStatus,
  type IntakePhase,
} from './IntakeShell'

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

// The deployment target is chosen exactly once, in step 1, and then flows into
// the preflight policy profile, the controlled submission's intended
// environment, and the deployment bundle's target_environment. Nothing
// downstream asks for it again.
export type ModelIntakeEnvironment = 'development' | 'test' | 'staging' | 'production'

const ENVIRONMENT_OPTIONS: Array<{
  value: ModelIntakeEnvironment
  label: string
  helper: string
  policyProfile: BuiltinPolicyProfile
}> = [
  { value: 'development', label: 'Development', helper: 'Format and provenance review only', policyProfile: 'research' },
  { value: 'test', label: 'Test', helper: 'Checksum and signature evidence', policyProfile: 'staging' },
  { value: 'staging', label: 'Staging', helper: 'Checksum, signature, governance basics', policyProfile: 'staging' },
  { value: 'production', label: 'Production', helper: 'Approval, evidence, deployment controls', policyProfile: 'production' },
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

// Anything above the in-memory inspection prefix is streamed into
// content-addressed quarantine by the worker, so a multi-gigabyte cap is a
// disk-bounded operation rather than a memory-bounded one. These presets exist
// because production models are routinely far larger than the old 100MB wall.
// What "scan this model" should mean by default. Every deep check used to be
// opt-in behind an Advanced disclosure, so the default run acquired the file
// and checked provenance without ever running ModelScan, Semgrep, Fickling, or
// Trivy — the adapters the page reports as ready.
export type ModelIntakeScanDepth = 'full' | 'quick'

const SCAN_DEPTHS: Array<{ value: ModelIntakeScanDepth; label: string; helper: string }> = [
  {
    value: 'full',
    label: 'Full scan',
    helper: 'Acquire and hash the whole model, snapshot the repository, and run every applicable evidence adapter',
  },
  {
    value: 'quick',
    label: 'Quick check',
    helper: 'Format, provenance, and governance metadata only. Much faster, far less evidence',
  },
]

const ARTIFACT_LIMIT_PRESETS: Array<{ label: string; bytes: number; helper: string }> = [
  { label: '100 MB', bytes: 100_000_000, helper: 'Header and format inspection only' },
  { label: '1 GB', bytes: 1_000_000_000, helper: 'Typical single-file model' },
  { label: '5 GB', bytes: 5_000_000_000, helper: '7B-class weights' },
  { label: '20 GB', bytes: 20_000_000_000, helper: 'Large or multi-shard weights' },
  { label: '100 GB', bytes: 100_000_000_000, helper: 'Large individual shard or model' },
  { label: '250 GB', bytes: 250_000_000_000, helper: 'Very large model artifact' },
  { label: '500 GB', bytes: 500_000_000_000, helper: 'Maximum supported single artifact' },
]

// Strict signing verification is meaningless against a truncated prefix, so
// strict profiles pull the acquisition limit up to at least a whole small model.
const QUEUED_SCANS_KEY = 'shakerscan:model-intake-queued-scans'

const STRICT_ARTIFACT_LIMIT_FLOOR = 1_000_000_000

// Pasting a model reference used to produce a report whose most valuable
// controls all read INDETERMINATE, because the scanners, the repository
// snapshot, and the sandbox were each an unchecked box behind an Advanced
// disclosure. Depth is now one visible choice that defaults to the complete
// evidence set; the individual toggles remain as overrides.
const INTAKE_DEPTHS = [
  {
    value: 'quick',
    label: 'Quick',
    helper: 'Artifact only: acquisition, full SHA-256, format inspection',
    scanners: false,
    snapshot: false,
    sandbox: false,
  },
  {
    value: 'standard',
    label: 'Standard',
    helper: 'Adds the pinned repository snapshot and custom-code analysis',
    scanners: false,
    snapshot: true,
    sandbox: false,
  },
  {
    value: 'full',
    label: 'Full',
    helper: 'Adds ModelScan, Semgrep, Fickling, Trivy and the no-egress sandbox',
    scanners: true,
    snapshot: true,
    sandbox: true,
  },
] as const

type IntakeDepth = (typeof INTAKE_DEPTHS)[number]['value']

const DEFAULT_INTAKE_DEPTH: IntakeDepth = 'full'

// Fetch the whole artifact plus headroom so the full-artifact SHA-256 is
// observed instead of a truncated prefix.
function artifactLimitForSize(sizeBytes: number): number {
  const withHeadroom = Math.ceil(sizeBytes * 1.05)
  const preset = ARTIFACT_LIMIT_PRESETS.find((item) => item.bytes >= withHeadroom)
  return preset ? preset.bytes : 500_000_000_000
}

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
  return (
    <Suspense fallback={<ModelIntakePageFallback />}>
      <ModelIntakeSettingsContent />
    </Suspense>
  )
}

function ModelIntakePageFallback() {
  return (
    <div className="min-w-0 max-w-full space-y-6">
      <CardSkeleton />
      <CardSkeleton />
      <CardSkeleton />
    </div>
  )
}

function ModelIntakeSettingsContent() {
  const searchParams = useSearchParams()
  const toast = useToast()
  const trustSectionRef = useRef<HTMLDivElement | null>(null)
  const [trustRemediationApplied, setTrustRemediationApplied] = useState(false)
  const [phase, setPhase] = useState<IntakePhase>('source')
  const [workflowMode, setWorkflowMode] = useState<'automatic' | 'advanced'>('automatic')
  const [automaticReviews, setAutomaticReviews] = useState<ModelIntakeAutomaticReview[]>([])
  const [automaticReviewsError, setAutomaticReviewsError] = useState<string | null>(null)
  const [showAllAutomaticReviews, setShowAllAutomaticReviews] = useState(false)
  const [automaticDownload, setAutomaticDownload] = useState('')
  const [checkCatalogOpen, setCheckCatalogOpen] = useState(false)
  const [checkCatalog, setCheckCatalog] = useState<ModelIntakeCheckCatalog | null>(null)
  const [checkCatalogLoading, setCheckCatalogLoading] = useState(false)
  const [checkCatalogError, setCheckCatalogError] = useState<string | null>(null)
  const [scanDepth, setScanDepth] = useState<ModelIntakeScanDepth>('full')
  const [platform, setPlatform] = useState<ModelIntakePlatform>('auto')
  const [environment, setEnvironment] = useState<ModelIntakeEnvironment>('production')
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
  const [requireCryptographicSignatureVerification, setRequireCryptographicSignatureVerification] = useState(false)
  const [requireHash, setRequireHash] = useState(true)
  const [requireModelGovernance, setRequireModelGovernance] = useState(true)
  const [maxDownloadBytes, setMaxDownloadBytes] = useState('10000000')
  const [completeArtifactDownload, setCompleteArtifactDownload] = useState(true)
  const [maxArtifactBytes, setMaxArtifactBytes] = useState('10000000000')
  const [completeRepositorySnapshot, setCompleteRepositorySnapshot] = useState(true)
  const [maxRepositoryBytes, setMaxRepositoryBytes] = useState('50000000000')
  const [runGeneratedScanners, setRunGeneratedScanners] = useState(true)
  const [runDynamicSandbox, setRunDynamicSandbox] = useState(true)
  const [requireDynamicSandbox, setRequireDynamicSandbox] = useState(false)
  const [evaluationSpecJson, setEvaluationSpecJson] = useState('')
  const [runGeneratedEvaluation, setRunGeneratedEvaluation] = useState(false)
  const [requireGeneratedEvaluation, setRequireGeneratedEvaluation] = useState(false)
  const [timeoutSeconds, setTimeoutSeconds] = useState('20')
  const [policyProfile, setPolicyProfile] = useState<string>('production')
  const [savedPolicyProfiles, setSavedPolicyProfiles] = useState<SavedPolicyProfile[]>([])
  const [policyProfilesLoading, setPolicyProfilesLoading] = useState(true)
  const [policyProfilesError, setPolicyProfilesError] = useState<string | null>(null)
  const [savedTrustAnchors, setSavedTrustAnchors] = useState<ModelIntakeTrustAnchor[]>([])
  const [admissions, setAdmissions] = useState<ModelIntakeAdmission[]>([])
  const [admissionsError, setAdmissionsError] = useState<string | null>(null)
  const [scannerReadiness, setScannerReadiness] = useState<ModelIntakeScannerReadiness | null>(null)
  const [runnerReadiness, setRunnerReadiness] = useState<ModelIntakeRunnerReadiness | null>(null)
  const [runnerInstallPlan, setRunnerInstallPlan] = useState<ModelIntakeRunnerInstallPlan | null>(null)
  const [intakeScans, setIntakeScans] = useState<ModelIntakeScanSummary[]>([])
  const [queuedScanIds, setQueuedScanIds] = useState<string[]>([])
  const [staticScanId, setStaticScanId] = useState('')
  const [scannerReadinessError, setScannerReadinessError] = useState<string | null>(null)
  const [selectedTrustAnchorIds, setSelectedTrustAnchorIds] = useState<string[]>([])
  const [trustAnchorsLoading, setTrustAnchorsLoading] = useState(true)
  const [trustAnchorsError, setTrustAnchorsError] = useState<string | null>(null)
  const [newAnchorName, setNewAnchorName] = useState('')
  const [newAnchorSha256, setNewAnchorSha256] = useState('')
  const [newAnchorPem, setNewAnchorPem] = useState('')
  const [newAnchorOwner, setNewAnchorOwner] = useState('')
  const [operatorToken, setOperatorToken] = useState('')
  const [operatorCredential, setOperatorCredential] = useState<ModelIntakeOperatorCredential | null>(null)
  const [savingAnchor, setSavingAnchor] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [quickSubmitting, setQuickSubmitting] = useState(false)
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

  const loadTrustAnchors = useCallback(async () => {
    setTrustAnchorsLoading(true)
    try {
      const payload = await getModelIntakeTrustAnchors(true)
      setSavedTrustAnchors(payload.trust_anchors || [])
      setTrustAnchorsError(null)
    } catch (err) {
      setSavedTrustAnchors([])
      setTrustAnchorsError(err instanceof Error ? err.message : 'Failed to load saved trust anchors')
    } finally {
      setTrustAnchorsLoading(false)
    }
  }, [])

  const loadAdmissions = useCallback(async () => {
    try {
      const payload = await getModelIntakeAdmissions(20)
      setAdmissions(payload.admissions || [])
      setAdmissionsError(null)
    } catch (err) {
      setAdmissions([])
      setAdmissionsError(err instanceof Error ? err.message : 'Failed to load admissions')
    }
  }, [])

  const loadScannerReadiness = useCallback(async () => {
    try {
      setScannerReadiness(await getModelIntakeScannerReadiness())
      setScannerReadinessError(null)
    } catch (err) {
      setScannerReadiness(null)
      setScannerReadinessError(err instanceof Error ? err.message : 'Failed to load scanner readiness')
    }
  }, [])

  const loadRunnerReadiness = useCallback(async () => {
    // Readiness and the install plan answer different questions — "is it
    // running" and "can this host run it at all" — and the Status panel needs
    // both to decide between an install button and an unavailable notice.
    const [readiness, plan] = await Promise.allSettled([
      getModelIntakeRunnerReadiness(),
      getModelIntakeRunnerInstallPlan(),
    ])
    setRunnerReadiness(readiness.status === 'fulfilled' ? readiness.value : null)
    setRunnerInstallPlan(plan.status === 'fulfilled' ? plan.value : null)
  }, [])

  const loadIntakeScans = useCallback(async () => {
    try {
      setIntakeScans(await listRecentModelIntakeScans(25))
    } catch {
      // A scan-list hiccup must not take down the intake form.
    }
  }, [])

  const loadAutomaticReviews = useCallback(async () => {
    try {
      const payload = await listModelIntakeAutomaticReviews(10)
      setAutomaticReviews(payload.reviews || [])
      setAutomaticReviewsError(null)
    } catch (err) {
      setAutomaticReviewsError(err instanceof Error ? err.message : 'Failed to load automatic reviews')
    }
  }, [])

  // A local install already owns its operator credential; asking the human to
  // find it in .env was pure friction. Fall back to the manual field only when
  // the UI server declines (remote bind, autofill disabled, or unconfigured).
  const loadOperatorCredential = useCallback(async () => {
    const stored = sessionStorage.getItem(MODEL_INTAKE_OPERATOR_TOKEN_KEY) || ''
    if (stored) {
      setOperatorToken(stored)
      setOperatorCredential({ available: true, reason: 'stored_session' })
      return
    }
    const credential = await getModelIntakeOperatorCredential()
    setOperatorCredential(credential)
    if (credential.available && credential.token) {
      setOperatorToken(credential.token)
      sessionStorage.setItem(MODEL_INTAKE_OPERATOR_TOKEN_KEY, credential.token)
    }
  }, [])

  useEffect(() => {
    setQueuedScanIds(JSON.parse(sessionStorage.getItem(QUEUED_SCANS_KEY) || '[]'))
    loadOperatorCredential()
    loadScenario()
    loadPolicyProfiles()
    loadTrustAnchors()
    loadAdmissions()
    loadScannerReadiness()
    loadRunnerReadiness()
    loadIntakeScans()
    loadAutomaticReviews()
  }, [
    loadOperatorCredential,
    loadScenario,
    loadPolicyProfiles,
    loadTrustAnchors,
    loadAdmissions,
    loadScannerReadiness,
    loadRunnerReadiness,
    loadIntakeScans,
    loadAutomaticReviews,
  ])

  const automaticReviewRunning = automaticReviews.some((review) =>
    !['technical_review_complete', 'attention_required', 'failed', 'cancelled'].includes(review.state)
  )

  useEffect(() => {
    if (!automaticReviewRunning) return
    const timer = setInterval(loadAutomaticReviews, 5_000)
    return () => clearInterval(timer)
  }, [automaticReviewRunning, loadAutomaticReviews])

  const queuedScans = useMemo(
    () => queuedScanIds
      .map((id) => intakeScans.find((scan) => scan.id === id))
      .filter((scan): scan is ModelIntakeScanSummary => Boolean(scan)),
    [queuedScanIds, intakeScans]
  )
  const awaitingScanCompletion = queuedScans.some((scan) => !isTerminalScanStatus(scan.status))

  // Poll only while a scan this page queued is still running, so the handoff
  // into admission lights up on its own instead of needing a manual reload.
  useEffect(() => {
    if (!awaitingScanCompletion) return
    const timer = setInterval(loadIntakeScans, 10_000)
    return () => clearInterval(timer)
  }, [awaitingScanCompletion, loadIntakeScans])

  function trackQueuedScan(scanId: string) {
    setQueuedScanIds((prev) => {
      const next = [scanId, ...prev.filter((id) => id !== scanId)].slice(0, 10)
      sessionStorage.setItem(QUEUED_SCANS_KEY, JSON.stringify(next))
      return next
    })
  }

  function useScanInAdmission(scanId: string) {
    setStaticScanId(scanId)
    setPhase('admission')
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  function updateOperatorToken(value: string) {
    setOperatorToken(value)
    if (value) sessionStorage.setItem(MODEL_INTAKE_OPERATOR_TOKEN_KEY, value)
    else sessionStorage.removeItem(MODEL_INTAKE_OPERATOR_TOKEN_KEY)
  }

  const remediationMode = searchParams.get('remediate')
  const trustRemediationMode = remediationMode === 'trust'

  useEffect(() => {
    if (!trustRemediationMode || trustRemediationApplied) return
    // The trust controls live in the preflight phase, so a remediation deep
    // link has to open that phase before scrolling to them.
    setPhase('preflight')
    setWorkflowMode('advanced')
    setPolicyProfile('strict')
    setRequireHash(true)
    setRequireSignature(true)
    setRequireSignatureVerification(true)
    setRequireCryptographicSignatureVerification(true)
    setRequireModelGovernance(true)
    setRequireDeploymentApproval(true)
    setCompleteArtifactDownload(true)
    setCompleteRepositorySnapshot(true)
    setRunGeneratedScanners(true)
    setRunDynamicSandbox(true)
    setRequireDynamicSandbox(true)
    setRunGeneratedEvaluation(true)
    setRequireGeneratedEvaluation(true)
    setTrustMode('trusted_key_fingerprint')
    raiseArtifactLimitFloor(STRICT_ARTIFACT_LIMIT_FLOOR)
    setTrustRemediationApplied(true)
    window.requestAnimationFrame(() => {
      trustSectionRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    })
  }, [trustRemediationApplied, trustRemediationMode])

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

  useEffect(() => {
    if (!trustRemediationMode) return
    const strictProfile = activeSavedPolicyProfiles.find((profile) =>
      profile.strict_model_intake && profile.environment === 'strict'
    )
    const requiredAnchorIds = strictProfile?.required_trust_anchor_ids || []
    if (!requiredAnchorIds.length) return
    setSelectedTrustAnchorIds((prev) => Array.from(new Set([...prev, ...requiredAnchorIds])))
  }, [activeSavedPolicyProfiles, trustRemediationMode])
  const selectedTrustAnchors = useMemo(
    () => savedTrustAnchors.filter((anchor) => selectedTrustAnchorIds.includes(anchor.id)),
    [savedTrustAnchors, selectedTrustAnchorIds]
  )
  const selectedAnchorFingerprints = selectedTrustAnchors
    .map((anchor) => anchor.public_key_sha256 || '')
    .filter(Boolean)
    .join('\n')
  const selectedAnchorPems = selectedTrustAnchors
    .map((anchor) => anchor.public_key_pem || '')
    .filter(Boolean)
    .join('\n')

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
    setRequireCryptographicSignatureVerification(payload.require_cryptographic_signature_verification ?? false)
    setRequireHash(payload.require_hash ?? true)
    setRequireModelGovernance(payload.require_model_governance ?? true)
    setMaxDownloadBytes(String(payload.max_download_bytes || 10000000))
    setCompleteArtifactDownload(payload.complete_artifact_download ?? false)
    setMaxArtifactBytes(String(payload.max_artifact_bytes || 10000000000))
    // A preset that says nothing about depth inherits the product default
    // rather than silently downgrading the scan to artifact-only. An explicit
    // false in the preset is still respected.
    setCompleteRepositorySnapshot(payload.complete_repository_snapshot ?? true)
    setMaxRepositoryBytes(String(payload.max_repository_bytes || 50000000000))
    setRunGeneratedScanners(payload.run_generated_scanners ?? true)
    setRunDynamicSandbox(payload.run_dynamic_sandbox ?? true)
    setRequireDynamicSandbox(payload.require_dynamic_sandbox ?? false)
    setEvaluationSpecJson(payload.evaluation_spec_json ? JSON.stringify(payload.evaluation_spec_json, null, 2) : '')
    setRunGeneratedEvaluation(payload.run_generated_evaluation ?? false)
    setRequireGeneratedEvaluation(payload.require_generated_evaluation ?? false)
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
    const maxTotalBytes = Number(maxArtifactBytes || 10000000000)
    const maxRepoBytes = Number(maxRepositoryBytes || 50000000000)
    const timeout = Number(timeoutSeconds || 20)
    const includeUrlSignature = trustMode === 'signature_url_key_url' || trustMode === 'trusted_key_fingerprint'
    const includeInlineSignature = trustMode === 'inline_signature_key' || trustMode === 'trusted_key_fingerprint'
    const includeTrustAnchor = trustMode === 'trusted_key_fingerprint'
    const includeSignatureOptions = trustMode !== 'checksum_only'
    const parsedSubmissionMetadata = parseOptionalJsonObject(metadataJson)
    const submissionMetadata = parsedSubmissionMetadata
    if (!Number.isFinite(maxBytes) || maxBytes < 1024) throw new Error('Download limit must be at least 1024 bytes')
    if (!Number.isFinite(maxTotalBytes) || maxTotalBytes < 1024) throw new Error('Complete artifact limit must be at least 1024 bytes')
    if (completeArtifactDownload && maxTotalBytes < maxBytes) throw new Error('Complete artifact limit must be greater than or equal to the inspection limit')
    if (!Number.isFinite(maxRepoBytes) || maxRepoBytes < 1024) throw new Error('Repository snapshot limit must be at least 1024 bytes')
    if (!Number.isFinite(timeout) || timeout < 1) throw new Error('Timeout must be at least 1 second')
    const payload: ModelIntakeScanRequest = {
      artifact_url: artifactUrl.trim(),
      intake_mode: 'preflight',
      name: optionalText(name),
      metadata_url: optionalText(metadataUrl),
      metadata_json: submissionMetadata,
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
      trust_anchor_ids: includeTrustAnchor && selectedTrustAnchorIds.length ? selectedTrustAnchorIds : undefined,
      model_card_url: optionalText(modelCardUrl),
      deployment_approved: deploymentApproved,
      require_deployment_approval: requireDeploymentApproval,
      require_signature: requireSignature,
      require_signature_verification: requireSignatureVerification,
      require_cryptographic_signature_verification: requireCryptographicSignatureVerification,
      require_hash: requireHash,
      require_model_governance: requireModelGovernance,
      policy_profile: policyProfile,
      max_download_bytes: maxBytes,
      complete_artifact_download: completeArtifactDownload,
      max_artifact_bytes: maxTotalBytes,
      complete_repository_snapshot: completeRepositorySnapshot,
      max_repository_bytes: maxRepoBytes,
      run_generated_scanners: runGeneratedScanners,
      run_dynamic_sandbox: runDynamicSandbox,
      require_dynamic_sandbox: requireDynamicSandbox,
      evaluation_spec_json: parseOptionalJsonObject(evaluationSpecJson),
      run_generated_evaluation: runGeneratedEvaluation,
      require_generated_evaluation: requireGeneratedEvaluation,
      require_signed_admission: false,
      timeout_seconds: timeout,
    }
    if (!payload.artifact_url) {
      throw new Error('Resolve or enter an artifact URL before queueing')
    }
    return payload
  }

  async function saveTrustAnchor() {
    const fingerprintError = validateSha256ListField(newAnchorSha256)
    if (fingerprintError) {
      setError(fingerprintError)
      return
    }
    setSavingAnchor(true)
    setError(null)
    try {
      const anchor = await createModelIntakeTrustAnchor({
        name: newAnchorName.trim(),
        public_key_sha256: optionalText(newAnchorSha256),
        public_key_pem: optionalText(newAnchorPem),
        policy_profile: policyProfile,
        owner: optionalText(newAnchorOwner),
        is_active: true,
      }, operatorToken.trim())
      setSavedTrustAnchors((prev) => [...prev, anchor].sort((a, b) => a.name.localeCompare(b.name)))
      setSelectedTrustAnchorIds((prev) => Array.from(new Set([...prev, anchor.id])))
      setNewAnchorName('')
      setNewAnchorSha256('')
      setNewAnchorPem('')
      setNewAnchorOwner('')
      toast.success('Trust anchor saved')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to save trust anchor'
      setError(msg)
      toast.error(msg)
    } finally {
      setSavingAnchor(false)
    }
  }

  async function deactivateTrustAnchor(anchorId: string) {
    try {
      await deactivateModelIntakeTrustAnchor(anchorId, operatorToken.trim())
      setSavedTrustAnchors((prev) => prev.filter((anchor) => anchor.id !== anchorId))
      setSelectedTrustAnchorIds((prev) => prev.filter((id) => id !== anchorId))
      toast.success('Trust anchor deactivated')
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to deactivate trust anchor'
      setError(msg)
      toast.error(msg)
    }
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
    // A preset carries its own depth flags; keep the operator's choice.
    applyScanDepth(scanDepth)
  }

  // Raise the acquisition limit toward a floor without ever shrinking a limit
  // the operator (or the resolver) deliberately set higher.
  function applyScanDepth(depth: ModelIntakeScanDepth, snapshotCapable = snapshotSupported) {
    setScanDepth(depth)
    const full = depth === 'full'
    setCompleteArtifactDownload(full)
    setRunGeneratedScanners(full)
    setCompleteRepositorySnapshot(full && snapshotCapable)
  }

  function raiseArtifactLimitFloor(floorBytes: number) {
    setMaxDownloadBytes((current) => {
      const parsed = Number(current)
      return Number.isFinite(parsed) && parsed >= floorBytes ? current : String(floorBytes)
    })
  }

  function applyEnvironment(next: ModelIntakeEnvironment) {
    setEnvironment(next)
    const option = ENVIRONMENT_OPTIONS.find((item) => item.value === next)
    // Strict is a deliberate hardening choice on top of production, so keep it
    // when the operator already selected it.
    if (option && policyProfile !== 'strict') applyPolicyProfile(option.policyProfile)
  }

  function applyDepth(next: IntakeDepth) {
    const option = INTAKE_DEPTHS.find((item) => item.value === next)
    if (!option) return
    setRunGeneratedScanners(option.scanners)
    setCompleteRepositorySnapshot(option.snapshot)
    setRunDynamicSandbox(option.sandbox)
    // "Require sandbox pass" cannot outlive the sandbox that would produce it.
    if (!option.sandbox) setRequireDynamicSandbox(false)
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
      if (saved.strict_model_intake) raiseArtifactLimitFloor(STRICT_ARTIFACT_LIMIT_FLOOR)
      if (saved.strict_model_intake) {
        setTrustMode('trusted_key_fingerprint')
        if ((saved.required_trust_anchor_ids || []).length) {
          setSelectedTrustAnchorIds((prev) => Array.from(new Set([...prev, ...(saved.required_trust_anchor_ids || [])])))
        }
      }
      return
    }
    if (profile === 'research') {
      setRequireDeploymentApproval(false)
      setRequireSignature(false)
      setRequireSignatureVerification(false)
      setRequireHash(false)
      setRequireModelGovernance(false)
      if (trustMode === 'trusted_key_fingerprint') setTrustMode('signature_url_key_url')
      return
    }
    setRequireHash(true)
    setRequireSignature(true)
    setRequireModelGovernance(true)
    setRequireDeploymentApproval(profile === 'production' || profile === 'strict')
    setRequireSignatureVerification(profile === 'strict')
    if (profile === 'strict') raiseArtifactLimitFloor(STRICT_ARTIFACT_LIMIT_FLOOR)
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
      // Presets and resolver payloads carry their own flags; re-apply the
      // selected depth so the request still matches what the operator chose.
      applyScanDepth(scanDepth, result.capabilities?.repository_snapshot === 'implemented')
      // A 1GB+ model must not silently fall back to a truncated prefix just
      // because the resolver's preset carried a small cap.
      const resolvedSize = Number(result.selected_file?.size_bytes || 0)
      if (Number.isFinite(resolvedSize) && resolvedSize > 0) {
        setMaxDownloadBytes((current) => {
          const parsed = Number(current)
          const needed = artifactLimitForSize(resolvedSize)
          return Number.isFinite(parsed) && parsed >= resolvedSize ? current : String(needed)
        })
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to resolve model reference'
      setError(msg)
      toast.error(msg)
    } finally {
      setResolving(false)
    }
  }

  async function runCompleteReview() {
    if (!sourceRef.trim()) {
      setError('Paste a Hugging Face model link or model reference first.')
      return
    }
    setQuickSubmitting(true)
    setError(null)
    try {
      const queued = await createModelIntakeAutomaticReview({
        source: sourceRef.trim(),
        intended_environment: environment,
        revision: optionalText(revision),
      })
      trackQueuedScan(queued.scan_id)
      await Promise.all([loadAutomaticReviews(), loadIntakeScans()])
      toast.success('Automatic end-to-end review started', {
        link: { href: queued.scan_report_url, label: 'Open live scan' },
      })
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to queue the complete model review'
      setError(message)
      toast.error(message)
    } finally {
      setQuickSubmitting(false)
    }
  }

  async function exportAutomaticReport(reviewId: string, format: 'json' | 'html' | 'sarif') {
    const key = `${reviewId}:${format}`
    setAutomaticDownload(key)
    try {
      const exported = await downloadModelIntakeAutomaticReport(reviewId, format)
      const url = URL.createObjectURL(exported.blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = exported.filename
      anchor.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to download automatic review report')
    } finally {
      setAutomaticDownload('')
    }
  }

  async function exportAutomaticBom(scanId: string, format: 'cyclonedx' | 'spdx' | 'aibom') {
    const key = `${scanId}:${format}`
    setAutomaticDownload(key)
    try {
      await downloadModelIntakeSbom(scanId, format)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to download model bill of materials')
    } finally {
      setAutomaticDownload('')
    }
  }

  async function exportAutomaticLicenseArtifact(
    scanId: string,
    format: 'license-bom' | 'third-party-notices',
  ) {
    const key = `${scanId}:${format}`
    setAutomaticDownload(key)
    try {
      await downloadModelIntakeLicenseArtifact(scanId, format)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to download license evidence')
    } finally {
      setAutomaticDownload('')
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
      // Stay on the pipeline. Navigating away to the report was what forced the
      // operator to copy the scan UUID back into the admission stage by hand.
      trackQueuedScan(result.scan_id)
      await loadIntakeScans()
      toast.success('Preflight scan queued', {
        link: { href: `/scans/${result.scan_id}`, label: 'Open report' },
      })
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
    signature_trusted_keys: signatureTrustedKeys.trim() || signatureTrustedKeySha256.trim() || selectedAnchorPems || selectedAnchorFingerprints || (parsedMetadata?.signature_trusted_keys as string | undefined),
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
  // One model reference for the whole page. The resolver pins it, the preflight
  // scan queues it, and the controlled workflow submits it — no stage asks for
  // the URL a second time.
  const intakeSource = artifactUrl.trim() || resolverResult?.normalized_ref?.trim() || sourceRef.trim()
  // Derived rather than stored, so hand-editing an Advanced toggle can never
  // leave a depth tile highlighted for evidence the scan will not produce.
  const activeDepth =
    INTAKE_DEPTHS.find(
      (option) =>
        option.scanners === runGeneratedScanners &&
        option.snapshot === completeRepositorySnapshot &&
        option.sandbox === runDynamicSandbox,
    )?.value ?? null
  const snapshotSupported = resolverResult
    ? resolverResult.capabilities?.repository_snapshot === 'implemented'
    : platform === 'huggingface' || platform === 'auto'
  const resolvedArtifactSize = Number(resolverResult?.selected_file?.size_bytes || 0)
  const artifactLimitCoversArtifact = (Number(maxDownloadBytes) || 0) >= resolvedArtifactSize
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
    signatureTrustedKeys: previewIncludesTrustAnchor ? [signatureTrustedKeys, selectedAnchorPems].filter(Boolean).join('\n') : '',
    signatureTrustedKeySha256: previewIncludesTrustAnchor ? [signatureTrustedKeySha256, selectedAnchorFingerprints].filter(Boolean).join('\n') : '',
    metadata: parsedMetadata,
    modelCardUrl,
  })
  const hasTrustFailures = hasIntakeInput && trustPreview.blockingFailures.length > 0

  async function openCheckCatalog() {
    setCheckCatalogOpen(true)
    if (checkCatalog || checkCatalogLoading) return
    setCheckCatalogLoading(true)
    setCheckCatalogError(null)
    try {
      setCheckCatalog(await getModelIntakeCheckCatalog())
    } catch (error) {
      setCheckCatalogError(error instanceof Error ? error.message : 'Failed to load the check catalog')
    } finally {
      setCheckCatalogLoading(false)
    }
  }

  return (
    <div className="min-w-0 max-w-full space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <PackageCheck className="h-6 w-6 text-cyan-300" />
            <h1 className="text-2xl font-bold text-white">Model Intake</h1>
          </div>
          <p className="mt-1 text-gray-400">
            One pipeline: pick the model, produce technical evidence, then take that exact evidence
            through controlled admission.
          </p>
        </div>
        <button
          type="button"
          onClick={openCheckCatalog}
          className="inline-flex items-center gap-2 rounded-lg border border-cyan-700/60 bg-cyan-950/30 px-3 py-2 text-sm font-medium text-cyan-100 hover:bg-cyan-900/40 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
        >
          <Info className="h-4 w-4" />
          What ShakerScan checks
        </button>
      </div>

      <Modal
        open={checkCatalogOpen}
        onClose={() => setCheckCatalogOpen(false)}
        title="What Model Intake checks"
        size="xl"
      >
        <div className="space-y-4">
          <div className="rounded-lg border border-cyan-800/50 bg-cyan-950/20 p-4 text-sm text-cyan-50">
            This is the implemented capability catalog. Every completed report separately states whether each
            applicable check ran, what evidence it produced, and whether it passed, failed, was incomplete, or needs review.
            A catalog entry by itself is never proof that a check ran.
          </div>
          {checkCatalogLoading && <CardSkeleton />}
          {checkCatalogError && <ErrorState message={checkCatalogError} />}
          {checkCatalog && (
            <>
              <div className="text-sm text-gray-400">{checkCatalog.status_note}</div>
              <div className="grid gap-3 md:grid-cols-2">
                {checkCatalog.checks.map((item) => (
                  <div key={item.id} className="rounded-lg border border-gray-800 bg-gray-950/60 p-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="font-medium text-white">{item.check}</div>
                      <span className="shrink-0 rounded bg-gray-800 px-2 py-0.5 font-mono text-xs text-gray-300">{item.id}</span>
                    </div>
                    <p className="mt-1 text-sm leading-5 text-gray-300">{item.description}</p>
                    <div className="mt-2 text-xs text-gray-500">
                      <span className="text-gray-400">Runs when:</span> {item.applies_when}
                    </div>
                    <div className="mt-1 text-xs text-gray-500">
                      <span className="text-gray-400">Evidence source:</span> {item.implementation}
                    </div>
                  </div>
                ))}
              </div>
              <details className="rounded-lg border border-amber-800/40 bg-amber-950/20 p-4">
                <summary className="cursor-pointer font-medium text-amber-100">
                  Deployment and organization follow-up ({checkCatalog.external_approval_requirements.length})
                </summary>
                <div className="mt-3 space-y-3">
                  {checkCatalog.external_approval_requirements.map((item) => (
                    <div key={item.id} className="border-l-2 border-amber-700/60 pl-3 text-sm">
                      <div className="font-medium text-amber-50">{item.id} — {item.category}</div>
                      <div className="mt-1 text-gray-300">{item.requirement}</div>
                      <div className="mt-1 text-xs text-gray-500">Owner: {item.typical_owner} · Evidence: {item.expected_evidence}</div>
                    </div>
                  ))}
                </div>
              </details>
            </>
          )}
        </div>
      </Modal>

      <div className="inline-flex rounded-lg border border-gray-800 bg-gray-950 p-1" aria-label="Model Intake workflow mode">
        <button
          type="button"
          onClick={() => setWorkflowMode('automatic')}
          className={`rounded-md px-4 py-2 text-sm font-medium ${workflowMode === 'automatic' ? 'bg-cyan-700 text-white' : 'text-gray-400 hover:text-white'}`}
        >
          Automatic review
        </button>
        <button
          type="button"
          onClick={() => setWorkflowMode('advanced')}
          className={`rounded-md px-4 py-2 text-sm font-medium ${workflowMode === 'advanced' ? 'bg-cyan-700 text-white' : 'text-gray-400 hover:text-white'}`}
        >
          Advanced / manual
        </button>
      </div>

      {workflowMode === 'automatic' && (
      <>
      <Card className="border-cyan-500/30 bg-gradient-to-br from-cyan-950/40 to-gray-950 p-5">
        <div className="max-w-3xl">
          <div className="flex items-center gap-2 text-lg font-semibold text-white">
            <PackageCheck className="h-5 w-5 text-cyan-300" />
            Test a model end to end
          </div>
          <p className="mt-1 text-sm text-gray-400">
            Paste one Hugging Face link and click Start. ShakerScan pins the revision, acquires and hashes the complete
            model repository, derives the exact inference runtime, runs every applicable scanner, creates the technical
            report and AIBOM, performs Firecracker
            calibration and repeat inference, freezes the evidence, and prepares one technical report. The result clearly
            separates verified checks, issues to fix, and deployment follow-up.
          </p>
        </div>
        <div className="mt-4 grid gap-3 lg:grid-cols-[minmax(0,1fr)_12rem_auto]">
          <label className={fieldClass}>
            Hugging Face model link
            <input
              value={sourceRef}
              onChange={(event) => {
                setSourceRef(event.target.value)
                setResolverResult(null)
              }}
              className={inputClass}
              placeholder="https://huggingface.co/nomic-ai/CodeRankEmbed"
            />
          </label>
          <label className={fieldClass}>
            Intended use
            <select
              value={environment}
              onChange={(event) => applyEnvironment(event.target.value as ModelIntakeEnvironment)}
              className={inputClass}
            >
              {ENVIRONMENT_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
          </label>
          <button
            type="button"
            onClick={runCompleteReview}
            disabled={quickSubmitting || !sourceRef.trim()}
            className="inline-flex items-center justify-center gap-2 self-end rounded-lg bg-cyan-600 px-5 py-2 text-sm font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
          >
            {quickSubmitting ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            {quickSubmitting ? 'Starting review…' : 'Start review'}
          </button>
        </div>
        <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs text-gray-500">
          <span>Complete artifact + repository</span>
          <span>ModelScan, Fickling, Semgrep, Trivy, OSV, pip-audit</span>
          <span>Firecracker load + repeat inference</span>
          <span>Clear HTML report + AIBOM, with machine exports when needed</span>
        </div>
        {runnerReadiness === null && (
          <div className="mt-4 flex items-center gap-2 rounded-lg border border-gray-800 bg-gray-900/50 p-3 text-sm text-gray-400">
            <RefreshCw className="h-4 w-4 animate-spin" /> Checking the isolated runtime on this host…
          </div>
        )}
        {runnerReadiness?.status === 'READY' && (
          <div className="mt-4 flex items-center gap-2 rounded-lg border border-green-800/60 bg-green-950/20 p-3 text-sm text-green-200">
            <CheckCircle2 className="h-4 w-4" /> Firecracker is ready. Automatic reviews will include isolated load and repeat-inference evidence.
          </div>
        )}
        {runnerReadiness !== null && runnerReadiness.status !== 'READY' && (
          <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-yellow-700/50 bg-yellow-950/20 p-3 text-sm text-yellow-100">
            <span>
              Static checks can run now, but isolated loading cannot run until the microVM runner is ready.
            </span>
            <button
              type="button"
              onClick={() => { setWorkflowMode('advanced'); setPhase('status') }}
              className="rounded border border-yellow-600/50 px-3 py-1.5 text-xs font-medium hover:bg-yellow-900/40"
            >
              Set up Firecracker
            </button>
          </div>
        )}
      </Card>

      <Card className="min-w-0 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-white">Automatic reviews</h2>
            <p className="mt-1 text-xs text-gray-500">The controller keeps working if this page is closed or the API restarts.</p>
          </div>
          <button type="button" onClick={loadAutomaticReviews} className="rounded border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800">Refresh</button>
        </div>
        {automaticReviewsError && <div role="alert" className="mt-3 text-xs text-red-300">{automaticReviewsError}</div>}
        {!automaticReviewsError && automaticReviews.length === 0 ? (
          <div className="mt-4 rounded-lg border border-gray-800 bg-gray-950 p-4 text-sm text-gray-500">
            No automatic review has been started yet.
          </div>
        ) : (
          <div className="mt-4 grid gap-3">
            {automaticReviews.slice(0, showAllAutomaticReviews ? automaticReviews.length : 5).map((review, reviewIndex) => {
              const terminal = ['technical_review_complete', 'attention_required', 'failed', 'cancelled'].includes(review.state)
              const displayedProgress = review.effective_progress ?? review.progress
              const displayedStep = review.effective_current_step || review.current_step
              const workflowComplete = review.state === 'technical_review_complete'
              const outcome = (review.technical_outcome || '').toUpperCase()
              const passed = workflowComplete && outcome === 'PASS'
              const blocked = workflowComplete && outcome === 'BLOCK'
              const incomplete = workflowComplete && outcome === 'INCOMPLETE'
              const queuedForRunner = review.active_runner_job_state === 'pending'
              const supersededByNewerReview = automaticReviews.slice(0, reviewIndex).some(
                (newerReview) => newerReview.source_label === review.source_label,
              )
              const pendingControls = review.pending_controls || []
              const legacyDeploymentControls = new Set(['publisher_trust', 'human_approvals', 'production_signer', 'deployed_data_plane'])
              const technicalFollowUp = pendingControls.filter((control) => !legacyDeploymentControls.has(control.control) && control.control !== 'deployment_follow_up')
              const deploymentFollowUp = pendingControls.filter((control) => legacyDeploymentControls.has(control.control) || control.control === 'deployment_follow_up')
              const outcomeLabel = workflowComplete
                ? `Review finished · ${outcome === 'BLOCK' ? 'blocked' : outcome === 'PASS' ? 'technical checks passed' : outcome.toLowerCase().replace(/_/g, ' ') || 'results ready'}`
                : (queuedForRunner ? review.state.replace(/_running$/, '_queued') : review.state).replace(/_/g, ' ')
              return (
                <div key={review.id} className="rounded-lg border border-gray-800 bg-gray-950 p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate text-base font-semibold text-white" title={review.source_label || review.id}>
                        {review.source_label || 'Model review'}
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`rounded px-2 py-1 text-xs font-semibold ${passed ? 'bg-green-950/60 text-green-300' : blocked ? 'bg-red-950/60 text-red-300' : terminal ? 'bg-yellow-950/60 text-yellow-300' : 'bg-cyan-950/60 text-cyan-300'}`}>
                          {outcomeLabel}
                        </span>
                        <span className="text-xs text-gray-500">{review.requested_environment}</span>
                        {supersededByNewerReview && (
                          <span className="rounded bg-gray-800 px-2 py-1 text-xs text-gray-400">Earlier run · newer review available</span>
                        )}
                      </div>
                      <div className="mt-2 text-sm font-medium text-white">{displayedStep.replace(/_/g, ' ')}</div>
                      {review.state === 'static_scan_pending' && review.static_scan_progress != null && (
                        <div className="mt-1 text-xs text-cyan-300">
                          Technical scan {review.static_scan_progress}% complete
                        </div>
                      )}
                      <div className="mt-1 text-[11px] text-gray-500">Started {new Date(review.created_at).toLocaleString()} · {review.source_kind}</div>
                      <div className="mt-1 font-mono text-[11px] text-gray-600">review {review.id} · scan {review.scan_id}</div>
                    </div>
                    <div className="text-right text-sm font-semibold text-white">{displayedProgress}%</div>
                  </div>
                  {workflowComplete && (
                    <div className={`mt-3 rounded border p-3 text-xs ${blocked ? 'border-red-800/60 bg-red-950/20 text-red-200' : passed ? 'border-green-800/60 bg-green-950/20 text-green-200' : 'border-yellow-800/60 bg-yellow-950/20 text-yellow-200'}`}>
                      <div className="font-semibold">{blocked ? 'Do not use this revision yet' : passed ? 'Technical checks passed' : incomplete ? 'Review incomplete' : 'Review needs attention'}</div>
                      <div className="mt-1 opacity-80">{blocked ? 'One or more required technical checks failed. Open the report for evidence and next steps.' : passed ? 'All technical checks selected for this review completed successfully.' : incomplete ? 'One or more technical checks could not complete. Open the report for the exact prerequisite or retry.' : `${technicalFollowUp.length || 'Some'} check${technicalFollowUp.length === 1 ? '' : 's'} ${technicalFollowUp.length === 1 ? 'needs' : 'need'} review. Open the report for evidence and next steps.`}</div>
                    </div>
                  )}
                  <div className="mt-3 h-2 overflow-hidden rounded-full bg-gray-800">
                    <div className={`h-full ${blocked ? 'bg-red-500' : terminal && !passed ? 'bg-yellow-500' : passed ? 'bg-green-500' : 'bg-cyan-500'}`} style={{ width: `${displayedProgress}%` }} />
                  </div>
                  {review.error_json?.message && (
                    <div role="alert" className="mt-3 rounded border border-yellow-800/60 bg-yellow-950/20 p-3 text-xs text-yellow-200">
                      {review.error_json.message}
                    </div>
                  )}
                  {technicalFollowUp.length > 0 && (
                    <div className="mt-3 grid gap-2 md:grid-cols-2">
                      {technicalFollowUp.map((control) => (
                        <div key={control.control} className="rounded border border-gray-800 bg-gray-900 p-2 text-xs">
                          <div className="font-medium text-gray-200">{control.control.replace(/_/g, ' ')} · {control.status}</div>
                          <div className="mt-1 text-gray-400">{control.summary || control.action}</div>
                          {(control.items || []).length > 0 && (
                            <ul className="mt-2 space-y-2">
                              {(control.items || []).map((item, index) => (
                                <li key={`${item.path || item.title}:${item.line || index}`} className="rounded border border-gray-800 bg-gray-950 p-2">
                                  <div className="text-gray-200">{item.title}</div>
                                  <div className="mt-1 text-[11px] text-gray-500">
                                    {[item.path && `${item.path}${item.line ? `:${item.line}` : ''}`, (item.scanners || []).join(', ')].filter(Boolean).join(' · ')}
                                  </div>
                                </li>
                              ))}
                            </ul>
                          )}
                          {(control.items || []).length === 0 && control.action && control.action !== (control.summary || control.action) && (
                            <div className="mt-1 text-gray-500">{control.action}</div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                  {deploymentFollowUp.length > 0 && (
                    <details className="mt-3 rounded border border-gray-800 bg-gray-900/60 p-3 text-xs">
                      <summary className="cursor-pointer font-medium text-gray-300">Deployment follow-up</summary>
                      <p className="mt-2 text-gray-500">
                        Confirm publisher trust, production signing, application/data-plane controls, and any reviews required by your organization before deployment.
                      </p>
                    </details>
                  )}
                  {(review.timeline_json || []).length > 0 && (
                    <details className="mt-3 rounded border border-gray-800 bg-gray-900/60 p-3 text-xs">
                      <summary className="cursor-pointer font-medium text-gray-300">Workflow steps ({(review.timeline_json || []).length})</summary>
                      <ol className="mt-2 grid gap-2 border-l border-gray-700 pl-3">
                        {(review.timeline_json || []).map((event, index) => (
                          <li key={`${event.event}:${event.at}:${index}`} className="text-gray-400">
                            <span className="font-medium text-gray-200">{event.event.replace(/_/g, ' ')}</span>
                            <span> · {event.state.replace(/_/g, ' ')} · {new Date(event.at).toLocaleString()}</span>
                          </li>
                        ))}
                      </ol>
                    </details>
                  )}
                  <div className="mt-3 flex flex-wrap gap-2">
                    {review.submission_id && (
                      <button
                        type="button"
                        onClick={() => exportAutomaticReport(review.id, 'html')}
                        disabled={automaticDownload === `${review.id}:html`}
                        className="rounded bg-cyan-700 px-3 py-1.5 text-xs font-semibold text-white hover:bg-cyan-600 disabled:opacity-50"
                      >
                        {automaticDownload === `${review.id}:html` ? 'Preparing…' : 'HTML report'}
                      </button>
                    )}
                    {review.submission_id && (
                      <button
                        type="button"
                        onClick={() => exportAutomaticBom(review.scan_id, 'aibom')}
                        disabled={automaticDownload === `${review.scan_id}:aibom`}
                        className="rounded border border-cyan-700 px-3 py-1.5 text-xs font-semibold text-cyan-200 hover:bg-cyan-950/50 disabled:opacity-50"
                      >
                        {automaticDownload === `${review.scan_id}:aibom` ? 'Preparing…' : 'AIBOM'}
                      </button>
                    )}
                    {review.submission_id && (
                      <details className="relative rounded border border-gray-700 px-3 py-1.5 text-xs text-gray-300">
                        <summary className="cursor-pointer select-none">More exports</summary>
                        <div className="mt-3 grid gap-2 sm:grid-cols-2">
                          <Link href={`/scans/${review.scan_id}`} className="rounded border border-gray-700 px-3 py-1.5 text-center hover:bg-gray-800">Static scan details</Link>
                          {(['cyclonedx', 'spdx'] as const).map((format) => (
                            <button key={format} type="button" onClick={() => exportAutomaticBom(review.scan_id, format)} disabled={automaticDownload === `${review.scan_id}:${format}`} className="rounded border border-gray-700 px-3 py-1.5 hover:bg-gray-800 disabled:opacity-50">
                              {automaticDownload === `${review.scan_id}:${format}` ? 'Preparing…' : `${format === 'cyclonedx' ? 'CycloneDX' : 'SPDX'} SBOM`}
                            </button>
                          ))}
                          {(['license-bom', 'third-party-notices'] as const).map((format) => (
                            <button key={format} type="button" onClick={() => exportAutomaticLicenseArtifact(review.scan_id, format)} disabled={automaticDownload === `${review.scan_id}:${format}`} className="rounded border border-gray-700 px-3 py-1.5 hover:bg-gray-800 disabled:opacity-50">
                              {automaticDownload === `${review.scan_id}:${format}` ? 'Preparing…' : format === 'license-bom' ? 'License BOM' : 'Notices draft'}
                            </button>
                          ))}
                          {(['json', 'sarif'] as const).map((format) => (
                            <button key={format} type="button" onClick={() => exportAutomaticReport(review.id, format)} disabled={automaticDownload === `${review.id}:${format}`} className="rounded border border-gray-700 px-3 py-1.5 hover:bg-gray-800 disabled:opacity-50">
                              {automaticDownload === `${review.id}:${format}` ? 'Preparing…' : `${format.toUpperCase()} report`}
                            </button>
                          ))}
                        </div>
                      </details>
                    )}
                  </div>
                </div>
              )
            })}
            {automaticReviews.length > 5 && (
              <button
                type="button"
                onClick={() => setShowAllAutomaticReviews((current) => !current)}
                className="rounded border border-gray-700 px-3 py-2 text-xs text-gray-300 hover:bg-gray-800"
              >
                {showAllAutomaticReviews ? 'Hide older reviews' : `Show ${automaticReviews.length - 5} older reviews`}
              </button>
            )}
          </div>
        )}
      </Card>
      </>
      )}

      {workflowMode === 'advanced' && (
      <>

      <IntakeContextBar
        source={intakeSource}
        environment={environment}
        policyProfile={policyProfile}
        operatorReady={Boolean(operatorToken.trim())}
        adaptersReady={scannerReadiness?.required_ready ?? null}
        adaptersTotal={scannerReadiness?.required_total ?? null}
        runnerStatus={runnerReadiness?.status ?? null}
        runnerSupportedHost={runnerReadiness?.supported_host}
        runnerUnsupportedReason={runnerReadiness?.unsupported_reason}
        runnerHostPlatform={runnerReadiness?.host_platform}
        onOpenRunnerStatus={() => {
          setPhase('status')
          window.scrollTo({ top: 0, behavior: 'smooth' })
        }}
      />

      <IntakePhaseTabs
        phase={phase}
        onPhaseChange={setPhase}
        completed={{
          source: Boolean(intakeSource),
          preflight: queuedScans.some((scan) => scan.status === 'completed'),
          admission: false,
        }}
      />

      {error && <div role="alert" className="rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-400">{error}</div>}

      {trustRemediationMode && (
        <div className="rounded-lg border border-cyan-500/30 bg-cyan-950/30 p-4 text-sm text-cyan-100">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2 font-medium text-white">
                <ShieldCheck className="h-4 w-4 text-cyan-300" />
                Model trust remediation
              </div>
              <p className="mt-1 text-cyan-100/80">
                Strict signing checks are selected. Add or select an operator trust anchor, provide
                signature evidence, and confirm the preview before queueing the replacement intake scan.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <a href="#model-intake-trust-remediation" className="rounded border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 text-xs font-medium text-cyan-100 hover:bg-cyan-500/20">
                Trust controls
              </a>
              <Link href="/exceptions?queue_filter=expired" className="rounded border border-gray-700 px-3 py-1.5 text-xs font-medium text-gray-300 hover:bg-gray-800">
                Exception hygiene
              </Link>
            </div>
          </div>
        </div>
      )}

      {phase === 'source' && (
        <Card className="min-w-0 p-4" id="model-intake-source">
          <div className="flex items-center gap-2 text-white">
            <Wand2 className="h-4 w-4 text-cyan-300" />
            <h2 className="text-sm font-semibold">1. Model &amp; Target</h2>
          </div>
          <p className="mt-1 text-xs text-gray-500">
            Pick the model and where it is headed once. Every stage below — the preflight scan and the
            controlled admission workflow — reads this reference and this environment.
          </p>

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

          <div className="mt-5 rounded-lg border border-gray-800 bg-gray-950 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-sm font-medium text-gray-200">Deployment target</div>
              <span className="text-xs text-gray-500">
                Sets the preflight policy profile and the controlled submission environment
              </span>
            </div>
            <div className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
              {ENVIRONMENT_OPTIONS.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => applyEnvironment(option.value)}
                  className={`min-w-0 rounded-lg border p-3 text-left ${
                    environment === option.value ? 'border-cyan-500 bg-cyan-950/40' : 'border-gray-800 bg-gray-900 hover:border-gray-700'
                  }`}
                >
                  <div className="break-words text-sm font-medium text-white">{option.label}</div>
                  <div className="mt-1 break-words text-xs text-gray-500">{option.helper}</div>
                </button>
              ))}
            </div>
          </div>

          <div className="mt-4 rounded-lg border border-gray-800 bg-gray-950 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-sm font-medium text-gray-200">Scan depth</div>
              <span className="text-xs text-gray-500">
                Controls which evidence the preflight scan generates
              </span>
            </div>
            <div className="mt-3 grid gap-2 sm:grid-cols-3">
              {INTAKE_DEPTHS.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => applyDepth(option.value)}
                  className={`min-w-0 rounded-lg border p-3 text-left ${
                    activeDepth === option.value ? 'border-cyan-500 bg-cyan-950/40' : 'border-gray-800 bg-gray-900 hover:border-gray-700'
                  }`}
                >
                  <div className="break-words text-sm font-medium text-white">{option.label}</div>
                  <div className="mt-1 break-words text-xs text-gray-500">{option.helper}</div>
                </button>
              ))}
            </div>
            <p className="mt-3 text-xs text-gray-500">
              {activeDepth === null
                ? 'Custom: the evidence toggles under Advanced in the preflight step no longer match a preset.'
                : 'Controls you leave out are reported as not run — never as clean. Fine-tune under Advanced in the preflight step.'}
            </p>
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
                  <div className="min-w-0 break-words">Artifact acquisition: <span className="text-gray-200">{resolverResult.capabilities?.artifact_acquisition || 'unknown'}</span></div>
                  <div className="min-w-0 break-words">Repository snapshot: <span className="text-gray-200">{resolverResult.capabilities?.repository_snapshot || 'unknown'}</span></div>
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

          <div className="mt-5 flex flex-wrap items-center justify-between gap-2 border-t border-gray-800 pt-4">
            <span className="text-xs text-gray-500">
              {intakeSource ? 'Model and deployment target selected.' : 'Resolve a reference, or paste an artifact URL in the preflight step.'}
            </span>
            <button
              type="button"
              onClick={() => setPhase('preflight')}
              className="inline-flex items-center gap-2 rounded-lg bg-cyan-700 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-600"
            >
              Continue to preflight
            </button>
          </div>
        </Card>
      )}

      {phase === 'preflight' && (
        <>
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
          <div className="mt-4 rounded-lg border border-yellow-700/50 bg-yellow-950/20 p-3">
            <div className="text-sm font-medium text-yellow-100">Technical preflight only</div>
            <div className="mt-1 text-xs text-yellow-200/70">
              This page produces technical evidence for the pinned model revision. A deployment decision is created separately from frozen evidence, policy, signing, and any required approvals.
            </div>
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
                {profile.strict_model_intake && (profile.required_trust_anchor_ids || []).length > 0 && (
                  <div className="mt-2 text-xs text-cyan-200">
                    {(profile.required_trust_anchor_ids || []).length} policy-bound trust anchor{(profile.required_trust_anchor_ids || []).length === 1 ? '' : 's'}
                  </div>
                )}
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
            <h2 className="text-sm font-semibold">3. Preflight Evidence Scan</h2>
          </div>
          <p className="-mt-2 text-xs text-gray-500">
            Technical evidence for the model selected in step 1. This never grants deployment
            authority — step 4 does that.
          </p>

          <div className="min-w-0 space-y-3 rounded-lg border border-gray-800 bg-gray-950 p-3">
            <div className="text-sm font-medium text-gray-200">Scan depth</div>
            <div className="grid gap-2 sm:grid-cols-2">
              {SCAN_DEPTHS.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => applyScanDepth(option.value)}
                  className={`min-w-0 rounded-lg border p-3 text-left ${
                    scanDepth === option.value ? 'border-cyan-500 bg-cyan-950/40' : 'border-gray-800 bg-gray-900 hover:border-gray-700'
                  }`}
                >
                  <div className="break-words text-sm font-medium text-white">{option.label}</div>
                  <div className="mt-1 break-words text-xs text-gray-500">{option.helper}</div>
                </button>
              ))}
            </div>
            <div className="text-xs text-gray-500">
              {scanDepth === 'full' ? (
                <>
                  Runs the {scannerReadiness ? `${scannerReadiness.required_ready}/${scannerReadiness.required_total} ready ` : ''}
                  evidence adapters over the complete quarantined subject
                  {snapshotSupported
                    ? ', including a full repository snapshot.'
                    : '. This source publishes no repository manifest, so the artifact alone is the subject.'}
                  {' '}A full-artifact checksum and signature are only verifiable at this depth.
                </>
              ) : (
                <>Acquires a bounded prefix only. Checksum and signature stay unverified, and no evidence adapter runs.</>
              )}
            </div>
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

          <div className="min-w-0 space-y-3 rounded-lg border border-gray-800 bg-gray-950 p-3">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div>
                <div className="text-sm font-medium text-gray-200">Artifact acquisition limit</div>
                <div className="mt-1 text-xs text-gray-500">
                  How many artifact bytes intake may fetch. A full-artifact checksum and signature can
                  only be verified when this covers the whole file — anything above the in-memory
                  inspection prefix streams into content-addressed quarantine instead.
                </div>
              </div>
              <span className="rounded bg-gray-800 px-2 py-1 font-mono text-xs text-gray-200">
                {formatBytes(Number(maxDownloadBytes) || 0)}
              </span>
            </div>
            <div className="grid gap-2 sm:grid-cols-3 xl:grid-cols-5">
              {ARTIFACT_LIMIT_PRESETS.map((preset) => (
                <button
                  key={preset.bytes}
                  type="button"
                  onClick={() => setMaxDownloadBytes(String(preset.bytes))}
                  className={`min-w-0 rounded-lg border p-2 text-left ${
                    Number(maxDownloadBytes) === preset.bytes ? 'border-cyan-500 bg-cyan-950/40' : 'border-gray-800 bg-gray-900 hover:border-gray-700'
                  }`}
                >
                  <div className="text-sm font-medium text-white">{preset.label}</div>
                  <div className="mt-0.5 break-words text-[11px] text-gray-500">{preset.helper}</div>
                </button>
              ))}
            </div>
            {resolvedArtifactSize > 0 && (
              <div className={`text-xs ${artifactLimitCoversArtifact ? 'text-gray-500' : 'text-yellow-200'}`}>
                {artifactLimitCoversArtifact
                  ? `Resolved artifact is ${formatBytes(resolvedArtifactSize)}; the full file will be acquired and hashed.`
                  : `Resolved artifact is ${formatBytes(resolvedArtifactSize)}, larger than this limit. Intake will report a truncated, unverified checksum.`}
              </div>
            )}
            <label className={fieldClass}>
              Exact limit (bytes)
              <input value={maxDownloadBytes} onChange={(e) => setMaxDownloadBytes(e.target.value)} className={inputClass} inputMode="numeric" />
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

          <div
            id="model-intake-trust-remediation"
            ref={trustSectionRef}
            className={`min-w-0 scroll-mt-24 space-y-3 rounded-lg border bg-gray-950 p-3 ${
              trustRemediationMode ? 'border-cyan-500/60 shadow-[0_0_0_1px_rgba(34,211,238,0.18)]' : 'border-gray-800'
            }`}
          >
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="flex items-center gap-2 text-sm font-medium text-gray-200">
                <ShieldCheck className="h-4 w-4 text-cyan-300" />
                Trust mode
              </div>
              <span className={`rounded px-2 py-1 text-xs ${
                hasIntakeInput ? TRUST_PREVIEW_BADGE[trustPreview.headlineStatus] : 'bg-gray-800 text-gray-400'
              }`}>
                {hasIntakeInput ? trustPreview.headline : 'Add an artifact to preview requirements'}
              </span>
            </div>
            {hasIntakeInput ? (
            <>
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
              <div className="space-y-3">
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

                <div className="rounded border border-gray-800 bg-gray-900 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <div className="text-sm font-medium text-gray-200">Saved trust anchors</div>
                      <div className="mt-1 text-xs text-gray-500">Reusable operator roots. Selected anchors are included in the queued scan as trusted PEM/fingerprint material.</div>
                    </div>
                    <button type="button" onClick={loadTrustAnchors} className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800">
                      Refresh
                    </button>
                  </div>
                  <div className="mt-3 rounded border border-gray-800 bg-gray-950 p-2 text-xs">
                    {operatorToken ? (
                      <span className="text-gray-500">
                        Trust-anchor changes are authorized with the operator credential resolved in
                        step 4. No separate token is needed here.
                      </span>
                    ) : (
                      <span className="text-yellow-200">
                        No operator credential is active. Set one in step 4 before creating or
                        deactivating a trust anchor.
                      </span>
                    )}
                  </div>
                  {trustAnchorsLoading && <div className="mt-3 text-xs text-gray-500">Loading trust anchors...</div>}
                  {trustAnchorsError && <div role="alert" className="mt-3 text-xs text-red-400">{trustAnchorsError}</div>}
                  {!trustAnchorsLoading && savedTrustAnchors.length === 0 && (
                    <div className="mt-3 rounded border border-gray-800 bg-gray-950 p-3 text-sm text-gray-500">
                      No saved trust anchors yet. Save a fingerprint or PEM below, then select it for strict scans.
                    </div>
                  )}
                  {savedTrustAnchors.length > 0 && (
                    <div className="mt-3 grid gap-2 md:grid-cols-2">
                      {savedTrustAnchors.map((anchor) => {
                        const selected = selectedTrustAnchorIds.includes(anchor.id)
                        return (
                          <div key={anchor.id} className={`rounded border p-3 ${selected ? 'border-cyan-500 bg-cyan-950/30' : 'border-gray-800 bg-gray-950'}`}>
                            <label className="flex min-w-0 items-start gap-2 text-sm text-gray-300">
                              <input
                                type="checkbox"
                                checked={selected}
                                onChange={(event) => {
                                  setSelectedTrustAnchorIds((prev) => event.target.checked
                                    ? Array.from(new Set([...prev, anchor.id]))
                                    : prev.filter((id) => id !== anchor.id)
                                  )
                                }}
                                className="mt-0.5 h-4 w-4 rounded border-gray-700 bg-gray-800"
                              />
                              <span className="min-w-0">
                                <span className="block break-words font-medium text-gray-100">{anchor.name}</span>
                                <span className="mt-1 block break-words text-xs text-gray-500">
                                  {anchor.policy_profile || 'any profile'}{anchor.owner ? ` - ${anchor.owner}` : ''}{anchor.public_key_sha256 ? ` - ${anchor.public_key_sha256.slice(0, 12)}...` : ' - PEM anchor'}
                                </span>
                              </span>
                            </label>
                            <button
                              type="button"
                              onClick={() => deactivateTrustAnchor(anchor.id)}
                              className="mt-2 rounded border border-gray-700 px-2 py-1 text-xs text-gray-400 hover:bg-gray-800"
                            >
                              Deactivate
                            </button>
                          </div>
                        )
                      })}
                    </div>
                  )}

                  <div className="mt-3 grid gap-2 lg:grid-cols-[minmax(0,0.7fr)_minmax(0,0.7fr)_minmax(0,1fr)_minmax(0,0.7fr)_auto]">
                    <input value={newAnchorName} onChange={(e) => setNewAnchorName(e.target.value)} className={inputClass} placeholder="Anchor name" />
                    <input value={newAnchorOwner} onChange={(e) => setNewAnchorOwner(e.target.value)} className={inputClass} placeholder="Owner" />
                    <input value={newAnchorSha256} onChange={(e) => setNewAnchorSha256(e.target.value)} className={inputClass} placeholder="Key SHA-256 fingerprint" />
                    <textarea value={newAnchorPem} onChange={(e) => setNewAnchorPem(e.target.value)} className={textareaClass} rows={2} placeholder="Optional PEM" />
                    <button
                      type="button"
                      onClick={saveTrustAnchor}
                      disabled={savingAnchor || !newAnchorName.trim() || (!newAnchorSha256.trim() && !newAnchorPem.trim())}
                      className="inline-flex items-center justify-center rounded bg-cyan-700 px-3 py-2 text-sm font-medium text-white hover:bg-cyan-600 disabled:opacity-50"
                    >
                      {savingAnchor ? 'Saving...' : 'Save'}
                    </button>
                  </div>
                </div>
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
            </>
            ) : (
              <p className="text-sm text-gray-500">
                Enter or resolve a model artifact first. ShakerScan will then explain the trust evidence required by the selected policy.
              </p>
            )}
          </div>

          <details className="rounded-lg border border-gray-800 bg-gray-950/50">
            <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-gray-300 hover:text-white">
              Advanced: evidence metadata and policy overrides
            </summary>
            <div className="grid gap-3 border-t border-gray-800 p-3 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
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
                  <input type="checkbox" checked={requireCryptographicSignatureVerification} onChange={(e) => setRequireCryptographicSignatureVerification(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
                  Require trusted crypto verification
                </label>
                <label className="flex min-w-0 items-center gap-2 text-sm text-gray-300">
                  <input type="checkbox" checked={requireDeploymentApproval} onChange={(e) => setRequireDeploymentApproval(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
                  Flag missing approval context
                </label>
                <label className="flex min-w-0 items-center gap-2 text-sm text-gray-300">
                  <input type="checkbox" checked={requireModelGovernance} onChange={(e) => setRequireModelGovernance(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
                  Require governance
                </label>
                <label className="flex min-w-0 items-center gap-2 text-sm text-gray-300">
                  <input type="checkbox" checked={deploymentApproved} onChange={(e) => setDeploymentApproved(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
                  Declare approval context (never grants authority)
                </label>
              </div>
              <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
                <label className={fieldClass}>
                  Timeout (seconds)
                  <input value={timeoutSeconds} onChange={(e) => setTimeoutSeconds(e.target.value)} className={inputClass} inputMode="numeric" />
                </label>
                <label className={fieldClass}>
                  Complete artifact limit (bytes)
                  <input value={maxArtifactBytes} onChange={(e) => setMaxArtifactBytes(e.target.value)} className={inputClass} inputMode="numeric" disabled={!completeArtifactDownload} />
                </label>
              </div>
              <label className="flex min-w-0 items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={completeArtifactDownload} onChange={(e) => setCompleteArtifactDownload(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
                Always acquire the complete artifact, whatever the limit above
              </label>
              <p className="text-xs text-gray-500">
                The acquisition limit in step 3 already escalates to complete streaming acquisition on
                its own. Use this only to force complete acquisition under a separate ceiling.
              </p>
              <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
                <label className="flex min-w-0 items-center gap-2 text-sm text-gray-300">
                  <input type="checkbox" checked={completeRepositorySnapshot} onChange={(e) => setCompleteRepositorySnapshot(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
                  Snapshot every pinned repository file
                </label>
                <label className={fieldClass}>
                  Repository snapshot limit (bytes)
                  <input value={maxRepositoryBytes} onChange={(e) => setMaxRepositoryBytes(e.target.value)} className={inputClass} inputMode="numeric" disabled={!completeRepositorySnapshot} />
                </label>
              </div>
              <p className="text-xs text-gray-500">
                Full repository snapshots currently require a complete Hugging Face manifest pinned to an immutable commit.
              </p>
              <label className="flex min-w-0 items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={runGeneratedScanners} onChange={(e) => setRunGeneratedScanners(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
                Run generated model, malware, secret, SBOM, and SCA scanners
              </label>
              <label className="flex min-w-0 items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={runDynamicSandbox} onChange={(e) => setRunDynamicSandbox(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
                Run no-egress dynamic sandbox
              </label>
              <label className="flex min-w-0 items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={requireDynamicSandbox} onChange={(e) => { setRequireDynamicSandbox(e.target.checked); if (e.target.checked) setRunDynamicSandbox(true) }} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
                Require sandbox pass for this technical evidence
              </label>
              <label className="flex min-w-0 items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={runGeneratedEvaluation} onChange={(e) => setRunGeneratedEvaluation(e.target.checked)} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
                Evaluate embeddings and the vector/graph data plane
              </label>
              <label className="flex min-w-0 items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={requireGeneratedEvaluation} onChange={(e) => { setRequireGeneratedEvaluation(e.target.checked); if (e.target.checked) setRunGeneratedEvaluation(true) }} className="h-4 w-4 rounded border-gray-700 bg-gray-800" />
                Require evaluation pass for this technical evidence
              </label>
              <label className={fieldClass}>
                Evaluation specification JSON
                <textarea
                  value={evaluationSpecJson}
                  onChange={(e) => setEvaluationSpecJson(e.target.value)}
                  className={textareaClass}
                  rows={8}
                  placeholder='{"suite_id":"corp-embedding-security","suite_version":"1","thresholds":{"min_recall_at_k":0.8,"max_acl_leaks":0,"max_poisoned_top_k_rate":0,"min_stability_cosine":0.999},"documents":[],"queries":[],"runtime_runs":[],"data_plane_controls":{}}'
                />
                <span className="text-xs text-gray-500">
                  Requester-supplied observations are treated as declared/debug evidence and cannot satisfy an admission gate. A trusted isolated runner must produce provenance-bound retrieval results. Source text is not retained.
                </span>
              </label>
              <p className="text-xs text-gray-500">
                Required tools that are missing, unsupported, timed out, crashed, or incomplete fail closed instead of being reported as clean.
              </p>
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
          </details>

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
          {hasIntakeInput && hasTrustFailures && (
            <p role="alert" className="text-sm text-red-400">Fix the failed trust preview checks before queueing this scan.</p>
          )}
        </form>

        <PreflightScanTracker
          scans={queuedScans}
          onUseInAdmission={useScanInAdmission}
          onRefresh={loadIntakeScans}
        />

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
                  ShakerScan generates the technical scan, SBOM, malware, runtime, and evaluation evidence. Add the organization-specific approval, private data context, production restrictions, and monitoring plan needed for your deployment.
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
        </>
      )}

      {phase === 'admission' && (
        <>
        <ControlledModelIntakeWorkflow
          operatorToken={operatorToken}
          onOperatorTokenChange={updateOperatorToken}
          operatorCredential={operatorCredential}
          source={intakeSource}
          sourceKind={platform}
          environment={environment}
          expectedArtifactSha256={expectedSha256.trim()}
          availableScans={intakeScans}
          staticScanId={staticScanId}
          onStaticScanIdChange={setStaticScanId}
          onEditContext={() => {
            setPhase('source')
            window.scrollTo({ top: 0, behavior: 'smooth' })
          }}
        />

        <Card className="min-w-0 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-white">Admission lifecycle</h2>
              <p className="mt-1 text-xs text-gray-500">Deployment accepts only active, registered, non-expired signed subjects.</p>
            </div>
            <button type="button" onClick={loadAdmissions} className="rounded border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800">Refresh</button>
          </div>
          {admissionsError ? (
            <div className="mt-3 text-xs text-red-300">{admissionsError}</div>
          ) : admissions.length === 0 ? (
            <div className="mt-3 text-xs text-gray-500">No signed admissions are registered yet.</div>
          ) : (
            <div className="mt-3 grid gap-2">
              {admissions.slice(0, 10).map((admission) => (
                <div key={admission.id} className="grid min-w-0 gap-2 rounded border border-gray-800 bg-gray-950 p-3 sm:grid-cols-[minmax(0,1fr)_auto]">
                  <div className="min-w-0">
                    <div className="truncate font-mono text-xs text-gray-300">sha256:{admission.artifact_sha256}</div>
                    <div className="mt-1 text-xs text-gray-500">Policy {admission.policy_profile || 'unspecified'} · reassess {new Date(admission.reassessment_due_at).toLocaleString()} · expires {new Date(admission.expires_at).toLocaleString()}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`rounded px-2 py-1 text-xs font-semibold ${admission.status === 'active' ? 'bg-green-950/50 text-green-300' : admission.status === 'reassessment_required' ? 'bg-yellow-950/50 text-yellow-300' : 'bg-red-950/50 text-red-300'}`}>{admission.status.replace(/_/g, ' ')}</span>
                    <Link href={`/scans/${admission.scan_id}`} className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800">Scan</Link>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
        </>
      )}

      {phase === 'status' && (
        <>
        <Card className="min-w-0 p-4">
          <RunnerInstallCard
            readiness={runnerReadiness}
            plan={runnerInstallPlan}
            operatorToken={operatorToken}
            environment={environment}
            onRecheck={loadRunnerReadiness}
          />
        </Card>

        <Card className="min-w-0 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-white">Evidence adapter readiness</h2>
              <p className="mt-1 text-xs text-gray-500">Strict intake requires applicable adapters; irrelevant formats report not applicable.</p>
            </div>
            <div className="flex items-center gap-2">
              {scannerReadiness && (
                <span className={`rounded px-2 py-1 text-xs font-semibold ${scannerReadiness.status === 'READY' ? 'bg-green-950/50 text-green-300' : 'bg-yellow-950/50 text-yellow-300'}`}>
                  {scannerReadiness.required_ready}/{scannerReadiness.required_total} ready
                </span>
              )}
              <button type="button" onClick={loadScannerReadiness} className="rounded border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800">Refresh</button>
            </div>
          </div>
          {scannerReadinessError ? (
            <div className="mt-3 text-xs text-red-300">{scannerReadinessError}</div>
          ) : scannerReadiness ? (
            <div className="mt-3">
              {scannerReadiness.reassessment_required && <div className="mb-3 rounded border border-red-800/60 bg-red-950/20 p-3 text-xs text-red-300">Required scanner rules or vulnerability data are stale. Strict scans fail incomplete; rebuild scanner material and trigger <code>{scannerReadiness.reassessment_trigger || 'scanner_data_stale'}</code> reassessment for affected active admissions.</div>}
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
              {scannerReadiness.adapters.filter((adapter) => adapter.enabled_by_default).map((adapter) => (
                <div key={adapter.name} className="rounded border border-gray-800 bg-gray-950 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs text-gray-200">{adapter.name}</span>
                    <span className={`rounded px-1.5 py-0.5 text-[10px] font-semibold ${adapter.ready ? 'bg-green-950/60 text-green-300' : 'bg-red-950/60 text-red-300'}`}>
                      {adapter.status}
                    </span>
                  </div>
                  <div className="mt-2 text-xs text-gray-500">{adapter.applicability.replace(/_/g, ' ')}</div>
                  <div className="mt-1 truncate font-mono text-[10px] text-gray-600">
                    {adapter.version || (adapter.installed ? 'installed · version unavailable' : 'not installed')}
                  </div>
                  {adapter.rules && <div className={`mt-2 text-[10px] ${adapter.rules.fresh ? 'text-green-400' : 'text-red-400'}`}>rules {adapter.rules.status?.toLowerCase()} · {adapter.rules.age_days ?? '?'}d / {adapter.rules.max_age_days ?? '?'}d</div>}
                  {adapter.database && <div className={`mt-1 text-[10px] ${adapter.database.fresh ? 'text-green-400' : 'text-red-400'}`}>database {adapter.database.status?.toLowerCase()} · {adapter.database.age_days ?? '?'}d / {adapter.database.max_age_days ?? '?'}d</div>}
                </div>
              ))}
            </div>
            </div>
          ) : (
            <div className="mt-3 text-xs text-gray-500">Checking adapter readiness…</div>
          )}
        </Card>
        </>
      )}
      </>
      )}
    </div>
  )
}
