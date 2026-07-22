export type ModelIntakeTrustMode =
  | 'checksum_only'
  | 'signature_url_key_url'
  | 'inline_signature_key'
  | 'trusted_key_fingerprint'
  | 'metadata_evidence'

export type ModelIntakeTrustPreviewStatus = 'pass' | 'fail' | 'advisory'

export interface ModelIntakeTrustPreviewItem {
  id: string
  label: string
  status: ModelIntakeTrustPreviewStatus
  detail: string
}

export interface ModelIntakeTrustPreviewInput {
  mode: ModelIntakeTrustMode
  policyProfile?: string
  requireHash: boolean
  requireSignature: boolean
  requireSignatureVerification: boolean
  requireDeploymentApproval: boolean
  requireModelGovernance: boolean
  deploymentApproved: boolean
  expectedSha256?: string
  signatureUrl?: string
  signaturePublicKeyUrl?: string
  signaturePublicKey?: string
  signatureValue?: string
  signatureTrustedKeys?: string
  signatureTrustedKeySha256?: string
  metadata?: Record<string, unknown>
  modelCardUrl?: string
}

export interface ModelIntakeTrustPreview {
  items: ModelIntakeTrustPreviewItem[]
  blockingFailures: ModelIntakeTrustPreviewItem[]
  headlineStatus: ModelIntakeTrustPreviewStatus
  headline: string
}

function hasText(value: unknown): boolean {
  return typeof value === 'string' && value.trim().length > 0
}

function hasMetadataEvidence(metadata: Record<string, unknown> | undefined, keys: string[]): boolean {
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

function item(
  id: string,
  label: string,
  status: ModelIntakeTrustPreviewStatus,
  detail: string
): ModelIntakeTrustPreviewItem {
  return { id, label, status, detail }
}

export function inferModelIntakeTrustMode(input: Partial<ModelIntakeTrustPreviewInput>): ModelIntakeTrustMode {
  if (hasText(input.signatureTrustedKeys) || hasText(input.signatureTrustedKeySha256)) return 'trusted_key_fingerprint'
  if (hasText(input.signatureValue) && hasText(input.signaturePublicKey)) return 'inline_signature_key'
  if (hasText(input.signatureUrl) && hasText(input.signaturePublicKeyUrl)) return 'signature_url_key_url'
  if (hasMetadataEvidence(input.metadata, ['signature_url', 'signature_public_key', 'signature_value', 'sigstore_verified', 'signature_verified'])) {
    return 'metadata_evidence'
  }
  return 'checksum_only'
}

export function buildModelIntakeTrustPreview(input: ModelIntakeTrustPreviewInput): ModelIntakeTrustPreview {
  const strictVerification = input.requireSignatureVerification || input.policyProfile === 'strict'
  const hasChecksum = hasText(input.expectedSha256) || hasMetadataEvidence(input.metadata, ['sha256', 'checksum', 'artifact_sha256'])
  const hasUrlSignature = hasText(input.signatureUrl)
  const hasUrlKey = hasText(input.signaturePublicKeyUrl)
  const hasInlineSignature = hasText(input.signatureValue)
  const hasInlineKey = hasText(input.signaturePublicKey)
  const hasOperatorSignature = hasUrlSignature || hasInlineSignature
  const hasOperatorKey = hasUrlKey || hasInlineKey
  const hasTrustAnchor = hasText(input.signatureTrustedKeys) || hasText(input.signatureTrustedKeySha256)
  const hasMetadataSignature = hasMetadataEvidence(input.metadata, [
    'signature_url',
    'signature_public_key',
    'signature_value',
    'signature_verified',
    'sigstore_verified',
    'provenance',
    'attestation_url',
  ])
  const hasGovernance = hasText(input.modelCardUrl) || hasMetadataEvidence(input.metadata, [
    'model_card_url',
    'license',
    'sbom',
    'malware_scan_result',
    'security_evals',
    'deployment_restrictions',
    'monitoring_plan',
  ])

  const items: ModelIntakeTrustPreviewItem[] = []

  items.push(
    item(
      'checksum',
      'Checksum evidence',
      hasChecksum ? 'pass' : input.requireHash ? 'fail' : 'advisory',
      hasChecksum
        ? 'A digest pin or registry checksum is present.'
        : input.requireHash
          ? 'This policy requires a checksum or registry digest before queueing.'
          : 'No checksum is present; integrity will be advisory only.'
    )
  )

  if (input.mode === 'checksum_only') {
    items.push(
      item(
        'signature',
        'Signature evidence',
        input.requireSignature ? 'fail' : 'advisory',
        input.requireSignature
          ? 'Checksum-only mode cannot satisfy a signature-required policy.'
          : 'No signature will be verified in this mode.'
      )
    )
  } else if (input.mode === 'signature_url_key_url') {
    items.push(
      item(
        'signature',
        'Signature URL + public key URL',
        hasUrlSignature && hasUrlKey ? 'pass' : 'fail',
        hasUrlSignature && hasUrlKey
          ? 'Detached signature and public key URLs are operator supplied.'
          : 'Provide both a detached signature URL and public key URL.'
      )
    )
  } else if (input.mode === 'inline_signature_key') {
    items.push(
      item(
        'signature',
        'Inline signature + public key',
        hasInlineSignature && hasInlineKey ? 'pass' : 'fail',
        hasInlineSignature && hasInlineKey
          ? 'Inline detached signature and public key material are present.'
          : 'Paste both the detached signature value and public key PEM.'
      )
    )
  } else if (input.mode === 'trusted_key_fingerprint') {
    items.push(
      item(
        'signature',
        'Operator signature material',
        hasOperatorSignature && hasOperatorKey ? 'pass' : 'fail',
        hasOperatorSignature && hasOperatorKey
          ? 'Signature material and verifier key are present.'
          : 'Provide signature material plus a public key URL or PEM.'
      )
    )
  } else {
    items.push(
      item(
        'signature',
        'Metadata-supplied evidence',
        hasMetadataSignature ? 'advisory' : input.requireSignature ? 'fail' : 'advisory',
        hasMetadataSignature
          ? 'Metadata can document a publisher claim, but it is not an operator trust root.'
          : input.requireSignature
            ? 'No metadata signature claim is present.'
            : 'Metadata evidence is optional for this policy.'
      )
    )
  }

  items.push(
    item(
      'trusted-root',
      'Operator trust root',
      hasOperatorSignature && hasOperatorKey && hasTrustAnchor ? 'pass' : strictVerification ? 'fail' : 'advisory',
      hasOperatorSignature && hasOperatorKey && hasTrustAnchor
        ? 'A valid signature can be checked against operator-supplied trust material.'
        : strictVerification
          ? 'Verified provenance requires signature material, verifier key, and a trusted key PEM or SHA-256 fingerprint.'
          : 'Without an operator trust anchor, a valid signature remains claimed or untrusted rather than verified.'
    )
  )

  items.push(
    item(
      'governance',
      'Governance evidence',
      hasGovernance ? 'pass' : input.requireModelGovernance ? 'fail' : 'advisory',
      hasGovernance
        ? 'Model card or governance metadata is present.'
        : input.requireModelGovernance
          ? 'This policy requires governance evidence such as model card, license, SBOM, evals, or monitoring plan.'
          : 'Governance evidence is optional for this policy.'
    )
  )

  items.push(
    item(
      'approval',
      'Deployment approval',
      input.deploymentApproved ? 'pass' : input.requireDeploymentApproval ? 'fail' : 'advisory',
      input.deploymentApproved
        ? 'The request is marked as approved for deployment.'
        : input.requireDeploymentApproval
          ? 'This policy requires explicit deployment approval.'
          : 'Deployment approval is not required for this policy.'
    )
  )

  const blockingFailures = items.filter((previewItem) => previewItem.status === 'fail')
  const advisoryOnly = !blockingFailures.length && items.some((previewItem) => previewItem.status === 'advisory')
  const headlineStatus: ModelIntakeTrustPreviewStatus = blockingFailures.length ? 'fail' : advisoryOnly ? 'advisory' : 'pass'
  const headline = blockingFailures.length
    ? `${blockingFailures.length} required trust check${blockingFailures.length === 1 ? '' : 's'} will fail`
    : advisoryOnly
      ? 'Trust check can run, but some evidence remains advisory'
      : 'Trust requirements look ready to submit'

  return { items, blockingFailures, headlineStatus, headline }
}
