import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'
import test from 'node:test'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const uiRoot = path.resolve(__dirname, '..')
const outDir = mkdtempSync(path.join(tmpdir(), 'model-intake-trust-'))

execFileSync(
  'npx',
  [
    'tsc',
    'src/lib/modelIntakeTrust.ts',
    '--module',
    'commonjs',
    '--target',
    'es2022',
    '--outDir',
    outDir,
    '--skipLibCheck',
  ],
  { cwd: uiRoot, stdio: 'pipe' }
)

const require = createRequire(import.meta.url)
const {
  buildModelIntakeTrustPreview,
  inferModelIntakeTrustMode,
} = require(path.join(outDir, 'modelIntakeTrust.js'))

test.after(() => {
  rmSync(outDir, { recursive: true, force: true })
})

test('strict trusted-anchor mode has no blocking failures when operator trust material is present', () => {
  const preview = buildModelIntakeTrustPreview({
    mode: 'trusted_key_fingerprint',
    policyProfile: 'strict',
    requireHash: true,
    requireSignature: true,
    requireSignatureVerification: true,
    requireDeploymentApproval: true,
    requireModelGovernance: true,
    deploymentApproved: true,
    expectedSha256: 'a'.repeat(64),
    signatureUrl: 'https://models.example/model.sig',
    signaturePublicKeyUrl: 'https://models.example/key.pem',
    signatureTrustedKeySha256: 'b'.repeat(64),
    metadata: { license: 'apache-2.0', sbom: { components: [] } },
  })

  assert.equal(preview.headlineStatus, 'pass')
  assert.deepEqual(preview.blockingFailures, [])
  assert.equal(preview.items.find((item) => item.id === 'trusted-root')?.status, 'pass')
})

test('metadata-supplied signing evidence cannot satisfy strict trusted provenance', () => {
  const preview = buildModelIntakeTrustPreview({
    mode: 'metadata_evidence',
    policyProfile: 'strict',
    requireHash: true,
    requireSignature: true,
    requireSignatureVerification: true,
    requireDeploymentApproval: true,
    requireModelGovernance: true,
    deploymentApproved: true,
    expectedSha256: 'a'.repeat(64),
    metadata: {
      signature_url: 'https://publisher.example/model.sig',
      signature_public_key: 'self-supplied',
      license: 'apache-2.0',
    },
  })

  assert.equal(preview.headlineStatus, 'fail')
  assert.equal(preview.items.find((item) => item.id === 'signature')?.status, 'advisory')
  assert.equal(preview.items.find((item) => item.id === 'trusted-root')?.status, 'fail')
})

test('checksum-only mode is advisory when policy does not require signature verification', () => {
  const preview = buildModelIntakeTrustPreview({
    mode: 'checksum_only',
    policyProfile: 'research',
    requireHash: false,
    requireSignature: false,
    requireSignatureVerification: false,
    requireDeploymentApproval: false,
    requireModelGovernance: false,
    deploymentApproved: false,
    expectedSha256: 'a'.repeat(64),
    metadata: {},
  })

  assert.equal(preview.headlineStatus, 'advisory')
  assert.deepEqual(preview.blockingFailures, [])
})

test('trust mode inference prefers operator trust anchors over metadata claims', () => {
  assert.equal(
    inferModelIntakeTrustMode({
      signatureUrl: 'https://models.example/model.sig',
      signaturePublicKeyUrl: 'https://models.example/key.pem',
      signatureTrustedKeySha256: 'b'.repeat(64),
      metadata: { signature_url: 'https://publisher.example/model.sig' },
    }),
    'trusted_key_fingerprint'
  )
})
