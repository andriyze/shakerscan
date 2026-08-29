import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const scan = fs.readFileSync(path.join(root, 'src/app/scan/new/page.tsx'), 'utf8')
const credentials = fs.readFileSync(path.join(root, 'src/app/credentials/page.tsx'), 'utf8')
const api = fs.readFileSync(path.join(root, 'src/lib/api.ts'), 'utf8')
const scanContract = fs.readFileSync(path.join(root, 'src/lib/scanContract.generated.ts'), 'utf8')
const publicApiContract = fs.readFileSync(path.join(root, 'src/lib/publicApi.generated.ts'), 'utf8')

test('canonical Scan UI submits only opaque exact-target credential profile IDs', () => {
  assert.match(scan, /listCredentialProfiles/)
  assert.match(scan, /credential_profile_ids: selectedCredentialIds/)
  assert.match(scan, /Only opaque IDs enter the Scan request and queue/)
  assert.match(api, /ScanStartRequest/)
  assert.match(scanContract, /SubmitScanScansPostRequest as ScanStartRequest/)
  assert.match(publicApiContract, /credential_profile_ids\?: Array<string>/)
  assert.doesNotMatch(scan, /authHeader|authCookies|user2Header|user2Cookies/)
  assert.doesNotMatch(scan, /Bearer …|session=…/)
})

test('Scan credential selection is disabled for batches and requires explicit authority', () => {
  assert.match(scan, /Credential profiles are exact-target-bound and cannot be shared across a batch/)
  assert.match(scan, /riskTier: credentialUse \? 'credential' : 'active'/)
  assert.match(scan, /effectiveApprovalReceipt = createdApproval\.approvalReceiptId/)
  assert.match(scan, /selected permissions and identities/)
})

test('new generic profiles use canonical least-privilege capability selections', () => {
  assert.match(credentials, /listCredentialCapabilities/)
  assert.match(credentials, /safe_defaults/)
  assert.match(credentials, /No selection resolves to the server&apos;s safe defaults, never unrestricted access/)
  assert.match(credentials, /no capabilities · legacy profile is unusable until narrowed explicitly/)
  assert.match(credentials, /allow_active_capabilities: draft\.allowActiveCapabilities/)
  assert.doesNotMatch(credentials, /blank permits any worker capability/)
  assert.doesNotMatch(credentials, /scan\.execute/)
  assert.match(credentials, /Client ID \(required for Scan\)/)
})
