import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const scan = fs.readFileSync(path.join(root, 'src/app/scan/new/page.tsx'), 'utf8')
const credentials = fs.readFileSync(path.join(root, 'src/app/credentials/page.tsx'), 'utf8')
const api = fs.readFileSync(path.join(root, 'src/lib/api.ts'), 'utf8')

test('canonical Scan UI submits only opaque exact-target credential profile IDs', () => {
  assert.match(scan, /listCredentialProfiles/)
  assert.match(scan, /credential_profile_ids: selectedCredentialIds/)
  assert.match(scan, /Only opaque IDs enter the Scan request and queue/)
  assert.match(api, /credential_profile_ids\?: string\[\]/)
  assert.doesNotMatch(scan, /authHeader|authCookies|user2Header|user2Cookies/)
  assert.doesNotMatch(scan, /Bearer …|session=…/)
})

test('Scan credential selection is disabled for batches and requires explicit authority', () => {
  assert.match(scan, /Credential profiles are exact-target-bound and cannot be shared across a batch/)
  assert.match(scan, /Credential use requires a target-bound approval receipt ID/)
  assert.match(scan, /selected permissions and identities/)
})

test('new generic profiles allow both replay and deterministic Scan by default', () => {
  assert.match(credentials, /request\.replay, scan\.execute/)
  assert.match(credentials, /Client ID \(required for Scan\)/)
})
