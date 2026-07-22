import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'
import test from 'node:test'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const out = mkdtempSync(path.join(tmpdir(), 'principal-profile-'))
execFileSync('npx', ['tsc', 'src/lib/principalProfile.ts', '--module', 'commonjs', '--target', 'es2022', '--outDir', out, '--skipLibCheck'], { cwd: root })
const require = createRequire(import.meta.url)
const { buildPrincipalProfilePayload } = require(path.join(out, 'principalProfile.js'))
test.after(() => rmSync(out, { recursive: true, force: true }))

test('omits empty optional fields when creating a principal', () => {
  assert.deepEqual(buildPrincipalProfilePayload('user1', {
    label: ' Customer ', role: '', tenantId: '', credentialProfile: '',
  }, false), {
    label: 'Customer', role: 'user', auth_state: 'user1',
  })
})

test('sends empty optional fields when updating so references can be cleared', () => {
  assert.deepEqual(buildPrincipalProfilePayload('user2', {
    label: 'Reviewer', role: 'viewer', tenantId: '', credentialProfile: '',
  }, true), {
    label: 'Reviewer', role: 'viewer', auth_state: 'user2', tenant_id: '', credential_profile: '',
  })
})
