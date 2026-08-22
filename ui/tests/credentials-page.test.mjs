import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const page = fs.readFileSync(path.join(root, 'src/app/credentials/page.tsx'), 'utf8')
const api = fs.readFileSync(path.join(root, 'src/lib/api.ts'), 'utf8')
const sidebar = fs.readFileSync(path.join(root, 'src/components/Sidebar.tsx'), 'utf8')

test('shared Credentials UI binds profiles to an exact supported target kind', () => {
  assert.match(sidebar, /href: '\/credentials'/)
  assert.match(page, /Manage encrypted, target-bound identities used by Scan and Hunt/)
  for (const kind of ['web', 'api', 'network', 'device']) {
    assert.match(page, new RegExp(`<option value="${kind}">`))
  }
  assert.match(api, /target_kind: params\.target_kind/)
  assert.match(api, /target_id: params\.target_id/)
})

test('shared Credentials UI supports every canonical credential kind and lifecycle action', () => {
  for (const kind of [
    'authorization_header',
    'bearer_token',
    'api_key_header',
    'cookie',
    'basic_auth',
    'form_login',
    'oauth_client_credentials',
    'oauth_password',
    'custom_headers',
    'ssh_password',
    'ssh_private_key',
    'ssh_private_key_with_passphrase',
  ]) {
    assert.match(page, new RegExp(`value: '${kind}'`))
  }
  assert.match(api, /fetch\(`\$\{API_URL\}\/credential-profiles`/)
  assert.match(api, /credential-profiles\/\$\{encodeURIComponent\(profileId\)\}\/rotate/)
  assert.match(api, /method: 'DELETE'/)
})

test('credential responses and presentation stay metadata-only', () => {
  assert.match(api, /secret_values_visible: false/)
  assert.match(api, /storage_encrypted: true/)
  assert.match(page, /secret values hidden/)
  assert.match(page, /never returned to this screen/)
  assert.doesNotMatch(page, /profile\.(secret|encrypted_secret|encrypted_metadata)/)
})
