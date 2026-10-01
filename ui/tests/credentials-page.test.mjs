import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const page = fs.readFileSync(path.join(root, 'src/app/credentials/page.tsx'), 'utf8')
const api = fs.readFileSync(path.join(root, 'src/lib/api.ts'), 'utf8')
const credentialApi = fs.readFileSync(path.join(root, 'src/lib/credentialApi.ts'), 'utf8')
const sidebar = fs.readFileSync(path.join(root, 'src/components/Sidebar.tsx'), 'utf8')

test('shared Credentials UI binds profiles to an exact supported target kind', () => {
  assert.match(sidebar, /href: '\/credentials'/)
  // A credential belongs to one target; sharing it is an explicit operator choice.
  assert.match(page, /Each belongs to one target and can be shared with others/)
  for (const kind of ['web', 'api', 'network', 'device']) {
    assert.match(page, new RegExp(`<option value="${kind}">`))
  }
  assert.match(credentialApi, /target_kind: params\.target_kind/)
  assert.match(credentialApi, /target_id: params\.target_id/)
})

test('changing credential target kind cannot query with the previous kind target ID', () => {
  const changeKind = page.match(/function changeTargetKind[\s\S]*?\n  }/)?.[0] || ''
  // Kind and target change in one URL update, so no render pairs the new kind with the old ID.
  assert.match(changeKind, /setFilters\(\{ target_kind: kind === 'web' \? undefined : kind, target_id: undefined/)
  assert.match(changeKind, /setProfiles\(\[\]\)/)
  assert.match(page, /onChange=\{\(event\) => changeTargetKind\(event\.target\.value as CredentialTargetKind\)\}/)
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
  assert.match(credentialApi, /fetch\(`\$\{API_URL\}\/credential-profiles`/)
  assert.match(credentialApi, /credential-profiles\/\$\{encodeURIComponent\(profileId\)\}\/rotate/)
  assert.match(credentialApi, /method: 'DELETE'/)
  assert.doesNotMatch(api, /export async function listCredentialProfiles/)
})

test('credential responses and presentation stay metadata-only', () => {
  assert.match(credentialApi, /secret_values_visible: false/)
  assert.match(credentialApi, /storage_encrypted: true/)
  assert.match(page, /secret values hidden/)
  assert.match(page, /never shown again/)
  assert.doesNotMatch(page, /profile\.(secret|encrypted_secret|encrypted_metadata)/)
})

test('a credential is shared with other targets explicitly, and a shared copy is managed by its owner', () => {
  const dialog = fs.readFileSync(path.join(root, 'src/components/credentials/ShareCredentialDialog.tsx'), 'utf8')
  const client = fs.readFileSync(path.join(root, 'src/lib/credentialApi.ts'), 'utf8')
  // The library lists every credential when no target is selected.
  assert.match(page, /: await listCredentialLibrary\(\{ include_inactive: includeInactive, limit: 500 \}\)/)
  // A copy shared to this target says where it is from and can only stop being shared here.
  assert.match(page, /shared from \{profile\.home_target_name \|\| 'another target'\}/)
  assert.match(page, /\{profile\.shared \? \(/)
  assert.match(page, /Stop sharing here/)
  // The dialog shares within one asset kind, and active capabilities need the receiving
  // target's own approval, asked for explicitly.
  assert.match(dialog, /sharesAsset\(profile\.target_kind, target\.kind\)/)
  assert.match(dialog, /riskTier: 'credential'/)
  assert.match(dialog, /disabled=\{!chosen \|\| busy \|\| \(needsApproval && !approveActive\)\}/)
  assert.match(dialog, /Each still needs\s+its own authorization/)
  assert.match(client, /\/credential-profiles\/\$\{encodeURIComponent\(profileId\)\}\/grants/)
})
