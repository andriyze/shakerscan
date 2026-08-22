import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const page = fs.readFileSync(path.join(root, 'src/app/hunt/page.tsx'), 'utf8')
const api = fs.readFileSync(path.join(root, 'src/lib/api.ts'), 'utf8')

test('unified Hunt binds generic principal profiles without treating SSH proposal as execution', () => {
  assert.match(page, /listCredentialProfiles/)
  assert.match(page, /primary_credential_profile_id:/)
  assert.match(page, /secondary_credential_profile_id:/)
  assert.match(page, /service_credential_profile_id:/)
  assert.match(page, /ssh_credential_profile_id:/)
  assert.match(page, /ssh: 'SSH identity'/)
  assert.match(page, /No SSH command runs until you separately confirm/)
  assert.match(api, /ssh_credential_profile_id\?: string/)
})

test('unified Hunt renders and explicitly confirms immutable SSH command plans', () => {
  assert.match(page, /SSH command plans/)
  assert.match(page, /Confirm and queue these exact remote commands/)
  assert.match(page, /expected_host_key_fingerprint/)
  assert.match(page, /plan_digest/)
  assert.match(api, /hunts\/\$\{encodeURIComponent\(huntId\)\}\/shell-plans/)
  assert.match(api, /confirm_exact_commands: true/)
  assert.match(api, /confirm_remote_device_effects: true/)
})

test('active unified Hunts refresh so external planner proposals appear', () => {
  assert.match(page, /getHuntV2\(hunt\.hunt_id\)/)
  assert.match(page, /window\.setInterval\(refresh, 5000\)/)
})
