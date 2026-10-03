import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import test from 'node:test'

const root = path.resolve(import.meta.dirname, '..')
const page = fs.readFileSync(path.join(root, 'src/app/hunt/page.tsx'), 'utf8')
const runView = ['HuntRunView', 'HuntResults', 'HuntTimeline', 'HuntDetails', 'huntFormat'].map((name) => {
  const file = name === 'huntFormat' ? `${name}.ts` : `${name}.tsx`
  return fs.readFileSync(path.join(root, 'src/components/hunt', file), 'utf8')
}).join('\n')
const api = fs.readFileSync(path.join(root, 'src/lib/api.ts'), 'utf8')
const huntClient = fs.readFileSync(path.join(root, 'src/lib/huntV2.ts'), 'utf8')

test('unified Hunt binds generic principal profiles without treating SSH proposal as execution', () => {
  assert.match(page, /listCredentialProfiles/)
  assert.match(page, /primary_credential_profile_id:/)
  assert.match(page, /secondary_credential_profile_id:/)
  assert.match(page, /service_credential_profile_id:/)
  assert.match(page, /ssh_credential_profile_id:/)
  assert.match(page, /ssh: 'SSH identity'/)
  assert.match(page, /Remote SSH commands use the target&apos;s saved SSH permission/)
  assert.match(api, /ssh_credential_profile_id\?: string/)
})

test('unified Hunt renders and explicitly confirms immutable SSH command plans', () => {
  assert.match(runView, /SSH command plans/)
  assert.match(runView, /Confirm and queue these exact remote commands/)
  assert.match(runView, /expected_host_key_fingerprint/)
  assert.match(runView, /plan_digest/)
  // A proposed plan is a decision the operator makes at the top of the run, not in a details tab.
  assert.match(runView, /kind === 'ssh_plan'/)
  assert.match(huntClient, /hunts\/\$\{encodeURIComponent\(huntId\)\}\/shell-plans/)
  assert.match(huntClient, /confirm_exact_commands: true/)
  assert.match(huntClient, /confirm_remote_device_effects: true/)
  assert.doesNotMatch(api, /export async function confirmHuntShellPlan/)
})

test('active unified Hunts refresh so external planner proposals appear', () => {
  assert.match(runView, /getHuntV2\(hunt\.hunt_id\)/)
  assert.match(runView, /window\.setInterval\(refresh, 5000\)/)
})
