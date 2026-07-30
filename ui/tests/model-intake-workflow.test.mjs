import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const api = readFileSync(path.join(root, 'src/lib/api.ts'), 'utf8')
const workflow = readFileSync(path.join(root, 'src/app/model-intake/ControlledWorkflow.tsx'), 'utf8')
const page = readFileSync(path.join(root, 'src/app/model-intake/page.tsx'), 'utf8')

test('controlled Model Intake UI exposes every authoritative workflow stage', () => {
  for (const fragment of [
    '/model-intake/submissions',
    '/static-runs',
    '/runner-jobs',
    '/agent/session',
    '/agent/sessions',
    '/cancel',
    '/freeze-evidence',
    '/approvals',
    '/policy-decisions',
    '/promote',
  ]) {
    assert.match(api, new RegExp(fragment.replaceAll('/', '\\/')))
  }
  assert.match(page, /ControlledModelIntakeWorkflow/)
})

test('runner evidence is rendered as phases, network telemetry, and resource telemetry', () => {
  assert.match(workflow, /Phase timeline/)
  assert.match(workflow, /Independent network telemetry/)
  assert.match(workflow, /Host resource envelope/)
  assert.match(workflow, /attempted_operations/)
  assert.match(workflow, /lost_events/)
  assert.match(workflow, /telemetry_sha256/)
})

test('Codex workflow is prominently advisory and promotion remains a separate operator action', () => {
  assert.match(workflow, /Codex-guided investigation \(advisory only\)/)
  assert.match(workflow, /cannot execute arbitrary commands, approve, change policy, freeze evidence, promote/)
  assert.match(workflow, /Invoke isolated signer and promote/)
  assert.match(workflow, /Production requires distinct server-configured identities/)
  assert.match(workflow, /Operator credential for controlled workflow/)
  assert.match(workflow, /Durable advisory sessions/)
  assert.match(workflow, /cancelModelIntakeAgentSession/)
})
