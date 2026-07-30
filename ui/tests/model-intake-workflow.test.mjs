import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const api = readFileSync(path.join(root, 'src/lib/api.ts'), 'utf8')
const workflow = readFileSync(path.join(root, 'src/app/model-intake/ControlledWorkflow.tsx'), 'utf8')
const page = readFileSync(path.join(root, 'src/app/model-intake/page.tsx'), 'utf8')

test('scanner readiness surfaces enforceable material freshness and reassessment', () => {
  assert.match(page, /scanner rules or vulnerability data are stale/)
  assert.match(page, /scanner_data_stale/)
  assert.match(page, /database\.status/)
  assert.match(api, /reassessment_required/)
})

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
    '/report',
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
  assert.match(workflow, /Converted target identity/)
  assert.match(workflow, /conversion_rescan/)
  assert.match(workflow, /Runtime bundle seeded/)
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

test('normalized corporate report has UI and export parity', () => {
  assert.match(workflow, /Normalized corporate review report/)
  assert.match(workflow, /Executive summary/)
  assert.match(workflow, /Full corporate approval: not determined by ShakerScan/)
  assert.match(workflow, /Checks performed/)
  assert.match(workflow, /Supported checks not completed/)
  assert.match(workflow, /Corporate approval requirements outside ShakerScan/)
  assert.match(workflow, /Detailed control evidence/)
  assert.match(workflow, /PASS, FAIL, REVIEW, INCOMPLETE, ERROR, NOT_RUN, or NOT_APPLICABLE/)
  assert.match(workflow, /Printable HTML \/ PDF/)
  assert.match(api, /format: 'json' \| 'html' \| 'sarif'/)
  assert.match(api, /ModelIntakeCorporateReport/)
})
