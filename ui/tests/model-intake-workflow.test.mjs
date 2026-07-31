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
  assert.match(workflow, /Operator credential/)
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

test('the model reference and deployment target are chosen once and reused downstream', () => {
  // The controlled workflow used to carry its own source, source-kind,
  // environment, and expected-digest inputs, so the same facts were entered two
  // or three times and could disagree. They are props now.
  assert.match(workflow, /source: string/)
  assert.match(workflow, /sourceKind: ModelIntakePlatform/)
  assert.match(workflow, /environment: ModelIntakeWorkflowSubmission\['requested_environment'\]/)
  assert.match(workflow, /expectedArtifactSha256: string/)
  assert.match(workflow, /Intake context from step 1/)
  assert.doesNotMatch(workflow, /setSource\(/)
  assert.doesNotMatch(workflow, /setSourceKind\(/)
  assert.doesNotMatch(workflow, /setEnvironment\(/)
  assert.doesNotMatch(workflow, /setExpectedSha\(/)

  // The single environment selector lives in step 1 and drives the bundle.
  assert.match(page, /const ENVIRONMENT_OPTIONS/)
  assert.match(page, /Deployment target/)
  assert.match(page, /environment=\{environment\}/)
  assert.match(workflow, /target_environment: environment/)
})

test('page stages are numbered in the order they are rendered', () => {
  const order = ['1. Model &amp; Target', '2. Policy Profile', '3. Preflight Evidence Scan', '<ControlledModelIntakeWorkflow']
  let cursor = -1
  for (const marker of order) {
    const index = page.indexOf(marker)
    assert.notStrictEqual(index, -1, `${marker} is missing from the Model Intake page`)
    assert.ok(index > cursor, `${marker} is rendered out of numbered order`)
    cursor = index
  }
  assert.match(workflow, /4\. Controlled Corporate Admission Workflow/)
  for (const stage of ['4.1', '4.2', '4.3', '4.4', '4.5', '4.6']) {
    assert.ok(workflow.includes(`>${stage} `), `controlled stage ${stage} is missing`)
  }
})

test('a local deployment resolves its own operator credential instead of asking for it', () => {
  assert.match(api, /getModelIntakeOperatorCredential/)
  assert.match(api, /\/api\/model-intake\/operator-credential/)
  assert.match(page, /loadOperatorCredential/)
  assert.match(page, /getModelIntakeOperatorCredential\(\)/)
  // The manual field remains for deployments the UI server will not autofill.
  assert.match(workflow, /operatorCredentialAutofilled/)
  assert.match(workflow, /onOperatorTokenChange\(event\.target\.value\)/)

  const route = readFileSync(path.join(root, 'src/app/api/model-intake/operator-credential/route.ts'), 'utf8')
  assert.match(route, /deploymentIsLoopbackBound/)
  assert.match(route, /requestIsLoopback/)
  assert.match(route, /SHAKERSCAN_UI_OPERATOR_AUTOFILL/)
  assert.match(route, /remote_deployment/)
})

test('artifact acquisition is presented in model-sized units, not a 100MB prefix', () => {
  assert.match(page, /ARTIFACT_LIMIT_PRESETS/)
  assert.match(page, /Artifact acquisition limit/)
  for (const label of ['100 MB', '1 GB', '5 GB', '20 GB', '100 GB']) {
    assert.ok(page.includes(`'${label}'`), `${label} preset is missing`)
  }
  // Resolving a large model must raise the limit to cover it.
  assert.match(page, /artifactLimitForSize/)
  assert.match(page, /artifactLimitCoversArtifact/)
  // A policy profile must never shrink a deliberately larger limit.
  assert.match(page, /raiseArtifactLimitFloor/)
  assert.doesNotMatch(page, /setMaxDownloadBytes\('10000000'\)/)
  assert.doesNotMatch(page, /setMaxDownloadBytes\('50000000'\)/)
})

const shell = readFileSync(path.join(root, 'src/app/model-intake/IntakeShell.tsx'), 'utf8')

test('model intake renders as one phased pipeline instead of eight stacked panels', () => {
  assert.match(shell, /INTAKE_PHASES/)
  for (const label of ['Source', 'Preflight', 'Admission', 'Status']) {
    assert.ok(shell.includes(`label: '${label}'`), `${label} phase is missing`)
  }
  // Exactly one phase is rendered at a time, and the shared context stays pinned.
  for (const phase of ['source', 'preflight', 'admission', 'status']) {
    assert.ok(page.includes(`phase === '${phase}' &&`), `${phase} phase is not gated`)
  }
  assert.match(page, /<IntakeContextBar/)
  assert.match(page, /<IntakePhaseTabs/)
  assert.match(shell, /operatorReady/)
  assert.match(shell, /adaptersReady/)
  assert.match(shell, /runnerStatus/)
})

test('queueing a preflight scan hands off to admission instead of navigating away', () => {
  // The old flow pushed the operator to /scans/{id}, so the only way back into
  // the admission stage was pasting that UUID into a free-text field.
  assert.doesNotMatch(page, /router\.push\(`\/scans\//)
  assert.match(page, /trackQueuedScan\(result\.scan_id\)/)
  assert.match(page, /useScanInAdmission/)
  assert.match(page, /setPhase\('admission'\)/)
  assert.match(page, /<PreflightScanTracker/)
  assert.match(shell, /Use in admission/)

  // The handoff lights up on its own while the scan is still running.
  assert.match(page, /awaitingScanCompletion/)
  assert.match(page, /setInterval\(loadIntakeScans/)
  assert.match(api, /listRecentModelIntakeScans/)
})

test('binding generated evidence is a picker over completed scans', () => {
  assert.match(workflow, /attachableScans/)
  assert.match(workflow, /scan\.status === 'completed'/)
  assert.match(workflow, /Select a completed preflight scan/)
  // A scan from another session can still be bound by ID.
  assert.match(workflow, /Bind a scan from another session by ID/)
  assert.match(workflow, /availableScans: ModelIntakeScanSummary\[\]/)
})

test('cross-phase navigation targets the phase that renders the control', () => {
  // Both of these used to be anchors into markup that a hidden phase no longer
  // renders, so they would silently do nothing.
  assert.match(workflow, /onEditContext: \(\) => void/)
  assert.doesNotMatch(workflow, /href="#model-intake-source"/)
  assert.match(page, /setPhase\('source'\)/)
  assert.match(page, /setPhase\('preflight'\)\n    setPolicyProfile\('strict'\)/)
})

test('operator credential autofill inspects forwarded hops rather than their presence', () => {
  const route = readFileSync(path.join(root, 'src/app/api/model-intake/operator-credential/route.ts'), 'utf8')
  // Next populates x-forwarded-for on every request, so treating the header's
  // presence as proof of a proxy silently disabled autofill everywhere.
  assert.match(route, /forwarded\.split\(','\)\.every/)
  assert.match(route, /::ffff:/)
  // An IPv6 host is "[::1]:3000"; splitting on ':' would mangle it.
  assert.match(route, /replace\(\/:\\d\+\$\/, ''\)/)
})

test('an unavailable microVM tier reads as unavailable, not broken', () => {
  // Firecracker cannot run on a macOS or Windows host at all. Showing a yellow
  // NOT_READY warning there implies a repairable fault and trains the operator
  // to ignore the readiness chips.
  assert.match(shell, /runnerUnsupported/)
  assert.match(shell, /n\/a on \$\{runnerHostPlatform/)
  assert.match(shell, /runnerUnsupported\n\s*\? 'idle'/)
  assert.match(workflow, /supported_host === false/)
  assert.match(workflow, /not available on \$\{runnerReadiness\?\.host_platform/)
  assert.match(workflow, /Every other Model Intake check/)
  assert.match(api, /supported_host\?: boolean/)
})
