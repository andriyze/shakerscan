import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const api = readFileSync(path.join(root, 'src/lib/api.ts'), 'utf8')
const workflow = readFileSync(path.join(root, 'src/app/model-intake/ControlledWorkflow.tsx'), 'utf8')
const page = readFileSync(path.join(root, 'src/app/model-intake/page.tsx'), 'utf8')
const scanDetail = readFileSync(path.join(root, 'src/app/scans/[id]/page.tsx'), 'utf8')

test('scanner readiness surfaces enforceable material freshness and reassessment', () => {
  assert.match(page, /scanner rules or vulnerability data are stale/)
  assert.match(page, /scanner_data_stale/)
  assert.match(page, /database\.status/)
  assert.match(api, /reassessment_required/)
})

test('adapter readiness never mislabels an installed scanner when its version is unavailable', () => {
  assert.match(page, /adapter\.installed \? 'installed · version unavailable' : 'not installed'/)
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

test('the browser credential status route never serializes an operator secret', () => {
  assert.match(api, /getModelIntakeOperatorCredential/)
  assert.match(api, /\/api\/model-intake\/operator-credential/)
  assert.match(page, /loadOperatorCredential/)
  assert.match(page, /getModelIntakeOperatorCredential\(\)/)
  // The manual field remains for deployments the UI server will not autofill.
  assert.match(workflow, /operatorCredentialAutofilled/)
  assert.match(workflow, /onOperatorTokenChange\(event\.target\.value\)/)

  const route = readFileSync(path.join(root, 'src/app/api/model-intake/operator-credential/route.ts'), 'utf8')
  assert.match(route, /manual_required/)
  assert.match(route, /Never serialize/)
  assert.doesNotMatch(route, /process\.env\.MODEL_INTAKE_OPERATOR_TOKEN/)
  assert.doesNotMatch(route, /headers\.get\('host'\)/)
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

test('operator credential delivery cannot be enabled by spoofed deployment headers', () => {
  const route = readFileSync(path.join(root, 'src/app/api/model-intake/operator-credential/route.ts'), 'utf8')
  assert.doesNotMatch(route, /headers\.get\('x-forwarded-for'\)/)
  assert.doesNotMatch(route, /headers\.get\('host'\)/)
  assert.doesNotMatch(route, /SHAKERSCAN_BIND_HOST/)
  assert.doesNotMatch(route, /MODEL_INTAKE_OPERATOR_TOKEN/)
})

test('credential messaging leads with impact and keeps ops detail behind a disclosure', () => {
  const route = readFileSync(path.join(root, 'src/app/api/model-intake/operator-credential/route.ts'), 'utf8')
  // Someone pasting a Hugging Face URL to run a preflight scan should never be
  // told to go paste an environment variable: the scan needs no credential.
  assert.match(route, /hint/)
  assert.match(route, /Corporate admission actions require an operator credential/)
  assert.match(route, /approved secret channel/)
  assert.match(workflow, /Where do I get one\?/)
  assert.match(workflow, /Everything before it/)
  // The context chip is neutral, not a warning, because preflight is unaffected.
  assert.match(shell, /needed for admission/)
  assert.doesNotMatch(shell, /operatorReady \? 'ok' : 'warn'/)
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

test('pasting a model reference produces the complete evidence set by default', () => {
  // The scanners, repository snapshot, and sandbox used to be unchecked boxes
  // behind an Advanced disclosure, so the default report read INDETERMINATE on
  // exactly the controls that matter most.
  assert.match(page, /const DEFAULT_INTAKE_DEPTH: IntakeDepth = 'full'/)
  assert.match(page, /useState\(true\)\n?\s*const \[maxRepositoryBytes/)
  for (const setter of [
    'const [completeRepositorySnapshot, setCompleteRepositorySnapshot] = useState(true)',
    'const [runGeneratedScanners, setRunGeneratedScanners] = useState(true)',
    'const [runDynamicSandbox, setRunDynamicSandbox] = useState(true)',
  ]) {
    assert.ok(page.includes(setter), `${setter} is missing`)
  }
  // A preset that omits depth must not silently downgrade the scan.
  assert.match(page, /payload\.run_generated_scanners \?\? true/)
  assert.match(page, /payload\.complete_repository_snapshot \?\? true/)
  assert.match(page, /payload\.run_dynamic_sandbox \?\? true/)
  // Depth is one visible choice, and the tile is derived so a hand-edited
  // toggle cannot leave a preset highlighted for evidence that will not exist.
  assert.match(page, /Scan depth/)
  assert.match(page, /const activeDepth =/)
  assert.match(page, /activeDepth === null/)
  assert.match(page, /never as clean/)
})

test('one pasted Hugging Face link queues the complete technical review', () => {
  assert.match(page, /Test a model end to end/)
  assert.match(page, /Run complete review/)
  assert.match(page, /runCompleteReview/)
  assert.match(page, /complete_artifact_download: true/)
  assert.match(page, /complete_repository_snapshot: true/)
  assert.match(page, /run_generated_scanners: true/)
  assert.match(page, /run_dynamic_sandbox: true/)
  assert.match(page, /Anything\s+unavailable is reported as not tested/)
})

test('model intake reports lead with outcomes and collapse technical bulk', () => {
  const report = readFileSync(path.join(root, 'src/components/ReportView.tsx'), 'utf8')
  assert.match(report, /Technical evidence coverage/)
  assert.match(report, /Checks not run \/ incomplete/)
  assert.match(report, /What to do next/)
  assert.match(report, /Detailed technical evidence, SBOM, hashes and phase logs/)
  assert.match(report, /Remediation tracking \(\{findings\.length\} raw finding/)
  assert.match(report, /Raw findings and remediation detail \(\{findings\.length\}\)/)
  assert.match(report, /open=\{!isModelIntakeScan\}/)
  assert.match(report, /Download SBOM/)
})

test('a Linux host with no CPU virtualization is named precisely, not "n/a on linux"', () => {
  // A c8i.large-style cloud guest is Linux, so the host-platform wording would
  // read as a bug. The wall there is the absent vmx/svm flag.
  assert.match(api, /unsupported_reason\?:/)
  assert.match(api, /no_hardware_virtualization/)
  assert.match(shell, /runnerUnsupportedReason === 'no_hardware_virtualization'/)
  assert.match(shell, /no kvm on this host/)
  assert.match(workflow, /unsupported_reason === 'no_hardware_virtualization'/)
  assert.match(workflow, /no KVM on this host/)
  // The page must actually pass the new signal through to the context bar.
  assert.match(page, /runnerUnsupportedReason=\{runnerReadiness\?\.unsupported_reason\}/)
})

test('the microVM tier is offered as an opt-in install, not executed by the API', () => {
  // Installing takes root on the host. The API runs in a container and must
  // not do that on the operator's behalf, so the button hands over an exact
  // command rather than pretending to run one.
  assert.match(api, /getModelIntakeRunnerInstallPlan/)
  assert.match(api, /ModelIntakeRunnerInstallPlan/)
  assert.match(shell, /Set up microVM runner/)
  assert.match(shell, /Receipt signer/)
  assert.match(shell, /navigator\.clipboard\.writeText\(command\)/)
  // An unsupported host gets the reason, never an install button it cannot use.
  assert.match(shell, /plan\.supported/)
  assert.match(shell, /Every other Model Intake check is unaffected/)
  // The Status phase renders it and can re-check after the operator runs it.
  assert.match(page, /<RunnerInstallCard/)
  assert.match(page, /onRecheck=\{loadRunnerReadiness\}/)
})

test('local PEM is the default runner signer and KMS remains opt-in', () => {
  assert.match(shell, /useState\('local-pem'\)/)
  assert.doesNotMatch(shell, /useState\(environment === 'production' \? 'kms:<key-id>'/)
})

test('the runner chip is the way to reach the runner setup', () => {
  // The setup lived only on the fourth tab, so the chip that reports the
  // problem was a dead end. It now opens the phase that renders the fix.
  assert.match(shell, /onOpenRunnerStatus\?: \(\) => void/)
  assert.match(shell, /onClick=\{onOpenRunnerStatus\}/)
  assert.match(shell, /if \(!onClick\) return <span/)
  assert.match(page, /onOpenRunnerStatus=\{\(\) => \{/)
  assert.match(page, /setPhase\('status'\)/)
})

test('the runner stage never ships a deployment bundle that cannot validate', () => {
  // blankBundle() seeded dimension 0 and the literal string "review-required",
  // so clicking through the provided template was guaranteed to be rejected by
  // the admission contract with a message that named no field.
  assert.doesNotMatch(workflow, /pooling: 'review-required'/)
  assert.doesNotMatch(workflow, /precision: 'review-required'/)

  // The gap is caught before the round trip, and each gap names its source.
  assert.match(workflow, /embeddingContractGaps/)
  assert.match(workflow, /hidden_size in config\.json/)
  assert.match(workflow, /max_position_embeddings in config\.json/)
  assert.match(workflow, /Declare the embedding configuration before queueing/)

  // Those four values get real fields instead of hiding in a JSON blob, and
  // the queue button stays disabled until they are declared.
  assert.match(workflow, /Embedding configuration/)
  assert.match(workflow, /updateEmbeddingField/)
  assert.match(workflow, /Raw deployment bundle JSON/)
  assert.match(workflow, /embeddingGaps\.length > 0/)
})

test('the deployment bundle arrives prefilled from the scanned revision', () => {
  // The operator used to face an all-zero template and had to look up
  // hidden_size, pooling mode, and dtype by hand — for facts the model
  // publishes and the scan already read.
  assert.match(workflow, /function embeddingHints/)
  assert.match(workflow, /embedding_configuration_hints/)
  assert.match(workflow, /storedObjectValue/)
  assert.match(workflow, /buildSeededBundle/)
  assert.match(workflow, /Seed authoritative runner bundle/)
  assert.match(workflow, /resolveModelIntakeRunnerProfile/)
  assert.match(workflow, /Corporate deployment bindings/)
  assert.match(workflow, /Retrieval application SHA-256/)
  assert.match(workflow, /Index schema SHA-256/)
  // Seeded on load, not only when the operator finds the seed button.
  assert.match(workflow, /seededSubmissions\.current\.has\(id\)/)
  // Seeded once, so a later refresh never discards operator edits.
  assert.match(workflow, /seededSubmissions\.current\.add\(id\)/)
  // Provenance is shown, because these values enter the signed bundle.
  assert.match(workflow, /Prefilled from the scanned revision/)
  assert.match(workflow, /hintSources/)
})

test('fields the operator should not have to invent are offered, not demanded', () => {
  assert.match(workflow, /suggestIdempotencyKey/)
  assert.match(workflow, /crypto\.randomUUID/)
  assert.match(workflow, /Replace the suggestion with your release ticket/)
  // Manifest and policy-decision IDs come back from the workflow itself.
  assert.match(workflow, /setManifestId\(latestManifest\.id\)/)
  assert.match(workflow, /setPolicyDecisionId\(latestDecision\.id\)/)
})

test('a disabled queue button always states what is blocking it', () => {
  // Four conditions gate this button and three of them used to be silent, so
  // it simply looked broken — including the one that says the host cannot run
  // a microVM at all.
  assert.match(workflow, /const queueBlockers/)
  assert.match(workflow, /No submission selected/)
  assert.match(workflow, /Create or pick one in stage 4\.1/)
  assert.match(workflow, /This host cannot run a microVM/)
  assert.match(workflow, /Runner prerequisites are incomplete/)
  assert.match(workflow, /Runner readiness is still being checked/)
  assert.match(workflow, /Undeclared \$\{summary\}/)

  // The reason is rendered next to the control and repeated on hover.
  assert.match(workflow, /things are missing before this can run/)
  assert.match(workflow, /title=\{queueBlockers\.length \? `Blocked: /)
  assert.match(workflow, /disabled=\{busy === 'runner' \|\| queueBlockers\.length > 0\}/)
})

test('undeclared embedding fields render empty, highlighted, and listed once', () => {
  // A number input bound to 0 renders "0", which reads as a declared value and
  // hides the placeholder showing what a real one looks like.
  assert.match(workflow, /function positiveOrBlank/)
  assert.match(workflow, /value=\{positiveOrBlank\(embeddingConfiguration\.dimension\)\}/)
  assert.match(workflow, /value=\{positiveOrBlank\(embeddingConfiguration\.max_sequence_length\)\}/)

  // The four gaps were printed in full next to the fields and again under the
  // button. The fields are marked instead, and the list appears once.
  assert.match(workflow, /undeclaredEmbeddingFields/)
  assert.match(workflow, /embeddingFieldClass/)
  assert.match(workflow, /border-yellow-600\/60/)
  assert.doesNotMatch(workflow, /embeddingGaps\.map\(\(gap\) => <li/)
})

test('re-seeding refreshes digests without discarding declared embedding values', () => {
  // Seeding pulls digests from bound evidence. When the scanned revision
  // published no embedding facts, clobbering the operator's own values with
  // zeroes would silently undo their work.
  assert.match(workflow, /previous\?: ModelIntakeDeploymentBundleRequest \| null/)
  assert.match(workflow, /Number\(current\.dimension\) \|\| 0/)
  assert.match(workflow, /String\(current\.pooling \|\| ''\)/)
  assert.match(workflow, /buildSeededBundle\(detail, latestJob, bundle\)/)
})

test('the default preflight actually scans the model', () => {
  // Every deep check used to be opt-in behind an Advanced disclosure, so the
  // default run acquired the file and checked provenance without ever running
  // the adapters the page reports as ready.
  assert.match(page, /const \[completeArtifactDownload, setCompleteArtifactDownload\] = useState\(true\)/)
  assert.match(page, /const \[completeRepositorySnapshot, setCompleteRepositorySnapshot\] = useState\(true\)/)
  assert.match(page, /const \[runGeneratedScanners, setRunGeneratedScanners\] = useState\(true\)/)
  assert.match(page, /useState<ModelIntakeScanDepth>\('full'\)/)

  // Depth is a visible first-class choice, not a set of hidden checkboxes.
  assert.match(page, /const SCAN_DEPTHS/)
  assert.match(page, /Scan depth/)
  assert.match(page, /'Full scan'/)
  assert.match(page, /'Quick check'/)
})

test('a full scan only requests a repository snapshot where one exists', () => {
  // Asking for a snapshot from S3 or OCI reports an UNSUPPORTED gap the
  // operator never asked for, so gate it on the resolved adapter capability
  // rather than a hardcoded provider list.
  assert.match(page, /snapshotSupported/)
  assert.match(page, /capabilities\?\.repository_snapshot === 'implemented'/)
  assert.match(page, /setCompleteRepositorySnapshot\(full && snapshotCapable\)/)

  // Resolver payloads and presets carry their own flags; the chosen depth wins.
  assert.match(page, /applyScanDepth\(scanDepth, result\.capabilities\?\.repository_snapshot === 'implemented'\)/)
  assert.match(page, /A preset carries its own depth flags/)
})

test('a completed scan exports a downloadable bill of materials', () => {
  const report = readFileSync(path.join(root, 'src/components/ReportView.tsx'), 'utf8')
  // The scan already produced a CycloneDX inventory and an AIBOM; neither had
  // any way out of ShakerScan.
  assert.match(api, /downloadModelIntakeSbom/)
  assert.match(api, /getModelIntakeSbomSummary/)
  assert.match(api, /\/model-intake\/scans\/\$\{scanId\}\/sbom/)
  assert.match(api, /'cdx\.json'/)

  assert.match(report, /ModelIntakeSbomDownload/)
  assert.match(report, /CycloneDX \$\{summary\.spec_version/)
  assert.match(report, /SBOM \(SPDX 2\.3\)/)
  assert.match(report, /AIBOM/)
  // Reachable from the pipeline too, without opening the report.
  assert.match(shell, /downloadModelIntakeSbom\(scan\.id\)/)
})

test('a bill of materials states its own coverage', () => {
  const report = readFileSync(path.join(root, 'src/components/ReportView.tsx'), 'utf8')
  // A Quick check never enumerates dependencies, so a small component count is
  // a coverage fact rather than a clean bill.
  assert.match(report, /dependency_inventory !== 'generated'/)
  assert.match(report, /no dependency inventory: re-run at Full scan depth/)
  assert.match(api, /dependency_inventory\?: 'generated' \| 'not_generated'/)
})

test('both bill-of-materials standards are offered', () => {
  const report = readFileSync(path.join(root, 'src/components/ReportView.tsx'), 'utf8')
  assert.match(api, /'cyclonedx' \| 'spdx' \| 'aibom'/)
  assert.match(api, /spdx\.json/)
  assert.match(report, /download\('spdx'\)/)
})

test('a Model Intake scan opens on the executive report, not generic scan chrome', () => {
  const report = readFileSync(path.join(root, 'src/components/ReportView.tsx'), 'utf8')
  assert.match(scanDetail, /if \(isModelIntake\)/)
  assert.match(scanDetail, /PageHeader title="Model Intake report"/)
  assert.match(scanDetail, /Corporate policy decision and exception details/)
  assert.match(scanDetail, /Model Intake execution log \(\{logs\.length\} lines\)/)
  assert.match(report, /!isModelIntakeScan && <div className="bg-gray-800\/50/)
  assert.match(report, /order-first bg-gray-800\/50/)
  assert.match(report, /Technical evidence coverage/)
  assert.match(report, /These counts are not the corporate policy decision shown above/)
  assert.doesNotMatch(report, /What the review established/)
})

test('a first Firecracker run is reachable without inventing anything', () => {
  // Three blockers made end-to-end impossible: a runtime job needs a digest
  // only calibration produces, and two digests describe a serving deployment
  // that need not exist when the model is being qualified.
  assert.match(workflow, /useState<'calibration' \| 'runtime' \| 'conversion'>\('calibration'\)/)
  assert.match(workflow, /calibratedDigest/)
  assert.match(workflow, /embedding_output_sha256/)
  assert.match(workflow, /Review and bind for runtime/)
  assert.match(workflow, /Switch Operation to calibration and run that first/)

  // The data-plane digests are optional, and validated only when supplied.
  assert.match(workflow, /Deliberately not blockers/)
  assert.doesNotMatch(workflow, /summary: 'Retrieval application digest is missing'/)
  assert.doesNotMatch(workflow, /summary: 'Index schema digest is missing'/)
  assert.match(workflow, /is not a SHA-256 digest/)
})
