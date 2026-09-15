# Authenticated Scan Profile and Assurance preview

## Inventory and reuse decision

Inspected OSS `0895585ce9915ec668901035b1489324863773f3` and Enterprise
`5ee9e51c56f74e17acdd28e84c82bffe0645ea0c` on 2026-09-14. The implementation
branch is `codex/authenticated-scan-assurance`. No external assessment was run.

| Concern | Existing source of truth | Decision |
|---|---|---|
| Secret ingestion | `api/credential_api.py`, `ui/src/app/credentials/page.tsx` | Reuse secure form; assurance requests never accept secret material |
| Encrypted versions | `api/runtime/credential_store.py`, `api/secret_store.py` | Reference existing profile and immutable credential version |
| Target authority | `api/target_authorization.py`, approval/scope receipts | Configuration never grants target or credential-use authority |
| Worker custody | `api/runtime/credential_resolver.py` | Keep decryption after live authority/version checks |
| Session state | `api/runtime/auth_session_store.py`, `api/scan/private_state.py` | Keep owner/target/profile binding; do not create a cookie database |
| Frozen transport | `api/capabilities/http.py`, `api/runtime/target_bound_socket.py` | Reuse canonical `http.request` with exact origin, frozen addresses, TLS verification and no redirects |
| Execution accounting | `api/runtime/reservation_store.py`, `capability_settlement.py`, `reservation_recovery.py` | Add a validation owner to the existing ledger, receipts, and crash recovery; do not create another budget system |
| Scan result | `api/scan/read_router.py`, scan result evidence and risk/assurance v8 | Add identity assurance independently of risk and finding verification |
| Gateway | `shakerscan-saas/src/shakerscan_saas/enterprise/policy.py` | New routes require explicit allowlist and capability review; no permissive fallback |

Secret flow: secure credential UI → encrypted credential version in PostgreSQL →
live target/receipt/version check → worker-local decrypted material → isolated
request/session → redacted evidence. Assurance metadata does not contain response
bodies, request headers, tokens, cookies, or ciphertext. Database backups require
the separately managed encryption key. Revocation prevents new use; it does not
erase old backups. Missing keys must fail closed.

## Trust and compatibility

The OSS API is a trusted operator boundary, not a multi-tenant service. Enterprise
must enforce reader/editor roles and exact route permissions independently of UI
visibility. Do not enable new mutations through an unreviewed gateway.

Credential presence, successful login, accepted identity, role, access, and continuous
coverage are distinct facts. Existing credentials are `legacy_unverified` unless a
deterministic health observation establishes assurance. A completed scan is not proof
that its identity remained valid. Sampling does not establish continuous validity.

| Consumer/method | Existing execution | Assurance |
|---|---|---|
| Static HTTP headers, bearer, API key, cookie, basic auth | Existing Scan adapters | Structured owner-reviewed health criteria required |
| Form/OAuth login | Existing session establishment | Login success alone is insufficient |
| Browser QA login | Separate existing profile path | Does not establish identity for other Scan actions |
| Interactive SSO/MFA | No verified reusable controlled sign-in path in this increment | Unsupported; human interaction is not automated |
| Hunt, devices, Model Intake | Separate compatibility/authority requirements | No implied assurance parity |

The canonical capability registry also publishes `capability-identity/v1` transport
facts in its semantic manifests. Native `http.request` declares exact-origin
credential delivery and cooperative stopping. Credential-free report finalization,
DNS, TLS, and infrastructure inspection declare that credentials are not used.
Other capabilities default to unverified; sharing a tool family does not inherit
another capability's guarantees. These facts never establish application identity,
continuous authentication, target authorization, or end-to-end Scan profile support.
The setup-validation contract and admission both require the declared HTTP transport
and stopping support. Missing support prevents admission before database or queue
side effects.

The preview is additive and defaults off. Preserve immutable revisions and evidence
when disabling it. Before downgrading, cancel or finish validation requests and
settle/recover their reservations: older binaries cannot interpret the new validation
owner kind. Do not drop the additive tables during rollback. Never use profile labels
as isolation or target authorization.

## Implemented in this branch

- Immutable, reviewed metadata revisions attached to the canonical credential ID
  and pinned secret version. Edits serialize on the same row as secret rotation
  and revocation and reject stale expected revisions.
- Additive startup migration; no changes to encrypted material or target authority.
- Exact-origin configuration checks, including scheme and effective port. The v1
  health policy accepts an owner-reviewed path and flat structured JSON identity
  criteria, with bounded timeout, response size, and freshness.
- Deterministic, content-free evaluation of health responses, and conservative
  current-state projection for expiry, revision changes, revocation, and restart.
  These functions do **not** execute network requests.
- Validation persistence rejects stale in-flight validity and orders observations
  deterministically. At equal timestamps an uncertain/failed record wins over a
  valid record. Duplicate IDs cannot change historical evidence.
- Local preview management at `/authenticated-scan-profiles`, sharing the secure
  credential UI. No secret entry or autonomous execution path is added.
- Explicit one-shot validation on the existing agent-tool queue using `http.request`.
  Requires an action-bound, expiring credential-tier receipt, exact target binding,
  reviewed profile revision, current credential secret and metadata revisions, and
  a matching worker build. Queue messages carry only opaque IDs and the job type.
- One GET, no redirect following, no cookie jar reuse or login retries, and a
  worker-private response bounded to 16 KiB plus one truncation-detection byte.
  Only match bits, states, stable reasons and receipt references are persisted.
  The 1–10 second request timeout, 60 second queue deadline, per-profile rate limit,
  reserved budget, settled charge, and measured HTTP elapsed time are explicit.
- Validation cancellation closes the in-flight request; an already transmitted
  request cannot be undone. Duplicate deliveries do not repeat traffic. Recovery
  charges uncertain execution conservatively and records unknown assurance.
- Requesting a new check immediately records pending uncertainty. An earlier
  successful timestamp remains historical and cannot keep the profile green while
  the new request waits for an unavailable worker.
- Paginated, content-free validation history links pending and terminal observations
  to the same request. The UI shows historical states and execution receipts with
  reserved/consumed budgets. Older records without request IDs remain readable and
  idempotent. Role predicates, timeout, and freshness can be reviewed in the UI.
- Validation admission requires the credential's existing `http.request`
  permission before reserving capacity, resolving DNS, or queueing work. The UI
  offers validation only when that permission exists; it never adds permission.
- A new validation request starts uncertainty even when a previous worker's clock
  was ahead. A future-dated historical success cannot later replace pending status.
- New Scan credential references pin their metadata revision as well as the secret
  version. Both are checked before decryption, and the metadata revision contributes
  to the existing action input digest. Legacy references remain readable.
- Local canonical Scan actions recheck generic credential metadata and the existing
  target-bound approval before dispatch, including continuation rounds. Revocation,
  expiry, rotation, metadata changes, and unavailable authority block the next
  action without disclosing or reloading secret material. The check is bounded to
  five seconds. Report finalization remains available and retains earlier findings.
- These blocked actions appear as `authentication_uncertain` in the action ledger
  and as an authentication gap with a blocked-action count in report/read summaries.
  The UI explains which work could not proceed and asks for identity/approval review.
  This gate does not observe application session acceptance or establish
  broker/browser-login parity; those guarantees remain pending.
- During a local generic-credential action, authority is sampled every half second
  through the same bounded metadata check. Loss sets an action-local stop signal
  consumed by the existing adapter callbacks. Inline HTTP now closes its pending
  operation on that signal. Any uncertain wire use is settled conservatively.
  Available observations survive as partial output; user cancellation stays distinct.
  The receipt records the last authority check and observed interruption time,
  without claiming application identity or continuous authentication. Timeout and
  identity uncertainty remain independently visible.
- The canonical HTTP executor refuses cross-origin redirects carrying credentials
  or newly received cookies, even when both origins are within target scope.
  Anonymous redirects between explicitly allowed origins retain their behavior.
- A tested immutable assessment-snapshot contract preserves reviewed labels and
  setup evidence without claiming future Scan authentication. This contract is not
  yet connected to Scan admission or execution; profile selection remains disabled.
- Shared UI review/approval, explicit HTTP transport consent where applicable,
  status and cancellation controls, and refreshed current assurance. Saving a
  profile does not dispatch a request. Interactive authentication remains unsupported.
- Read-only `/scans/{id}/authentication-assurance`, coverage API metadata, stored
  final report metadata, and qualified identity labels in the result UI.

## Rollout and remaining work

Set `SHAKERSCAN_AUTHENTICATED_ASSURANCE=1` only for a loopback-published internal
preview and rebuild using the launcher. The default is off. The preview creates
reviewed configuration: even `ready` never implies accepted authentication.
The contract advertises the supported static credential methods for explicitly
requested read-only validation. Scan selection, Hunt assurance, and interactive
SSO remain unsupported. Older Enterprise capability
manifests hide the new UI controls, and its existing route allowlist denies the new
management paths. No Enterprise code was changed.

The supplied implementation plan is **not complete**. Remaining release gates:

1. Pin reviewed profile revisions at Scan admission; validate before credential
   disclosure; enforce profile destination restrictions across every participating
   adapter. Keep selection disabled until consumer isolation tests pass.
2. Connect the budgeted Scan health actions below to admission, identify uncertain
   intervals, and expose their timeline and frozen snapshot in every report/summary.
3. Review and implement Enterprise reader/editor authorization, actor propagation,
   capability negotiation, and the old/new gateway compatibility matrix in SaaS.
4. Extend the passing clean-install/upgrade and database/key restore fixtures to
   integrated Scan session isolation and approved design-partner acceptance. No
   external customer or benchmark assessment has been performed by this implementation.

Revoke credentials through the existing credential control. Disabling or archiving
assurance configuration does not delete or revoke its underlying credential, and
existing legacy Scan selections retain their existing behavior. Archived assurance
configuration is immutable. Deletion of historical evidence is not provided here.

## Validation commands

```sh
PYTHONPATH=.:api:scanner .venv/bin/python -m pytest \
  tests/test_authenticated_assurance.py tests/test_scan_explanation.py \
  tests/test_scan_read_router.py tests/test_scan_finalizer.py \
  tests/test_retest_contract_migrations.py tests/test_credential_api.py \
  tests/test_public_api_contract_generation.py -q
npm --prefix ui test
npm --prefix ui exec -- tsc --noEmit -p ui/tsconfig.json
PLAYWRIGHT_BASE_URL=http://127.0.0.1:3100 npm --prefix ui run test:browser -- authentication-profiles.spec.ts
```

`tests/test_authenticated_assurance_postgres.py` additionally uses an explicitly
opted-in **disposable** local database named `shakerscan_assurance_test` via
`ASSURANCE_TEST_DATABASE_URL`. It resets that test schema. Never point it at the
application database. Its fixture covers atomic edits, immutable history,
revocation races, deterministic ordering, and the full ASGI API boundary without
starting schedulers or performing assessment traffic.

`tests/test_authenticated_validation_worker.py` uses the same disposable database
and real loopback HTTP with synthetic Fernet-encrypted credentials. It never creates
a Scan or contacts a third-party target. Coverage includes redirects, oversized
responses, anonymous 200, wrong identity, denied access, expiry, timeout, missing
keys, revoked approval/credential races, cancellation, stale builds, recovery, rate
limits, and API review/secret-redaction boundaries.

## Previous foundation verification receipt

- `make test`: 133 unit tests and 490 foundation tests passed on the rebuilt stack.
- Assurance model and disposable PostgreSQL/API fixtures: 39 tests passed,
  including the revoke/reactivate race using the canonical credential record version.
- UI: 298 unit tests, TypeScript, and two desktop/mobile browser cases passed.
  Fixture screenshots were reviewed; no horizontal overflow was detected.
- Public OpenAPI generation, capability inventory, module-size ratchet, and diff
  whitespace checks passed. The test runner now propagates first-group failures
  and checks the installed pytest module instead of assuming a console script.
- Launcher rebuild succeeded after fixing the package copies in both worker and
  slim API images. The initial packaging failure was detected and corrected;
  it is not counted as a passing build.
- Live migration receipt exists. API/database/Redis are healthy, all five scan
  workers are current (zero stale), specialized worker identity is verified, and
  checked services have zero restarts. Live preview management is disabled.
- Existing ASM scheduling logged DNS failures for unavailable saved fixture
  targets. Those targets and schedules were not changed by this work.

These checks certify the preview above, not the remaining execution, Enterprise,
restore, or customer acceptance gates.

## Read-only validation increment verification

- 22 real loopback worker/API cases, seven PostgreSQL cases, and 34 assurance-model
  cases passed. The upgrade fixture preserves existing Scan reservation hashes.
- 122 targeted credential, receipt, reservation, fingerprint, migration, and API
  contract tests passed. Resolver tests check metadata revision before decryption.
- 298 UI unit tests, TypeScript checks, and four desktop/mobile browser cases passed, including
  explicit credential-use review and unencrypted HTTP consent.
- `make test` passed on the rebuilt stack: 133 unit and 557 foundation cases.
- The worker/API package participates in the shared build fingerprint. Launcher
  rebuild succeeded; UI, API, and specialized worker identity matched. Five of five
  Scan workers were current on fingerprint `7734839393bce0bd`, with zero stale
  workers and zero restarts across checked services.
- All three additive migration markers were present. The live contract advertised
  the six static header methods while retaining `enabled: false`. The application
  database contained zero validation requests; no real Scan or validation was submitted.
- The earlier in-progress build was stopped to include the pending-state reporting
  regression fix. Only the subsequent successful rebuild is counted here.
- Public contract generation, capability inventory, module-size ratchet, and diff
  checks passed. Temporary loopback UI and disposable PostgreSQL services were removed.

These results do not establish Scan-wide session assurance, Enterprise support,
clean-install/restore acceptance, or customer pilot readiness.

## History and Scan custody increment

Host tests cover pre-decryption secret/metadata version checks, action input digest
binding, immutable snapshot rejection rules, real cross-port and cross-scheme HTTP
isolation, history pagination, and old-record compatibility. Browser tests cover the
advanced criteria fields, historical success alongside current uncertainty, and
receipt budget display.

- 230 focused model, snapshot, Scan credential, and worker custody tests passed.
- 32 real PostgreSQL and synthetic loopback worker/API tests passed, including
  history pagination, backward-compatible record replay, clock skew, and denied
  capability admission without a queued request or budget reservation.
- 298 UI unit tests, TypeScript, and four desktop/mobile browser cases passed.
  The mobile history/receipt screenshot was reviewed for readability.
- The public contract, capability inventory, module-size ratchet, and whitespace
  checks passed. The temporary UI and disposable database were removed.

- Launcher rebuild passed on fingerprint `65a1ac82551f9cc0`; all five Scan workers
  were current, zero were stale, and checked API/UI/worker services had zero
  restarts. API, database, Redis, and Model Intake readiness checks passed.
- Rebuilt-container tests passed: 133 unit and 574 foundation cases (one existing
  Starlette deprecation warning). The live contract includes history support while
  management remains disabled. No application validation requests were submitted.
- The installer now includes the assurance model used by installed report code.
  Installed import closure, manifest integrity, clean installer, stable release
  channel, and installer upgrade smoke checks passed. These do not substitute for
  database/secret-key backup and restore acceptance.

## Action credential gate verification

- 263 focused host tests passed across authority checks, receipts, orchestration,
  reports, read routes, and worker compatibility. After the read-projection case
  was added, its focused 45-case set also passed.
- 35 PostgreSQL/loopback fixtures passed, including real persisted approval
  revocation, credential revocation, and metadata changes between action checks.
  Those new cases made zero HTTP requests. The disposable database was removed.
- 299 UI unit tests, TypeScript, and two desktop/mobile report fixtures passed.
  The mobile screenshot shows the blocked-action count alongside an independently
  supported finding. Initial browser failures came from fixture routing and invalid
  unrelated API mock responses; the corrected fixtures passed against the rebuilt UI.
- Launcher rebuild passed on fingerprint `6a43efca526048f1`. Five of five Scan
  workers were current, zero stale; the specialized validation worker matched.
  API/database/Redis and Model Intake were ready, with zero checked service restarts.
- Rebuilt tests passed: 133 unit and 593 foundation cases, with one existing
  Starlette deprecation warning. Clean installer, import closure, install manifest,
  public contract, capability inventory, module-size, and whitespace checks passed.

This verifies checks between local generic-credential actions. It does not complete
in-flight interruption, application session-health sampling, profile selection,
Enterprise integration, or backup/restore acceptance.

## In-flight interruption verification

- 281 focused execution/reporting tests and 81 shared adapter/archive checks passed.
  Tests preserve partial observations, keep user cancellation distinct, retain a gap
  after an out-of-order positive authority result, isolate concurrent action signals,
  and retain identity uncertainty alongside timeout status.
- Seven real loopback cases passed, including closure of an HTTP connection whose
  server never responded. No real target or Scan was submitted.
- Rebuilt-container tests passed: 133 unit and 613 foundation cases, with one
  existing Starlette deprecation warning. UI unit tests (299), TypeScript, and two
  desktop/mobile report fixtures passed. The final mobile screenshot was reviewed.
- Launcher rebuild passed; a subsequent UI-only rebuild corrected a timing-specific
  label. The final fleet fingerprint is `a5fe2d702fca5a29`, with five current Scan
  workers, zero stale workers, matching specialized validation worker, healthy
  dependencies, and zero checked service restarts. Bounded API startup logs were clean.
- Install manifest/import closure, public contracts, capability inventory,
  module-size, and whitespace checks passed. The historical assurance read endpoint
  remained compatible after adding receipt-metadata interruption detection.

This proves the shared stop signal and inline HTTP transport path. Other adapters
still require their own compatibility acceptance before profile selection is enabled.
Authority polling is not an application session-health check; that integration,
profile selection, Enterprise access control, and restore acceptance remain open.

## Registry identity contract verification

- 69 semantic-registry, admission, assurance, authority, and MCP/ASGI checks passed.
  Invalid or contradictory transport declarations are rejected. Withdrawing either
  required HTTP guarantee disables the advertised validation method and rejects
  admission before database or queue work.
- 160 runtime/credential/Scan-plan compatibility tests and 35 PostgreSQL/loopback
  validation cases passed. The two fixture tests initially blocked by loopback
  sandbox permissions passed when rerun with local-network access. The disposable
  database was removed after verification.
- Rebuilt-container tests passed: 133 unit and 626 foundation cases, with one
  existing Starlette deprecation warning. Public contracts, capability inventory,
  install manifest/import closure, module-size, and whitespace checks passed.
- Launcher rebuild passed on `eeef6396763f417d`: five current Scan workers, zero
  stale workers, matching specialized validation worker, healthy dependencies,
  zero checked service restarts, and clean bounded API startup logs. The live
  validation contract exposes `capability-identity/v1` without claiming identity
  proof or enabling Scan profile selection. No Scan or real-target validation was
  submitted.

This is the canonical compatibility source for further profile admission work,
not a claim that profile selection or session-health sampling is complete.

## Database restore acceptance

The opt-in restore fixture uses PostgreSQL 16 `pg_dump` and `psql` against a new,
disposable database. It checks every restored public-table row, including encrypted
credential versions, immutable profile revisions, validation history, evidence
references, approval receipts, and budget records. Reapplying the assurance schema
does not change those rows. A seeded credential and its separately held encryption
key must both be absent from the SQL backup. The temporary dump has mode `0600`
and is removed after restore.

Restored positive evidence remains historical: a new process generation projects
it as `unknown / process_restarted`. Without the encryption key, a newly reviewed
validation fails before sending HTTP. Restoring the key alone does not change that
observation; another explicitly reviewed validation is required. The fixture uses
only a synthetic loopback identity and submits no Scan or Hunt.

Reproduce with an unused local port and the local PostgreSQL 16 image:

```bash
docker run --rm -d --name shakerscan-assurance-restore-fixture \
  --label shakerscan.assurance_restore_fixture=true \
  -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=shakerscan_assurance_test \
  -p 127.0.0.1:56396:5432 postgres:16.15-alpine3.23
# Wait for pg_isready to report accepting connections before running pytest.
docker exec shakerscan-assurance-restore-fixture pg_isready -U postgres
ASSURANCE_TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:56396/shakerscan_assurance_test \
ASSURANCE_TEST_POSTGRES_CONTAINER=shakerscan-assurance-restore-fixture \
PYTHONPATH=.:api:scanner .venv/bin/python -m pytest -q \
  tests/test_authenticated_assurance_restore.py
docker stop shakerscan-assurance-restore-fixture
```

The test refuses an unlabelled container, non-loopback port binding, non-disposable
database name, or container without automatic removal. It fails if the restore
database already exists. Recreate the fixture container for each run. The test
resets only `shakerscan_assurance_test`; never use the application database.

This acceptance covers the additive database metadata and key dependency. It does
not claim a full production-volume recovery, Enterprise tenant restoration, or
customer pilot acceptance. Operators must back up the existing secret-store key
separately under their access controls; revocation does not erase older backups.

Verification: 36 restore, persistence, and synthetic loopback cases passed together.
Module-size and whitespace checks passed. These changes affect tests and
documentation only; the previously verified runtime build remains unchanged.

## Binding reviewed snapshots to Scan authority

Server-created assessment snapshots can now be attached to canonical credential
references. The existing action input digest includes the complete snapshot, so a
changed profile revision, configuration digest, or historical label changes action
identity. Credential IDs and both credential versions must match. The binding
copies metadata rather than retaining mutable caller state.

The existing worker authority callback also checks a bound profile's current
revision, lifecycle, configuration digest, target, and exact origin. Edits,
disablement, and origin changes interrupt authority without modifying the pinned
history. These remain metadata checks, not application session-health observations.

Report and read-only assurance projections preserve the validated snapshot and
its setup evidence reference. They still report `unknown` authentication and
`unverified` coverage without recorded Scan health. Invalid snapshot metadata is
not exported as trusted history. Setup success cannot erase an authentication gap.

Verification includes 124 action/compiler/guard/report tests, 80 assurance and
report projection tests, and 38 real persistence/loopback cases. Clean installer,
release-channel, and upgrade fixtures passed with the new snapshot dependencies.
Public contracts and capability inventory remain current. Scan admission and UI
selection are not connected to this binding yet; session-health actions and
consumer compatibility checks must be integrated before enabling selection.

The launcher rebuild passed on `11af8be7dbc8a8de`: five current Scan workers,
zero stale workers, all specialized pools ready, healthy API/database/Redis,
zero checked service restarts, and clean bounded startup logs. Rebuilt-container
tests passed (133 unit, 635 foundation; one existing Starlette deprecation
warning), as did desktop/mobile report compatibility fixtures. The live contract
continues to disable management by default and advertise Scan selection as
unsupported. No Scan or real-target validation was submitted.

## Budgeted Scan health action path

For reviewed profile references, the compiler inserts required `http.request`
health samples before and after participating actions. These share the ordinary
action graph, reservations, receipts, and whole-plan ceilings. The graph rejects
unverified consumers and requires local placement. It does not silently remove
requested families or broaden credential permissions. Legacy graphs are unchanged.

Setup and Scan validation use the same bounded GET and deterministic identity
parser. A Scan health action resolves the canonical encrypted credential with its
own existing `scan.submit` approval, pinned secret and metadata revisions, exact
origin, and freshly checked profile authority. HTTP consent must be supplied for
that Scan; setup consent is not reused. No response body or sensitive header is
retained in the `authentication_health` receipt observation. The canonical HTTP
registry declares that additive evidence type. Numeric credential revisions are
preserved in receipts only as positive 32-bit integers; strings, booleans, and
other values under those names remain redacted.

Partial or timed-out health checks do not satisfy dependencies. Ordinary partial
evidence keeps its existing dependency semantics. The worker rejects missing,
expired, changed-generation, or uncertain health before credential-using work and
through the in-flight interruption callback. Restored health prerequisites cannot
authorize resumed traffic. Missing or capability-denied reviewed principals fail
closed instead of falling back to anonymous requests. Finalization still preserves
independently supported findings after interruption.

Verification includes 51 real persistence/loopback cases: one-request accounting,
anonymous 200, denied access, wrong destination, unavailable key, missing consent,
insufficient budget, in-flight profile/approval revocation, timeout, restart, and
expiry interrupting a live request. Compiler and scheduler tests prove that health
costs fit the existing ledger and that a partial health result blocks its consumer
without changing ordinary partial-evidence behavior. These are synthetic fixtures,
not submitted product Scans or third-party tests.

This path remains behind the unfinished profile admission workflow. The default
feature flag is off, the public contract still advertises Scan selection as
unsupported, and normal full-plan consumers such as `web.probe` still need their
transport/isolation acceptance. Health timeline aggregation, UI selection and
presentation, and Enterprise authorization/version parity remain release gates.

The final adapter also bounds database/credential preflight waits by the reserved
wall budget; its stalled-preflight fixture closes the pending operation and records
unknown health with zero HTTP requests. A late positive response cannot override a
profile or approval change. The final verification run passed 51 PostgreSQL/loopback
cases, 220 worker/report compatibility tests, and 40 additional redaction checks.
Clean installation, release-channel and upgrade fixtures, generated contracts,
inventory, import closure, module-size, and whitespace checks passed.

Launcher verification passed on `83a092b6091f5734` with five current Scan workers,
zero stale workers, all specialized pools ready, healthy dependencies, and zero
checked restarts. The rebuilt-container suite passed 133 unit and 644 foundation
tests (one existing Starlette deprecation warning). Both desktop/mobile report
compatibility fixtures passed. The public feature remains disabled by default;
no product Scan, Hunt, or real-target validation was submitted.
