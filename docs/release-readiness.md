# ShakerScan 2.0.0 Release Readiness

**Status (2026-08-25): candidate preparation; not approved for publication.** The V2 source audit
and current-head manual product pass are complete on the `v2` branch; fresh long-running Scan
submissions and frozen-candidate qualification remain separate follow-up gates. `VERSION` and release
notes are prepared for 2.0.0, but no release tag, candidate image publication, GitHub Release, `latest` alias, hosted
installer change, or stable-channel promotion is authorized by this document. The stable installer
must remain on 0.8.18 until every frozen-candidate gate below has a successful exact-SHA receipt.

This is the live release checklist. Source, migrations, generated inventories, immutable runtime
receipts, and fresh test output are authoritative. Earlier branch runs and historical scans are
useful regression evidence, but do not qualify the frozen 2.0.0 candidate.

## Supported product boundary

ShakerScan 2.0.0 is a trusted-operator, self-hosted security scanner.

- Localhost is the default. Remote UI/API access must remain behind Tailscale, a VPN, a firewall, or
  an operator-managed authenticated reverse proxy. Direct public exposure is unsupported.
- ShakerScan does not provide application login, users, roles, tenant isolation, or protection from
  another person who can access its process, API, UI, database, Docker socket, configuration, or
  result files.
- Results can contain sensitive request, response, authentication, payload, model, and evidence
  data. Public credential and collection responses are metadata-only; comprehensive rewriting of
  arbitrary historical evidence is not promised.
- Active DAST, Hunt, and connected-device testing require ownership or explicit authorization for
  the exact target. Silence, missing telemetry, and blocked work remain inconclusive.
- Model Intake is release-gated for deterministic static review, artifacts/reports, and the opt-in
  AMD64 Linux/KVM Firecracker tier. Incomplete evidence or unavailable required controls fail closed.
- Fleet production support is the outbound-only HTTPS `broker` transport. WireGuard remains preview
  code outside the 2.0.0 support boundary pending its own physical acceptance.
- AI Gate remains preview in 2.0.0.

## Stop-ship contract

| ID | Requirement | Required evidence |
|---|---|---|
| **SCAN-01** | One canonical Scan plan controls local, broker, and parallel execution. No legacy identity or caller-supplied argv regains authority. | Contract, compatibility-sunset, dispatcher, and exact-image parity receipts. |
| **SCAN-02** | Scope, destination, redirect, time, request, payload, host, mutation, cancellation, and multi-dimensional budget bounds fail closed. | Unit/fault gates plus counting-target external-wire acceptance. |
| **SCAN-03** | Verified status and high-impact severity require deterministic proof. AI, labels, and stale findings cannot manufacture proof. | Adversarial promotion, replay, linkage, severity-cap, and finding-detail checks. |
| **SCAN-04** | Coverage distinguishes completed, skipped, blocked, cancelled, failed, partial, and unobserved work. | Parent/shard/ASM rollups and multiple live scan configurations. |
| **HUNT-01** | One target-kind-aware Hunt runtime exposes only canonical registered capabilities and cannot broaden target/approval scope. | MCP/CLI/UI Hunt smoke across web and device targets, plus fail-closed negative calls. |
| **DATA-01** | Targets, scans, findings, credentials, collections, evidence, campaigns, and historical rows remain target-bound, redacted, bounded, and navigable. | API cross-checks and multiple real UI detail records from each source. |
| **DEVICE-01** | Device inventory, positive reachability, service evidence, policies, collections, credentials, and HTTP handoff stay separate from Web DAST metrics. | Current device worker, LG TV scan/Hunt, saved-profile/collection, and policy UI receipts. |
| **MODEL-01** | Model acquisition, scanners, reports, signing, policy, and Firecracker evidence remain bound to one immutable subject and fail closed. | Full suites, fixture/public-model E2E, artifact cross-checks, and host-readiness UI. |
| **FLEET-01** | Broker enrollment, leases, placement, credentials, artifacts, cancellation, and build truth fail closed across real Linux hosts. | Automated contracts and exact-SHA real-fleet parity; physical fault acceptance when available. |
| **UPGRADE-01** | Clean, repeated dirty upgrades and rollback preserve state; required-schema failures stop startup. | Published-baseline upgrade/rollback receipt and migration-failure tests. |
| **DEP-01** | Supported runtimes contain no unaccepted high/critical production dependency findings. | Locked Python audit, production npm audit, and candidate image inventory. |
| **BUILD-01** | UI, API, workers, signer, tools, rules, templates, version, source SHA, and image digests are reproducible and identical where required. | Candidate build self-tests, complete suite, generated inventory, SBOM/provenance, and identity checks. |
| **REL-01** | Publication fails closed on wrong SHA/version/digest and never advances stable before public acceptance. | Candidate receipt, promotion checks, public-install smoke, notes, ledger, and separate stable PR. |

Do not waive untrustworthy proof, false-clean coverage, unsafe unbounded execution, stale-fleet
evidence, migration startup after required-schema failure, failed core DAST/Hunt/device acceptance,
failed Model Intake containment, digest drift, or unaccepted high/critical production dependencies.

## Preliminary preparation evidence

These checks were run during the working audit and must be repeated if product/runtime code changes
after the candidate is frozen:

- [x] Complete candidate-runtime Python suite: 1,143 package-native and 3,686 compatibility tests
  (4,829 total).
- [x] All 17 named release gates pass after exercising their canonical `api` package layout.
- [x] UI unit contracts (167), browser acceptance (30 passed, 2 intentionally skipped), and the
  production Next.js build pass.
- [x] Production npm and locked Python dependency audits report no known vulnerabilities.
- [x] Generated capability inventory is current.
- [x] Frozen-source installer smoke passes without retired V1 command files.
- [x] Clean, duplicate-dirty, verification, and rollback migration scenarios pass from v0.8.17.
- [x] Manual MCP initialize/tool-list/read-only Arsenal execution was exercised; target inventory is bounded.
- [x] The latest exact V2 migration workflow completes successfully without cancellation by a later push:
  [`33e9629f` run 32879562615](https://github.com/andriyze/shakerscan/actions/runs/32879562615).
- [ ] Final live stack is rebuilt at the exact candidate SHA with uniform current fingerprints.
- [ ] Final UI/API/CLI/MCP/Hunt/device/DAST submissions and navigation checks are recorded.

### Current-head manual audit receipts

These are pre-candidate acceptance records, not substitutes for the frozen-candidate gates below:

- Runtime revision `60d2fa35` was rebuilt locally with uniform UI, API, general-worker,
  agent-tool-worker, and device-worker identity. Every static UI route and representative dynamic
  Scan, finding, campaign, target-graph, device, and Hunt detail was exercised at desktop and
  390-by-844 viewports with no console/runtime errors. Filters, mobile navigation, detail links, and
  intentional table scrollers were clicked rather than inferred from unit tests.
- Historical Scan `315c0e48-014e-4360-b56a-ecc315b71e45` is a failed child shard, not a running
  two-shard parent. Its parent `1a05c2b0-6ad2-4125-b927-066f05c97d5c` is terminal with two failed
  shards and an invalid old parallel authority. The UI now labels the child as non-verdict evidence,
  links to the parent, and distinguishes that record from newer healthy parallel Honey completion
  `14b3212c-0f9a-49c3-9563-1fde4ed07021` (three of three shards, five findings).
- Existing complete and partial Honey, Juice Shop, device, finding, and Hunt records were cross-checked
  against API data. Partial Honey `5160e342...` truthfully shows two completed and one failed shard;
  LG posture `020f7699...` truthfully shows provisional B/84 with incomplete required checks. No
  terminal parent had a non-terminal child.
- Web Hunt `8684a29d-c163-486e-b3e5-19bf99320f03` completed against Juice Shop using its saved
  collection: four safe replays returned HTTP 200, direct product search returned HTTP 200, and the
  same-origin browser capability preserved partial output when its 20-request ceiling was reached.
- Passive LG Hunt `9295b45d-9d05-4e6d-9cab-ed9585397169` used saved selection
  `740bd8fd-2d00-4a89-af52-1fd8e574c151`; HTTPS 3001 timed out and HTTP 7000 returned 403. A direct
  probe failed closed because the latest posture scan had no current confirmed web origin. Its
  durable replay now preserves the exact safety reason and charges zero unattempted traffic.
- Credential-bound LG Hunt `cf9e1e68-c1cf-43f8-8ecf-994dcbf6bd51` used saved SSH profile metadata
  and a UI-created lab approval. Inventory/capability inspection succeeded; the read-only immutable
  SSH proposal failed closed because port 22 was not a confirmed, host-key-pinned SSH service. No
  command or plan executed and active/network/fragility use remained zero.
- Source CLI help/status, credential test, evidence manifest export, Hunt capability calls, retry-safe
  idempotency, and safety failures were exercised. MCP initialized, enumerated its generated tools,
  and executed bounded read-only Arsenal work without exposing secret values.
- The manually dispatched installed-stack acceptance at `de634236` built every image and passed the
  scanner/API overlay, startup/schema/real-tool smoke, external wire ceilings, cancellation admission,
  reservation identity, resume-without-repeat-traffic, and production UI build. It then exposed two
  browser-test assumptions rather than hiding them behind retries: an ambiguous Hunt label query and
  a literal `127.0.0.1` expectation for a valid `localhost` API origin. `33e9629f` fixes both acceptance
  tests and the one stale source-inspection assertion; its path-filtered follow-up passed all 4,829
  Python tests plus focused and UI contracts. The installed browser and Model Intake rerun remains a
  local final-head preparation receipt, not a release-publication action.

### CI cost control

V2 does not rebuild every image on every commit. `V2 source bundle` creates only the source archive;
the migration workflow first classifies changed paths, runs UI contracts only for UI changes, and
runs backend contracts/complete Python only for backend changes. The `images-api-ui` job is skipped
on pushes and is available only through explicit `workflow_dispatch`. Full image construction and
installed-stack E2E belong to non-publishing candidate acceptance, where paying that cost once per
exact candidate is intentional.

## Frozen-candidate validation

Run every item against the exact commit intended for `v2.0.0`. Any product, migration, runtime,
test, workflow, or operational change creates a new candidate and invalidates earlier candidate
receipts.

### Code, dependencies, builds, and migration

- [ ] `scripts/run_complete_python_suite.py` passes inside the locked candidate worker image.
- [ ] `make release-gates`, UI tests/build, dependency audits, and capability-inventory check pass.
- [ ] Scanner, API overlay, UI, signer, and fixed Firecracker guest build and self-test.
- [ ] External adapter wire acceptance proves observed request/connection ceilings for all adapters.
- [ ] Clean installer, duplicate dirty upgrade, required-migration failure, backup, and rollback pass.
- [ ] CodeQL, security/static checks, commit policy, V2 contracts, full E2E, and real-fleet parity are
  successful for the same 40-character source SHA.

### Manual UI acceptance

- [ ] Desktop and narrow viewport cover every sidebar route, loading/empty/error state, modal, filter,
  pagination control, and internal link without console/runtime errors.
- [ ] Dashboard, Docs, Targets, New Scan, Scans, Scan Detail, Findings, Finding Detail, Credentials,
  Request Collections, Devices, Device Detail/Policies, Schedules, Interactive, Exposure, Coverage,
  Hunt, Evidence, Timeline, Campaigns, AI Gate, Model Intake, Policy Profiles, Exceptions, Arsenal,
  AI Ops Router, Settings, Fleet guidance, and Application Graph are inspected.
- [ ] Multiple existing Juice Shop, Honey, Hunt, AI Gate, and LG TV records have coherent target,
  status, shard, progress, finding, evidence, provenance, and navigation data.
- [ ] Running parent scans do not become failed because an unfinished shard is absent or stale; true
  terminal failures explain which shard/action failed and preserve trustworthy partial results.
- [ ] Historical pathological labels and large device/evidence records remain bounded in list views;
  full redacted detail loads only on demand.

### API, CLI, MCP, and agent acceptance

- [ ] Health and worker endpoints report one current build; stale-worker submission fails closed.
- [ ] Scan, target, finding, evidence, credential, collection, Hunt, device, Model Intake, and Fleet
  responses are target-bound, redacted, paginated/bounded, and agree with UI records.
- [ ] Source and installed CLI paths exercise status/doctor/help plus Scan, Hunt, credential,
  collection, and evidence commands, including negative validation without queueing unintended work.
- [ ] MCP initializes, exposes read-only Arsenal inspection plus contract-generated Hunt V2 tools,
  paginates large inventories, rejects malformed/out-of-scope input, and completes a bounded Hunt
  start/manifest capability/query/candidate/finish flow with retry-safe idempotency.
- [ ] AI Ops preview reports missing inputs, safety, blast radius, and confirmations without executing
  an unconfirmed plan.

### Live authorized workloads

- [ ] Juice Shop and `honey.shakerscan.com` are exercised through the UI with materially different
  policy/budget/collection configurations on a current fleet.
- [ ] Saved request collections and exact-target credential profiles are selected where applicable;
  reusable secret values never enter UI, canonical requests, queues, logs, or receipts.
- [ ] A bounded Web/API Hunt and an LG TV device/Hunt path exercise saved collections/credentials and
  preserve device/Web namespace separation.
- [ ] Every new submission records its scan/Hunt ID and browser link. Long-running scans are not
  polled as part of the submission turn; results are evaluated in a later acceptance pass.

### Model Intake and Fleet

- [ ] Local fixture E2E reports Firecracker unsupported precisely on macOS and incomplete, not passed.
- [ ] Public-model E2E and report/artifact parity pass on an authorized networked runner.
- [ ] AMD64 Linux/KVM qualification passes on a compatible host or remains an explicit stop-ship item
  for the claimed support tier.
- [ ] Exact-SHA broker parity covers local/broker/parallel semantics, worker loss/reclaim, lease
  authority, centralized artifacts, finding dedupe, and build identity.

## Publication sequence (not authorized by preparation)

1. Freeze one exact candidate SHA after all implementation and manual fixes.
2. Obtain successful exact-SHA full E2E, CodeQL, and V2 real-fleet parity runs.
3. Run **Release candidate** for 2.0.0; publish only immutable candidate tags and preserve receipts.
4. Complete candidate-image, upgrade, Model Intake, UI/API/CLI/MCP, and public-install acceptance.
5. Run **Promote release** to map version tags to accepted digests without rebuilding.
6. Record the published SHA/digests in `RELEASES.md` and verify the GitHub Release.
7. Only in a separate stable-channel change, update `install/STABLE_VERSION` and run **Promote stable
   channel** with the public smoke receipt.

Stop before step 3 unless the user explicitly authorizes release publication. This preparation task
does not authorize tagging, candidate publication, GitHub Release creation, `latest`, hosted
installer deployment, or stable-channel promotion.
