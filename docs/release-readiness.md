# Release Readiness

**Status (2026-07-26):** `0.7.0` candidate preparation continues on `v8`; `VERSION` remains
`0.7.0`. Multi-node is now in candidate scope, but the branch is not release-ready until its
physical fleet, upgrade, installer, benchmark, and full E2E gates pass on one frozen SHA.
This is the single live release scope, stop-ship, validation, installer, and publication checklist.
It is not a claim that the branch is release-ready: it is release-ready only when every applicable
item below is green on the **frozen candidate SHA**.

Code, migrations, runtime receipts, and tests are authoritative. Historical test results and audit
snapshots may support investigation, but they cannot satisfy a current-release gate — the
authoritative validation is a fresh run on the frozen candidate (VAL-01), not on branch HEAD.

## 0.7.0 product boundary

ShakerScan 0.7.0 is a **trusted-operator, self-hosted security scanner**, not a hosted SaaS or
multi-tenant security platform.

- The operator controls the ShakerScan process, API, UI, database, Docker socket, and result files.
  ShakerScan does not provide application login, users, roles, tenant isolation, or protection from
  another person who can access those resources.
- Localhost is the default. Remote access must stay behind Tailscale, a VPN, firewall, or an
  operator-managed authenticated reverse proxy. Direct public exposure is unsupported.
- Starting an ordinary local active DAST scan is treated as the trusted operator's authorization.
  Clear target and active-testing warnings remain mandatory. Approval receipts and a global
  enforcement toggle are implemented, and Deep Hunt always requires a target-bound expiring
  approval; only mandatory receipt enforcement for every trusted-local DAST scan is deferred.
- Scan evidence can contain request/response content, payloads, tokens, or application data. Treat
  results and backups as sensitive. Comprehensive secret masking and historical evidence rewriting
  are not promised in 0.7.0.
- Target authentication remains core scanner functionality, including distinct-principal BOLA
  testing, credential rotation, and proof that the target accepted each test identity.

## Stop-ship contract

| ID | 0.7.0 requirement | Exit evidence |
|---|---|---|
| **SCAN-01** | Deterministic evidence—not AI opinion, labels, or caller-supplied state—controls verified status and high-impact severity. Phantom or hypothetical attack-chain steps cannot render as proven exploitation. Registry `severity_rules` may remain advisory with the current wired severity caps for XSS, SQLi, BOLA, auth, mass assignment, and JWT. | Adversarial proof/promotion tests, deterministic replay, D-4 no-phantom-chain coverage, and tests proving AI cannot manufacture or upgrade deterministic proof. |
| **SCAN-02** | Execution and coverage distinguish tested from skipped, blocked, cancelled, failed, partial, or unobserved work. Missing telemetry never means clean or covered. | Parent/shard/ASM rollups degrade honestly on malformed or absent telemetry and agree for release-critical paths. |
| **SCAN-03** | Release-critical active work has effective time, request, payload, redirect, same-origin, cancellation, and mutation-restoration bounds. | Cancellation, scope, request-cap, and restoration tests plus candidate soak for the claimed release paths. |
| **SCAN-04** | Authenticated detector claims require server-observed accepted-auth and distinct-principal evidence; configured or attempted contexts alone cannot satisfy BOLA. | Current-fleet authenticated crAPI and Smart Juice Shop scorecards with explicit principal and build receipts. |
| **UPGRADE-01** | Required schema failures stop startup, and upgrade/rollback preserves configuration, results, and volumes. | Clean install, dirty upgrade, deliberate migration-failure, backup, and rollback acceptance. |
| **DEP-01** | Supported runtimes and no unaccepted high/critical production dependency findings. | UI/Python dependency audits, production build, browser smoke, and a recorded exception for any accepted finding. |
| **BUILD-01** | Release-critical tools, assets, templates, base images, source SHA, and final image digests are reproducible and auditable. | Immutable references/checksums, repeat-build inventory comparison, and published multi-architecture digests. |
| **VAL-01** | One exact frozen candidate passes every applicable release gate and current-fleet acceptance run. | Candidate SHA, uniform worker fingerprints, content-free artifacts, installer smoke, E2E, and benchmark evidence. |
| **REL-01** | Publication fails closed on the wrong SHA/version and the public docs describe the scoped product consistently. | Release workflow checks plus README, walkthrough, agent instructions, installer, API reference, release notes, and this checklist in agreement. |
| **FLEET-01** | Multi-node enrollment, broker/overlay transport, placement, leases, artifacts, lifecycle controls, and build truth fail closed across real hosts. A local test build must remain visible as drift, and enrollment throttling must not trust caller-controlled forwarding metadata. | Two-VPS physical acceptance for the supported topology, worker-loss/reclaim and duplicate-result probes, reusable-token exhaustion/revocation, remote placement, artifact verification, and a clean/current fleet receipt. |

The release owner may accept a candidate exception only with rationale, compensating control, owner,
and expiry. Known high/critical production dependency findings, untrustworthy proof, unsafe unbounded
execution, migration failure that permits startup, stale-fleet validation, and failed core DAST
acceptance should not be waived.

## Product and security items — reconciled to the 0.7.0 scope

The July UI/UX audit decisions that affect the release boundary are summarized here. The original
point-in-time audit remains available in Git history.

- **AUD-03 — proof/provenance authority — CLOSED under SCAN-01.** Deterministic evidence controls
  verified status and severity; AI verdicts are downgrade-only and cannot manufacture or upgrade a
  verified/high finding; a registry proof contract that is unmet can no longer persist
  `last_verification_verdict='exploited'` from a raw proof signal (the persisted-surface fix in
  `e35fe24`).
- **AUD-08 — attack-path semantics — CLOSED under SCAN-01.** A chain reaches the proven `chains[]`
  only when it is complete AND every step is reference-backed "observed"; otherwise it routes to
  `partial_chains` with per-step status. Observed/verified/partial/hypothetical cannot appear as one
  fully proven path.
- **AUD-02 — comprehensive nested-evidence secret redaction — DEFERRED to 0.8.0** per the scope
  boundary. Existing safeguards remain and documentation warns that result storage is sensitive; a
  typed redaction pipeline and old-data rewrite are not 0.7.0 gates.
- **AUD-10 — mandatory approval receipts for ordinary local DAST — DEFERRED beyond 0.7.0** under the
  trusted-operator boundary. Receipts, target binding, expiry, and the global enforcement toggle are
  already implemented; Deep Hunt requires them. Scope, same-target-host enforcement with explicit
  concrete origins, and active-testing
  warnings remain required for ordinary scans even when blanket receipt enforcement is disabled.
- **AUD-11 — deployment trust boundary — STANDING documented requirement.** Until ShakerScan has
  application authentication, docs and installer defaults bind to localhost and require Tailscale, a
  VPN, firewall, or an authenticated reverse proxy for remote access. Direct public exposure is
  unsupported.

## Known limitations accepted for 0.7.0

Recorded from the release-candidate adversarial audit (2026-07-21, three tracks over SCAN-01..04 /
UPGRADE-01). **None can produce a false-VERIFIED finding or a false "covered" coverage claim**; each
is conservative/fail-closed or latent, and is an owned decision rather than a silent gap:

- Registry `severity_rules` may remain advisory with the current wired active-family severity caps
  for `xss`, `sqli`, `bola`, `auth`, `mass_assignment`, and `jwt`, which cover the families that emit
  critical/high. No detector emits a name-only high today; a generic rule evaluator is deferred
  (per-predicate evidence mapping carries mis-cap regression risk with no confirmed benefit).
- The attack-chain "observed step" gate accepts a self-attested `evidence_ref`, but the
  `attack_chain_observations` field has no producer today, so every multi-step chain already demotes
  to `partial`. Latent only.
- `partial` is not a top-level registry execution status (it collapses to `failed`, never to
  `completed`); budget-exhausted work is reported honestly via `budget_exhausted_reason` telemetry.
- Non-active scans omit receipts for the active families (absent, not an explicit `skipped`); nothing
  derives "covered/clean" from receipt absence, and the e2e harness cross-checks receipt presence.

## Release-candidate validation

Run these against the exact candidate commit and retain content-free receipts/artifacts. Earlier
branch results are not release evidence; every applicable check must be re-run on the frozen
candidate SHA.

- [ ] Unit and contract suites pass on the candidate.
- [ ] UI production build and targeted browser QA pass at desktop and narrow viewport widths.
- [ ] `python3 scripts/generate_capability_inventory.py --check` passes.
- [ ] Every skill validates with the skill validator.
- [ ] Documentation links and the maintained documentation index pass.
- [ ] `make release-gates` passes. (The Release workflow now invokes the gates in the candidate
      scanner image before publish, so a wrong candidate cannot be published green.)
- [ ] The manual **E2E (full release gate)** workflow passes for the exact frozen candidate SHA
      against its pinned Juice Shop target and a uniform build-current fleet (`make e2e` is the
      equivalent local harness invocation).
- [ ] `make e2e-model-intake` passes the real public-model path, or the offline fixture is explicitly
      recorded as a limited substitute.
- [ ] A single current-fleet Smart Juice Shop scorecard is recorded.
- [ ] A current-fleet authenticated crAPI scorecard is recorded with distinct-principal and
      accepted-auth receipts; seeded detector-isolation evidence must remain labeled as seeded.
- [ ] Broker multi-node physical acceptance passes on the frozen candidate, including a bounded
      multi-use token, explicit revocation of unused enrollment capacity, node-specific placement,
      local-build drift visibility, lease loss/reclaim, and central artifact/result verification.
- [ ] WireGuard mode either passes its physical acceptance matrix or is explicitly excluded from
      the candidate's supported deployment boundary before release.
- [ ] Open P0/P1 audit items are fixed or explicitly accepted by the release owner with rationale.

The implemented-versus-planned E2E matrix is maintained in [`E2E_TEST_PLAN.md`](E2E_TEST_PLAN.md).
Benchmark reinterpretations and contamination corrections are preserved in the
[`Benchmark Integrity Ledger`](../results/benchmark-runs/INTEGRITY_LEDGER.md).

## Release automation and metadata

Complete these before creating a tag:

- [x] Correct OCI image license labels from MIT to Apache-2.0 in the GitHub release workflow and
      manual image publisher. (`release.yml` + `scripts/publish-images.sh` label Apache-2.0.)
- [x] Replace the hard-coded `0.5.7` GitHub release highlights with version-specific release notes.
      (`docs/releases/0.7.0.md`; the workflow refuses to publish without non-empty version notes.)
- [x] Make the Release workflow run the required documentation, release-gate, and candidate
      validation jobs. (`release.yml` builds the candidate scanner and API images, proves that only
      the API contains the pinned Docker client, and runs unit/contract + `release_gates.py` +
      `npm audit --audit-level=high` + inventory `--check` before publish.)
- [x] Publish a distinct API/control-plane image for both native architectures and keep the shared
      scanner/worker image free of Docker tooling. (`shakerscan/shakerscan-api` is built with
      `INSTALL_DOCKER_CLI=1`; release Compose uses it only for `api`.)
- [x] Restrict manual release dispatch to an approved release commit/branch and verify that the
      requested version matches `VERSION`. (Candidate SHA must equal checked-out HEAD and be an
      ancestor of `origin/main`; the tag must equal `v${VERSION}`.)
- [ ] Decide which slower benchmark/E2E jobs are scheduled and add the schedule before describing
      them as nightly.
- [x] Replace remaining absolute CLI help claims such as Full running “ALL security tests.”
      (User-facing help is clean; internal leftovers in an api.py comment and scanner.py argparse
      help were reworded in the pre-release hygiene sweep.)
- [ ] Use one product name, **ShakerScan**, in release titles and notes.

## Version and provenance

`VERSION`, the 0.7.0 release notes, and the pending `RELEASES.md` row are already prepared. After the
blocking work and candidate validation are complete:

1. Confirm `VERSION`, the version-specific release notes, and the pending
   [`../RELEASES.md`](../RELEASES.md) row still match the frozen candidate.
2. Merge the exact candidate to `main`.
3. Tag that commit and publish all four multi-architecture images: scanner/worker, API control
   plane, UI, and Model Intake signer.
4. Record the release commit and image digests in `RELEASES.md`.

Do not reuse `0.5.7`; it is already a published release.

## Hosted installer

The hosted bootstrap is a separate deployment artifact. Updating this repository does not deploy
`https://install.shakerscan.com`.

After the release commit is public:

- [ ] Deploy the current `install/index.sh`.
- [ ] Verify the root response is shell content with an appropriate text/shell content type.
- [ ] Confirm the installer fetches `skills/shakerscan`, `skills/research-agent`, and the full
      `.claude/commands/` set (including `research.md` and `deep-hunt.md`).
- [ ] Confirm Python 3 is installed and the runtime includes `scripts/shakerscan_mcp.py`,
      `scripts/local_planner_adapter.py`, `scripts/planner_evals.py`, and
      `api/command_arsenal.py`.
- [ ] Run a clean install into an empty temporary home.
- [ ] Confirm the installed runtime includes the Model Intake host/guest locks, fixed guest builder,
      Firecracker provisioner, runner service modules, and `.dockerignore` needed by the staging
      workflow.
- [ ] On an AMD64 KVM host, start the prebuilt Compose stack, stage the fixed guest through the API,
      install the runner with explicit operator confirmation, and require READY plus a guest
      self-test. On ARM64, require a clear `UNSUPPORTED_HOST` result for the x86-only runner tier.
- [ ] Inspect all four published manifests and prove that each contains `linux/amd64` and
      `linux/arm64`; prove `docker --version` succeeds in the API image and the Docker command is
      absent from the scanner/worker image.
- [ ] Verify `shakerscan doctor`, `shakerscan status`, `shakerscan mcp`, planner startup, agent
      launch, skill discovery, and one safe quick-scan submission.
- [ ] Verify an upgrade preserves `.env`, results, and Docker volumes.
- [ ] Confirm the installed instructions use public documentation links for files that are not part
      of the minimal runtime.

## Documentation sign-off

- [ ] README installation, first scan, UI map, terminology, safety boundary, and upgrade steps match
      the candidate.
- [ ] AGENTS and CLAUDE instructions match the live OpenAPI and installed package layout.
- [ ] The functionality reference generated inventory is current and its curated sections do not
      contradict the generated routes.
- [ ] Only one live roadmap exists; completed plans, prompts, audits, and stale screenshots are not
      shipped as maintained documentation.
- [ ] Walkthrough text matches the current UI.
