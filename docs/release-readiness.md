# ShakerScan 0.8.4 Release Readiness

**Status (2026-08-08):** candidate prepared, not published. Parallel DAST acceptance passed on
implementation commit `b86177f0`; the candidate source tree passed an exact-source rebuild/restart,
3,106 backend tests, 89 UI tests, the production UI build, all 14 named safety gates, locked
production dependency audits, generated-inventory validation, installer smoke, and browser QA. A
final tag still requires the remaining physical Fleet/upgrade and frozen-SHA publication gates below.
The stable installer remains on 0.8.3 until published multi-architecture manifests are verified.

This is the single live release checklist. Code, migrations, generated inventories, runtime
receipts, and fresh test output are authoritative. Earlier branch results are useful for finding
regressions but do not satisfy a frozen-candidate gate.

## Supported product boundary

ShakerScan 0.8.4 is a trusted-operator, self-hosted security scanner.

- Localhost is the default. Remote UI/API access must remain behind Tailscale, a VPN, a firewall, or
  an operator-managed authenticated reverse proxy. Direct public exposure is unsupported.
- ShakerScan does not provide application login, users, roles, tenant isolation, or protection from
  another person who can access its process, API, UI, database, Docker socket, configuration, or
  result files.
- Results can contain sensitive request, response, authentication, payload, model, and evidence
  data. Comprehensive historical secret rewriting is not promised.
- Active DAST requires target authorization. Deep Hunt always requires a target-bound, expiring
  approval; ordinary local scans use the configured approval policy and visible active-test warning.
- Model Intake is release-gated for deterministic static review, artifact/report generation, and
  the opt-in AMD64 Linux/KVM Firecracker tier. Unsupported formats, incomplete evidence, unavailable
  required tools, or missing runtime qualification fail closed. Technical review does not replace
  publisher trust, privacy, legal, business, or deployed-data-plane approval.
- Fleet production support is the outbound-only HTTPS `broker` transport. Built-in WireGuard remains
  preview code outside the 0.8.4 support boundary until it passes a separate physical acceptance
  matrix.
- AI Gate remains preview in this release.

## Stop-ship contract

| ID | Requirement | Required evidence |
|---|---|---|
| **SCAN-01** | Deterministic evidence controls verified status and high-impact severity. AI, labels, and caller state cannot manufacture proof. | Adversarial promotion, replay, severity-cap, and no-phantom-chain tests. |
| **SCAN-02** | Coverage distinguishes completed, skipped, blocked, cancelled, failed, partial, and unobserved work. Missing telemetry is never clean coverage. | Parent/shard/ASM rollup and malformed/absent telemetry tests. |
| **SCAN-03** | Active work enforces scope, time, request, payload, redirect, cancellation, and mutation-restoration bounds. | Contract tests plus current-build physical scans. |
| **SCAN-04** | Authenticated detector claims require server-observed accepted authentication and distinct-principal proof. | Current-fleet authenticated benchmark receipts. |
| **MODEL-01** | Model acquisition, scanners, reports, policy, signing, and Firecracker evidence fail closed and remain bound to one immutable subject. | Full suites plus multiple real public-model runs on AMD64 KVM through UI, API, and agent skill paths. |
| **MODEL-02** | Reports are decision-first, readable, and complete: controls, scanner details, CVEs, licenses, packages, network attempts, runtime evidence, gaps, and artifacts agree. | Browser QA and programmatic cross-checks of JSON, HTML, SARIF, AIBOM, SPDX, CycloneDX, license BOM, and notices. |
| **FLEET-01** | Broker enrollment, placement, leases, artifacts, lifecycle controls, credentials, and build truth fail closed across real Linux hosts. | Two-node physical acceptance, exact-node placement, scaling, drain/resume, fault/reclaim, dedupe, artifact, token, and public-store isolation receipts. |
| **UPGRADE-01** | Required schema failures stop startup; clean and repeated dirty upgrades preserve configuration, results, volumes, targets, findings, and Fleet identity. | Installer/upgrade/rollback smoke and deliberate migration-failure tests. |
| **DEP-01** | Supported runtimes contain no unaccepted high/critical production dependency findings. | Locked Python audit, production npm audit, image/tool inventory, and documented exceptions if any. |
| **BUILD-01** | Release-critical tools, rules, templates, images, source SHA, and final digests are reproducible and auditable. | Candidate image self-tests, inventory comparison, labels, SBOM/provenance, and published manifest inspection. |
| **VAL-01** | One exact frozen commit passes every applicable gate on a uniform current fleet. | Candidate SHA and content-free validation receipts. |
| **REL-01** | Publication fails closed on the wrong SHA/version; public docs describe the product consistently. | Workflow checks, docs/link checks, tag/version match, release notes, and post-publish validation. |

Do not waive untrustworthy proof, false-clean coverage, unsafe unbounded execution, migration startup
after a required-schema failure, stale-fleet evidence, failed core DAST acceptance, failed Model
Intake containment/evidence binding, failed Fleet lease isolation, or unaccepted critical/high
production dependency findings.

## Frozen-candidate validation

Run every item against the exact commit intended for `v0.8.4`.

### Code, dependencies, and builds

- [ ] Full Python unit/contract suite passes without hiding release-critical modules behind skips.
- [ ] UI tests and production build pass; `npm audit --omit=dev --audit-level=high` is clean.
- [ ] Locked Python dependency audit is clean or has an explicit time-bounded exception.
- [ ] `python3 scripts/generate_capability_inventory.py --check` passes.
- [ ] Documentation index and links pass.
- [ ] Every installed agent skill validates.
- [ ] `make release-gates` passes.
- [ ] Scanner, API, UI, signer, and Firecracker guest candidate builds pass self-tests.
- [ ] The API image contains the pinned Docker CLI; scanner/worker images contain no Docker client.
- [ ] Clean installer, duplicate dirty upgrade, migration failure, backup, and rollback tests pass.

### Web scanning and agent workflows

- [ ] The manual full E2E workflow passes on a uniform current fleet.
- [ ] One current-fleet Smart Juice Shop benchmark meets its scorecard.
- [ ] One authenticated crAPI benchmark records accepted distinct-principal evidence.
- [ ] Deep Hunt and agent skill smoke tests prove bounded submission, status, evidence, and refusal
      behavior without bypassing deterministic proof.
- [ ] Desktop and narrow-width browser QA covers dashboard, scan creation/detail, findings, ASM,
      Deep Hunt, settings, errors, loading states, and navigation.

### Model Intake

- [ ] Local macOS fixture E2E passes and reports Firecracker as unsupported without presenting that
      host limitation as a model failure.
- [ ] Public-model acquisition E2E passes with complete and intentionally capped inputs; truncation
      is never mislabeled as a hash mismatch.
- [ ] On the AMD64 KVM host, all three maintained real-model acceptance cases run through automatic
      UI, API, and agent skill paths using the frozen commit.
- [ ] At least one safetensors case and two unsafe `.bin` conversion cases exercise static scans,
      dependency resolution, conversion/equivalence, Firecracker calibration, repeat inference,
      network/resource telemetry, evidence freeze, and report generation.
- [ ] Automatic and Advanced/manual UI paths are tested at desktop and narrow widths, including
      runner readiness/setup guidance, progress, restart-safe resume, failure recovery, and exports.
- [ ] Report cross-check confirms that executive outcome, control matrix, detailed scanner tables,
      severity-colored CVEs, packages/licenses, network attempts, runtime receipt, artifacts, and
      external follow-up agree across formats.
- [ ] No documented example model name is embedded in provider-neutral product scope or policy.

### Fleet

- [ ] Control plane and at least two broker nodes run the exact frozen source/image identity.
- [ ] Preflight proves artifact PUT/GET/DELETE, uniform transport, private Redis/PostgreSQL, and
      isolated lease reclaim/duplicate completion.
- [ ] Bounded join-token use, exhaustion, revocation, credential rotation, and revoked-node refusal
      pass without exposing secrets in logs or receipts.
- [ ] Fleet-wide scaling, per-node scaling, drain/resume, digest-pinned rollout, and state/error
      recovery pass and restore the original desired capacity.
- [ ] Automatic, remote-fleet, control-plane-local, and exact-node placement produce durable
      execution snapshots and centralized results/artifacts.
- [ ] Physical worker loss causes bounded reclaim; stale ownership cannot heartbeat, acknowledge,
      upload artifacts, or complete a duplicate result.
- [ ] Finding dedupe, parent/shard merge, cancellation, and centralized artifact verification pass
      across nodes.
- [ ] Fleet UI with and without the session-only operator token reports authoritative locked,
      loading, empty, healthy, unhealthy, drift, work, event, and lifecycle states.
- [ ] WireGuard remains labeled preview and is not counted as accepted Fleet evidence.

## Publication

After all frozen-candidate gates are green:

1. Confirm `VERSION`, `docs/releases/0.8.4.md`, and the pending `RELEASES.md` row agree.
2. Merge the exact candidate to `main` without adding an untested merge-only change.
3. Wait for required `main` checks, then create annotated tag `v0.8.4` on that exact commit.
4. Push the tag and require the Release workflow to build/publish scanner, API, UI, and signer for
   `linux/amd64` and `linux/arm64`.
5. Verify manifest architectures, OCI labels, source revision, image digests, API Docker CLI,
   scanner Docker absence, and GitHub release notes.
6. Replace `pending candidate` in `RELEASES.md` with the tagged commit and published digests in a
   provenance-only follow-up.

## Post-publish installation and cleanup

- [ ] Deploy and verify the hosted installer separately; repository/image publication does not
      update `install.shakerscan.com`.
- [ ] Clean-install `0.8.4` into an empty home and verify doctor, status, UI/API, MCP, agent launch,
      skills, one Quick scan, and Model Intake readiness.
- [ ] Upgrade a stateful installation and verify preserved targets, scans, findings, settings,
      evidence, and Fleet credentials.
- [ ] Retest the exact released commit locally on macOS and on the Linux acceptance hosts.
- [ ] Remove temporary ShakerScan test deployments and credentials from the acceptance hosts.
- [ ] Terminate the temporary KVM EC2 instance only after its final Model Intake and Fleet evidence
      is retained.
- [ ] Do not destroy user-owned VPS instances unless the owner separately confirms that permanent
      provider-level deletion is intended.
