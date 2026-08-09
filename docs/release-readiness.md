# ShakerScan 0.8.17 Release Readiness

**Status (2026-08-09):** 0.8.17 is a pending corrective candidate. The literal clean 0.8.16
two-VPS acceptance proved broker enrollment, three-way shard execution, physical worker loss and
reclaim, central artifacts, and datastore isolation, but exposed that official scanner/API builds
did not pass the release version into the Dockerfile. A completed scan therefore reported
`scanner dev`. Version 0.8.17 must pass CodeQL, the frozen full-stack E2E, complete release
validation, native multi-architecture publication, independent manifest/label checks, and a second
literal clean two-VPS acceptance before the stable channel advances.
That acceptance also found a long-running broker Model Intake scan could starve its asyncio
heartbeat task and be reaped after five minutes despite a healthy worker. The candidate now uses a
dedicated native lease-heartbeat thread and includes a blocking-work regression test.
Version 0.8.9 passed CodeQL, all frozen gates, dependency audits, clean/dirty upgrade smokes,
multi-architecture publication, and independent manifest checks. Its bounded clean-build retry also
recovered the registry boundary that stopped 0.8.8. The stable channel was deliberately not advanced:
the subsequent whole-product audit found that `shakerscan agent`, the installed Claude session hook,
and `shakerscan mcp` still defaulted to loopback even when `--remote` intentionally bound the API only
to Tailscale. That made a healthy remote install appear unavailable to those agent-facing paths.

The 0.8.15 candidate carries forward 0.8.9's narrow Redis `NOGROUP` route-lifecycle handling and
routes installed agent/MCP entry points through the persisted host bind. It also corrects installed
documentation links and remaining detailed-skill loopback examples for engineering files omitted
from the minimal curl runtime, and reconciles the human architecture prose with the current Redis
Streams and API-controller implementation. The 0.8.10 workflow was cancelled before publication
when those final detailed-skill examples were found. The 0.8.11 workflow was cancelled before
publication when the final host-security audit found that standalone and Fleet launchers made the
Model Intake sandbox evidence queue world-writable. Version 0.8.15 replaces that permission parity
with a stable non-root image identity, an operator-identity mapping on non-root/Desktop installs,
and an owner-only `0700` queue.
The 0.8.12 clean Linux/root suite then rejected a `Path.chown` call that the non-root macOS test path
could not reach. Version 0.8.15 uses `os.chown`, adds a direct root-branch regression, and must repeat
the complete clean-root suite. Full
frozen-candidate gates and clean published-image acceptance remain required before advancing
`install/STABLE_VERSION`.

Version 0.8.13 passed those frozen gates and published correct multi-architecture images. Its first
literal clean curl installation was healthy, but converting the fresh standalone control plane to
a broker fleet exposed a startup-order defect: the API became healthy just before bundled MinIO's
initializer created the artifact bucket, and the one-shot write probe returned HTTP 503 and rolled
the conversion back. Version 0.8.14 implemented a bounded retry, then stopped during pre-publication
validation because a runtime regression test hardcoded the historical stable version `0.8.7`.
No 0.8.14 images were published. Version 0.8.15 carries the Fleet fix, validates the stable channel
against its published ledger row instead of a fixed version, still fails closed on a genuinely
unavailable bundled or external S3 plane, and covers both a transient HTTP failure and a not-ready
probe response.

The 0.8.15 clean acceptance proved the managed broker control plane and MinIO readiness fix under a
literal hosted-installer deployment. It also exposed three defects that unit-only release gates did
not make visible: broker scan reports used the fallback `dev` label, a safetensors-selected Model
Intake review ran ModelScan against only that preferred artifact while the immutable snapshot also
contained a legacy PyTorch `.bin`, and the default DAST scan list still displayed Model Intake
evidence rows. Version 0.8.16 added the correct Dockerfile identity input, scanned every serialized
alternate in the snapshot, and separated the default DAST and Model Intake lists while preserving
an explicit API opt-in for evidence workflows. Its clean acceptance then proved the latter changes
and exposed the missing official build argument. Version 0.8.17 supplies that argument to both
scanner and API images and reads it back from every native release artifact before publication.

### 0.8.8 unpublished-candidate evidence motivating the build hardening

- Metadata resolution, source checkout, generated documentation, and the frozen installer smoke
  passed on exact candidate `0edc1b720dc98a49c90ff12b4fded0e347f7bb66`.
- The clean scanner build downloaded only 5 MiB of Playwright's 821 MiB checksum-pinned base layer
  over 23 minutes before the registry connection reset. The build exited nonzero; API/UI/signer
  builds, audits, publication, GitHub Release, and stable promotion did not run.
- The 0.8.9 workflow retries only whole deterministic build commands, retaining successful BuildKit
  layers between attempts. Four exhausted attempts still stop publication, and image contents,
  source revision, and base-image digest remain unchanged.

### 0.8.7 post-publish evidence motivating this patch

- The hosted installer populated empty homes on both VPSs from immutable `v0.8.7`, selected only
  published 0.8.7 images, and reached healthy, fingerprint-current standalone state.
- Managed HTTPS initialized with a publicly trusted certificate, and a short-lived single-use token
  enrolled the broker worker without Redis, PostgreSQL, or object-store credentials.
- The remote node reached healthy state with three active non-local-build workers and zero image or
  desired-state drift.
- Exact-node Smart coverage against the authorized Honey target materialized its discovery and
  parallel work, and all three replicas leased work concurrently under the fair-share allocator.
- An empty placement route was pruned while another worker polled it; `lease_job` propagated Redis
  `NOGROUP` and the broker endpoint returned HTTP 500. This is a release blocker, not accepted Fleet
  evidence.

### 0.8.5 post-publish evidence motivating this patch

- The literal hosted installer populated empty homes on both VPSs from immutable `v0.8.5` runtime
  files, pulled only 0.8.5 images, and reached healthy API, UI, PostgreSQL, Redis, signer, sandbox,
  and current local-worker state.
- Managed HTTPS Fleet initialization at `m.shakerscan.com` succeeded, and a short-lived single-use
  token enrolled the clean worker without installing Redis, PostgreSQL, or object-store credentials.
- The joined node reached healthy, current, non-local-build state on the exact published scanner
  digest and reconciled from one to three active remote workers.
- Exact-node Smart coverage submission created its discovery child, global backbone, and three
  endpoint children. The backbone leased the remote node, but its 1,000-request reservation consumed
  the whole default domain cap; the other children remained queued. The parent and all four children
  cancelled cleanly. This is a release blocker, not accepted parallel evidence.

### 0.8.4 post-publish evidence motivating this patch

- The literal hosted installer command populated empty ShakerScan homes on control-plane and worker
  VPS hosts, selected `0.8.4`, pulled only the published images, and reached healthy API, UI,
  PostgreSQL, Redis, and current-worker state.
- Broker Fleet enrollment over managed HTTPS joined one remote node without distributing datastore
  credentials. Scaling reached three current remote workers; exact remote placement exercised three
  concurrent shard workers; removing one worker container caused bounded agent reconciliation back
  to desired capacity. This is control-plane-plus-one-node evidence, not the separate two-remote-node
  matrix required by **FLEET-01**.
- Automatic Model Intake completely acquired the pinned public
  `hf-internal-testing/tiny-random-bert` revision, persisted centralized artifacts and findings, and
  produced JSON, HTML, and SARIF reports. Runtime qualification correctly remained `INCOMPLETE` on
  a host without hardware virtualization. The static report exposed ModelScan's missing `h5py`
  extra on the repository's TensorFlow HDF5 artifact instead of falsely passing it.
- A bounded Smart coverage scan of the authorized Honey target ran its backbone and two endpoint
  shards concurrently on three distinct broker workers and merged their results centrally. Its
  deliberate two-minute budget produced an honest partial outcome. The run also exposed the Nuclei
  availability-message defect; actual unmetered Nuclei traffic remained blocked by the enforced
  request budget.

This is the single live release checklist. Code, migrations, generated inventories, runtime
receipts, and fresh test output are authoritative. Earlier branch results are useful for finding
regressions but do not satisfy a frozen-candidate gate.

## Supported product boundary

ShakerScan 0.8.17 is a trusted-operator, self-hosted security scanner.

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
  preview code outside the 0.8.17 support boundary until it passes a separate physical acceptance
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

Run every item against the exact commit intended for `v0.8.17`.

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

1. Confirm `VERSION`, `docs/releases/0.8.17.md`, and the pending `RELEASES.md` row agree.
2. Merge the exact candidate to `main` without adding an untested merge-only change.
3. Wait for required `main` checks, then create annotated tag `v0.8.17` on that exact commit.
4. Push the tag and require the Release workflow to build/publish scanner, API, UI, and signer for
   `linux/amd64` and `linux/arm64`.
5. Verify manifest architectures, OCI labels, source revision, image digests, API Docker CLI,
   scanner Docker absence, and GitHub release notes.
6. Replace `pending candidate` in `RELEASES.md` with the tagged commit and published digests in a
   provenance-only follow-up.

## Post-publish installation and cleanup

- [ ] Deploy and verify the hosted installer separately; repository/image publication does not
      update `install.shakerscan.com`.
- [ ] Clean-install `0.8.17` into an empty home and verify doctor, status, UI/API, MCP, agent launch,
      skills, one Quick scan, and Model Intake readiness.
- [ ] Upgrade a stateful installation and verify preserved targets, scans, findings, settings,
      evidence, and Fleet credentials.
- [ ] Retest the exact released commit locally on macOS and on the Linux acceptance hosts.
- [ ] Remove temporary ShakerScan test deployments and credentials from the acceptance hosts.
- [ ] Terminate the temporary KVM EC2 instance only after its final Model Intake and Fleet evidence
      is retained.
- [ ] Do not destroy user-owned VPS instances unless the owner separately confirms that permanent
      provider-level deletion is intended.
