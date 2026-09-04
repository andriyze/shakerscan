# ShakerScan 2.2.0 plan: trustworthy upgrades, a complete fifth image, and DAST depth

**Status (2026-09-04): planned source changes implemented except DAST-1; certification pending.**
The base is published 2.1.0 (`0723cbb5` on `main`); implementation is on
`fix/start-secrets-before-rotation`. No test, build, image scan, or target Scan was run while
completing the branch because the operator explicitly prohibited them. Static syntax, generated
contract, generated image-inventory, and generated installer-manifest checks are preparation only
and are not release evidence.

### Implementation ledger

| Area | Source status | Certification still required |
|---|---|---|
| A1–A6 installer/upgrade | Implemented in `7957291e`, `230c1b4f`, `e4350771`, `9ec647ea`, and `1fecb57e`. | Installer and both supported-baseline upgrade smokes. |
| IMG-1–IMG-3, B1, B2, D3, UPG-1 | Implemented in `7b54a800`, `3c476c19`, `9c1592bc`, `a949377d`, `9ec647ea`, `a867a069`, and `d2c59e33`. | Exact-SHA five-image startup, pool readiness, and both upgrade receipts. |
| B3, B4, B6 | Complete-image scanning is enforced (`4e994037`), Trivy provenance/refresh is implemented (`88d93d6f`), and the stale build-tool waivers are removed (`a59cd213`). | A fresh candidate image scan must prove the now waiver-free image clean. |
| API-1, API-2 | Execution inventory is frozen (`ba1ee634`); the API is slim and non-root (`c07abdb1`). | Image-content and installed Model Intake staging gates. API-3 remains a 2.3.0 design item. |
| DAST-2–DAST-5 | Profile ladder (`6200743f`), proportional batches (`7ca5bad2`), bounded append-only continuation (`ab77a262`, `6185a4bb`), and authenticated browser state (`46de445b`) are implemented. | Current-fleet authenticated Juice Shop/crAPI measurements and the DAST-8 exit gate. |
| DAST-6, DAST-7 | Body/spec and browser-XSS paths were already present in the 2.1.0 history, including PRs #59 and #60 and their later correctness fixes. | Re-measure the named fixture expectations; source presence is not proof of recall. |
| H-10/H-11, MI-6 | Installed CLI targeting is fixed (`926c074d`); trust-anchor lifecycle is a hard gate (`708cbe03`). | Installed-stack execution of those named checks. |
| D1, D2 | Exact-SHA image reuse and image-affecting path classification are implemented in `8dbfc6f3` and `fead8f7d`. | Candidate workflow execution and attestation lookup. |

DAST-1 is not complete. Its proposed premise—“settle from the transaction ledger the worker
already keeps”—is false for external child processes: their HTTPS is opaque behind the pinned
SOCKS transport and never enters the in-process HTTP archive. HTTPX's one-request contract and
Nuclei's explicit cumulative counter settle exactly. Katana, Dalfox, SQLMap, and FFUF retain the
full HTTP hold when no authoritative counter exists. TCP connection counts are not HTTP request
counts and must not be substituted. Completing DAST-1 therefore requires a separately reviewed
per-tool counter or a target-bound TLS-aware metering design; until then continuation may reuse
actual wall surplus but must not refund unknown request authority.

DAST-0 and DAST-8 are measurements, not missing source implementation. D5 is a GitHub UI cleanup.
The release metadata, candidate, publication, and stable promotion remain intentionally unstarted.

2.2.0 has three themes, in priority order:

1. **Upgrades that cannot eat an install.** Every installer and startup path that bit the VPS on
   2026-09-04 gets a fail-closed guard and a release gate (A1–A6).
2. **Five images, everywhere.** The Model Intake image becomes first-class in lifecycle, health,
   fleet overlays, upgrade certification, and the vulnerability gate (B1–B6, audit findings 1–4).
3. **DAST depth restored.** Profiles regain the wall the 0.8.x smart scan had, the plan keeps
   spending until the ceiling or the work runs out, and the authenticated crawl works for
   token-in-localStorage applications. Exit is the Juice Shop bar, not a waiver (C1).

The API-image privilege boundary (audit finding 5) starts in 2.2.0 and finishes in 2.3.0.

## 1. Audit verdict

Every item was checked against source. "Agree" means the mechanism described is what the code does.

### A. Upgrade and installer path

| Item | Verdict | Evidence |
|---|---|---|
| A1 datastore ensure runs before the signer ensure | Agree, fixed on branch | `scanner.sh` `prepare_runtime_files` now ensures operator, session, signer, then datastore; `tests/test_start_secret_ordering.py` reproduces the incident (4 passed). Correction: the order has been wrong since the signer ensure was added in the 0.8 line (`cf9d3f9e`, 2026-07-29), not since 2.0.0. |
| A2 installer creates a second install beside an existing one | Agree, half fixed | Guard on branch (`SHAKERSCAN_ADOPT_EXISTING_DATA=1` override, tested). `install/index.sh` still defaults to `~/.shakerscan` and never inspects Docker for another project directory. |
| A3 installer over a source checkout keeps local-build mode | Agree | `configure_runtime_mode` picks local whenever `has_local_source_tree` is true, marker or not; the installer never calls `record_runtime_mode` and never passes `--prebuilt`; `scanner.sh` never reads `release-image-lock.env` (only the generated launcher does). |
| A4 signer role init has no retry | Agree | `db/configure-model-intake-signer-role.sh` is one `psql` under `set -eu`; the compose service has `restart: "no"`; postgres health is `pg_isready`, which does not prove password auth. |
| A5 only `install/STABLE_VERSION` is a certified upgrade base | Agree | `scripts/upgrade_smoke.sh` refuses any `BASELINE_REF` other than `v$STABLE_VERSION`. 0.8.18 → 2.1.0 crosses two releases of migrations untested. |
| A6 no release gate covers installer-driven upgrades | Agree | `scripts/installer_smoke.sh` is a clean install with `SHAKERSCAN_START=0`; `upgrade_smoke.sh` drives containers directly. |

### B. 2.1.0 regressions and gaps from the split

| Item | Verdict | Evidence |
|---|---|---|
| B1 fleet overlays run the sandbox on the worker image | Agree | `docker-compose.worker.yml:36-59` and `docker-compose.broker-worker.yml:32` define `model-intake-sandbox` on `FLEET_WORKER_IMAGE`; it runs `model_intake_sandbox.py --serve`, which needs `/opt/model-intake-tools`. Nothing dispatches Model Intake to fleet nodes, so the service is dead weight that fails on start, not a data-path bug. |
| B2 Model Intake placement on fleet nodes is unguarded | Agree, mechanism differs | Both submit sites call the generic `enqueue_job`, which routes any payload carrying `placement` to `model_intake_jobs:route:<digest>`; the option sanitizer strips approval keys but not `placement`; the only consumer of the base queue is the control-plane worker. A placement-bearing submission queues forever. |
| B3 Model Intake toolchain is not vulnerability-scanned | Agree | `release-candidate.yml:882-887` skips `/opt/model-intake-tools`, `/opt/tools/trivy`, `/opt/tools/osv-scanner`. |
| B4 waivers expire 2026-12-01 | Fixed in source, pending image gate | The pip-audit lock already carries patched `msgpack==1.2.1`; the image now removes unneeded venv-seeded setuptools and the waiver file is empty. A candidate scan must confirm the built image. |
| B5 API image is the scanner image plus a Docker client | Agree | `scanner/Dockerfile.api:6` is `FROM ${SCANNER_RUNTIME_IMAGE}`; no `USER` in any of the three Dockerfiles; `docker-compose.release.yml:212` mounts `/var/run/docker.sock`. `/workers` also reads that socket, so the socket cannot simply be removed. |
| B6 Trivy database baked at build time | Agree | `scanner/Dockerfile.model-intake:70-77`. |

### C. Declared debt

| Item | Verdict | Evidence |
|---|---|---|
| C1 DAST quality bar | Agree on the bar, corrections on two root causes | 2.1.0 certified with `complete_dast_quality_bar` waived (measured 0.44). Root cause 1 (body candidates never funded) is partly outdated: thorough now reserves 780 s for the SQLi slice and the benchmark policy sets `allow_state_changing_http: true`, so one body attempt fits; the Juice Shop login remains unproven and must be re-measured. Root cause 3 names H-18, but H-18 is the Hunt adaptive-XSS check in `tests/e2e/run_e2e.py:1982`; the Scan's `prove.xss` was skipped `not_applicable` on the live run because the verifier produced nothing to prove. The crawl root cause is confirmed and already partly addressed by open PR #59. |
| C2 H-10, H-11, MI-6 | Agree | `tests/e2e/run_e2e.py:1455-1517`, `tests/release_preservation_matrix.json:217-218`. |

### D. Release pipeline and operations

| Item | Verdict | Evidence |
|---|---|---|
| D1 certification rebuilds everything | Agree | `release-candidate.yml`: `validate` builds scanner and API (lines 221-235); `build-runtime`, `build-ui`, `build-signer` build again; no job consumes the `build-on-main` candidate manifests. |
| D2 build-on-main runs on every non-docs push | Agree | `paths-ignore` covers only docs, LICENSE, `.gitignore`, rulesets. |
| D3 freshness ignores specialized pools | Agree | `_is_local_scan_worker_container` accepts only compose service `worker`; `/health` exposes device and agent-tool readiness but no Model Intake pool; `verify_specialized_worker_identity` checks agent and device only. |
| D4 fingerprint hashes `/opt/model-intake-locks` | Agree, low priority | `scanner/scanner_tools/build_fingerprint.py:142`; `scanner/Dockerfile:201-207` keeps the locks for uniformity. |
| D5 stale CodeQL workflow record | Not verifiable from source | GitHub UI only. |

### The second audit (2.1.0 split)

| Finding | Verdict | Evidence |
|---|---|---|
| 1. Fifth image missing from lifecycle | Agree | `scanner.sh:1443-1461` derives scanner, API, UI, signer only; `MODEL_INTAKE_IMAGE` appears nowhere in `scanner.sh`; `pull_prebuilt_images` pulls four services and its cache fallback checks four images; compose defaults the fifth to `:latest`. Only the curl launcher exports the locked digest. |
| 2. Model Intake worker identity never consumed | Agree | Registry `shakerscan:model_intake_worker_build` is written (`worker_queue_policy.py:17`) and read by nothing; `/health` and startup verification omit it. |
| 3. Vulnerability gate excludes the new payload | Agree | Same as B3. |
| 4. Upgrade certification does not test the fifth image | Agree | `release-candidate.yml:1046-1058` and `upgrade_smoke.sh` pass, check, and receipt three images. |
| 5. Web-facing API is a privileged scanner image with the socket | Agree | Same as B5. |
| 6. Payload split, not execution isolation | Agree | `Dockerfile.model-intake:10` is `FROM ${SCANNER_RUNTIME_IMAGE}`. |

### E. Carried items (not re-verified this session)

ASM soft-404 phantom garbage collection, Hunt Tier-0 secret classes, `--auth` benchmark silently
anonymous when `host.docker.internal` is unreachable, stray host `next start` on port 3000. They are
triaged in section 3.8, not fixed by 2.2.0 unless noted.

### New findings from this audit

| Finding | Evidence |
|---|---|
| Thorough's tool-wall ceiling exceeds its wall ceiling | `BUDGET_PROFILES["thorough"]` is 5,400 s wall but 7,200 s tool wall; the tool wall can never be spent. |
| UI profile labels disagree with the contract | `ui/src/app/scan/new/page.tsx:33` and `ui/src/app/schedules/page.tsx` say thorough is 60 minutes; the contract says 90. |
| A thorough Scan ends with most of its ceiling unspent | Section 2. |
| Settled HTTP usage equals the reservation | On the live run `verify.xss` settled 240 of 240 reserved requests in 2 s of wall, `verify.sqli` 480 of 480 in 2 s, `discover.browser_crawl` 600 of 600, `active.templates` 4,000 of 4,000. Either the adapters report reservations as actual traffic, or the attempts failed instantly and were charged their floor. Both hide surplus from continuation and make a family read `success` on work that did not run. |
| `scanner.sh rebuild` refreshes the sandbox and signer but not `model-intake-worker` | `scanner.sh:2646-2673`. |

## 2. Why Scans feel shallow: the numbers

The pre-2.0.0 smart scan and the 2.1.0 Scan both use profiles. The ceilings moved a long way.

| Profile | 0.8.x smart wall | 2.1.0 wall | 2.1.0 HTTP requests | 2.1.0 tool wall |
|---|---|---|---|---|
| fast | 30 min | 5 min | 1,000 | 3 min |
| balanced (default) | 90 min | 20 min | 5,000 | 15 min |
| thorough | 240 min | 90 min | 20,000 | 120 min (unreachable) |
| exhaustive | 600 min | none | | |

Source: `v0.8.9:scanner/constants.py` smart block; `api/scan/contracts.py:41-45`.

The 0.8.x balanced smart scan also crawled to depth 4 over 1,000 URLs with 40 browser pages, spent
900 s on active testing across 50 endpoints, and tested BOLA on 100 endpoints. The 2.1.0 balanced
Scan gets 200 browser actions and 2,000 endpoints on paper but only 15 minutes of tool wall to use
them.

The ceiling is not what ends a Scan today. The live thorough Scan of `honey.shakerscan.com` on
2026-09-04 (`995014c4`) shows what does:

| Dimension | Ceiling | Used |
|---|---|---|
| wall | 5,400 s | 1,389 s (26%) |
| HTTP requests | 20,000 | 7,898 |
| tool wall | 7,200 s | 1,459 s |
| state-changing requests | 2,000 | 0 |
| browser actions | 1,000 | 0 |

Coverage was `partial`. `passive.templates` timed out at exactly its 240 s slice, `active.templates`
at exactly its 600 s slice, their single continuation round (`.001`) timed out again, and the Scan
finalized with 67 minutes of wall it was allowed to spend. Every batch shape in
`api/scan/action_plan.py` `_BATCH_PROFILES` is an absolute number that was tuned against a 3,600 s
ceiling, and `build_discovery_continuation_manifests` runs once. The profile ceilings are effectively
decorative above what the fixed slices add up to.

So the user's read is right: the Scan is not balanced. It is bounded by per-batch slices and one
continuation round, and the slices were sized for a wall that has since doubled.

## 3. Workstreams

Each item names the files, the test that must fail without the fix, and the gate that proves it.

### 3.1 WS1 Installer and upgrade path (A1–A6)

| ID | Change | Files | Test / gate |
|---|---|---|---|
| A1 | Merge the branch: ensure order, `SHAKERSCAN_ADOPT_EXISTING_DATA` guard, upgrade doc. | `scanner.sh`, `docs/upgrade-and-rollback.md`, `tests/test_start_secret_ordering.py` | Already green (4 tests). |
| A2b | Installer detects another install directory before downloading: query `docker ps -a --filter label=com.docker.compose.project=<project>` for `com.docker.compose.project.working_dir`, and `docker volume ls` for `<project>_postgres-data`. If a different directory owns them and `SHAKERSCAN_HOME` was not set, print the exact `SHAKERSCAN_HOME=<dir> curl ... \| sh` line and exit 1. | `install/index.sh` and `install/index.html` (identical payload, both must change), `scripts/generate_install_manifest.py` (regenerate `install/MANIFEST.sha256`) | New case in `scripts/installer_smoke.sh` with a stub `docker` on `PATH` that reports a foreign working dir. |
| A3 | Installer records `prebuilt` via `record_runtime_mode` after `commit_staged_downloads` and starts with `--prebuilt`. `scanner.sh configure_runtime_mode` reads `release-image-lock.env` from `SCRIPT_DIR` when present: default to prebuilt even over a source tree, export the five images unless already set, and warn when a source tree is being ignored. | `install/index.sh`, `install/index.html`, `scanner.sh` | Bash-extraction test in the style of `test_start_secret_ordering.py`: lock file present plus source tree resolves prebuilt and exports `MODEL_INTAKE_IMAGE`; explicit `--local`/`SCANNER_LOCAL_BUILD` still wins. |
| A4 | Bounded retry in the signer init: loop up to 30 × 2 s on `psql -c 'select 1'` with the scanner password before running the role script; exit 2 with a clear message after the bound. | `db/configure-model-intake-signer-role.sh` | `tests/test_signer_role_init.py` running the script against a stub `psql` that fails N times then succeeds; fails without the loop. |
| A5 | Upgrade baseline matrix: certify from `install/STABLE_VERSION` and from a pinned `install/OLDEST_SUPPORTED_UPGRADE_BASE` (proposal: `0.8.18`, whose digests are in `RELEASES.md`). Document the minimum base and the two-step path for anything older. | `scripts/upgrade_smoke.sh` (accept the second baseline), `release-candidate.yml` (matrix), `docs/upgrade-and-rollback.md` | Both upgrade receipts attached to the candidate receipt; `certify_release_receipt.py` requires both. |
| A6 | Installer-upgrade smoke with three cases: existing directory in place; new directory beside the old volumes (expect the A2 refusal); source checkout with a `local` marker (expect `prebuilt` recorded and the lock honored). Uses the existing `SHAKERSCAN_RAW_BASE=file://` harness and a stub `docker`. | new `scripts/installer_upgrade_smoke.sh`, `Makefile` target, `release-candidate.yml` `validate` job | Gate is red without A2b/A3. |

### 3.2 WS2 Five images, everywhere (audit 1, 2, 4; B1, B2; D3, D4)

| ID | Change | Files | Test / gate |
|---|---|---|---|
| IMG-1 | One canonical image inventory: `install/release-images.json` listing the five images with repo, role, compose services, and Dockerfile. Consumers: `scanner.sh` (a generated shell snippet, checked in and verified by test), `install/index.sh` lock validation, `installer_smoke.sh`, `upgrade_smoke.sh`, `release-candidate.yml` matrices, `record_release_ledger.py`, `certify_release_receipt.py`. | as listed | `tests/test_release_image_inventory.py`: every consumer names exactly the inventory's set; red on any four-versus-five drift. |
| IMG-2 | `scanner.sh`: derive `MODEL_INTAKE_IMAGE` from `SCANNER_IMAGE_TAG`; pull `model-intake-worker` and `model-intake-sandbox`; cache fallback checks five images; `status`/`ps` list the pool; `rebuild` and `restart` refresh `model-intake-worker`. | `scanner.sh` | Extraction test on `configure_runtime_mode` and `pull_prebuilt_images` with a stub `docker`. |
| IMG-3 | API: `_model_intake_worker_readiness()` mirroring the agent-tool helper (registry `shakerscan:model_intake_worker_build`, required tool self-test names, fingerprint match) exposed as `/health.model_intake_worker`; `verify_specialized_worker_identity` waits for it whenever the service is expected. | `api/api.py` (or `api/model_intake/router.py`), `scanner.sh` | Unit test on the helper; `installed_stack_smoke.sh` asserts `ready`. |
| D3 | `/workers` gains `pools` (`web_dast`, `agent_tool`, `device`, `model_intake`), each with count, current, stale, pending; `worker_build` keeps its meaning for Web DAST; UI workers page renders pools; E2E preflight waits up to 60 s for pool registration before judging uniformity. | `api/api.py`, `ui/src/app/workers/*`, `tests/e2e/run_e2e.py` | Pool test with a mixed container fixture. |
| UPG-1 | Upgrade smoke checks, starts, and receipts the Model Intake image and worker; the candidate workflow passes its digest. | `scripts/upgrade_smoke.sh`, `scripts/upgrade_acceptance_receipt.py`, `release-candidate.yml:1046` | Receipt schema requires `model_intake` digests; `certify_release_receipt.py` refuses receipts without them. |
| B1 | Remove `model-intake-sandbox` from both fleet overlays; fleet workers never consume `model_intake_jobs`. | `docker-compose.worker.yml`, `docker-compose.broker-worker.yml`, `tests/test_model_intake_image_split.py` | Overlay test asserts no Model Intake service on a fleet image. |
| B2 | Strip `placement` from Model Intake submission and rescan options and reject an explicit one with a clear reason; enqueue for the Model Intake queue asserts the payload is unrouted. | `api/model_intake/router.py` (both `enqueue_job` sites and the option sanitizer) | Test: a submission with `options.placement` lands on the base `model_intake_jobs` stream; a fleet-only placement is refused with reason `model_intake_local_only`. |
| D4 | Defer. Record the coupling in `build_fingerprint.py` docstring; revisit when the API image stops carrying the locks (3.4). | | |

### 3.3 WS3 Supply-chain hygiene (B3, B4, B6; audit 3)

| ID | Change | Files | Test / gate |
|---|---|---|---|
| B3 | Scan the Model Intake image completely: delete `skip_dirs`/`skip_files` for `model-intake`; run one candidate to characterize findings; add exact `vulnerability_id` waivers with reasons and expiry only for findings inside vendored tool environments that no runtime path executes. The `api` skip of `/usr/local/bin/docker` stays until 3.4 removes the binary. | `.github/workflows/release-candidate.yml:882-887`, `security/image-vulnerability-waivers.json` | The waiver validator refuses directory-wide exclusions (add a check that the workflow matrix has empty skip fields for every image except the documented `api` binary). |
| B4 | Keep the pip-audit graph on patched `msgpack==1.2.1`, remove venv-seeded setuptools because it is not a runtime dependency, and carry no waiver for either package. | `scanner/Dockerfile.model-intake`, `scanner/model_intake_tools/pip-audit.lock`, `security/image-vulnerability-waivers.json` | Candidate vulnerability gate must prove the built image clean without these waivers. |
| B6 | Decision proposed: the worker refreshes the Trivy database at start when it has egress, falls back to the baked copy, and records `trivy_db_updated_at` in every Model Intake evidence manifest so a report states the database age. Document the cadence. | `scanner/scanner_tools/model_intake_scanners.py`, `docs/functionality-reference.md` | Evidence manifest test asserts the field; E2E fixture path asserts the fallback. |

### 3.4 WS4 API image boundary (B5; audit 5, 6)

Phase 1 ships in 2.2.0, phase 2 in 2.3.0.

| ID | Change | Files | Test / gate |
|---|---|---|---|
| API-1 | Inventory what the API process executes: Playwright/Chromium for Interactive Testing and AI Gate widget probes (`api/session_manager.py`, `api/ai_gate/targets/widget_playwright.py`), the Docker client for Model Intake staging and `/workers`. No Go tool in `/opt/tools` is invoked by the API process (`gungnir` runs in `gungnir-worker`). Record the inventory as a test that greps the API package for `/opt/tools` and subprocess calls. | `tests/test_api_image_boundary.py` | Red if the API package gains a tool invocation. |
| API-2 | Build the API image from the Playwright runtime stage without the Go toolset and the network tools (`nmap`, `masscan`, `hydra`, `medusa`, `nikto`, `dirb`, `gobuster`, `dnsrecon`), keeping Chromium and the pinned Docker client. Add a non-root `USER` whose supplementary group matches the host socket group, configurable via `SHAKERSCAN_DOCKER_GID`. | `scanner/Dockerfile`, `scanner/Dockerfile.api`, `docker-compose.release.yml`, `scanner.sh` (gid detection) | `validate` job asserts the API image lacks the tools; `installed_stack_smoke.sh` proves Model Intake staging still works as the non-root user. |
| API-3 (2.3.0) | Move Model Intake guest staging and worker inventory behind a narrow internal service (or a socket proxy allowing only the needed endpoints), and drop the socket mount from the API. `/workers` reads the Redis registries instead of Docker. | design doc first | |

### 3.5 WS5 DAST depth and balance (C1 and the timing complaint)

This is the product work of the release. Order matters: measure, restore ceilings, make the plan spend
them, then fix the two recall gaps that need new mechanisms.

| ID | Change | Files | Test / gate |
|---|---|---|---|
| DAST-0 | Baseline measurement before any change: one thorough authenticated Juice Shop Scan and one crAPI Scan on a current fleet, recording used-versus-ceiling per dimension, per-action reserved/consumed, and the scorecard. This is the number every later step is judged against. | `scripts/benchmark_targets.py --submit-only`, `--scan-id` | Stored under `tests/benchmark/results/`. |
| DAST-1 | Settle actual usage only where authoritative telemetry exists. The original proposal incorrectly assumed external TLS requests enter the worker HTTP ledger. Existing exact counters are refunded; unknown traffic retains the full hold. A future design must add per-tool counters or TLS-aware target-bound metering without deriving requests from connections. Invariant 6 in `AGENTS.md`. | `api/agent_tools.py`, `api/capabilities/scanner.py`, future metering design | Exact-counter paths settle actual values; adapters without proof remain conservative. This item is unresolved, not waived. |
| DAST-2 | Restore the profile ladder. Proposal, matching what the 0.8.x smart scan actually delivered and what the user asks for: fast 30 min / balanced 60 min / thorough 180 min, plus a new opt-in `deep` profile at 360 min (the old smart ceiling). Requests and endpoints scale with wall (proposal: 5k / 20k / 60k / 150k requests). Tool wall never exceeds wall (fixes the thorough inconsistency). Advanced values still only lower. | `api/scan/contracts.py` `BUDGET_PROFILES`, `api/runtime/models.py`, `ui/src/lib/scanContract.generated.ts` (regenerate), UI labels in `scan/new` and `schedules`, `docs/functionality-reference.md`, `/scan/contracts` | Contract test pins wall ≥ tool wall for every profile; a `test_profile_funds_its_own_plan` per profile (the thorough one referenced in `contracts.py` does not exist in `tests/`; add it). |
| DAST-3 | Reservations that scale with the profile. Express `_BATCH_PROFILES` slices as a share of the profile ceilings (wall and requests) with the measured per-attempt floors kept absolute, so a bigger profile funds more candidates and longer template sweeps rather than the same fixed 600 s. | `api/scan/action_plan.py` | Test: for each profile, planned reservations sum to at least 80% of the wall ceiling on a fixture with abundant candidates, and never exceed it. |
| DAST-4 | Continue until the ceiling. Replace the single `.001` round with a bounded loop: re-plan while the reconciled ceiling funds at least one fast-tier batch and unattempted candidates or template targets remain; cap at 8 rounds; every round digest-bound as today. Timeout of a round still preserves partial output. | `api/scan/continuation.py`, `api/worker.py` continuation site | Test: a plan whose first template batch times out with wall remaining gets a second and third round; the loop stops at the cap and at exhaustion. |
| DAST-5 | Authenticated crawl. Merge PR #59 (capability parity). Add browser storage-state seeding for `web.browser_crawl`: when the credential profile is a bearer or cookie kind, a Playwright pre-navigation step writes the token into `localStorage`/cookies on the target origin and exports the storage state the headless crawl loads. Header-only stays the fallback. Validated need: Juice Shop renders anonymous with a bearer header (memory note 2026-09-03). | `api/scan/action_adapter.py` browser crawl, `api/agent_tools.py` katana headless template, `api/runtime/scan_credentials.py` | Test against the Juice Shop fixture: basket/order routes enter the manifest with the seeded state and not without. |
| DAST-6 | Body candidates end to end. Re-measure the login SQLi on Juice Shop under thorough with state-changing authority. Fix ranking so login bodies outrank socket.io plumbing; give the body attempt an explicit per-candidate reservation at the measured cost (410 requests, 420 s); pass `--ignore-code 401 --ignore-code 403` to sqlmap for authentication endpoints. Merge PR #60 (spec ingestion) for spec-publishing targets. | `api/scan/work_manifests.py` ranking, `api/scan/action_plan.py` floors, `api/scan/action_adapter.py` argv | Benchmark expectation `smart_sqli` verified on the login body. |
| DAST-7 | Browser-proven XSS. Ensure browser-crawl and hash-route observations produce XSS candidates the verifier attempts, so `prove.xss` is not `not_applicable` on a target with a DOM sink; record deterministic sink evidence; pass an explicit CVSS so a proven XSS is not capped at medium. | `api/scan/work_manifests.py`, `api/scan/action_adapter.py` `_xss_browser_proof_batch` | Benchmark expectations `dom_xss` and `smart_xss` verified. |
| DAST-8 | Exit gate. Juice Shop thorough authenticated `expected_recall ≥ 0.67` with the precision gates held, grade reliable, and at least one browser-proven XSS. The `complete_dast_quality_bar` debt is not renewed for 2.2.0; if the bar is missed the release owner re-declares it with the new measurement, which is a stop-ship decision, not a default. | `tests/benchmark/benchmarks.json`, `scripts/certify_release_receipt.py` | Candidate certification. |

Not in scope: adding a scan type (invariant 1), any target-specific detector (memory rule:
universal engine, never benchmark fitting), path-segment injection candidates.

### 3.6 WS6 E2E debt (C2)

| ID | Change | Test / gate |
|---|---|---|
| H-10/H-11 | Reproduce the installed wrapper failure in `installed_stack_smoke.sh` (the API path is proven by H-16/H-17). Fix the wrapper so `hunt start` and `hunt call` complete in the packaged runtime, or retire the two checks with the rationale recorded in `tests/release_preservation_matrix.json`. | Either the checks pass without `xfail`, or they are removed from the matrix. |
| MI-6 | Decide: ship the trust-anchor lifecycle (it is implemented per `docs/E2E_TEST_PLAN.md:49`) as gated, or keep it a declared preview exclusion with an owner and a date. | Declared in `docs/release-readiness.md` before the freeze. |

### 3.7 WS7 Release pipeline (D1, D2, D5)

| ID | Change | Files |
|---|---|---|
| D1 | Certify by digest: the candidate workflow looks up the `build-on-main` candidate manifests for the exact SHA, verifies their attestations, and skips `validate`'s builds and the three build jobs when they exist; falls back to building when they do not. Saves about 50 minutes per candidate. | `release-candidate.yml`, `build-on-main.yml` outputs |
| D2 | Path filter: skip `build-on-main` for pushes touching only `tests/`, `docs/`, `.github/` files other than image-affecting workflows, and Markdown. | `build-on-main.yml` |
| D5 | Remove the stale `dynamic/github-code-scanning/codeql` record in the GitHub UI. Manual. | |

### 3.8 WS8 Carried items (E)

| Item | 2.2.0 disposition |
|---|---|
| ASM soft-404 phantom GC | Re-verify after DAST-4; schedule for 2.3.0 unless the GC is a one-day change. |
| Hunt Tier-0 secret classes narrow | Keep; document as a Hunt limitation. |
| `--auth` benchmark silently anonymous | Fix in DAST-0: the benchmark fails closed when the token mint fails. |
| Stray host `next start` on port 3000 | Add a `scanner.sh start` warning when port 3000 is held by a non-compose process. |

## 4. Sequencing

Sprint 0 stops the bleeding and is small enough to cut as a 2.1.1 patch if the VPS cannot wait for
2.2.0. Everything else rides 2.2.0.

| Sprint | Items | Outcome |
|---|---|---|
| 0 (this week) | A1, A2 guard (merge branch), A3, A4, B1, B2, IMG-2 | Upgrades stop rotating passwords out from under other installs, stop building from source by accident, and run five images at the selected version. |
| 1 | A2b, A5, A6, IMG-1, IMG-3, D3, UPG-1, B3, B4, B6 | Installer-driven upgrades and the fifth image are release-gated; the vulnerability gate has no directory exclusions. |
| 2 | DAST-0 through DAST-4 | A thorough Scan spends its ceiling; the profile ladder and labels agree; usage is actual. |
| 3 | DAST-5 through DAST-8, C2, API-1, API-2 | Juice Shop bar met; wrapper debt closed or retired; API image slimmed and non-root. |
| 4 | D1, D2, docs, readiness, freeze, candidate, certify, publish, promote | 2.2.0 stable. |

## 5. Exit criteria for 2.2.0

- `installer_upgrade_smoke.sh` passes all three cases; the upgrade smoke passes from 2.1.0 and from
  the pinned oldest base with Model Intake digests in both receipts.
- All five images are vulnerability-scanned without directory or binary exclusions except the `api`
  Docker client; every waiver is an exact ID with an expiry.
- `/health` reports the Model Intake pool; `/workers` reports pools; startup verifies the Model
  Intake worker; `scanner.sh` pulls, caches, statuses, and rebuilds five images from one inventory.
- Fleet overlays carry no Model Intake service; Model Intake submissions cannot carry placement.
- Every profile's wall is at least its tool wall; a thorough Scan of the benchmark spends at least
  80% of its wall or exhausts its work; settled usage is actual traffic.
- Juice Shop thorough authenticated `expected_recall ≥ 0.67`, precision gates held, browser-proven
  XSS present. Any shortfall is an explicit, newly measured, release-owner-authorized debt.
- H-10/H-11 pass or are retired; MI-6 has a recorded decision.
- Candidate certification reuses `build-on-main` digests.

## 6. Release execution (from `docs/release-process.md`)

1. Merge every workstream PR through protected `main`; each carries its failing-without-fix test.
2. Update `docs/release-readiness.md` to the 2.2.0 template with the declared-debt table emptied or
   re-declared, and write `docs/releases/2.2.0.md`.
3. `release: prepare 2.2.0 candidate metadata`: bump `VERSION`, regenerate `install/MANIFEST.sha256`
   with `scripts/generate_install_manifest.py`, keep `install/STABLE_VERSION` at 2.1.0.
4. Wait for exact-SHA `CodeQL analysis`; look the run up by name.
5. Dispatch **Release candidate** with `version=2.2.0`, the SHA, and the CodeQL run ID; no
   `waive_e2e_declared_debt` unless section 5 recorded a debt decision.
6. Certification must show both upgrade receipts, five scanned images, the Model Intake pool ready,
   and the benchmark bar.
7. Publish the immutable version with `release.yml`; run the public install smoke on a stopped local
   stack; record the ledger provenance PR before the channel PR (lesson from 2.0.1).
8. **Promote stable channel**; merge the `release/stable-2.2.0` PR last.
9. Upgrade the VPS in place with `SHAKERSCAN_HOME=/root/shakerscan` and `--prebuilt`.

## 7. Risks

- **Bigger defaults cost operator time.** A 60-minute balanced default changes expectations; the
  UI and docs must say so, and `fast` must stay genuinely fast.
- **DAST-1 may reveal that verify batches were not running.** If the 2-second `success` results
  were instant tool failures, prior scorecards overstated examination strength. That is a finding
  to publish, not to hide.
- **Storage-state seeding touches the trusted execution boundary.** Keep it a registered capability
  with runtime target binding; the token never enters argv or logs.
- **A5's oldest base doubles certification time** until D1 lands; land D1 in the same sprint.
- **Non-root API with a socket group** is host-specific; detect the gid at start and fail closed
  when it cannot be determined rather than falling back to root.
