# ShakerScan End-to-End Test Plan

**Status (reconciled 2026-07-30):** this is the E2E coverage contract, not a current pass report.
Historical `10/10`, `12/12`, and `12/12` totals were produced by an older harness/fleet and are not
release evidence. The change-aware PR smoke workflow runs the platform regression lane,
deterministic MI-1/MI-2–MI-6, and AI-1–AI-4 coverage. The manual full release workflow additionally
runs D-1–D-4; MI-1-HF remains
explicitly opt-in. Rows marked **Planned** below are not implemented in
`tests/e2e/run_e2e.py` and must not be included in pass totals. `make e2e` skips the external
Hugging Face row; `make e2e-model-intake` enables it, while `make e2e-model-intake-fixture` is the
explicit offline path. The worker-fingerprint preflight rejects a stale/non-uniform fleet. Slow
authenticated crAPI BOLA recall remains in the benchmark harness rather than the E2E workflows.

## Why this exists

Every recent escaped bug lived at an **integration seam that unit tests mocked out**:

| Bug | What the unit test did | What an e2e test does |
|---|---|---|
| 206 partial-download → false `sha256_mismatch` / false invalid safetensors header | mocked `_download_http` / local files | fetch a real multi-shard HF model, assert capped checksum semantics and full-size header validation |
| AI judge redactor leaked secrets to the LLM | called `_redact_secrets_for_judge(...)` | plant a secret in a honey AI target, scan, assert it is absent from the stored transcript |
| `UnboundLocalError` in Full Coverage | unit-tested `harvest_endpoints_with_meta` | run a real Full Coverage scan and assert it completes |
| Principal-probe production bypass | tested `classify_production_safety` | run a production AI scan, assert the admin-impersonation probe never executes |

**Principle:** an e2e test exercises the full pipeline — `POST` to the public API → Redis → worker → **pinned target or deterministic fixture** → DB → result JSON → deployment decision — and asserts on the **real output**, including adversarial negatives (secrets must not leak, truncation must be flagged, false criticals must not fire). No mocking the seams. Explicit opt-in cases cover external network fetches. Ground truth lives in per-target answer keys.

## Harness (Phase 0)

`tests/e2e/` — a runner invoked as `python -m tests.e2e.run_e2e --area {all|platform|model_intake|ai_gate|dast}`:

1. **Preflight** — assert `/health` and a current, uniform worker fleet. Target failures then surface
   as real scan failures; optional external prerequisites are enabled explicitly.
2. **Submit** real jobs through the public API only (no internal imports).
3. **Poll** `GET /scans/{id}` to a terminal state with a timeout + heartbeat; a stuck/reaped scan fails the case (catches the finalize-hang class).
4. **Evaluate** the real result/findings/transcript against the case's expectations.
5. **Scorecard** — print per-assertion pass/fail summaries and return non-zero on any gate failure.

## Test matrices

### Model Intake (Phase 1)
| # | Harness status | Real submit | Assertion | Catches |
|---|---|---|---|---|
| MI-1 | Implemented | deterministic local large-artifact partial response | `checksum_status == known_unverified_truncated`; no `sha256_mismatch` | the 206 bug without external-network variance |
| MI-1-HF | Implemented, opt-in external | real `nex-agi/Nex-N2-mini` shard 1 (`make e2e-model-intake`) | capped checksum is unverified; header offsets validate against the 4.74 GB declared size; no false mismatch/malformed finding | the real registry/range-fetch path |
| MI-2 | Implemented | small fully-downloadable artifact, correct digest | `checksum_status == verified`, `sha256_scope == full_artifact` | regression guard |
| MI-3 | Implemented | same, deliberately wrong `expected_sha256` | critical `sha256_mismatch` + `decision == block` | real tamper detection |
| MI-4 | Implemented | crafted `.pkl`/`.pt` with dangerous opcode | unsafe-serialization finding | serialization detector |
| MI-5 | Implemented | self-signed, no trust anchor | `signature_verification_status == untrusted_root` | trust root |
| MI-6 | Implemented | caller-supplied trust rejection plus operator-created expired-correct, active-wrong, active-correct, and deactivated durable anchors | caller cannot self-trust; expired/wrong/deactivated keys are `untrusted_key`; exact active key is `verified` with `signature_trusted_root == true` | trust authority, positive crypto path, expiry, wrong-key, revocation |
| MI-7 | Implemented | forged `intake_mode=admission` request through the compatibility scan endpoint | HTTP 409, controlled-workflow pointer, and no queued scan | accidental second admission-authority path |
| MI-8 | **Planned** | Model-Intake deployment decision with an active policy/exception | decision honors the active policy (stays `block` when a required control/exception applies) | policy/exception-wiring regression |

### AI Gate (Phase 2)
| # | Harness status | Scenario (honey `secure-rag-agent`) | Assertion | Catches |
|---|---|---|---|---|
| AI-1 | Implemented | `shaker-owasp-llm`/`shaker-rag-lite` smoke scan | fixture scan completes; target and scan submission are real | detection-pipeline integration |
| AI-2 | Implemented | secret planted in response; fetch `/ai/scans/{id}/transcript` | secret **absent** from stored transcript and judge prompt | judge-redactor leak |
| AI-3 | Implemented | production and staging control scans | admin-impersonation probe is blocked in production, not executed there, and generated in staging | principal-probe bypass |
| AI-4 | Implemented | production scan without `confirm_production` | HTTP 409 | confirm_production gate |
| AI-5 | **Planned** | deterministically-proven finding + AI false-positive | finding not downgraded to `info` | judge deterministic guard |
| AI-6 | **Planned** | AI scan → deployment-decision, `allow_active_exceptions=false` + active exception | stays `block` | exception gating |

### DAST (Phase 3)

**DAST is a manual release gate, not a per-PR job.** The active SQLi/XSS cases run against a pinned
Juice Shop container on the scanner's Compose network. Recall %, precision, and dual-user BOLA are
slower and more discovery-heavy; they live in the benchmark harness (`tests/benchmark/`), which is
a separate quality signal and is not currently scheduled nightly. The DAST area asserts:

| # | Harness status | Scenario (manual release gate) | Assertion | Catches |
|---|---|---|---|---|
| D-1 | Implemented | standard scan of pinned Juice Shop | worker proves target reachability; scan completes (no hang/crash/reap) + graded + findings persist | network-wiring / finalize-hang / NUL-crash class |
| D-1 receipt | Implemented | same standard scan | template receipt matches the underlying Nuclei completion state | adapter-return completion overclaim |
| D-2 | Implemented | bounded (un-sharded) active scan of the injectable login | critical SQLi detected | active SQLi recall (spot) |
| D-3 | Implemented | bounded active scan of the search | XSS detected | active XSS recall (spot) |
| D-4 | Implemented | attack-chain assertions | the 3 removed phantom chains never appear | overclaim regression |
| D-5 | **Planned slow case** | Full Coverage run producing truncated/NUL-byte evidence | scan completes; oversized evidence is truncated-and-flagged and NUL bytes stripped before DB persist | truncation + NUL-byte crash class |

Slow benchmark scope (quality, not the E2E release gate): authenticated smart recall ≥ 70% of the
Juice Shop answer key, crAPI dual-user BOLA/IDOR + mass-assignment + JWT, precision
(false-positive rate), Full Coverage truncation, and NUL-byte evidence persistence.

### Platform regression (Phase 4)

This lane does not launch a scan. It exercises the assembled API, shared database, and Redis-backed
read models, then creates and removes a disposable target, disabled schedule, and informational
manual-finding record. It is safe for the PR gate and protects adjacent products from Scan/Hunt
runtime refactors.

| # | Harness status | Surface | Assertion |
|---|---|---|---|
| P-1 | Implemented | health, canonical Scan contract, V2 metrics | database/Redis/reconciliation are healthy; canonical contract and content-free metrics are mounted |
| P-2 | Implemented | Continuous ASM | canonical check-family registry remains queryable |
| P-3 | Implemented | Connected Devices | inventory and explicit readiness/degraded state remain queryable |
| P-4 | Implemented | workers and Fleet | worker freshness plus supported/disabled/unsupported Fleet state remain explicit |
| P-5 | Implemented | schedules, findings, evidence, timeline, campaigns, Arsenal | public read models preserve their stable response contracts |
| P-6 | Implemented | target + ASM | disposable target can disable ASM and read coverage/gap projections without launching work |
| P-7 | Implemented | schedules | create, disable, read, and delete lifecycle works |
| P-8 | Implemented | findings + evidence | manual record appears in filtered findings and its evidence projection, then is deleted |

## Every recent bug → the e2e test that catches it
Implemented: MI-1 (206) · AI-2 (redaction) · AI-3 (prod bypass) · AI-4 (confirm) ·
MI-5/6 (trust root) · D-4 (phantom chains).

Planned: AI-5 (judge guard) · D-5 (truncation + crash) · AI-6 / MI-8 (policy wiring).

## Workflow split
- `.github/workflows/e2e-pr.yml` runs on every pull request so it can be a required check, but starts
  the stack and executes the platform, deterministic Model Intake, and AI Gate cases only when backend, database,
  Compose, harness, or workflow code changed. Documentation/UI-only PRs pass without starting Docker.
- `.github/workflows/e2e.yml` is a manual full release gate. It starts the pinned Juice Shop profile,
  proves worker-to-target reachability, and runs `--area all`. Run it on the exact approved candidate
  before creating a release tag.
- There is no automatic `push` or scheduled nightly E2E run. Do not describe any suite as nightly
  until a `schedule` trigger and corresponding operational ownership exist.

## Workflow rule
Changes to fetch, scan, redaction, or decision code require the applicable real-stack smoke coverage.
Scanner detection changes also require the manual full E2E release gate before release—not a unit test alone.
