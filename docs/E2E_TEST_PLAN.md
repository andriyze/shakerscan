# ShakerScan End-to-End Test Plan

**Status (2026-07-10):** the rebuilt local fleet passes Model Intake `9/9` with the real bounded
Nex-N2-mini Hugging Face shard enabled, AI Gate `12/12`, and DAST `11/11`. `make e2e` remains the
deterministic all-area gate and skips the external Hugging Face row; `make e2e-model-intake` enables
that real-model row by default, while `make e2e-model-intake-fixture` is the explicit offline path.
The worker fingerprint preflight rejects a stale/non-uniform fleet. Slow authenticated crAPI BOLA
recall remains in the benchmark harness rather than this fast E2E gate.

## Why this exists

Every recent escaped bug lived at an **integration seam that unit tests mocked out**:

| Bug | What the unit test did | What an e2e test does |
|---|---|---|
| 206 partial-download → false `sha256_mismatch` | mocked `_download_http` / local files | fetch a real multi-shard HF model, assert `checksum_status != mismatch` |
| AI judge redactor leaked secrets to the LLM | called `_redact_secrets_for_judge(...)` | plant a secret in a honey AI target, scan, assert it is absent from the stored transcript |
| `UnboundLocalError` in Full Coverage | unit-tested `harvest_endpoints_with_meta` | run a real Full Coverage scan and assert it completes |
| Principal-probe production bypass | tested `classify_production_safety` | run a production AI scan, assert the admin-impersonation probe never executes |

**Principle:** an e2e test exercises the full pipeline — `POST` to the public API → Redis → worker → **real target / real network fetch** → DB → result JSON → deployment decision — and asserts on the **real output**, including adversarial negatives (secrets must not leak, truncation must be flagged, false criticals must not fire). No mocking the seams. Ground truth lives in per-target answer keys.

## Harness (Phase 0)

`tests/e2e/` — a runner invoked as `python -m tests.e2e.run_e2e --area {all|model_intake|ai_gate|dast}`:

1. **Preflight** — assert `/health` and a current, uniform worker fleet. Target failures then surface
   as real scan failures; optional external prerequisites are enabled explicitly.
2. **Submit** real jobs through the public API only (no internal imports).
3. **Poll** `GET /scans/{id}` to a terminal state with a timeout + heartbeat; a stuck/reaped scan fails the case (catches the finalize-hang class).
4. **Evaluate** the real result/findings/transcript against the case's expectations.
5. **Scorecard** — print per-assertion pass/fail summaries and return non-zero on any gate failure.

## Test matrices

### Model Intake (Phase 1)
| # | Real submit | Assertion | Catches |
|---|---|---|---|
| MI-1 | deterministic local large-artifact partial response | `checksum_status == known_unverified_truncated`; no `sha256_mismatch` | the 206 bug without external-network variance |
| MI-1-HF | real `nex-agi/Nex-N2-mini` shard 1 (`make e2e-model-intake`) | `checksum_status == known_unverified_truncated`; no false full-digest mismatch | the real registry/range-fetch path |
| MI-2 | small fully-downloadable artifact, correct digest | `checksum_status == verified`, `sha256_scope == full_artifact` | regression guard |
| MI-3 | same, deliberately wrong `expected_sha256` | critical `sha256_mismatch` + `decision == block` | real tamper detection |
| MI-4 | crafted `.pkl`/`.pt` with dangerous opcode | unsafe-serialization finding | serialization detector |
| MI-5 | self-signed, no trust anchor | `signature_verification_status == untrusted_root` | trust root |
| MI-6 | trusted-anchor-signed | `verified`, `signature_trusted_root == true` | trust root positive |

### AI Gate (Phase 2)
| # | Scenario (honey `secure-rag-agent`) | Assertion | Catches |
|---|---|---|---|
| AI-1 | `shaker-owasp-llm`/`shaker-rag-lite` scan | known prompt-injection + RAG-leak findings (recall ≥ gate) | detection e2e |
| AI-2 | secret planted in response; fetch `/ai/scans/{id}/transcript` | secret **absent** from stored transcript and judge prompt | judge-redactor leak |
| AI-3 | production scan (`confirm_production=true`) | generated `tool_abuse` admin-impersonation probe in `blocked_for_production_probe_ids`, absent from executed | principal-probe bypass |
| AI-4 | production scan without `confirm_production` | HTTP 409 | confirm_production gate |
| AI-5 | deterministically-proven finding + AI false-positive | finding not downgraded to `info` | judge deterministic guard |
| AI-6 | AI scan → deployment-decision, `allow_active_exceptions=false` + active exception | stays `block` | exception gating |

### DAST (Phase 3)

**The fast PR gate is integration + hardening, NOT broad quality/recall.** Recall %,
precision, and dual-user BOLA are slow + discovery-heavy and live in the nightly
benchmark (`tests/benchmark/`), which is a separate quality signal — not this gate.
What the fast runner (`run_e2e.py`) actually asserts:

| # | Scenario (fast gate) | Assertion | Catches |
|---|---|---|---|
| D-1 | standard scan of Juice Shop | completes (no hang/crash/reap) + graded + findings persist | finalize-hang / NUL-crash class |
| D-2 | bounded (un-sharded) active scan of the injectable login | critical SQLi detected | active SQLi recall (spot) |
| D-3 | bounded active scan of the search | DOM XSS detected | active XSS recall (spot) |
| D-4 | attack-chain assertions | the 3 removed phantom chains never appear | overclaim regression |

Nightly / benchmark (quality, not the gate): authenticated smart recall ≥ 70% of the
Juice Shop answer key, crAPI dual-user BOLA/IDOR + mass-assignment + JWT, precision
(false-positive rate), Full Coverage truncation, and NUL-byte evidence persistence.

## Every recent bug → the e2e test that catches it
MI-1 (206) · AI-2 (redaction) · AI-3 (prod bypass) · AI-4 (confirm) · AI-5 (judge guard) · D-5 (truncation + crash) · MI-5/6 (trust root) · D-4 (phantom chains) · AI-6 / MI-7 (policy wiring).

## Rollout
- **Phase 0** harness + preflight + scorecard.
- **Phase 1–3** a thin real slice of each area first (harness-first), then deepen toward the full matrices.
- **Phase 4** `make e2e` + `.github/workflows/e2e.yml` **hard gate** + nightly run; a red e2e blocks.

## Workflow rule
Any change to fetch / scan / redaction / decision code requires an e2e test through the real stack before it is called done — not a unit test alone.
