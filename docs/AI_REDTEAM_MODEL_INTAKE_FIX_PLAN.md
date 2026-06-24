# AI Red-Teaming and Model Intake Fix Plan

**Original audit:** last 30 commits ending `bfee04e`, 2026-05-23.
**Status re-verified against code:** 2026-06-23.

> Most of this plan has shipped. This revision marks every item's current status and foregrounds the
> remaining work. As always, **the code, DB schema, and tests are authoritative** — each status below
> cites the symbol that proves it; verify before acting. Completed items are collapsed to a one-line
> pointer so they are not re-proposed; partial/missing items keep full remaining-work detail.

Scope: AI Gate / AI red-teaming, Model Intake artifact/supply-chain/governance, and the persistence,
reporting, UI, and retest paths that affect these products.

---

## Status at a glance

Legend: ✅ implemented · 🟡 partial · 🔴 missing.

| # | Item | Status | Remaining gap (if any) |
|---|------|--------|------------------------|
| 3.1 | Model Intake checksum semantics | ✅ | — |
| 3.2 | HTTP Range truncation handling | ✅ | — |
| 3.3 | Signature / provenance **crypto** verification | 🔴 | No real cosign/sigstore/DSSE; trusts caller-supplied booleans |
| 3.4 | Secret redaction | 🟡 | Shared helper done (R2a); worker inline secrets + encryption-at-rest remain (R2b) |
| 3.5 | Local file read gate | ✅ | — |
| 3.6 | AI Gate production safety | 🟡 | Probe production-safety filter is inert (binary flag, no probe overrides); no endpoint-hash in evidence |
| 3.7 | Request budget by HTTP call | ✅ | (widget target not integrated) |
| 3.8 | Response body cap | ✅ | Flat 256 KB cap; per-profile defaults not wired; widget not integrated |
| 3.9 | AI Gate per-finding retest | ✅ | — |
| 3.10 | Transcript retention & redaction policy | ✅ | Response-time redaction default + audited admin gate (R3) |
| 3.11 | Cross-principal AI testing | ✅ | — |
| 3.12 | Judging availability gate | ✅ | UI "deterministic only" indicator not surfaced |
| 3.13 | MCP readiness auth-aware checks | ✅ | No `resources/list` probe; some checks lean on declared metadata |
| 3.14 | Parser-backed model-format checks | ✅ | ONNX degrades to string heuristics when the `onnx` lib is absent |
| 3.15 | Governance evidence validation | 🟡 | No SPDX identifier normalization / expression parsing |
| 4.1 | Indirect prompt-injection harness | ✅ | — |
| 4.2 | Deployment gate API | ✅ | — |
| 4.3 | Agent execution receipts | 🟡 | Detects missing/replayed/unscoped, but does not cryptographically verify the hash chain/signature |
| 4.4 | Model/data poisoning coverage | ✅ | Strict-policy-gated; no explicit data-source allowlist check |
| 4.5 | Policy profiles + exception workflow | 🟡 | Hard-coded profiles + payload-driven exceptions; no DB-backed `policies`/`finding_exceptions` tables |

**Net:** the breadth and most of the trust/safety semantics shipped. The materially-open items are
**3.3** (the one true remaining P0 — signature verification is asserted, not enforced), the structural
half of **3.4** (shared redaction helper, credential indirection, encryption-at-rest), and the two
PARTIAL product features **4.3** (receipt crypto) and **4.5** (durable policy/exception registry).

### Updated priority order

| Priority | Item | Why |
|---|---|---|
| **P0** | Real signature/provenance verification — **R1** | Strict Model Intake policy is not trustworthy while caller-supplied booleans can pass. |
| **P0** | Shared redaction + credential indirection + encryption-at-rest — **R2** | AI targets/transcripts/model metadata are sensitive; foundational. |
| **P0** | Transcript response-time redaction — **R3** | Storage-time controls are not enough; transcripts carry the exact secrets the scanner hunts. |
| **P1** | Unified AI proof/evidence taxonomy — [target arch](#unified-ai-proof-and-evidence-taxonomy) | Prevents claimed / AI-judged evidence from rendering as verified. |
| **P1** | Durable policy + exception registry — **R4** | Needed for deployment gates, audits, expiring risk acceptance. |
| **P1** | Agent receipt hash-chain/signature verification — **R5** | Required before receipts can be called verified. |
| **P1** | Model Intake source-type split — [target arch](#source-type-taxonomy-r8) | Fixes reporting, dashboards, deployment decisions, exposure-graph clarity. |
| **P2** | Production probe-safety classification — **R6** | Makes AI Gate safer for real environments. |
| **P2** | MCP `resources/list`, widget parity, per-profile caps, SPDX parsing — **R6** | Independent hardening. |
| **P2** | AI surface inventory / attempt ledger — [target arch](#ai-surface-inventory-and-attempt-ledger-r9) | Aligns AI Gate/Model Intake with the DAST/ASM evidence-first architecture. |

---

## Remaining work (impact-ordered, actionable)

### R1 — Real signature/provenance verification (was P0 §3.3) 🔴
`scanner/scanner_tools/model_intake.py:_signature_verification_status` sets
`cryptographically_verified` purely from caller-supplied metadata booleans
(`signature_cryptographically_verified`, `sigstore_bundle_verified`, `cosign_bundle_verified`, …).
No cosign/sigstore/DSSE/in-toto/rekor verification runs anywhere in the module. A caller can assert
`signature_cryptographically_verified: true` and pass strict policy.
**Do:** add optional verifier integration (`cosign verify-blob`/`verify-attestation`, DSSE/in-toto/SLSA
against configured trust roots), detect verifier availability at startup (do not hard-require cosign),
add policy flag `require_cryptographic_signature_verification`, and split the reported state into
`signature_claimed_present` / `signature_claimed_verified` / `signature_cryptographically_verified`
plus `signature_verifier` / `transparency_log_verified` / `attestation_subject_digest_match`.
**Done when:** metadata-only `sigstore_verified: true` fails strict policy; a valid fixture signature
passes; a signature over a different digest fails; the report distinguishes "present" vs "claimed
verified" vs "cryptographically verified".

### R2 — Secret-handling structural fixes (was P0 §3.4) 🟡 (R2a done)
Masking keys and nested-metadata redaction shipped. Remaining structural fixes:
- ✅ **One shared `redact_sensitive()` helper — DONE (R2a, 2026-06-24).** `scanner/redaction.py` is now
  the single source of the sensitive key-set (the **union** of the old api + model_intake sets, so the
  AWS/Azure/GCP gap on the api side is closed and api auth keys are covered by model_intake) plus the
  masking / URL-credential / free-text helpers. `api/api.py`, `scanner/scanner_tools/model_intake.py`,
  and `scanner/reporting.py` all delegate to it; `ai_verifier.py` keeps its separate, more aggressive
  `[REDACTED]` provider redactor by design. Verified: `tests/test_shared_redaction.py` (8) +
  `test_api_scan_option_masking` (90), `test_model_intake` (29), `test_ai_verifier_safety` (11) green;
  live stack reboots healthy with the flat-layout import.
- **Credential-reference indirection in the worker.** `api/worker.py` still passes raw `--auth-*` /
  `--login-password` on the command line and returns raw `secret_value`; replace inline secrets with
  credential refs resolved at the worker. (R2b)
- **Encryption-at-rest for `ai_target_credentials.secret_value`** (`db/init.sql` stores it as plaintext
  `TEXT`; no Fernet/crypto touches that column). (R2b)

### R3 — Transcript redaction enforcement (was §3.10) ✅ DONE (2026-06-24)
`GET /ai/scans/{id}/transcript` now redacts at response time by default
(`redact_sensitive(..., redact_strings=True, scrub_text=True)` — masks credential keys, URL
credentials, and inline bearer/api-key/token/secret patterns while keeping the prompt/response
readable). Raw bodies are returned only when the operator sets `AI_TRANSCRIPT_ALLOW_SENSITIVE` **and**
the caller passes `include_sensitive=true`; that access is audit-logged (`logger.warning` with the
client host). The response surfaces `redaction_applied`, `sensitivity_label`, and
`include_sensitive_available`. Verified live against honey (`shaker-rag-lite` smoke): default
`redaction_applied=true`, `include_sensitive_available=false`, and `include_sensitive=true` with the
flag off does **not** reveal; the admin-gate helper honors `true/1/yes/on`. Behaviour unit-locked in
`tests/test_shared_redaction.py` (`scrub_text` composition).

### R4 — Durable policy + exception registry (was §4.5) 🟡
`POLICY_PROFILES` is a hard-coded Python dict and exceptions are read from scan options/result JSON
(`api/api.py:_policy_profile_for_scan`, `_exception_records`, `_apply_policy_exceptions`). There is no
`policies` or `finding_exceptions` table (confirmed absent from `db/init.sql` and
`retest_contract.run_schema_migrations`). **Do:** persist policy profiles and finding exceptions
(owner, scope, compensating controls, approver, expiry) so decisions are auditable and exceptions can
expire server-side and re-open blocking status.

### R5 — Agent execution receipt verification (was §4.3) 🟡
`ai_gate_scan.py:_agent_execution_receipt_findings` detects missing approval, replayed approval
(duplicate `approval_id`), unscoped tool calls, and output-not-bound-to-receipt — but only by field
**presence**. It does not verify the hash chain (`prev_hash` linkage) or any signature, so a forged
receipt with non-empty fake `receipt_hash`/`signature` passes. **Do:** validate the chain and signature
when present; report "claimed" vs "verified" receipts.

### R6 — Minor hardening (small, independent)
- **§3.6** Make the production-safety probe filter effective: today every probe defaults to
  `safe_for_production=True` with no overrides in `probe_registry.py`, so the planner filter removes
  nothing. Either populate the classification (or the proposed 3-way `production_safe` /
  `production_review` / `non_production_only`) or drop the inert filter. Also add the endpoint-URL hash
  to the stored `confirm_production` evidence.
- **§3.8** Wire per-profile response caps (smoke 64 KB / standard 256 KB / deep 1 MB) instead of the
  flat 256 KB default.
- **Widget target parity:** integrate the request budget (§3.7) and response cap (§3.8) into
  `ai_gate/targets/widget_playwright.py` (currently rest_json only).
- **§3.12** Surface the judging quality gate in the UI ("deterministic only" / "needs review") —
  `judging_quality_gate` is computed and exposed by the API but no UI reads it.
- **§3.13** Add a safe `resources/list` probe to MCP readiness.
- **§3.14** Ensure the `onnx` package is installed in the scanner image so ONNX inspection is always
  parser-backed (it falls back to ASCII-string heuristics when absent).
- **§3.15** Add SPDX identifier normalization + expression parsing (`MIT OR Apache-2.0`) on top of the
  existing permissive/restricted/review classification.

---

## Target architecture (object models & flows)

Everything in this section is **target/proposed**, not shipped. These object models deliberately
converge with the DAST evidence-first work in [`proposed-next-steps.md`](proposed-next-steps.md)
(§2 application graph, §4 evidence object store, §5 finding/evidence split) — AI and DAST should share
one inventory → evidence → proof-state → policy pipeline, not two parallel ones.

### AI product flow

```text
AI Target / Model Artifact / Session
        |
        v
AI Surface Resolver            (GET /ai/inventory exists today as a derived view)
        |
        v
Policy Gate + Probe Safety Classifier
        |
        v
Probe Pack / Model Intake Scanner / Session Action
        |
        v
Deterministic Classifier + Optional AI Judge
        |
        v
Proof State + Evidence Objects + Redaction
        |
        v
Findings + Exposure Graph + Deployment Decision
        |
        v
Retest / Exception / Continuous Monitoring
```

AI is not "an LLM decides vulnerability": it is probe → evidence → proof state → policy decision.

### Unified AI proof and evidence taxonomy

Current: a finding exposes `verified` / `suspected` / `unverified` (`api/api.py`) with scanner
`proof_state` `exploited` / `likely_vulnerable`. Target: one taxonomy across DAST + AI so that *claimed*
and *AI-judged* evidence can never render as *verified*.

| Proof state | Meaning | Can block deploy? | Counts as verified? |
|---|---|---:|---:|
| `deterministic_verified` | Replayed/proved by deterministic checker, parser, crypto verifier, or protocol result | Yes | Yes |
| `cryptographically_verified` | Signature/provenance/receipt verified against configured trust roots | Yes | Yes |
| `claimed_present` | Metadata claims evidence exists; ShakerScan did not verify it | Policy-dependent | No |
| `ai_judged_likely` | AI or heuristic says likely vulnerable | Review gate | No |
| `inconclusive` | Probe ran but evidence insufficient | No, unless strict policy requires proof | No |
| `blocked` | Missing credentials, principals, approval, policy, or verifier | Policy-dependent | No |
| `false_positive` | Deterministic or reviewed downgrade | No | No |

### Secret-handling target architecture (R2)

- one shared `redact_sensitive()` helper used by API, scanner reporting, Model Intake, AI verifier, transcripts;
- credential references (not raw secrets) in API/Redis/worker job payloads;
- worker resolves credentials just-in-time;
- secrets never appear on scanner subprocess command lines;
- AI-target credentials encrypted at rest;
- transcript and report responses apply response-time redaction by default.

### Transcript access model (R3)

- default transcript response is redacted;
- sensitive fields withheld unless caller is local/admin and `include_sensitive` is actually available;
- response includes `redaction_applied`, `sensitivity_label`, and `include_sensitive_available`;
- raw transcript access is audited.

### Policy and exception registry (R4)

`PolicyProfile { policy_id, product_area (ai_gate|model_intake|dast|asm), name, environment
(dev|staging|prod), required_evidence, blocked_finding_families, allowed_exceptions, owner, version,
active_from, active_until }`.

`FindingException { exception_id, finding_id|fingerprint, policy_id, scope, owner, approver, reason,
compensating_controls, expiry, status, audit_events }`.

The deployment-decision endpoint should consume these durable records (today it reads a hard-coded
profile dict plus payload-supplied exceptions). Converges with the evidence/exception direction in
[`proposed-next-steps.md`](proposed-next-steps.md) §4–§5.

### Verified-receipt requirements (R5)

A receipt is `cryptographically_verified` only when: canonical serialization is stable; the hash
matches receipt contents; `prev_hash` links to the previous receipt; the signature verifies against the
configured tool/agent key; and scope + approval binding match the action. Until then, `receipt_hash` /
`prev_hash` / `signature` are reported as **claimed**, not verified.

### Three-tier probe safety model (R6)

Replace the always-true binary `safe_for_production` with a real classification carried by every probe
pack entry:

- `production_safe` — passive/harmless probes; OK with confirmation + budget caps.
- `production_review` — may produce sensitive output, policy stress, tool-boundary attempts, or
  unexpected cost; requires explicit review/confirmation.
- `non_production_only` — prompt-injection chains, tool abuse, poisoning, approval bypass, destructive
  or state-changing tests; requires a Lab/staging target.

### Source-type taxonomy (R8)

Stop overloading `source_type=dast` to mean "not AI Gate." Persist distinct values — `dast`, `asm`,
`ai_gate`, `ai_session`, `model_intake`, `ai_assisted_retest`, `manual` — while the UI still groups
them as DAST/AI. This is a schema + derivation + deployment-decision + exposure-graph change (a real
implementation task with a migration, not a doc edit).

### AI surface inventory and attempt ledger (R9)

`GET /ai/inventory` / `build_ai_inventory` already produce a derived inventory view. Make it durable,
mirroring the DAST endpoint inventory + attempt ledger (`target_endpoints` + `asm_endpoint_attempts`):

`AISurface { surface_id, target_id, type (api_chat|rag|agent|mcp|widget|model_artifact),
endpoint/template, auth_profile, principals, tools/resources_exposed, data_sources/retrieval_indexes,
model/provider_metadata, owner/environment, last_seen, last_tested, risk_posture }`.

`AISurfaceAttempt { surface_id, campaign_id|scan_id, probe_pack, probe_family, principal, status,
proof_state, evidence_ids, started_at, completed_at }`.

This makes AI Gate / Model Intake part of the same continuous control plane as DAST/ASM.

---

## Implemented (collapsed — do not re-propose; pointers for reference)

- **§3.1 Checksum semantics** — `model_intake.py` derives `checksum_policy_status`
  (`pass`/`review`/`fail_*`), `observed_hash_scope`, `checksum_match`, `expected_hash_present`; only
  `checksum_status=="verified"` passes (`test_model_intake.py:197`).
- **§3.2 Range truncation** — `_parse_content_range` + `_download_http` mark truncated only when
  `end+1 < total`; store `range_requested`/`range_satisfied`.
- **§3.5 Local file gate** — `_fetch_artifact(allow_local_files=False)`; env
  `MODEL_INTAKE_ALLOW_LOCAL_FILES`, default off; rejects `file:`/no-scheme/absolute paths.
- **§3.6 Production confirmation** — `environment=production` alone (not just `production_mode`) →
  409 unless `confirm_production`; evidence stored in `metadata_json`/`storage_options`
  (`api.py`). (Probe filtering wired but inert — see R6.)
- **§3.7 Request budget** — real per-HTTP-call `RequestBudget` (`api/ai_gate/budget.py`) counting
  setup/preflight/turns/cleanup, with stop + telemetry; wired via `set_request_budget`.
- **§3.8 Response cap** — `_read_response_text_capped` streams to `max_response_bytes`, marks
  `response_truncated` (flat default, per R6).
- **§3.9 Per-finding retest** — `POST /ai/findings/{id}/retest` with `same_probe`/`same_family`/
  `strict_replay`; focused single-probe execution (`ai_gate_scan.py:5737`); history in
  `finding_verifications`; worker `finalize_ai_finding_retest`.
- **§3.11 Cross-principal** — `ai_target_principals` table (`retest_contract.py`),
  `/ai/targets/{id}/principals` CRUD, real per-turn credential switching
  (`ai_gate/targets/rest_json.py:_select_principal`), pairwise cross-tenant probe generation.
- **§3.12 Judging gate** — `judging_gate_status` (`required`/`completed`/`unavailable`/`failed`);
  flips decision to `needs_review` for standard/deep high-risk when judging unavailable (UI surfacing
  per R6).
- **§3.13 MCP readiness** — `POST /ai/targets/{id}/mcp/live-readiness` runs credentialed JSON-RPC
  `initialize` + `tools/list` (+ unauth differential); checks audience/scopes/PKCE/WWW-Authenticate/
  overbroad schema; never calls `tools/call` (`ai_assurance.py`).
- **§3.14 Parser-backed checks** — real safetensors header/offset validation, ONNX protobuf parse +
  external-data/custom-op detection, GGUF magic/version, zip bomb/path-traversal/nested + embedded
  `trust_remote_code`/chat-template inspection.
- **§3.15 Governance validation** — SBOM CycloneDX/SPDX shape + component extraction, malware-scan
  staleness + required fields, eval required fields, approval required fields (SPDX normalization per R6).
- **§4.1 Indirect prompt-injection harness** — fixture lifecycle (`_ensure_lifecycle_setup` /
  `_wait_for_lifecycle_condition` / `finalize_session` cleanup), canary tokens, and poisoned-document/
  tool-result/ranking probe families (`probe_registry.py`).
- **§4.2 Deployment gate API** — `GET /scans/{id}/deployment-decision` →
  `build_deployment_decision` with `decision`/`product`/`policy_name`/`blocking_findings`/
  `required_evidence_missing`/`expires_at` across dast/ai_gate/model_intake.
- **§4.4 Model/data poisoning coverage** — `missing_dataset_lineage`/`_digest`/`base_model_lineage`/
  `training_pipeline_provenance`/`poisoning_eval_evidence` findings (strict-policy-gated).

---

## Regression test matrix

```bash
python3 -m pytest tests/test_model_intake.py
python3 -m pytest tests/test_ai_gate_judging.py
python3 -m pytest tests/test_ai_assurance_inventory.py
python3 -m pytest tests/test_ai_redteam_artifacts.py
python3 -m pytest tests/test_api_scan_option_masking.py
```

UI checks when copy/controls change: `npm run build` then `npx playwright test`. Targeted smoke scans
only after API/unit tests pass.

**Required trust-contract tests** (gate the remaining work above):

- metadata-only signature claim fails strict policy; valid fixture signature passes; signature over the wrong digest fails (R1);
- a forged receipt hash/signature stays `claimed`, not `verified` (R5);
- transcript response redacts sensitive fields by default; `include_sensitive` requires an admin/local gate and is audited (R3);
- `source_type=model_intake` filters separately from `dast` and `ai_gate` (R8);
- a policy exception expires and re-opens blocking status (R4);
- the `production_safe` filter actually removes non-production probes (R6);
- the UI visibly marks deterministic vs judged vs claimed vs missing evidence (R6 §3.12).

---

## External guidance alignment (reference taxonomies)

- **OWASP Top 10 for LLM Applications:** prompt injection, sensitive disclosure, supply chain,
  data/model poisoning, improper output handling, excessive agency, system-prompt leakage,
  vector/embedding weakness, misinformation, unbounded consumption.
- **OWASP MCP Top 10:** token exposure, scope creep, tool poisoning, dependency tampering, command
  injection, intent-flow subversion, authz/authn gaps, telemetry gaps, shadow MCP servers, context
  over-sharing.
- **OWASP ML Security Top 10:** ML supply-chain attacks, model theft, model/data poisoning, model
  inversion, membership inference.
- **NIST AI RMF + Generative AI Profile:** map, measure, manage, govern.
- **SLSA + Sigstore:** verify provenance, signatures, builder identity, and expected build parameters
  rather than trusting metadata claims (directly motivates R1).

---

## Definition of done (current state)

| Goal | Met? |
|------|------|
| Model Intake never labels partial/claimed integrity as verified | ✅ (3.1) |
| Strict policy can require real cryptographic signature/provenance verification | 🔴 **R1** |
| Secrets redacted from API responses, results, transcripts, reports, logs, Redis jobs | 🟡 (3.4 surface done; **R2** structural) |
| Local artifact reads disabled by default | ✅ (3.5) |
| AI Gate production scans require explicit confirmation + enforce probe safety | 🟡 (confirm ✅; probe filter inert — **R6**) |
| AI Gate budgets cap actual HTTP calls and response size | ✅ (3.7/3.8; widget parity in **R6**) |
| AI Gate findings retestable individually | ✅ (3.9) |
| RAG/agent targets can test ≥2 principals | ✅ (3.11) |
| MCP readiness uses auth-aware, non-destructive protocol checks | ✅ (3.13) |
| Reports show evidence quality clearly (deterministic / judged / claimed / verified / missing) | 🟡 (data present; UI surfacing — **R6** §3.12) |
| CI/CD can consume a stable deployment-decision endpoint | ✅ (4.2) |
| Durable, auditable policy + exception registry | 🟡 **R4** |
