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
| 3.4 | Secret redaction | 🟡 | No shared helper; worker inline secrets; no encryption-at-rest |
| 3.5 | Local file read gate | ✅ | — |
| 3.6 | AI Gate production safety | 🟡 | Probe production-safety filter is inert (binary flag, no probe overrides); no endpoint-hash in evidence |
| 3.7 | Request budget by HTTP call | ✅ | (widget target not integrated) |
| 3.8 | Response body cap | ✅ | Flat 256 KB cap; per-profile defaults not wired; widget not integrated |
| 3.9 | AI Gate per-finding retest | ✅ | — |
| 3.10 | Transcript retention & redaction policy | 🟡 | `include_sensitive` override is a hardcoded-`False` stub; no response-time redaction gate |
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

### R2 — Secret-handling structural fixes (was P0 §3.4) 🟡
Masking keys and nested-metadata redaction shipped (`api/api.py:_sanitize_scan_options` +
`SENSITIVE_SCAN_OPTION_KEYS`; `model_intake.py:redact_model_intake_value`). The structural fixes did
not land:
- **One shared `redact_sensitive()` helper.** Logic is duplicated 4 ways (`api.py`, `model_intake.py`,
  `scanner/reporting.py:_redact_sensitive`, `ai_verifier.py`) with **diverging** key-sets — only
  `model_intake`'s set covers the AWS/Azure/GCP keys. Unify them so coverage can't drift.
- **Credential-reference indirection in the worker.** `api/worker.py` still passes raw `--auth-*` /
  `--login-password` on the command line and returns raw `secret_value`; replace inline secrets with
  credential refs resolved at the worker.
- **Encryption-at-rest for `ai_target_credentials.secret_value`** (`db/init.sql` stores it as plaintext
  `TEXT`; no Fernet/crypto touches that column).

### R3 — Transcript redaction enforcement (was §3.10) 🟡
Sensitivity labels, retention fields, and the purge endpoint shipped
(`ai_gate_scan.py:_ai_gate_sensitivity_summary`; `DELETE /ai/scans/{id}/transcript`). But
`include_sensitive_available` is hardcoded `False` (`ai_gate_scan.py`, `api.py`) — the
`include_sensitive=true` override is echoed back but never honored — and the transcript endpoint
returns persisted `transcripts` verbatim with **no response-time redaction gate** keyed to the
sensitivity label. **Do:** make redaction the default at response time and wire a real
admin/local-only `include_sensitive` path.

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
