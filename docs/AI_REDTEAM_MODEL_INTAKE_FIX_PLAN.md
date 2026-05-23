# AI Red-Teaming and Model Intake Fix Plan

Source: audit of the last 30 commits ending at `bfee04e` on 2026-05-23.

Scope:

- AI Gate / AI red-teaming functionality.
- Model Intake artifact, supply-chain, and governance functionality.
- Persistence, reporting, UI, and retest paths where they affect these products.

Target outcome:

- AI Gate results should be safe to run in production-like environments, explainable, replayable, and resistant to false confidence.
- Model Intake should distinguish metadata assertions from verified evidence, block risky artifacts reliably, and avoid leaking intake secrets.
- Findings should be actionable, filterable, retestable where possible, and tied to clear deployment decisions.

---

## 1. Current State Summary

The recent commits added substantial capability:

- AI Gate target types for chat APIs, RAG endpoints, agent traces, MCP traces, and widgets.
- Static and adaptive probe planning.
- Deterministic AI Gate classifiers with optional semantic judging.
- Control-evidence generation for RAG, agent, MCP, and governance controls.
- AI inventory discovery from prior DAST scans.
- Model Intake scanning for unsafe serialization, hashes, signatures, model cards, licensing, SBOM/dependencies, malware evidence, eval evidence, deployment approval, restrictions, monitoring, and AIBOM output.
- Report and UI rendering for AI Gate and Model Intake.

The main problems are not lack of breadth. The gaps are confidence semantics, production safety, cryptographic verification, retest/replay support, and secret handling.

---

## 2. Priority Roadmap

### P0 - Safety and Trust Semantics

Do these first because they prevent misleading pass/fail outcomes or sensitive-data exposure.

1. Fix Model Intake checksum pass/fail semantics.
2. Add real signature/provenance verification or clearly mark metadata-only assertions as unverified.
3. Redact Model Intake and AI Gate secrets from options, results, transcripts, and Redis jobs.
4. Disable local file reads in Model Intake unless explicitly enabled for local development.
5. Enforce production scan safety using target mode, requested environment, and probe-level safety metadata.
6. Enforce AI Gate request/response budgets by actual HTTP call and response byte count.

### P1 - Functional Completeness

Do these after the trust semantics are accurate.

1. Add AI Gate per-finding retest/replay.
2. Add cross-principal AI target credentials for RAG and agent tests.
3. Strengthen MCP readiness checks with auth-aware protocol checks.
4. Add parser-backed Model Intake checks for safetensors, ONNX, GGUF, archives, and tokenizer/config files.
5. Validate governance evidence schemas rather than only checking presence.

### P2 - Product Depth

These make the product more complete and enterprise-ready.

1. Add indirect prompt-injection harnesses for RAG and tool outputs.
2. Add CI/CD deployment gate APIs and exports.
3. Add signed agent execution receipts and audit chains.
4. Add model/data poisoning and embedding-index checks.
5. Add policy profiles, exceptions, owners, expiry dates, and reassessment schedules.

---

## 3. Detailed Issues and Fixes

### 3.1 Model Intake Checksum Semantics Are Too Optimistic

Current behavior:

- `checksum_status` can be `known_unverified_truncated` or `provided_unverified`.
- `model_intake.checks.checksum` can still be `true` when the full artifact was not verified.
- This can make the report look like integrity passed when only metadata or a byte range was inspected.

Affected files:

- `scanner/scanner_tools/model_intake.py`
- `ui/src/components/ReportView.tsx`
- `ui/src/app/settings/model-intake/page.tsx`
- `tests/test_model_intake.py`

Fix:

- Treat only `checksum_status == "verified"` as a passing checksum check.
- Treat `known_unverified_truncated` as `warning` or `review_required`.
- Treat `provided_unverified` as `fail` when `require_hash` is true.
- Split checksum status into:
  - `expected_hash_present`
  - `observed_hash_scope`: `none`, `partial`, `full`
  - `checksum_match`: `true`, `false`, `unknown`
  - `checksum_policy_status`: `pass`, `review`, `fail`

Implementation notes:

- Keep backward-compatible fields for UI consumers.
- Update report copy to avoid saying "verified" unless the full artifact digest was checked or a trusted registry digest/signature was cryptographically verified.

Acceptance checks:

- Full artifact hash match returns `checks.checksum == true`.
- Truncated artifact with expected hash returns `checks.checksum == false` or `null`, plus a review finding when policy requires full verification.
- Expected hash mismatch remains critical.
- UI shows "partial hash only" distinctly from "verified".

---

### 3.2 HTTP Range Handling Over-Flags Truncation

Current behavior:

- HTTP fetch always sends a `Range` header.
- Any `Content-Range` response marks `truncated = true`, even if the returned range covers the entire artifact.

Affected files:

- `scanner/scanner_tools/model_intake.py`
- `tests/test_model_intake.py`

Fix:

- Parse `Content-Range: bytes start-end/total`.
- Mark truncated only if `end + 1 < total`.
- If there is no `Content-Range`, compare `Content-Length` and bytes read.
- Store:
  - `range_requested`
  - `range_satisfied`
  - `content_range_start`
  - `content_range_end`
  - `content_range_total`

Acceptance checks:

- `Content-Range: bytes 0-1023/1024` is not truncated.
- `Content-Range: bytes 0-1023/2048` is truncated.
- `200 OK` with content length below cap is not truncated.
- `200 OK` with bytes read above cap is truncated.

---

### 3.3 Signature and Provenance Verification Is Metadata-Only

Current behavior:

- Fields such as `sigstore_verified`, `cosign_verified`, `attestation_verified`, and `provenance_verified` are trusted from metadata.
- No real cosign, Sigstore, DSSE, or in-toto verification is performed.

Affected files:

- `scanner/scanner_tools/model_intake.py`
- `api/api.py`
- `ui/src/components/ReportView.tsx`
- `tests/test_model_intake.py`

Fix:

- Add explicit fields:
  - `signature_claimed_present`
  - `signature_claimed_verified`
  - `signature_cryptographically_verified`
  - `signature_verifier`
  - `signature_identity`
  - `signature_issuer`
  - `transparency_log_verified`
  - `attestation_subject_digest_match`
  - `provenance_builder_trusted`
  - `provenance_build_type_allowed`
- Add optional verifier integrations:
  - `cosign verify-blob` for blobs with bundle/certificate/key.
  - `cosign verify` and `cosign verify-attestation` for OCI references when native OCI support is added.
  - DSSE/in-toto/SLSA provenance verification against configured trust roots.

Implementation notes:

- Do not require cosign at first startup. Detect if installed and report verifier availability.
- Keep a metadata-only mode, but label it as `claimed_verified`.
- Add policy flag `require_cryptographic_signature_verification`.

Acceptance checks:

- Metadata-only `sigstore_verified: true` does not pass strict policy.
- A valid test fixture signature passes strict policy.
- A signature over a different digest fails.
- Report distinguishes "signature present", "claimed verified", and "cryptographically verified".

References:

- Sigstore verification supports identity/certificate and blob verification flows.
- SLSA verification requires checking provenance signature, trusted builder identity, and expected build parameters.

---

### 3.4 Secrets Can Leak Through Metadata, Results, and Jobs

Current behavior:

- Model Intake can read `hf_token` from metadata.
- Result payload returns `model_intake.metadata` directly.
- Sensitive scan option masking does not include common model-intake secret keys.
- AI target credentials are stored in DB and sent into worker options.
- Redis job payloads can contain target credentials.

Affected files:

- `api/api.py`
- `api/worker.py`
- `scanner/scanner_tools/model_intake.py`
- `ui/src/components/ReportView.tsx`
- `ui/src/app/settings/model-intake/page.tsx`
- `ui/src/app/settings/ai-gate/page.tsx`

Fix:

- Expand secret-key masking:
  - `hf_token`
  - `huggingface_token`
  - `access_token`
  - `refresh_token`
  - `api_token`
  - `aws_access_key_id`
  - `aws_secret_access_key`
  - `azure_sas_token`
  - `gcp_credentials`
  - `private_key`
  - `client_secret`
- Redact nested metadata before returning API responses or writing final scan results.
- Replace worker job inline secrets with credential references where possible.
- Add encryption-at-rest for `ai_target_credentials.secret_value`.
- Avoid writing provider auth headers or tokens into `artifact.fetch`, transcripts, logs, or report exports.

Implementation notes:

- Introduce a shared `redact_sensitive(value)` helper used by API, worker, reports, and UI response shaping.
- Add tests for nested metadata redaction.

Acceptance checks:

- A submitted `hf_token` never appears in `/scans/{id}`, `/scans/{id}/result`, report exports, logs, Redis job status, or UI.
- AI target secret previews remain visible, but raw secrets do not.
- Existing tests still pass with sanitized options.

---

### 3.5 Model Intake Allows Local File Reads by Default

Current behavior:

- `/model-intake/scan` accepts no-scheme artifact refs.
- The worker treats no scheme and `file:` as local file reads.

Risk:

- In a hosted or shared deployment, a user could attempt to read local worker files as artifacts.

Affected files:

- `api/api.py`
- `scanner/scanner_tools/model_intake.py`
- `ui/src/app/settings/model-intake/page.tsx`

Fix:

- Disable local file and no-scheme artifact reads by default.
- Add env flag `MODEL_INTAKE_ALLOW_LOCAL_FILES=false`.
- Allow local files only in explicit local-dev mode.
- Reject absolute paths, relative paths, and `file:` unless the flag is enabled.
- When enabled, restrict reads to configured allowlisted directories.

Acceptance checks:

- `artifact_url=/etc/passwd` is rejected by default.
- `artifact_url=file:///tmp/model.safetensors` is rejected by default.
- Local calibration tests can enable local reads in test env.
- UI explains local file refs require local-dev mode.

---

### 3.6 AI Gate Production Safety Is Incomplete

Current behavior:

- Production confirmation is required only if `ai_targets.production_mode` is true.
- Request `environment=production` does not require confirmation by itself.
- `Probe.safe_for_production` exists but all probes default to true and planning does not filter unsafe probes.

Affected files:

- `api/api.py`
- `api/ai_gate/models.py`
- `api/ai_gate/planner.py`
- `api/ai_gate/probe_registry.py`
- `ui/src/app/settings/ai-gate/page.tsx`

Fix:

- Require confirmation when either:
  - target is marked production, or
  - requested environment is `production`.
- Add `confirm_production` evidence to scan options:
  - confirmed target name
  - confirmed endpoint URL hash
  - environment
  - timestamp
  - probe pack
  - scan profile
- Classify probes as:
  - `production_safe`
  - `production_review`
  - `non_production_only`
- Filter or block non-production probes unless explicit override is provided.
- UI should show why a run is blocked or requires review.

Acceptance checks:

- `environment=production` without confirmation returns 409.
- Production scans exclude or block probes marked `non_production_only`.
- The stored scan options contain confirmation evidence without secrets.

---

### 3.7 AI Gate Request Budget Counts Probes, Not HTTP Calls

Current behavior:

- `request_budget` limits probe count.
- Multi-turn probes, setup, preflight, and cleanup can issue additional HTTP calls.

Affected files:

- `api/ai_gate_scan.py`
- `api/ai_gate/runner.py`
- `api/ai_gate/targets/rest_json.py`
- `api/ai_gate/targets/widget_playwright.py`

Fix:

- Introduce a global `RequestBudget` object separate from `TokenBudget`.
- Count every outbound target HTTP request:
  - lifecycle setup
  - lifecycle wait
  - preflight
  - probe turns
  - cleanup
- Stop before issuing a request if the remaining budget is zero.
- Record:
  - `target_requests_attempted`
  - `target_requests_successful`
  - `target_requests_skipped_budget`
  - `budget_stop_reason`

Acceptance checks:

- A scan with `request_budget=1` sends at most one target HTTP request.
- Setup and preflight count against budget unless explicitly excluded by policy.
- Coverage matrix shows probes skipped due to budget.

---

### 3.8 AI Gate Response Bodies Are Not Capped

Current behavior:

- AI Gate target adapter reads `await response.text()` with no explicit response-size cap.
- This is risky for unbounded-consumption probes and hostile targets.

Affected files:

- `api/ai_gate/targets/rest_json.py`
- `api/ai_gate/runner.py`
- `api/ai_gate_scan.py`

Fix:

- Stream response body up to `max_response_bytes`.
- Default cap by profile:
  - smoke: 64 KB
  - standard: 256 KB
  - deep: 1 MB
- Add metadata override with max allowed limit.
- Mark transcript `response_truncated=true`.
- Detector logic should account for truncated responses.

Acceptance checks:

- A target returning 10 MB does not cause memory pressure.
- Transcript records the cap and truncation.
- Unbounded-consumption finding still fires based on observed output.

---

### 3.9 AI Gate Findings Cannot Be Retested Individually

Current behavior:

- Web retest rejects AI Gate findings and tells users to rerun the target.

Affected files:

- `api/api.py`
- `api/worker.py`
- `api/ai_gate_scan.py`
- `api/retest_contract.py`
- `ui/src/app/findings/[id]/page.tsx`

Fix:

- Add AI Gate finding replay endpoint:
  - `POST /ai/findings/{finding_id}/retest`
  - mode: `same_probe`, `same_family`, `strict_replay`
- Resolve original:
  - AI target id
  - probe id
  - probe family
  - probe pack
  - scan profile
  - judge settings
  - target metadata version
- Queue a focused AI Gate scan with only the relevant probe(s).
- Store retest history in `finding_verifications` or an AI-specific extension.

Acceptance checks:

- AI Gate finding detail page can retest one finding.
- Retest stores transcript, decision, and proof.
- Fixed finding can become `likely_fixed` or `inconclusive` instead of requiring manual status changes.

---

### 3.10 Transcript Retention and Redaction Need Policy Controls

Current behavior:

- AI Gate transcripts are returned through scan result and transcript endpoints.
- Transcripts may contain leaked secrets or sensitive retrieved content.

Affected files:

- `api/api.py`
- `api/ai_gate_scan.py`
- `api/ai_redteam_artifacts.py`
- `ui/src/components/ReportView.tsx`

Fix:

- Add transcript sensitivity labels:
  - `public`
  - `internal`
  - `secret_evidence`
  - `pii_evidence`
- Redact by default in normal API responses.
- Add explicit `include_sensitive=true` for local/admin contexts if needed.
- Add retention fields:
  - `transcript_retention_days`
  - `redaction_applied`
  - `sensitive_evidence_count`
- Add purge endpoint for transcripts/evidence.

Acceptance checks:

- Findings still show useful proof without raw secrets.
- Full evidence export requires explicit flag.
- Purge removes transcript content while preserving finding metadata.

---

### 3.11 Cross-Principal AI Testing Is Under-Modeled

Current behavior:

- AI target has one credential object.
- BOLA/IDOR-style AI tests for RAG and agents need multiple users, tenants, and roles.

Affected files:

- `api/api.py`
- `api/retest_contract.py`
- `api/ai_gate_scan.py`
- `api/ai_gate/targets/rest_json.py`
- `ui/src/app/settings/ai-gate/page.tsx`

Fix:

- Add `ai_target_principals` table:
  - target id
  - label
  - role
  - tenant id
  - auth kind
  - credential ref
  - active flag
- Let probes request a principal:
  - `attacker`
  - `victim`
  - `admin`
  - `service`
- Generate pairwise tests for cross-tenant retrieval and agent authorization.

Acceptance checks:

- RAG target can be scanned with user A and user B credentials.
- Cross-tenant probes send requests as attacker and assert victim data is not disclosed.
- Report maps findings to principal pairs without exposing secrets.

---

### 3.12 Semantic Judging Availability Is Too Quiet

Current behavior:

- Semantic judge can be enabled by profile, but if provider config is missing it silently becomes deterministic-only in practical terms.
- The execution summary records provider status, but deployment decisions do not require semantic review for high-risk cases.

Affected files:

- `api/ai_gate_scan.py`
- `ui/src/components/ReportView.tsx`
- `ui/src/app/settings/ai-gate/page.tsx`

Fix:

- Add quality gate status:
  - `judging_required`
  - `judging_completed`
  - `judging_unavailable`
  - `judging_failed`
- For standard/deep scans and high-risk target types, mark decision as `needs_review` when judging is required but unavailable.
- Make UI show "deterministic only" distinctly.

Acceptance checks:

- Standard RAG/agent/MCP scan with no AI provider does not present as fully judged.
- Report shows number of findings/probes reviewed by semantic judge.
- Deployment decision includes judging availability.

---

### 3.13 MCP Readiness Checks Are Too Shallow

Current behavior:

- MCP readiness checks well-known metadata and `OPTIONS`.
- It does not use saved credentials and does not perform a safe JSON-RPC initialize/tools-list flow.

Affected files:

- `api/ai_assurance.py`
- `api/api.py`
- `ui/src/app/settings/ai-gate/page.tsx`

Fix:

- Use stored target credential for readiness checks.
- Add safe protocol probes:
  - initialize
  - tools/list
  - resources/list if read-only
  - OAuth protected resource metadata
- Check:
  - token audience
  - scopes
  - PKCE requirement signal
  - WWW-Authenticate details
  - overbroad tool schema fields
  - unauthenticated tool listing
- Never invoke destructive tools.

Acceptance checks:

- Authenticated MCP target can pass readiness.
- Unauthenticated tools/list is flagged.
- Tool schemas with dangerous or overbroad scopes are reported.

---

### 3.14 Model Format Inspection Needs Parser-Backed Checks

Current behavior:

- Safetensors, ONNX, and GGUF checks are mostly header/string heuristics.
- Archive inspection only lists some entries.

Affected files:

- `scanner/scanner_tools/model_intake.py`
- `tests/test_model_intake.py`

Fix:

- Safetensors:
  - validate header length and JSON shape
  - detect duplicate or invalid tensor offsets
  - detect suspicious metadata keys
  - optionally compare declared tensor byte ranges with file size
- ONNX:
  - use protobuf parser when available
  - detect external data references
  - detect custom operators/domains
  - flag absolute paths and remote locations
- GGUF:
  - validate magic/version
  - parse metadata keys where feasible
  - flag embedded URLs or suspicious tokenizer templates
- Archives:
  - detect zip bombs by compression ratio
  - detect nested archives
  - detect path traversal entries
  - inspect selected small files inside the archive for loader markers
- Tokenizer/config:
  - flag risky chat templates that include tool-invocation or system override behavior
  - flag remote code requirements such as `trust_remote_code`

Acceptance checks:

- ONNX external data location is flagged.
- Zip path traversal and nested executable archives are flagged.
- Safetensors malformed header fails safely.
- `trust_remote_code` in config is flagged.

---

### 3.15 Governance Evidence Is Presence-Based

Current behavior:

- SBOM, malware scan, security evals, monitoring plan, and license checks mostly test whether fields exist.

Affected files:

- `scanner/scanner_tools/model_intake.py`
- `ui/src/components/ReportView.tsx`
- `docs/AI_REDTEAM_AND_MODEL_INTAKE.md`

Fix:

- SBOM:
  - accept CycloneDX and SPDX JSON
  - validate schema shape
  - extract package count, purls, hashes, licenses
  - flag empty SBOM as review, not pass, for production
- Malware scan:
  - require status, scanner, timestamp, artifact digest, and engine/version
  - fail stale scans by policy
- Security evals:
  - require eval suite id, date, target model digest, result, thresholds
  - distinguish safety evals, red-team evals, and regression evals
- License:
  - normalize SPDX identifiers
  - support allow/deny/review lists
- Approval:
  - require approver, timestamp, policy version, and environment.

Acceptance checks:

- Empty SBOM no longer satisfies strict production policy.
- Stale malware scan is flagged.
- Non-SPDX license goes to review.
- Approval without approver/timestamp fails strict policy.

---

## 4. Product Improvements Missing From the App

### 4.1 Indirect Prompt-Injection Harness

Need:

- Ability to seed malicious documents, web pages, emails, tickets, or tool outputs into a target test environment.
- Ability to query through the normal RAG/agent path.
- Cleanup lifecycle with canary tokens.

Implementation idea:

- Extend AI Gate lifecycle requests:
  - setup malicious fixture
  - wait for indexing
  - run probes
  - cleanup fixture
- Add purpose-built probe families:
  - poisoned document
  - poisoned tool result
  - poisoned web page
  - poisoned OCR/image text

Acceptance checks:

- Safe RAG app refuses malicious document instructions but can still cite benign content.
- Unsafe RAG app leaks canary or follows document instruction.

### 4.2 Deployment Gate API

Need:

- A single machine-readable endpoint for CI/CD.

Proposed API:

```http
GET /scans/{scan_id}/deployment-decision
```

Response:

```json
{
  "decision": "allow|needs_approval|block",
  "product": "ai_gate|model_intake",
  "policy_name": "production-ai-v1",
  "blocking_findings": [],
  "required_evidence_missing": [],
  "expires_at": "2026-06-22T00:00:00Z"
}
```

Acceptance checks:

- CI can block on high/critical findings.
- CI can block on missing strict model-intake evidence.
- Decision includes policy version and expiry.

### 4.3 Agent Execution Receipts

Need:

- Evidence for what an agent actually did, not just what it said.

Implementation idea:

- Accept signed or hash-chained receipts:
  - tool name
  - principal
  - approval id
  - input hash
  - output hash
  - timestamp
  - policy decision
- Detect:
  - missing approval
  - replayed approval
  - unscoped tool call
  - output not bound to receipt

Acceptance checks:

- Finding can prove an unauthorized tool call using receipt evidence.
- Replay attempts are detected when approval ids are reused.

### 4.4 Model and Data Poisoning Coverage

Need:

- Model Intake currently focuses on artifact and governance checks, not poisoning or backdoor risk.

Implementation idea:

- Add optional metadata checks:
  - training dataset lineage
  - dataset digest
  - data source allowlist
  - base model lineage
  - fine-tuning job provenance
  - eval suite coverage
- Add canary/backdoor eval evidence requirements.
- Integrate with external model eval reports where available.

Acceptance checks:

- Missing dataset lineage is flagged for production policy.
- Eval report must bind to artifact digest and model version.

### 4.5 Policy Profiles and Exception Workflow

Need:

- Current decision logic is mostly hard-coded.
- Real users need policy profiles and time-bound exceptions.

Implementation idea:

- Add `policies` table or config:
  - product
  - environment
  - required controls
  - block thresholds
  - expiry rules
  - owner requirements
- Add finding exceptions:
  - accepted risk
  - approver
  - expiry
  - scope
  - compensating controls
- Show policy in scan reports and exports.

Acceptance checks:

- Production policy can require cryptographic signature verification.
- Staging policy can allow metadata-only signature claims with review.
- Expired exception reopens blocking status.

---

## 5. Suggested Implementation Sequence

### Phase 1 - Correct Trust Signals

Deliverables:

- Checksum semantics fix.
- HTTP range truncation fix.
- Metadata-only signature labeling.
- Secret redaction expansion.
- Local file read gate.

Tests:

- `tests/test_model_intake.py`
- `tests/test_api_scan_option_masking.py`
- Add new redaction tests for nested metadata.

### Phase 2 - AI Gate Safety and Budget Enforcement

Deliverables:

- Production confirmation on environment and target.
- Probe production-safety filtering.
- Actual request budget counter.
- Response byte cap.
- Judgment availability in decisions.

Tests:

- `tests/test_ai_gate_judging.py`
- Add tests for production confirmation, budget enforcement, and response truncation.

### Phase 3 - Replay and Multi-Principal Testing

Deliverables:

- AI Gate focused replay endpoint.
- Per-finding retest UI for AI Gate.
- Multi-principal credential model.
- Cross-tenant RAG/agent probes.

Tests:

- API tests for retest endpoint.
- Worker tests for focused probe execution.
- UI smoke tests for retest flow.

### Phase 4 - Parser-Backed Model Intake

Deliverables:

- Safetensors validation.
- ONNX parser-backed inspection.
- Archive bomb/path traversal checks.
- Tokenizer/config risk checks.

Tests:

- Malformed safetensors fixture.
- ONNX external data fixture.
- Zip traversal fixture.
- `trust_remote_code` config fixture.

### Phase 5 - Governance and Deployment Gate

Deliverables:

- SBOM/eval/malware/approval schema validation.
- Policy profile engine.
- Deployment decision endpoint.
- Exception expiry workflow.

Tests:

- Strict production policy blocks metadata-only evidence.
- Staging policy allows review state.
- Expired exceptions re-block.

---

## 6. Regression Test Matrix

Run before merging each phase:

```bash
python3 -m pytest tests/test_model_intake.py
python3 -m pytest tests/test_ai_gate_judging.py
python3 -m pytest tests/test_ai_assurance_inventory.py
python3 -m pytest tests/test_ai_redteam_artifacts.py
python3 -m pytest tests/test_api_scan_option_masking.py
```

Add browser/UI checks when UI copy or controls change:

```bash
npm run build
npx playwright test
```

Use targeted smoke scans only after API/unit tests pass.

---

## 7. Documentation Updates

Update these docs as fixes land:

- `docs/AI_REDTEAM_AND_MODEL_INTAKE.md`
- `docs/AI_TEST_WORKFLOWS.md`
- `AGENTS.md`
- UI help text in:
  - `ui/src/app/settings/ai-gate/page.tsx`
  - `ui/src/app/settings/model-intake/page.tsx`
  - `ui/src/components/ReportView.tsx`

Specific doc changes:

- Define the difference between `claimed`, `present`, and `verified` evidence.
- Document production confirmation behavior.
- Document local file restrictions for Model Intake.
- Document AI Gate retest/replay workflow.
- Document policy profiles and deployment gate response.

---

## 8. External Guidance Alignment

Use these as reference taxonomies while implementing:

- OWASP Top 10 for LLM Applications: prompt injection, sensitive disclosure, supply chain, data/model poisoning, improper output handling, excessive agency, system prompt leakage, vector/embedding weakness, misinformation, unbounded consumption.
- OWASP MCP Top 10: token exposure, scope creep, tool poisoning, dependency tampering, command injection, intent-flow subversion, authz/authn gaps, telemetry gaps, shadow MCP servers, context over-sharing.
- OWASP Machine Learning Security Top 10: ML supply-chain attacks, model theft, model poisoning, data poisoning, model inversion, membership inference.
- NIST AI RMF and Generative AI Profile: map, measure, manage, govern trustworthy AI risks.
- SLSA and Sigstore: verify artifact provenance, signatures, builder identity, and expected build parameters rather than trusting metadata claims.

---

## 9. Definition of Done

The fix program is done when:

- Model Intake never labels partial or claimed integrity as verified.
- Strict policy can require real cryptographic signature/provenance verification.
- Secrets are redacted from API responses, scan results, transcripts, reports, logs, and Redis jobs.
- Local artifact reads are disabled by default.
- AI Gate production scans require explicit confirmation and enforce probe safety.
- AI Gate budgets cap actual HTTP calls and response size.
- AI Gate findings can be retested individually.
- RAG and agent targets can test at least two principals.
- MCP readiness uses auth-aware, non-destructive protocol checks.
- Reports show evidence quality clearly: deterministic-only, semantically judged, claimed evidence, verified evidence, missing evidence.
- CI/CD can consume a stable deployment decision endpoint.
