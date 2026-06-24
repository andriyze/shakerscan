# Proposed Next Steps — DAST & ASM Quality

**Status:** rewritten 2026-06-23. The contract-first proof layer is now implemented and wired;
this document lists only the *verified-remaining* work (gaps and unfinished layers) plus the
architectural direction. Each remaining item cites the code symbol that proves its status, so it
stays auditable. No item below is "already done."

## Done (do not re-list as TODO)

The product-invariant / contract-first layer that the last cycle targeted is implemented and
called at real sites — verify before re-proposing any of it:

- Scan/report **invariant harness** — `findings.check_report_invariants` (build_report + parent
  merge + benchmark).
- **Durable finalization** — `api.synthesize_degraded_result`; a terminal scan always has a
  `/result` (degraded if needed), never NULL.
- **Canonical report blocks** — `findings.compute_quality_metrics` recomputed from the one merged
  finding set (scanner + `worker.process_scan_merge_job`).
- **One budget contract** — `constants.resolve_or_consume_budget` (consumed, not re-resolved).
- **Worker/fleet truth** — `api.compute_fleet_summary` (current/stale/uniform) + `scanner.sh status`.
- **Active-execution honesty** — `assess_scan_completeness` flags active-zero as `grade_reliable=false`.
- **Finding-count collapse** — `findings.templated_finding_identity` (DB fingerprint + merge key + dedup).
- **One proof taxonomy** — `ai_verdict_policy.has_deterministic_exploit_proof` + `proof_state`;
  **AI never promotes to `verified`** (enforced across grading/reporting/gating/API/UI).
- **Benchmark** — two-user run + post-retest re-score + fleet gate + invariant/active gates;
  scorecards committed to `results/benchmark-runs/`.

## Direction (north star)

Modern DAST for 2026+ is neither "crawl → fuzz → report" nor "let an LLM hack it and trust the
output." It is **AI-guided, deterministically-proven**:

> AI proposes → policy gates → deterministic modules test → proof engine verifies → evidence
> store preserves → canonical report explains → ASM loop learns.

AI does planning, endpoint/workflow classification, hypothesis generation, correlation, and
human-readable summaries. AI is **never** the sole authority for verified status, severity
promotion, exploit success, report counts, or security gates. The engine should be **modular
around contracts** — each module (discovery, graph, check, proof, evidence, retest, scoring,
report, ai-ops) has explicit input/output/proof/telemetry/failure/redaction/test contracts. The
target layering: continuous inventory → application/resource graph → campaign planner → modular
check registry → deterministic check modules → proof engine → evidence object store → canonical
finding model → retest loop → AI planner/analyst → continuous-ASM improvement loop. We have the
inventory, ledger, coverage, proof taxonomy, and canonical totals; the missing pieces are the
**application graph**, the **evidence object store**, and the **registry-driven execution** that
turn detectors into a durable, audit-grade platform.

## Remaining work (impact-ordered, verified)

### 1. Detection recall — the misses are still missed (highest near-term value)
**Status: PARTIAL.** Reflected XSS on id-like path segments shipped
(`active_checks._injectable_path_segment`). Still missed on the Juice Shop benchmark:
`sqli-login` (POST-body SQLi on `/rest/user/login`) and `nosqli-reviews`
(`/rest/products/reviews`). The probes exist — body-param SQLi/NoSQL is implemented
(`active_checks` has 34 `body_params` sites; `nosql_injection_test_json_body`) — so the gap is
**reaching the endpoints with the right body/param under the right auth**: the login POST body
must be captured/exercised, and the NoSQL operator probe routed to the reviews body.
**Done when:** a two-user benchmark proves `sqli-login` and `nosqli-reviews` as deterministic
findings (recall ≥ 7/9), not merely "tested."

### 2. Application / resource graph (the big missing layer)
**Status: MISSING.** There is no durable graph (0 `%graph%`/`%resource%`/`%workflow%` tables).
Object-ID and cross-user primitives exist *per scan* (`access_control_checks` object-id
extraction, `_path_has_object_id_segment`, cross-principal replay in `proof_of_exploit` /
`verification_engine`), but nothing persists **producer→consumer→object-id**, roles, workflows,
sensitive fields, or trust boundaries. This is what unlocks bug-bounty-class authz/business-logic
bugs (BOLA, BFLA, BOPLA, tenant isolation, mass assignment, workflow/payment bypass) instead of
one-off parameter fuzzing. **Do:** build an `ApplicationGraph` per target from discovery + HAR +
attempt facts: routes/params/resources/object-ids and which endpoint *produces* vs *consumes* an
id, plus auth boundary. Drive BOLA/BFLA hypotheses from it. **Done when:** the scanner can state
"`GET /api/orders` produces `order.id` owned by user1; `GET /api/orders/{id}` consumes it →
test user2 read/mutate" from a persisted graph, not from per-scan heuristics.

### 3. Auth / principal / role matrix
**Status: PARTIAL.** `target_endpoints.auth_state` exists but only `anonymous / user1 / user2`.
Real access-control testing needs principals with **roles** and **credential profiles** (admin
vs user vs tenant-B), so BFLA/tenant-isolation can be expressed. **Do:** model principals
(role, credential profile, tenant) and an endpoint×principal expectation matrix; feed #2.
**Done when:** a campaign can assert "endpoint X requires role admin" and prove a lower-role
principal's access is a finding.

### 4. Evidence object store
**Status: MISSING.** Evidence is JSON embedded in findings (0 `%evidence%` tables, no
`EvidenceObject`/`storage_uri`). **Do:** make evidence first-class — `EvidenceObject {evidence_id,
campaign_id, scan_id, finding_id, source_type, object_type (http_exchange|screenshot|
browser_trace|transcript|payload|callback|report_json), storage_uri, sha256, redaction_profile,
sensitive, node_id, retention_class}` backed by S3/MinIO. This also unblocks production multi-node
(the multi-node doc already says local evidence is PoC-only) and AI-transcript auditability.
**Done when:** findings reference evidence objects by id/hash; evidence survives worker churn and
is retrievable centrally.

### 5. Finding / EvidenceInstance object split
**Status: PARTIAL.** The *collapse* works (templated fingerprint + dedup accumulates `all_urls` /
`all_payloads` / `duplicate_count`), but evidence instances are merged into the evidence dict, not
modeled as discrete objects. **Do:** make the canonical `Finding` carry the route template /
parameter / family / auth boundary, and attach N `EvidenceInstance {concrete_url, object_id,
payload_variant, request_response_refs, principal_pair, proof_observation}` (referencing #4).
**Done when:** one templated BOLA route is one finding whose concrete ids/payloads are enumerable
as evidence instances, not folded into a JSON blob.

### 6. Check-registry → execution migration + proof contracts per family
**Status: PARTIAL.** `api/check_registry.py` (`CheckFamilySpec`) is the family contract for API
validation and ASM scheduling and carries `requires_auth_states` / `requires_credentials` /
`risk_level` / `runnable` / `telemetry_schema` — but `scanner.build_report` still executes checks
via hardcoded module calls, the spec has **no `proof_contract` / `severity_rules`**, and
`lfi`/`rce`/`ssrf` are `runnable=False` (planned, surfaced as "unavailable" in the UI). **Do:**
migrate `build_report` module execution to registry iteration; add `proof_contract` +
`severity_rules` per family; make `lfi`/`rce`/`ssrf` runnable ASM families. **Done when:** adding a
check family is a registry entry (with its proof contract), not edits scattered through
`build_report`.

### 7. AI planner over the graph + gaps
**Status: PARTIAL.** An AI ops router (`/ai/ops/route`) and AI-Gate adaptive logic
(`api/ai_gate/adaptive.py`) exist, but no planner reads the application graph (#2) + coverage gaps
to propose and rank campaigns. **Do (after #2):** an AI planner that observes graph + gaps +
prior findings, proposes campaigns/hypotheses, and explains missing prerequisites — while the
deterministic engine runs them and the proof engine decides. **Done when:** the planner's output
is policy-gated campaigns with proof contracts, never direct "verified" claims.

### 8. Operational / inventory-hygiene follow-ups
**Status: OPEN (migrated from the now-archived asm-parallel-improvement-plan).** Smaller than
§1–§7, but verified still-open after the 2026-06-17 live-validation round (most of that round's
items — A1/A3/A2 reachability + soft-404 + `gone`-retirement GC, P1/P2/P3/P4/P5 — landed; these three
did not):
- **Cap synthetic endpoint permutation (was A4).** Version/resource permutation can dominate the
  worklist before reachability filtering (Juice Shop: 4475 versioned + 1677 resource-permuted paths,
  the bulk phantom). Gate synthetic generation behind the A3 reachability signal and/or cap
  permutation breadth so generation can't out-run the filter. Today the soft-404 GC
  (`asm_inventory.sweep_endpoint_reachability`) retires phantoms *after* they are created rather than
  not creating them.
- **Worker code-version handshake (was the P1 follow-up).** A version-skewed worker/API silently runs
  old code (the root cause behind the earlier "dynamic executes static" and "parallel dropped"
  mis-diagnoses). Make `./scanner.sh rebuild/restart` recreate API-scaled workers too, and have a
  skewed worker refuse jobs instead of running stale code. `compute_fleet_summary` already reports
  `build_current`/uniformity; this closes the loop by acting on it.
- **All-worker log aggregation (was P6).** `docker compose logs worker` only captures the compose
  replicas, not API-scaled `shakerscan-worker-*` containers, so fan-out/plan lines on scaled workers
  are invisible. Add a `scanner.sh logs` mode that aggregates all worker containers.

## Standing invariants (enforced — keep them enforced)
- No finding becomes `verified`/grade-capping from AI classification alone — only deterministic proof.
- Every user-facing count (severity dist, quality, verification, triage, grade, benchmark) derives
  from the one canonical finding set.
- An active scan with zero active attempts is `degraded`, never a clean grade.
- A terminal scan always has a durable `/result`.
- The **benchmark is the unit of progress**: no DAST/ASM change is "done" until a recorded
  scorecard shows the targeted metric moved; the runner aborts on a stale/non-uniform fleet.

## Non-goals
- Do not hardcode target facts (filenames/routes/models) to pass a benchmark — ship generic techniques.
- Do not go **LLM-first** (inconsistent, unreproducible, false High/Critical, unauditable).
- Do not go **classic-DAST-only** (misses APIs, authz, business logic, and AI surfaces — the bulk
  of 2026 high-impact bugs).
- Do not treat more shards, more commits, or "feature implemented" as success.
- Do not let agentic AI take unchecked/destructive actions — propose → policy-gate → deterministic execute.
