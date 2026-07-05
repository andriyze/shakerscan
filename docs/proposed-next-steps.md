# Proposed Next Steps — DAST & ASM Quality

**Status:** updated 2026-07-05 after the latest-20-commit audit. The contract-first proof layer,
first app-graph/evidence slices, target de-dupe, policy exceptions, Model Intake trust controls,
AI Gate hardening, and ASM scheduling foundations are now implemented and wired. This document lists
only the *verified-remaining* work (gaps and unfinished layers) plus the architectural direction.
Each remaining item cites the code symbol or UI/API surface that proves its status, so it stays
auditable. No item below is "already done."

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
- **Build-stale fail-closed jobs** — `api.worker._refuse_stale_job_if_needed` rejects jobs when
  `require_current_workers` / submit-time fingerprint expectations say the worker is stale.
- **Active-execution honesty** — `assess_scan_completeness` flags active-zero as `grade_reliable=false`.
- **Finding-count collapse** — `findings.templated_finding_identity` (DB fingerprint + merge key + dedup).
- **Canonical target de-dupe prevention** — `api.target_dedupe.canonical_target_key` +
  self-healing migrations and target insert `ON CONFLICT` paths prevent duplicate-target gate bypasses.
- **One proof taxonomy** — `ai_verdict_policy.has_deterministic_exploit_proof` + `proof_state`;
  **AI never promotes to `verified`** (enforced across grading/reporting/gating/API/UI).
- **Policy profiles and exceptions** — `policy_profiles` / `finding_exceptions` are durable and
  consumed by deployment gates.
- **Evidence-object phase 1** — `evidence_objects` persists one object per finding for DAST,
  AI Gate, and Model Intake evidence.
- **Application-graph phase 1** — `application_graph_nodes` / `application_graph_edges` persist
  route/object/auth-boundary graph facts and expose `GET /targets/{id}/graph`.
- **Model Intake trust controls** — `/model-intake/scan` accepts detached signature, public key,
  signature algorithm/hash/payload, and trusted-key anchors.
- **AI Gate hardening** — transcript redaction/purge, MCP readiness, control inventory, trust-root
  receipt verification, and red-team report export are implemented.
- **ASM automation foundation** — per-target ASM policy, `/settings/automation`, background
  dispatcher, and recurring ASM-wave schedules exist.
- **Dashboard Action Center phase 1** — `/dashboard` returns `action_center` items for worker
  freshness, deployment blockers, failed scans, policy-exception hygiene, ASM gaps/schedules,
  Model Intake trust gaps, and AI control-baseline gaps; the dashboard renders them as a
  prioritized operator feed.
- **ASM next-action / skip-reason contract phase 1** — `asm_inventory.decide_asm_action` now returns
  `blocked_by`, `next_eligible_at`, `daily_cap_remaining`, `rate_cap_remaining`, `claimable`, and
  `tested_today`; `/targets/{id}/asm/policy`, `/asm/gaps`, and `/asm/improve` expose
  `scheduler_state`, while the dispatcher/scheduler persist the latest decision under
  `targets.metadata_json.asm_last_decision`. The ASM page renders the live and last recorded
  scheduler decision plus remaining daily/domain budget.
- **Findings product taxonomy UI** — the findings list and detail pages now expose the API taxonomy
  as distinct `DAST`, `AI Gate`, `AI Session`, `Model Intake`, `ASM`, and `Manual` badges/filters
  instead of collapsing product sources into only DAST vs AI.
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
inventory, ledger, coverage, proof taxonomy, canonical totals, first durable graph slice, and first
inline evidence-object slice; the remaining platform gaps are **graph consumers**, **externalized
evidence storage**, and **registry-driven execution** that turn detectors into a durable,
audit-grade platform.

## Remaining work / implementation plan (impact-ordered, verified)

The next work should be implemented as separate increments. Do not combine UI workflow cleanup,
ASM scheduler semantics, AI red-team campaign UX, detector recall, and evidence storage in one PR.

### 1. Product-operability layer: one place that explains "what needs action"
**Status: PHASE 1 DONE, DEEPER ACTIONS PARTIAL.** `/dashboard` now includes a server-backed
`action_center` feed built from worker freshness, deployment blockers, failed scans, exception
hygiene, ASM coverage/schedule facts, Model Intake signature trust, and AI control-baseline gaps.
The dashboard renders this as a prioritized Action Center. ASM policy/gaps/improve now expose live
`scheduler_state`, and dispatcher/scheduler decisions are persisted as
`metadata_json.asm_last_decision`. Remaining work is deeper actionability: wiring those facts into
Dashboard CTAs, a dedicated Exceptions Queue page, and inline one-click remediation for each blocker
class.

**Implement:**
1. Extend Action Center items with direct remediation where safe: restart/rescale worker CTA,
   Improve Coverage CTA with target preselection, exception-renew/revoke CTA, and retry failed scan.
2. Extend first-class "next action" and "why skipped" facts from ASM policy/gaps/improve into
   `/asm/activity` and Dashboard Action Center CTAs. The first contract is live, including
   `blocked_by`, `next_eligible_at`, `rate_cap_remaining`, `daily_cap_remaining`, and active scan
   links; activity rows still need to show the decision alongside scan history.
3. Add an Exceptions Queue page/filter for `finding_exceptions`: expiring soon, expired, missing
   owner/approver, no compensating controls, policy-scoped, and target-scoped.
4. DONE: make finding filters use product taxonomy consistently. Remaining polish is to add product
   counts/quick links in Action Center and dashboards, not to expose the filter itself.

**Done when:** a junior operator can answer, from one screen, "what is risky, what is blocked, what
will run next, and which button fixes the next blocker" without reading scan JSON or worker logs.

### 2. ASM scheduling and campaign semantics
**Status: PARTIAL.** The backend can run scheduled ASM waves (`api.run_due_schedules`) and a
background dispatcher (`api.run_asm_dispatch`), while `/asm` exposes per-target policy and now shows
live/persisted scheduler decisions. The remaining product problem is that the product still has two
overlapping automation models: recurring schedules and continuous policy. Schedules encode ASM as
`scan_options.kind='asm_improve'` while `ScheduleCreate.scan_type` remains required, so ASM waves are
a hidden variant of a DAST scan schedule rather than a first-class schedule kind.

**Implement:**
1. Introduce a typed schedule kind (`normal_scan`, `asm_improve`, later `focused_family` /
   `finding_retest`) in the API and DB migration/backfill. Keep backward compatibility by decoding
   legacy `scan_options.kind`.
2. Show one unified target timeline: background dispatcher decision, recurring schedule next run,
   current active scan/ASM batch, last activity, and last skip reason.
3. Let `/schedules` create/edit ASM waves without pretending they have a DAST `scan_type`; expose
   batch size, stale days, endpoint filter, family, and Lab/deep gating only when relevant.
4. Add tests for schedule-kind validation, legacy decode, due-run dispatch, target active-scan skip,
   and UI payload shape.

**Done when:** "Keep this target covered" is a first-class scheduled/campaign action, not an
encoded scan option, and users can see why a target did or did not receive ASM work.

### 3. AI red-team campaign UX and replay loop
**Status: PARTIAL.** AI Gate has targets, scenario presets, deterministic/semantic judging,
redacted transcripts (`GET /ai/scans/{id}/transcript`), transcript purge, MCP readiness, control
inventory (`api.ai_assurance`), adaptive logic (`api/ai_gate/adaptive.py`), and red-team report
export (`GET /scans/{id}/ai-redteam-report` / `api.get_ai_redteam_report`). It still feels
target/scan-centric, not campaign-centric.

**Implement:**
1. Add an AI Red-Team Campaign view grouping target, environment, profile, probe pack, readiness,
   control inventory, skipped probes, transcripts, findings, semantic judge output, and report export.
2. Add an OWASP LLM / RAG / agent / MCP coverage matrix: planned, executed, skipped, blocked by
   safety profile, finding count, and evidence hash per family.
3. Add "rerun failed/skipped probes" and "replay this transcript/finding" actions that preserve
   production confirmation and rate/budget controls.
4. Promote MCP readiness and missing-control findings into the Action Center from §1.

**Done when:** an AI red-team run can be reviewed, rerun, compared, and defended as a campaign
artifact instead of a loose scan report.

### 4. Model Intake trust UX
**Status: PARTIAL.** The API and UI now carry real signature/trust-anchor fields:
`ModelIntakeScanRequest.signature_*` and the Model Intake page fields around signature URL, public
key URL/PEM, signature value, trusted keys, hash, payload, and padding. The issue is operator
ergonomics: the form is dense and does not guide users to valid trust modes.

**Implement:**
1. Add a signature-mode segmented control: `checksum only`, `signature URL + key URL`, `inline
   signature + inline key`, `trusted key fingerprint`, and `metadata-supplied evidence`.
2. Add a pre-submit validation/preview panel that states exactly which trust requirements will pass,
   fail, or be advisory under the selected policy profile.
3. Add a saved trust-anchor selector and clear warnings when metadata-supplied keys are evidence but
   not an operator trust root.
4. Add UI tests for each mode and API tests that prove trusted signature verification is reachable
   only with operator-supplied trust material.

**Done when:** a developer can submit a model with a valid trust configuration without knowing every
low-level signature field, and the UI explains why "signature present" is not the same as "trusted."

### 5. Detection recall: benchmark misses still matter
**Status: PARTIAL.** Reflected XSS on id-like path segments shipped
(`active_checks._injectable_path_segment`). Still historically weak or missed on benchmark apps:
POST-body SQLi/login coverage, NoSQL operator probes routed to the right JSON/body params, stored
XSS store-then-render proof, and workflow/write-side BOLA. Body-param SQLi/NoSQL primitives exist
(`nosql_injection_test_json_body` and body-param sites in `active_checks`), so the near-term gap is
endpoint/body capture, auth context, and proof routing.

**Implement:** keep the benchmark as the unit of progress. Add focused campaigns for login/search/
review/order APIs; capture real POST bodies from browser/HAR/OpenAPI; route NoSQL operators to JSON
body params; add browser-first reflected/stored XSS proof; add safe Lab/deep workflow/write-BOLA
checks after graph/principal preconditions exist.

**Done when:** recorded two-user benchmark scorecards show the targeted miss becoming a deterministic
finding, not merely an attempted endpoint.

### 6. Application / resource graph consumers
**Status: PHASE 1 DONE, CONSUMERS MISSING.** `application_graph_nodes` /
`application_graph_edges` now persist route/object nodes plus producer/consumer/auth-boundary edges
from discovery + recursive BOLA `resource_map`; `GET /targets/{id}/graph` exposes the graph.
Object-ID and cross-user primitives also exist per scan (`access_control_checks` object-id
extraction, `_path_has_object_id_segment`, cross-principal replay in `proof_of_exploit` /
`verification_engine`). The remaining gap is that BOLA/BFLA/BOPLA/tenant/workflow campaigns still
do not read the durable graph as their source of hypotheses.

**Implement:** make an `ApplicationGraph` consumer that drives BOLA/BFLA hypotheses from persisted
producer->consumer->object-id facts, then add params/resources/roles/tenants/workflow nodes.

**Done when:** the scanner can state "`GET /api/orders` produces `order.id` owned by user1;
`GET /api/orders/{id}` consumes it -> test user2 read/mutate" from a persisted graph and schedule
the deterministic campaign from it.

### 7. Auth / principal / role matrix
**Status: PARTIAL.** `target_endpoints.auth_state` exists but only `anonymous / user1 / user2`.
Real access-control testing needs principals with roles and credential profiles (admin vs user vs
tenant-B), so BFLA/tenant-isolation can be expressed.

**Implement:** model principals (role, credential profile, tenant) and an endpoint x principal
expectation matrix; feed §6 and the AI/ASM campaign planners.

**Done when:** a campaign can assert "endpoint X requires role admin" and prove a lower-role
principal's access is a finding.

### 8. Evidence object store phase 2 and EvidenceInstance split
**Status: PHASE 1 DONE (inline).** `evidence_objects` table ships (hash, redaction_profile,
retention_class, storage_uri, scan/finding links); `save_findings` + `save_ai_findings` write one
object per finding; `GET /findings/{id}/evidence` + `GET /evidence/{id}` read them. The canonical
finding collapse works (`templated_finding_identity`, `all_urls`, `all_payloads`,
`duplicate_count`), but individual proof instances are still folded into evidence JSON.

**Implement:** externalize `storage_uri` from `inline:` to S3/MinIO or local object storage for large
objects; add a retention sweeper; split canonical `Finding` from
`EvidenceInstance {concrete_url, object_id, payload_variant, request_response_refs,
principal_pair, proof_observation}`.

**Done when:** findings reference evidence objects by id/hash; one templated BOLA route is one
finding with enumerable concrete proof instances; evidence survives worker churn.

### 9. Check-registry execution migration + proof contracts per family
**Status: PARTIAL.** `api/check_registry.py` (`CheckFamilySpec`) is the family contract for API
validation and ASM scheduling and carries `requires_auth_states` / `requires_credentials` /
`risk_level` / `runnable` / `telemetry_schema`. Scanner `build_report()` still executes many checks
through hardcoded module calls, specs need `proof_contract` / `severity_rules`, and planned families
such as `lfi`/`rce`/`ssrf` are not runnable.

**Implement:** migrate `build_report()` module execution to registry iteration; add
`proof_contract`, `severity_rules`, telemetry schema, safety gate, and report rollup per family;
then make `lfi`/`rce`/`ssrf` runnable only when their deterministic proof contracts exist.

**Done when:** adding a check family is a registry entry plus module integration, not edits scattered
through `build_report`.

### 10. Operational / inventory-hygiene follow-ups
**Status: OPEN (migrated from the now-archived asm-parallel-improvement-plan).** Most of the
2026-06-17 live-validation items landed (A1/A3/A2 reachability + soft-404 + `gone` retirement,
P1/P2/P3/P4/P5). Still open:

- **Cap synthetic endpoint permutation (was A4).** Version/resource permutation can dominate the
  worklist before reachability filtering. Gate synthetic generation behind reachability signal and
  cap permutation breadth so soft-404 GC does not have to retire thousands of phantoms after creation.
- **Worker restart/rebuild closure.** `_refuse_stale_job_if_needed` now fail-closes stale jobs, but
  `./scanner.sh rebuild/restart` should also recreate API-scaled workers so users do not have to
  manually scale down/up to replace them.
- **All-worker log aggregation (was P6).** `docker compose logs worker` only captures compose
  replicas, not API-scaled `shakerscan-worker-*` containers. Add `scanner.sh logs` aggregation.

### 11. Verification requirements for the next cycle
Every implementation increment above must include its own test slice:

- API/unit tests for new data contracts and legacy compatibility.
- UI tests for action-center cards, ASM schedule payloads, Model Intake trust modes, and AI red-team
  campaign review/rerun.
- At least one live or fixture-backed scorecard for detector/ASM changes.
- Browser QA across desktop/mobile before claiming UI completion.
- A worker-freshness preflight (`GET /workers` build-current) before any DAST-quality benchmark.

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
