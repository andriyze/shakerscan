# Proposed Next Steps — Proof-First Continuous Exposure Management

**Status:** updated 2026-07-05 after reconciling this roadmap with
`docs/archive/asm-parallel-improvement-plan.md`, `docs/parallel-scan-architecture.md`, and the
current code. The contract-first proof layer, first app-graph/evidence slices, target de-dupe,
policy exceptions, Model Intake trust controls, AI Gate hardening, and ASM scheduling foundations are
implemented and wired. This document lists only the *verified-remaining* work (gaps and unfinished
layers) plus the architectural direction. Each remaining item cites the code symbol, route, or UI
surface that proves its status, so it stays auditable. No item below is "already done."

## Report reconciliation (2026-07-05)

The supplied strategy report is directionally correct and should sharpen the roadmap. ShakerScan
should be positioned as **proof-first Continuous Exposure Management for modern apps, APIs, and AI
systems**, not as only a DAST scanner, only an ASM inventory, or an LLM hacking assistant.

The durable product loop is:

> continuous inventory -> application/resource graph -> campaign planner -> deterministic checks
> -> proof engine -> evidence store -> canonical findings -> retest/deployment gates ->
> continuous ASM loop.

The report is partly stale because several operator and backend foundations have now shipped:
Dashboard Action Center phase 1 plus structured CTAs, Exceptions Queue phase 1, ASM scheduler-state
surfacing in policy/gaps/improve/activity, product-source finding taxonomy, low-level Model Intake
trust controls, AI Gate hardening/report export/transcripts, evidence-object phase 1, and
application-graph phase 1. Treat those as foundations, not open P0 items.

The report remains correct on the larger gaps: the graph is not yet a campaign consumer, evidence is
not yet externalized into proof instances, scanner execution is not yet fully registry-driven, Model
Intake trust is too low-level, AI Gate review is scan-centric instead of campaign-centric, and ASM
schedule/campaign semantics are still encoded through legacy scan concepts.

Market positioning guidance:

- External ASM vendors are strong at discovering and mapping internet-facing assets. Do not compete
  first on internet-scale corpus. Compete on owned-surface testing quality: authenticated, replayable,
  proof-grade campaigns with honest coverage and attempt ledgers.
- DAST/API scanners are strong at crawl, audit, CI, and template execution. ShakerScan's wedge is
  continuous endpoint inventory plus graph-driven authenticated proof campaigns and canonical
  evidence across web, API, and AI surfaces.
- AI red-team tools prove demand for automated AI probing. ShakerScan should differentiate on
  campaign evidence, replay, control inventory, deterministic findings, and deployment gates.
- Dedicated model-security vendors may go deeper on malware/backdoor analysis. ShakerScan should win
  first on operational trust decisions: checksum/signature/trusted anchor/model-card/governance
  evidence, clear claim-vs-trust semantics, exceptions, and gates.

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
- **Dashboard Action Center CTAs** — `action_center` items now include structured `actions[]`
  alongside legacy `href/action_label`, and the dashboard renders safe direct links for worker
  controls, deployment blockers, failed scans, exception queues, target-preselected ASM coverage,
  ASM schedules, Model Intake trust gaps, and AI Gate control gaps.
- **ASM next-action / skip-reason contract phase 1** — `asm_inventory.decide_asm_action` now returns
  `blocked_by`, `next_eligible_at`, `daily_cap_remaining`, `rate_cap_remaining`, `claimable`, and
  `tested_today`; `/targets/{id}/asm/policy`, `/asm/gaps`, and `/asm/improve` expose
  `scheduler_state`, while the dispatcher/scheduler persist the latest decision under
  `targets.metadata_json.asm_last_decision`. The ASM page renders the live and last recorded
  scheduler decision plus remaining daily/domain budget.
- **ASM activity scheduler-state surfacing** — `GET /targets/{id}/asm/activity` returns the same
  `scheduler_state` contract as policy/gaps/improve, and the ASM Activity card renders the live
  decision, skip reason, last recorded decision, budget/claimable counters, and active scan link
  alongside recent ASM scan/campaign rows.
- **First-class schedule kind for ASM waves** — `schedules.schedule_kind`, `ScheduleCreate` /
  `ScheduleUpdate`, `run_due_schedules`, and `/schedules` now treat `normal_scan` and
  `asm_improve` as typed schedule actions. Legacy `scan_options.kind='asm_improve'` is backfilled
  and still decoded for old clients, but new UI/API payloads use `schedule_kind`.
- **Target campaign timeline phase 1** — `GET /targets/{id}/asm/activity` now returns a derived
  `timeline` that merges live scheduler decision, next eligible time, next recurring ASM wave,
  currently active target scans, last recorded scheduler decision, and recent ASM activity. The
  `/asm?target_id=...` page renders this as the target campaign timeline while preserving the
  existing activity-list fallback.
- **Guided Model Intake trust modes phase 1** — `/settings/model-intake` now has a trust-mode
  selector (`checksum only`, `signature URL + key URL`, `inline signature + key`, `trusted key
  fingerprint`, `metadata evidence`) plus a pre-submit trust preview that classifies checksum,
  signature, trusted-root, governance, and approval readiness as pass/fail/advisory before queueing.
  Metadata-supplied signing data is explicitly shown as publisher evidence, not an operator trust
  root.
- **AI red-team campaign review phase 1** — completed AI Gate scan detail pages now render an
  AI Red-Team Campaign panel from the stored `ai_gate.coverage_matrix`, `execution_plan`, and
  `evidence_manifest`: target/profile context, deploy decision, OWASP/RAG/agent/MCP-style family
  coverage, skipped reasons, transcript/report links, evidence hashes, semantic-judge status, and
  finding-level replay entry points.
- **AI red-team scan-level replay phase 1** — `POST /ai/scans/{scan_id}/replay` now queues focused
  AI Gate reruns from a completed campaign using the original target, probe pack, profile, and
  environment. It can rerun skipped probe IDs, errored families, one selected family, or the full
  campaign, and production targets still require explicit `confirm_production=true`. The scan-detail
  campaign panel exposes these actions.
- **AI red-team transcript replay phase 1** — the same replay endpoint now supports
  `mode=transcript` with `probe_id` or `transcript_index`, validates the selected stored transcript,
  and queues a focused rerun of that exact transcript probe under the original target/profile/pack.
  The scan-detail campaign panel lists replayable transcript probe IDs with per-transcript replay
  buttons and the same production confirmation boundary.
- **AI red-team campaign history phase 1** — `GET /ai/scans/{scan_id}/campaign-history` now compares
  recent completed AI Gate runs for the same AI target, probe pack, profile, and environment. The
  scan-detail campaign panel shows previous-run links, findings/coverage/executed/skipped/error
  deltas, decision changes, and a compact comparable-run table.
- **Findings product taxonomy UI** — the findings list and detail pages now expose the API taxonomy
  as distinct `DAST`, `AI Gate`, `AI Session`, `Model Intake`, `ASM`, and `Manual` badges/filters
  instead of collapsing product sources into only DAST vs AI.
- **Exceptions Queue phase 1** — `/finding-exceptions` supports hygiene queue filters for expired,
  expiring, missing owner, missing approver, missing compensating controls, policy-scoped, and
  target-scoped records. `/settings/exceptions` renders those queues, summaries, finding links, and
  non-destructive revoke actions that preserve the audit row.
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
inline evidence-object slice. The remaining platform gaps are **graph consumers**, **externalized
evidence storage**, **registry-driven execution**, and **campaign-level operator UX** that turn
detectors into a durable, audit-grade exposure-management platform.

## Remaining work / implementation plan (impact-ordered, verified)

The next work should be implemented as separate increments. Do not combine UI workflow cleanup,
ASM scheduler semantics, AI red-team campaign UX, detector recall, and evidence storage in one PR.

### Findings from this doc/code reconciliation

The three planning docs agree on the strategic direction, but the canonical next steps needed sharper
ordering and more exact implementation boundaries:

- `docs/archive/asm-parallel-improvement-plan.md` is correctly archived. It should remain evidence for
  A4/P6/worker-rebuild history, not a live roadmap.
- `docs/parallel-scan-architecture.md` is still useful for parent/plan/shard/merge and coverage
  mechanics, but its next work should be treated as execution hardening only. Product gaps now sit in
  campaign UX, schedule semantics, and proof-quality family campaigns.
- `docs/continuous-asm-architecture.md` correctly identifies the target architecture, but the live
  product still exposes overlapping concepts: background ASM policy, recurring schedules, manual
  Improve Coverage, and hidden implementation scans.
- ASM waves are now a first-class schedule kind (`normal_scan`, `asm_improve`) with legacy
  `scan_options.kind` compatibility. `/targets/{id}/asm/activity` now exposes the first derived
  target campaign timeline, so the next change is deeper schedule editing/workflow controls, not
  another schedule button or contract bridge.
- `/targets/{id}/asm/activity` now returns scan/campaign rows, attempt counts, and the shared
  scheduler decision object. Dashboard Action Center items now expose structured safe CTAs; the next
  dashboard gap is richer product counts/quick links, not the base action contract.
- Model Intake has the low-level trust fields in API/UI and now has guided trust modes plus a
  pre-submit preview. The next slice is saved trust-anchor management and policy-profile integration,
  not more low-level signature fields.
- AI Gate has transcripts, reports, adaptive probes, MCP readiness, control evidence, a first
  campaign review surface on scan detail, scan-level rerun actions for skipped/errors/family/all,
  per-transcript replay actions, and same-context run comparison on scan detail. Remaining AI Gate
  gaps are richer campaign history outside a single scan and longitudinal reporting.

### Immediate implementation sequence

These are the next commit-sized slices, in order:

1. **Model Intake saved trust anchors:** add saved trust-anchor management/selection and connect
   strict policy profiles to explicit operator anchors.
2. **Detector recall campaigns:** keep benchmark gaps as proof-backed work items: POST-body SQLi,
   NoSQL JSON/body routing, stored/reflected XSS browser proof, workflow/write-side BOLA, and
   graph-driven authz hypotheses.
3. **Richer AI campaign history:** expand same-context scan-detail comparison into target-level
   longitudinal reporting after the saved-anchor and detector-recall slices.

### Positioning-adjusted priority order

Use this order when choosing between otherwise-valid work:

- **P0: productize shipped foundations.** Richer Action Center product counts/links and deeper
  schedule workflow controls. The base Action Center/CTAs, Exceptions Queue, first-class ASM schedule
  kinds, and target campaign timeline phase 1 are already done.
- **P1: make Continuous ASM the flagship.** Family-aware coverage quality, proof-quality gaps,
  worker-aware waves, CT/new-surface inheritance, and Improve Coverage explanations that always say
  what ran or why it waited.
- **P1: close benchmark proof gaps.** Browser-first/stored XSS, POST-body SQLi, NoSQL JSON/body
  routing, workflow/write-BOLA, mass assignment, JWT/session weakness, and deterministic retest
  loops per verified family.
- **P1: AI red-team campaign UX.** Scan-detail campaign review, coverage matrix, skipped reasons,
  transcript/report links, finding-level replay entry points, scan-level rerun actions, and deploy
  decisions are phase 1 done. Selected transcript replay and same-context scan comparison are also
  phase 1 done. Remaining work is target-level longitudinal history/reporting.
- **P2: Model Intake trust UX.** Guided trust modes and pre-submit trust preview are phase 1 done;
  remaining work is saved trust anchors, policy-profile anchor binding, and clearer exception flows.
- **P2: evidence store phase 2.** External object storage, `EvidenceInstance`-style proof instances,
  retention/sweeper, redaction consistency, and audit/export manifests.
- **P2: registry-driven execution.** Migrate scanner execution and report rollups to proof contracts,
  telemetry schemas, safety gates, and family-specific run contracts.
- **P3: multi-node and internet-scale ASM.** Do this only after local queue leases, object evidence,
  worker freshness, campaign semantics, and proof/evidence invariants stay green.

### 1. Product-operability layer: one place that explains "what needs action"
**Status: PHASE 1 DONE, DEEPER ACTIONS PARTIAL.** `/dashboard` now includes a server-backed
`action_center` feed built from worker freshness, deployment blockers, failed scans, exception
hygiene, ASM coverage/schedule facts, Model Intake signature trust, and AI control-baseline gaps.
The dashboard renders this as a prioritized Action Center. ASM policy/gaps/improve/activity now
expose live `scheduler_state`, and dispatcher/scheduler decisions are persisted as
`metadata_json.asm_last_decision`. `/settings/exceptions` now provides the first dedicated
Exceptions Queue. Dashboard items now expose structured safe CTAs. Remaining work is deeper
product-level actionability: richer product counts/quick links and state-changing remediation only
after each flow has a tested confirmation boundary.

**Implement:**
1. DONE: extend Action Center items with safe CTAs for workers, failed scans, target-preselected ASM
   coverage, exception queues, Model Intake trust gaps, and AI control gaps.
2. DONE: extend first-class "next action" and "why skipped" facts from ASM policy/gaps/improve/activity
   into Dashboard Action Center CTAs where target/action links are safe.
3. DONE: add an Exceptions Queue page/filter for `finding_exceptions`: expiring soon, expired,
   missing owner/approver, no compensating controls, policy-scoped, and target-scoped.
4. DONE: make finding filters use product taxonomy consistently. Remaining polish is to add product
   counts/quick links in Action Center and dashboards, not to expose the filter itself.

**Done when:** a junior operator can answer, from one screen, "what is risky, what is blocked, what
will run next, and which button fixes the next blocker" without reading scan JSON or worker logs.

### 2. ASM scheduling and campaign semantics
**Status: PARTIAL.** The backend can run scheduled ASM waves (`api.run_due_schedules`) and a
background dispatcher (`api.run_asm_dispatch`), while `/asm` exposes per-target policy and now shows
live/persisted scheduler decisions. `/schedules` has a visible ASM coverage-wave option and the
API/DB now expose first-class schedule kinds (`normal_scan`, `asm_improve`) with legacy
`scan_options.kind` compatibility. `/targets/{id}/asm/activity` now exposes and the ASM UI renders a
derived campaign timeline that combines scheduler decisions, next eligible time, next recurring ASM
wave, active scans, last scheduler decision, and recent activity. Remaining work is deeper workflow
editing and remediation actions, not the base timeline contract.

**Implement:**
1. DONE: introduce a typed schedule kind (`normal_scan`, `asm_improve`) in API/DB/UI with
   migration/backfill and legacy `scan_options.kind` decode.
2. DONE: show one unified target timeline: background dispatcher decision, recurring schedule next run,
   current active scan/ASM batch, last activity, and last skip reason.
3. Let `/schedules` create/edit ASM waves without pretending they have a DAST `scan_type`; expose
   batch size, stale days, endpoint filter, family, and Lab/deep gating only when relevant. The
   existing typed UI selector is the starting point, not the final workflow.
4. Add tests for schedule-kind validation, legacy decode, due-run dispatch, target active-scan skip,
   and UI payload shape.

**Done when:** "Keep this target covered" is a first-class scheduled/campaign action, not an
encoded scan option, and users can see why a target did or did not receive ASM work.

### 3. AI red-team campaign UX and replay loop
**Status: PARTIAL, PHASE 1 REVIEW DONE.** AI Gate has targets, scenario presets, deterministic/semantic judging,
redacted transcripts (`GET /ai/scans/{id}/transcript`), transcript purge, MCP readiness, control
inventory (`api.ai_assurance`), adaptive logic (`api/ai_gate/adaptive.py`), and red-team report
export (`GET /scans/{id}/ai-redteam-report` / `api.get_ai_redteam_report`). Completed scan detail
now renders a campaign review card backed by `ai_gate.coverage_matrix`, `execution_plan`, and
`evidence_manifest`, and `POST /ai/scans/{scan_id}/replay` queues focused reruns for skipped
probes, errored families, selected families, selected transcript probes, or all probes.
`GET /ai/scans/{scan_id}/campaign-history` returns same-context run comparison for the campaign
panel. It still needs target-level longitudinal campaign history outside a single scan detail page.

**Implement:**
1. DONE: add an AI Red-Team Campaign view grouping target, environment, profile, probe pack, readiness,
   control inventory, skipped probes, transcripts, findings, semantic judge output, and report export.
2. DONE: add an OWASP LLM / RAG / agent / MCP coverage matrix: planned, executed, skipped, blocked by
   safety profile, finding count, and evidence hash per family.
3. PARTIAL: finding-level replay entry points link to finding detail, where focused AI Gate replay
   already preserves production confirmation. Scan-level "rerun failed/skipped probes" now exists
   for skipped/errors/family/all modes and also preserves production confirmation. Selected
   transcript replay now exists through `mode=transcript` and uses the same production gate.
   Same-context campaign history/comparison now exists on scan detail. Still add target-level
   longitudinal reporting.
4. DONE for the base Action Center: missing AI control-baseline gaps already appear there; remaining
   AI Gate campaign work is richer readiness/campaign history, not the first blocker card.

**Done when:** an AI red-team run can be reviewed, rerun, compared across runs, and defended as a
campaign artifact instead of a loose scan report. Phase 1 satisfies this on scan detail; broader
target-level history remains a later polish item.

### 4. Model Intake trust UX
**Status: PARTIAL, PHASE 1 UI DONE.** The API and UI now carry real signature/trust-anchor fields:
`ModelIntakeScanRequest.signature_*` and the Model Intake page fields around signature URL, public
key URL/PEM, signature value, trusted keys, hash, payload, and padding. The form now adds guided
trust modes plus a pre-submit pass/fail/advisory preview, so users can see why checksum, signature,
trusted-root, governance, or approval evidence will block or remain advisory before queueing.
Remaining ergonomics work is saved trust-anchor selection and policy-profile anchor binding.

**Implement:**
1. DONE: add a signature-mode segmented control: `checksum only`, `signature URL + key URL`, `inline
   signature + inline key`, `trusted key fingerprint`, and `metadata-supplied evidence`.
2. DONE: add a pre-submit validation/preview panel that states exactly which trust requirements will pass,
   fail, or be advisory under the selected policy profile.
3. PARTIAL: clear warnings now explain when metadata-supplied keys are evidence but not an operator
   trust root. Still add a saved trust-anchor selector/manager.
4. PARTIAL: helper tests cover each preview mode's core trust semantics; keep the existing API/e2e
   signature tests proving trusted verification is reachable only with operator-supplied trust
   material, and add browser/e2e coverage around saved anchors when that feature lands.

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
