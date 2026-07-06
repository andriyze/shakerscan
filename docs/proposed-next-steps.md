# Proposed Next Steps — Proof-First Continuous Exposure Management

**Status:** updated 2026-07-05 after reconciling this roadmap with
`docs/t3mp3st-adoption-implementation-plan-updated.md`,
`docs/archive/asm-parallel-improvement-plan.md`, `docs/parallel-scan-architecture.md`, and the
current code. The contract-first proof layer, first app-graph/evidence slices, target de-dupe,
policy exceptions, Model Intake trust controls, AI Gate hardening, ASM scheduling foundations,
Command Arsenal contracts, dry-run planning records, scope receipts, approval receipts, context
packs, decision traces, local-agent-labeled dry-run planning, and policy-based approval enforcement
are implemented and wired. This document lists only the *verified-remaining* work (gaps and
unfinished layers) plus the architectural direction. Each remaining item cites the code symbol, route,
or UI surface that proves its status, so it stays auditable. No item below is "already done."

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
not yet externalized into proof instances, scanner execution is not yet fully registry-driven,
detector recall still misses important benchmark families/workflows, Model Intake remediation is
still more explanation than workflow, and AI Gate target history needs readiness/export polish. The
part of the report that is now stale is the P0 operator foundation: structured Action Center CTAs,
typed ASM schedule kinds, ASM scheduler-state surfacing, and the target campaign timeline have
shipped. The remaining operator gap is **productized decision flow**: one dashboard/action surface
that summarizes DAST, ASM, AI Gate, Model Intake, exceptions, worker freshness, and deployment gates
with counts, blockers, next actions, and safe remediation entry points.

Market positioning guidance:

- External ASM vendors are strong at discovering and mapping internet-facing assets. Do not compete
  first on internet-scale corpus. Compete on owned-surface testing quality: authenticated, replayable,
  proof-grade campaigns with honest coverage, blocked/skipped reasons, and attempt ledgers.
- DAST/API scanners are strong at crawl, audit, CI, and template execution. ShakerScan's wedge is
  continuous endpoint inventory plus graph-driven authenticated proof campaigns and canonical
  evidence across web, API, and AI surfaces.
- Template/exposure scanners are strong at broad checks and ecosystem velocity. ShakerScan should
  use templates where useful, but make stateful workflows, auth context, proof contracts, and
  evidence instances the differentiator.
- AI red-team tools prove demand for automated AI probing. ShakerScan should differentiate on
  campaign evidence, replay, control inventory, deterministic findings, and deployment gates.
- Dedicated model-security vendors may go deeper on malware/backdoor analysis. ShakerScan should win
  first on operational trust decisions: checksum/signature/trusted anchor/model-card/governance
  evidence, clear claim-vs-trust semantics, exceptions, and gates.

## T3MP3ST adoption reconciliation (2026-07-05)

`docs/t3mp3st-adoption-implementation-plan-updated.md` is now folded into this roadmap as an
operating-model input. The useful adoption target is not T3MP3ST's broad offensive-tool surface or
raw local-agent execution. The useful target is its harness discipline:

- objective-driven missions instead of disconnected scan buttons;
- schema-described commands instead of raw shell access;
- scope, approval, environment, rate, and evidence gates before execution;
- local coding agents as optional dry-run planners, never privileged executors;
- a shared lead/hypothesis board before anything becomes a finding;
- durable tool receipts and parser status before tool output can affect proof;
- refuter workflows and integrity ledgers that record benchmark/planner mistakes instead of hiding
  them.

The merged roadmap rule is: **agentic planning may propose work, but deterministic ShakerScan
contracts decide execution, proof, evidence, findings, and gates.** Mission contracts, context packs,
decision traces, Command Arsenal status labels, scope receipts, approval receipts, policy-required
approval enforcement, and file-backed planner/benchmark integrity ledgers now exist in phase 1 form.
The next adoption increments are: command-result audit rows, a cross-product mission timeline,
campaign/hypothesis records, tool receipts, evidence instances, runtime destination re-checks,
refuter records, bounded source-informed hypotheses, and read-only MCP only after REST Command
Arsenal contracts are stable. No local-agent or MCP path may execute state-changing actions until
those audit, receipt, parser, and evidence layers are durable.

The T3MP3ST plan adds useful implementation detail that this roadmap should preserve:

- Treat "War Room / Op Admiral" as ShakerScan's mission intake and campaign timeline, not as a
  separate agent console. A mission is an objective over ASM, DAST, AI Gate, Model Intake, retests,
  exceptions, evidence, and deployment gates.
- Treat Arsenal commands as product actions, not binaries. Good commands are `asm.gaps`,
  `asm.improve`, `scan.focused_family`, `finding.retest`, `ai_gate.replay_probe`,
  `model_intake.trust_preview`, and `deployment.decision`; bad commands are `run_shell`,
  `run_sqlmap`, `curl_this_url`, or `execute_python`.
- Treat external tools as internal adapters with receipts. Tool count is not progress until the
  adapter has scope extraction, version/smoke status, redacted argv, parser status, evidence refs,
  timeout/failure handling, and an operator-visible state.
- Treat PackBoard as ShakerScan hypotheses. Leads from graph facts, source/spec hints, AI planners,
  scanner weak signals, AI Gate, Model Intake, and humans are coordinated work items; they are not
  findings until a proof path promotes them.
- Treat refuters as a product workflow. High-impact weak claims, AI semantic hits, metadata trust
  claims, benchmark wins, parser-promoted results, and deployment-gating findings should be
  challengeable without deleting history.
- Treat source-informed testing as graph/hypothesis input only. Source, OpenAPI, GraphQL, package,
  frontend, backend, and IaC facts can enrich the worklist, but source text alone can never satisfy a
  runtime proof contract.
- Treat MCP as a later transport over REST Command Arsenal. It must start read-only and must not
  expose any command or bypass any guard that REST does not already expose.

Every agent-facing or operator-facing capability should carry an explicit maturity label until it is
fully implemented:

| Label | Meaning |
| --- | --- |
| `contract` | Schema or documentation only; no runtime behavior. |
| `read_only` | Can inspect stored ShakerScan state only. |
| `dry_run` | Can produce plans/previews but cannot queue work or mutate target state. |
| `gated` | Can execute only through scope receipt, approval/policy checks, and existing API handlers. |
| `proof_backed` | Can affect findings/gates because a deterministic evidence contract exists. |
| `experimental` | Available behind feature flag; not for production claims. |
| `catalog_only` | Known future adapter or command; not wired or runnable. |
| `out_of_scope` | Intentionally excluded from the current roadmap. |

T3MP3ST features are translated as follows in this roadmap. The table is deliberately conservative:
anything that can queue work, touch a target, consume credentials, or influence findings remains
behind ShakerScan-owned API handlers, policy profiles, receipts, proof contracts, and evidence
records.

| T3MP3ST idea | ShakerScan implementation target | Current status |
| --- | --- | --- |
| Op Admiral / mission intake | `OperationPlan` plus cross-product campaign timeline | dry-run plan persistence done; unified timeline open |
| Local-agent brain mode | bounded planner that emits `OperationPlan`, never direct tool execution | deterministic dry-run planner done; real adapters disabled |
| Arsenal | REST Command Arsenal over ShakerScan product actions | read-only schemas/status done; gated execution gateway/audit open |
| Scope/approval gates | `ActionScopeGuard`, `ScopeReceipt`, `ApprovalReceipt` | optional validation and policy-required enforcement done for existing routes; runtime redirect/resolution re-checks open |
| PackBoard | `campaigns`, `campaign_actions`, `hypotheses`, situation reports | campaign actions + hypothesis records phase 1 done; graph routing/situation reports open |
| Evidence gate | proof taxonomy, evidence objects, evidence instances, tool receipts | proof taxonomy/evidence objects done; instances/receipts open |
| Arsenal doctor | tool status and receipt registry | status endpoint/UI phase 1 done; receipts open |
| Refuter culture | weak-claim refuter workflow and integrity ledgers | ledgers phase 1 done; refuter records/workflow open |
| Source-informed testing | graph facts and hypotheses from source/spec inputs | later/experimental |
| MCP interface | thin adapter over REST Command Arsenal | later/read-only first |

### T3MP3ST-derived implementation waves

Use these waves to decide sequence when a T3MP3ST idea competes with detector work:

1. **Contracts and labels:** DONE phase 1 for mission, context, trace, command, receipt, risk, and
   maturity contracts. Remaining work is campaign/hypothesis schema persistence and release gates.
2. **Read-only operator visibility:** DONE phase 1 for Command Arsenal/status and dashboard/product
   cards. Remaining work is the cross-product mission timeline and command results for blocked work.
3. **Safety receipts and audit:** DONE phase 1 for scope/approval receipts and optional plus
   policy-required enforcement. Remaining work is runtime destination re-checks, blocked/denied audit
   rows, and campaign action records.
4. **Planner evaluation before planner power:** DONE phase 1 for fixture scoring and dry-run local
   planning. Remaining work is harmless capability ping, strict parser validation, and release gates
   that prevent raw shell, scope broadening, risk escalation, or AI-verified claims.
5. **Hypotheses before new detectors:** DONE phase 1 for campaign-action audit records and durable
   hypothesis records with dedupe, endorsements, and claim leases. Remaining work is graph/source/AI
   signal routing, bounded situation reports, and refuter workflow before treating broad agent output
   as product truth.
6. **Receipts before new tools:** wrap existing tools first (`httpx`, `katana`, `nuclei`,
   `subfinder`, `ffuf`, `dalfox`, `sqlmap`, `nmap`, TLS tools, Playwright, AI Gate executor, Model
   Intake artifact/signature checks). New offensive tooling stays `catalog_only`.
7. **External evidence and replay:** split concrete proof instances from canonical findings,
   externalize large artifacts, add retention/export manifests, and make missing evidence degrade
   reports honestly.
8. **Read-only MCP, then gated MCP later:** only after REST Command Arsenal, receipts, evidence,
   planner evals, and audit records are reliable.

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
- **Dashboard Product Status phase 1** — `/dashboard` now returns `product_status` cards for DAST,
  Continuous ASM, AI Gate, Model Intake, policy exceptions, deployment gates, and worker freshness.
  The dashboard renders blocker/running/stale counts and safe quick links from API facts rather than
  client-side inference.
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
- **Read-only Command Arsenal and integrated tool status phase 1** — `/arsenal/commands` now exposes
  schema-versioned product command contracts, risk tiers, required confirmations, scope fields,
  redaction rules, and evidence contracts. `/arsenal/tools` exposes integrated scanner/tool adapter
  status with optional read-only version probes. `/settings/arsenal` renders both surfaces without
  adding a state-changing execution path.
- **Mission contract schema phase 1** — `/arsenal/contracts` now exposes read-only schemas for
  `OperationPlan`, `AgentContextPack`, `AgentDecisionTrace`, `ScopeReceipt`, `ApprovalReceipt`,
  `CommandResult`, `ToolReceipt`, `CampaignAction`, `Hypothesis`, and `EvidenceInstance`, including
  secret-handling policy and safety invariants. `/settings/arsenal` renders these contracts without
  adding planning, approval, or execution power.
- **OperationPlan persistence phase 1** — `POST /arsenal/plans` now validates and persists dry-run
  `OperationPlan` records without executing actions. Plans validate context-hash format, known
  Command Arsenal command names, risk-tier escalation, gated-action confirmations, scope receipts,
  approval receipts, and receipt/scope consistency; `GET /arsenal/plans` returns recent plans with
  validation errors/warnings and `execution_enabled=false`. `/settings/arsenal` can create and review
  these dry-run plan records from the same scope/approval receipt workflow.
- **AgentContextPack / AgentDecisionTrace persistence phase 1** — `POST /arsenal/context-packs`
  validates and stores bounded redacted planning context without exposing raw transcripts, secrets, or
  execution power; `POST /arsenal/decision-traces` validates and stores dry-run operational traces,
  rejects executed-action claims in traces, checks linked context/plan hashes, and keeps
  `execution_enabled=false`. `/settings/arsenal` can record and review context/trace rows from the
  same dry-run operator workflow.
- **Local-agent capability discovery phase 1** — `GET /agents/local` returns read-only capability
  records for Codex, Claude Code, OpenCode, and Hermes-style local planners: binary detection,
  optional version probe, auth-artifact existence only, support flags, prompt/output caps, and risk
  notes. It never reads auth artifact contents, never forwards provider API keys, and keeps
  planner execution disabled. `/settings/arsenal` renders the same capability matrix.
- **Planner eval fixtures and integrity-ledger locations phase 1** —
  `tests/fixtures/planner_evals/planner_eval_fixtures.json` captures the required dry-run planning
  safety fixtures, and `scripts/planner_evals.py` scores candidate `OperationPlan` JSON for command
  selection, missing inputs, risk tier, scope broadening, raw shell, forbidden verified claims, and
  blocked reasons. `results/planner-evals/INTEGRITY_LEDGER.md` and
  `results/benchmark-runs/INTEGRITY_LEDGER.md` now provide durable correction ledgers.
- **Target-fact generated AgentContextPack phase 1** — `POST /arsenal/context-packs/from-target`
  now builds and persists bounded redacted context packs from stored target facts: target metadata,
  ASM coverage, endpoint state counts, sampled endpoint inventory, active finding summaries with
  server-derived proof state, known preconditions, and current Command Arsenal allow/deny state. The
  command is exposed as `agent_context_pack.generate_from_target` with `dry_run` / `read_only`
  maturity, and `/settings/arsenal` can generate a pack from a target ID without queueing work or
  giving local agents execution power.
- **Local-agent dry-run planning phase 1** — `POST /agents/local/plan` now creates and persists a
  validated `OperationPlan` from a saved bounded `AgentContextPack`, labels the planner as
  `local_agent`, and records `local_agent_spawned=false` / `planner_execution_enabled=false`. It uses
  deterministic read-only planning rules and server-side validation; Codex/Claude/OpenCode/Hermes
  CLIs are still not spawned, shell access is still unavailable, and no scanner work is queued.
  `/settings/arsenal` can generate that dry-run plan from a selected local-agent label and context
  pack ID.
- **ActionScopeGuard and persisted scope receipt preview phase 1** — `api.action_scope.evaluate_scope`
  now fail-closes malformed URLs, scheme-relative URLs, userinfo, trailing-dot hosts,
  Unicode/punycode confusion, loopback/private/reserved ranges outside lab policy, broad CIDRs,
  hosts outside the provided allowed scope, and supplied redirect destinations that leave scope.
  `POST /arsenal/scope/preview` persists `scope_receipts` without queueing work, and
  `/settings/arsenal` exposes the read-only receipt preview.
- **Approval receipt recording phase 1** — `POST /arsenal/approvals` now persists approval or denial
  receipts bound to an existing `scope_receipt`, requires `confirm_authorized` for approvals, rejects
  approval of blocked scopes, and preserves `execution_enabled=false`. `/settings/arsenal` can record
  an approval/denial for the previewed scope without queueing work.
- **Approval receipt validation phase 1** — `/scans`, `/targets/{id}/asm/test`,
  `/targets/{id}/asm/recon`, and `/targets/{id}/asm/improve` now accept optional
  `approval_receipt_id`, validate that it is approved, unexpired, confirm-authorized, linked to a
  non-blocked scope, and compatible with the requested target host/id, then stamp
  `approval_receipt_id` / `scope_receipt_id` into queued scan options. Legacy submissions without a
  receipt still work; mandatory enforcement is the remaining rollout step.
- **Approval receipt validation phase 2** — AI Gate scans, AI Gate finding replay, AI Gate campaign
  replay, Model Intake scans, single finding retest, and bulk finding retest now also accept optional
  `approval_receipt_id`. They validate the same approval/scope invariants against the saved AI target,
  model artifact reference, or finding retest target before queueing, then stamp receipt IDs into
  queued scan/retest metadata where that route has a durable job/options record. Legacy submissions
  without a receipt still work; mandatory enforcement is still a policy rollout step.
- **Policy-based approval receipt enforcement phase 1** — `/settings/automation` now exposes
  `approval_receipts_required_for_state_changing_actions`. When enabled, scan submission, ASM
  recon/test/improve, AI Gate scans/replay, Model Intake scans, single finding retest, and bulk
  finding retest reject missing `approval_receipt_id` before queueing work; scan and Model Intake
  routes perform an early missing-receipt guard before target-row creation. Compatibility mode remains
  the default until an operator explicitly enables the policy.
- **Command-result audit records phase 1** — `command_results` now persists sanitized read-only audit
  rows for successful queued product actions from `/scans`, ASM recon/test/improve, AI Gate
  scan/finding replay/campaign replay, Model Intake scans, and single/bulk finding retests. The
  records include operation id, command, status, risk tier, scope/approval receipts, scan/finding
  refs, blocked/skipped reasons when available, next action, and operator message.
  `GET /arsenal/command-results`, `command_result.list`, the `CommandResult` contract, and
  `/settings/arsenal` expose the recent audit trail.
- **Blocked/denied command-result rows** — the enforcement path (`_require_approval_receipt_if_policy_enabled`,
  `_validate_approval_receipt_for_action`) now writes a durable `command_results` row with status
  `approval_required`/`blocked` and a specific `blocked_by` reason (e.g. `approval_receipt_expired`,
  `approval_scope_host_mismatch`) before it raises, best-effort and FK-safe, so "nothing ran because
  policy/scope blocked it" is auditable with the same operation id and receipt refs as a queued
  action. Bulk retest records one aggregate blocked row when nothing queues.
- **Cross-product mission timeline phase 1** — `GET /timeline` (Command Arsenal `mission.timeline`)
  merges command-result audit rows (with live scan status joined in), recent user-facing scans not
  tied to a command result, and upcoming schedules into one normalized event feed with the explicit
  statuses (`planned`/`blocked`/`approval_required`/`queued`/`running`/`completed`/`partial`/
  `degraded`/`failed`/`cancelled`/…) and event fields (`event_id`, `kind`, `command`, `status`,
  `risk_tier`, `target_id`, `scan_id`, `active_scan_id`, `operation_plan_id`, `campaign_id`,
  `blocked_by`, `next_eligible_at`, `operator_message`). Optional `target_id` filter. Campaign/action
  execution records and evidence/refuter events remain open.
- **Local-agent harmless capability ping phase 1** — `POST /agents/local/test` now runs only the
  configured version/capability command for known local-agent binaries with timeout/output caps,
  environment credential stripping, no prompt, no planner execution, no target state mutation, and no
  queued scanner work. `local_agent.test` is registered as a dry-run/read-only Command Arsenal
  command, and `/settings/arsenal` exposes a per-agent Ping action plus safety facts from the result.
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
- **Model Intake saved trust anchors phase 1** — `/model-intake/trust-anchors` now stores reusable
  operator trust roots (PEM and/or SHA-256 fingerprint) with owner/profile metadata. Model Intake scan
  requests can pass `trust_anchor_ids`; the API expands active anchors into the existing trusted-key
  material before queueing, and the UI can create, select, refresh, and deactivate anchors in strict
  trust mode.
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
  scheduler decision object. Dashboard Action Center items now expose structured safe CTAs, and
  `/dashboard.product_status` now provides API-backed product status cards for DAST, ASM, AI Gate,
  Model Intake, exceptions, deployment gates, and worker freshness. The next dashboard gap is deeper
  remediation flow, not counts/links or the base action contract.
- Model Intake has the low-level trust fields in API/UI, guided trust modes, pre-submit preview, and
  saved trust-anchor selection/creation. Strict policy profiles can now require saved anchors and
  matching Model Intake scans inherit them. Deployment decisions now expose strict policy-required
  anchor gaps plus exception hygiene/expiry summaries, and dashboard Model Intake trust blockers now
  open `/settings/model-intake?remediate=trust`, which selects the strict trusted-anchor path and
  focuses the trust remediation panel. Remaining work is broader exception remediation workflow depth,
  not more low-level signature fields.
- AI Gate has transcripts, reports, adaptive probes, MCP readiness, control evidence, a first
  campaign review surface on scan detail, scan-level rerun actions for skipped/errors/family/all,
  per-transcript replay actions, same-context run comparison on scan detail, and target-level
  longitudinal campaign history on the AI Gate target surface. Remaining AI Gate gaps are deeper
  readiness trends and report export from the target-level history view.

### Immediate implementation sequence

These are the next commit-sized slices, in order. The T3MP3ST adoption plan is now folded into this
roadmap as an operating model, not a separate product direction. Borrow mission planning, command
schemas, scope/approval receipts, lead boards, tool receipts, and integrity ledgers; do **not** borrow
raw shell execution or LLM-produced verified findings.

1. **Mission/command contracts:** DONE phase 1 for read-only schema discovery:
   `OperationPlan`, `AgentContextPack`, `AgentDecisionTrace`, Command Arsenal schemas, command result
   schema, risk tiers, scope receipt, approval receipt, tool receipt, campaign action, hypothesis, and
   `EvidenceInstance` schemas. DONE phase 1 for persisted dry-run `OperationPlan` validation records.
   DONE phase 1 for persisted `AgentContextPack` and `AgentDecisionTrace` validation records.
   DONE phase 1 for read-only local-agent capability records. DONE phase 1 for target-fact generated
   `AgentContextPack` records from stored target, ASM, endpoint, finding, precondition, and command
   facts. DONE phase 1 for local-agent-labeled deterministic dry-run `OperationPlan` creation from a
   context pack without spawning local-agent CLIs. DONE phase 1 for policy-required approval receipt
   enforcement on current state-changing API routes. DONE phase 1 for command-result audit records on
   successful queued product actions. DONE phase 1 for blocked/approval-required command-result rows,
   durable campaign-action audit records (`campaign_actions` / `GET /arsenal/campaign-actions`), and
   a read-only cross-product mission timeline (`GET /timeline`). Remaining work is standalone
   execution-gateway action state, runtime destination re-checks, and later optional real local-agent
   adapter parsing behind stricter gates; it still must add no new execution power until receipts,
   command audit records, parser validation, and evidence gates are durable.
2. **Unified Action Center + mission timeline:** DONE phase 1 — `GET /timeline` merges command-result
   audit rows (with live scan status), recent scans, and upcoming schedules into one normalized event
   feed with explicit statuses. DONE phase 1 for campaign-action audit records mirrored from command
   results plus read-only timeline support for standalone action rows. Remaining work is evidence
   export/replay + refuter events on the same feed.
3. **Command Arsenal execution gateway, still no raw shell:** extend the schema-discoverable
   Command Arsenal into a gated product-action layer over existing API handlers. It is not the check
   registry, not the external tool registry, and not a shell runner. Every command result must carry
   operation id, status, dry-run flag, scope/approval ids, campaign id, scan/finding/evidence/tool
   receipt refs, blocked reasons, next action, and operator message.
   The first executable command families should be inventory, ASM, scans, findings, AI Gate, Model
   Intake, evidence, governance, and tool status. External binaries may be used only behind narrow
   adapters; the command schema should never expose raw shell, arbitrary Python/Node execution, or
   generic "run this command" behavior.
4. **Scope and approval receipts for state-changing actions:** DONE phase 1 for central
   `ActionScopeGuard`, persisted `ScopeReceipt` previews, and durable `ApprovalReceipt` records.
   DONE phase 1 for optional receipt validation on `/scans` and Continuous ASM recon/test/improve.
   DONE phase 2 for optional receipt validation on AI Gate scans/replay, Model Intake scans, and
   finding retests. DONE phase 1 for policy-based mandatory enforcement across those existing
   state-changing routes via `/settings/automation`. DONE phase 1 for command-result audit rows on
   successful queued operations, and for blocked/approval-required rows written before the enforcement
   path raises (best-effort, FK-safe). Remaining work is campaign/action execution records, runtime
   redirect/resolution scope re-checks, and extending the same enforcement model to future command/MCP
   adapters.
5. **Continuous ASM quality lane:** make `/asm/coverage`, `/asm/gaps`, scan detail, Action Center,
   and the mission timeline agree on family-aware state: attempted, proved, partial, blocked by auth,
   blocked by second user, blocked by schedule/rate cap, stale, and worker-stale.
6. **Campaign + hypothesis layer:** DONE phase 1 for durable deduped hypotheses/leads, endorsements,
   read APIs, bounded context-pack summaries, compare-and-set claim leases, and app-graph authz
   hypothesis generation. Remaining work is to route source/spec hints, AI planner suggestions, weak
   scanner signals, AI Gate signals, and Model Intake metadata claims into those hypotheses.
   Hypotheses are claimable/refutable work items, not findings.
7. **Detector recall campaigns:** keep benchmark gaps as proof-backed work items: POST-body SQLi,
   NoSQL JSON/body routing, stored/reflected XSS browser proof, workflow/write-side BOLA, mass
   assignment/JWT, and graph-driven authz hypotheses.
8. **Evidence store phase 2 and tool receipts:** split canonical findings from concrete
   `EvidenceInstance` rows, externalize large artifacts, add retention/export manifests, and receipt-wrap
   existing tools before adding any new offensive tooling.
   Treat this as the T3MP3ST evidence-gate adoption point: parser failure, timeout, missing binary,
   missing smoke status, or missing proof-critical evidence must produce a skipped/degraded/blocked
   record, not a verified finding or phantom success.
9. **Registry-driven execution:** migrate scanner family execution and report rollups to proof
   contracts after the evidence/proof shape is stable.
10. **Refuter and integrity layer:** add refuter workflows for weak High/Criticals, AI Gate semantic
    hits, Model Intake metadata claims, benchmark wins, and deployment-gating findings. Add benchmark
    and planner integrity ledgers for contamination, retractions, stale-fleet runs, phantom tool
    assumptions, and methodology corrections. DONE phase 1 for file-backed planner/benchmark ledger
    locations and planner fixture scoring.
11. **Planner evals and local-agent planning, dry-run only:** planner fixtures, integrity ledgers,
    local-agent capability detection, target context packs, deterministic local-agent-labeled
    dry-run planning, and bounded harmless local-agent capability ping/testing are phase 1 done.
    Remaining work is strict parsed-output validation and fixture-gated real-adapter experiments.
    Local agents may propose plans; they must not execute shell commands, broaden scope, bypass
    confirmations, or mark findings verified. A real prompt-based planner adapter can come only after
    strict JSON parsing, output caps, fixture gates, and receipt/audit records are stable.
12. **AI Gate and Model Intake polish:** add AI Gate target-history export/readiness trends and Model
    Intake exception remediation workflow depth after the cross-product operator surface can link to
    them cleanly.

### Positioning-adjusted priority order

Use this order when choosing between otherwise-valid work:

- **P0: contracts and read-only operating layer.** `OperationPlan`, Command Arsenal, risk tiers,
  scope/approval receipt schemas, context packs, decision traces, tool status, maturity labels, and
  integrity-ledger locations are phase 1 done. Policy-required approval enforcement is phase 1 done
  for current state-changing routes. The remaining P0 work is turning these into auditable
  operation/campaign records without adding raw shell or direct local-agent execution power.
- **P0: productize shipped foundations.** The base Action Center/CTAs, Product Status cards,
  Exceptions Queue, first-class ASM schedule kinds, and target campaign timeline phase 1 are already
  done. Remaining P0 work is the unified mission timeline, deeper safe remediation entry points, and
  cross-page agreement on blocker/blocked/running state.
- **P1: safety receipts for state-changing actions.** Central `ActionScopeGuard`, durable scope
  receipts, durable approval records, dry-run previews, policy-required receipt enforcement, command
  result audit rows, redirect/runtime destination checks, and explicit
  production/lab/credential/high-risk gates.
- **P1: make Continuous ASM the flagship.** Family-aware coverage quality, proof-quality gaps,
  worker-aware waves, CT/new-surface inheritance, Improve Coverage explanations, and mission-timeline
  events that always say what ran, what skipped, why, and what evidence exists.
- **P1: campaign + hypothesis layer.** Graph/source/AI/tool signals become deduped, claimable,
  refutable hypotheses before they become findings. Graph-driven authz work should flow through this
  layer rather than creating direct findings from durable graph facts.
- **P1: refuter and integrity discipline.** High-impact or weakly supported claims should be
  challenged by deterministic replay, parser/protocol evidence, cryptographic verification, or
  human-approved review policy before they influence gates. Benchmark and planner mistakes should be
  logged as durable integrity records.
- **P1: close benchmark proof gaps.** Browser-first/stored XSS, POST-body SQLi, NoSQL JSON/body
  routing, workflow/write-BOLA, mass assignment, JWT/session weakness, and deterministic retest loops
  per verified family.
- **P1/P2: evidence store phase 2 and existing-tool receipts.** External object storage,
  `EvidenceInstance` proof instances, retention/sweeper, redaction consistency, audit/export
  manifests, and receipts for current tools such as Nuclei, sqlmap, Dalfox/browser proof, nmap,
  subfinder, Playwright, AI Gate probe execution, and Model Intake signature verification.
- **P2: AI red-team campaign UX.** Scan-detail campaign review, coverage matrix, skipped reasons,
  transcript/report links, finding-level replay entry points, scan-level rerun actions, selected
  transcript replay, same-context scan comparison, and target-level history are phase 1 done.
  Remaining work is export/readiness trend polish from target history and campaign evidence manifests.
- **P2: Model Intake trust UX.** Guided trust modes, pre-submit trust preview, saved trust anchors,
  scan selection, strict policy-profile anchor binding, and deployment-decision anchor gaps are phase 1
  done. Remaining work is exception remediation workflow depth and campaign evidence export.
- **P2: registry-driven execution.** Migrate scanner execution and report rollups to proof contracts,
  telemetry schemas, safety gates, and family-specific run contracts.
- **P2/P3: planner evals and local-agent planning.** Only after read-only Command Arsenal and safety
  receipts are stable, add planner fixture scorecards, bounded/redacted context packs, durable
  decision traces, local-agent capability detection, and optional dry-run local-agent planning.
- **P3: MCP, new tools, multi-node, and internet-scale ASM.** MCP must be a thin adapter over REST
  Command Arsenal; new tools stay `catalog_only` until receipts/proof contracts exist. Multi-node and
  internet-scale ASM wait until queue leases, object evidence, worker freshness, campaign semantics,
  and proof/evidence invariants stay green.

### 1. Product-operability layer: one place that explains "what needs action"
**Status: PHASE 1 DONE, PRODUCTIZED DECISION FLOW OPEN.** `/dashboard` now includes a server-backed
`action_center` feed built from worker freshness, deployment blockers, failed scans, exception
hygiene, ASM coverage/schedule facts, Model Intake signature trust, and AI control-baseline gaps.
The dashboard renders this as a prioritized Action Center. ASM policy/gaps/improve/activity now
expose live `scheduler_state`, and dispatcher/scheduler decisions are persisted as
`metadata_json.asm_last_decision`. `/settings/exceptions` now provides the first dedicated
Exceptions Queue. Dashboard items now expose structured safe CTAs. `GET /timeline` now provides a
read-only cross-product mission timeline (command results with live scan status + recent scans +
upcoming schedules) with explicit API-backed statuses. Remaining work is product-level
decision flow: summarize each product area, show blocker/stale/running counts, explain why work is
blocked, and provide safe remediation links without making users infer state from scan JSON.

**Implement:**
1. DONE: extend Action Center items with safe CTAs for workers, failed scans, target-preselected ASM
   coverage, exception queues, Model Intake trust gaps, and AI control gaps.
2. DONE: extend first-class "next action" and "why skipped" facts from ASM policy/gaps/improve/activity
   into Dashboard Action Center CTAs where target/action links are safe.
3. DONE: add an Exceptions Queue page/filter for `finding_exceptions`: expiring soon, expired,
   missing owner/approver, no compensating controls, policy-scoped, and target-scoped.
4. DONE: make finding filters use product taxonomy consistently. Dashboard product counts/quick
   links are now backed by `/dashboard.product_status`, not browser inference.
5. DONE: add `/dashboard.product_status` or equivalent API-backed cards for DAST, ASM, AI Gate,
   Model Intake, policy exceptions, deployment gates, and worker freshness. Do not compute these
   counts only in the browser.
6. PARTIAL/NEXT: add safe remediation routes from those cards: open failed scans, open target ASM timeline,
   open missing-auth/second-user blockers, open exception hygiene filters, open AI Gate
   readiness/control gaps, and open worker rebuild/scale controls. DONE for Model Intake trust
   blockers: `/settings/model-intake?remediate=trust` selects strict trusted-anchor mode, highlights
   the trust controls, and links exception hygiene.
7. DONE phase 1: `GET /timeline` merges the command-result audit rows (with live scan status joined),
   recent user-facing scans, and upcoming schedules into one normalized cross-product event feed with
   an optional `target_id` filter. Remaining sources to fold in are evidence export/replay events and
   refuter requests, once those subsystems exist.
8. DONE phase 1: timeline statuses are explicit and API-backed: `planned`, `blocked`, `approval_required`,
   `approved`, `queued`, `running`, `completed`, `partial`, `degraded`, `failed`, `cancelled`,
   `evidence_bound`, `retest_scheduled`, and `refuter_requested`.
9. DONE phase 1: timeline events carry `event_id`, `campaign_id`, `target_id`,
   `operation_plan_id`, `kind`, `status`, `action_name`, `risk_tier`, `blocked_by`,
   `next_eligible_at`, `active_scan_id`, `evidence_object_ids`, `tool_receipt_ids`, and a concise
   `operator_message`.

**Done when:** a junior operator can answer, from one screen, "what is risky, what is blocked, what
will run next, and which button fixes the next blocker" without reading scan JSON or worker logs.

### 2. Mission contract, Command Arsenal, and scope/approval receipts
**Status: READ-ONLY / DRY-RUN / GATED PHASE 1 DONE; ACTION AUDIT PHASE 1 DONE; RUNTIME RE-CHECKS OPEN.** The
T3MP3ST adoption plan correctly identifies the missing operating model: ShakerScan has many
safe/productized primitives, and now has persisted dry-run mission/context/trace/receipt records plus
policy-required approval enforcement on current state-changing routes. The remaining goal is not
broad agent execution. It is deepening the campaign/action audit records beyond the first mirrored
command-result ledger, re-checking runtime destinations, and keeping every future planner/MCP path on
the same API rails.

Command Arsenal boundaries:

- It is the safe product action layer exposed to UI, REST, AI Ops Router, local-agent planners,
  scheduler, and future MCP clients.
- It is not the scanner check registry.
- It is not the external tool registry.
- It must not expose raw shell, arbitrary Python/Node execution, or generic "run this command"
  behavior.
- External binaries may run only behind narrow adapters that produce tool receipts and evidence
  parser status.
- Product commands should stay human/action-oriented: `target.list`, `domain.list`,
  `exposure.graph.get`, `asm.gaps`, `asm.improve`, `asm.recon`, `asm.test`, `scan.submit`,
  `scan.focused_family`, `finding.retest`, `ai_gate.scan`, `ai_gate.replay_probe`,
  `model_intake.trust_preview`, `model_intake.scan`, `evidence.export_manifest`,
  `deployment.decision`, `exception.request`, and `tool.status`.
- Product commands should not describe low-level binaries: no `run_sqlmap`, `run_nmap`,
  `curl_this_url`, `execute_shell`, or `run_python_code` command should appear in Command Arsenal.

**Implement:**
1. DONE phase 1: define read-only `OperationPlan` schema with objective, planner metadata, context
   hash, target scope, allowed hosts, environment, allowed/disallowed families, budget/rate/window
   constraints, missing inputs, confirmations, actions, stop conditions, and success criteria.
   DONE phase 1 persistence: `/arsenal/plans` stores validated dry-run plans and never queues actions.
2. DONE phase 1: define read-only `AgentContextPack` schema as a bounded redacted summary: target
   summary, current surface, ASM/family gaps, hypothesis summary, active findings with proof
   state/evidence IDs, allowed/disallowed commands, known preconditions, worker freshness, and
   `context_hash`. Prefer evidence IDs over raw evidence bodies; never send secrets or full
   transcripts by default. DONE phase 1 persistence: `/arsenal/context-packs` validates, redacts,
   stores, and lists bounded context packs with `execution_enabled=false`. DONE phase 1 generation:
   `/arsenal/context-packs/from-target` creates the bounded pack from existing target/ASM/endpoint/
   finding facts and stores it without queueing work.
3. DONE phase 1: define read-only `AgentDecisionTrace` schema for durable operational trace:
   planner kind/version, context hash, command schema version, proposed/rejected actions, missing
   inputs, approvals/denials, result summaries, evidence refs, and final rationale. Do not store
   hidden chain-of-thought or raw secrets. DONE phase 1 persistence: `/arsenal/decision-traces`
   validates, stores, and lists dry-run traces, rejects executed-action claims, and verifies linked
   context/plan hash consistency.
4. DONE phase 1: add a read-only Command Arsenal schema for product actions, not shell commands.
   `/arsenal/commands` currently includes the initial read-only commands plus gated placeholders for
   state-changing actions such as ASM improve, focused family scans, finding retest, AI probe replay,
   and Model Intake scans.
5. DONE phase 1: add risk tiers: `read_only`, `passive`, `active`, `intrusive`, `credential`, and
   `dangerous`. Every command declares status (`contract`, `read_only`, `dry_run`, `gated`,
   `proof_backed`, `experimental`, `catalog_only`, `out_of_scope`), required confirmations, scope
   fields, redaction contract, and evidence contract.
6. DONE phase 1 for scope previews: add central `ActionScopeGuard` and durable `ScopeReceipt`
   preview records before any new state-changing Command Arsenal execution path. Scope checks now
   fail closed for malformed URLs, scheme-relative URLs, userinfo tricks, punycode/Unicode confusion,
   trailing-dot hosts, loopback/private ranges outside lab policy, broad CIDRs, hosts outside the
   provided allowed scope, and supplied redirect destinations that leave scope. DONE phase 1 for
   durable `ApprovalReceipt` recording: approvals require `confirm_authorized`, needs-approval scopes
   require `confirm_scope_reviewed`, and blocked scopes cannot be approved. DONE phase 1 for optional
   route validation on scan submission and Continuous ASM actions. DONE phase 2 for optional route
   validation on AI Gate scans/replay, Model Intake scans, and finding retests. DONE phase 1 for
   policy-based mandatory enforcement across those existing state-changing routes through
   `/settings/automation`.
7. Keep `/ai/ops/route` as the execution safety gateway. Local agents, AI Ops Router, scheduler, MCP,
   and UI should all use the same command schemas and scope/approval receipts; none may bypass the
   existing API handlers.
8. DONE phase 1: add local-agent capability records before any planner connector is usable.
   `GET /agents/local` exposes binary presence, optional version probe, auth-detected status without
   reading auth artifact contents, headless/JSON mode support, timeout support, workdir isolation
   support, network-disable support if any, max prompt and output bytes, and adapter risk notes.
9. DONE phase 1: add local-agent-labeled dry-run planning without spawning local planners:
   `POST /agents/local/plan` consumes a saved bounded `AgentContextPack`, uses deterministic
   read-only planning rules, persists a validated `OperationPlan`, and exposes
   `local_agent_spawned=false` / `planner_execution_enabled=false`.
10. Strip provider API-key environment variables when spawning local planners. Send bounded context
   packs and command schemas; do not send secrets, cookies, bearer tokens, private keys, raw
   transcripts, or raw request/response bodies by default.
11. DONE phase 1: add benchmark/planner integrity ledgers for stale workers, benchmark fitting, hidden contamination,
   AI prose counted as evidence, phantom tool assumptions, auth context not actually used, planner
   scope/risk broadening, and unrunnable planned families being presented as runnable. The first
   implementation is file-backed under `results/benchmark-runs/INTEGRITY_LEDGER.md` and
   `results/planner-evals/INTEGRITY_LEDGER.md`.
12. DONE phase 1: add policy-based mandatory approval receipt enforcement for existing
    state-changing action routes. Legacy no-receipt mode remains the default compatibility setting
    until an operator explicitly enables the requirement.
13. Check scope twice for network-following actions: before execution from declared parameters, and
    during/after redirects or resolution from actual destination. If runtime destination cannot be
    verified, mark the action blocked or degraded rather than in-scope.
14. DONE phase 1: add command result audit records for successful queued product actions: operation id, command,
    status, dry-run flag, risk tier, operation-plan id, scope receipt id, approval id, campaign id,
    scan id, finding ids, hypothesis ids, evidence object ids, tool receipt ids, blocked reasons,
    next action, operator message, sanitized result summary, and created-by/source metadata.
15. DONE phase 1: route successful current API actions into those command-result rows first: `/scans`, ASM
    recon/test/improve, AI Gate scan/replay, Model Intake scan, single/bulk finding retest, and
    finding-level AI replay.
16. Keep command-result records separate from scanner-family proof contracts. A queued operation is
    not evidence, and a command result may never mark a finding verified without downstream proof
    objects/evidence instances.
17. DONE phase 1: add a read-only command-result UI panel under `/settings/arsenal`. DONE phase 1:
    the same records feed the cross-product mission timeline (`GET /timeline`). DONE phase 1:
    `campaign_actions` mirrors command-result audit rows into action-shaped records,
    `GET /arsenal/campaign-actions` exposes them read-only, `campaign_action.list` advertises the
    surface, `/settings/arsenal` renders the campaign action ledger, and the mission timeline can
    include standalone action rows without duplicating mirrored command-result events. Remaining work
    is richer execution-gateway action transitions and evidence/refuter events.
18. DONE phase 1: blocked and approval-required command-result records are written before the
    enforcement path raises (best-effort, FK-safe), so "nothing ran because policy/scope blocked it"
    is auditable with the same operation id, scope/approval refs, blocked reasons, and next action.
    Remaining: skipped/degraded rows for non-policy skip paths and runtime-check blocks.
19. Add release/test gates for Command Arsenal and planner safety:
    `test:no-phantom-tools`, `test:no-benchmark-fitting`, `test:no-ai-verified`,
    `test:evidence-provenance`, `test:fleet-current`, `test:planner-scope`,
    `test:planner-risk`, and `test:planner-no-shell`.

**Done when:** a mission can be planned, previewed, blocked, approved, queued, executed, and audited
through one schema without exposing raw shell, bypassing policy gates, or allowing AI/local-agent prose
to create verified findings. A local agent can only produce a validated dry-run `OperationPlan` from
a bounded `AgentContextPack`; it cannot execute a command directly. Operators can also answer "what
was requested, who/what approved it, what ran, what was blocked, what evidence resulted, and what is
the next safe action" from stored command/campaign records.

### 3. ASM scheduling and campaign semantics
**Status: PARTIAL.** The backend can run scheduled ASM waves (`api.run_due_schedules`) and a
background dispatcher (`api.run_asm_dispatch`), while `/asm` exposes per-target policy and now shows
live/persisted scheduler decisions. `/schedules` has a visible ASM coverage-wave option and the
API/DB now expose first-class schedule kinds (`normal_scan`, `asm_improve`) with legacy
`scan_options.kind` compatibility. `/schedules` can now create and edit ASM waves with batch size,
stale-days, endpoint filter, focused family, and Lab/deep gating; due-run execution honors those
per-schedule settings when counting claimable work and enqueueing batches. `/targets/{id}/asm/activity`
now exposes and the ASM UI renders a derived campaign timeline that combines scheduler decisions,
next eligible time, next recurring ASM wave, active scans, last scheduler decision, and recent
activity. Remaining work is remediation actions from the timeline, not schedule payload depth.

**Implement:**
1. DONE: introduce a typed schedule kind (`normal_scan`, `asm_improve`) in API/DB/UI with
   migration/backfill and legacy `scan_options.kind` decode.
2. DONE: show one unified target timeline: background dispatcher decision, recurring schedule next run,
   current active scan/ASM batch, last activity, and last skip reason.
3. DONE: `/schedules` creates/edits ASM waves without pretending they have a DAST `scan_type`; it
   exposes batch size, stale days, endpoint filter, focused family, and Lab/deep gating only when
   relevant.
4. DONE/PARTIAL: schedule-kind validation, legacy decode, due-run dispatch, scoped ASM option
   execution, and target active-scan skip have backend tests. UI payload shape is covered by
   TypeScript/production build and browser QA; add component-level tests when the UI test harness
   expands beyond helper scripts.

**Done when:** "Keep this target covered" is a first-class scheduled/campaign action, not an
encoded scan option, and users can see why a target did or did not receive ASM work.

### 4. AI red-team campaign UX and replay loop
**Status: PARTIAL, PHASE 1 REVIEW DONE.** AI Gate has targets, scenario presets, deterministic/semantic judging,
redacted transcripts (`GET /ai/scans/{id}/transcript`), transcript purge, MCP readiness, control
inventory (`api.ai_assurance`), adaptive logic (`api/ai_gate/adaptive.py`), and red-team report
export (`GET /scans/{id}/ai-redteam-report` / `api.get_ai_redteam_report`). Completed scan detail
now renders a campaign review card backed by `ai_gate.coverage_matrix`, `execution_plan`, and
`evidence_manifest`, and `POST /ai/scans/{scan_id}/replay` queues focused reruns for skipped
probes, errored families, selected families, selected transcript probes, or all probes.
`GET /ai/scans/{scan_id}/campaign-history` returns same-context run comparison for the campaign
panel, and `GET /ai/targets/{target_id}/campaign-history` plus `/settings/ai-gate` now expose
target-level longitudinal run/context history outside a single scan detail page.

**Implement:**
1. DONE: add an AI Red-Team Campaign view grouping target, environment, profile, probe pack, readiness,
   control inventory, skipped probes, transcripts, findings, semantic judge output, and report export.
2. DONE: add an OWASP LLM / RAG / agent / MCP coverage matrix: planned, executed, skipped, blocked by
   safety profile, finding count, and evidence hash per family.
3. PARTIAL: finding-level replay entry points link to finding detail, where focused AI Gate replay
   already preserves production confirmation. Scan-level "rerun failed/skipped probes" now exists
   for skipped/errors/family/all modes and also preserves production confirmation. Selected
   transcript replay now exists through `mode=transcript` and uses the same production gate.
   Same-context campaign history/comparison now exists on scan detail. Target-level longitudinal
   run/context reporting now exists on the AI Gate target page.
4. DONE for the base Action Center: missing AI control-baseline gaps already appear there; remaining
   AI Gate campaign work is richer readiness/campaign history, not the first blocker card.

**Done when:** an AI red-team run can be reviewed, rerun, compared across runs, and defended as a
campaign artifact instead of a loose scan report. Phase 1 now satisfies this on scan detail and on
the AI Gate target page; export/readiness trend polish remains later work.

### 5. Model Intake trust UX
**Status: PARTIAL, PHASE 1 UI DONE.** The API and UI now carry real signature/trust-anchor fields:
`ModelIntakeScanRequest.signature_*` and the Model Intake page fields around signature URL, public
key URL/PEM, signature value, trusted keys, hash, payload, and padding. The form now adds guided
trust modes plus a pre-submit pass/fail/advisory preview, so users can see why checksum, signature,
trusted-root, governance, or approval evidence will block or remain advisory before queueing.
Saved trust-anchor selection/creation/deactivation is now implemented for strict trust mode.
Policy profiles can now bind required saved trust anchors, and matching strict Model Intake scans
inherit those anchors before cryptographic trust evaluation. Dashboard Model Intake blockers now open
the trust-remediation route state. Remaining ergonomics work is clearer exception remediation after
deployment decisions surface anchor gaps and exception expiry/hygiene.

**Implement:**
1. DONE: add a signature-mode segmented control: `checksum only`, `signature URL + key URL`, `inline
   signature + inline key`, `trusted key fingerprint`, and `metadata-supplied evidence`.
2. DONE: add a pre-submit validation/preview panel that states exactly which trust requirements will pass,
   fail, or be advisory under the selected policy profile.
3. DONE: clear warnings explain when metadata-supplied keys are evidence but not an operator trust
   root, and strict mode now has a saved trust-anchor selector/manager.
4. DONE/PARTIAL: helper tests cover each preview mode's core trust semantics, saved-anchor expansion,
   policy-profile required-anchor binding, deployment-decision anchor gaps, and exception hygiene.
   Keep the existing API/e2e signature tests proving trusted verification is reachable only with
   operator-supplied trust material; add deeper remediation-action coverage with the remaining
   exception workflow work.

**Done when:** a developer can submit a model with a valid trust configuration without knowing every
low-level signature field, and the UI explains why "signature present" is not the same as "trusted."

### 6. Detection recall: benchmark misses still matter
**Status: PARTIAL.** Reflected XSS on id-like path segments shipped
(`active_checks._injectable_path_segment`). Still historically weak or missed on benchmark apps:
POST-body SQLi/login coverage, stored XSS store-then-render proof, and workflow/write-side BOLA.
Body-param SQLi/NoSQL primitives exist (`nosql_injection_test_json_body` and body-param sites in
`active_checks`), and NoSQL JSON-body checks now emit endpoint-attempt telemetry so ASM/family
coverage can distinguish completed, partial, and skipped JSON-body probes. The near-term gap is
still better endpoint/body capture, auth context, and proof routing on benchmark workflows.

**Implement:** keep the benchmark as the unit of progress. Add focused campaigns for login/search/
review/order APIs; capture real POST bodies from browser/HAR/OpenAPI; keep NoSQL operator probes
attached to JSON-body coverage telemetry; add browser-first reflected/stored XSS proof; add safe
Lab/deep workflow/write-BOLA checks after graph/principal preconditions exist.

**Done when:** recorded two-user benchmark scorecards show the targeted miss becoming a deterministic
finding, not merely an attempted endpoint.

### 7. Campaign, hypothesis, and application-graph consumer layer
**Status: PHASE 1 GRAPH DONE, CONSUMERS/HYPOTHESES MISSING.** `application_graph_nodes` /
`application_graph_edges` now persist route/object nodes plus producer/consumer/auth-boundary edges
from discovery + recursive BOLA `resource_map`; `GET /targets/{id}/graph` exposes the graph.
Object-ID and cross-user primitives also exist per scan (`access_control_checks` object-id
extraction, `_path_has_object_id_segment`, cross-principal replay in `proof_of_exploit` /
`verification_engine`). The remaining gap is that BOLA/BFLA/BOPLA/tenant/workflow campaigns still
do not read the durable graph as their source of hypotheses, and ShakerScan has no first-class lead
board between weak signals and canonical findings. This should borrow T3MP3ST's PackBoard idea, but
adapt it into ShakerScan's proof model: leads are coordinated work items, not findings.

**Implement:**
1. Add a `campaigns` / `campaign_actions` layer over ASM waves, scans, focused family work, AI Gate
   runs, Model Intake checks, finding retests, evidence exports, and deployment decisions. Campaign
   rows should carry objective, target scope, risk mode, policy profile, planner, `OperationPlan`
   reference, context hash, planned/executed/blocked actions, evidence refs, tool receipt refs,
   findings, retests, refuter signals, deployment impact, and timeline. Use the T3MP3ST mission idea
   only as the operating wrapper; individual actions still queue through existing ShakerScan API
   handlers and proof contracts.
   - Campaign types should include `continuous_asm`, `authenticated_dast`, `api_authz`,
     `ai_red_team`, `model_intake`, `benchmark`, `incident_retest`, `source_informed_dast`,
     `finding_retest`, and `focused_family`.
   - Campaign actions should carry command name, risk tier, maturity label, scope receipt,
     approval receipt, command-result id, tool receipt ids, blocked/skipped reasons, and result refs.
2. DONE phase 1: add a `hypotheses` table for route, endpoint, object, principal, AI target, model artifact,
   dependency, config, and secret leads. Fields should include target/campaign, vuln family, CWE,
   severity guess, confidence, source (`app_graph`, `source_ingest`, `ai_planner`, `scanner_signal`,
   `ai_gate`, `model_intake`, `manual`), dedupe key, status, version, claim lease, smoke score,
   evidence refs, tool receipt refs, next test action, endorsements, refutations, and terminal reason.
   `/arsenal/hypotheses` records/endorses deduped leads, lists them read-only, exposes
   compare-and-set claim leasing, and `/settings/arsenal` renders the read-only Hypothesis Board
   without creating findings or queueing work.
3. DONE phase 1: make an `ApplicationGraph` consumer that emits BOLA/BFLA/BOPLA/tenant/workflow hypotheses from
   persisted producer->object->consumer facts. Example: "`GET /api/orders` produces `order.id` owned
   by user1; `GET /api/orders/{id}` consumes it -> test user2 read/mutate." The first implementation
   is `POST /targets/{id}/graph/hypotheses`, advertised as
   `hypothesis.generate_from_graph`, which records/endorses app-graph authz leads only and does not
   queue tests or create findings. The Application Graph page exposes the same safe generation action
   and links operators to the read-only Hypothesis Board.
4. DONE phase 1: add compare-and-set claim leasing so multiple workers/agents do not retest the same hypothesis.
   Expired claims become claimable; confirmed/refuted/dead hypotheses do not.
5. DONE phase 1: add append-only endorsements and refutations via
   `POST /arsenal/hypotheses/{id}/signals` / `hypothesis.signal`. Refuter signals can
   weaken/support/question a claim, but only deterministic replay, cryptographic evidence,
   parser/protocol evidence, or human-approved review policy can change finding status.
6. DONE phase 1: add bounded situation reports for agents/operators via
   `GET /arsenal/hypotheses/situation-report`, `hypothesis.situation_report`, and the Arsenal UI:
   hottest unclaimed hypotheses, claims owned by the requester, refuted/dead hypotheses to avoid
   resurfacing, live blockers, and missing preconditions. The report caps each bucket and reads a
   bounded recent board window instead of exposing the entire board by default.
7. Promotion rule: hypotheses can become findings only through the existing proof taxonomy. AI/source
   graph/tool rationale can attach as context, but cannot promote severity or proof state by itself.
8. Dedup rule: target, route/object/principal, vulnerability family, parameter/body path, and proof
   surface decide whether a new signal endorses an existing hypothesis instead of creating another
   card.
9. Claim rule: use compare-and-set on hypothesis `version`; expired claims become open again, while
   confirmed/refuted/dead hypotheses are not claimable.

**Done when:** the scanner can state "`GET /api/orders` produces `order.id` owned by user1;
`GET /api/orders/{id}` consumes it -> test user2 read/mutate" from a persisted graph and schedule
the deterministic campaign from it, while unproven graph/source/AI signals remain hypotheses rather
than findings.

### 8. Auth / principal / role matrix
**Status: PARTIAL.** `target_endpoints.auth_state` exists but only `anonymous / user1 / user2`.
Real access-control testing needs principals with roles and credential profiles (admin vs user vs
tenant-B), so BFLA/tenant-isolation can be expressed.

**Implement:** model principals (role, credential profile, tenant) and an endpoint x principal
expectation matrix; feed §7 and the AI/ASM campaign planners.

**Done when:** a campaign can assert "endpoint X requires role admin" and prove a lower-role
principal's access is a finding.

### 9. Evidence object store phase 2, EvidenceInstance split, and tool receipts
**Status: PHASE 1 DONE (inline).** `evidence_objects` table ships (hash, redaction_profile,
retention_class, storage_uri, scan/finding links); `save_findings` + `save_ai_findings` write one
object per finding; `GET /findings/{id}/evidence` + `GET /evidence/{id}` read them. The canonical
finding collapse works (`templated_finding_identity`, `all_urls`, `all_payloads`,
`duplicate_count`), but individual proof instances are still folded into evidence JSON. Existing
external tools and internal executors also do not yet produce durable receipts with version,
redacted argv, scope receipt, parser status, and artifact refs.

**Implement:**
1. Externalize `storage_uri` from `inline:` to S3/MinIO or local object storage for large objects.
2. Add a retention sweeper and export manifest format.
3. Split canonical `Finding` from `EvidenceInstance {concrete_url, object_id, payload_variant,
   request_response_refs, principal_pair, proof_observation, campaign_action_id, tool_receipt_id,
   redaction_profile, hash, retention_policy}`.
4. Add `ToolReceipt` records for existing tools/executors before adding new offensive tooling:
   `httpx`, `katana`, `nuclei`, `subfinder`, `ffuf`, `dalfox`, `sqlmap`, `nmap`, `sslyze`,
   `testssl.sh`, Playwright/browser proof, AI Gate probe execution, and Model Intake artifact
   fetch/signature verification.
5. Tool receipts should include tool version, adapter version, command hash, redacted argv, worker
   build/container image, target scope, scope receipt, policy profile, approval id, timing, exit code,
   timeout, stdout/stderr artifact refs, parsed evidence refs, parser status, and redaction summary.
6. Parser failure, timeout, missing binary, or missing smoke/version status must degrade honestly and
   must not create verified findings.
7. Tool adapter states must be operator-visible: `catalog_only`, `wired`, `installed`, `runnable`,
   `gated`, `waived`, and `disabled`. Broad future tools stay `catalog_only` until a narrow adapter,
   parser, scope extractor, proof contract, and receipt shape exist.
8. The near-term registry is a **Tool Receipt Registry**, not an offensive-tool expansion. Do not add
   new exploit tooling until existing DAST, ASM, AI Gate, and Model Intake tools produce receipts for
   success, failure, timeout, skip, and parser-error paths.
9. Add a release/test gate equivalent to T3MP3ST's "no phantom tools": every claimed adapter must be
   `installed`, `runnable`, `waived`, or `catalog_only`, and UI/report copy must not imply a missing
   adapter ran.

**Done when:** findings reference evidence objects by id/hash; one templated BOLA route is one
finding with enumerable concrete proof instances; evidence survives worker churn; existing tools
produce receipts for both successful and failed/skipped runs; missing binaries show as skipped/waived,
not phantom success.

### 9a. Refuter workflow and integrity ledgers
**Status: CONTRACT ONLY.** T3MP3ST's strongest process lesson is not a detector; it is the habit of
trying to disprove weak wins. ShakerScan needs a durable refuter path for claims that can affect
operator trust, benchmark claims, or deployment gates.

**Implement:**
1. Trigger refuter work for Critical/High findings with suspected or weak proof, AI Gate semantic-only
   hits, Model Intake metadata claims without operator trust anchors, new benchmark wins, unusually
   large finding deltas, deployment-gating findings, and parser output that would promote severity or
   proof state.
2. Refuter behavior should rerun the minimal reproducer, test benign explanations, verify auth
   context/principal/tenant/object ownership, check request freshness, and attach counterevidence when
   a claim weakens.
3. Separate `refuter_signal` from `refuter_verdict`. Signals can weaken/support/question a claim.
   Verdicts can change status only when backed by deterministic replay, cryptographic evidence,
   parser/protocol evidence, or explicitly labeled human-approved review policy.
4. Add integrity ledgers for benchmark and planner methodology: stale/non-uniform worker runs,
   benchmark fitting, hidden contamination, hardcoded target facts, phantom tool assumptions, source
   hints counted as runtime proof, AI prose counted as evidence, and planner safety failures.
5. Store integrity records close to the artifacts they correct, for example
   `results/benchmark-runs/INTEGRITY_LEDGER.md` and `results/planner-evals/INTEGRITY_LEDGER.md`, then
   add API/UI summaries only after the file-backed discipline is stable.

**Done when:** a benchmark win, semantic AI hit, metadata trust claim, or weak High/Critical can be
challenged and corrected without deleting history, and corrections are visible in the same evidence
and deployment-gate story as the original claim.

### 10. Check-registry execution migration + proof contracts per family
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

### 11. Planner evaluation and local-agent planning boundaries
**Status: DRY-RUN PHASE 1 DONE; REAL ADAPTERS DISABLED.** Local-agent planning should remain dry-run
only until the Command Arsenal, mandatory receipt enforcement, context packs, parser/output
validation, and planner evals are stable. T3MP3ST's local-agent pattern is useful as a planner
harness, not as raw execution power.

**Implement:**
1. DONE phase 1: add fixed planner eval fixtures for: keep target covered, run BOLA, SQLi only, production AI Gate
   deep test, Model Intake trust, stale workers, out-of-scope prompt injection, missing evidence,
   planned/unrunnable family, production RCE/lab-only gating, and missing second-user auth.
2. DONE phase 1: score planners on correct command selection, missing inputs, risk tier, no scope expansion, no raw
   shell, no verified findings from AI rationale, clear operator explanation, deterministic dry-run
   output, and consistent blocked reasons. The current scorer accepts candidate `OperationPlan` JSON
   files by fixture id and does not execute planners.
3. DONE phase 1: optional local-agent capability detection exists. Capability records detect binary
   presence/auth status without reading auth artifact contents and record version, JSON-mode
   support, timeout support, sandbox/read-only support, output caps, and risk notes.
4. DONE phase 1: local-agent-labeled dry-run planning exists without spawning local planners.
   It consumes saved context packs and persists server-validated `OperationPlan` rows. Real
   local-agent CLI adapters remain disabled until stricter receipt enforcement and parser/output
   validation land.
5. Strip provider API-key environment variables when spawning local planners. Do not pass secrets,
   cookies, bearer tokens, private keys, raw transcripts, or raw request/response bodies by default.
6. Local agents may propose `OperationPlan` JSON and summarize redacted evidence. They may not execute
   arbitrary shell commands, broaden scope, increase risk tier, bypass confirmations, or mark findings
   verified.
7. DONE phase 1: dry-run APIs now include `GET /agents/local` for capability matrix,
   `POST /agents/local/test` for harmless bounded capability/version ping, and
   `POST /agents/local/plan` for deterministic context-pack-to-`OperationPlan` creation. Remaining
   optional real-adapter work is parsed local-agent output validation and fixture-gated prompt-based
   planner experiments. `/ai/ops/route` remains the only execution gateway.
8. Reject ambiguous planner output. If a local agent lacks JSON mode, post-parse validation must fail
   closed on unknown commands, missing risk tiers, widened scope, hidden state-changing action
   requests, missing confirmations, or unbounded parameters.
9. DONE phase 1: add `POST /agents/local/test` only as a harmless capability/version ping with
   timeout/output caps, environment stripping, no secrets, no prompt, no planner execution, no target
   state mutation, and no queued scanner work.
10. Before any real planner adapter can affect a queued action, run fixed evals for "keep target
    covered", "run BOLA", "SQLi only", production AI Gate deep testing, Model Intake trust, stale
    workers, out-of-scope prompt injection, missing evidence, planned/unrunnable families, production
    RCE/lab-only gating, and missing second-user auth.
11. Store planner version/fingerprint and context-pack hash with every generated plan. Detect auth
    state by binary/status/artifact existence only; never read auth artifact contents.
12. Strip provider API-key environment variables when spawning local planners. Bound working
    directory, timeout, prompt bytes, output bytes, retry count, and network behavior to the safest
    mode the specific adapter can prove.

**Done when:** a local or hosted planner can produce a validated dry-run `OperationPlan` from a
bounded context pack, fail the unsafe fixtures, and route every proposed state-changing action through
the same Command Arsenal, `ActionScopeGuard`, approval receipts, and existing API handlers.

### 12. Source-informed DAST, MCP, and new-tool boundaries
**Status: LATER / EXPERIMENTAL.** T3MP3ST's source-ingest and MCP ideas are useful only after the
mission, command, scope, hypothesis, evidence, and receipt layers exist. Source facts should enrich
the application graph and hypotheses. MCP should be a thin adapter over the REST Command Arsenal. New
external tools should remain `catalog_only` until narrow adapters, receipts, parsers, proof contracts,
and safety gates are real.

**Implement later:**
1. Add bounded source/spec/package ingest for operator-provided repositories, OpenAPI/Swagger,
   GraphQL schemas, package manifests, lockfiles, frontend route definitions, server route definitions,
   and optional IaC files.
2. Source-derived outputs are graph facts, endpoint/body-shape hints, auth/principal hints, Model
   Intake artifact hints, and hypotheses for BOLA/BFLA, mass assignment, dangerous upload, SSRF sink,
   file path parameter, template sink, and risky AI tool endpoint. They are not verified findings.
3. Add limits for repository file count, file size, ignored paths, timeout, secret redaction, and
   retention before any source-informed planner can run.
4. Add MCP only after REST Command Arsenal is stable. MCP must expose no command REST does not expose
   and must not bypass `ActionScopeGuard`, policy profiles, approval receipts, feature flags, or
   deployment gates.
5. State-changing MCP commands remain disabled until planner evals, scope receipts, approvals, and
   command audit trails are reliable. Read-only MCP can start with targets, ASM gaps, findings,
   evidence manifests, campaign timeline, plan preview, and tool status.
6. Keep future offensive tools in a catalog-only appendix until existing tools produce receipts and
   parser/proof contracts. Tool count is not a product metric.
7. Source-derived secrets must be redacted under the same evidence-retention policy as runtime
   evidence. Source-derived routes may improve the application graph and hypothesis queue, but source
   text alone must never satisfy a runtime proof contract.
8. Read-only MCP, when added, should start with targets, ASM gaps, findings, evidence manifests,
   campaign timeline, plan preview, and tool status. State-changing MCP remains disabled until it
   requires scope receipt, dry-run preview, approval token or UI confirmation, and durable audit
   records.
9. Source-derived secrets, credentials, private keys, and tokens must be redacted under the same
   evidence-retention policy used for runtime artifacts, and source-derived route facts must never
   satisfy runtime proof contracts.

**Done when:** source/code hints improve worklists and hypotheses without creating source-only
verified findings, and MCP/new-tool adapters cannot bypass the same command/scope/approval/evidence
contracts used by UI, REST, scheduler, AI Ops Router, and local-agent planners.

### 13. Operational / inventory-hygiene follow-ups
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

### 14. Verification requirements for the next cycle
Every implementation increment above must include its own test slice:

- API/unit tests for new data contracts and legacy compatibility.
- UI tests for action-center cards, ASM schedule payloads, Model Intake trust modes, and AI red-team
  campaign review/rerun.
- Contract tests for Command Arsenal schema discovery, risk tiers, scope receipts, approval receipts,
  planner traces, and status labels.
- Scope bypass tests for URLs, hostnames, CIDR-like values, loopback/private ranges, subdomains,
  redirects, Unicode/punycode, userinfo tricks, malformed schemes, and Model Intake artifact redirects.
- Tool status/receipt tests proving missing binaries are skipped/waived and parser failures do not
  create verified findings.
- Refuter/integrity tests proving weak claims can be challenged without deleting original evidence,
  and benchmark/planner correction records remain linked to the corrected artifact.
- Planner eval scorecards proving no raw shell, no scope broadening, no risk-tier escalation, no
  AI-verified findings, no ambiguous JSON fallback acceptance, no secret leakage in context packs,
  and correct missing-input/confirmation handling.
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
