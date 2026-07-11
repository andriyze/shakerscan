# Proposed Next Steps — Proof-First Continuous Exposure Management

**Status:** implementation-complete for the bounded roadmap scope as of 2026-07-10. The rebuilt
local fleet passes the unit, runtime-container, UI production-build, planner-eval, and named release
gates. Detector acceptance is only partly closed: the current-fleet Juice Shop scorecard passes, while
the fresh authenticated crAPI scorecard must be rerun because its in-progress scan was explicitly
cancelled before the requested full-stack rebuild. Reconciled with
`docs/t3mp3st-adoption-implementation-plan-updated.md`,
`docs/archive/asm-parallel-improvement-plan.md`, `docs/parallel-scan-architecture.md`, and the
current code. The contract-first proof layer, application graph/campaign consumer, externalized
evidence instances, current-tool receipts, target de-dupe, exception lifecycle, Model Intake trust,
AI Gate campaigns, ASM scheduling, registry-validated scanner dispatch, Command Arsenal, scope and
approval receipts, bounded Codex dry-run planning, refuters, and read-only MCP are implemented and
wired. Historical phase notes remain below as an implementation ledger. The open acceptance checks
are fresh fingerprint-current detector scorecards; intentionally excluded expansion items are
listed as non-goals or deferred architecture, not implied completed work.

### Cross-document reality check (2026-07-10)

This file is the authoritative bounded implementation record. The related T3MP3ST, Continuous ASM,
parallel-scan, and archived live-investigation documents contain target architecture and historical
phase text as well as shipped behavior. They must not be read as claiming that every aspirational
item is implemented.

- **Implemented and verified in code/tests:** the bounded phases recorded as DONE below, including
  Command Arsenal, receipts, planner safety, hypotheses/refuters, current-tool receipts,
  EvidenceInstance/external storage, read-only MCP, current registry adapters, Continuous ASM
  allocator/attempt ledgers, parallel parent-plan-shard-merge, operational rebuild/fleet truth, and
  direct ASM timeline remediation links.
- **Implemented but still requiring live acceptance/soak:** authenticated crAPI detector recall after
  the rebuild, broader dynamic-allocation parity on large owned targets, and request-rate behavior at
  larger worker counts.
- **Deferred target architecture:** full `build_report()` iteration from the registry, telemetry and
  focused-family expansion beyond current contracts, request-accurate budgets for internally
  discovered standalone traffic, deeper cooperative cancellation inside scanner loops, and
  multi-node placement/reliable leases/brokered untrusted workers.
- **Intentionally excluded:** state-changing MCP, raw shell/arbitrary-code agent commands,
  post-exploitation/password-spraying tooling, and source- or AI-only verified findings.

Verification snapshot on the rebuilt local fleet (2026-07-10):

- Python suite: `1715 passed, 6 skipped`.
- Container runtime target: `33 passed` (with FastAPI deprecation warnings only).
- UI: Next.js production build and TypeScript validation passed.
- Planner fixtures: `10/10` passed; all 10 named release gates passed.
- Live local E2E: Model Intake gate passed (`8/9`, one opt-in external Hugging Face case skipped),
  AI Gate passed (`12/12`), and DAST passed (`11/11`, including bounded SQLi and DOM-XSS recall).
- Worker preflight: 16/16 current on one fingerprint, zero stale workers.

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

Those larger implementation gaps have since closed: graph hypotheses plan campaigns and reconcile
exact deterministic proof; evidence is split into instances and externalizable objects; runnable
scanner families are adapter-validated by the registry; Model Intake and exception remediation are
actionable; and AI Gate target history includes readiness trends and content-free exports. Detector
recall remains subject to the benchmark acceptance check described in section 6.

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
Those adoption increments are now implemented: command-result/campaign audit rows, mission timeline,
hypotheses, tool receipts, evidence instances, runtime destination checks, refuters, source-informed
hypotheses, and read-only MCP. State-changing MCP remains intentionally unrepresentable.

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
| Op Admiral / mission intake | `OperationPlan` plus cross-product campaign timeline | implemented |
| Local-agent brain mode | bounded planner that emits `OperationPlan`, never direct tool execution | fixture-gated Codex dry-run adapter implemented |
| Arsenal | REST Command Arsenal over ShakerScan product actions | read-only and approval-gated adapters implemented |
| Scope/approval gates | `ActionScopeGuard`, `ScopeReceipt`, `ApprovalReceipt` | implemented with runtime destination checks |
| PackBoard | `campaigns`, `campaign_actions`, `hypotheses`, situation reports | implemented through deterministic proof reconciliation |
| Evidence gate | proof taxonomy, evidence objects, evidence instances, tool receipts | implemented for current tools/executors |
| Arsenal doctor | tool status and receipt registry | implemented |
| Refuter culture | weak-claim refuter workflow and integrity ledgers | implemented with explicit integrity-signal intake |
| Source-informed testing | graph facts and hypotheses from source/spec inputs | implemented as runtime-proof-required hints |
| MCP interface | thin adapter over REST Command Arsenal | read-only phase implemented |

### T3MP3ST-derived implementation waves

Use these waves to decide sequence when a T3MP3ST idea competes with detector work:

1. **Contracts and labels:** DONE for mission, context, trace, command, receipt, risk, maturity,
   campaign/hypothesis persistence, and release gates.
2. **Read-only operator visibility:** DONE for Command Arsenal/status, dashboard/product cards,
   cross-product mission timeline, and blocked command results.
3. **Safety receipts and audit:** DONE phase 1 for scope/approval receipts and optional plus
   policy-required enforcement, queued runtime-scope guard payloads, a deterministic actual-destination
   re-check helper, DAST worker final-URL enforcement, AI Gate/Model Intake runtime destination
   capture, redirect-chain/resolution audit, runtime-scope blocked/degraded command-result rows
   (missing per-hop DNS telemetry degrades while observed out-of-scope destinations or disallowed
   resolutions block), and
   campaign action records. Future adapters must satisfy the same contract before becoming runnable.
4. **Planner evaluation before planner power:** DONE for fixture scoring, capability ping, strict
   parser validation, bounded Codex dry-run planning, and no-shell/scope/risk/AI-proof release gates.
5. **Hypotheses before new detectors:** DONE phase 1 for campaign-action audit records and durable
   hypothesis records with dedupe, endorsements, and claim leases. DONE phase 2 for graph plus
   AI Gate/Model Intake, source/spec, planner, weak-scanner, and benchmark routing into hypotheses,
   plus the refuter workflow.
6. **Receipts before new tools:** wrap existing tools first (`httpx`, `katana`, `nuclei`,
   `subfinder`, `ffuf`, `dalfox`, `sqlmap`, `nmap`, TLS tools, Playwright, AI Gate executor, Model
   Intake artifact/signature checks). New offensive tooling stays `catalog_only`.
7. **External evidence and replay:** split concrete proof instances from canonical findings,
   externalize large artifacts, add retention/export manifests, and make missing evidence degrade
   reports honestly.
8. **Read-only MCP:** DONE after REST Command Arsenal, receipts, evidence, planner evals, and audit
   records stabilized. State-changing MCP is excluded from this roadmap.

Server-side Arsenal dispatch revalidates catalog parameter types, bounds, enums, UUID formats, string
lengths, and array constraints before invoking any adapter. MCP schemas are client guidance, not a
security boundary; direct REST/planner callers cannot bypass the same declared limits.

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
  recurring schedule-health failures, Model Intake trust gaps, and AI control-baseline gaps; the
  dashboard renders them as a prioritized operator feed.
- **Dashboard Action Center CTAs** — `action_center` items now include structured `actions[]`
  alongside legacy `href/action_label`, and the dashboard renders safe direct links for worker
  controls, deployment blockers, failed scans, exception queues, target-preselected ASM coverage,
  ASM schedules, recurring schedule timeout remediation, Model Intake trust gaps, and AI Gate
  control gaps.
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
  `approval_receipt_id` / `scope_receipt_id` plus a non-secret `runtime_scope_guard` into queued scan
  options. Mandatory enforcement is available through `/settings/automation`; compatibility mode
  remains an explicit operator choice.
- **Approval receipt validation phase 2** — AI Gate scans, AI Gate finding replay, AI Gate campaign
  replay, Model Intake scans, single finding retest, and bulk finding retest now also accept optional
  `approval_receipt_id`. They validate the same approval/scope invariants against the saved AI target,
  model artifact reference, or finding retest target before queueing, then stamp receipt IDs into
  queued scan/retest metadata where that route has a durable job/options record. Legacy submissions
  without a receipt still work; mandatory enforcement is still a policy rollout step.
- **Runtime destination scope re-check phase 1** — validated approval contexts now carry a
  non-secret `runtime_scope_guard` with the approved scope receipt id, environment, allowed hosts/root
  domains, normalized scope, and a `requires_runtime_destination_check` flag into queued job/options
  metadata. `evaluate_runtime_destination_scope` gives workers/adapters a deterministic fail-closed
  helper for actual post-resolution or post-redirect destinations: missing guards, missing actual
  destinations, and out-of-scope redirects return blocked/degraded status rather than in-scope.
- **Runtime destination scope re-check phase 2** — the DAST worker now applies
  `runtime_scope_guard` to the scanner report's actual `http.final_url` before findings are persisted
  or the scan is marked completed. Out-of-scope or missing final URLs fail closed with no findings
  saved, a `scan_metadata.runtime_scope_check` record, and a durable blocked
  `scan.runtime_scope_check` command-result row for the mission timeline.
- **Runtime destination scope re-check phase 3** — AI Gate REST transcripts now capture requested and
  final response URLs, Model Intake fetch metadata captures requested/final artifact URLs, both
  product results expose `runtime_destinations`, and the worker applies the same fail-closed
  `runtime_scope_guard` checks to DAST, AI Gate, and Model Intake before findings persist. Redirect
  chains and observed peer IPs are captured and audited; future adapters must satisfy this contract.
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
  `blocked_by`, `next_eligible_at`, `operator_message`). Optional `target_id` filter. Campaign/action,
  evidence-instance, export, and refuter events now share the same timeline.
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
- **Exception lifecycle phase 2** — `POST /finding-exceptions/lifecycle/sweep` and
  `finding_exception.lifecycle_sweep` provide bounded dry-run previews and approval-gated execution.
  Execution only marks elapsed effective exceptions `expired`, preserves prior state in
  `edit_history`, and emits a command-result receipt; it never renews or deletes exceptions.
- **Benchmark harness** — two-user run + post-retest re-score + fleet gate + invariant/active gates;
  historical scorecards are committed to `results/benchmark-runs/`. The fresh current-fleet Juice
  Shop scorecard passes. The authenticated crAPI scorecard remains the final detector-acceptance
  check because the prior run was cancelled for the requested rebuild before it could produce an
  artifact.

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
inventory, ledger, coverage, proof taxonomy, canonical totals, graph consumer, externalized evidence,
registry-driven dispatch, and campaign-level operator UX needed for an audit-grade exposure platform.

## Implementation plan and acceptance record

The increments below were implemented as separate features and retained as an auditable phase record.

### Findings from this doc/code reconciliation

The three planning docs agreed on the strategic direction; this record preserves the resulting
ordering and implementation boundaries:

- `docs/archive/asm-parallel-improvement-plan.md` is correctly archived. It should remain evidence for
  A4/P6/worker-rebuild history, not a live roadmap.
- `docs/parallel-scan-architecture.md` remains useful for parent/plan/shard/merge and coverage
  mechanics; product-facing campaign, schedule, and proof-quality work is recorded here.
- `docs/continuous-asm-architecture.md` identifies the target architecture; background policy,
  recurring schedules, manual Improve Coverage, and hidden implementation scans now share typed
  schedule/activity contracts.
- ASM waves are now a first-class schedule kind (`normal_scan`, `asm_improve`) with legacy
  `scan_options.kind` compatibility. `/targets/{id}/asm/activity` now exposes the first derived
  target campaign timeline and editable coverage-wave controls.
- `/targets/{id}/asm/activity` now returns scan/campaign rows, attempt counts, and the shared
  scheduler decision object plus a bounded target-scoped hypothesis situation report for read-only
  proof leads. Dashboard Action Center items now expose structured safe CTAs, and
  `/dashboard.product_status` now provides API-backed product status cards for DAST, ASM, AI Gate,
  Model Intake, exceptions, deployment gates, and worker freshness, with safe remediation links.
- Model Intake has the low-level trust fields in API/UI, guided trust modes, pre-submit preview, and
  saved trust-anchor selection/creation. Strict policy profiles can now require saved anchors and
  matching Model Intake scans inherit them. Deployment decisions now expose strict policy-required
  anchor gaps plus exception hygiene/expiry summaries, and dashboard Model Intake trust blockers now
  open `/settings/model-intake?remediate=trust`, which selects the strict trusted-anchor path and
  focuses the trust remediation panel. The bounded exception repair and lifecycle sweep now complete
  this remediation scope without automating risk acceptance renewal.
- AI Gate has transcripts, reports, adaptive probes, MCP readiness, control evidence, a first
  campaign review surface on scan detail, scan-level rerun actions for skipped/errors/family/all,
  per-transcript replay actions, same-context run comparison on scan detail, and target-level
  longitudinal campaign history on the AI Gate target surface. Target history now includes phase-1
  readiness trends, per-context trend chips, and a content-free export with run report links plus
  per-run evidence-manifest hashes/counts. Target history now also exposes bounded trend-series
  points and renders an advanced readiness-over-time visualization for overall and per-context runs.

### Implemented sequence

These were the commit-sized slices, in order. The T3MP3ST adoption plan is folded into this roadmap
as an operating model, not a separate product direction. Borrow mission planning, command
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
   a read-only cross-product mission timeline (`GET /timeline`). DONE phase 1 for standalone
   execution-gateway action state in `/arsenal/execute` responses. Runtime destination checks and the
   fixture-gated Codex dry-run adapter are also complete; the planner adds no execution power.
2. **Unified Action Center + mission timeline:** DONE phase 1 — `GET /timeline` merges command-result
   audit rows (with live scan status), recent scans, and upcoming schedules into one normalized event
   feed with explicit statuses. DONE phase 1 for campaign-action audit records mirrored from command
   results plus read-only timeline support for standalone action rows. DONE phase 1 for durable
   evidence-instance binding events and refuter review/signal events on the same feed. DONE phase 1
   for content-free evidence export bundle descriptors with API read-replay plans. DONE phase 1 for
   explicit `record_event=true` durable export event records on the timeline. DONE phase 1 for
   content-free zip download packaging for manifests, bundle descriptors, and replay plans.
3. **Command Arsenal execution gateway, still no raw shell:** DONE phase 1. `POST /arsenal/execute`
   invokes a product command by NAME through its existing route handler. Unknown / `catalog_only` /
   `out_of_scope` / `contract` commands are refused, so raw shell and arbitrary code are not
   representable. Read-only/dry-run inspection commands dispatch directly and record a `command_result`;
   state-changing commands stay behind the same execution gate as the AI Ops router (`execute=true` +
   required confirmations + valid approval receipt + `AI_OPS_ROUTER_EXECUTE_ENABLED`), otherwise they
   dry-run with a recorded `approval_required`/`blocked` audit row. The dispatch registry wires
   read-only `target.list`, `campaign.list`, `campaign.get`, `command_result.list`, `mission.timeline`,
   `tool.status`, `local_agent.list`, `asm.gaps`, `operation_plan.list`, `agent_context_pack.list`, and
   `hypothesis.list`, plus all currently catalogued read-only/dry-run product commands for target
   principal matrices, exposure graph, ASM activity, scan/finding/evidence/deployment reads, AI Gate
   history export, Model Intake trust preview, local-agent dry-run planning, scope/plan/context/trace
   records, campaign actions, hypotheses, refuter reviews, evidence instances, and tool receipts. It
   also wires gated `asm.improve`, `asm.test`, `asm.recon`, `finding.retest`, `scan.focused_family`,
   `ai_gate.scan`, `ai_gate.replay_probe`, `model_intake.scan`, and `evidence.retention_sweep`
   through their existing handlers (each records its own command result); gate-approved commands
   without a wired adapter return `dispatch_adapter_pending` rather than a shortcut. DONE phase 2 for
   mission-campaign linkage on dispatched results and returned persisted `command_result` rows with
   tool/evidence receipt refs when present. DONE phase 3 for execution-gateway `action_state`
   transition details covering catalog status, risk, confirmation gate state, adapter status, blocked
   reason, operation id, and command-result id.
   External binaries may be
   used only behind narrow adapters; the command schema still never exposes raw shell, arbitrary
   Python/Node execution, or generic "run this command" behavior.
4. **Scope and approval receipts for state-changing actions:** DONE phase 1 for central
   `ActionScopeGuard`, persisted `ScopeReceipt` previews, and durable `ApprovalReceipt` records.
   DONE phase 1 for optional receipt validation on `/scans` and Continuous ASM recon/test/improve.
   DONE phase 2 for optional receipt validation on AI Gate scans/replay, Model Intake scans, and
   finding retests. DONE phase 1 for policy-based mandatory enforcement across those existing
   state-changing routes via `/settings/automation`. DONE phase 1 for command-result audit rows on
   successful queued operations, for blocked/approval-required rows written before the enforcement
   path raises (best-effort, FK-safe), for runtime-scope guard payloads plus a deterministic
   actual-destination re-check helper, for DAST worker final-URL enforcement before finding
   persistence, for AI Gate/Model Intake runtime destination capture and enforcement, and for
   runtime-scope blocked/degraded command-result rows, campaign/action execution records, and
   redirect/resolution re-checks. Future adapters must reuse this enforcement model.
5. **Continuous ASM quality lane:** DONE phase 1 for `/asm/coverage`, `/asm/gaps`, scan detail,
   Action Center, and the mission timeline agreeing on family-aware state: attempted, proved,
   partial, blocked by auth, blocked by second user, blocked by schedule/rate cap, stale, and
   worker-stale. DONE phase 2 for target ASM activity consuming the bounded hypothesis situation
   report so graph/source/scanner/AI leads are visible next to coverage state without promotion.
   Safe remediation entry points now cover those states.
6. **Campaign + hypothesis layer:** DONE phase 1 for durable deduped hypotheses/leads, endorsements,
   read APIs, bounded context-pack summaries, compare-and-set claim leases, and app-graph authz
   hypothesis generation. DONE phase 2 for AI Gate weak/semantic signals and Model Intake trust
   metadata claims becoming replay/remediation hypotheses from worker finalization. DONE phase 3 for
   bounded source/spec/package hints becoming `source_ingest` hypotheses through
   `/arsenal/hypotheses/source-ingest` / `hypothesis.generate_from_source`; source facts remain
   source-only context with `runtime_proof_required=true` and create no findings or queued work.
   DONE phase 4 for saved dry-run `OperationPlan` actions becoming `ai_planner` hypotheses through
   `/arsenal/hypotheses/from-plan` / `hypothesis.generate_from_plan`; planner output remains a
   source-only signal with `runtime_proof_required=true` and creates no findings or queued work.
   DONE phase 5 for broader weak scanner signal routing: uncertain medium+ scanner findings become
   `scanner_signal` hypotheses with deterministic `finding.retest` next actions and
   `runtime_proof_required=true`. Hypotheses are claimable/refutable work items, not findings.
7. **Detector recall campaigns:** keep benchmark gaps as proof-backed work items: POST-body SQLi,
   NoSQL JSON/body routing, stored/reflected XSS browser proof, workflow/write-side BOLA, mass
   assignment/JWT, and graph-driven authz hypotheses.
8. **Evidence store phase 2 and tool receipts:** split canonical findings from concrete
   `EvidenceInstance` rows, externalize large artifacts, add retention/export manifests, and receipt-wrap
   existing tools before adding any new offensive tooling.
   Treat this as the T3MP3ST evidence-gate adoption point: parser failure, timeout, missing binary,
   missing smoke status, or missing proof-critical evidence must produce a skipped/degraded/blocked
   record, not a verified finding or phantom success.
9. **Registry-driven execution:** DONE phase 2 for fail-closed registry execution metadata:
   explicitly requested but unrunnable families now stay skipped with `registry_family_not_runnable`,
   enabled families expose dispatch adapters, and scan plans summarize requested blocked families.
   DONE phase 7 for independent scanner adapter contracts and reportable dispatch decisions across
   every runnable scanner task family. An enabled plan cannot dispatch a detector when the
   scanner-side adapter contract is missing or mismatched.
10. **Refuter and integrity layer:** DONE phase 1 for refuter workflows for weak High/Criticals,
    AI Gate semantic hits, Model Intake metadata claims, parser-promoted/degraded output, and
    deployment-gating claims. Refuter plans now carry structured counterevidence bundles with review
    questions, benign explanations, required evidence refs, and verdict paths. Add benchmark and
    planner integrity ledgers for contamination, retractions, stale-fleet runs, phantom tool
    assumptions, and methodology corrections. DONE phase 1 for file-backed planner/benchmark ledger
    locations and planner fixture scoring; the benchmark ledger now records the flat Juice Shop
    post-retest recall result as an explicit correction instead of treating retest plumbing as recall
    progress.
11. **Planner evals and local-agent planning, dry-run only:** planner fixtures, integrity ledgers,
    local-agent capability detection, target context packs, deterministic local-agent-labeled
    dry-run planning, and bounded harmless local-agent capability ping/testing are phase 1 done.
    Strict parsed-output validation and the fixture-gated Codex dry-run adapter are complete.
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
  integrity-ledger locations, policy-required approval enforcement, and auditable operation/campaign
  records are done without adding raw shell or direct planner execution power.
- **P0: productize shipped foundations.** The base Action Center/CTAs, Product Status cards,
  Exceptions Queue, first-class ASM schedule kinds, and target campaign timeline phase 1 are already
  done, including the unified mission timeline, safe remediation entry points, and cross-page
  agreement on blocker/blocked/running state.
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
  transcript replay, same-context scan comparison, target-level history, phase-1 readiness trends,
  target-history export links, per-context readiness trend chips, content-free campaign evidence
  manifest summaries, and bounded readiness-over-time trend-series visualization are phase 1 done.
- **P2: Model Intake trust UX.** Guided trust modes, pre-submit trust preview, saved trust anchors,
  scan selection, strict policy-profile anchor binding, deployment-decision anchor gaps, the first
  exception metadata repair flow, and content-free Model Intake evidence exports are phase 1 done.
  DONE phase 2: bounded exception lifecycle previews and approval-gated expiry execution are
  available from the Exceptions Queue and Command Arsenal. Renewal remains a deliberate operator
  edit because extending an exception must not be automated.
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
**Status: DONE FOR THE BOUNDED PRODUCT DECISION FLOW.** `/dashboard` now includes a server-backed
`action_center` feed built from worker freshness, deployment blockers, failed scans, exception
hygiene, ASM coverage/schedule facts, Model Intake signature trust, and AI control-baseline gaps.
The dashboard renders this as a prioritized Action Center. ASM policy/gaps/improve/activity now
expose live `scheduler_state`, and dispatcher/scheduler decisions are persisted as
`metadata_json.asm_last_decision`. `/settings/exceptions` now provides the first dedicated Exceptions
Queue plus a bounded repair workflow for owner/approver/control/expiry hygiene without changing
exception scope. Dashboard items now expose structured safe CTAs. `GET /timeline` now provides a
read-only cross-product mission timeline (command results with live scan status + recent scans +
upcoming schedules) with explicit API-backed statuses. Bounded remediation now includes credential
blockers, trust controls, exception repair/expiry, workers, failed scans, and ASM actions.

**Implement:**
1. DONE: extend Action Center items with safe CTAs for workers, failed scans, recurring
   schedule-health failures, target-preselected ASM coverage, exception queues, Model Intake trust
   gaps, and AI control gaps.
2. DONE: extend first-class "next action" and "why skipped" facts from ASM policy/gaps/improve/activity
   into Dashboard Action Center CTAs where target/action links are safe.
3. DONE: add an Exceptions Queue page/filter for `finding_exceptions`: expiring soon, expired,
   missing owner/approver, no compensating controls, policy-scoped, and target-scoped.
4. DONE: make finding filters use product taxonomy consistently. Dashboard product counts/quick
   links are now backed by `/dashboard.product_status`, not browser inference.
5. DONE: add `/dashboard.product_status` or equivalent API-backed cards for DAST, ASM, AI Gate,
   Model Intake, policy exceptions, deployment gates, and worker freshness. Do not compute these
   counts only in the browser.
6. DONE: add safe remediation routes from those cards: open failed scans, open target ASM timeline,
   open missing-auth/second-user blockers, open exception hygiene filters, open AI Gate
   readiness/control gaps, and open worker rebuild/scale controls. DONE phase 1 for product-status
   remediation links: DAST cards route to active findings, failed scans, running scans, or new-scan
   entry as appropriate; ASM cards route to the selected target timeline and preselected schedule
   creation; exception cards route directly to expired, expiring, or missing-controls queues; AI Gate
   cards route to control gaps or AI findings; `/settings/ai-gate?remediate=controls` now sorts and
   highlights targets with missing control evidence; worker cards route to dashboard worker controls
   and pending scans. DONE for Model Intake trust blockers: `/settings/model-intake?remediate=trust`
   selects strict trusted-anchor mode, highlights the trust controls, and links exception hygiene.
   DONE phase 2 for credential-gated ASM blockers: the dashboard action center now surfaces targets
   with `auth_missing`/`auth_failed` endpoint attempts and routes operators to the target ASM timeline
   or preselected ASM schedule creation. DONE phase 3 for second-user authz/BOLA blockers: blocked
   campaign actions with second-user precondition failures route to the target ASM timeline and the
   campaign-action ledger.
   DONE for exception repair phase 1: `/settings/exceptions` can update owner, approver, reason,
   compensating controls, expiry, and status without changing scope or creating new exceptions.
7. DONE phase 1: `GET /timeline` merges the command-result audit rows (with live scan status joined),
   recent user-facing scans, and upcoming schedules into one normalized cross-product event feed with
   an optional `target_id` filter. DONE phase 1: the feed also includes standalone campaign actions,
   durable evidence-instance binding events, and refuter review/signal events. DONE phase 1:
   content-free evidence export bundle descriptors expose replay/read paths and bundle hashes. DONE
   phase 1: evidence export bundles can explicitly record durable content-free export events with
   `record_event=true`, and `GET /timeline` includes those events with hashes, filters, evidence IDs,
   and replay paths. DONE phase 1: AI Gate target-history exports include content-free per-run
   evidence-manifest summaries with manifest hashes, evidence hashes, probe counts, detector hashes,
   judging metadata, budget counters, and sanitization flags.
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
**Status: DONE FOR READ-ONLY, DRY-RUN, AND APPROVAL-GATED PRODUCT ACTIONS.** The
T3MP3ST adoption plan correctly identifies the missing operating model: ShakerScan has many
safe/productized primitives, and now has persisted dry-run mission/context/trace/receipt records plus
policy-required approval enforcement, campaign/action audit rows, runtime destination checks, and
planner/MCP API rails. Broad agent execution remains intentionally excluded.

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
  `model_intake.trust_preview`, `model_intake.evidence_export`, `model_intake.scan`,
  `evidence.export_manifest`, `evidence.export_bundle`,
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
13. DONE phase 3 for runtime destination scope re-checks: approval validation now stamps a
    `runtime_scope_guard` into queued job/options metadata, `evaluate_runtime_destination_scope`
    fail-closes missing guards, missing actual destinations, and out-of-scope redirects, the DAST
    worker applies that guard to the scanner report's actual `http.final_url`, and AI Gate/Model
    Intake adapters now emit runtime destinations that are enforced before findings persist. Runtime
    blocks preserve the check in scan metadata and write a blocked `scan.runtime_scope_check`
    command-result row for the timeline. DONE phase 4: DAST header capture now preserves every
    observed redirect hop and the final peer IP; AI Gate transcripts preserve aiohttp redirect
    history and peer IP when available; Model Intake fetch metadata preserves its observed final hop
    and peer IP. The worker evaluates every supplied hop, blocks production resolutions into
    private/loopback/reserved space, and marks missing DNS observations `degraded` rather than
    silently in-scope. Future tool/MCP adapters must supply the same destination contract.
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
    include standalone action rows without duplicating mirrored command-result events. DONE phase 1:
    the timeline also includes evidence-instance binding events and refuter review/signal events.
    DONE phase 1: `evidence.export_bundle` exposes content-free bundle descriptors with replay/read
    paths. DONE phase 1: explicit durable content-free export events are now recorded and surfaced on
    the timeline. DONE phase 1: `/arsenal/execute` responses include `action_state` transition detail
    for completed, approval-required, blocked, adapter-pending, and dispatched commands.
18. DONE phase 1: blocked and approval-required command-result records are written before the
    enforcement path raises (best-effort, FK-safe), so "nothing ran because policy/scope blocked it"
    is auditable with the same operation id, scope/approval refs, blocked reasons, and next action.
    DONE phase 2 for DAST, AI Gate, and Model Intake runtime-check blocks. DONE phase 3 for runtime
    scope degradation audit: incomplete DNS observations preserve findings but stamp scan metadata
    and write a `degraded` command-result row with the same scope receipt and destination evidence.
    Other non-policy skip paths remain governed by their family/tool telemetry and receipt records.
19. DONE phase 1: add release/test gates for Command Arsenal and planner safety.
    `scripts/release_gates.py` and `make release-gates` expose the named gates
    `test:no-phantom-tools`, `test:no-benchmark-fitting`, `test:no-ai-verified`,
    `test:evidence-provenance`, `test:fleet-current`, `test:planner-scope`,
    `test:planner-risk`, and `test:planner-no-shell` as stable focused pytest
    slices, with mapping tests so the gate names cannot silently drift.

**Done when:** a mission can be planned, previewed, blocked, approved, queued, executed, and audited
through one schema without exposing raw shell, bypassing policy gates, or allowing AI/local-agent prose
to create verified findings. A local agent can only produce a validated dry-run `OperationPlan` from
a bounded `AgentContextPack`; it cannot execute a command directly. Operators can also answer "what
was requested, who/what approved it, what ran, what was blocked, what evidence resulted, and what is
the next safe action" from stored command/campaign records.

### 3. ASM scheduling and campaign semantics
**Status: DONE.** The backend can run scheduled ASM waves (`api.run_due_schedules`) and a
background dispatcher (`api.run_asm_dispatch`), while `/asm` exposes per-target policy and now shows
live/persisted scheduler decisions. `/schedules` has a visible ASM coverage-wave option and the
API/DB now expose first-class schedule kinds (`normal_scan`, `asm_improve`,
`evidence_retention_sweep`) with legacy `scan_options.kind` compatibility. `/schedules` can now
create and edit ASM waves with batch size, stale-days, endpoint filter, focused family, and Lab/deep
gating; due-run execution honors those per-schedule settings when counting claimable work and
enqueueing batches. Retention schedules run bounded evidence sweeps from `scan_options`, default to
dry-run, and require an approval receipt before scheduled execution can delete evidence. `/targets/{id}/asm/activity`
now exposes and the ASM UI renders a derived campaign timeline that combines scheduler decisions,
next eligible time, next recurring ASM wave, active scans, last scheduler decision, and recent
activity. Timeline events now carry server-backed remediation contracts for failed/active scans,
schedule and rate-cap blockers, stale workers, auth/second-user blockers, and immediately claimable
coverage work; the ASM UI renders those links/actions without inferring state from display text.

**Implement:**
1. DONE: introduce typed schedule kinds (`normal_scan`, `asm_improve`,
   `evidence_retention_sweep`) in API/DB with migration/backfill and legacy `scan_options.kind`
   decode. DONE phase 2: `/schedules` now exposes evidence-retention sweep schedules with dry-run
   default, retention-class/age/limit/local-file controls, and an approval-receipt field for
   scheduled deletion.
2. DONE: show one unified target timeline: background dispatcher decision, recurring schedule next run,
   current active scan/ASM batch, last activity, and last skip reason.
3. DONE: `/schedules` creates/edits ASM waves without pretending they have a DAST `scan_type`; it
   exposes batch size, stale days, endpoint filter, focused family, and Lab/deep gating only when
   relevant.
4. DONE: schedule-kind validation, legacy decode, due-run dispatch, scoped ASM option
   execution, and target active-scan skip have backend tests. UI payload shape is covered by
   TypeScript/production build and browser QA; add component-level tests when the UI test harness
   expands beyond helper scripts.
5. DONE phase 1: add safe remediation actions to the target campaign timeline. Failed and active
   jobs open their scan, policy/rate blockers open preselected schedule controls, stale-worker
   blockers open worker controls, auth/second-user blockers open a target-prefilled interactive
   session, and claimable work calls the existing `/asm/improve` route.

**Done when:** "Keep this target covered" is a first-class scheduled/campaign action, not an
encoded scan option, and users can see why a target did or did not receive ASM work.

### 4. AI red-team campaign UX and replay loop
**Status: PHASE 1 CAMPAIGN REVIEW DONE.** AI Gate has targets, scenario presets, deterministic/semantic judging,
redacted transcripts (`GET /ai/scans/{id}/transcript`), transcript purge, MCP readiness, control
inventory (`api.ai_assurance`), adaptive logic (`api/ai_gate/adaptive.py`), and red-team report
export (`GET /scans/{id}/ai-redteam-report` / `api.get_ai_redteam_report`). Completed scan detail
now renders a campaign review card backed by `ai_gate.coverage_matrix`, `execution_plan`, and
`evidence_manifest`, and `POST /ai/scans/{scan_id}/replay` queues focused reruns for skipped
probes, errored families, selected families, selected transcript probes, or all probes.
`GET /ai/scans/{scan_id}/campaign-history` returns same-context run comparison for the campaign
panel, and `GET /ai/targets/{target_id}/campaign-history` plus `/settings/ai-gate` now expose
target-level longitudinal run/context history outside a single scan detail page. `GET
/ai/targets/{target_id}/campaign-history/export` returns a content-free JSON export with readiness
trends, bounded trend-series points, per-run red-team report links, and per-run evidence-manifest
hash/count summaries.

**Implement:**
1. DONE: add an AI Red-Team Campaign view grouping target, environment, profile, probe pack, readiness,
   control inventory, skipped probes, transcripts, findings, semantic judge output, and report export.
2. DONE: add an OWASP LLM / RAG / agent / MCP coverage matrix: planned, executed, skipped, blocked by
   safety profile, finding count, and evidence hash per family.
3. DONE: finding-level replay entry points link to finding detail, where focused AI Gate replay
   already preserves production confirmation. Scan-level "rerun failed/skipped probes" now exists
   for skipped/errors/family/all modes and also preserves production confirmation. Selected
   transcript replay now exists through `mode=transcript` and uses the same production gate.
   Same-context campaign history/comparison now exists on scan detail. Target-level longitudinal
   run/context reporting now exists on the AI Gate target page, with phase-1 readiness trend summary,
   a bounded readiness-over-time trend visualization, a content-free campaign-history export link,
   and content-free evidence-manifest summaries.
4. DONE: missing AI control-baseline gaps appear in Action Center and richer readiness/campaign
   history is available on scan and target surfaces.

**Done when:** an AI red-team run can be reviewed, rerun, compared across runs, and defended as a
campaign artifact instead of a loose scan report. Phase 1 now satisfies this on scan detail and on
the AI Gate target page; per-context readiness trend chips and content-free evidence-manifest export
summaries are now visible, and bounded readiness-over-time trend bars are rendered for overall and
per-context run history.

### 5. Model Intake trust UX
**Status: DONE FOR THE BOUNDED TRUST AND EXCEPTION WORKFLOW.** The API and UI now carry real signature/trust-anchor fields:
`ModelIntakeScanRequest.signature_*` and the Model Intake page fields around signature URL, public
key URL/PEM, signature value, trusted keys, hash, payload, and padding. The form now adds guided
trust modes plus a pre-submit pass/fail/advisory preview, so users can see why checksum, signature,
trusted-root, governance, or approval evidence will block or remain advisory before queueing.
Saved trust-anchor selection/creation/deactivation is now implemented for strict trust mode.
Policy profiles can now bind required saved trust anchors, and matching strict Model Intake scans
inherit those anchors before cryptographic trust evaluation. Dashboard Model Intake blockers now open
the trust-remediation route state. `GET /model-intake/scans/{scan_id}/evidence-export` and
`model_intake.evidence_export` now return content-free trust/AIBOM/policy/replay hashes without
artifact bytes, metadata JSON, signatures, keys, model cards, or runtime URLs. Exception lifecycle
preview and approved expiry execution are now available from the Exceptions Queue.

**Implement:**
1. DONE: add a signature-mode segmented control: `checksum only`, `signature URL + key URL`, `inline
   signature + inline key`, `trusted key fingerprint`, and `metadata-supplied evidence`.
2. DONE: add a pre-submit validation/preview panel that states exactly which trust requirements will pass,
   fail, or be advisory under the selected policy profile.
3. DONE: clear warnings explain when metadata-supplied keys are evidence but not an operator trust
   root, and strict mode now has a saved trust-anchor selector/manager.
4. DONE: helper tests cover each preview mode's core trust semantics, saved-anchor expansion,
   policy-profile required-anchor binding, deployment-decision anchor gaps, exception hygiene, and
   content-free Model Intake evidence export, and approved exception lifecycle remediation. Existing
   API/e2e signature tests prove trusted verification is reachable only with operator-supplied trust material.

**Done when:** a developer can submit a model with a valid trust configuration without knowing every
low-level signature field, and the UI explains why "signature present" is not the same as "trusted."

### 6. Detection recall: benchmark misses still matter
**Status: IMPLEMENTATION PHASES COMPLETE; FRESH CURRENT-FLEET BENCHMARK ACCEPTANCE PENDING.**
Reflected XSS on id-like path segments shipped (`active_checks._injectable_path_segment`). Historical
benchmark weaknesses in POST-body SQLi/login coverage, stored XSS store-then-render proof, and
workflow/write-side BOLA drove the phases below.
Body-param SQLi/NoSQL primitives exist (`nosql_injection_test_json_body` and body-param sites in
`active_checks`), and NoSQL JSON-body checks now emit endpoint-attempt telemetry so ASM/family
coverage can distinguish completed, partial, and skipped JSON-body probes. Focused SQLi/XSS active
loops pass their family into the shared endpoint scorer, while endpoint ordering relies on generic
source, method, body/parameter shape, and injection-surface signals rather than benchmark product
nouns. The near-term gap is still better
endpoint/body capture, auth context, and proof routing on benchmark workflows. Benchmark
summaries and scorecards now include `auth_workflow` diagnostics with required/observed auth states,
missing second-principal blockers, and authz/BOLA attempt rollups so a missed BOLA expectation is
classified as `missing_required_auth_context` instead of a generic detector miss when the benchmark
did not actually exercise both principals. Scorecards now also emit `benchmark_followups`: every
missed fixture expectation becomes either a runnable `scan.focused_family` work item (SQLi/NoSQL,
browser-proof XSS, auth/BOLA when preconditions are present), a blocked action template with explicit
auth/principal blockers, or a detector-gap record when no focused executor exists yet.
`POST /arsenal/hypotheses/from-benchmark` / `hypothesis.generate_from_benchmark` now converts those
follow-up rows into deduped `benchmark` hypotheses with `runtime_proof_required=true`, without
queueing scans, creating findings, or satisfying proof. `scripts/benchmark_targets.py --seed-hypotheses`
now posts each scored card's `benchmark_followups` to that route and records the ingest response in
the benchmark artifact; optional `--hypothesis-target-id name=uuid` binds those leads to a target.

**Implement:** keep the benchmark as the unit of progress. Add focused campaigns for login/search/
review/order APIs; capture real POST bodies from browser/HAR/OpenAPI; keep NoSQL operator probes
attached to JSON-body coverage telemetry; add browser-first reflected/stored XSS proof; add safe
Lab/deep workflow/write-BOLA checks after graph/principal preconditions exist. DONE phase 1 for
auth-workflow diagnostics in `scanner_tools.benchmark_summary` and `scripts/benchmark_targets.py`;
DONE phase 2 for turning missed scorecard expectations into explicit follow-up worklist rows;
DONE phase 3 for connecting those rows to the hypothesis/campaign planning layer as benchmark
hypotheses;
DONE phase 4 for an opt-in benchmark-runner bridge that seeds those hypotheses from a recorded
scorecard;
CORRECTED phase 5: focused SQLi/XSS active-loop ordering remains, but benchmark workflow noun boosts
were removed; source provenance, request method, body/parameter shape, and generic sink signals drive
the bounded worklist instead.
DONE phase 6 for stored-XSS store-then-render proof routing: stored marker evidence remains
suspected/likely-vulnerable, while exact stored payloads are promoted to verified High only when
the headless browser proof confirms execution and carries `browser_proof`/`poe_result` into the
normalized finding. DONE phase 7 for POST-body SQLi proof replay preserving the captured JSON/form
body template, content type, and replay-safe request headers during extraction, so required sibling
fields are not dropped after initial detection. DONE phase 8 for
reflected XSS path-value synthesis on lookup/track-style GET routes: queryless parent routes can now
receive a constrained synthetic child segment and must still pass the existing reflection/browser-proof
gates before any finding is emitted. DONE phase 9 for stricter-but-broader NoSQL JSON-body auth-bypass
success signals: token/session responses with account/customer/id identity markers count as proof,
while token-only or generic 200 responses remain insufficient. DONE phase 10 for JSON mass-assignment
effect proof: privileged-field probes now accept normalized privilege effects such as
`authorities=["admin:write"]` only when the baseline response lacks the same privilege signal, while
exact field reflection remains the preferred proof. DONE phase 11 for authenticated JWT coverage:
basic and comprehensive JWT weakness checks now reuse configured bearer/cookie JWTs before falling
back to guessed login endpoints, and forged-token probes suppress the original Authorization header.
DONE phase 12 for workflow/write-side BOLA replay: the graph/resource replay path now attempts a
bounded empty-JSON `PATCH` against owner object URLs with the second principal and emits a separate
critical `write_cross_principal_replay` finding only when the response returns the requested owner
object ID that was absent from the attacker's own listing. DONE phase 13 for nested POST-body SQLi
request construction: DBMS detection and active JSON-body probes now mutate flattened body-path
parameters such as `credentials.email` through the same nested JSON writer used by replay, preserving
captured sibling fields and avoiding flat-key bodies that type-strict login/search APIs reject.
DONE phase 14 for XSS budget quality: smart XSS now receives the same reachable/prioritized active
worklist as SQLi, so bounded scans spend XSS budget on filtered real endpoints instead of the raw
synthetic candidate list. DONE phase 15 for POST-body reflected-XSS browser proof: HTML-like
POST/PUT/PATCH responses that reflect an executable payload now get a headless response-render proof
attempt and can be promoted to verified High with `browser_proof`; JSON responses are explicitly
excluded from that render path so raw JSON reflection is not overclaimed as browser execution. DONE
phase 16 for crAPI-style BOLA consumer synthesis: cross-principal replay now applies owner object IDs
harvested from authenticated producer responses to discovered consumer/sub-resource templates such as
`/vehicle/{id}/location`, while keeping the existing proof gate that requires the attacker response to
return the requested owner object ID. DONE phase 17 for smart-mode debug exposure recall: default
smart scans now run a narrow `debug_dev` forced-browsing lane, so validated Prometheus/actuator-style
endpoints such as `/metrics` can surface without enabling the full broad forced-browsing wordlist.
DONE phase 18 for reflected-XSS route preservation: Smart now keeps discovered queryless
lookup/action routes such as `/rest/track-order` in the active endpoint graph even when it also
creates synthetic query-param variants, allowing the existing path-value XSS proof to test
`/route/{value}` surfaces instead of only `/route?id=...`. DONE phase 19 for NoSQL collection
differential proof: JSON-body NoSQL checks now compare restrictive `$eq` controls with permissive
`$ne`/regex/exists operators and promote only material JSON collection expansion with data-shaped
items, carrying control/payload item counts into finding evidence. DONE phase 20 for structured API
SQLi proof: SQLi response classification now treats material JSON collection expansion as a strong
signal when an injected payload changes a rejected/empty control into a successful multi-record
response, covering coupon/search/filter APIs that do not emit DB error banners. DONE phase 21 for
query-parameter NoSQL proof: Smart's NoSQL lane now tests discovered GET endpoints with query
parameters using `$eq`/`$ne` operator differentials and only promotes material JSON collection
expansion, covering review/search collection routes that are not JSON-body sinks. DONE phase 22 for
BFLA collection-authz scheduling: authenticated Smart scans now run the safe anon-vs-auth collection
differential independently from the heavier BOLA lane, using discovered collection routes from crawl,
browser, endpoint graph, JS, HAR, and the existing model-collection wordlist. DONE phase 23 for BOLA
producer quality: cross-principal replay now ranks compound resource route names such as
`mechanic_report`, boosts concrete collection/list producers, and diversifies producer selection so
repeated synthetic query variants cannot starve service-prefixed collection endpoints. DONE phase 24
for non-`id` object identifiers: BOLA replay now treats VIN/license-style keys as replayable resource
identifiers and can apply them to discovered placeholders or query parameters such as
`<vehicleVIN>`/`?VIN=`, preserving the existing cross-principal proof requirement. CORRECTED phase 25:
product-specific coupon/shop/mechanic fragment filters and direct community/identity/workshop API-doc
probes were removed along with the earlier service-mount rewrite. Frontend request recovery now
depends on generic versioned literals or statically observed HTTP calls and client bases. DONE phase
26 for method-aware frontend request capture: static `fetch` and
axios-style calls now preserve literal same-origin URLs, HTTP methods, and query/body parameter names in
the active endpoint graph. These observed request facts remain usable on SPA catch-all sites, while loose
route strings do not gain fabricated POST methods or bodies.
DONE phase 27 for client-bound API base recovery: statically configured axios client instances bind
their literal `baseURL` only to calls made through that same client variable. This replaces broad
base/path cross-products with a program-derived request URL and preserves the same-origin active gate.
DONE phase 28 for config-style frontend requests: axios callable/request configurations with literal
`method`, `url`, `data`, and `params` now produce the same bounded request contract as verb-style calls;
objects without an explicit method are ignored.
DONE phase 29 for provenance-aware request contracts: active endpoints now merge by canonical
method/path rather than raw query-bearing URL, retain all contributing sources, and let runtime
traffic override schema/static/inferred content types, body templates, and conflicting defaults.
Only OpenAPI, explicit manual input, or form metadata marks fields required; observed and inferred
body fields remain replay siblings without being mislabeled as schema requirements.
DONE phase 30 for bounded response-guided SQLi request completion: when a JSON POST baseline returns
an explicit `400/422` missing-field validation structure, Smart SQLi can add at most five safe sibling
fields and retry once before payload testing. Privilege, ownership, tenant, payment, approval, and
workflow-state fields are denied; non-JSON text never drives completion, and completion telemetry is
recorded separately from vulnerability proof.
DONE phase 31 for the same bounded completion contract in JSON-body NoSQL testing: validation-derived
safe siblings are added to the persistent baseline and one retry is made before operator differentials,
with the added fields carried in endpoint-attempt telemetry and excluded from proof classification.
DONE phase 32 for scorecard-backed POST-body injection measurement: shared benchmark summaries and
saved target scorecards now report SQLi/NoSQL body attempts, attempted/completed parameter counts,
completion ratios, response-guided completion counts, redacted validation-field samples, statuses,
and proof-type counts without retaining request bodies.
DONE phase 33 for fail-closed response-guided baselines: SQLi and JSON-body NoSQL parameter probes
now stop before sending attack payloads when the completed benign retry fails or remains a `400/422`
validation error. A completed attack body is never compared against the earlier incomplete baseline.
DONE phase 34 for bounded frontend request parsing: static object inspection uses one depth pass,
caps each object at 64KB and 30 keys, and verb-style calls require `axios` or a client variable proven
by `axios.create`. Non-HTTP objects such as queues and caches cannot fabricate mutating requests.
DONE phase 35 for production-wired body-completion telemetry: merged active attempts preserve
per-family validation fields and proof labels, benchmark consumers expand the canonical family map,
and response-guided completion ratios are distinct from ordinary probe-parameter execution ratios.
DONE phase 36 for query-preserving canonical contracts: method/path still deduplicates endpoint rows,
while query names/defaults are merged into the contract and the strongest query-bearing observed URL
survives later queryless or weaker-source rows.
DONE phase 37 for proof-preserving post-retest scorecards: structured browser/PoE contracts survive
finding persistence, and live retest verdicts overlay the original scan finding instead of replacing
immutable scan-time evidence. CORRECTED phase 38 for bounded sensitive-metrics exposure signals:
unauthenticated Prometheus responses qualify only when bounded parsing finds at least three
application-defined sensitive metric names spanning two independent identity, commerce, or security
classes; standard runtime/exporter prefixes are excluded and generic metrics remain unverified.
Metric names alone are an observed lead, not deterministic value-disclosure or exploited proof, and
therefore retain the human-verification gate.
DONE phase 39 for non-polling benchmark submission: `scripts/benchmark_targets.py --submit-only`
queues exactly one fingerprint-current benchmark and exits with a content-free receipt, while
requested two-user runs fail before submission unless both principals are minted successfully and
their server-issued JWT identity claims prove they are distinct accounts.
DONE phase 40 for honest BOLA budget telemetry: Smart scan progress and `bola_status` distinguish
the discovered candidate inventory from the configured endpoint execution ceiling and report the
scheduled upper bound. A large pre-cap URL pool is no longer presented as if every candidate were
scheduled for active replay, while the existing `smart_bola_test` endpoint and deadline limits remain
the authoritative execution controls.
DONE phase 41 for repeatable authenticated benchmark bootstrap: each submission mints fresh,
role-distinct test-account emails under one per-run nonce before comparing stable server-issued JWT
identity claims. Prior benchmark accounts with stale passwords can no longer block a later authorized
run, signup-only phone identifiers are deterministically unique per fresh account for APIs that
enforce global phone uniqueness, and account identifiers remain absent from the content-free queue
receipt. Login minting uses a bounded backoff after successful signup for targets whose identity
service is briefly eventually consistent; failures remain content-free and fail before queueing.

**Done when:** recorded two-user benchmark scorecards show the targeted miss becoming a deterministic
finding, not merely an attempted endpoint.

### 7. Campaign, hypothesis, and application-graph consumer layer
**Status: GRAPH + HYPOTHESES + CAMPAIGN EXECUTION + PROOF RECONCILIATION DONE.** `application_graph_nodes` /
`application_graph_edges` now persist route/object nodes plus producer/consumer/auth-boundary edges
from discovery + recursive BOLA `resource_map`; `GET /targets/{id}/graph` exposes the graph.
Object-ID and cross-user primitives also exist per scan (`access_control_checks` object-id
extraction, `_path_has_object_id_segment`, cross-principal replay in `proof_of_exploit` /
`verification_engine`). Bounded hypothesis situation reports now consume the durable graph as context
by target, summarizing route/object/principal nodes, producer/consumer edges, auth-boundary edges,
and graph-missing targets. `POST /arsenal/hypotheses/{id}/plan-campaign` /
`hypothesis.plan_campaign` now creates or links a mission campaign and planned campaign action from a
hypothesis `next_test_action` without executing it, queueing scans, or creating findings. `POST
/arsenal/execute` now accepts `campaign_action_id`, validates that the requested command matches the
planned action, and binds the resulting `command_results` row back onto that planned action so the
mission timeline can show the transition from planned to blocked/queued/completed.
`POST /arsenal/hypotheses/{id}/reconcile-proof` / `hypothesis.reconcile_proof` now reconciles an
executed action back to its lead through the existing deterministic proof taxonomy. This borrows
T3MP3ST's PackBoard idea, but adapt it into ShakerScan's proof model: leads are coordinated work
items, not findings.

**Implement:**
1. DONE phase 1: the `campaigns` mission layer wraps `campaign_actions` over ASM/scan/focused-family/
   AI Gate/Model Intake/retest/export work. A `campaigns` table carries objective, name, campaign
   type, target, target scope, risk tier, policy profile, planner, `OperationPlan` reference, context
   hash, status, and deployment impact; `campaign_actions.mission_campaign_id` links the action
   ledger to it. `POST /arsenal/campaigns` (`campaign.create`, dry-run/record-only), `GET
   /arsenal/campaigns` (`campaign.list`), `GET /arsenal/campaigns/{id}` (`campaign.get`, with an
   action rollup by status), and `POST /arsenal/campaigns/{id}/actions` (`campaign.link_action`)
   expose it. Creating or linking a campaign queues no work and creates no findings; individual
   actions still flow through the existing product routes and receipt gates. The campaign type enum is
   `continuous_asm`, `authenticated_dast`, `api_authz`, `ai_red_team`, `model_intake`, `benchmark`,
   `incident_retest`, `source_informed_dast`, `finding_retest`, `focused_family`. DONE phase 2:
   `GET /arsenal/campaigns/{id}` now returns a `deployment_impact` rollup
   (`_campaign_deployment_impact`) over the findings linked to the campaign's actions —
   `by_severity`, `by_status`, `active_finding_count`, and an `estimated_default_blockers` count of
   active critical/high findings, plus `total_action_count` and a `partial` flag when the fetched
   actions are bounded. The rollup is explicitly labelled an estimate, not the authoritative
   deployment decision (policy profiles/exceptions/proof state still own that). Execution-gateway
   command results now link automatically to their planned campaign action.
2. DONE phase 1: add a `hypotheses` table for route, endpoint, object, principal, AI target, model artifact,
   dependency, config, and secret leads. Fields should include target/campaign, vuln family, CWE,
   severity guess, confidence, source (`app_graph`, `source_ingest`, `ai_planner`, `scanner_signal`,
   `ai_gate`, `model_intake`, `benchmark`, `manual`), dedupe key, status, version, claim lease, smoke score,
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
   bounded recent board window instead of exposing the entire board by default. DONE phase 2:
   reports now include bounded application-graph context for hypothesis targets (`graph_context`):
   route/object/principal node counts, producer/consumer and auth-boundary edge counts, target
   samples, and graph-missing targets. This is reporting context only; it cannot queue tests, create
   findings, or promote proof state. DONE phase 3: `GET /targets/{id}/asm/activity` now embeds the
   same bounded target-scoped situation report, and the ASM target view renders it as proof leads next
   to coverage and the campaign timeline.
7. DONE phase 1: hypotheses become `promoted` only by linking an already-created canonical finding
   from the exact campaign action. Reconciliation requires a target-scoped approval receipt,
   compare-and-set hypothesis version, target/family/route/method/parameter agreement, exact scan,
   deterministic-retest, or gated-authz action provenance, and persisted `exploited` proof. It never
   creates a finding. AI/source/graph/tool rationale, scan completion, weak/likely proof, unrelated
   findings, and mismatched routes remain ineligible and are recorded as bounded rejection counts.
   The Hypothesis Board exposes this gated reconciliation and links promoted finding IDs without
   changing finding severity or proof state. `test:hypothesis-proof-promotion` is the focused release
   gate for these invariants.
8. DONE phase 1: dedupe rule now accepts canonical `dedupe_dimensions` for route/method,
   object key, principal pair, tenant, parameter/body path, and proof surface. These dimensions
   produce the stored `dedupe_key`, and `_upsert_hypothesis` matches existing target/family/key rows
   across signal sources so a new source endorses the existing hypothesis instead of creating another
   card.
9. DONE phase 1: claim rule uses compare-and-set on hypothesis `version`, keeps
   confirmed/refuted/dead hypotheses unclaimable, and now exposes expired claimed/testing rows with
   `effective_status: open`, `claim_state.expired`, and `claimable: true`; `status=open` list queries
   include those expired claims.
10. DONE phase 1 for product-signal routing: worker finalization now converts AI Gate semantic,
    needs-review, or low-confidence findings into focused replay hypotheses, and Model Intake
    metadata/governance/trust-control findings into `model_intake.trust_preview` remediation
    hypotheses. These records endorse the hypothesis board only; they do not create findings, promote
    proof state, or execute follow-up work.
11. DONE phase 1: `hypothesis.plan_campaign` consumes a hypothesis' `next_test_action` and records a
    mission campaign plus planned campaign action with the hypothesis id, planned action payload, and
    `proof_state: planned_not_executed`. This is a coordination record only; it does not call
    `asm.improve`, queue scans, claim the hypothesis, create findings, or alter proof state.
12. DONE phase 1: `/arsenal/hypotheses/source-ingest` and `hypothesis.generate_from_source` accept
    bounded route/OpenAPI/GraphQL/package/frontend/backend/IaC/AI-tool hints and convert them into
    deduped `source_ingest` hypotheses for authz, SQLi/NoSQL, XSS, SSRF, LFI/path traversal,
    mass-assignment, upload, secret, and AI/tool-boundary work. The route records or endorses leads
    only, marks them `source_only` and `runtime_proof_required`, reports skipped vague hints, dedupes
    package/IaC/non-route facts by their explicit subject metadata instead of collapsing all same-kind
    hints together, and returns `findings_created=0` / `execution_enabled=false`.
13. DONE phase 1: `/arsenal/hypotheses/from-plan` and `hypothesis.generate_from_plan` consume a
    persisted dry-run `OperationPlan` and convert bounded supported actions
    (`asm.improve`, `asm.test`, `scan.focused_family`, AI Gate, Model Intake trust, and
    hypothesis-planning actions) into deduped `ai_planner` hypotheses. The route skips commands that
    are not hypothesis seeds, records missing inputs/preconditions as metadata, and returns
    `findings_created=0`, `queued_scans=0`, `execution_enabled=false`, and
    `runtime_proof_required=true`.

**Done when:** the scanner can state "`GET /api/orders` produces `order.id` owned by user1;
`GET /api/orders/{id}` consumes it -> test user2 read/mutate" from a persisted graph and schedule
the deterministic campaign from it, while unproven graph/source/AI signals remain hypotheses rather
than findings, and then link only the exact deterministic finding proof produced by that campaign.

### 8. Auth / principal / role matrix
**Status: DONE THROUGH PHASE 14 MANAGED CREDENTIAL EXECUTION AND POLICY-WRITE GATING.** `target_endpoints.auth_state` exists, and
`target_principals` plus `target_endpoint_expectations` now persist role, tenant, credential-profile
references, auth states, and endpoint x principal expected access. `GET/POST /targets/{id}/principals`
and `GET/POST /targets/{id}/principal-matrix` expose the matrix as non-executing planning facts, and
generated `AgentContextPack` records include a bounded `principal_matrix` plus credential
precondition signals. Graph-generated authz hypotheses now consume that principal matrix, attaching
matched principal, role/tenant, expected access, and credential-precondition facts to the next
`asm.improve` action while keeping the record an unproven hypothesis. Hypothesis campaign planning
now derives a non-executing `authz_replay_plan` with method/path, principal pair, expected access
rows, and missing preconditions from that matrix. `authz.replay_plan` now executes that stored plan
through an existing interactive session only via the gated Command Arsenal path (`execute=true`,
`confirm_authorized`, approval receipt, and execution feature flag), refuses anonymous fallback when
the required authenticated principals are missing, records replay observations, binds them to
record-only evidence instances plus an `authz.replay_plan` tool receipt, and updates the planned
campaign action without creating findings automatically. `authz.promote_replay_finding` now
explicitly promotes only reviewed replay observations with a cross-principal differential into
manual-source BOLA findings, validates the approval receipt against the campaign action's real
target, links evidence instances/tool receipts, records a command-result audit row, and collapses
volatile object ids into route-template fingerprints so `/orders/1` and `/orders/46` do not create
separate replay findings; this is still gated and never happens automatically after replay.

**Implementation record:** DONE phase 1 for richer replay proof bundles. `authz.replay_plan` now stores a
content-free `proof_bundle` that distinguishes access-granted 2xx observations, soft 200 denials,
denial-like redirects, authenticated-principal count, and whether a cross-principal differential was
observed; `authz.promote_replay_finding` requires that differential and carries the bundle into
promoted evidence. DONE phase 6 for campaign-action operator controls: the advertised authz replay
and promotion routes now dispatch through the approval-receipt gate, completed replay actions are
eligible for explicit promotion, and the Command Arsenal UI supports origin-aware interactive-session
selection, proof-bundle review, gated replay, and differential-only finding promotion. DONE
phase 7: ASM auth-remediation links now carry target identity into the interactive workflow; that page
loads the content-free persisted principal matrix, labels user contexts with role/tenant expectations,
shows credential-profile presence without credential contents, summarizes allow/deny expectations,
and can load a selected expectation into the endpoint replay form without executing it.
DONE phase 8: the same workflow can create, update, and deactivate the content-free `user1` and
`user2` principal records, including labels, roles, tenant ids, and credential-profile references.
The UI never accepts or returns raw credential contents; session auth remains an explicit separate
step. Managed credential-profile storage, expiry, rotation, and worker-time resolution are complete.
DONE phase 9: operators can create or update allow/deny/requires-role endpoint expectations from the
interactive principal plan, load persisted rows back into the editor, and explicitly delete obsolete
expectations through a target-scoped UUID route. These remain planning records only: expectation
maintenance cannot execute a replay or create a finding.
DONE phase 10: generated target context packs no longer treat content-free principal identities as
configured credentials. Primary readiness requires an active credential-profile reference (or the
legacy target auth signal), and second-user readiness requires two distinct profile references (or
the legacy alternate-user signal), preventing record-only principal setup from unblocking auth/BOLA
execution plans prematurely.
DONE phase 11: Command Arsenal replay and promotion controls inspect fail-closed HTTP 200 responses
and show the dispatcher block reason or action-state phase; successful dispatches show explicit
completion feedback. Operators no longer have to infer execution from a silent refresh.
DONE phase 12: target-scoped credential profiles now store write-only Authorization-header or cookie
material behind masked REST responses, use the shared optional Fernet encryption-at-rest layer,
track expiry and near-expiry refresh state, support explicit rotation, and retain deactivated rows for
audit history. This storage phase did not itself queue work or prove an authorization finding.
DONE phase 13: normal target scans, manual ASM recon/test/improve actions, and the background ASM
dispatcher now attach only content-free, target-bound profile ids for active, unexpired profiles
referenced by active `user1`/`user2` principals. Workers resolve and decrypt those ids in memory
immediately before execution into the scanner's existing primary/second-user Authorization or cookie
fields; managed values are never copied into `scans.options`, parent/shard rows, or Redis jobs.
Explicit per-scan auth wins; an unavailable or undecryptable Fernet value fails closed. Parallel and
dynamic ASM auth-state planners preserve/remap profile references without materializing secrets.
The API and worker both reject a shared profile id across user1/user2, so BOLA cannot compare one
identity to itself. Principal lists,
context packs, and graph hypotheses count a credential as configured only when the named managed
profile currently resolves. The interactive workflow manages masked profiles, expiry, rotation, and
deactivation and selects real profile names instead of accepting only free text. Loading a managed
profile into an already-running browser session remains an explicit session-auth step; no secret is
returned to the browser, and profile resolution does not create findings.
DONE phase 14: endpoint/principal expectation writes are authorization-policy changes, not read-only
inventory. `target.principal_matrix.record` is now an active, gated Command Arsenal command with
`confirm_authorized`; direct create/update and delete routes always require a target-scoped approval
receipt and write command-result audit rows. The interactive workflow obtains that scoped receipt
only after an explicit operator confirmation. An unaudited AI/read-only command can no longer alter
`expected_access` and suppress a future authorization proof.
DONE phase 15: gated authz replay requires both distinct managed profile bindings and distinct stable
server-issued JWT identities in the active session. Identity claims are hashed for equality checks and
never retained; same-account profiles and opaque credentials without a provable identity make replay
inconclusive instead of allowing a cross-principal proof claim.

**Done when:** a campaign can assert "endpoint X requires role admin" and prove a lower-role
principal's access is a finding.

### 9. Evidence object store phase 2, EvidenceInstance split, and tool receipts
**Status: DONE FOR CURRENT EVIDENCE AND TOOL-RECEIPT SCOPE.** `evidence_objects`
table ships (hash, redaction_profile, retention_class, storage_uri, scan/finding links);
`save_findings` + `save_ai_findings` write one object per finding; `GET /findings/{id}/evidence` +
`GET /evidence/{id}` read them. The canonical finding collapse works
(`templated_finding_identity`, `all_urls`, `all_payloads`, `duplicate_count`). `tool_receipts` and
`evidence_instances` now persist record-only receipts and concrete proof observations through
`GET/POST /arsenal/tool-receipts` and `GET/POST /evidence/instances`; recording either cannot run
tools, create findings, or update canonical finding proof state. Large redacted evidence payloads now
externalize to a content-addressed local object store under `RESULTS_DIR/evidence-objects` with
`local:evidence_objects/...` storage URIs, and the evidence read API hydrates/verifies them on read.
`GET /evidence/export-manifest` returns a content-free hash/storage/retention manifest,
`GET /evidence/export-bundle` returns a content-free bundle descriptor with a manifest hash, bundle
hash, retention/integrity summaries, API read-replay paths, and a deterministic zip archive descriptor;
`GET /evidence/export-bundle?format=zip` downloads a content-free archive containing the manifest,
bundle descriptor, and replay plan. Callers that pass `record_event=true` also get a durable
content-free export event for `GET /timeline`, and
`POST /evidence/retention/sweep` previews or executes bounded evidence-object cleanup with
`dry_run: true` by default and `legal_hold` excluded. `GET /arsenal/tools` now returns a
`release_gate` named `no_phantom_tools` that fails if an adapter
claims installed/runnable status without a resolved binary or internal implementation, or if a
runnable adapter lacks parser/proof metadata. Worker finalization now emits record-only `ToolReceipt`
rows for the internal AI Gate probe executor, Model Intake signature verifier, parsed DAST module
output from Nuclei, Dalfox, sqlmap, nmap, SSLyze, and testssl, and passive/lifecycle DAST outputs
from httpx, katana, subfinder, ffuf, and Playwright/browser discovery, stamping returned
receipt ids into scan results without changing findings or proof state. Continuous ASM recon and
endpoint-batch executors now emit ASM-specific receipts for success, partial/missing telemetry,
timeout, auth-missing skip, cancellation-before-start, and failure states. Oversized evidence can now
externalize to an opt-in S3/MinIO-compatible object store via `EVIDENCE_STORAGE_BACKEND=s3`,
`EVIDENCE_S3_BUCKET`, and optional endpoint/region/credential settings; API reads hydrate remote
objects through signed GET and verify their recorded SHA-256 before returning content. Retention
sweeps now classify remote evidence candidates separately; dry-runs preserve them as previews, and
approved executions retire S3/MinIO objects through signed DELETE before deleting their DB rows.
Remote delete failures leave rows preserved and retryable. Long subprocess stdout/stderr parser-failure
snippets now persist as redacted evidence-object refs linked from tool receipts.

**Implement:**
1. DONE phase 1: externalize `storage_uri` from `inline:` to local object storage for large objects.
   `api/evidence_storage.py` stores oversized redacted evidence by content hash under
   `RESULTS_DIR/evidence-objects`, returns `local:evidence_objects/...`, and `GET /evidence/{id}` /
   `GET /findings/{id}/evidence` hydrate and integrity-check local content. DONE phase 2:
   `EVIDENCE_STORAGE_BACKEND=s3` stores oversized payloads in S3/MinIO-compatible object storage
   using content-addressed `s3:evidence_objects/...` URIs and SigV4 PUT/GET without adding a runtime
   dependency. Remote reads return content only after the downloaded bytes match `content_sha256`;
   failed remote writes fall back to the local store so scan finalization does not lose evidence.
2. DONE phase 1: add a retention sweeper, export manifest format, and content-free bundle descriptor. `GET /evidence/export-manifest`
   returns a content-free manifest with object ids, hashes, storage URIs, retention classes, storage
   status/integrity, and a manifest hash. `POST /evidence/retention/sweep` is dry-run by default,
   skips `legal_hold`, applies bounded retention windows (`short`, `sensitive`, `standard`, `audit`),
   reports remote object candidates as preserved, and can delete expired DB rows plus local object
   files only when explicitly executed.
   `GET /evidence/export-bundle` / `evidence.export_bundle` returns a content-free bundle descriptor
   with `bundle_hash`, `manifest_hash`, retention/integrity summaries, and API read-replay paths.
   DONE phase 1: deliberate bundle export requests with `record_event=true` write durable
   `export_events` rows, and `GET /timeline` exposes those events without evidence content. DONE
   phase 1: `GET /evidence/export-bundle?format=zip` returns a content-free metadata archive with
   manifest, bundle descriptor, replay plan, archive hash, filename, and download headers. DONE phase
   1: `schedule_kind=evidence_retention_sweep` runs bounded retention sweeps from schedule
   `scan_options`, defaults to `dry_run=true`, advances only after success, and requires
   `approval_receipt_id` before any scheduled `dry_run=false` execution.
3. DONE phase 1: split canonical `Finding` from `EvidenceInstance {concrete_url, object_id, payload_variant,
   request_response_refs, principal_pair, proof_observation, campaign_action_id, tool_receipt_id,
   redaction_profile, hash, retention_policy}` as durable record-only rows. Finding promotion still
   goes through the existing proof taxonomy.
4. DONE for current tools/executors: add `ToolReceipt` records before adding new offensive tooling:
   `httpx`, `katana`, `nuclei`, `subfinder`, `ffuf`, `dalfox`, `sqlmap`, `nmap`, `sslyze`,
   `testssl.sh`, Playwright/browser proof, AI Gate probe execution, and Model Intake artifact
   fetch/signature verification. The registry/record schema exists, and worker finalization now emits
   internal `ai_gate_probe_executor` / `model_intake_signature_verifier` receipts plus parsed-result
   DAST module receipts for Nuclei, Dalfox, sqlmap, nmap, SSLyze, and testssl, passive/lifecycle
   DAST receipts for httpx, katana, subfinder, ffuf, and Playwright/browser discovery, plus ASM recon
   and endpoint-batch executor receipts. Passive receipts no longer claim parser success from aggregate
   discovery counters alone; aggregate-only observations are recorded as partial/recorded telemetry.
   DONE phase 2: `scanner_tools.common.run()` now records bounded, redacted subprocess outcomes
   (`redacted_argv`, command hash, exit code, timeout flag, duration, stdout/stderr lengths, stderr
   preview) into `scan_metadata.subprocess_receipts`, and worker finalization persists those exact
   outcomes as normal `tool_receipts` with `scanner-subprocess` provenance. DONE phase 3: bounded
   subprocess receipts now include stdout previews and worker finalization conservatively classifies
   known JSON/parser failure markers from stderr/stdout previews as `status=parser_error` with
   `parser_status=failed`. DONE phase 4: retention sweeps can delete S3/MinIO remote evidence through
   signed DELETE before deleting DB rows, with dry-run preservation and failed-delete retry semantics.
   DONE phase 5: subprocess receipts now carry bounded/redacted long-output artifacts, and worker
   finalization persists those snippets as scan-scoped evidence objects linked from
   `stdout_evidence_object_id` / `stderr_evidence_object_id`.
5. DONE phase 1: tool receipts include tool version, adapter version, command hash, redacted argv, worker
   build/container image, target scope, scope receipt, policy profile, approval id, timing, exit code,
   timeout, stdout/stderr artifact refs, parsed evidence refs, parser status, and redaction summary.
6. DONE phase 1: parser failure, timeout, missing binary, or missing smoke/version status can be
   recorded honestly as receipt status/parser status and cannot create verified findings through the
   receipt API.
7. DONE phase 1: tool adapter states are operator-visible through `/arsenal/tools`: `catalog_only`, `wired`, `installed`, `runnable`,
   `gated`, `waived`, and `disabled`. Broad future tools stay `catalog_only` until a narrow adapter,
   parser, scope extractor, proof contract, and receipt shape exist.
8. The near-term registry is a **Tool Receipt Registry**, not an offensive-tool expansion. Do not add
   new exploit tooling until existing DAST, ASM, AI Gate, and Model Intake tools produce receipts for
   success, failure, timeout, skip, and parser-error paths. Internal AI Gate/Model Intake worker
   receipts, parsed-result/passive DAST module receipts, ASM executor receipts, and bounded scanner
   subprocess outcome receipts now cover success/failure/recorded/skipped states plus exact subprocess
   exit/timeout/stderr-preview evidence and conservative parser-error classification.
9. DONE phase 1: add a release/test gate equivalent to T3MP3ST's "no phantom tools": every claimed
   adapter must be `installed`, `runnable`, `waived`, or `catalog_only`, and UI/report copy must not
   imply a missing adapter ran. The `describe_tools`/`/arsenal/tools` response carries
   `release_gate: {name: "no_phantom_tools", status, violations}` and the test suite blocks phantom
   runnable/installed adapter claims.

**Done when:** findings reference evidence objects by id/hash; one templated BOLA route is one
finding with enumerable concrete proof instances; evidence survives worker churn; existing tools
produce receipts for both successful and failed/skipped runs; missing binaries show as skipped/waived,
not phantom success.

### 9a. Refuter workflow and integrity ledgers
**Status: PHASE 11 DONE.** T3MP3ST's strongest process lesson is not a detector; it
is the habit of trying to disprove weak wins. ShakerScan now has durable
`refuter_reviews` records exposed through `GET/POST /arsenal/refuter-reviews` and
`refuter_review.list` / `refuter_review.record`, plus read-only trigger summaries through
`GET /arsenal/refuter-reviews/summary` / `refuter_review.summary`. The summary identifies
Critical/High findings with weak or suspected proof, AI Gate semantic/weak deterministic claims, and
Model Intake metadata trust claims that lack checksum/signature trust signals, and emits suggested
signal-only review requests. `POST /arsenal/refuter-reviews/queue-from-summary` /
`refuter_review.queue_from_summary` can now record unreviewed suggested review work as signal-only
refuter rows without executing scanners or mutating findings; `/settings/arsenal` renders the
summary, candidates, queue action, and the non-executing automation plan for each candidate. Those
plans name the minimal deterministic replay, AI Gate replay, Model Intake trust-preview, and auth
context checks needed to produce counterevidence. `POST /arsenal/refuter-reviews/{id}/execute` and
`refuter_review.execute_plan` now execute the next planned step through existing gates: normal DAST
findings queue deterministic `finding.retest`, AI Gate findings queue focused AI finding replay, and
Model Intake trust claims produce the existing trust-preview artifact. The executor stamps
`latest_refuter_execution` metadata plus a `refuter_review.execute_plan` command-result audit row,
but it does not directly mutate findings, proof state, hypotheses, severity, or deployment gates.
`POST /arsenal/refuter-reviews/{id}/derive-verdict` and `refuter_review.derive_verdict` can now read
the review's linked completed finding verification, or an explicitly supplied verification id, and
record a new refuter signal or deterministic proof-backed refuter verdict. The command is gated, so
dry requests return approval state instead of mutating review history. AI-driven, failed, or errored
verification outcomes are intentionally recorded as signal-only unless a human-approved review records
a verdict. `/settings/arsenal` now exposes queued-review controls to request the execution gate state
and derive a verdict from completed replay evidence. `refuter_signal` remains separate from
`refuter_verdict`; verdicts require deterministic replay, cryptographic, parser/protocol, or
human-approved-review basis, and recording a review cannot directly update findings, hypotheses,
proof state, severity, or gates. File-backed integrity ledgers exist at
`results/benchmark-runs/INTEGRITY_LEDGER.md` and `results/planner-evals/INTEGRITY_LEDGER.md`.
Durable review rows and their counterevidence bundles are now operator-visible after refresh, with
receipt-gated selected-step execution and verdict derivation. Operators can now append durable
signal-only counterevidence or an explicitly labeled human-approved verdict, including bounded
evidence-object/tool-receipt refs, observed behavior, and redacted notes. DONE phase 11 for explicit
integrity-signal intake: finding-delta and benchmark-win signals remain separate/report-only by
default, but an operator can opt in to durable signal-only `target`/`benchmark` review rows. Prior
subject reviews are deduplicated, and this path still executes no scanner and changes no finding,
proof state, severity, or gate.

**Implement:**
1. DONE phase 1: trigger refuter work for Critical/High findings with suspected or weak proof, AI Gate semantic-only
   hits, Model Intake metadata claims without operator trust anchors, new benchmark wins, unusually
   large finding deltas, deployment-gating findings, and parser output that would promote severity or
   proof state. Current implementation covers weak findings, AI Gate semantic/weak deterministic
   hits, Model Intake metadata trust claims, parser-promoted/degraded output, and deployment-gating
   unverified claims as a read-only work summary and can queue signal-only review rows from that
   summary. DONE phase 2: summary candidates now include
   bounded automation plans for minimal deterministic retest, AI Gate replay, Model Intake trust
   preview, and auth/principal/tenant/object context checks; queued review metadata preserves the
   same plan. DONE phase 3: plans now include counterevidence bundles with review questions, benign
   explanations to test, required evidence refs, and supported/weakened/refuted/inconclusive verdict
   paths. DONE phase 4: the refuter summary now emits report-only target-level `integrity_signals`
   for the `finding_delta_spike` trigger — a target whose latest web-DAST scan reports a finding
   count far above its own recent baseline median (`_finding_delta_refuter_signal`, conservative
   absolute+multiplier thresholds). These remain separate from `candidates` and are never queued by
   default; an explicit `include_integrity_signals=true` request can preserve them as signal-only
   target reviews, and they never mutate findings or proof state. DONE phase 5: the unreviewed weak-proof candidate count
   and the finding-delta integrity spikes are now surfaced as a `refuter-review-backlog` item in the
   dashboard `action_center` (`_build_dashboard_action_center`, best-effort), closing the loop from
   integrity signal to the productized operator decision flow (§1). DONE phase 6: benchmark scorecard
   win deltas now surface as report-only integrity signals when a latest scorecard improves sharply
   over its own recent history, so possible stale-fleet, contamination, or benchmark-fitting wins are
   reviewed without auto-queueing or mutating findings. DONE phase 7: the Command Arsenal UI renders
   durable review questions, benign explanations, required evidence refs, verdict paths, and selected
   automation steps, then routes execution and verdict derivation through the approval-receipt gate.
   DONE phase 9: verdict badges are styled by both verdict and `verdict_basis`; signal-only records
   remain neutral and cannot visually inherit proof-backed green treatment.
2. DONE: refuter behavior plans how to rerun the minimal reproducer, test benign
   explanations, verify auth context/principal/tenant/object ownership, check request freshness, and
   attach counterevidence when a claim weakens. DONE phase 2: a gated executor now queues the
   smallest existing deterministic/AI replay primitive for the refuter review and records execution
   metadata/audit without changing product truth. DONE phase 3: completed finding verifications can
   derive new refuter signal/verdict rows; deterministic outcomes can become proof-backed refuter
   verdicts, while AI-driven outcomes stay signal-only unless reviewed by a human. DONE phase 4:
   durable analyst counterevidence attachment/annotation uses
   the existing record-only refuter route; signal notes stay `signal_only`, while human verdict mode
   is explicitly stamped `human_approved_review` and never mutates findings or deployment gates.
3. DONE phase 1: separate `refuter_signal` from `refuter_verdict`. Signals can
   weaken/support/question a claim. Verdicts are accepted only when backed by deterministic replay,
   cryptographic evidence, parser/protocol evidence, or explicitly labeled human-approved review
   policy; review records still do not directly mutate product truth.
4. DONE phase 1: add integrity ledgers for benchmark and planner methodology: stale/non-uniform worker runs,
   benchmark fitting, hidden contamination, hardcoded target facts, phantom tool assumptions, source
   hints counted as runtime proof, AI prose counted as evidence, and planner safety failures. DONE
   phase 10: a release test inspects executable discovery/prioritization constants and rejects known
   benchmark hostnames or service-mount answer strings while allowing docs, fixtures, and benchmark
   tooling to name their targets explicitly.
5. DONE phase 1: store integrity records close to the artifacts they correct, for example
   `results/benchmark-runs/INTEGRITY_LEDGER.md` and `results/planner-evals/INTEGRITY_LEDGER.md`, then
   add API/UI summaries only after the file-backed discipline is stable.

**Done when:** a benchmark win, semantic AI hit, metadata trust claim, or weak High/Critical can be
challenged and corrected without deleting history, and corrections are visible in the same evidence
and deployment-gate story as the original claim.

### 10. Check-registry execution migration + proof contracts per family
**Status: REGISTRY DISPATCH MIGRATION DONE FOR RUNNABLE FAMILIES; HIGH-RISK UNIMPLEMENTED FAMILIES FAIL-CLOSED.** `api/check_registry.py` (`CheckFamilySpec`) is the family contract for API
validation and ASM scheduling and now carries `requires_auth_states` / `requires_credentials` /
`risk_level` / `runnable` / `telemetry_schema` / `proof_contract` / `severity_rules`. Scanner
`build_report()` now emits a registry-derived `scanner_execution_plan` in scan config, active
telemetry, and metadata. That plan now includes a registry-derived summary rollup with enabled and
skipped family lists, skip reason counts, enabled risk/phase counts, runnable-enabled counts, and
per-enabled-family proof contracts. It now also records dispatch adapter counts, requested blocked
families, per-family `requested`/`blocked_by`/`dispatch_adapter` metadata, and fail-closes explicitly
requested registered-but-unrunnable families such as `lfi`/`rce`/`ssrf`. SQLi/XSS active dispatch
gates derive from that plan before entering the legacy module loops. Focused auth/BOLA dispatch now
also treats the registry plan as authoritative for explicit `check_family` requests while preserving
legacy broad smart-scan behavior when no family was requested. The smart active SQLi/XSS loop now
derives its family dispatch order from registry runnable parallel families with a scanner-local
fallback. The phase-4 mass-assignment executor is now registry-backed with its effect-based proof and
severity contract, explicit legacy flag activation, and `legacy_phase4_mass_assignment` dispatch
adapter; task creation now reads only the registry decision and fails closed when the plan/family is
missing instead of rechecking the legacy input that produced the plan. Basic and comprehensive
JWT checks are likewise registered with token-source/mutation/acceptance-delta proof requirements and
the `legacy_advanced_jwt` adapter; their dispatch also has no permissive legacy fallback. Broad
Smart/full/aggressive scans add JWT to their registry scope,
while focused family scans continue to omit it. Nuclei is now a runnable template family with the
`legacy_nuclei_template` adapter; task creation reads the registry plan, so standard/deep/full/smart
profiles dispatch templates while quick, public-only, focused-endpoint, and zero-rediscovery scopes
retain explicit skip metadata instead of starting the legacy executor. Focused scanner aliases,
finding attribution, remediation, auth-state requirements, telemetry flags, and dispatch-adapter
names now derive from that same registry instead of a second scanner-local registry. Passive
header/config finding emission runs through a generic phase dispatcher and records completed,
failed, or missing-adapter state in `scanner_execution_receipts`. Every runnable scanner task family
now passes through an independent scanner-side adapter contract; decisions are attached to reports
and fail closed on missing, blocked, unrunnable, or mismatched adapters. Detector algorithms remain
inside their specialized modules. Planned `lfi`/`rce`/`ssrf` families remain explicitly
unrunnable: response validators alone are not bounded discovery executors and cannot justify claiming
those families were dispatched.

**Implement:** make `lfi`/`rce`/`ssrf` runnable only when bounded executors and their deterministic
proof contracts exist; their current fail-closed state is intentional, not unfinished dispatch.
DONE phase 3 for mass-assignment registration and dispatch gating without expanding ASM focus or
changing explicit `--mass-assignment-testing` behavior.
DONE phase 4 for JWT basic/comprehensive task gating without exposing JWT as an ASM focus family.
DONE phase 5 for Nuclei task gating without exposing templates as an ASM endpoint-test family.
DONE phase 6 for canonical focused-family metadata and registry-driven passive report dispatch.
DONE phase 7 for adapter-validated, reportable task dispatch decisions across SQLi, XSS, Nuclei,
JWT, mass assignment, focused auth, and BOLA. Specialized detector internals stay module-owned;
the registry and scanner adapter contract own whether those modules may run.

**Done when:** adding a check family is a registry entry plus module integration, not edits scattered
through `build_report`.

### 11. Planner evaluation and local-agent planning boundaries
**Status: DRY-RUN PHASE 1 + STRICT PARSER VALIDATION + FIXTURE-GATED CODEX ADAPTER DONE.** Local-agent
planning should remain dry-run only until the Command Arsenal, mandatory receipt enforcement,
context packs, parser/output validation, and planner evals are stable. T3MP3ST's local-agent pattern
is useful as a planner harness, not as raw execution power.

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
4. DONE phase 1: local-agent-labeled deterministic dry-run planning consumes saved context packs and
   persists server-validated `OperationPlan` rows. DONE phase 2: the bounded host-side Codex adapter
   can propose exact JSON only after a current passing fixture scorecard.
5. DONE phase 2: strip provider API-key environment variables when spawning local planners. Do not pass secrets,
   cookies, bearer tokens, private keys, raw transcripts, or raw request/response bodies by default.
6. Local agents may propose `OperationPlan` JSON and summarize redacted evidence. They may not execute
   arbitrary shell commands, broaden scope, increase risk tier, bypass confirmations, or mark findings
   verified.
7. DONE: dry-run APIs now include `GET /agents/local` for capability matrix,
   `POST /agents/local/test` for harmless bounded capability/version ping, and
   `POST /agents/local/plan` for deterministic context-pack-to-`OperationPlan` creation, plus the
   fixture-gated Codex prompt adapter. `/ai/ops/route` and gated Arsenal handlers remain the only
   execution gateways; the adapter itself cannot execute actions.
8. DONE phase 1: reject ambiguous planner output through `POST /agents/local/plan/parse` /
   `local_agent.parse_plan`. Candidate local-agent output must be a single exact JSON
   `OperationPlan` object bound to the supplied context-pack hash and target scope; validation fails
   closed on unknown commands, missing risk tiers, catalog risk mismatch, commands outside the
   context pack, widened scope, hidden state-changing action requests, missing confirmations, and
   unbounded parameters. The parser does not persist candidate plans, spawn local agents, queue work,
   or enable execution.
9. DONE phase 1: add `POST /agents/local/test` only as a harmless capability/version ping with
   timeout/output caps, environment stripping, no secrets, no prompt, no planner execution, no target
   state mutation, and no queued scanner work.
10. DONE phase 2: before any real planner adapter can persist a dry-run plan, run fixed evals for "keep target
    covered", "run BOLA", "SQLi only", production AI Gate deep testing, Model Intake trust, stale
    workers, out-of-scope prompt injection, missing evidence, planned/unrunnable families, production
    RCE/lab-only gating, and missing second-user auth.
11. DONE phase 2: store planner version/fingerprint and context-pack hash with every generated plan. Detect auth
    state by binary/status/artifact existence only; never read auth artifact contents.
12. DONE phase 2: strip provider API-key environment variables when spawning local planners. Bound working
    directory, timeout, prompt bytes, output bytes, retry count, and network behavior to the safest
    mode the specific adapter can prove.

Phase 2 adds the host-side `scripts/local_planner_adapter.py` Codex adapter. `evaluate` must produce
a passing scorecard for every fixed fixture, and the scorecard is bound to the fixture hash, adapter
version, and detected Codex version/path fingerprint. `plan` fails closed on a missing, failing, or
stale scorecard; runs Codex once in an empty temporary workdir with a read-only sandbox, ephemeral
session, bounded prompt/output/timeout, zero retries, stripped provider/secret environment variables,
and shell, unified-exec, browser, app, plugin, computer, image, and multi-agent features disabled;
then submits exact JSON to `/agents/local/plan/parse`. Only an accepted candidate is sent to the
existing dry-run `/arsenal/plans` persistence route. The adapter never calls an execution route,
does not read auth artifact contents, and records its controls, planner fingerprint, context hash,
and eval scorecard hash in `planner` metadata.

**Done when:** a local or hosted planner can produce a validated dry-run `OperationPlan` from a
bounded context pack, fail the unsafe fixtures, and route every proposed state-changing action through
the same Command Arsenal, `ActionScopeGuard`, approval receipts, and existing API handlers.

### 12. Source-informed DAST, MCP, and new-tool boundaries
**Status: SOURCE-HINT INGEST + READ-ONLY MCP DONE; NEW OFFENSIVE TOOLS DEFERRED.** T3MP3ST's
source-ingest and MCP ideas are useful only after the mission, command, scope, hypothesis, evidence,
and receipt layers exist. Bounded source/spec/package hints now enrich hypotheses through
`/arsenal/hypotheses/source-ingest` without creating findings, queueing scans, or satisfying runtime
proof. `scripts/shakerscan_mcp.py` is now a thin stdio adapter over the REST Command Arsenal. New external tools should remain
`catalog_only` until narrow adapters, receipts, parsers, proof contracts, and safety gates are real.

**Implementation record and non-goals:**
1. DONE phase 1: add bounded source/spec/package hint ingest for operator-provided route,
   OpenAPI/Swagger, GraphQL, package, frontend route, server route, IaC, and AI-tool facts. DONE
   phase 2: `/arsenal/hypotheses/source-ingest` now accepts bounded file descriptors with max file
   count, max file size, ignored-path, and parse-timeout controls, extracts OpenAPI JSON operations
   and common backend route declarations into source hints, and still routes everything through
   runtime-proof-required hypotheses only.
2. Source-derived outputs are graph facts, endpoint/body-shape hints, auth/principal hints, Model
   Intake artifact hints, and hypotheses for BOLA/BFLA, mass assignment, dangerous upload, SSRF sink,
   file path parameter, template sink, and risky AI tool endpoint. They are not verified findings.
3. DONE: repository file count, file size, ignored paths, timeout, secret redaction, and bounded
   source metadata retention are enforced before source hints become hypotheses.
4. DONE phase 1: read-only MCP was added only after REST Command Arsenal stabilized. The adapter
   exposes a fixed mapping to existing REST commands, revalidates the live catalog before listings
   and calls, and dispatches through `/arsenal/execute`; it cannot bypass `ActionScopeGuard`, policy
   profiles, approval receipts, feature flags, or deployment gates.
5. DONE phase 1: state-changing MCP commands remain unrepresentable. Read-only MCP exposes targets,
   ASM gaps, findings, content-free evidence manifests, campaign timeline, saved dry-run plans, and
   tool status. Calls preserve Command Arsenal audit rows without exposing scan/retest/replay/policy
   mutation commands.
6. Keep future offensive tools in a catalog-only appendix until existing tools produce receipts and
   parser/proof contracts. Tool count is not a product metric.
7. Source-derived secrets must be redacted under the same evidence-retention policy as runtime
   evidence. Source-derived routes may improve the application graph and hypothesis queue, but source
   text alone must never satisfy a runtime proof contract.
8. DONE phase 1: `./scanner.sh mcp` starts a bounded stdio server with request/response caps,
   no-redirect REST calls, loopback-only API origins by default, exact input schemas, and live
   status/risk/method drift checks. State-changing MCP remains disabled by design; any future phase
   must require scope receipt, dry-run preview, approval token or UI confirmation, and durable audit
   records through the same Arsenal route.
9. Source-derived secrets, credentials, private keys, and tokens must be redacted under the same
   evidence-retention policy used for runtime artifacts, and source-derived route facts must never
   satisfy runtime proof contracts.

**Done when:** source/code hints improve worklists and hypotheses without creating source-only
verified findings, and MCP/new-tool adapters cannot bypass the same command/scope/approval/evidence
contracts used by UI, REST, scheduler, AI Ops Router, and local-agent planners.

### 13. Operational / inventory-hygiene follow-ups
**Status: PHASE 1 DONE (migrated from the now-archived asm-parallel-improvement-plan).** The
2026-06-17 live-validation items now have phase 1 closures: A1/A3/A2 reachability + soft-404 +
`gone` retirement, P1/P2/P3/P4/P5, bounded synthetic endpoint generation, API-scaled worker
restart/rebuild closure, and all-worker log aggregation.

- **DONE phase 1: Cap synthetic endpoint permutation (was A4).** Common synthetic active endpoints
  are now generated only when API/reachability signal exists (or an operator explicitly forces
  thorough params), and the pre-reachability fallback burst is capped relative to active budget.
  BOLA collection-to-resource URL synthesis also has a finite output cap so resource permutations
  cannot dominate the worklist before soft-404/reachability filtering.
- **DONE phase 1: Worker restart/rebuild closure.** `_refuse_stale_job_if_needed` fail-closes stale
  jobs, and `./scanner.sh restart` now preserves the running worker count when auto-sized,
  removes scanner worker containers left outside Compose, and recreates the fleet. Scanner/all
  `./scanner.sh rebuild` records local-build mode, removes stale stopped workers, and recreates any
  running worker fleet from the rebuilt image without requiring manual scale down/up.
- **DONE phase 1: All-worker log aggregation (was P6).** `scanner.sh logs worker` / `workers`
  enumerates scanner worker containers with Docker, prefixes each line by container name, supports
  follow mode, and falls back to Compose worker logs if no matching containers exist.

### 14. Final verification requirements
Every implementation increment above must include its own test slice:

- **DONE phase 15: Active parameter prioritization for recall.** Smart SQLi and Smart XSS now
  value-sort query/body parameters before applying per-endpoint param budgets, so tight runs spend
  attempts on generic high-yield bug surfaces first (search/query/login/ID/coupon/product/content
  fields) and push pagination/tracking/cache noise later. Regression coverage includes a
  budget-constrained POST-body reflected-XSS case where the vulnerable `message` parameter appears
  after low-value fields in discovery order.
- **DONE phase 15 UI visibility:** scan reports now show a capped Active Attempt Ledger from
  `active_checks.endpoint_attempts`, including endpoint, family, completed/expected params, status,
  prioritized parameter names, skip/budget reason, and SQLi technique coverage where present, so
  operators can see where active budget was spent without opening raw JSON.

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
