# ShakerScan — Reconciled Architecture & Roadmap Review

**Mode:** REVIEW_AND_PLAN (no code changed in the review run).
**As-of:** ShakerScan HEAD `b8eda2c` (2026-07-10); T3MP3ST `main` HEAD `ae32cf5` (unchanged since prior review).
**Method:** 5 read-only grounding agents + direct verification. Documentation treated as context; code + reproducible tests + live artifacts win.

> Source-of-truth note: every "implemented/default/authoritative/tested" claim below was checked against the current code path, its tests, and (where relevant) a committed benchmark artifact. Contradictions are reported, not smoothed over.

## 1. Executive verdict
The deferred **direction is correct and should be kept**: Continuous ASM as the operating loop; authenticated, stateful, proof-backed testing of owned apps/APIs as the wedge; *AI proposes / deterministic contracts decide*; parallelism as substrate, not a quality claim. The safety invariants are right and **largely already enforced in code** (deterministic proof types, `ai_verdict` advisory-only, distinct-principal BOLA, gated arsenal, fail-closed planner health).

Four things dominate the directive's amendments:
1. **Auth is increment 0 and is currently unproven-in-practice.** All 17 committed scorecards are `two_user:False`; the one single-user run scored recall 0.0 (substitution pitfall); the one two-principal run found zero BOLA. "Run the authenticated crAPI baseline now" presumes a capability that has never produced a green artifact.
2. **"Registry-owned execution" is overclaimed.** The registry is authoritative for the *enable decision* of 9 families, but execution is legacy wrappers and ≥3 legacy paths still enable registered-family coverage outside the plan (notably `bola_testing → check_bola`).
3. **Do not build the LLM control plane (10 schemas) yet.** It is the exact "overbuild the control plane while detectors are unproven" danger the directive itself names. Gate it behind detector acceptance.
4. **The benchmark "PASS" is honest-in-mechanism but not a trustworthy status claim** — thin (exactly 6/6), anonymous, on fleet `ddc6173b` (NOT the current `bc6c357`), no integrity-ledger entry.

## 2. Status preflight
Maturity levels: documented / implemented / unit-tested / stack-tested / benchmark-accepted / live-soaked.

| Capability | Verified status | Max maturity | Discrepancy / consequence |
|---|---|---|---|
| Cooperative cancellation (`87591e5`) | Wired to **only 3 modules** (phase-4, active sqli/xss, access-control); subprocess tools/browser/discovery/nuclei-wave NOT wired | implemented + unit | "No request after observed cancellation" holds **module-scoped only**; not a global gate |
| Registry authority (`25052d4`) | Authoritative for the **enable decision** of 9 runnable families; `legacy_default` removed; `scanner_enabled` veto = mechanism-without-policy (no family sets False) | implemented + unit | Execution = legacy wrappers; `bola_testing→check_bola` + advanced_scan nosql + endpoint-scoped checks enable registered-family coverage **outside the plan**; "Wave 2 complete" overclaims the strict bar |
| Adapter identity validation | Fail-closed name-binding map + drift tests; **no** `AdapterInvocationSpec`; coarse receipts `{blocked/skipped/cancelled/failed/completed}` | implemented + unit | No binary_present→…→evidence_bound ladder; new adapter fails closed (can't inherit generic invocation — good) |
| Versioned attempt schemas | sqli/xss/bola/auth `active_endpoint_attempt_v1`; mass_assignment + jwt versioned + normalizer-enforced; recon/nuclei/headers unversioned | implemented + unit | `proof_contract`/`severity_rules` **declarative only, not enforced**; the 4 active families skip the shared normalizer; directive's "wait for versioned schemas" precondition is **obsolete** |
| Request accounting | `RequestMeter` + `request_meter_v1` receipt; browser/httpx/aiohttp/urllib **exact**, curl **adapter_reported**, nuclei/sqlmap/dalfox/ffuf **unknown** (subprocess-opaque); default `compatibility` = observe-only | implemented + unit | Honest `fully_metered` signal ships → the metering_quality enum is a **formalization, not a build**; a hard request cap is impossible while subprocess tools run |
| Dynamic/static Full Coverage | **Dynamic IS the shipped default** (`parallel_scan.py:1053`, test-locked) | implemented + unit | Coverage crit/high **recall gap persists in BOTH modes** (zero_rediscovery + global-check fragmentation, orthogonal to allocation); single Smart scan remains the recall benchmark |
| Parent/ASM rollup | Dynamic default **agrees** with `/asm/gaps` (mark_tested path); **static** merge doesn't promote `test_status` | implemented; not test-guarded | Static fallback: parent-says-tested / ASM-says-gap divergence → re-tests covered endpoints |
| **Auth/BOLA detector acceptance** | **PLUMBED but UNPROVEN**; propagation to 5 tools correct; substitution pitfall confirmed (single auth replaces anon → recall 0.0 artifact); 2-principal differential sound but the one 2-principal run found **zero** BOLA (stale scanner); all 17 scorecards `two_user:False` | **NOT accepted** | **Increment 0** — no green authed artifact exists |
| UI component coverage | Deferred UI browser acceptance recorded (`b8eda2c`); E2E claims disputed by deferred-work-plan ("could not run, no pass inferred") | documented; partial | UI must never infer completed/clean/covered from display strings |
| Multi-node prerequisites | Single Redis+Postgres; **fencing tokens, stale-owner-write prevention, partition/clock-skew tests, brokered secrets, per-node approval revalidation = ABSENT**; leases/heartbeats/reaper present | documented (Proposed/RFC) | Correctly deferred; fencing + stale-owner-write are the same missing mechanism and the load-bearing blocker |
| Local planner health/fallback | Fail-closed eval gate (`require_current_scorecard`), planner fingerprint, read-only sandbox, no execution authority | implemented + unit | Solid; matches T3MP3ST live-vs-connected lesson |
| Tool invocation contracts | Coarse receipts only; arsenal `ToolAdapterSpec` version-probes only (not the run-time invocation contract) | implemented + unit | `AdapterInvocationSpec` is net-new |
| Benchmark PASS honesty | Honest-in-mechanism (real `/metrics` detection; no gate-weakening, no fitting, no faked auth) but **thin (6/6), anonymous, fleet `ddc6173b`≠current `bc6c357`, no ledger entry** | benchmark (non-current fleet) | Not a trustworthy "current-fleet passes" claim |

## 3. Latest T3MP3ST findings
**HEAD `ae32cf5` (2026-07-09) = the prior review's commit; `main` has not advanced.** TS/Node framework. The tip's themes — `353ea33` real invocations; the `f502bfb`/`fb0feb0`/`49d0827`/`73d888f`/`d9a4c47` cluster (live-vs-connected model health + failure propagation); `23713fa`/`75b7ca0`/`e53c61e` (idle vs hard deadline); `808ce11`/`5e40e60` (provider contract) — are exactly those the directive enumerates, and ShakerScan has **already largely absorbed them** (planner fingerprint/health fail-closed; `scanner_execution_receipts`; typed `RegistryPhaseOutcome`). **Nothing new to borrow.** Take the two still-open ideas — a formal `AdapterInvocationSpec` (+ spec-hash) and a typed `ResourceRef` union — and stop treating "compare to latest T3MP3ST" as a recurring input. ShakerScan is ahead of T3MP3ST on the deterministic proof/evidence/policy side.

## 4. Architecture gaps (by risk × dependency)
1. **Auth acceptance unproven + substitution pitfall** (blocks every recall claim) — `scanner.py:5657-5663`.
2. **Registry gates but does not own execution; ≥3 legacy paths bypass the plan** — `bola_testing→check_bola` (`scanner.py:6294`); advanced_scan nosql (`scanner.py:5103-5117`); endpoint-scoped exposure/auth (`scanner.py:12156`).
3. **Cancellation coverage partial** — 3 modules; subprocess/browser/discovery keep firing until SIGKILL.
4. **Metering honest but enforcement opt-in + subprocess-opaque** — no honest hard request cap today.
5. **proof_contract/severity_rules declarative, not enforced** — registry publishes contracts nothing validates against.
6. **Static coverage merge ≠ ASM `test_status`** (dynamic default is fine).
7. **Benchmark integrity hygiene** — no ledger entry for the flip; evidence-mislabel; COMPAT-alias overclaim; pass on non-current fleet.
8. **Multi-node** — no fencing / stale-owner-write guard (correctly deferred).

## 5. Target architecture (ownership per boundary)
```
 inventory/recon ─▶ resource/principal GRAPH ─▶ ObservationPack (versioned, redacted, omission-manifest)
        [ShakerScan owns]                                    │
                                                              ▼
                                    LLM CAMPAIGN CONTROLLER  (proposes only)
                                    emits ProbeExperimentSpec + DecisionEpisode
                                                              │
                                                              ▼
   DETERMINISTIC POLICY SELECTOR — scope · approval · risk · budget · resource-kind   [owns, DECIDES]
                                                              ▼
   PROBE COMPILER — replay contract · payload class · baseline/control/treatment · auth/workflow state  [owns]
                                                              ▼
   FAMILY EXECUTOR (registry adapter) — attempts + tool receipts + RequestMeter   [owns]
                                                              ▼
   PROOF EVALUATOR — family proof_contract (ENFORCED) → proof_state   [owns; sole minter of "verified"]
                                                              ▼
   EVIDENCE INSTANCE ─▶ CANONICAL FINDING / REFUTER / DEPLOYMENT GATE ─▶ observation delta ─▶ (loop)
```
Invariant: **the LLM chooses which question to ask; the deterministic engine decides how to ask it and what may count as proof.** No LLM output is ever a finding, proof, or scope/risk change.

## 6. Contract definitions (reconciled to existing ShakerScan types; ✎ = new, ✔ = exists)
- **AdapterInvocationSpec** — extend `CheckFamilySpec` (`check_registry.py:16`) + `SCANNER_REGISTRY_ADAPTER_CONTRACTS`. ✔ dispatch_adapter, telemetry_schema, proof_contract, severity_rules, scanner_options, requires_auth_states/credentials, risk_level, allowed_presets. ✎ accepted_resource_kinds, argv_builder_version, interaction_mode, output_contract, required_safe_flags, cancellation_contract, parser_schema_version, request_metering_quality, smoke_fixture_id, invocation_spec_hash.
- **ResourceRef** (✎ tagged union) — WebTargetRef | EndpointRef | RepositoryRef | ArtifactRef | AISurfaceRef | EvidenceRef (✔ evidence_instances) | InteractiveSessionRef (✔ sessions). Each adapter declares accepted kinds; policy rejects URL-in-repo-slot etc.
- **PlannerBackendHealth** — mostly ✔ (planner fingerprint + `require_current_scorecard` + health_state). ✎ formalize: configured/authenticated/process_reachable/schema_probe_passed/tool_contract_probe_passed, last_live_probe_at, health_expires_at, idle vs hard deadline, failure_reason.
- **ObservationPack** (✎) — pack_version, context_hash, surface_map (✔ graph), current_hypotheses (✔), attempt_deltas (✔ attempt_telemetry), proof_deltas (✔ evidence), blocked_preconditions, request_budget_state (✔ request_meter), decision_budget_state (✎), available_action_schemas (✔ command catalog), evidence_refs, inclusion_manifest{included, omitted_counts_by_kind, omission_reasons, truncated, original_hashes}. Preserve the full surface_map even when evidence is sampled.
- **ProbeExperimentSpec** (✎) — experiment_id, hypothesis_id (✔), family (✔ registry), endpoint_contract_id (✔), principal_context, workflow_context, mutation_point{location, param/body path}, technique_class, control_strategy, expected_observation, falsify_if, benign_explanations_to_test, max_requests/seconds/response_bytes, risk_tier (✔), required_confirmations (✔ approval).
- **ProbeExecutionPlan** (✎, compiler output) — resolved replay contract, approved payload class, preserved sibling fields, baseline/control/treatment requests, applied auth/workflow state, scope/approval/risk/budget checks passed, metering_quality.
- **ExperimentResult** (✎) — attempts (✔ attempt_telemetry), differential, proof_state (✔), evidence_instance_ref (✔), budget spent, metering_quality, cancellation state.
- **DecisionEpisode** (✎; align `campaign_actions`/`command_results`) — episode_id, campaign_id (✔), hypothesis_id (✔), observation_pack_hash, planner_backend_receipt_id, proposed/selected/rejected actions + reasons, expected_information_gain, falsify_if, policy_decision (✔), reserved decision/request budgets, result_delta{graph/coverage/proof/blocker}, pivot/stop reason. **No chain-of-thought.**
- **RequestBudget** — ✔ `request_meter` snapshot; ✎ add metering_quality{exact/adapter_reported/reserved_upper_bound/estimated/unknown} + budget_enforcement{hard/soft/unavailable} per adapter.
- **DecisionBudget** (✎, net-new) — planner_calls, input/output tokens, model_cost, context_bytes, candidate_actions_per_turn, no_progress_episodes, same_hypothesis_variants, planning_wall_clock. Kept **separate** from RequestBudget.

## 7. Revised roadmap (dependency-ordered; single path)
| # | Increment | Prereq | Deliverable | Acceptance artifact | Fallback | Excluded |
|---|---|---|---|---|---|---|
| 0 | **Fix + PROVE auth (2-principal + anon-additive)** | — | working authed 2-user scan; substitution fixed | crAPI + Juice scorecards: `two_user:True`, ≥1 **verified** BOLA, anon baseline retained | anon-only scoring | any LLM work |
| 1 | Authed crAPI/Juice baseline (3 boundaries) | 0 | fingerprint-current authed scorecards + ledger entries | committed scorecards on current fleet | — | — |
| 2 | Invocation contracts + typed ResourceRef (vertical slices) | 1 | `AdapterInvocationSpec` + resource-kind isolation + no-broken-invocation gate | new receipt states + tests | legacy dispatch | swarm |
| 3 | Enforce proof_contract + close registry execution bypasses | 2 | proof/severity gated; `bola_testing→check_bola` folded into registry | parity test: no registered-family finding outside plan | legacy | — |
| 4 | Shadow request accounting (metering_quality) + cancellation coverage | 1 | per-adapter metering tier; cancel wired engine-wide | "no request after observed cancel" soak | observe-only | hard cap |
| 5 | ObservationPack + DecisionEpisode contracts | 3,4 | versioned packs + episodes (no planner yet) | schema + redaction tests | — | execution authority |
| 6 | **Shadow LLM campaign controller (no authority)** | 5 | planner proposes; scheduler executes | shadow eval report (§9) | disable planner | any live action |
| 7 | Hard budget enforcement where metering provable | 4 | enforce mode where exact/upper-bound | enforcement soak | soft | subprocess hard cap |
| 8 | Component/UI contract harness | 3 | schedule/skip/cancel/rollup contracts | UI tests | — | — |
| 9 | Dynamic/static parity + cancellation soak | 4,8 | quantitative soak (§10) | soak report | static rollback | — |
| 10 | One-step gated LLM action selection | 6,9 | planner picks 1 action from approved set | gated-action soak | shadow | multi-step autonomy |
| 11 | Reviewed StrategyCard memory | 10 | abstract, expiring, artifact-linked | review process | none | per-run auto-promote |
| 12 | Multi-node (fencing + idempotency) | 9 | fencing tokens + stale-owner-write guard | partition/skew tests | single-node | production 2-node before gates green |

## 8. First three increments (bounded, implementation-ready)
**Increment 0 — Prove authenticated 2-principal scanning.**
- *Why now:* every recall claim depends on it; it's the only thing with zero green artifacts.
- *Contracts:* benchmark harness auth path; scan auth-state recording (`scanner.py:5657-5663`); `auth_split` (`parallel_scan.py:1427`).
- *Files:* `scripts/benchmark_targets.py` (`--auth`, host bridge `1fb3bac`, mint retry `c146bdf`), `tests/fixtures/benchmarks/crapi.yaml` + `juice_shop.yaml`, `scanner.py` auth-state, `access_control_checks.py` (BOLA differential).
- *Migration/compat:* none (harness + fixtures); default scan behavior unchanged.
- *Fix the pitfall:* make an authed benchmark run **additive** (anon baseline + authed) via `auth_split` fixture opt-in OR paired anon+authed scorecards. Do **not** make single-auth additive globally (behavior change).
- *Failure modes:* host.docker.internal unreachable from host (bridge must be proven), token mint flake, same-account tokens (bd1a5d5 guard).
- *Tests:* unit for auth-state additivity + distinct-identity; integration: `benchmark_targets.py --auth crapi` on current HEAD.
- *Artifact (REQUIRED):* crAPI scorecard `two_user:True`, `two_principal_observed:true`, ≥1 verified BOLA, on current fleet, + ledger entry.
- *Rollback:* keep anon-only scoring path. *Non-goals:* registry refactor, LLM, UI.

**Increment 1 — Fingerprint-current authed baseline at 3 boundaries** (before refactor / after each family migration / at soak). Deliverable: committed authed scorecards + honest ledger entries; separates "is the detector acceptable" from "did orchestration preserve it." Non-goal: any control-plane change.

**Increment 2 — AdapterInvocationSpec + typed ResourceRef (vertical slice: passive header/config first, then template).** Extend `CheckFamilySpec`; add receipt states binary_present→…→evidence_bound; add `test:no-broken-invocations`, `test:resource-kind-isolation`. Migration: additive registry fields. Fallback: legacy dispatch stays. Non-goal: planner, multi-node.

## 9. Shadow-planner evaluation plan
No execution authority. The scheduler runs normally; the planner receives the same pre-action ObservationPack and proposes what it *would* have done. Fixtures: recorded ObservationPacks from real crAPI/Juice campaigns (versioned, hashed). Metrics: action-agreement vs the deterministic scheduler; schema-valid proposal rate; policy-rejection rate by reason; duplicate-action rate; expected-vs-actual information gain; predicted-vs-actual request cost; targeted proof yield; risk-tier accuracy; missing-precondition accuracy; cross-run variance from the same recorded pack. Promotion gate: schema-valid ≥ threshold, duplicate rate below bound, variance bounded, **zero** policy-invariant proposals that would have escalated risk/scope — only then allow one-step gated selection from an already-approved set.

## 10. Quantitative release gates
Zero scope violations · zero hard-budget violations (hard-enforced adapters) · **zero AI-only or source-only verified findings** · **no request after observed cooperative cancellation (engine-wide)** · every planner action tied to context_hash + backend receipt · every runnable adapter covered by an invocation-contract test · no worse benchmark precision · no worse required-family recall vs the increment-1 baseline · no parent/ASM coverage disagreement · no orphan leases past recovery deadline · static fallback functional · better proof yield / 100 requests (or lower requests/proof) · lower median time-to-first-deterministic-proof · bounded duplicate/no-progress decision rate. Several of these are **unmeasurable until increment 1 sets the baseline** — that is why auth + baseline lead.

## 11. Documentation corrections
- `AI_REDTEAM_MODEL_INTAKE_FIX_PLAN.md`: reconcile the top-half ✅ (R1/R4/R5/R6) with the stale "Net"/priority/DoD tail still marking them 🔴 (L54-72, L346, L421-436). The two halves are mutually exclusive.
- `continuous-asm-architecture.md:518`: "static remains the shipped default" is **stale** — code defaults to dynamic (`parallel_scan.py:1053`). Reword to "static = rollback/fallback; dynamic is default."
- `E2E_TEST_PLAN.md`: define or renumber undefined rows **D-5**, **MI-7**; add an "older-fleet, not rerun on `bc6c357`" disclaimer to the "12/12 passes" line (contradicts deferred-work "no pass inferred").
- `proposed-next-steps.md:3`: qualify "implementation-complete" → "code-complete; live detector acceptance + Wave-6 soak open." Reword "current-fleet Juice scorecard passes" → "most recent scorecard (fleet `ddc6173b`) passes at 0.67; not re-run on current `bc6c357`."
- `INTEGRITY_LEDGER.md`: **add the missing FAIL→PASS entry** (scans `148dd7f2`/`330f5679`, fleet `ddc6173b`, the 6th verified finding, 3 still-missed: xss-reflected/bfla-users/nosqli-reviews); fix the `exposed-ftp-listing` evidence-mislabel; drop the zero-backing `broken_access_control` COMPAT-alias.
- **Doc hierarchy:** Tier1 status = proposed-next-steps + E2E_TEST_PLAN (after fixes); Tier2 roadmap = deferred-work-plan; Tier3 architecture = continuous-asm + parallel-scan + multi-node; Tier4 ledger = t3mp3st-adoption; Tier5 archive = AI_REDTEAM (stale tail).

## 12. Risks & rejected alternatives
- **Raw-agent/shell execution, LLM-produced findings, product commands like `run_sqlmap`** — rejected: violate the no-AI-only-proof + gated-arsenal invariants already enforced.
- **Challenge-mode persistence ("continue while iterations remain")** — rejected: use an obligation-completion stop rule; the BOLA deadline regression (`7847736`) shows how time/iteration heuristics silently drop coverage.
- **Broad autonomous swarm as the next milestone** — rejected: prefer one planner + deterministic validators + optional critic; shadow-first.
- **Premature multi-node** — rejected: no fencing / stale-owner-write guard; a reaped-then-returning worker clobbers `test_status` today.
- **Building the 10 LLM schemas now** — rejected: overbuilds the control plane while detectors are unproven (the directive's own #1 danger).

## 13. Final recommendation
- **Single best next increment:** fix + prove authenticated 2-principal scanning (increment 0) — additive anon baseline + a verified BOLA.
- **Benchmark artifact to produce immediately:** a fingerprint-current **authenticated crAPI scorecard** with `two_user:True`, `two_principal_observed:true`, ≥1 verified BOLA — the first-ever green authed datapoint.
- **Feature that must stay deferred:** the LLM campaign controller with any execution authority (and the 10 planner schemas) — behind detector acceptance + shadow eval.
- **Top product metric for the next cycle:** verified proofs per 100 target requests (with the honest `metering_quality` denominator), plus required-family recall on the authed baseline.

---

## Appendix — Immediate execution order
1. Save this report (done — this file).
2. Apply the Section 11 documentation/ledger corrections (low-risk, no scanner code) and reclassify docs per the Tier1–5 hierarchy.
3. Run `benchmark_targets.py --auth crapi` on current HEAD to size increment 0 (the auth-bootstrap fixes landed after the last committed scorecard, so it is unknown whether authed 2-principal scanning already works).
4. Implement increment 0 (fix the substitution pitfall + produce the first green authed scorecard) based on (3).
5. Defer the broad code-fix sweep (BOLA deadline regression `7847736`, arsenal bound gap) — fold in opportunistically.

*Grounded by read-only agent audits of: auth/BOLA propagation, request accounting/budgets, dynamic-vs-static + multi-node primitives, invocation contracts + attempt schemas + registry authority, and documentation contradictions. Verified directly: HEAD `b8eda2c`, coverage default = dynamic, single-auth substitution, scorecard fleet fingerprint, T3MP3ST pinned at `ae32cf5`.*
