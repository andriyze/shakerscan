# ShakerScan — Reconciled Architecture & Roadmap Review

**Mode:** REVIEW_AND_PLAN (no code changed in the review run).
**As-of:** ShakerScan HEAD `87ee530` (2026-07-11), including the current-fleet authenticated crAPI
scorecard from scan `85d3bafb`; T3MP3ST `main` HEAD `ae32cf5` (unchanged since prior review).
**Method:** 5 read-only grounding agents + direct verification. Documentation treated as context; code + reproducible tests + live artifacts win.

> Source-of-truth note: every "implemented/default/authoritative/tested" claim below was checked against the current code path, its tests, and (where relevant) a committed benchmark artifact. Contradictions are reported, not smoothed over.

## 1. Executive verdict
The deferred **direction is correct and should be kept**: Continuous ASM as the operating loop; authenticated, stateful, proof-backed testing of owned apps/APIs as the wedge; *AI proposes / deterministic contracts decide*; parallelism as substrate, not a quality claim. The safety invariants are right and **largely already enforced in code** (deterministic proof types, `ai_verdict` advisory-only, distinct-principal BOLA, gated arsenal, fail-closed planner health).

Four things dominate the directive's amendments:
1. **The authenticated crAPI baseline now exists, and it failed at `0/4` recall.** The harness minted
   two JWTs with different stable identity claims and both scanner auth lanes were scheduled. The
   four expected routes never entered the stored scan result, confirming discovery as a blocker.
   This does **not** yet prove that the authenticated requests were accepted or that BOLA/SQLi would
   detect the routes when supplied; seeded detector controls are the next acceptance boundary.
2. **"Registry-owned execution" is overclaimed.** The registry is authoritative for the *enable decision* of 9 families, but execution is legacy wrappers and ≥3 legacy paths still enable registered-family coverage outside the plan (notably `bola_testing → check_bola`).
3. **Do not build the LLM control plane (10 schemas) yet.** It is the exact "overbuild the control plane while detectors are unproven" danger the directive itself names. Gate it behind detector acceptance.
4. **The Juice Shop benchmark "PASS" is honest-in-mechanism but not a current status claim** — thin
   (exactly 6/6), anonymous, and on fleet `ddc6173b` rather than current `bc6c357`. Its late
   integrity-ledger entry now records those limits.

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
| **Auth/BOLA detector acceptance** | Current-fleet crAPI run is `two_user:true`; the harness rejected equal JWT identity claims and both auth lanes were scheduled. It still found **zero** BOLA and all four required routes were absent from the stored result. `two_principal_observed` currently means session lanes present, not server-validated identities. | stack-tested bootstrap; **detector not accepted** | Persist a redacted principal-validation receipt, run seeded BOLA/SQLi controls, then close universal authenticated API discovery and rerun the unseeded benchmark. |
| UI component coverage | Shared contract suite passes `20/20`, production build passes, and rebuilt-stack desktop/mobile browser QA is recorded (`b8eda2c`). Full stack E2E was not rerun on `bc6c357`. | component/browser accepted; stack E2E stale | Keep the component/browser result distinct from the open full E2E gate. |
| Multi-node prerequisites | Single Redis+Postgres; **fencing tokens, stale-owner-write prevention, partition/clock-skew tests, brokered secrets, per-node approval revalidation = ABSENT**; leases/heartbeats/reaper present | documented (Proposed/RFC) | Correctly deferred; fencing + stale-owner-write are the same missing mechanism and the load-bearing blocker |
| Local planner health/fallback | Fail-closed eval gate (`require_current_scorecard`), planner fingerprint, read-only sandbox, no execution authority | implemented + unit | Solid; matches T3MP3ST live-vs-connected lesson |
| Tool invocation contracts | Coarse receipts only; arsenal `ToolAdapterSpec` version-probes only (not the run-time invocation contract) | implemented + unit | `AdapterInvocationSpec` is net-new |
| Benchmark PASS honesty | Honest-in-mechanism (real `/metrics` detection; no gate-weakening or fitting) but **thin (6/6), anonymous, and on fleet `ddc6173b` rather than current `bc6c357`**; the ledger now records the caveats. | benchmark (non-current fleet) | Not a trustworthy "current-fleet passes" claim. |

## 3. Latest T3MP3ST findings
**HEAD `ae32cf5` (2026-07-09) = the prior review's commit; `main` has not advanced.** TS/Node framework. The tip's themes — `353ea33` real invocations; the `f502bfb`/`fb0feb0`/`49d0827`/`73d888f`/`d9a4c47` cluster (live-vs-connected model health + failure propagation); `23713fa`/`75b7ca0`/`e53c61e` (idle vs hard deadline); `808ce11`/`5e40e60` (provider contract) — are exactly those the directive enumerates, and ShakerScan has **already largely absorbed them** (planner fingerprint/health fail-closed; `scanner_execution_receipts`; typed `RegistryPhaseOutcome`). **Nothing new to borrow.** Take the two still-open ideas — a formal `AdapterInvocationSpec` (+ spec-hash) and a typed `ResourceRef` union — and stop treating "compare to latest T3MP3ST" as a recurring input. ShakerScan is ahead of T3MP3ST on the deterministic proof/evidence/policy side.

## 4. Architecture gaps (by risk × dependency)
1. **Authenticated API discovery + detector acceptance remain open.** Different JWT identities were
   minted, but `auth_states_tested` only records session presence (`scanner.py:5657-5663`). The
   expected crAPI routes were absent, and no seeded control has shown that BOLA/SQLi proves them once
   supplied.
2. **Registry gates but does not own execution; ≥3 legacy paths bypass the plan** — `bola_testing→check_bola` (`scanner.py:6294`); advanced_scan nosql (`scanner.py:5103-5117`); endpoint-scoped exposure/auth (`scanner.py:12156`).
3. **Cancellation coverage partial** — 3 modules; subprocess/browser/discovery keep firing until SIGKILL.
4. **Metering honest but enforcement opt-in + subprocess-opaque** — no honest hard request cap today.
5. **proof_contract/severity_rules declarative, not enforced** — registry publishes contracts nothing validates against.
6. **Static coverage merge ≠ ASM `test_status`** (dynamic default is fine).
7. **Benchmark integrity hygiene** — the flip is now in the ledger, but the evidence-mislabel,
   COMPAT-alias overclaim, invalid completion ratio, and non-current-fleet pass remain.
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
| 0 | **Benchmark truth contract + seeded detector controls** | — | redacted distinct-principal receipt; valid completion metrics; minimized discovery inventory; seeded BOLA/SQLi controls | current-fleet artifact distinguishes configured, accepted, attempted, and proved | existing scorecard fields retained | detector fitting; LLM work |
| 1 | **Universal authenticated API discovery** | 0 | authenticated spec/link/JS/browser discovery feeds replayable endpoint contracts without benchmark nouns/routes | unseeded current-fleet crAPI scorecard improves required-route discovery and recall | existing discovery path | fixture route injection into detector |
| 2 | Enforce proof_contract + close registry execution bypasses | 0 | proof/severity gated; `bola_testing→check_bola`, NoSQL, and endpoint-scoped registered coverage folded into registry | parity test: no registered-family finding outside plan | legacy adapter implementations | planner or multi-node work |
| 3 | Invocation contracts + typed ResourceRef (vertical slices) | 2 | `AdapterInvocationSpec` + resource-kind isolation + no-broken-invocation gate | new receipt states + tests | legacy dispatch | swarm |
| 4 | Shadow request accounting (metering_quality) + cancellation coverage | 0 | per-adapter metering tier; cancel wired engine-wide | "no request after observed cancel" soak | observe-only | hard cap for unknown metering |
| 5 | ObservationPack + DecisionEpisode contracts | 3,4 | versioned packs + episodes (no planner yet) | schema + redaction tests | — | execution authority |
| 6 | **Shadow LLM campaign controller (no authority)** | 5 | planner proposes; scheduler executes | shadow eval report (§9) | disable planner | any live action |
| 7 | Hard budget enforcement where metering provable | 4 | enforce mode where exact/upper-bound | enforcement soak | soft | subprocess hard cap |
| 8 | Dynamic/static parity + cancellation soak | 4; UI harness already accepted | quantitative soak (§10) | soak report | static rollback | — |
| 9 | One-step gated LLM action selection | 6,8 | planner picks 1 action from approved set | gated-action soak | shadow | multi-step autonomy |
| 10 | Reviewed StrategyCard memory | 9 | abstract, expiring, artifact-linked | review process | none | per-run auto-promote |
| 11 | Multi-node (fencing + idempotency) | 8 | fencing tokens + stale-owner-write guard | partition/skew tests | single-node | production 2-node before gates green |

## 8. First three increments (bounded, implementation-ready)
**Increment 0 — Make benchmark authentication and diagnostics evidentiary.**
- *Why now:* the first current-fleet run exposed ambiguous names and an impossible ratio, which
  prevents trustworthy acceptance decisions.
- *Contracts:* benchmark submission receipt; auth workflow; body-completion diagnostics; benchmark
  artifact schema.
- *Files:* `scripts/benchmark_targets.py`, `scanner/scanner_tools/benchmark_summary.py`,
  `scanner/scanner_tools/coverage_tracker.py`, `scanner/scanner_tools/attempt_telemetry.py`, benchmark
  summary/rescore tests.
- *Deliverable:* persist only redacted identity fingerprints and validation outcome; distinguish
  `principal_contexts_configured`, `principal_contexts_attempted`, and
  `principal_identities_validated`; reject or rename ratios outside `[0,1]`; include a bounded
  discovered-route/template diagnostic manifest.
- *Migration/compat:* additive fields; keep `two_principal_observed` as a deprecated compatibility
  alias until consumers migrate.
- *Failure modes:* leaking JWT claims, treating token decode as server acceptance, unbounded route
  artifacts, changing historical scorecard interpretation.
- *Tests:* no secret/claim leakage; same identity rejected; failed authenticated response is not
  accepted; ratios bounded; omission counts/hash stable.
- *Artifact:* rescore the existing scan plus one fresh current-fleet authenticated run.
- *Rollback:* omit new receipt fields and continue reading legacy scorecards. *Non-goals:* detector
  changes, registry migration, planner work.

**Increment 1 — Isolate detector correctness, then close universal authenticated discovery.** Add a
test-only/benchmark-controlled seeded endpoint input to prove whether current BOLA and SQLi contracts
detect the four expected route classes. Preserve that result separately from the unseeded benchmark.
Then improve authenticated OpenAPI/JSON-link/JS/browser route extraction generically and rerun without
seeded answer-key routes. Non-goals: hardcoded benchmark routes or product nouns in detector inputs.

**Increment 2 — Close registry bypasses and enforce proof contracts.** Move phase-4 BOLA, NoSQL, and
registered endpoint-scoped auth coverage behind the authoritative registry decision; add a test where
each legacy condition says yes while the registry says no. Validate emitted proof/severity against the
declared family contract. Keep adapter implementations as rollback-compatible internals.

## 9. Shadow-planner evaluation plan
No execution authority. The scheduler runs normally; the planner receives the same pre-action ObservationPack and proposes what it *would* have done. Fixtures: recorded ObservationPacks from real crAPI/Juice campaigns (versioned, hashed). Metrics: action-agreement vs the deterministic scheduler; schema-valid proposal rate; policy-rejection rate by reason; duplicate-action rate; expected-vs-actual information gain; predicted-vs-actual request cost; targeted proof yield; risk-tier accuracy; missing-precondition accuracy; cross-run variance from the same recorded pack. Promotion gate: schema-valid ≥ threshold, duplicate rate below bound, variance bounded, **zero** policy-invariant proposals that would have escalated risk/scope — only then allow one-step gated selection from an already-approved set.

## 10. Quantitative release gates
Zero scope violations · zero hard-budget violations (hard-enforced adapters) · **zero AI-only or source-only verified findings** · **no request after observed cooperative cancellation (engine-wide)** · every planner action tied to context_hash + backend receipt · every runnable adapter covered by an invocation-contract test · no worse benchmark precision · no worse required-family recall vs the corrected increment-0 baseline · no parent/ASM coverage disagreement · no orphan leases past recovery deadline · static fallback functional · better proof yield / 100 requests (or lower requests/proof) · lower median time-to-first-deterministic-proof · bounded duplicate/no-progress decision rate. Metrics that depend on accepted auth or route discovery remain gated until increment 0 emits truthful receipts and increment 1 supplies an unseeded baseline.

## 11. Documentation corrections
- **Applied:** dynamic is documented as the Full Coverage default; D-5/MI-7 are defined; older-fleet
  E2E and Juice Shop claims are labeled; the missing integrity-ledger entries exist.
- **Corrected after the crAPI run:** the authenticated baseline has now run on `bc6c357`; it proves
  distinct JWT claims at submission and two scheduled auth lanes, not server-observed identities or
  detector acceptance. Discovery is a confirmed blocker, while detector outcome remains untested.
- **Archive historical plans:** move the completed AI/Model Intake fix plan, June roadmap review,
  June UI QA snapshot, and bounded T3MP3ST adoption ledger under `docs/archive/`; keep links as
  historical references only.
- **Live hierarchy:** Tier 1 capability/status = `functionality-reference.md`,
  `proposed-next-steps.md`, and `E2E_TEST_PLAN.md`; Tier 2 active roadmap = this review plus
  `deferred-work-implementation-plan.md`; Tier 3 designs = Continuous ASM, parallel scan, and
  multi-node; Tier 4 historical material = `docs/archive/`.

## 12. Risks & rejected alternatives
- **Raw-agent/shell execution, LLM-produced findings, product commands like `run_sqlmap`** — rejected: violate the no-AI-only-proof + gated-arsenal invariants already enforced.
- **Challenge-mode persistence ("continue while iterations remain")** — rejected: use an obligation-completion stop rule; the BOLA deadline regression (`7847736`) shows how time/iteration heuristics silently drop coverage.
- **Broad autonomous swarm as the next milestone** — rejected: prefer one planner + deterministic validators + optional critic; shadow-first.
- **Premature multi-node** — rejected: no fencing / stale-owner-write guard; a reaped-then-returning worker clobbers `test_status` today.
- **Building the 10 LLM schemas now** — rejected: overbuilds the control plane while detectors are unproven (the directive's own #1 danger).

## 13. Final recommendation
- **Single best next increment:** make benchmark auth/diagnostic evidence truthful, then run seeded
  BOLA/SQLi controls to separate discovery failure from detector failure.
- **Benchmark artifact to produce immediately:** a fingerprint-current authenticated crAPI control
  pair: one seeded detector-isolation run and one unseeded discovery run, both carrying redacted
  principal-validation and route-omission receipts.
- **Feature that must stay deferred:** the LLM campaign controller with any execution authority (and the 10 planner schemas) — behind detector acceptance + shadow eval.
- **Top product metric for the next cycle:** verified proofs per 100 target requests (with the honest `metering_quality` denominator), plus required-family recall on the authed baseline.

---

## Appendix — Immediate execution order
1. Save this report (done — this file).
2. Apply the Section 11 documentation/ledger corrections (low-risk, no scanner code) and reclassify docs per the Tier1–5 hierarchy.
3. Implement increment 0's redacted principal-validation and bounded diagnostic receipts; correct
   the completion-ratio contract.
4. Run seeded BOLA/SQLi detector controls, then improve universal authenticated discovery and rerun
   the unseeded scorecard.
5. Close registered-family execution bypasses before adding planner authority.

*Grounded by read-only audits of auth/BOLA propagation, request accounting/budgets,
dynamic-vs-static + multi-node primitives, invocation contracts + attempt schemas + registry
authority, the stored crAPI scan result, and documentation contradictions. Verified directly:
HEAD `87ee530`, current-fleet scorecard `85d3bafb`, coverage default = dynamic, expected routes absent
from the stored result, and T3MP3ST pinned at `ae32cf5`.*
