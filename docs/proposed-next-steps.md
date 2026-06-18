# Proposed Next Steps — DAST Engine Direction

**Status:** proposal, 2026-06-18. Grounded against code at HEAD `3cf4804` (audited this session),
**not** against the architecture docs — so it credits what already shipped and proposes only the
work that is actually missing. Turns the "continuous internal scanner + bug-bounty-strength hunter"
strategy into a measured, benchmark-driven plan.

## Why this doc
A strategy review compared ShakerScan to Burp Pro / ZAP / Tenable WAS / StackHawk and recommended
shifting the next work away from "more parallelism / more payloads" toward **workflow understanding,
authz / business-logic testing, proof depth, and benchmark-driven detector quality**. The direction
is right and matches where the codebase is already heading (continuous campaign + endpoint inventory
+ attempt ledger). But the review was written against the docs and **understates what already
shipped**, so several of its "P0 builds" already exist. This doc re-grounds the plan and proposes
only the missing pieces.

**Guiding principle — benchmark-driven, not speculative.** Do not build the target architecture up
front. Wire crAPI + Juice Shop into the existing benchmark harness, run it, and let the
**miss-analysis** decide which detector work actually moves High/Critical counts. "Tune the engine
to find crAPI/Juice Shop bugs" and "move toward the hunter/graph architecture" are the **same loop**,
not sequential phases.

## Already shipped — do NOT rebuild
The review lists these as work to do; they already exist in code.

| Capability the review asked for | Status in code | Where |
|---|---|---|
| Benchmark miss-analysis harness | ✅ shipped — classifies misses as `family_not_attempted` / `proof_gap` / `auth_state_untested` | `fefe781` `scanner_tools/benchmark_summary.py`, `tests/benchmark/analyze_dast_benchmark.py` |
| BOLA / cross-principal resource replay | ✅ shipped — extract resource IDs from a producer JSON response, replay as user2 only for IDs absent from user2's own listing | `c88f54f` `access_control_checks.py::authz_resource_replay_test` |
| BOPLA / mass assignment + telemetry | ✅ shipped — per-endpoint `endpoint_attempts` | `017a186`, `4277c17` `active_checks.py::mass_assignment_test_json_body` |
| Vertical privilege escalation + forced browsing | ✅ shipped | `access_control_checks.py::check_vertical_privilege_escalation` (3269), `check_forced_browsing` (722) |
| Wide / deep budget split | ✅ shipped — `wide_budget` / `deep_budget` are columns **and** consumed | `asm_inventory.create_campaign`, `api.py:8968` |
| Unified family policy + cooperative cancellation | ✅ shipped | `655bd1d` `check_registry` policy contract; file-based scanner cancel |
| Standalone-scan request-budget reservation | ✅ shipped | `4277c17` `process_scan_job` |
| Login auth-bypass SQLi detection | ✅ shipped — failed-login → 200 + token/identity = strong evidence | `ddd3de9` |

So the work ahead is **finish + connect what exists**, not a rebuild.

## The benchmark feedback loop (the spine of this plan)
1. Wire **crAPI** and **Juice Shop** into the benchmark harness (`fefe781`) as fixtures:
   `benchmarks/<target>/{profile.yml, auth.yml, expected_families.yml}` (+ `openapi.yml` for crAPI).
   Do **not** hardcode challenge solutions — store expected *families / route categories / auth
   states*, not answers.
2. Run the harness to get a baseline: `discovered`, `attempted`, `auth_coverage`,
   `resource_id_pairs_found`, `confirmed_findings`, `expected_family_misses`, `proof_gaps`,
   `severity_gaps`.
3. Treat every item below as a hypothesis the miss-analysis must justify before we build it.
   The two targets pull in opposite directions, which is the point:
   - **crAPI** → API import + authz graph + BOLA / BOPLA / JWT.
   - **Juice Shop** → browser / JS route discovery + stored-XSS proof + SQLi.

## Genuinely-missing capabilities (prioritized)
Only build the ones the benchmark baseline shows as real misses.

- **N1 — Multi-step workflow / state modeling.** *(highest-value gap)* No
  register → login → create → share → mutate sequence model exists today (only single-hop
  producer→consumer in BOLA and one internal `stored_xss_workflow`). This is what unlocks
  business-logic High/Critical bugs. Seed traces from browser sessions, HAR, OpenAPI examples,
  and previous successful scans; test mutations around those sequences.
- **N2 — Persist the resource / principal / producer-consumer graph.** The BOLA replay pack already
  builds this in memory; lift it into a durable structure (extend `target_endpoints` or a sibling
  table) so other detectors and the Continuous ASM loop can reuse object IDs, ownership, and
  producer→consumer edges instead of rediscovering them per scan.
- **N3 — BFLA as a first-class role-matrix.** We have the ingredients (forced browsing, vertical
  priv-esc); add the explicit `anon / user1 / user2 / admin × endpoint` matrix view and the
  function-level-access detector that reads it.
- **N4 — Discovery-source imports.** Add **GraphQL introspection-as-import** and **Postman** import,
  and unify **OpenAPI** import into the same endpoint-inventory path (detection exists today;
  import-into-inventory does not). Critical for crAPI-class API coverage.
- **N5 — Registry-driven scanner execution (keystone "A").** `build_report()` still dispatches via
  the per-module boolean ladder (`scanner.py:5148,5156` + ~7 `if run_sqli/run_xss` sites); the
  `ACTIVE_FAMILY_DISPATCH_ORDER` loop is cosmetic. Migrate active-check dispatch to iterate the
  `ACTIVE_CHECK_FAMILIES` / `check_registry.CheckFamilySpec` registry so families are independently
  schedulable and each new check is one registry entry, not N edit sites. Large, high-risk refactor
  of the scanner's most critical function — do it behind the byte-identical family-scope tests.
- **N6 — Formalized proof contracts across detectors.** The pieces exist per-detector (BOLA
  cross-principal proof, SQLi evidence, mass-assignment state-change). Define a shared
  `proof_contract` per family (what evidence is required to confirm + assign severity by impact),
  and have the benchmark harness's `proof_gap` metric enforce it.

## Explicitly deprioritized (don't build yet)
- **Hunter campaign mode** — mostly repackages `deep_budget` + focused families + Lab gating that
  already exist; not worth a new campaign type until detector depth justifies it.
- **Full ApplicationGraph ontology** — build the N1/N2 slice that feeds authz/business-logic, not
  the whole ontology.
- **Multi-node fleet / object evidence store / reliable queue leases** — infra; correct long-term,
  but it does not find High bugs. After the detector loop improves.

## Watch-items to verify (from recent commits, not confirmed bugs)
- `a729602` dropped `in_progress` from claim-blocking — confirm the `leased` rows prevent duplicate
  cross-family claims / coverage over-count.
- `4277c17` mutates `custom_budget["active_max_endpoints"]` in-place on a partial rate grant —
  confirm a throttled scan isn't later escalated to ASM carrying the reduced cap.
- Benchmark harness treats "family ran but emitted no `endpoint_attempts`" as `family_not_attempted`
  — could mislabel early-exit skips; ensure every active module emits ≥1 attempt even on skip.

## Sequencing
| Priority | Step | Why |
|---|---|---|
| **P0** | crAPI + Juice Shop benchmark fixtures + baseline run | Objective miss-analysis; turns the roadmap into numbers |
| **P0** | Close benchmark-confirmed detector misses (N3/N4 first if `auth_state_untested` / `family_not_attempted` dominate) | Direct High/Critical lift |
| **P1** | N1 workflow/state modeling + N2 persisted resource graph | The real business-logic unlock |
| **P1** | N5 registry-driven execution | Makes families independently schedulable; enables new runnable families cheaply |
| **P1** | N6 proof contracts | Stops weak/noisy findings; impact-based severity |
| **P2** | Object evidence store, then queue leases / node registry | Production fleet scale — after the detector loop |

## Success metric
Benchmark deltas across runs (`compare_benchmark_summaries`): **confirmed High/Critical up**,
`expected_family_misses` **down**, `proof_gaps` **down** — on both crAPI and Juice Shop.
