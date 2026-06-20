# Proposed Next Steps - DAST and ASM Quality Plan

**Status:** proposal, updated 2026-06-20.

This plan is intentionally benchmark-driven. Parallel scans, ASM inventory, and fleet scaling are
only valuable when they increase verified High/Critical discovery. The next work should be measured
against Juice Shop, crAPI, and Honey, with explicit proof quality and coverage metrics.

## Current Baseline

- **Juice Shop:** latest Smart scan found verified Critical SQLi and browser-proven High DOM XSS.
  This is real progress from the earlier shallow runs.
- **crAPI:** prior authenticated/multi-user Smart runs found verified BOLA/Authz findings. The latest
  visible crAPI scan was only Quick, so it does not measure DAST depth.
- **Honey:** broad detector work is producing approval bypass, webhook bypass, data exposure, path
  traversal, SQLi, and AI/model findings, but many new detector findings still need stronger
  verified-vs-suspected treatment.
- **ASM:** functional but immature. Current attempt-ledger coverage is roughly 14% for Juice Shop and
  20% for crAPI in the local inventory. ASM tracks gaps, but it does not yet drive enough completed
  family-specific proof work by default.
- **Operational note:** workers were stale after the latest provenance commits during the audit. Any
  benchmark scan must start only after the worker fleet reports `build_current: true`.

## North Star

A great ShakerScan run should answer:

1. What exploitable High/Critical bugs did we prove?
2. What did we test?
3. What did we not test?
4. Why not?
5. What is the next highest-value campaign?

The product direction to protect is: verified exploit discovery first, coverage clarity second,
orchestration third.

## 1. Establish Benchmark Scorecards

**Goal:** stop guessing whether changes improve DAST quality.

**Files:**

- `scripts/dast_calibration.py`
- `scripts/honey_calibration.py`
- new: `scripts/benchmark_targets.py`
- new: `tests/fixtures/benchmarks/juice_shop.yaml`
- new: `tests/fixtures/benchmarks/crapi.yaml`
- new: `tests/fixtures/benchmarks/honey.yaml`
- `tests/benchmark/analyze_dast_benchmark.py`

**Steps:**

1. Define expected bug classes per target: SQLi, DOM XSS, BOLA/IDOR, exposed secrets, XXE, BFLA,
   workflow auth bypass, webhook bypass, approval bypass.
2. Add a benchmark runner that submits scans, waits for completion, fetches results, and writes a
   compact report.
3. Track `verified_high_critical`, `suspected_high_critical`, `false_positive_risk`,
   `coverage_percent`, `budget_exhausted`, `auth_blocked`, `timeout`, and `error`.
4. Add per-target pass/fail gates:
   - Juice Shop must find verified Critical SQLi and browser-proven High XSS.
   - crAPI must find verified BOLA/IDOR when two users are supplied.
   - Honey must find broad category issues without promoting weak evidence to Critical.
5. Store scan IDs and summaries under `results/benchmark-runs/`.

**Acceptance:**

- Benchmark output shows expected families found, missed, and blocked.
- A regression that drops Juice Shop SQLi/XSS or crAPI BOLA is visible immediately.

## 2. Fix Operational Freshness Before Scans

**Goal:** never run serious validation on stale workers.

**Files:**

- `api/api.py`
- `api/worker.py`
- `ui/src/app/page.tsx`
- `ui/src/app/scan/new/page.tsx`
- `ui/src/app/scans/[id]/page.tsx`
- `ui/src/lib/api.ts`

**Steps:**

1. Make `/workers` stale state highly visible in Dashboard and New Scan.
2. Disable or strongly warn on Smart, Full, Aggressive, and Full Coverage when any worker is stale.
3. Add API-side optional guard: reject active scans when `require_current_workers=true` and stale
   workers exist.
4. Add scan metadata fields:
   - `expected_build_fingerprint_at_submit`
   - `stale_worker_count_at_submit`
   - `worker_fleet_size_at_submit`
5. Add a Scan Detail banner that explains when scan results came from stale workers.

**Acceptance:**

- UI clearly says "workers stale, restart before scanning."
- Scan results prove which code fingerprint ran.

## 3. Raise Smart and Full Coverage Budgets Safely

**Goal:** do not miss obvious bugs because the scanner stops after a small slice.

**Files:**

- `scanner/constants.py`
- `api/parallel_scan.py`
- `api/worker.py`
- `ui/src/app/scan/new/page.tsx`
- `ui/src/app/scans/[id]/page.tsx`
- `docs/parallel-scan-architecture.md`

**Steps:**

1. Rework `SCAN_BUDGET_DEFAULTS` so `smart/thorough` and `smart/exhaustive` are large enough for
   vulnerable apps.
2. For Full Coverage, scale active endpoint budget from discovered endpoint count and worker count.
3. Prefer repeated dynamic waves over huge shard counts.
4. Keep the UI simple:
   - Normal
   - Smart
   - Full Coverage
   - Full Coverage Deep
5. In Scan Detail, explain capped worklists. Example: "150 of 2458 active candidates tested; run
   Full Coverage Deep or focused family waves to continue."
6. Expose `budget_exhausted_at`, selected endpoint count, discovered endpoint count, and family
   coverage in the report.

**Acceptance:**

- Full Coverage tests most active candidates across waves, not a small selected subset.
- Budget exhaustion becomes an actionable coverage gap, not a hidden footnote.

## 4. Improve XSS Detectability

**Goal:** reliably prove Juice Shop-style DOM, reflected, hash-route, and stored XSS.

**Files:**

- `scanner/scanner_tools/active_checks.py`
- `scanner/scanner_tools/proof_of_exploit.py`
- `scanner/scanner.py`
- `scanner/constants.py`
- `tests/test_active_checks.py`
- `tests/test_smart_active_budget.py`
- `tests/test_dast_precision.py`

**Steps:**

1. Keep browser proof as the standard for High XSS.
2. Expand browser-first proof across reflected, DOM, hash-route, stored, attribute, script, and JSON
   contexts.
3. Preserve browser state and authentication in proof runs.
4. Load payload packs from `payloads/xss/*` instead of relying mostly on hardcoded payloads.
5. Add DOM sink prioritization from JS analysis.
6. Add a benchmark assertion that Juice Shop hash-route XSS stays detected and browser-proven.

**Acceptance:**

- Browser-proven XSS is High with explicit CVSS.
- Unproven XSS remains Medium or suspected.
- Juice Shop DOM XSS is a stable benchmark pass.

## 5. Improve SQLi Detectability

**Goal:** find SQLi across GET, POST, JSON, form, and API endpoints with proof.

**Files:**

- `scanner/scanner_tools/active_checks.py`
- `scanner/scanner_tools/proof_of_exploit.py`
- `scanner/scanner.py`
- `scanner/constants.py`
- `tests/test_sqli_poe_precision.py`
- `tests/test_dast_precision.py`

**Steps:**

1. Increase POST, JSON, and form parameter coverage in Smart and Full Coverage.
2. Load payload packs from `payloads/sqli/*`.
3. Improve blind/time/OOB SQLi support behind safe opt-in.
4. Keep reflection false-positive checks strict.
5. Make SQLi family campaigns first-class through ASM and API.
6. Report which SQLi techniques were attempted per endpoint: boolean, error, union, auth bypass,
   extraction, OOB.

**Acceptance:**

- SQLi findings include verified evidence or are downgraded.
- Juice Shop search/login SQLi remains consistently detected.

## 6. Improve BOLA and Authz Detectability

**Goal:** make crAPI BOLA/Authz a first-class benchmark, not an accidental win.

**Files:**

- `scanner/scanner_tools/access_control_checks.py`
- `scanner/scanner_tools/proof_of_exploit.py`
- `scanner/scanner.py`
- `api/api.py`
- `api/worker.py`
- `ui/src/app/asm/page.tsx`
- `ui/src/app/scan/new/page.tsx`

**Steps:**

1. Make user1/user2 auth setup explicit and easy in UI/API.
2. Build an object graph from producer endpoints, then replay IDs as user2.
3. Add safe object creation/harvesting workflows for crAPI-like apps.
4. Separate read-BOLA, write-BOLA, BFLA, and auth bypass in evidence.
5. Ensure BOLA runs only when primary and second-user credentials exist.
6. Add blocked reasons: missing primary auth, missing second user, no producer endpoint, no object IDs,
   auth expired, insufficient budget.

**Acceptance:**

- crAPI dashboard/order/user endpoints produce verified BOLA findings.
- Missing second user shows a clear blocked reason, not silent low coverage.

## 7. Mature ASM Coverage

**Goal:** ASM should guide continuous improvement, not just store endpoint rows.

**Files:**

- `api/asm_inventory.py`
- `api/api.py`
- `api/worker.py`
- `api/parallel_scan.py`
- `ui/src/app/asm/page.tsx`
- `docs/continuous-asm-architecture.md`
- `tests/test_asm_inventory.py`
- `tests/test_coverage_strategy.py`
- `tests/test_worker_scan_ai_gating.py`

**Steps:**

1. Add family-level coverage: all, SQLi, XSS, Auth, BOLA.
2. Add auth-state coverage: anonymous, user1, user2.
3. Make `/asm/gaps` explain low coverage by reason:
   - untested
   - stale
   - auth missing
   - timeout
   - error
   - gone
   - partial telemetry
4. Add "recommended next campaign" response:
   - recon
   - SQLi wave
   - XSS wave
   - BOLA wave
   - retest stale
   - add credentials
5. Clean up `gone` and duplicate endpoint inventory so coverage is not diluted.
6. Add policy execution for daily/weekly ASM waves, not just manual improve.
7. Make attempt-ledger rollups distinguish endpoint attempted from proof attempted.

**Acceptance:**

- ASM page answers: "what remains untested and why?"
- Coverage improves over time without flooding Scans with implementation rows.
- Juice Shop/crAPI ASM reaches meaningful coverage after scheduled waves.

## 8. Improve ASM UI and UX

**Goal:** powerful, but not overwhelming.

**Files:**

- `ui/src/app/asm/page.tsx`
- `ui/src/app/scan/new/page.tsx`
- `ui/src/app/schedules/page.tsx`
- `ui/src/app/scans/[id]/page.tsx`
- `ui/src/lib/api.ts`

**Steps:**

1. ASM target page should show:
   - total coverage
   - family coverage
   - auth-state coverage
   - blockers
   - next best action
2. Add simple presets:
   - Safe
   - Balanced
   - Deep Lab
3. Hide advanced knobs by default.
4. Show "needs user2 credentials for BOLA" as an actionable state.
5. Add one-click actions:
   - Improve coverage
   - Run SQLi wave
   - Run XSS wave
   - Run BOLA wave
   - Refresh discovery
6. Scan Detail should explain parent/shard/ASM rollups in human terms.

**Acceptance:**

- A normal user can understand what to do next without seeing dozens of scan options.

## 9. Make Schedules ASM-Aware

**Goal:** continuous scanning should be deliberate and budgeted.

**Files:**

- `api/api.py`
- `api/worker.py`
- `ui/src/app/schedules/page.tsx`
- `ui/src/app/asm/page.tsx`

**Steps:**

1. Add schedule type: normal scan vs ASM policy.
2. Support time windows:
   - daytime recon
   - nighttime active testing
   - weekend deep coverage
3. Add daily endpoint cap and family rotation.
4. Add stale-only retest campaigns.
5. Add schedule outcome summaries.
6. Add a compact "keep this target covered" flow from ASM target page.

**Acceptance:**

- User can set "keep this target covered" once.
- ASM spreads work safely across days/weeks.

## 10. Improve Verification and Triage

**Goal:** High/Critical must be trustworthy.

**Files:**

- `scanner/findings.py`
- `api/evidence_triage.py`
- `api/worker.py`
- `scanner/scanner_tools/proof_of_exploit.py`
- `tests/test_dast_precision.py`
- `tests/test_worker_evidence_triage.py`

**Steps:**

1. Enforce: Critical requires exploit proof or strong deterministic evidence.
2. Keep suspected High/Critical visible but clearly labeled.
3. Route inconclusive findings to deterministic retest first.
4. Use AI only after deterministic proof fails or needs semantic judgment.
5. Add confidence distribution to reports and ASM gaps.
6. Ensure weak indicators do not drag scores down as if they were proven exploitation.

**Acceptance:**

- Reports distinguish verified exploitable bugs from review-needed signals.
- Critical/High counts are credible.

## 11. Update Architecture Docs as Behavior Ships

**Files:**

- `docs/parallel-scan-architecture.md`
- `docs/continuous-asm-architecture.md`
- `AGENTS.md`

**Steps:**

1. Update outdated language about Juice Shop XSS after benchmark status is codified.
2. Add current benchmark status and expected target scorecards.
3. Document Full Coverage Deep and ASM family waves.
4. Document that parallelism is a substrate, not the goal.
5. Add operational warning: stale workers invalidate benchmark scans.

**Acceptance:**

- Docs describe current behavior and next gaps accurately.

## Recommended Execution Order

1. Restart/rebuild workers before any new scan validation.
2. Build benchmark scorecards and runner.
3. Fix budgets and Full Coverage wave sizing.
4. Harden XSS and SQLi proof lanes.
5. Mature BOLA/auth setup and crAPI workflows.
6. Improve ASM gaps and recommendations.
7. Improve ASM UI and schedules.
8. Update docs after behavior is real.

## Non-Goals for This Plan

- Do not add more visible scan options unless they simplify a real workflow.
- Do not treat more shards as success by itself.
- Do not auto-enable high-risk families such as SSRF, LFI, RCE, destructive mass assignment, or
  write-BOLA outside explicit Lab/deep intent.
- Do not promote findings to High/Critical without deterministic proof or clearly labeled suspected
  status.
