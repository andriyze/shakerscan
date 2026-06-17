# ASM + Parallel Scanning — Improvement Plan

**Status:** living plan from a live validation run (Juice Shop / crAPI / honey.shakerscan.com,
2026-06-17). Each item lists the **evidence** observed, the **root cause**, and the **fix**.
Worker scaling (P1) is **fixed & committed**; the rest are prioritized below.

## How this was found
Ran Full Coverage scans against the three targets and inspected logs, the DB (scans,
scan_campaigns, target_endpoints), the worker fleet, and the `/asm` UI. Several behaviors did
not match the shipped design.

---

## Parallel scanning

### P1 — Worker version skew + scaling crash  ✅ FIXED (commit 707ae9e)
- **Evidence:** the fleet ran 5 new + 15 stale workers (`Up 17h`); scan_plan jobs on stale
  workers used old code, so Full Coverage ran *static* even though dynamic is the new default.
  Scaling up via `/workers` then crash-looped every new worker
  (`ModuleNotFoundError: check_registry` → circular import).
- **Root cause:** `./scanner.sh restart` only restarts the 5 compose replicas, not the
  API-scaled workers. The `/workers` scaler scale-**down** only *stopped* workers; scale-**up**
  *restarted* those stopped containers, which run an **outdated baked image** under the
  bind-mounted current code. Image/config were also inferred from `workers[0]` (could be stale).
  Count was hard-capped at 20.
- **Fix (done):** scale-down force-removes; scale-up removes non-running workers and creates the
  shortfall fresh from a **running** worker's current image/env/binds. Cap is configurable via
  `SHAKERSCAN_MAX_WORKERS` (default 30). Verified live: 20→30→5→30, 0 crash-loops, all current image.
- **Follow-up:** make `./scanner.sh rebuild/restart` recreate API-scaled workers too (today they
  must be re-scaled); consider a worker code-version handshake so a version-skewed worker refuses
  jobs instead of silently running old code.

### P2 — Dynamic Full Coverage executes *static*  🔴 HIGH
- **Evidence (clean uniform new-code fleet):** recon harvested 1591 endpoints; the plan logged
  `coverage: dynamic campaign allocation with 11 pull worker(s)` and **created a `full_coverage`
  campaign** — but all 11 shard children are `scan_role='shard'` with `custom_endpoints` and
  **no `coverage_dynamic_worker`** (i.e. static `plan_coverage_shards` output, not the dynamic
  pull-workers from `plan_dynamic_coverage_shards`). No "falling back to static" log fired.
- **Impact:** dynamic allocation (made default in `0a888cf`) is effectively non-functional — it
  plans/campaigns as dynamic but runs as static slices, so the lease/attempt-ledger pull model
  isn't exercised. This is the path that was shipped-as-default without live validation.
- **Root cause:** not yet pinned. `plan.notes` carries the dynamic note (so `plan` came from
  `plan_dynamic_coverage_shards`, `api/parallel_scan.py:831` which sets `coverage_dynamic_worker=True`
  on every shard), yet the fanned-out children lack that flag — so the `plan` reaching the fan-out
  loop (`api/worker.py:4447`) is not the dynamic plan, or its shards lost the flag. Needs focused
  tracing between the plan decision (`worker.py:4327`) and fan-out.
- **Fix:** (1) add a decisive per-parent log at fan-out: resolved `coverage_allocation`, plan
  strategy, and **job type per shard** (`exploit_batch` vs `shard`); (2) trace why the dynamic
  plan's `coverage_dynamic_worker` shards don't reach the fan-out; (3) regression test asserting a
  dynamic coverage plan fans out `EXPLOIT_BATCH`/`coverage_dynamic_worker` children, not static ones.

### P3 — Observability & log spam  🟡 MEDIUM
- **Evidence:** the `Shard 'coverage[N]' waiting for parent slot` retries flood worker stdout and
  rotate out the plan-stage decision lines, making P2 hard to diagnose; no single line states the
  chosen allocation + per-shard job type.
- **Fix:** log the slot-wait **once per shard** (not every retry), and emit one allocation-decision
  summary line per parent.

### P4 — `parallel:true` dropped → standalone  🟡 MEDIUM
- **Evidence:** crAPI was submitted with `parallel:true, shard_strategy:coverage` (same payload as
  Juice Shop/Honey, empty saved options) but stored `parallel:None` and ran standalone.
- **Root cause:** unconfirmed — possibly a race across rapid submits, or a submit-path
  normalization that drops explicit `parallel` under some condition. Needs reproduction.
- **Fix:** reproduce with a single submit; ensure explicit `parallel:true` always forces a parent.

---

## ASM

### A1 — Inventory pollution: phantom endpoints + method fan-out  🔴 HIGH
- **Evidence:** the `/asm` "New surface" feed showed **5394 in 7 days**, every path across all four
  methods (GET/POST/PUT/PATCH). Verified `GET https://honey.shakerscan.com/api/ai-redteam/user_consent`
  → **404**, a made-up path → 404, but the inventory holds 132/128/128/128 rows for those paths
  (`source='recon'`). honey exposes `/openapi.json` (200) declaring `/api/ai-redteam/*`.
- **Root cause:** the harvest records **OpenAPI-spec-declared and OPTIONS-derived
  (`discover_allowed_methods`, `discovery.py:754`) method×path combos** into `target_endpoints`
  with **no reachability validation** — `api/asm_inventory.py` has no 404/status filtering. Spec
  declares endpoints the server doesn't actually serve → phantom inventory, inflated coverage
  denominators, wasted test budget, and noisy new-surface alerts.
- **Fix:** validate reachability before inventory upsert (and before active-testing): drop
  endpoints whose declared method returns 404 during recon; don't fan methods from spec/OPTIONS
  unless the method actually responds. Record a `reachable`/`last_status` signal on
  `target_endpoints` and exclude unreachable rows from coverage + the new-surface diff.

### A2 — Inventory bloat / no campaign linkage  🟡 MEDIUM
- **Evidence:** 3000+ `target_endpoints` rows per target, mixed `source` (recon/scan/asm), **zero**
  `campaign_id`-linked rows even for coverage parents.
- **Root cause:** compounds A1 (phantom rows accumulate) and the static-execution bug P2 (dynamic
  campaign-scoped upserts don't run, so rows aren't campaign-linked). Also revisit fingerprint/
  auth-state dedup so re-recon doesn't grow near-duplicates.
- **Fix:** lands largely once A1 (don't record phantoms) and P2 (dynamic path actually runs) are
  fixed; add inventory GC for `gone`/unreachable rows.

---

## Suggested order
1. **A1** (phantom-endpoint pollution) — user-visible, corrupts coverage + new-surface. 
2. **P2** (dynamic executes static) — the default coverage path is mis-executing.
3. **P3/P4** (observability + parallel-drop) — make P2 and future issues debuggable.
4. **P1 follow-up** (scale-aware rebuild + version handshake) and **A2** (GC) clean up the rest.
