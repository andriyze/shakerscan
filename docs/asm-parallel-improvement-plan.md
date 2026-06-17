# ASM + Parallel Scanning — Improvement Plan

**Status:** living plan from a live validation run (Juice Shop / crAPI / honey.shakerscan.com,
2026-06-17). Each item lists the **evidence** observed, the **root cause**, and the **fix**.
P1 (worker scaling), A1 (phantom-endpoint pollution), P2 (re-classified as a P1 skew symptom, not a
planner bug), P3 (observability), and P4 (re-classified as a stale-API skew + a misread, not a
submit bug) are **fixed & committed**; A2 and the P1 follow-up (code-version handshake) remain.

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

### P2 — "Dynamic Full Coverage executes static"  ✅ NOT A BUG — was a P1 (skew) symptom
- **Original evidence:** a Full Coverage scan (`6f3e9dec`) planned/campaigned as dynamic but its 11
  children were static (`scan_role='shard'`, `custom_endpoints` populated, **no
  `coverage_dynamic_worker`**). This looked like the dynamic planner being bypassed.
- **Re-investigation (corrected):** the earlier `->>` DB query that reported "0 dynamic shards"
  was **mis-evaluated**. Re-checking the raw `scans.options` directly:
  - **Clean uniform new-code fleet** (`c901c31b`): all 11 children carry
    `coverage_dynamic_worker=true`, `coverage_dynamic_campaign_only=true`, `zero_rediscovery=true`,
    `custom_endpoints=null` — i.e. genuine **dynamic pull-workers**, queued as
    `EXPLOIT_BATCH_JOB_TYPE` (`api/worker.py:4470`) and claiming batches via
    `claim_test_batch` (`worker.py:5245`).
  - **Skewed fleet** (`6f3e9dec`): children have `coverage_dynamic_worker=null` (static) — because
    the `scan_plan` job landed on a **stale-code worker** that pre-dated dynamic allocation.
- **Root cause:** the static execution was the **P1 worker-version-skew symptom**, not a planner
  bug. `plan_dynamic_coverage_shards` (`api/parallel_scan.py:831`) was always correct (verified:
  produces `coverage-dynamic[i]` shards with `coverage_dynamic_worker=True`, no static slices;
  locked by `tests/test_coverage_strategy.py:479`).
- **Resolution:** fixed by **P1** — a uniform new-code fleet runs dynamic correctly. No separate
  code change needed for execution. The hard-to-diagnose part (no decisive fan-out log) is fixed
  under **P3** so a future skew is obvious immediately instead of needing DB archaeology.

### P3 — Observability & log spam  ✅ FIXED
- **Evidence:** the `Shard '…' waiting for parent slot` / `Coverage batch waiting for parent slot`
  retries flooded worker stdout every ~2s and rotated out the plan-stage decision lines, making the
  P2 mis-diagnosis possible; no single line stated the chosen allocation + per-shard job type.
- **Fix (done):** (1) the fan-out now emits one decisive summary line per parent —
  `fanned out N '<strategy>' shards (allocation=dynamic|static|mixed, dynamic_pull_workers=…,
  static_slices=…)` (`api/worker.py:4493`); (2) both slot-wait requeue paths log **once on the
  first wait, then every 15th cycle** instead of every retry (`worker.py:4575`, `:5232`).

### P4 — "`parallel:true` dropped → standalone"  ✅ NOT A BUG — stale-API skew + a misread
- **Original evidence:** crAPI appeared to be submitted with `parallel:true` but "stored
  `parallel:None` and ran standalone."
- **Re-investigation (corrected):**
  - **The submit logic is correct.** Clean single-submit repros on current code:
    `parallel:true`+`shard_strategy:family` → `scan_role=parent, options.parallel=true,
    shard_strategy=family`; omitted `parallel` → `scan_role=standalone, options.parallel=false`.
    `_apply_auto_sharding_policy` (`api/api.py:871`) **always** sets an explicit `parallel` key,
    and explicit intent (via Pydantic `model_fields_set`) wins. Coverage scans are additionally
    rescued by `force_parent` (`worker.py:4373`).
  - **The "`parallel:None`" was a diagnostic artifact** — the GET scan-detail response had **no
    top-level `parallel` field** (it lives in `options.parallel`), so `response.get('parallel')`
    returned `None` on a genuine parent. `scan_role` was already present and said `parent`.
  - **The one real standalone anomaly** (`58758cf3`, a full ScanOptions dump with **no
    `parallel`/`shards`/`shard_strategy` keys at all**) was created by an **API container running
    stale, pre-"always-set-parallel" code** before a restart — the same skew family as P1/P2, on
    the single API container (the single-file-mount staleness gotcha). Every post-restart submit
    carries the key.
- **Resolution / hardening (done):**
  - Regression tests lock the contract — explicit `parallel:true`→parent, omitted→explicit
    `parallel:false` key, never unset (`tests/test_api_helpers.py`).
  - GET `/scans/{id}` now returns a top-level `parallel` boolean mirroring `options.parallel` /
    `scan_role==parent`, so the submit and detail responses are consistent and the misread can't
    recur (`api/api.py:7732`).

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
- **Root cause:** compounds A1 (phantom rows accumulate). The "zero campaign-linked rows" was the
  P1/P2 skew symptom — when the `scan_plan` ran on a stale worker, the campaign-scoped dynamic
  upsert path (`source='coverage_recon'`, `campaign_id=…`) never executed, so rows landed as plain
  `source='recon'` with no campaign link. On a uniform new-code fleet the dynamic path runs and
  links rows. Also revisit fingerprint/auth-state dedup so re-recon doesn't grow near-duplicates.
- **Fix:** lands largely now that A1 (don't record phantoms) is fixed and the fleet is uniform
  (dynamic campaign-scoped upserts run); remaining work is inventory GC for `gone`/unreachable rows.

---

## Status / remaining order
1. **A1** (phantom-endpoint pollution) — ✅ fixed (`3c9afff`), validated live against honey.
2. **P2** (dynamic executes static) — ✅ resolved: it was the P1 skew symptom, not a planner bug;
   dynamic coverage runs correctly on a uniform new-code fleet (verified on `c901c31b`).
3. **P3** (observability + slot-spam) — ✅ fixed: decisive fan-out allocation line + throttled
   slot-wait logging, so a future skew is visible immediately.
4. **P4** (`parallel:true`→standalone) — ✅ resolved: stale-API skew + a misread, not a submit bug;
   contract locked by tests and GET detail now surfaces `parallel`.
5. **Remaining:** **P1 follow-up** (scale-aware `rebuild/restart` recreates API-scaled workers + a
   code-version handshake so a skewed worker/API refuses jobs instead of silently running old code
   — this is the common root of P2 and P4), and **A2** (inventory GC for `gone`/unreachable rows).
