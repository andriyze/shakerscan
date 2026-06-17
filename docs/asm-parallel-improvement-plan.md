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

---

## Round 2 — second live data run (2026-06-17)

Ran three parallel scans concurrently on a uniform 10-worker fleet — Juice Shop coverage
(`454f786e`), honey coverage (`e2dbf9a3`), crAPI family (`2158c971`) — plus Continuous ASM on
crAPI. **All completed with zero shard failures.**

### What is now validated working
- **Dynamic Full Coverage** fans out real pull-workers (`allocation=dynamic`); honey 2, Juice Shop 8.
- **Merge / dedup**: parent reports correctly collapse shard findings (family 55→19, Juice 32→5,
  honey 27→17); no shard findings lost, no duplicates.
- **Campaign linkage** now happens (Juice Shop **2079** campaign-linked rows, honey 183) — the
  earlier "0 linked" was the P1/P2 skew, resolved on uniform code.
- **Family fan-out** correctly caps at 3 (broad/sqli/xss), logged `allocation=static, static_slices=3`.
- **ASM dispatcher** correctly defers (`action=wait`) while a target has active scans, then
  dispatches a test batch (`action=test`) once clear — good concurrency control.

### A3 — Soft-404 / unknown-route phantom endpoints  ✅ FIXED
- **Evidence:** A1's literal-404 filter is **defeated by apps that don't 404 unknown routes.**
  Measured per-target reachability-filter drop rate (`harvested N (M pre-reachability-filter)`):

  | Target | Unknown-route response | A1 (drop-404) result |
  |--------|------------------------|----------------------|
  | honey | clean **404** (9 b) | **1095 → 183** (83% phantoms dropped) ✓ |
  | crAPI | **404** at root, **401/405** under auth prefixes | partial |
  | Juice Shop | **500** (~3060 b) for `/api`,`/rest`; **200** 75 KB SPA index catch-all; never 404 | **1137 → 1137** (0 dropped) ✗ |

  Consequence on Juice Shop: the dynamic coverage scan tested ~1071 endpoints to a **94% coverage**
  grade — but most were **phantom** (soft-404), so the budget was wasted and the coverage metric
  was meaningless. (1261 endpoint test-attempts were recorded that run, the bulk on phantoms.)
- **Root cause:** `filter_reachable_worklist` only dropped a literal `404`. SPAs serve a 200 index
  shell for unknown routes; API frameworks return 500/401/403/405 under a prefix. Neither is 404.
- **Fix (done):** learn each path-prefix's *soft-404 signature* (HTTP status + body size) by probing
  implausible **decoy** paths, then drop GET entries when their response is a literal 404 **or** matches
  the prefix's decoy signature (status equal + size within tolerance). Non-GET entries on the same path
  are kept because the probe is a safe GET and many routers return 404 for unsupported methods even when
  a POST/PUT route exists. This is a *differential* check, so per-prefix variation is handled automatically
  (crAPI 404-at-root vs 401-under-`/identity`). Bias stays conservative: any inconclusive probe keeps the
  endpoint; a status that differs from the decoy (a real 401 where unknown→500) is kept. `api/asm_inventory.py` (`_probe_path_status`,
  `_path_prefix`, `_soft404_matches`, rewritten `filter_reachable_worklist`); env knobs
  `ASM_SOFT404_DETECT=0` (revert to literal-404), `ASM_SOFT404_SIZE_TOL_BYTES`.
  **Validated live on Juice Shop**: an 8-entry real+phantom worklist kept the 3 real endpoints + 1
  auth-gated 401 path and dropped both 500-phantoms and both SPA-200 catch-alls; on a full recon
  worklist the harvest went **1138 → 480 (658 / 58% phantoms dropped)**, versus A1's 1137 → 1137
  (0 dropped) on the same target.

### A2 — Inventory bloat / GC + reachability lifecycle  ✅ FIXED
- **Evidence:** rows / distinct-paths — Juice Shop **9391 / 2339**, honey **5394 / 852**,
  crAPI **2351 / 307**. Most Juice Shop "paths" are synthetic permutations (4475 versioned,
  1677 `/api/{Resource}s/…`) that A1 could not drop (they soft-404). There was **no HTTP-status
  reachability column** — `last_attempt_status` holds the *lease lifecycle* (`leased`/`completed`),
  not the response code — and **nothing ever set `test_status='gone'`** (the status was honored by
  the dispatcher but had no writer), so dead endpoints were re-tested every `stale_days` forever.
- **Fix (done):**
  1. **Schema** (`db/init.sql` + `run_schema_migrations`): `last_http_status`,
     `unreachable_streak`, `last_reachability_at` on `target_endpoints`.
  2. **`sweep_endpoint_reachability`** (`api/asm_inventory.py`): re-probes existing non-`gone` rows
     (least-recently-swept first, so bounded runs rotate the whole inventory), records the status,
     bumps `unreachable_streak` on 404/soft-404 (resets it on reachable), and **retires to `gone`**
     at `ASM_GONE_STREAK_THRESHOLD` confirmations. Reuses the A3 soft-404 signature logic, so it
     handles soft-404 apps too. Retirement is **reversible** — re-discovery resets `gone`→`untested`
     (existing `upsert_endpoints` logic), so an endpoint that returns later comes back.
  3. **On-demand GC**: `POST /targets/{id}/asm/prune` runs the sweep and reports retired counts.
  4. **Automatic**: `process_scan_job` runs a bounded sweep (`ASM_SCAN_SWEEP_MAX`, default 400)
     after each scan's inventory upsert, so the inventory self-heals incrementally over time.
  - The dispatcher already excludes `gone` (`claim_test_batch`), so retired phantoms drop out of the
    testable set and the coverage denominator immediately.
- **Validated live on honey**: one prune retired **4022 / 5395 rows (75%)** to `gone` in ~21 s —
  and was *precise*: it kept real 200 endpoints even inside a mostly-phantom prefix
  (`/api/ai-redteam/course` 200 kept while `/api/ai-redteam/llm_app` 404 retired), and the gaps
  recommendation dropped from "test all 5395" to "1194 untested" real endpoints.
- **Answers the lifecycle question:** phantom/dead endpoints are now retired (not re-scanned
  forever), cleanup runs both on-demand and automatically, and endpoints that come back are
  auto-resurrected — so we do **not** scan vanished endpoints indefinitely.

### A4 — Cap synthetic endpoint permutation  🟡 MEDIUM
- **Evidence:** 4475 versioned + 1677 resource-permuted Juice Shop paths, the bulk phantom.
- **Fix:** gate synthetic/version-permutation generation behind A3 reachability and/or cap the
  permutation breadth so generation can't dominate the worklist before filtering.

### P5 — Dynamic-coverage batch granularity  🟢 LOW
- **Evidence:** dynamic shard durations spread 228–1319 s (~6×) on Juice Shop; with
  `batch_size=150` the final claimed batch runs long while earlier workers idle.
- **Fix:** taper the claimed batch size as the worklist drains (smaller terminal batches) so the
  long-tail batch can't dominate wall-clock. Minor — the pull model already balances the bulk.

### P6 — API-scaled worker logs are invisible  🟢 LOW (observability)
- **Evidence:** plan jobs for the new scans ran on API-scaled workers 6–10, whose logs are **not**
  captured by `docker compose logs worker` (only the compose replicas) — the fan-out lines were
  invisible until querying each container directly.
- **Fix:** a `scanner.sh logs` mode that aggregates *all* `shakerscan-worker-*` containers, not just
  compose-managed ones.

### Round 2 status
1. **A3** (soft-404 detection) — ✅ fixed (`6736dea`).
2. **A2** (reachability persistence + `gone`-retirement + GC sweep) — ✅ fixed; validated live
   (honey 4022/5395 retired, real endpoints preserved, dispatcher excludes them).
3. **Remaining:** **A4** (cap synthetic permutation — stop generating phantoms at the source),
   **P5 / P6** (batch taper, all-worker logs), and the **P1 follow-up** (code-version handshake).
