# Parallel Scanning Architecture — Design & Implementation Plan

**Status:** Phase 0 + Phase 1 core implemented & deployed; Phase 2 deferred
**Date:** 2026-06-14 (implemented 2026-06-15)
**Author:** Architecture audit (Claude Code)
**Scope:** Make a single logical scan of one target fan out across the worker fleet; expand dictionaries, checks, and budgets that this parallelism makes affordable.

---

## Implementation status (2026-06-15)

**Shipped & verified end-to-end:**
- **Parent → plan → shard → merge orchestration** on the existing Redis queue. New job types `scan_plan` / `scan_shard` / `scan_merge` routed in `api/worker.py::process_job`. Planner in `api/parallel_scan.py`.
- **DB:** `scans.parent_scan_id`, `scan_role`, `shard_index`, `shard_count` (+ `idx_scans_parent`), in `db/init.sql` and `run_schema_migrations()`.
- **API:** `POST /scans` accepts `options.parallel`, `options.shards`, `options.shard_strategy`. Omitted `options.parallel` now follows `/settings/scan-execution` auto-sharding policy; explicit `parallel:false` forces standalone and explicit `parallel:true` forces a parent scan. `GET /scans/{id}` returns a `shard_rollup` + per-shard list for parents. Shard rows hidden from `GET /scans` by default (`include_shards=true` to show).
- **Two strategies:** `scope` (partition `custom_endpoints` across shards with small per-shard discovery/active budgets — real speed-up) and `family` (broad + deeper SQLi/XSS focused shards — more coverage/budget). `auto` picks scope when ≥2 endpoints are present.
- **Barrier + merge:** Redis SET-NX guarded `reconcile_parallel_parent`; last shard to reach all-terminal enqueues the merge. Stale checker exempts parents and reconciles when a shard is failed (robust to crashed shards). Merge dedupes the finding union (canonical fingerprint), recomputes attack chains over the union, persists findings under the parent, computes a conservative aggregate score, queues auto-retests once.
- **Cancellation safety:** parent cancellation fans out to queued/running shard rows, sets child cancel flags, blocks/short-circuits merge, and prevents late shard output from overwriting cancelled rows. The scanner subprocess still does not poll the cancel flag mid-run.
- **Target stats safety:** shard rows are excluded from target `total_scans`, `latest_scans`, and dashboard scan counts; only standalone scans and parallel parents count as logical scans.
- **UI controls:** Settings exposes one `Auto-shard eligible scans` toggle. New Scan exposes `Auto`, `Normal`, and `Parallel`; shard count/strategy/endpoint input are tucked behind `Parallel tuning` only when Parallel is forced. Scans rerun actions stay one item per scan type and rely on the global auto policy. Scan Detail shows parent shard rollup.
- **Phase 0 dictionaries:** first-class `custom_wordlist` (inline keywords → ffuf, via `SHAKERSCAN_CUSTOM_WORDLIST`) and file/inline-driven `custom_sqli_payloads` / `custom_xss_payloads` (drop-in `payloads/<cat>/custom.txt` or `SHAKERSCAN_CUSTOM_<CAT>_PAYLOADS`), appended additively in `_select_sqli_payloads` / `_select_xss_payloads`.
- **Tests:** `tests/test_parallel_scan.py`, `tests/test_custom_dictionaries.py`, scan budget coverage in `tests/test_scan_budget_profiles.py`, and auto-sharding policy coverage in `tests/test_api_scan_option_masking.py`. Verified live on Juice Shop after rebuilding images: auto scope run completed and merged 4/4 shards into one parent in 195s (2 deduped findings); family run completed 3/3 shards and merged duplicate findings under the parent.

**Deferred (Phase 2, documented below):** the build_report carve-out for true "discover-once then endpoint-slice" raw speed-up (family currently repeats discovery per shard — depth over speed); a first-class check registry; cooperative cancellation polling inside the scanner subprocess; richer UI breakdowns for shard coverage contribution.

---

## Product behavior

Parallel scanning is both a user-selectable execution mode and an optional global
automation policy. Standalone scans remain the default unless the
`Auto-shard eligible scans` setting is enabled or a request explicitly sends
`parallel:true`.

User-facing rules:

- **Settings:** one on/off switch controls automatic sharding. The UI does not expose
  every planner knob because that would make routine scan submission noisy.
- **New Scan:** users choose `Auto`, `Normal`, or `Parallel`. `Auto` follows the
  global setting. `Normal` sends `parallel:false` and always stays single-worker.
  `Parallel` sends `parallel:true`; advanced shard count, strategy, and endpoint
  input are available only inside an expandable `Parallel tuning` area.
- **Scans page rerun:** reruns stay one action per scan type. If the global setting is
  on, eligible reruns auto-shard; if it is off, they stay standalone.
- **Scan Detail:** parent scans show a shard rollup. Child shard rows are implementation
  details and are hidden from the main Scans list unless the API caller explicitly asks
  for `include_shards=true`.
- **Automatic enablement:** off by default for compatibility. When enabled, it applies
  only to scans that can produce at least two useful shards: Smart/Full/Aggressive
  active scans, or any DAST scan with at least two explicit `custom_endpoints`.

Performance expectations:

- **Fastest real speed-up today:** `parallel=true` + `scope` strategy + at least two
  `custom_endpoints`. Each shard receives a distinct endpoint slice plus internal
  child-only caps for discovery, Phase 4, active checks, and BOLA endpoint count. Those
  caps are not separate UI settings; they are part of making known-endpoint sharding
  behave like a fast execution mode.
- **More depth in parallel today:** Smart, Full, and Aggressive can use `family`
  strategy: broad + SQLi-focused + XSS-focused shards. This often improves coverage in
  the same wall-clock window, but each shard still repeats discovery/pre-scan work.
- **Auto mode today:** when enabled, API submission, batch scans, target scans, schedules,
  and Scans-page reruns all use the same policy. Explicit Normal/Parallel on New Scan
  overrides the global policy for that scan only.
- **Still deferred:** the ideal "discover once, build endpoint worklist once, then shard
  active checks" scanner refactor. That is the Phase 2 scanner-stage extraction below.

Productization plan:

1. **Expose parallel execution safely without overwhelming the UI.** Implemented:
   Settings has one auto-shard toggle; New Scan has Auto/Normal/Parallel; detailed
   shard controls are hidden behind Parallel tuning; Scans rerun menus stay compact.
2. **Keep one logical scan visible.** Implemented: shard rows are hidden from the Scans
   list by default, parent rows are labeled as Parallel, and Scan Detail shows a shard
   rollup for parent scans.
3. **Keep cancellation/state safe.** Implemented: cancelling a parent cancels child rows,
   blocks merge, and prevents late shard writes from reviving cancelled scans.
4. **Make statistics count logical scans.** Implemented: shard rows are excluded from
   target scan totals, latest-scan views, and dashboard scan counts.
5. **Implement true scanner-stage sharding.** Deferred: extract recon/discovery into a
   reusable stage, persist the endpoint worklist/context, then run active checks over
   endpoint slices without repeating discovery per shard.

---

## 1. Goals (restated from the request)

1. **Run checks in parallel** when multiple workers ("agents") are available, instead of one scan running its phases serially on one worker.
2. **Parallel scans of the same target** — split one target's work across many workers and merge into a single report.
3. **Additional dictionaries / keyword lists** — pluggable wordlists and payload sets.
4. **Additional checks** — easier path to register new active/passive modules.
5. **Maximum / larger budget** — exploit the lower wall-clock that parallelism buys to run much deeper (exhaustive) scans.
6. **Orchestration recommendation** — "subagents somehow or else, you tell me."

The headline answer to #6 is in §4: **use the existing Redis queue + worker fleet as the parallelism substrate (a parent/coordinator + shard model), not Claude subagents.** The reasons are below.

---

## 2. Current architecture (audited)

### 2.1 Queue & worker model
- **Submit:** `POST /scans` writes a `scans` row (`status='pending'`) and `RPUSH`es a job onto the Redis list `scan_jobs` (`api/api.py:6730-6824`, queue name `api/worker.py:52-53`).
- **Consume:** each worker process runs one blocking `BLPOP scan_jobs/retest_jobs` loop and processes **one job to completion before popping the next** (`api/worker.py:3646-3703`). Scan execution spawns the scanner as a subprocess.
- **Scale:** `POST /workers` (1–20) drives the Docker socket to add/remove identical `shakerscan-oss-worker-N` replicas (`api/api.py:9120-9250`, `docker-compose.yml:120-193`). Workers are **stateless, no per-target affinity, no sharding.**
- **Concurrency today:** `N workers × 1 scan = N parallel scans`, but **each individual scan is single-worker and internally serial**.

### 2.2 Concurrency safety that already exists (key enabler)
- Findings are de-duplicated at the DB by `UNIQUE(target_id, fingerprint)` plus `SELECT … FOR UPDATE` + `INSERT … ON CONFLICT DO NOTHING` (`db/init.sql:354-355`, `api/worker.py:1074-1268`). **Concurrent writes from multiple workers against the same target are already race-safe.** This is the single most important fact for parallelizing one target.
- **No global scan lock** — two workers can already scan the same target simultaneously; nothing coordinates them today.

### 2.3 The retest queue is a working precedent for fan-out
- Separate Redis list `retest_jobs`, **slot-limited** parallelism via a Redis `INCR/DECR` counter (`RETEST_MAX_PARALLEL`, default 2), a SETNX **watchdog lock** for stale recovery, and exponential-backoff requeue (`api/worker.py:85-88, 3083-3505`). The parent/child scan model in §5 reuses exactly these primitives.

### 2.4 Single-scan orchestrator is phase-serial
`scanner/scanner.py::build_report()` (~lines 2254–12200) runs as a **waterfall**:

```
Baseline infra ─► Discovery (katana+browser) ─► Nuclei (staged) ─► Passive (P2)
   ─► Client-side (P3a) ─► Infra-leak (P3b) ─► Active web checks (P4) ─► Smart active XSS/SQLi (P5) ─► Report
```

- Tasks within a phase are created with `asyncio.create_task` but **awaited one by one** (parallel I/O, serial collection) — `scanner.py:3176-3632`, `4430-4445`, `4894-4920`.
- **Hard barriers:** Discovery must finish before Nuclei/P2–P5 (everything needs `crawl_urls`); Nuclei signals feed P5 endpoint prioritization; DBMS fingerprint from the first SQLi probe steers later payloads.
- **The deepest serial cost is P5** — `smart_sqli_test`/`smart_xss_test` are nested `for endpoint → for param → for payload → curl` loops with **no parallelism at all** (`scanner_tools/active_checks.py:5650-5900, 6569-6800`). This is the prime target for fan-out.

### 2.5 Budgets, dictionaries, checks (extensibility today)
- **Budgets:** `SCAN_BUDGET_DEFAULTS[scan_type][profile]` matrix in `scanner/constants.py:50-205`; profiles `fast|balanced|thorough|exhaustive`; overridable with `custom_budget` (capped at the exhaustive ceiling). Knobs: `max_urls`, `browser_max_pages`, `nuclei_max_targets`, `active_max_seconds`, `active_max_endpoints`, `active_params_per_endpoint`, etc.
- **Wordlists:** 6 bundled lists in `scanner/wordlists/`, loaded via `WORDLIST_PATHS` + `_read_wordlist()` (`discovery.py:164-185`); ffuf list chosen per scan_type (`discovery.py:1533-1545`). **No first-class user wordlist option** (only `custom_endpoints`).
- **Payloads:** 9 files in `scanner/payloads/`, but most active payloads are **hardcoded** in `active_checks.py`/`constants.py`; only JWT secrets load from file (`_load_jwt_secrets_wordlist`, `active_checks.py:3191-3207`).
- **Checks:** ~73 modules in `scanner_tools/`; **no registry** — each check is a boolean parameter on `build_report()` wired at ~5 edit sites (import, signature, task-create, await, consume). Mapped to scan_type in `api/worker.py:575-610`.

---

## 3. What is parallelizable vs. what is a barrier

| Stage | Parallelizable? | Axis | Barrier / merge concern |
|---|---|---|---|
| Baseline infra (DNS/TLS/headers) | Already async; low value to shard | per-check | none |
| **Discovery** | **No** — produces the work-list | — | hard barrier; everything downstream needs `crawl_urls` |
| Nuclei | Internally multi-core (subprocess) | template chunk | signals feed P5; global early-stop |
| Passive P2 / Client P3 / Infra P3b | **Yes** | per-check-family | independent; just merge findings |
| Active web checks P4 | **Yes** | per-check-family | shared P4 deadline |
| **Smart active P5 (SQLi/XSS)** | **Yes — highest value** | **per-endpoint slice** | DBMS fingerprint broadcast; global finding cap; global early-stop |
| Attack-chain + AI correlation | **No** | — | needs the **full** finding set → runs once after merge |
| Report assembly / score | **No** | — | single coordinator |

**Conclusion:** the natural shape is **discover once, fan out the per-endpoint and per-family work, then merge and correlate once.** This is scatter-gather / map-reduce.

---

## 4. Orchestration choice (the "subagents or else" question)

| Option | Fit | Verdict |
|---|---|---|
| **A. Redis queue + worker fleet (parent + shard jobs)** | Reuses existing durable queue, scaling API, finding-dedup, and the retest slot/watchdog precedent. Survives worker crashes; scales with `POST /workers`. | **Recommended.** Lowest new infra, highest reuse. |
| B. Claude/LLM subagents orchestrating scans | Subagents are for *interactive* AI security work (the AI session, AI Gate judging). They are not durable workers, not horizontally pooled, and shouldn't be in the throughput path of a DAST scan. | Reject for throughput. Keep subagents for the interactive `/ai-security-session` only. |
| C. External engine (Celery / Temporal / Arq) | Real workflow features (retries, barriers, signals) but a large new dependency and operational surface. | Overkill now; the Redis primitives already cover what we need. Revisit only if orchestration logic outgrows Redis. |

**Recommendation: Option A.** Introduce a **coordinator/shard** job model on top of the queue we already have. "Multiple agents" = the worker replicas; orchestration = a parent scan that emits child shard jobs and a merge job.

---

## 5. Target architecture — parent/coordinator + shards (scatter-gather)

A parallel scan becomes **three job types** routed exactly like the existing `discovery` / `finding_retest` types in `process_job()` (`api/worker.py`):

```
                       POST /scans {parallel:true, shards:N}
                                   │
                                   ▼
                        ┌─────────────────────┐
        scan_plan ──────►  PLAN / RECON STAGE  │  (1 worker)
                        │  baseline+discovery  │
                        │  +nuclei signals     │
                        │  → shared context    │
                        └─────────┬───────────┘
                                  │ writes scan:{parent}:context (Redis/DB)
                                  │ enqueues N scan_shard jobs + 1 barrier
                 ┌────────────────┼────────────────┐
                 ▼                ▼                ▼
   scan_shard #0          scan_shard #1     scan_shard #2     (any free workers)
   endpoints[0:k]+P2..    endpoints[k:2k]   families {...}
   rehydrate context      rehydrate ctx     rehydrate ctx
   write findings (dedup) write findings    write findings
   write shard result     ...               ...
                 └────────────────┼────────────────┘
                                  │ last shard to finish (atomic DECR == 0)
                                  ▼
                        ┌─────────────────────┐
        scan_merge ─────►   MERGE / CORRELATE  │  (1 worker)
                        │  coverage merge      │
                        │  attack-chain + AI   │
                        │  score/grade         │
                        │  write parent result │
                        └─────────────────────┘
```

### 5.1 Stage 1 — Plan/Recon (single worker, `scan_plan`)
Runs baseline + discovery + a fast nuclei signal pass, then **persists a shared scan context**:
- `crawl_urls`, the built **(endpoint, param) work-list**, tech stack, nuclei signals, DBMS hints, and a **serialized auth recipe** (cookies/headers/token + re-auth instructions from `auth_session.py`).
- Stored at `scan:{parent_id}:context` (Redis blob, or a `scan_contexts` row for durability).
- Computes the shard plan: how to slice the work-list (§6) and the **per-shard sub-budget** (§7).
- Enqueues N `scan_shard` jobs and initializes the barrier counter `scan:{parent_id}:shards:remaining = N`.

### 5.2 Stage 2 — Shards (N workers, `scan_shard`)
Each shard:
- Rehydrates the shared context (no re-discovery, no re-auth from scratch).
- Runs **only its slice**: an endpoint range for P5 and/or a set of check families for P2–P4.
- Writes findings normally — **the existing `UNIQUE(target_id, fingerprint)` dedup makes cross-shard duplicates collapse automatically** (§2.2). Tag each finding with `parent_scan_id` so the merge can count/own them.
- Honors shared coordination counters (finding caps, early-stop — §7) via Redis `INCR`, mirroring the retest slot pattern.
- Writes a compact `scan:{parent_id}:shard:{i}` result blob (coverage metrics, per-family stats, errors).
- On finish, `DECR scan:{parent_id}:shards:remaining`; **the worker that hits 0 enqueues the `scan_merge` job** (same "last one out" trick the retest watchdog uses).

### 5.3 Stage 3 — Merge/Correlate (single worker, `scan_merge`)
- Loads all shard blobs + the target's findings for this parent.
- **Merges coverage** via the existing `CoverageTracker.merge()` (`coverage_tracker.py:180-225`).
- Runs **attack-chain correlation and AI correlation once on the full finding set** (these inherently need everything — `attack_chains.analyze_attack_chains`).
- Computes score/grade, writes the parent `scans.result`, flips parent `status='completed'`.

### 5.4 Failure & lifecycle handling
- **Stale shards:** reuse the retest watchdog idea — a SETNX-locked reaper requeues or fails shards whose heartbeat expired, then still drives the barrier so merge isn't blocked forever.
- **Partial success:** merge proceeds with whatever shards completed; parent result records `shards_succeeded/shards_total` and degrades grade confidence rather than failing the whole scan.
- **Cancellation:** parent cancellation fans out to child shard rows and Redis cancel flags. Workers and merge jobs treat cancelled rows as terminal and refuse to overwrite them with late output. Remaining work: make the scanner subprocess poll `scan:{id}:cancel` so cancellation stops active probes earlier instead of only preserving final state.
- **Idempotency:** shard jobs carry `(parent_id, shard_index, attempt)` like retest jobs so requeues don't double-run.

---

## 6. Sharding strategies (pick per scan, combine)

1. **By endpoint slice (intra-target, primary):** split the P5 work-list into N contiguous slices; each shard runs `smart_sqli_test`/`smart_xss_test` over its slice. Highest speedup because P5 is the serial bottleneck. Requires DBMS fingerprint broadcast (compute once in plan stage, put in context).
2. **By check family:** assign disjoint families (e.g. shard A = {file_upload, open_redirect, host_header}, shard B = {csrf, idor, path_traversal}, …) for P2–P4. Good when one target has few endpoints but many check types.
3. **By URL scope / sub-path / subdomain (inter-target):** for large estates, shard by path prefix or subdomain. Works **today with almost no refactor** because there are no scan locks (see Phase 0).
4. **By nuclei template category:** chunk template families across shards if Nuclei dominates wall-clock.

The plan stage chooses a strategy mix from target shape (endpoint count, family count) and shard budget.

---

## 7. Budget coordination under parallelism

Splitting work means the **global budget must be split or shared**, or shards will collectively do N× the intended work:

- **Time:** divide `active_max_seconds` by shard count, or give each shard the full window but cap total via a shared deadline `scan:{parent}:deadline`.
- **Finding caps (`max_findings_per_family`):** make them **global** with a Redis `INCR` counter per family (`scan:{parent}:cap:{family}`) — exactly the retest-slot mechanism. A shard checks the counter before continuing.
- **Early-stop (confidence-weighted ≥ 12):** today each scan early-stops independently (`nuclei.py:1361-1410`). For one logical scan, accumulate the weighted score in `scan:{parent}:score`; any shard that pushes it past threshold sets `scan:{parent}:stop=1`, which all shards poll. (Or, for "max budget" scans, simply disable early-stop — see below.)

**The synergy with "larger budget":** because wall-clock now scales with worker count, you can safely default parallel scans to **`budget_profile: exhaustive` with `no_early_stop`** and far higher `active_max_endpoints` / `max_urls` — the whole point of parallelism is to make the deepest scans finish in reasonable time.

---

## 8. Dictionaries & checks expansion (rides on the same change)

### 8.1 First-class custom wordlists
- Add `custom_wordlists` / `wordlist_profile` to scan options; resolve user-supplied paths in `WORDLIST_PATHS` (`discovery.py:164-185`) and let ffuf selection (`discovery.py:1533-1545`) accept them. Ship larger bundled lists (e.g. SecLists subsets) gated behind the deeper profiles.
- Parallelism makes big lists practical: shard the ffuf/content-discovery space across workers by wordlist chunk.

### 8.2 File-driven payload sets
- Generalize the JWT loader pattern (`_load_*_wordlist`, `active_checks.py:3191-3207`) into a shared `load_payloads(category, fallback)` helper and convert the currently-hardcoded SQLi/XSS payload tables to **file + inline-default** so users can drop in `payloads/<category>/<name>.txt`. The files already exist (`payloads/sqli/*`, `payloads/xss/*`, `payloads/ssrf/*`, `payloads/lfi/*`) but most are unused — wire them in.

### 8.3 A real check registry (removes the 5-edit-site tax)
- Replace the scattered boolean-parameter wiring with a **registry** (`CHECK_REGISTRY: list[CheckSpec]` with `name, phase, family, fn, default_profiles, is_active`). `build_report()` iterates the registry per phase; adding a check = one registry entry + module. This also lets the **plan stage assign families to shards declaratively** (§6.2) and lets budgets/scan-types reference families by name.

---

## 9. Data-model & API changes

**`scans` table (additive):**
- `parent_scan_id UUID NULL` (FK to scans.id) — shard/merge rows point at the parent.
- `scan_role TEXT` ∈ {`standalone`,`plan`,`shard`,`merge`} (default `standalone` — fully backward compatible).
- `shard_index INT NULL`, `shard_count INT NULL`.
- index on `(parent_scan_id)`.
- Schema change goes in **both** `db/init.sql` and `run_schema_migrations()` in `api/retest_contract.py` (per project convention).

**Findings:** add `parent_scan_id` (or reuse `scan_id` = parent on merge) so the merge stage can own/count findings produced by shards.

**Redis keys:** `scan:{parent}:context`, `scan:{parent}:shards:remaining`, `scan:{parent}:cap:{family}`, `scan:{parent}:score`, `scan:{parent}:stop`, `scan:{parent}:deadline`, `scan:{parent}:shard:{i}` (result), `scan:{parent}:cancel`.

**API:** `POST /scans` gains `options.parallel: bool`, `options.shards: int|"auto"`, `options.shard_strategy: "endpoint"|"family"|"scope"|"auto"`. `GET /scans/{id}` returns parent rollup (`shard_count`, `shards_completed`, aggregate progress). The Scans UI shows the parent as one row with a shard sub-progress bar (mirror the retest history UI you already built).

**Worker routing:** extend `process_job()` with `scan_plan` / `scan_shard` / `scan_merge` next to the existing `discovery` / `finding_retest` branches (`api/worker.py:3367`+).

---

## 10. Scanner refactor (the real lift)

`build_report()` is a ~10k-line monolith. To shard cleanly, extract three callable stages that pass an explicit context object instead of recomputing:

1. `run_recon_stage(target, options) -> ScanContext` (baseline + discovery + signals + auth recipe + work-list).
2. `run_shard_stage(ScanContext, slice_spec, sub_budget) -> ShardResult` (the P2–P5 work for one slice; **must accept injected `crawl_urls`/dbms/auth and skip re-discovery**).
3. `merge_reports(ScanContext, [ShardResult]) -> Report` (coverage merge + attack chains + AI correlation + score).

Do this **incrementally**: first carve `run_recon_stage` out (it already roughly exists as the discovery block), then make P5 accept an endpoint slice (smallest, highest-value change), then generalize to families. The single-worker path becomes `merge_reports([run_shard_stage(ctx, full_slice)])` so existing behavior is preserved and testable side-by-side.

---

## 11. Phased delivery plan

**Phase 0 — Quick wins (days, low risk, no scanner refactor)**
- Expose `custom_wordlists` + file-driven payloads (§8.1–8.2).
- Default parallel-capable profiles to `exhaustive` + `no_early_stop`; document `custom_budget` ceilings.
- **Scope-sharding via a "scan group":** a thin API that, for a domain/subdomain/path list, submits N independent existing-style scans (already race-safe) and presents them as one group in the UI. Delivers real parallel-of-same-estate immediately and proves the merge/rollup UI.

**Phase 1 — Intra-target fan-out (the core feature)**
- DB + Redis + job-routing changes (§9).
- Extract `run_recon_stage` and shared `ScanContext`; implement `scan_plan` → `scan_shard` (endpoint-slice strategy) → `scan_merge`.
- Reuse retest slot/watchdog primitives for the barrier and stale recovery.
- Global finding-cap + early-stop counters (§7).

**Phase 2 — Breadth & polish**
- Family-based and nuclei-category sharding (§6.2/6.4).
- Check registry refactor (§8.3).
- Cooperative cancel polling in the scanner subprocess (see Risks).
- UI: parent progress with per-shard breakdown; coverage shows shard contribution.

---

## 12. Risks & mitigations

- **Scanner monolith refactor risk.** Mitigate by keeping the single-worker path as `merge([shard(full)])` and golden-diffing reports against current output before/after.
- **Cancellation preserves state but does not yet interrupt active subprocess work.** The API now cancels parent/shard rows and prevents late writes from reviving them, but `scanner/scanner.py` still needs to poll `scan:{id}:cancel` to stop active probes early.
- **Auth session sharing across shards.** Stateful logins may not be cleanly serializable; mitigate by capturing a reusable token/cookie recipe in the recon stage and re-authing per shard on expiry (the scanner already re-auths).
- **DBMS-fingerprint coupling.** Broadcast the fingerprint from the recon/plan stage so shards don't each re-detect and diverge.
- **Resource exhaustion.** Each worker uses 2–4 GB / 1–2 cores; fanning one scan to N workers competes with other queued scans. Add a per-parent concurrency cap (Redis slot, like `RETEST_MAX_PARALLEL`) and respect the `POST /workers` ceiling.
- **Budget double-counting.** Without §7's shared counters, N shards do N× the work — make global caps mandatory for parallel scans.
- **Cost of "max budget + exhaustive lists."** Communicate expected wall-clock/resource use; keep these behind explicit opt-in like `full`/`aggressive` already are.

---

## 13. Effort estimate (rough)

| Item | Size |
|---|---|
| Phase 0 (wordlists/payloads/budgets + scan-group scope sharding + UI rollup) | S–M |
| Phase 1 (DB/Redis/routing + recon extraction + endpoint-slice shard + merge + barrier) | L |
| Phase 2 (family sharding + registry + cancel polling + UI) | M–L |

The biggest single item is extracting `run_recon_stage`/`run_shard_stage` from `build_report()`; everything else reuses primitives that already exist (queue, dedup, slot counter, watchdog, coverage merge, attack-chain correlation).

---

## 14. TL;DR recommendation

- **Orchestrate with the worker fleet, not Claude subagents:** a **parent `scan_plan` → N `scan_shard` → `scan_merge`** model on the existing Redis queue.
- **Discover once, fan out per-endpoint (and per-family) work, merge and correlate once.**
- The DB's existing `UNIQUE(target_id, fingerprint)` dedup and the retest queue's slot/watchdog give us race-safe parallel writes and a barrier almost for free.
- **Parallelism is the enabler for "max budget":** once wall-clock scales with workers, default deep scans to exhaustive profiles, bigger wordlists, and file-driven payload sets.
- Ship **Phase 0 scope-sharding + dictionaries now** (low risk), then invest in the **recon/shard/merge refactor** for true intra-target parallelism.

---

## 15. Coverage-gap analysis & next-gen budget plan (2026-06-15)

### What a real family parallel smart scan of Juice Shop showed
Scan `34e8d955` (smart, parallel, `family`, 14m41s, grade B, 4 deduped findings):

| Shard | Profile | Endpoints discovered | Endpoints tested | Coverage |
|---|---|---|---|---|
| 0 broad | balanced | 520 | 100 | **0.192** |
| 1 sqli | thorough | 775 | 150 | 0.194 |
| 2 xss | thorough | 821 | 150 | 0.183 |

- **Only ~19% of discovered endpoints get actively tested**, and the parent report shows just the broad shard's number (`50/680 selected`, coverage 0.19). Juice Shop exposes 500–800+ endpoints; we exploit a sliver.
- **Discovery is repeated per shard and is inconsistent** (520 vs 775 vs 821 discovered) — wasted work, and the focused shards only test their one family per endpoint.
- **`family` adds depth, not breadth.** It never partitions the endpoint space, so endpoint coverage does not rise with more shards.
- **Anonymous auth only** — authenticated surface (the most interesting part of Juice Shop) is untested.
- **Hard ceiling:** even the `exhaustive` profile caps `active_max_endpoints` at **300** < the 520–821 discovered. **No single scan can cover all endpoints — partitioning across shards is mathematically required.**
- **Minor bugs:** the merged parent report's `input.port` shows `8080` (the API port) instead of `3001`; the parent "Coverage Budget" card reflects only the broad shard's balanced budget, not the aggregate.

### Implementation status (shipped 2026-06-15)
All items below are implemented, tested, and deployed.

**Full-worklist emit (closes coverage to ~100%, universal):** the scanner now emits its
complete pre-cap active worklist at `report['active_checks']['active_worklist']` (custom-endpoint
strings, capped by `custom_budget.active_worklist_max`, default 5000). `coverage` recon harvests
that instead of lossy discovery samples. Verified live on Juice Shop: recon harvested **1378
endpoints** (vs 390 from samples) and fanned out **18 disjoint coverage shards of ~77 each**.

**Huge budgets on demand:** `custom_budget` overrides are now capped at the generous
`SCAN_BUDGET_CEILINGS` (e.g. `active_max_endpoints` 10000, `max_urls` 100000,
`active_max_seconds` 24h) instead of the per-scan-type `exhaustive` profile — so operators can dial
in very large budgets without changing default profile behavior.

**Shard count scales:** `coverage` fans out `N = ceil(worklist / coverage_per_shard_cap)` shards
(default cap 150, tunable per scan), bounded by `COVERAGE_MAX_SHARDS` (32). `auto` scales to the
worker fleet up to `MAX_SHARDS` (12). `family` is intentionally fixed at 3 (broad/sqli/xss — the
only capability lanes the scanner exposes). Concurrency is bounded by the worker fleet; excess
shards queue and run as workers free up.

Also shipped earlier the same day: coverage-aware merge aggregation, `input.port 8080→3001` fix at
source, exploit-depth, auth-state sharding, and a pre-fan-out UI state
("Discovering endpoints once, then sharding…").

### The fix set (in priority order)

1. **Coverage-aware merge (quick, do first).** The merge must **union `smart_coverage` across shards** (tested endpoints/params, `auth_states_tested`, `discovery_sources`) and recompute `coverage = |union tested| / |union discovered|`, instead of inheriting the broad shard's. Also fix `input.port` in the merged report. Without this, none of the breadth work below is even visible. Worker-side only (`process_scan_merge_job`).

2. **`coverage` shard strategy = discover-once + endpoint-worklist partitioning (the headline).** This is the deferred recon carve-out, now the top priority:
   - Plan/recon stage runs discovery **once**, persists the full deduped endpoint worklist (the ~520 unique endpoints) + shared context (tech, DBMS, auth recipe) to Redis.
   - Fan out: partition the worklist round-robin across N shards; each shard runs the **full active suite (all families)** over its slice with **discovery disabled** (inject the worklist).
   - `N = ceil(discovered_endpoints / per_shard_active_cap)` so the union approaches **100% coverage**.
   - Merge (with fix #1) then reports true aggregate coverage.
   - Eliminates the 3× redundant crawl and the 300-endpoint single-scan ceiling.

3. **`saturate` budget profile / auto-sizing.** A profile whose goal is `coverage → 1.0`: it sizes shard count and per-shard caps to the *discovered* endpoint count rather than a fixed number. Pairs with `shards: "auto"` and the worker fleet.

4. **Authenticated & multi-auth-state sharding.** Accept creds/token; shard by auth state (`anonymous`, `user1`, `user2`) so authenticated endpoints and BOLA/IDOR get covered. `auth_states_tested` becomes a first-class coverage axis.

5. **Exploit-depth mode ("exploit all").** Raise per-finding exploitation caps (`sqli_extract_max`, `oob_max_findings`, `max_findings_per_family`) and run attack-chain correlation on the full union, so confirmed issues are driven to proof, not capped at 3.

6. **Hybrid `coverage × family` (the "scan + exploit everything" mode).** Two-level fan-out: partition endpoints across a first axis, and within each partition run deep per-family passes. Highest coverage *and* depth; scales to the fleet/budget directive.

### Going bigger on budget today (no refactor)
Until #2 lands, the largest achievable in one parallel scan: `budget_profile: exhaustive` + `custom_budget` raising `active_max_endpoints` toward the ceiling, plus `scope` strategy with the endpoint list partitioned across shards (each shard ≤300 active endpoints, N shards = ceil(total/300)). That already beats `family` for breadth — it's `coverage` strategy done manually with a known endpoint list.

### Effort
- #1 coverage-merge + port fix: **S** (worker merge only).
- #2 `coverage` strategy (recon carve-out): **L** (the `run_recon_stage` extraction).
- #3 saturate profile: **S–M**. #4 auth sharding: **M**. #5 exploit depth: **S**. #6 hybrid: **M** (composes #2+#4/#5).
