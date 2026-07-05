# Parallel Scanning Architecture — Design & Implementation Plan

**Status:** Parallel-scan core (Phase 0 dictionaries + Phase 1 orchestration) implemented & deployed; high-budget `coverage` mode implemented; zero-rediscovery coverage child execution implemented; dynamic pull-based Full Coverage allocation is now the default for coverage parents, with explicit static slices kept as fallback. Continuous ASM is now documented separately in [continuous-asm-architecture.md](continuous-asm-architecture.md). Current DAST-quality lesson from Juice Shop/crAPI validation: parallelism is the execution substrate, not the goal. The scanner now proves real Critical SQLi and High BOLA/Authz on lab apps, but broad fan-out still needs worker-aware sizing, family-specific campaigns, and browser/stateful XSS/BOLA workflows to consistently raise true High/Critical coverage.
**Date:** 2026-06-23 (core implemented 2026-06-15)
**Author:** Architecture audit (Claude Code)
**Scope:** Make a single logical scan of one target fan out across the worker fleet; expand dictionaries, checks, and budgets that this parallelism makes affordable.

**2026-07-05 audit note:** the parallel substrate is no longer the main product gap. The latest
roadmap is in [proposed-next-steps.md](proposed-next-steps.md): prioritize ASM activity scheduler
state, Action Center remediation CTAs, typed ASM schedule kinds, target campaign timeline, AI
red-team campaign UX, and guided Model Intake trust UX before adding more fan-out knobs. The first
ASM scheduler/dispatcher skip-reason contract is now live in ASM policy/gaps/improve responses and
persisted target metadata; the schedules UI has an ASM coverage-wave bridge, but the API/DB still
encode it through `scan_options.kind='asm_improve'`.

> **How to read this doc.** It is now scoped to one thing: parallel execution for one logical scan.
> 1. **§1–§14 — Parallel scan core (SHIPPED & verified).** The parent→plan→shard→merge design and
>    its implementation status. The "Implementation status" block immediately below is the source of
>    truth for what's live; the design sections behind it are kept for rationale.
> 2. **§15 — `coverage` strategy (SHIPPED).** Discover-once recon → harvest full worklist →
>    partition across auto-sized shards. The bridge from "fan out a scan" to "cover the whole target."
> 3. **§16 — ASM integration boundary.** A short description of how parallel scans feed ASM inventory,
>    with the full ASM current state, target architecture, and roadmap moved to
>    [continuous-asm-architecture.md](continuous-asm-architecture.md).
>
> When design prose and a "SHIPPED"/"Gap" note disagree, the note wins — the prose predates it.

---

## Shared capability status matrix (agent quick read)

This matrix is duplicated only in the two canonical local-execution docs
(`parallel-scan-architecture.md` and `continuous-asm-architecture.md`). It gives AI coding/review
agents one compact starting point before they choose an implementation increment. The docs describe
intended architecture; the current code, migrations, and tests remain the source of truth for
shipped behavior. Every implementation task must verify the current state with search/tests before
editing.

| Capability | Status | Next implementation prompt |
|---|---|---|
| Parallel parent/plan/shard/merge | Shipped | Maintain, harden, and extend only through focused increments. |
| Coverage full-worklist fan-out | Shipped | Keep zero-rediscovery child mode stable while dynamic allocation soaks. |
| ASM endpoint inventory | Shipped | Keep replay/auth identity aligned with scanner telemetry. |
| ASM campaign/lease/attempt foundation | Shipped | Broaden scanner telemetry schemas beyond smart active SQLi/XSS/hash-route DOM XSS and focused BOLA/Auth. |
| Full Coverage dynamic allocation | Default shipped | Keep static fallback available and continue live parity/soak on large targets. |
| Coverage x family dynamic allocation | Shipped for broad/SQLi/XSS; gated Auth/BOLA lanes when preconditions exist | Make shard count worker-aware; run shared recon once, then focused family lanes without diluting SQLi/XSS/BOLA budgets. |
| Known-endpoint distributed rate limits | Shipped | Extend beyond known endpoint batches only when scanner telemetry can budget discovered requests accurately. |
| First-class check registry | Foundation + scanner boundary shipped | Migrate scanner `build_report()` module execution to registry iteration and add more runnable families beyond SQLi/XSS/Auth/BOLA. |
| Operator-facing campaign/ASM UX | Partial; Dashboard Action Center, ASM scheduler-state phase 1, and ASM schedule UI bridge shipped | Surface scheduler state in ASM activity, add Action Center CTAs, make ASM waves a typed schedule kind, then show recurring waves, background dispatcher state, and active blockers in one target timeline. |
| DAST quality benchmark loop | Active workstream | Treat "no XSS on Juice Shop" and "no workflow/write-BOLA on crAPI" as benchmark failures, not acceptable coverage. |
| Multi-node WireGuard POC | Proposed/RFC | Build a two-VPS proof only after local queue/worker invariants stay green. |
| Production multi-node fleet | Proposed/RFC | Add node registry, reliable queue leases, object evidence, and routing. |
| HTTPS broker for untrusted workers | Future | Do not build until owned-fleet primitives are stable. |

---

## Implementation status (2026-06-16)

**Shipped & verified end-to-end:**
- **Parent → plan → shard → merge orchestration** on the existing Redis queue. New job types `scan_plan` / `scan_shard` / `scan_merge` routed in `api/worker.py::process_job`. Planner in `api/parallel_scan.py`.
- **DB:** `scans.parent_scan_id`, `scan_role`, `shard_index`, `shard_count` (+ `idx_scans_parent`), in `db/init.sql` and `run_schema_migrations()`.
- **API:** `POST /scans` accepts `options.parallel`, `options.shards`, `options.shard_strategy`. Omitted `options.parallel` now follows `/settings/scan-execution` auto-sharding policy; explicit `parallel:false` forces standalone and explicit `parallel:true` forces a parent scan. `GET /scans/{id}` returns a `shard_rollup` + per-shard list for parents. Shard rows are hidden from `GET /scans` by default (`include_shards=true` to show); ASM batch/recon implementation rows are also hidden by default (`include_internal=true` to show).
- **Four strategies:** `scope` (partition `custom_endpoints` across shards with small per-shard discovery/active budgets — real speed-up), `family` (broad + deeper SQLi/XSS focused shards — more specialization, but not endpoint partitioning), `coverage` (a discover-once recon harvests the full endpoint worklist, then partitions it across auto-sized shards to test the whole target — see §15), and `coverage_family` (advanced API/AI strategy: broad/SQLi/XSS lanes over the full endpoint worklist, with dynamic campaign allocation by default and static buckets as fallback). Explicit focused requests such as `check_family=bola` or `check_family=auth` keep `coverage_family` to that single approved lane instead of silently expanding to broad/SQLi/XSS. `auto` picks `scope` when ≥2 endpoints are present; otherwise Smart/Full/Aggressive active scans resolve to `coverage` so the default spends parallel capacity on endpoint breadth instead of repeated family discovery. `family` remains explicit. All five (`auto`/`scope`/`family`/`coverage`/`coverage_family`) are accepted by `options.shard_strategy` and `/settings/scan-execution`. The New Scan UI exposes the simple **Full Coverage** path and keeps `coverage_family` out of the primary controls.
- **Barrier + merge:** Redis SET-NX guarded `reconcile_parallel_parent`; last shard to reach all-terminal enqueues the merge at the front of the scan queue so completed parents finalize before more shard work starts. Stale checker exempts parents and reconciles when a shard is failed (robust to crashed shards). Merge dedupes the finding union (canonical fingerprint), recomputes attack chains over the union, persists findings under the parent, computes a conservative aggregate score, queues auto-retests once.
- **Full Coverage campaigns:** `coverage` parents create a `full_coverage` `scan_campaigns` row, link parent and child scan rows through `campaign_id`, and `scan_merge` writes `asm_endpoint_attempts`. Dynamic allocation is the default: the recon harvest is upserted into campaign-scoped inventory and child workers claim endpoint batches through the ASM allocator. The discover-once recon pass strips focused active-family flags (`check_family`, `asm_check_family`, SQLi/XSS booleans) so planning cannot run the real BOLA/Auth/SQLi/XSS pass before fan-out. API/AI callers can force legacy static slices with `coverage_allocation=static`, and operators can set `COVERAGE_ALLOCATION_DEFAULT=static` as a rollback default. New child reports use scanner-proven `active_checks.endpoint_attempts`; old/no-telemetry static reports keep the legacy conservative assigned-slice fallback as partial attempts. Parent reports overlay `smart_coverage.endpoints` from campaign attempt-ledger facts when they exist. Coverage merge still does not promote endpoint `test_status`.
- **Shard concurrency guard:** child shard jobs acquire a Redis slot keyed by parent scan before marking themselves running. The default cap is `PARALLEL_SHARD_MAX_PER_PARENT=4`; API/AI callers can override per scan with `options.shard_concurrency` up to the hard cap. This keeps high-budget coverage scans from overwhelming smaller targets while still allowing large fleets to run many different parents.
- **Global-check de-duplication:** coverage shards still run full active endpoint checks over their assigned slice, but only the first shard per auth state runs target-global exposure/posture probes such as exposed-file discovery, auxiliary API/XXE discovery, Phase 4 API-security sweeps, and forced browsing. Later shards carry `skip_global_checks=true` and the scanner emits skipped module results, so the merge keeps one logical report without wasting every shard on identical global probes.
- **BOLA auth preservation:** explicit BOLA coverage-family batches claim user1-scoped inventory but preserve the second-user credential on the scanner invocation so cross-principal replay can run. Non-BOLA auth-state shards still scope to one identity and drop unrelated credentials.
- **Active enrichment budget reservation:** smart active checks reserve a tail of the active time budget for SQLMap/NoSQL/stored-XSS/DOM-XSS/auxiliary enrichment. A large endpoint slice can exhaust its primary SQLi/XSS loop without causing every enrichment module to be skipped; post-active modules skip only when the combined active/enrichment budget is genuinely exhausted.
- **Cancellation safety:** parent cancellation fans out to queued/running shard rows, sets child cancel flags, blocks/short-circuits merge, and prevents late shard output from overwriting cancelled rows. Workers now launch scanner subprocesses in their own process group and poll `scan:{id}:cancel`, so active shard subprocesses are terminated instead of running to natural completion after cancellation.
- **Target stats safety:** shard rows are excluded from target `total_scans`, `latest_scans`, and dashboard scan counts; only standalone scans and parallel parents count as logical scans.
- **UI controls:** Settings exposes one `Auto-shard eligible scans` toggle. New Scan exposes `Auto`, `Normal`, and `Parallel`; shard count/strategy/endpoint input are tucked behind `Parallel tuning` only when Parallel is forced. Scans rerun actions stay one item per scan type and rely on the global auto policy. Scan Detail shows parent shard rollup, compact per-shard contribution facts (endpoint attempts/assignment, family, auth, active budget, telemetry statuses), and a compact Full Coverage campaign endpoint rollup when attempt-ledger facts exist.
- **Phase 0 dictionaries:** first-class `custom_wordlist` (inline keywords → ffuf, via `SHAKERSCAN_CUSTOM_WORDLIST`) and file/inline-driven `custom_sqli_payloads` / `custom_xss_payloads` (drop-in `payloads/<cat>/custom.txt` or `SHAKERSCAN_CUSTOM_<CAT>_PAYLOADS`), appended additively in `_select_sqli_payloads` / `_select_xss_payloads`.
- **Tests:** `tests/test_parallel_scan.py`, `tests/test_coverage_strategy.py`, `tests/test_worker_scan_ai_gating.py`, `tests/test_active_checks.py`, `tests/test_custom_dictionaries.py`, scan budget coverage in `tests/test_scan_budget_profiles.py`, auto-sharding policy coverage in `tests/test_api_scan_option_masking.py`, and active enrichment budget coverage in `tests/test_active_enrichment_policy.py`. Current focused tests assert that auto active scans resolve to coverage, dynamic batches use the smaller default caps, and explicit scope/family behavior remains available.

**Discover-once + zero-rediscovery children are now implemented** as the `coverage` strategy (§15):
the plan stage runs one discovery-focused recon, harvests the scanner's full emitted worklist, and
partitions it across shards. Coverage child shards carry `zero_rediscovery=true`, pass
`--zero-rediscovery` to the scanner, skip crawl/recursive/JS/json/OPTIONS/Nuclei discovery, and run
active checks over only their assigned endpoint slice. Duplicate target-global probes are still
suppressed after the first shard per auth state.

**Still deferred (Phase 2):** full `build_report()` module iteration from the first-class check
registry; deeper in-scanner cooperative cancellation checkpoints between long active-check loops;
request-accurate budgets for internally discovered standalone scans; and more runnable focused
families beyond SQLi/XSS/Auth/BOLA.

---

## Current DAST quality lessons (2026-06-19)

Live Juice Shop and crAPI validation changed the interpretation of "parallel scanning":

- **What is working:** focused runs now find real, verified issues: Juice Shop produces Critical
  SQLi on `/rest/products/search` and `/rest/user/login`; **browser-proven High DOM XSS on the
  `#/search` hash route** (the iframe `javascript:`/`srcdoc` vector that survives Angular's
  sanitizer — previously missed); BFLA on `/api/Users` and `/metrics`; and crAPI produces High
  cross-principal BOLA/Authz findings through `smart_authz`. Benchmark scorecards live under
  `scripts/benchmark_targets.py` + `tests/fixtures/benchmarks/*.yaml` (verified vs suspected, coverage,
  per-target gates) so regressions are visible.
- **What is not working yet:** stored XSS (store-then-render proof) and reflected XSS beyond the hash
  route are still partial; NoSQLi on discovered GET endpoints is limited; broad all-family runs can
  over-shard badly; and BOLA depth is still mostly read-side, not workflow/write-side. Note: **parallel
  `coverage` mode detects FEWER crit/high than a single Smart scan** on apps like Juice Shop because
  coverage children run zero-rediscovery (no browser/DOM-XSS) and fragment the global posture checks.
- **Bad pattern observed:** a broad `coverage_family` Juice Shop run planned 140 shards while only
  three workers were available. That is not "more coverage"; it is queue/merge overhead and delayed
  evidence. Shard count must be bounded by live workers, target size, and campaign class.
- **Correct model:** run shared recon once, build a durable endpoint/app graph, then run focused
  family campaigns over that graph: SQLi, XSS, BOLA/Auth, plus future families. Each family gets its
  own prioritization and proof budget, and merge produces one logical scan report.

Practical rules for new implementation work:

1. **Worker-aware fan-out.** A parent should normally create at most a small multiple of available
   workers for active family lanes. If more endpoints remain, use larger dynamic batches or repeated
   campaign waves, not hundreds of pending shards.
2. **Do not dilute focused families.** `check_family=sqli`, `xss`, `auth`, or `bola` must never be
   silently converted into broad `coverage`. Parallelize the requested family with
   `coverage_family`, or run direct when only one worker/batch is useful.
3. **Shared recon, separate proof lanes.** SQLi, XSS, and BOLA should share browser/HAR/JS/OpenAPI
   discovery, but their active probes should be separate lanes with separate budgets and evidence
   contracts.
4. **XSS needs browser-first proof.** Treat reflected/stored/DOM XSS as a Playwright-backed lane:
   inject into browser-discovered params/forms/content fields, revisit affected views, and capture
   console/screenshot/DOM evidence.
5. **BOLA needs stateful workflows.** The engine should create or harvest fresh object IDs, preserve
   producer->consumer links, replay as user1/user2/anonymous, and eventually support safe
   non-destructive write/BFLA checks under Lab/deep intent.

## Product behavior

Parallel scanning is both a user-selectable execution mode and a global automation policy.
Fresh installs enable `Auto-shard eligible scans` by default, but the policy still only fans
out eligible scans when enough workers are running. Standalone scans remain available through
the New Scan `Normal` choice, an explicit `parallel:false` API request, or by turning the
setting off.

Product caution from the 2026-07-05 audit: users now see three related controls - one-shot
parallel scans, Continuous ASM background policy, and recurring schedules that can queue ASM waves.
The schedules UI already exposes ASM waves, but the API/DB still encode them as
`scan_options.kind='asm_improve'` on normal schedules. The next UX should collapse these into one
target campaign timeline showing "what runs next" and "why nothing ran" instead of exposing them as
independent knobs.

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
- **Automatic enablement:** on by default for fresh installs, bounded by worker availability
  and scan eligibility. Users can turn it off from Settings or force standalone execution
  with New Scan `Normal` / API `parallel:false`. It applies only to scans that can produce
  at least two useful shards: Smart/Full/Aggressive active scans, or any DAST scan with
  at least two explicit `custom_endpoints`.

Performance expectations:

- **Fastest real speed-up today:** `parallel=true` + `scope` strategy + at least two
  `custom_endpoints`. Each shard receives a distinct endpoint slice plus internal
  child-only caps for discovery, Phase 4, active checks, and BOLA endpoint count. Those
  caps are not separate UI settings; they are part of making known-endpoint sharding
  behave like a fast execution mode.
- **More specialization in parallel today:** Smart, Full, and Aggressive can explicitly use
  `family` strategy: broad + SQLi-focused + XSS-focused shards. This can increase depth for
  selected vulnerability families, but each shard still repeats discovery/pre-scan work and does
  not split endpoint load.
- **Most endpoint breadth today:** Smart, Full, and Aggressive can use `coverage`
  strategy, exposed in the UI as **Full Coverage**. The plan job runs one recon scan,
  harvests up to `custom_budget.active_worklist_max` endpoints, partitions them by
  `coverage_per_shard_cap`, and fans out up to `coverage_max_shards` base coverage
  shards. If auth-state sharding is enabled, shards multiply across anonymous/user1/user2
  without dropping endpoint buckets; the planner uses larger endpoint slices when needed.
  The recon pass is endpoint-harvest only: active exploitation and Nuclei are disabled
  there so heavyweight work starts after shard fan-out.
- **Dynamic Full Coverage allocation:** coverage parents default to pull-based allocation.
  Recon still runs once, but child jobs do not receive static `custom_endpoints`; they claim
  campaign-scoped endpoint batches from the ASM allocator at execution time. API/AI callers can
  set `coverage_allocation=static` for the legacy round-robin slice path, or tune dynamic fan-out
  with `coverage_dynamic_batch_size` and `coverage_dynamic_max_batches`.
- **Hybrid endpoint x family depth:** API/AI callers can set `shard_strategy=coverage_family`
  to run the same discover-once recon, then split work into broad, SQLi-focused, and XSS-focused
  lanes. With dynamic allocation, each lane claims campaign-scoped endpoint batches and records
  endpoint+family attempt rows. When primary/second-user auth and Lab/deep intent are present,
  Auth/BOLA lanes may be added explicitly or through the gated family-union path; without those
  preconditions they remain fail-closed. `coverage_allocation=static` remains the rollback path.
- **Auto mode today:** when enabled, API submission, batch scans, target scans, schedules,
  and Scans-page reruns all use the same policy. Active scans without explicit endpoints resolve
  to `coverage`, not `family`; explicit Normal/Parallel on New Scan overrides the global policy
  for that scan only.
- **Zero-rediscovery child mode:** coverage children skip generic crawl/discovery/Nuclei work and
  run active checks only over assigned endpoint slices or dynamically claimed endpoint batches.

Worker-aware sizing requirement:

- Dynamic coverage should prefer **waves** over massive shard counts. Plan enough runnable work to
  keep the current worker fleet busy, then let allocator claims continue until the campaign budget is
  spent. A run with 3 workers should not create 140 active child scan rows just because the endpoint
  graph is large.
- `coverage_dynamic_batch_size`, `coverage_dynamic_max_batches`, and `shard_concurrency` are
  internal pressure controls. They should be resolved from live worker count, target class, and
  family depth unless the caller explicitly overrides them.

API shape for the high-budget path:

```json
{
  "target": "https://example.com",
  "options": {
    "scan_type": "smart",
    "budget_profile": "exhaustive",
    "parallel": true,
    "shard_strategy": "coverage",
    "coverage_allocation": "dynamic",
    "coverage_dynamic_batch_size": 35,
    "coverage_dynamic_max_batches": 256,
    "coverage_per_shard_cap": 35,
    "coverage_max_shards": 128,
    "exploit_depth": true,
    "auth_state_shards": true,
    "custom_budget": {
      "active_worklist_max": 50000,
      "active_params_per_endpoint": 20,
      "max_findings_per_family": -1,
      "sqli_extract_max": 25,
      "oob_max_findings": 25
    }
  }
}
```

Productization plan:

1. **Expose parallel execution safely without overwhelming the UI.** Implemented:
   Settings has one auto-shard toggle; New Scan has Auto/Normal/Parallel; detailed
   shard controls are hidden behind Parallel tuning; Scans rerun menus stay compact.
2. **Keep one logical scan visible.** Implemented: shard rows are hidden from the Scans
   list by default, parent rows are labeled as Parallel, and Scan Detail shows a shard
   rollup for parent scans.
3. **Keep cancellation/state safe.** Implemented: cancelling a parent cancels child rows,
   blocks merge, prevents late shard writes from reviving cancelled scans, and terminates
   running scanner subprocess groups through the worker cancel watchdog.
4. **Make statistics count logical scans.** Implemented: shard rows are excluded from
   target scan totals, latest-scan views, and dashboard scan counts.
5. **Implement true scanner-stage sharding.** Implemented for `coverage` active slices:
   discover once, emit the active worklist, then run zero-rediscovery child scans over dynamic
   allocator claims by default or assigned endpoint slices when static fallback is selected.
   Deferred: richer shard/batch contribution UI.

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

> **Note:** Line numbers in this section are from the original audit (2026-06-14) and drift as the
> code grows — prefer the named symbols (e.g. `submit_scan`, `process_job`). Locate with
> `grep -n 'def submit_scan' api/api.py`. (Example drift: `submit_scan` moved from ~6730 to ~7057.)

### 2.1 Queue & worker model
- **Submit:** `POST /scans` (`submit_scan`, ~`api/api.py:7057`) writes a `scans` row (`status='pending'`) and `RPUSH`es a job onto the Redis list `scan_jobs` (queue name `api/worker.py:52-53`).
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
- **Checks:** `api/check_registry.py` is now the first registry contract for family metadata,
  API validation, ASM focused scheduling, and parallel family shard labels. Scanner internals still
  have legacy `build_report()` wiring, so the remaining work is migrating module execution to
  registry iteration and adding more runnable families beyond SQLi/XSS/Auth/BOLA. Auth is runnable
  only as an explicit credential-gated ASM/API family; BOLA is runnable only as an explicit Lab/deep
  ASM/API family. Neither is an automatic parallel family lane.

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
- **Cancellation:** parent cancellation fans out to child shard rows and Redis cancel flags. Workers and merge jobs treat cancelled rows as terminal and refuse to overwrite them with late output. Worker-level cancel polling terminates the scanner process group; remaining polish is in-scanner cooperative checkpoints so long inner loops can clean up even more gracefully before SIGTERM.
- **Idempotency:** shard jobs carry `(parent_id, shard_index, attempt)` like retest jobs so requeues don't double-run.

---

## 6. Sharding strategies (pick per scan, combine)

> **Shipped names (see §15):** the design descriptions below map to the implemented
> `options.shard_strategy` values: "by endpoint slice" shipped as **`coverage`**, "by check family"
> as **`family`**, "by URL scope / custom_endpoints" as **`scope`**, plus **`auto`**. There is no
> `"endpoint"` strategy value.

1. **By endpoint slice → shipped as `coverage` (intra-target, primary):** discover once, harvest the full worklist, split it across N shards; each shard runs the active suite over its slice. Highest breadth.
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
- **Target concurrency:** implemented with Redis slots (`scan:{parent}:active_shards`). This is intentionally separate from shard count: shard count controls total work/budget, while concurrency controls how much simultaneous pressure one target receives.

**The synergy with "larger budget":** because wall-clock now scales with worker count, you can safely default parallel scans to **`budget_profile: exhaustive` with `no_early_stop`** and far higher `active_max_endpoints` / `max_urls` — the whole point of parallelism is to make the deepest scans finish in reasonable time.

---

## 8. Dictionaries & checks expansion (rides on the same change)

### 8.1 First-class custom wordlists
- Add `custom_wordlists` / `wordlist_profile` to scan options; resolve user-supplied paths in `WORDLIST_PATHS` (`discovery.py:164-185`) and let ffuf selection (`discovery.py:1533-1545`) accept them. Ship larger bundled lists (e.g. SecLists subsets) gated behind the deeper profiles.
- Parallelism makes big lists practical: shard the ffuf/content-discovery space across workers by wordlist chunk.

### 8.2 File-driven payload sets
- Generalize the JWT loader pattern (`_load_*_wordlist`, `active_checks.py:3191-3207`) into a shared `load_payloads(category, fallback)` helper and convert the currently-hardcoded SQLi/XSS payload tables to **file + inline-default** so users can drop in `payloads/<category>/<name>.txt`. The files already exist (`payloads/sqli/*`, `payloads/xss/*`, `payloads/ssrf/*`, `payloads/lfi/*`) but most are unused — wire them in.

### 8.3 A real check registry (removes the 5-edit-site tax)
- Registry foundation is shipped in `api/check_registry.py`: `CHECK_REGISTRY` carries family
  metadata (`name`, `phase`, `family`, profiles, active/risk/auth requirements, telemetry schema,
  scanner option mapping, runnable/planned state), ASM validation rejects unknown or planned-only
  families, and the parallel `family` planner derives the automatic focused SQLi/XSS lanes from the
  registry. High-risk BOLA is registry-runnable only for explicit ASM/API focused requests.
- Scanner boundary wiring is shipped: workers pass registry-selected `asm_check_family` values as
  `--check-family`, the scanner resolves aliases (`sql` -> `sqli`, `idor` -> `bola`), rejects
  unsupported/planned families fail-closed, and reports `check_family_scope.source=check_family` for
  focused shards. BOLA also requires the API-side Lab/deep plus two-auth preconditions.
- Remaining scanner refactor: make `build_report()` iterate registry entries per phase so adding a
  runnable check is one registry entry plus module integration, not another set of scattered boolean
  parameters.

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

**API (shipped names):** `POST /scans` gains `options.parallel: bool`, `options.shards: int|"auto"`, `options.shard_strategy: "auto"|"scope"|"family"|"coverage"|"coverage_family"` (the design's "by endpoint slice" shipped as **`coverage`**; there is no `"endpoint"` value). `GET /scans/{id}` returns parent rollup (`shard_count`, `shards_completed`, aggregate progress). The Scans UI shows the parent as one row with a shard sub-progress bar.

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
- More granular cooperative cancel checkpoints inside scanner active-check loops (see Risks).
- UI: parent progress, per-shard contribution, aggregate auth/family rollups, and runtime-versus-active-cap
  budget view are shipped.

---

## 12. Risks & mitigations

- **Scanner monolith refactor risk.** Mitigate by keeping the single-worker path as `merge([shard(full)])` and golden-diffing reports against current output before/after.
- **Cancellation cleanup is coarse-grained.** The worker now interrupts active scanner subprocess groups on cancel, and DB state stays terminal. `scanner/scanner.py` can still improve graceful cleanup by checking a cancel signal between long active-check loops before the worker has to send SIGTERM.
- **Auth session sharing across shards.** Stateful logins may not be cleanly serializable; mitigate by capturing a reusable token/cookie recipe in the recon stage and re-authing per shard on expiry (the scanner already re-auths).
- **DBMS-fingerprint coupling.** Broadcast the fingerprint from the recon/plan stage so shards don't each re-detect and diverge.
- **Resource exhaustion / target overload.** Each worker uses 2–4 GB / 1–2 cores, and a small lab app can fail under 20 simultaneous active shards. The per-parent Redis slot cap is now implemented; keep the default conservative and raise `options.shard_concurrency` only for targets known to tolerate it.
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
or dynamic endpoint batches. For broad active mixes, the automatic cap is intentionally small:
50 endpoints per shard/batch by default, and 35 for exploit-depth/exhaustive runs. Focused SQLi/XSS
lanes and explicit caller overrides can still use larger batches through `coverage_per_shard_cap` or
`coverage_dynamic_batch_size` (legacy/focused default 150). Fan-out is bounded by
`coverage_max_shards` / `COVERAGE_MAX_SHARDS` (128 today). Auth-state expansion can multiply that up
to the total coverage shard ceiling while preserving every endpoint per state. `auto`/`scope` use the
generic `MAX_SHARDS` ceiling (24 today). `family` is intentionally fixed at 3 (broad/sqli/xss focused
lanes) and is no longer the default `auto` path for active scans. BOLA is available only as an
explicit gated ASM/API focused family, not in default fan-out. Concurrency is bounded by the worker
fleet; excess shards queue and run as workers free up.

**Coverage depth is decoupled from breadth.** Coverage always tests *every* endpoint, but depth is
a choice: New Scan exposes **Standard** (thorough budget, no exploit-depth — broad but sane;
default) vs **Deep** (exhaustive budget + exploit-depth — maximal). This stops "test all endpoints"
from being welded to "test each one maximally." The UI flags Coverage as the heaviest mode, shows
the current worker count as a scaling hint, and clarifies that "target endpoints per shard" is a
goal (slices grow to preserve coverage when the worklist is large). When a forced slice would exceed
the per-shard active ceiling, the planner emits a note.

**Operator-tunable caps.** All shard ceilings are env-overridable: `SHAKERSCAN_MAX_SHARDS`,
`SHAKERSCAN_AUTH_STATE_MAX_SHARDS`, `SHAKERSCAN_COVERAGE_MAX_SHARDS`,
`SHAKERSCAN_COVERAGE_MAX_TOTAL_SHARDS`, plus coverage batch sizing through
`SHAKERSCAN_COVERAGE_ACTIVE_MIX_PER_SHARD_CAP` and
`SHAKERSCAN_COVERAGE_EXPLOIT_DEPTH_PER_SHARD_CAP` — so operators can right-size for their fleet/DB
without a code change.

Also shipped earlier the same day: coverage-aware merge aggregation, `input.port 8080→3001` fix at
source, exploit-depth, auth-state sharding, and a pre-fan-out UI state
("Discovering endpoints once, then sharding…").

**Per-endpoint active telemetry (shipped 2026-06-17):** smart active checks now emit
`report['active_checks']['endpoint_attempts']` with `custom_endpoint`, family, status, and
attempted/completed parameter counts. Coverage merge consumes those rows for `asm_endpoint_attempts`
when present and refuses to fall back to whole-shard completion if telemetry exists but cannot be
resolved to inventory. Legacy/no-telemetry child reports still use the conservative assigned-slice
partial-attempt fallback so old scans remain mergeable without inflating tested coverage.

### Shipped high-budget coverage behavior

1. **Coverage-aware merge.** Parent reports aggregate shard coverage for disjoint
   `scope`/`coverage` shards, union auth states and discovery sources, and correct the
   merged `input` identity back to the parent target.
2. **`coverage` strategy.** Plan/recon runs once, harvests the full emitted active
   worklist, partitions every harvested endpoint round-robin across coverage shards, and
   runs the full active suite over each slice with zero-rediscovery child execution.
3. **Large budget overrides.** `custom_budget` values are capped by
   `SCAN_BUDGET_CEILINGS`, not the smaller exhaustive profile defaults. This includes
   `active_worklist_max`, so API/UI callers can ask recon to emit much larger endpoint
   worklists.
4. **Auth-state sharding.** `auth_state_shards` expands coverage across anonymous,
   user1, and user2 when credentials are supplied. Expansion preserves every endpoint per
   auth state; if the total shard ceiling would be too high, the planner uses larger
   base endpoint slices instead of dropping buckets.
5. **Exploit-depth mode.** `exploit_depth` disables early stop and raises proof caps so
   confirmed findings get driven further instead of stopping after a few examples.
6. **Telemetry-backed attempt ledger.** Smart active endpoint attempts are persisted into the
   Full Coverage campaign ledger per endpoint, or per endpoint+family for `coverage_family`, when
   child reports include telemetry. Parent reports use those attempt facts for endpoint coverage
   rollups while still keeping endpoint status promotion out of coverage merge.
7. **Reserved active enrichment budget.** The primary SQLi/XSS active loop receives most of the active
   budget, but large scans reserve a tail for SQLMap/NoSQL/stored-XSS/DOM-XSS/auxiliary modules. This
   prevents a shard with many parameters from spending the whole active window before deeper proof
   modules run.

### Remaining next work

- **Dynamic allocation soak:** continue live parity tests on Juice Shop, crAPI, and Honey while
  retaining `coverage_allocation=static` and `COVERAGE_ALLOCATION_DEFAULT=static` as fallback
  controls.
- **More focused families:** `coverage_family` dynamic allocation is shipped for default
  broad/SQLi/XSS lanes. Auth and BOLA are explicit ASM/API only and intentionally excluded from
  automatic lanes; when explicitly requested they run as single focused `coverage_family` lanes. Add more
  lanes only after the scanner registry can route those modules cleanly and each family has its own
  safety gate.
- **Rate-limit soak:** known-endpoint static shards and dynamic ASM/Full Coverage batches now reserve
  endpoint budget through shared Redis domain buckets before execution. Keep validating this under
  larger worker fleets and extend it to internally discovered standalone requests only once scanner
  telemetry can expose a reliable request budget.
- **Richer UI rollups:** parent scan detail now shows campaign endpoint coverage from the attempt
  ledger, per-shard contribution facts, aggregate auth/family rollups, and runtime-versus-active-cap
  budget view.

---

## 16. Continuous ASM integration boundary

Continuous ASM is documented separately in
[continuous-asm-architecture.md](continuous-asm-architecture.md). Keep this parallel-scan document
focused on one-shot scan orchestration.

Parallel scanning touches ASM in three shipped places:

1. `coverage` recon harvests the scanner's emitted active worklist.
2. `scan_merge` persists the union of shard-discovered endpoint worklists into `target_endpoints`.
3. ASM inventory identity preserves auth state, parameter location, and replay spec so later ASM
   batches can replay the same surface safely.

Current boundary:

- One-shot `coverage` defaults to dynamic pull workers planned by `api/parallel_scan.py`. The plan
  stage pre-creates a `full_coverage` campaign, upserts the recon harvest into campaign-scoped
  `target_endpoints`, and queues allocator-backed batch children. API/AI callers can opt into the
  legacy static path with `coverage_allocation=static`. Merge writes telemetry-backed attempt rows
  when child reports include `active_checks.endpoint_attempts`, and uses assigned-slice partial
  attempt rows only for legacy/no-telemetry static child reports. Parent endpoint coverage uses the
  campaign attempt ledger when rows exist, with assigned-slice coverage retained as fallback context.
  Coverage children run in zero-rediscovery mode over assigned or claimed endpoint batches.
- Continuous ASM batches use pull-based `claim_test_batch()` over `target_endpoints`; claims now set
  durable leases, link to `scan_campaigns`, and write `asm_endpoint_attempts`.
- Both paths write into the same endpoint inventory and attempt ledger. Dynamic Full Coverage uses
  the ASM allocator with `campaign_only=true` so workers claim only endpoints discovered for the
  current campaign.

Target boundary:

- Dynamic Full Coverage is the default. Static round-robin slices remain the fallback.
- `scan_merge` should continue preserving attempt-ledger coverage rollups as dynamic claims soak on
  larger live targets.
- The parent scan report should keep showing tested, partial, untested, auth-blocked, and
  rate-limited endpoint counts as the campaign model moves to dynamic claims.

Do not add detailed ASM roadmap material back here. Update
[continuous-asm-architecture.md](continuous-asm-architecture.md) instead.

---

## 17. AI Agent Task Appendix

Use this appendix when asking an AI coding/review agent to implement or audit a parallel-scan
increment. The goal is to make one bounded change without confusing shipped behavior, proposed
architecture, and future fleet work.

### Required prompt contract

Every prompt should contain:

```text
ROLE
You are a senior backend/security architecture agent working on ShakerScan DAST.

MODE
Choose exactly one: IMPLEMENT | REVIEW | PLAN | TEST_ONLY | DOCS_ONLY.

EDIT PERMISSION
State whether code edits are allowed. If MODE is REVIEW or PLAN, do not modify files.

TASK
Implement or review exactly one architecture increment.

SOURCE OF TRUTH
Use these docs as authoritative architecture context:
- docs/parallel-scan-architecture.md
- docs/continuous-asm-architecture.md
- docs/multi-node-architecture.md
Before changing code, verify shipped behavior in the repository, DB migrations, API handlers, worker
code, scanner code, and tests.
If repository behavior contradicts these docs, stop and report the discrepancy before editing.

STATUS PREFLIGHT
Return a 6-row table before implementation:
| Claim from docs | Code checked | Tests checked | Result | Action |
If a doc says "shipped", verify it with code and tests. Do not implement proposed behavior as if it
were already shipped.

CURRENT STATE
Summarize the shipped behavior relevant to this task in 5 bullets before changing code.

TARGET BEHAVIOR
Describe the desired behavior in observable terms.

NON-GOALS
List what must not be changed in this task.

DO NOT TOUCH
List specific components, files, APIs, UI surfaces, or features out of scope.

SAFETY INVARIANTS
Preserve the invariants listed below.

AUTHORIZATION / BLAST RADIUS
State target authorization assumptions, allowed preset (Safe/Balanced/Lab), credentials and auth
states affected, high-risk families included/excluded, rate limits/daily caps affected, and whether
confirmation is required before queueing active work.

DATA CONTRACTS
For DB rows, API JSON, Redis job payloads, scanner telemetry, report rollups, and UI-facing fields
changed or verified, state producer, consumer, backward compatibility, old-row/null behavior, and the
idempotency key or uniqueness rule.

MIGRATION / BACKFILL / COMPATIBILITY
State whether schema/data changes are required, how existing rows are handled, and what rollback or
fallback behavior exists.

ROLLOUT / FALLBACK
State feature flag name, default value, fallback path, rollback behavior, old scan/report readability,
and log/metric signals that indicate unsafe behavior.

FAILURE-MODE MATRIX
Explicitly cover worker crash mid-job, duplicate job delivery, parent cancellation, timeout after
partial work, missing credentials, rate budget exhaustion, missing scanner telemetry, and
corrupt/missing shard context. For each: expected behavior and whether a test is required.

OBSERVABILITY / UI / REPORT BEHAVIOR
State what API responses, scan detail pages, logs, reports, and hidden implementation rows should
show after the change.

FILES / COMPONENTS TO INSPECT
List expected files, but verify with search before editing.

IMPLEMENTATION PLAN
Return a short plan first. Then implement.

ACCEPTANCE CRITERIA
Provide API behavior, DB state, queue behavior, UI/report behavior, and failure behavior.

TESTS REQUIRED
Add or update unit, DB/integration, worker/API, and UI tests where applicable.

TEST COMMANDS
Before final response, report commands run and commands not run with reasons. Include minimum expected
unit, DB/integration, worker/API, UI, and live-smoke coverage for the task.

OUTPUT FORMAT
Return: status preflight; changed files; behavior summary; safety checks; data contracts changed;
tests run; remaining risks; follow-up tasks.
```

Hard rule: exactly one architecture increment per implementation task. Do not combine scanner-stage
refactors, campaign allocation, check registry, multi-node, and UI redesign in the same change.

### Safety invariants for parallel work

- No endpoint is marked tested unless scanner telemetry proves it was attempted/completed.
- Partial timeout preserves findings but does not mark unattempted endpoints clean.
- Root-domain and target rate tokens are reserved before queueing high-volume active work.
- Shard rows stay hidden from normal user-facing scan lists.
- Parent/merge logic is idempotent under retries and duplicate shard completion.
- Parent cancellation blocks/short-circuits merge and terminates active child work.
- Active exploitation remains bounded unless an explicit Lab/deep policy is selected.
- Attack-chain and AI correlation run once after merge, not independently inside shards.

### Prompt: harden zero-rediscovery child execution

```text
ROLE
You are a senior DAST engine engineer refactoring ShakerScan scanner stages.

MODE
IMPLEMENT

EDIT PERMISSION
Code and test edits are allowed for this prompt. Do not edit campaign allocator, check registry,
multi-node transport, public POST /scans API shape, or AI router behavior.

TASK
Harden zero-rediscovery child execution for parallel coverage shards and preserve it while the
default dynamic allocator continues to soak with static slices available as fallback.

SOURCE OF TRUTH
Use:
- docs/parallel-scan-architecture.md
- docs/continuous-asm-architecture.md
- docs/multi-node-architecture.md
Verify api/parallel_scan.py, api/worker.py, scanner/scanner.py, DB migrations, API handlers, UI scan
detail behavior, and tests before editing.

STATUS PREFLIGHT
Confirm:
- coverage children receive explicit endpoint slices;
- worker maps zero_rediscovery to --zero-rediscovery;
- scanner skips crawl/recursive/JS/json/OPTIONS/Nuclei discovery in zero-rediscovery mode;
- parent merge remains attempt-ledger backed;
- single-slice fallback remains valid;
- dynamic pull-based allocation is the default and static allocation remains an explicit fallback.

CURRENT STATE
- Verify the current shipped behavior before editing.
- Coverage mode is shipped as discover-once recon plus zero-rediscovery child execution.
- Each child receives an injected endpoint slice, passes --zero-rediscovery to the scanner, skips
  crawl/recursive/JS/json/OPTIONS/Nuclei discovery, and runs active checks over assigned endpoints.
- Duplicate target-global probes are suppressed after the first shard per auth state.
- Dynamic pull workers are the default work allocation model; static round-robin slices remain
  available as fallback.

TARGET BEHAVIOR
- Keep scanner child runs active-only over assigned endpoints.
- Preserve parent merge/attempt-ledger rollups while dynamic allocation soaks as the default.
- Add live parity tests that prove coverage children do not invoke crawl/discovery/Nuclei modules.
- Single-slice coverage remains valid: it either runs as a zero-rediscovery standalone/static fallback
  or through the same parent rollup path.

NON-GOALS
- Do not change public POST /scans API shape.
- Do not implement the campaign allocator in this task.
- Do not run attack-chain or AI correlation inside shards; run it once after merge.

DO NOT TOUCH
- Campaign allocator behavior.
- Check registry behavior.
- Multi-node transport.
- Public POST /scans API shape.
- AI router behavior.

SAFETY INVARIANTS
- No endpoint is marked tested without scanner telemetry.
- Missing scanner telemetry records partial/error, not completed coverage.
- Parent cancellation blocks merge and terminates child subprocesses.
- Attack-chain and AI correlation run only after merge.

AUTHORIZATION / BLAST RADIUS
- Target authorization assumption: user owns or is authorized to test the target.
- Allowed preset: Safe or Balanced unless the task explicitly says Lab/deep.
- Auth states: preserve anonymous/user1/user2 separation.
- High-risk families: do not add new high-risk families.
- Rate limits: do not raise target/root-domain caps.
- Confirmation is required before queueing active scans outside tests.

DATA CONTRACTS
- Verify Redis scan_shard payload options and CLI flag mapping.
- Verify scanner telemetry JSON under active_checks.endpoint_attempts.
- Verify parent smart_coverage/report rollup JSON remains backward compatible.
- Verify scan rows and shard visibility behavior are unchanged.
- For changed contracts, name producer, consumer, old-row behavior, and idempotency key.

MIGRATION / BACKFILL / COMPATIBILITY
- Keep the current static coverage path as fallback until dynamic allocation parity tests pass.
- Do not reinterpret older coverage child rows as telemetry-backed attempts unless endpoint
  telemetry is present.

ROLLOUT / FALLBACK
- Feature flag: none unless the implementation introduces one.
- Default: existing coverage mode remains available.
- Fallback: static coverage slices and standalone single-slice fallback.
- Rollback: disable new zero-rediscovery branch or return to focused endpoint child execution.
- Unsafe signals: child logs show crawl/discovery/Nuclei execution or parent coverage rises without
  endpoint telemetry.

FAILURE-MODE MATRIX
Cover worker crash, duplicate shard delivery, parent cancellation, timeout after partial work,
missing credentials, rate budget exhaustion, missing scanner telemetry, and corrupt/missing shard
context. State expected behavior and required tests for each.

OBSERVABILITY / UI / REPORT BEHAVIOR
- Shard logs clearly show active-stage-only execution.
- Parent report remains one logical scan and shows any partial/fallback state.
- The Scans list still hides child shards by default.

ACCEPTANCE CRITERIA
- Coverage children skip crawl/discovery/Nuclei modules and run active checks over assigned endpoints.
- Parent report remains ledger-backed and does not count unattempted endpoints as covered.
- If assigned endpoints cannot be resolved or telemetry is missing, the parent reports partial/failure accurately.
- Parent cancellation still blocks merge and terminates child subprocesses.

TESTS REQUIRED
- Planner/worker/scanner tests proving zero-rediscovery flags and skip branches stay wired.
- Worker tests for scan_plan -> scan_shard -> scan_merge.
- Regression tests proving attack-chain correlation runs once on merged findings.
- Cancellation tests for queued/running shards.

TEST COMMANDS
Report exact commands run and any expected commands not run with reasons.

OUTPUT FORMAT
Return status preflight, changed files, behavior summary, safety checks, data contracts changed,
tests run, remaining risks, and follow-up tasks.
```
