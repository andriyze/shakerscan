# Continuous ASM Architecture — Current State and Target Design

**Status:** first continuous ASM loop is shipped; correctness hardening for auth-aware inventory,
replay fidelity, partial-timeout coverage semantics, dispatcher rate reservation, ASM campaign
records, durable endpoint leases, normalized ASM endpoint attempt rows, and one-shot Full Coverage
campaign linkage with merge-time attempt rows are implemented. Scanner-level smart active
per-endpoint telemetry is now emitted and consumed by ASM/Full Coverage attempt ledgers.
`/targets/{id}/asm/coverage` now exposes both endpoint-status coverage and attempt-ledger coverage,
using attempt facts for the top-level coverage when available. Full Coverage parent reports now
overlay campaign attempt-ledger rollups when merge-time attempt rows exist. Dynamic pull-based Full
Coverage allocation is now the default for one-shot Full Coverage parents; `coverage_allocation=static`
and `COVERAGE_ALLOCATION_DEFAULT=static` keep the legacy round-robin path available as fallback.
Current DAST-quality lesson from Juice Shop/crAPI validation: ASM must measure and schedule
campaign quality, not just endpoint touch count. The engine now proves real Critical SQLi and High
BOLA/Authz on lab apps, but XSS, workflow/write-BOLA, mass-assignment, and JWT remain quality gaps
that ASM should expose as family/proof/workflow gaps.
**Date:** 2026-06-23
**Related design:** [parallel-scan-architecture.md](parallel-scan-architecture.md),
[multi-node-architecture.md](multi-node-architecture.md).

**2026-07-05 audit note:** Continuous ASM is the flagship surface for the product thesis in
[proposed-next-steps.md](proposed-next-steps.md): proof-first Continuous Exposure Management for
modern apps, APIs, and AI systems. External ASM vendors are strong at discovering and mapping unknown
internet-facing assets; ShakerScan should differentiate by turning owned web/API surface into
authenticated, replayable, proof-grade campaigns with honest coverage, attempt ledgers, and canonical
evidence. The backend foundations are ahead of the operator workflow: graph-driven campaign
consumers, detector recall campaigns, and deployment/exception UX are the next product priorities.
First-pass next-action / skip-reason state is now live: ASM policy/gaps/improve/activity return `scheduler_state`, and
dispatcher/scheduler decisions persist to `targets.metadata_json.asm_last_decision`. ASM waves are
now a first-class schedule kind (`schedules.schedule_kind='asm_improve'`) with legacy
`scan_options.kind='asm_improve'` compatibility. ASM activity now also returns a derived target
campaign `timeline` that merges scheduler state, next ASM schedule, active scans, and recent
campaign activity. Model Intake now has guided trust modes and a pass/fail/advisory pre-submit
preview, saved operator trust anchors, and strict policy-profile required anchors. AI Gate scan detail now surfaces a
campaign review panel from the stored coverage matrix/evidence manifest and can queue scan-level
reruns for skipped probes, errored families, selected families, selected transcript probes, or all
probes. Scan detail now also compares recent same-context AI Gate runs, and the AI Gate target page
exposes target-level longitudinal campaign history grouped by probe pack/profile/environment.

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
| ASM scheduling/operator UX | Partial; next-action/skip-reason contract, ASM activity surfacing, Action Center CTAs, and schedule UI bridge shipped | Make ASM waves a first-class schedule kind and unify background policy, recurring waves, manual actions, and scan rows into one target timeline. |
| DAST quality benchmark loop | Active workstream | Treat "no XSS on Juice Shop" and "no workflow/write-BOLA on crAPI" as benchmark failures, not acceptable coverage. |
| Multi-node WireGuard POC | Proposed/RFC | Build a two-VPS proof only after local queue/worker invariants stay green. |
| Production multi-node fleet | Proposed/RFC | Add node registry, reliable queue leases, object evidence, and routing. |
| HTTPS broker for untrusted workers | Future | Do not build until owned-fleet primitives are stable. |

---

## Purpose

ShakerScan should evolve from "a scan is a one-shot job" into "a target has a living attack
surface that is discovered, queued, tested, retried, and aged continuously."

The goal is not to build the largest internet corpus first. The goal is to continuously convert
owned inventory into family-aware, deterministic proof campaigns: recon freshness, endpoint and
parameter inventory, auth/principal context, graph hypotheses, check-family attempts, proof
instances, canonical findings, retests, exceptions, and deployment gates.

Parallel Full Coverage scans and Continuous ASM should become two views over the same facts:

- **One-shot Full Coverage:** a user asks for a logical scan now; ShakerScan discovers endpoints,
  spends an explicit campaign budget, fans work out across workers, and merges one parent report.
- **Continuous ASM:** the system keeps the target inventory fresh over time; it spends small safe
  budgets during allowed windows and converges toward higher coverage without overwhelming the target.

The user-facing model stays simple: "run Full Coverage now" and "keep this target covered" are
different entry points, not separate engines.

### Current DAST Quality Lessons

Recent Juice Shop/crAPI validation proves the ASM loop must optimize for **campaign quality**:

- **SQLi:** focused SQLi campaigns can produce verified Critical findings on Juice Shop. ASM should
  prioritize login/search/filter/order/track endpoints with query and JSON/body parameters for SQLi
  family passes.
- **BOLA/Authz:** focused dual-user campaigns can produce verified High cross-principal findings on
  crAPI. ASM should track producer endpoints, object IDs, owner fields, auth states, and
  producer->consumer links, then retest those links as user1/user2/anonymous.
- **XSS:** Juice Shop hash-route DOM XSS is now browser-proven High (the iframe `javascript:`/
  `srcdoc` vector). Stored XSS (store-then-render proof) and broad reflected XSS remain family/proof
  gaps — ASM should report those as gaps, not "covered" just because endpoints were attempted. The
  attempt ledger now distinguishes endpoint-attempted from family-proved via `/asm/gaps`
  `family_coverage` (completed vs attempts).
- **Broad fan-out:** a parent that creates hundreds of shards on a small worker fleet delays merged
  evidence and can trigger shard timeouts. ASM/Full Coverage should prefer worker-aware campaign
  waves over huge pending shard sets.

Therefore ASM coverage should answer four questions:

1. Which endpoints and parameters exist?
2. Which auth states and object/workflow contexts have been exercised?
3. Which vulnerability families have proof-quality attempts on those contexts?
4. Which benchmark-relevant families are still missing verified evidence?

---

## Current Implementation

### Shipped Loop

Shipped pieces:

- `target_endpoints` persists discovered endpoint worklists from standalone scans, coverage recon,
  parallel scan merge, and ASM batches.
- Current shipped APIs (verify route handlers before editing):
  - `GET /targets/{id}/asm/endpoints`
  - `GET /targets/{id}/asm/coverage`
  - `GET /targets/{id}/asm/diff`
  - `POST /targets/{id}/asm/test`
  - `POST /targets/{id}/asm/recon`
  - `POST /targets/{id}/asm/improve`
  - `GET /targets/{id}/asm/gaps`
  - `GET /targets/{id}/asm/activity`
  - `GET /targets/{id}/asm/policy`
  - `PUT /targets/{id}/asm/policy`
- `exploit_batch` claims untested/stale rows with `FOR UPDATE SKIP LOCKED`, runs `run_scan()` with
  `custom_endpoints`, saves findings, and stamps inventory.
- `run_asm_dispatch` periodically decides recon vs. test using target policy: batch size, stale TTL,
  min interval, daily cap, recon cadence, UTC windows, weekday windows, and per-root-domain caps.
- `asm_inventory.decide_asm_action` returns operator-facing decision facts: `blocked_by`,
  `next_eligible_at`, `daily_cap_remaining`, `rate_cap_remaining`, `claimable`, and `tested_today`.
  `/targets/{id}/asm/policy`, `/asm/gaps`, and `/asm/improve` expose those facts as
  `scheduler_state`; dispatcher/scheduler runs persist the latest decision under
  `targets.metadata_json.asm_last_decision`.
- `/asm` gives users a rollup, coverage advisor, one-click Improve Coverage action, target
  inventory, coverage gaps, live/last scheduler decisions, remaining daily/domain budget, target
  campaign timeline, policy presets, local-time window helper, and new-surface feed.
- `/schedules` gives users a first typed UI/API path for recurring ASM waves through
  `schedule_kind='asm_improve'`. Legacy `scan_options.kind='asm_improve'` rows are still decoded for
  compatibility.
- Gungnir can inherit ASM policy for newly discovered subdomains under an ASM-enabled root.
- `/scans` hides shard and ASM implementation rows by default; `include_shards=true` and
  `include_internal=true` expose them for debugging.
- ASM test/improve can request the currently supported focused active families: `sqli`, `xss`,
  credential-gated `auth`, and gated `bola`.

### Current Table Shape

The current physical table is `target_endpoints` in `db/init.sql`.

Important current behavior:

- The physical unique index is `UNIQUE(target_id, fingerprint)`.
- The generated `fingerprint` includes auth state, HTTP method, normalized path, parameter location,
  and parameter shape. In other words, auth/location are in identity even though the physical index is
  still the compact `(target_id, fingerprint)` form.
- Current fields include:
  - `auth_state`
  - `param_location`
  - `replay_spec`
  - `content_type`
  - `priority_score`
  - `test_status`
  - `last_attempt_status`
  - `last_verdict`
  - `credential_ref`
  - `campaign_id`
  - `lease_owner`
  - `lease_expires_at`
  - `attempt_count`
  - first/last seen/tested timestamps

Current scanner telemetry:

- Smart active checks emit `report['active_checks']['endpoint_attempts']` with `custom_endpoint`,
  family, status, attempted parameter count, and completed parameter count.
- ASM batches and Full Coverage merge resolve those telemetry rows back to `target_endpoints` before
  writing `asm_endpoint_attempts`.

Related shipped tables:

- `scan_campaigns` stores durable campaign records for ASM recon/test batches and future Full
  Coverage campaigns.
- `asm_endpoint_attempts` records per-endpoint attempt facts keyed by endpoint, scan, campaign,
  worker, auth state, status, start/end times, param counts, finding IDs, error summary, and scanner
  telemetry JSON.

### Current Correctness Guarantees

Implemented:

- Endpoint identity separates anonymous/user1/user2 coverage obligations.
- Endpoint identity separates query/form/JSON parameter locations.
- Replay preserves query vs. form vs. JSON custom endpoint strings.
- JSON replay preserves nested JSON body shape when the scanner emits it.
- ASM batches claim one auth state at a time, then scope scan options to that auth state.
- If a claimed auth state no longer has usable credentials, rows are marked `auth_missing` instead of
  being tested anonymously.
- Timeout-recovered partial ASM results are marked partial/stale instead of clean tested.
- Dispatcher reserves per-root-domain budget in Redis before queueing batches, so concurrent targets
  under one root do not all enqueue full batches in the same tick.
- ASM recon/test jobs create `scan_campaigns` rows; scan rows link back through `scans.campaign_id`.
- ASM test batches set `lease_owner`, `lease_expires_at`, and increment `attempt_count` when claimed.
- Expired endpoint leases are reaped back to `stale` with `last_attempt_status='lease_expired'`.
- ASM batch completion writes `asm_endpoint_attempts` rows and clears endpoint lease fields.
- ASM batches promote only telemetry-completed endpoint IDs to `tested`; partial, skipped, timed-out,
  or missing telemetry rows are released as stale/partial for later retry.
- Full Coverage merge writes telemetry-backed `asm_endpoint_attempts` when child reports include
  `active_checks.endpoint_attempts`; legacy/no-telemetry children keep an assigned-slice fallback,
  but successful child status is recorded as `partial`, not `completed`. Full Coverage merge still
  does not promote endpoint `test_status`.
- `/targets/{id}/asm/coverage` returns `status_coverage` and `attempt_coverage`; top-level
  `tested`/`coverage` use the latest attempt per endpoint when attempt facts exist.

Still limited:

- Per-endpoint scanner telemetry currently covers smart active SQLi/XSS/hash-route DOM XSS attempts,
  focused Auth attempts, and focused BOLA attempt rows. Registry metadata now exists, but telemetry
  schemas and runnable scanner integrations are still needed for other active families.
- One-shot parallel `coverage` defaults to dynamic pull allocation. It feeds ASM inventory and
  campaign attempt ledgers by claiming campaign-scoped inventory through the ASM allocator; API/AI
  callers can force legacy static slices with `coverage_allocation=static`.
- Coverage children now run in zero-rediscovery mode over assigned endpoint slices or dynamically
  claimed endpoint batches: no crawl, recursive, JS, JSON, OPTIONS, or Nuclei discovery is run
  inside children.
- Full Coverage parent scan reports overlay `smart_coverage.endpoints` from campaign
  `asm_endpoint_attempts` when merge-time attempt facts exist; the assigned-slice rollup is retained
  as `endpoint_assignment_rollup` for context/fallback.
- ASM batch scan rows still exist in the `scans` table, but they are hidden from the default scan
  list and exposed through ASM activity.
- Focused ASM batches support `sqli`, `xss`, credential-gated `auth`, and high-risk `bola` via
  registry-backed validation and current scanner boundary wiring. Auth requires primary credentials
  on the target. BOLA requires `exploit_depth=true` plus primary and second-user credentials.
  Registered planned families such as `ssrf`, `lfi`, `rce`, and `business_logic` are rejected for
  ASM execution until their scanner integrations exist.
- Coverage is still too endpoint-centric for DAST quality. A completed/partial endpoint attempt
  does not mean the app has been meaningfully tested for SQLi, XSS, BOLA, workflow, or proof depth.
  Gaps and rollups must remain family-aware and should increasingly become workflow/object-aware.

---

## Target Architecture

The desired architecture is not "parallel scans over here, ASM batches over there." Both should use
the same durable primitives:

1. **Endpoint inventory:** what exists and what auth/replay context is required to exercise it.
2. **Work allocator:** who owns the next slice of test work, until what lease expiry, under which
   campaign/policy, and with what rate budget.
3. **Attempt ledger:** what the scanner actually attempted, what completed, what timed out, and which
   findings or coverage gaps resulted.
4. **Rollup views:** one-shot scan parent reports, `/asm` coverage, targets chips, and AI-agent
   summaries all read from those facts instead of inferring coverage from scan rows alone.

### Campaign Model

Everything that spends meaningful target budget should be represented as a campaign, even if the
current API still starts from `POST /scans` or `/asm/improve`.

Recommended campaign kinds:

```text
full_coverage       -- one logical scan now; discover once, fan out, merge into one parent report
continuous_asm      -- background policy loop; small budget slices during allowed windows
focused_family      -- run one check family such as SQLi, XSS, BOLA, auth, headers, or nuclei tags
finding_retest      -- replay evidence for known findings and update verification state
surface_recon       -- passive/low-impact discovery refresh without active exploitation
```

Common campaign fields:

```text
target_id
root_domain
requested_by        -- ui | api | ai | scheduler | dispatcher
mode
priority
budget_profile
wide_budget         -- max endpoints/routes/auth-states to cover
deep_budget         -- max params/payloads/extraction/OOB/proof effort per endpoint
check_families      -- all | passive | sqli | xss | bola | auth | headers | nuclei:<tags>
auth_states
allowed_windows
daily_cap
rate_caps
parent_scan_id      -- optional logical scan rollup
policy_id           -- optional continuous ASM policy
```

This keeps "run Full Coverage now", "keep this target covered", and "test only SQLi tonight" as
different campaign modes over one allocator, not separate engines.

### Wide vs. Deep Budgeting

Large targets need an explicit split between breadth and depth:

- **Wide work:** discover and exercise more endpoints, methods, auth states, forms, API routes,
  JavaScript-discovered routes, OpenAPI/HAR routes, and newly observed surface.
- **Deep work:** spend more payloads, parameters, proof attempts, extraction attempts, OOB checks,
  BOLA comparisons, and tool-specific templates on selected endpoints.

The allocator should be able to choose "go wider" or "go deeper" per campaign:

- Full Coverage defaults to wide first, then a bounded deep pass on higher-priority endpoints.
- Continuous ASM defaults to small wide refreshes plus small test batches, spread over time.
- Focused family campaigns default to deep work for one vulnerability class over a selected subset.
- Finding retests are narrow and deep against known proof paths.

UI should expose this as presets, not knobs:

```text
Safe       -- mostly wide/passive, small active batches, conservative depth
Balanced   -- wider endpoint batches plus normal active checks
Lab        -- high breadth, deeper active checks, explicit user confirmation
```

API and AI callers can still pass explicit budgets, but default user workflows should map to these
presets.

### Modular Check Execution

The DAST engine should become a registry of check families that can be scheduled independently:

```text
recon/passive   -- crawl, DNS/TLS/headers, JS links, OpenAPI/HAR import, content discovery
nuclei          -- template tags/severity filters
sqli            -- SQL injection probes and extraction/proof depth
xss             -- reflected/stored/DOM XSS probes
bola            -- IDOR/BOLA multi-user comparison checks
auth            -- access control, weak JWT/session/cookie checks
ssrf/lfi/rce    -- high-risk active families, permission-gated
business_logic  -- AI/manual-assisted flows over discovered workflows
```

Workers should be able to run one family against claimed endpoint IDs. That makes it possible to run
wide passive recon during the day, deep SQLi/XSS during a maintenance window, BOLA only when two
credential sets exist, and lightweight retests immediately after a fix.

Family-specific quality contracts:

- **SQLi:** prioritize endpoints with query/body parameters and auth/login/search/order semantics;
  prove impact through auth bypass, DB error, timing, or extraction evidence. Do not let generic
  endpoint breadth starve login/search routes.
- **XSS:** use browser-backed reflected/stored/DOM proof. Candidate attempts are not enough; a
  high-quality XSS result needs execution evidence such as DOM mutation, console callback, alert
  equivalent, screenshot, or stored replay.
- **BOLA/Authz:** require at least two principals or one principal plus anonymous context. Track
  producer endpoints, object IDs, sensitive fields, owner/attacker listings, and replay equivalence.
  Future write/BFLA checks must be non-destructive and Lab/deep-gated.
- **Workflow/business logic:** record blocked hypotheses when required setup is missing: no primary
  auth, no second principal, no created object, no writable test account, no resettable lab target.

ASM should expose a campaign as successful only when it improves one of these quality contracts:
new endpoint/param discovery, new auth/workflow context, new completed family attempts, verified
findings, or an explicit blocked/proof gap.

### Inventory v2

Recommended logical identity:

```text
target_id
auth_state
method
normalized_path
param_location
param_shape_hash
```

The current implementation stores this identity as a generated `fingerprint` plus supporting columns.
That is acceptable while the table remains compact. A future schema can expose the identity fields
directly if query/reporting needs justify it.

Additional fields now shipped in the current table:

```text
credential_ref              -- reference to current credential, not raw secret
campaign_id                 -- optional one-shot coverage campaign that discovered/claimed it
lease_owner
lease_expires_at
attempt_count
```

Recommended future logical/reporting fields beyond the current table:

```text
param_shape_hash            -- explicit stable hash of parameter names / JSON paths
source_set                  -- crawl, HAR, JS, OpenAPI, manual, Gungnir, previous scan
last_attempt_at
last_successful_test_at
coverage_status             -- untested | leased | tested | partial | stale | gone | blocked
```

Rules:

- `auth_state` belongs in identity. A `GET /api/user/profile` found as anonymous, user1, and user2 is
  three coverage obligations, not one.
- Replay must preserve body semantics. `POST /login form:email=1&password=1` must not degrade to
  `POST /login?email=1&password=1`.
- Store compact descriptors and sampled evidence, not full response bodies.
- When credentials rotate or disappear, rows move to `auth_missing`/`auth_failed` rather than "clean."

### Work Allocator

Target flow:

1. Decide policy/campaign scope: target, root domain, auth states, depth, max endpoints, max requests,
   allowed windows, and priority.
2. Reserve rate/budget tokens before enqueue using Redis or DB-backed buckets:
   `root_domain`, `target_id`, `auth_state`, and optional global/fleet buckets.
3. Claim endpoint rows with `FOR UPDATE SKIP LOCKED`, set `lease_owner`, `lease_expires_at`,
   increment `attempt_count`, and move the current physical `test_status` to `in_progress`.
4. Queue a worker job that carries claimed endpoint IDs and replay specs.
5. On success, stamp only endpoints the scanner reports as attempted/completed.
6. On timeout/partial, mark attempted endpoints as `partial` and release unattempted rows for retry.
7. On worker crash, a lease reaper returns expired `in_progress` rows to `stale` without marking
   them clean; later passes can add backoff based on `attempt_count`.

This solves the high-risk cases:

- A root-domain rate cap cannot be exceeded by several targets queueing at once.
- A slow batch cannot claim 100 endpoints, time out after 3, and mark all 100 clean.
- Many workers can drain one target without static stragglers.

### Attempt Ledger

`asm_endpoint_attempts` is the shipped normalized attempt storage:

```text
id
endpoint_id
scan_id
parent_scan_id
campaign_id
worker_id
auth_state
started_at
completed_at
status                  -- completed | partial | timeout | auth_missing | rate_limited | error
attempted_params_count
completed_params_count
finding_ids
error_summary
scanner_telemetry_json
```

Coverage percentages should derive from attempt outcomes, not scan status alone. The ASM coverage API
now returns both:

- `status_coverage`: physical endpoint status used by the allocator for stale/claimable work.
- `attempt_coverage`: latest `asm_endpoint_attempts` status per endpoint.

Top-level `tested` and `coverage` use `attempt_coverage` when attempt facts exist; otherwise they
fall back to `status_coverage` for fresh installs and legacy inventories. Full Coverage parent scan
reports now use the same attempt-ledger treatment for campaign rows written during merge.

Operational note: coverage can decrease after this change if earlier status-based coverage marked
endpoints tested but the latest attempt facts are partial, timed out, auth-blocked, or missing
scanner endpoint telemetry. Treat that drop as a correction, not a regression; it means the system is
no longer counting unproven batch completion as tested coverage.

---

## Relationship to Parallel Scans

Parallel `coverage` should become a campaign over the same allocator.

Current shipped behavior:

- `scan_plan` runs discover-once recon.
- `scan_plan` creates a `full_coverage` campaign tied to the parent scan.
- Dynamic allocation is the default: `coverage_allocation` omitted upserts the recon harvest into
  campaign-scoped `target_endpoints` and queues `exploit_batch` pull workers with
  `campaign_only=true`.
- Static allocation remains available by explicit request: `coverage_allocation=static` partitions
  the worklist into static coverage shards and `scan_shard` workers run zero-rediscovery scans over
  disjoint endpoint slices.
- `scan_merge` produces one parent report, persists the union into ASM inventory, and writes
  telemetry-backed attempt rows for child reports that include endpoint telemetry. Legacy/no-telemetry
  child reports keep conservative assigned-slice partial attempt rows.
- `scan_merge` overlays the parent report's endpoint coverage from campaign attempt-ledger facts
  when those facts exist; assigned endpoint coverage remains as contextual fallback.

Target behavior:

- Dynamic allocation is the default; the campaign asks the allocator for work until it hits its
  budget or all eligible rows are terminal. Static allocation remains a rollback/fallback path.
- Worker jobs are coverage-batch/ASM-batch equivalents; the difference is the rollup target:
  `parent_scan_id` for one-shot scans, target policy for continuous ASM.
- The parent report shows tested, partial, untested, auth-blocked, and rate-limited counts so the
  grade can be trusted or clearly marked limited.

Static partitioning remains the shipped default and rollback path. Pull-based allocation is the end
state because it handles uneven endpoints, retries, auth-state expansion, and large fleets better.

---

## User-Facing Model

Keep the UI small. Users should not need twenty sharding controls.

Current UI/API:

- `/asm` shows coverage posture, new surface, inventory, policy, and manual test actions.
- `/asm` now leads with a coverage advisor and one-click Improve Coverage action.
- The Dashboard now includes a server-backed Action Center fed by `/dashboard.action_center`, including
  ASM coverage/schedule gaps, worker freshness, deploy blockers, failed scans, policy-exception
  hygiene, Model Intake trust gaps, and AI control-baseline gaps.
- Policy setup is preset-first (`Safe`, `Balanced`, `Lab`) with raw knobs hidden behind Advanced.
- New Scan exposes the parallel/coverage path without requiring users to understand every shard knob.
- `/asm` loads focused batch labels from `/asm/check-families`, so the UI only offers registry-approved
  runnable families while keeping the control to one compact selector. Registered active families
  that are not runnable yet are shown as disabled `planned` options with their risk tier instead of
  disappearing from the selector.
- Child shard and ASM implementation rows are hidden from the main Scans list by default.
- Auto-sharding exists behind `/settings/automation` and the compatibility
  `/settings/scan-execution` endpoint; fresh installs default it on for eligible scans, while
  explicit `Normal`/`parallel:false` still forces standalone execution.
- Continuous ASM exists per target. New explicit web targets default it on with the conservative
  safe policy from `/settings/automation`; existing targets, model-intake artifact targets, and
  bulk discovery rows are not silently flipped.

Recommended UI:

- **Attack Surface (`/asm`):** one primary action, `Improve coverage`, that chooses recon vs. test
  batch based on current state. Keep manual `Run recon` and `Test next batch` secondary.
- **Target campaign timeline:** `GET /targets/{id}/asm/activity` returns a derived `timeline` with
  background dispatcher state, next recurring ASM-wave schedule, current active scan/batch, last
  activity, last skip/block reason, and next eligible time in one place. A user should not have to
  know whether work came from `run_asm_dispatch`, `run_due_schedules`, or a manual Improve Coverage
  click.
- **Skip/block reasons:** expose rate cap, daily cap, UTC window, weekday window, min interval,
  active scan, missing auth, missing second user, stale worker, and no claimable endpoints as
  user-facing states instead of silent "nothing happened" behavior.
- **Continuous policy:** one enable switch plus presets: `Safe`, `Balanced`, `Aggressive lab`.
  Advanced fields stay expandable.
- **Recurring ASM waves:** the current UI exposes them, but the API/DB still model them as
  `scan_options.kind='asm_improve'` on a normal schedule. Move to first-class schedule kinds while
  keeping legacy decoding for old rows and old clients.
- **Automation defaults:** fresh installs should enable safe automation by default: auto-shard
  eligible active scans when enough workers exist, and enable passive ASM recon/new-surface tracking
  for new targets. Active ASM exploitation should use small safe batches by default and require an
  explicit `Lab`/aggressive policy for deep exploit mode.
- **Scans list:** keep one logical scan row. Hide child shards by default. Group Continuous ASM batch
  rows under ASM activity so users do not see hundreds of implementation rows.
- **Scan detail:** parent rows show campaign coverage: endpoints discovered, tested, partial,
  untested, auth states, and shard/batch progress.

Current shipped API (verify route handlers before editing):

```text
POST /scans
GET  /targets/{id}/asm/endpoints
GET  /targets/{id}/asm/coverage
GET  /targets/{id}/asm/diff
POST /targets/{id}/asm/test
POST /targets/{id}/asm/recon
POST /targets/{id}/asm/improve
GET  /targets/{id}/asm/gaps
GET  /targets/{id}/asm/activity
GET  /targets/{id}/asm/policy
PUT  /targets/{id}/asm/policy
```

AI skills should map natural requests to these APIs, while respecting current capability status:

- "Run full coverage on this target" -> one-shot coverage scan with safe defaults.
- "Keep this target covered" -> enable Continuous ASM with a safe preset and report the policy.
- "What is still untested?" -> gaps response with auth/rate/timeout reasons.
- "Spend more budget on APIs" -> raise endpoint/test budget for the next campaign, not global defaults.
- "Only retest SQLi/XSS tonight" -> focused family campaign over known inventory using those
  medium-risk supported families.
- "Retest anonymous access/authentication bypasses" -> focused Auth campaign only when primary
  credentials are configured; otherwise ask for the missing authorization context.
- "Only retest BOLA tonight" -> focused BOLA campaign only when Lab/deep intent plus primary and
  second-user credentials are configured; otherwise ask for the missing authorization context rather
  than silently running unrelated active checks.
- "What changed since yesterday?" -> new-surface diff plus current untested gap summary.

---

## Safety Invariants

These should be enforced in tests and code review:

- No endpoint is marked `tested` unless scanner telemetry proves it was attempted/completed.
- Partial timeout results preserve findings but do not count unattempted endpoints as covered.
- Root-domain and target rate tokens are reserved before work is queued.
- Endpoint identity includes auth state and parameter location/shape.
- Replay specs preserve query vs. form vs. JSON vs. multipart semantics.
- Shard/batch rows are implementation details; user-facing lists show logical scans or ASM activity.
- Parent/merge logic is idempotent under duplicate shard completion or worker retry.
- Cancellation preserves state and releases leased inventory.
- Default automation must stay bounded: passive/recon can be safe-on, active exploitation must respect
  low default caps, auth scope, rate limits, and explicit lab/deep policy.
- A focused family campaign must not silently run unrelated high-risk check families.

---

## Implementation Plan

### Phase A — Current Hardening

Implemented:

- Inventory identity tests for auth state and parameter location.
- `form:`/`json:` replay preservation through `upsert_endpoints()` and `to_custom_endpoint()`.
- `exploit_batch` scopes scan credentials by endpoint `auth_state`.
- Missing credentials mark rows `auth_missing` instead of testing anonymously.
- Timeout-recovered partial results are `partial`/`stale`, not clean coverage.
- Dispatcher uses Redis token reservation before enqueue for per-root-domain caps.

Implemented in this pass:

- Default `/scans` hides shard, ASM batch, and ASM recon rows unless internal flags are supplied.
- ASM batches can request `check_family=sqli`, `check_family=xss`, credential-gated
  `check_family=auth`, or gated `check_family=bola` where the current scanner already supports
  narrow active-family execution.
- `api/check_registry.py` centralizes family metadata, ASM focused-family validation, UI/API
  discoverability, and parallel family shard labels. BOLA is runnable only through explicit
  Lab/deep plus two-auth preconditions; remaining planned/high-risk families fail closed instead of
  silently running all checks.
- `/asm/check-families` is consumed by the ASM UI for focused batch labels/options instead of
  hardcoding `sqli`/`xss`.
- Worker jobs now pass registry-selected `asm_check_family` values to the scanner as
  `--check-family`; the scanner resolves aliases, rejects unsupported/planned families fail-closed,
  and emits `check_family_scope.source=check_family` under `scan_config`, `scan_metadata.options`,
  and `active_checks`. The report UI shows a compact focused-scope badge such as `SQLi only`.
- AGENTS, CLAUDE, and the scanner skill now describe Full Coverage, ASM improve/gaps/activity, and
  focused ASM batches.

Remaining:

- Migrate scanner `build_report()` module execution to registry iteration and add further runnable
  focused families beyond the current `sqli`, `xss`, credential-gated `auth`, and explicit gated
  `bola` paths.

### Phase B — Attempt Ledger + Durable Leases

Implemented:

- Added `scan_campaigns` for ASM recon/test batches, with `scans.campaign_id` linking implementation
  scan rows back to durable campaign records.
- Added endpoint lease fields: `lease_owner`, `lease_expires_at`, `attempt_count`, and a lease reaper
  that returns expired work to `stale` without marking it clean.
- Added `asm_endpoint_attempts` keyed by endpoint, check family, scan, campaign, worker, auth state,
  status, started/completed time, parameter counts, finding IDs, error summary, and scanner
  telemetry JSON.
- Record attempt rows for `auth_missing`, partial/timeout, completed, and error ASM batch outcomes.
- Preserve scanner-proven smart active endpoint attempts when present; completed telemetry can promote
  only those endpoint IDs to `tested`, while missing/partial telemetry keeps rows stale.
- Expose campaign and attempt-status facts in ASM activity/gaps.
- `/targets/{id}/asm/coverage` derives top-level coverage from latest attempt outcomes when present
  and keeps endpoint-status coverage available as a compatibility/allocator view.

Remaining:

- Extend first-class telemetry schemas beyond smart active SQLi/XSS/hash-route DOM XSS, focused
  Auth, and focused BOLA.

### Phase C — Parallel Coverage Uses The Allocator

Implemented:

- One-shot `coverage` parents create `full_coverage` campaign records with wide/deep budget metadata
  and auth-state scope.
- Coverage child scan rows inherit `campaign_id`.
- `scan_merge` resolves scanner endpoint telemetry back to `target_endpoints` and writes idempotent
  `asm_endpoint_attempts`; legacy/no-telemetry children fall back to assigned shard endpoint slices
  as partial attempts.
- `scan_merge` reads campaign attempt facts back into the parent report so `smart_coverage.endpoints`
  shows tested, partial, untested, auth-blocked, rate-limited, and error counts from the ledger.
- Scan Detail renders those campaign endpoint facts in a compact Full Coverage Rollup card on
  parent scans when attempt-ledger coverage is present.
- Advanced API/AI callers can use `shard_strategy=coverage_family` to run discover-once recon, then
  multiply coverage by broad/SQLi/XSS lanes. Dynamic mode uses the campaign allocator with
  endpoint+family attempt identity; `coverage_allocation=static` keeps the static bucket fallback.
  BOLA is intentionally excluded from automatic `coverage_family` lanes and remains explicit ASM/API
  focused work. If an explicit `check_family` such as `bola` or `auth` is present, coverage-family
  planning uses that single approved lane rather than broad/SQLi/XSS.

Implemented as default:

- Omitted `coverage_allocation` queues campaign-scoped pull workers instead of static endpoint
  slices; `coverage_allocation=static` forces the legacy path.
- Dynamic workers claim through `claim_test_batch(campaign_only=true)`, keep zero-rediscovery
  scanner execution, write parent-linked attempt rows, and let parent merge own final findings.
  `coverage_family` dynamic workers claim the same campaign inventory separately for `all`, `sqli`,
  and `xss` attempt families, or for one explicit focused family when requested, so one family lane
  cannot prematurely satisfy another.
- The coverage recon pass is discovery-only: workers strip focused active-family flags from recon
  options before calling the scanner, then restore the requested family only on child/batch jobs.
- BOLA batch execution is user1-scoped for inventory ownership, but keeps the supplied second-user
  credential as a comparator. Other focused families continue to scope to one auth identity and drop
  unrelated credentials.
- Worker execution enforces the target/root-domain endpoint cap through shared Redis token buckets
  before known endpoint batches run. Dispatcher-reserved ASM batches carry their reservation into the
  job payload to avoid double-counting; unreserved static shards wait, and dynamic batches can shrink
  to the granted endpoint count while releasing the rest for a later pass.

Remaining:

- Continue live parity/soak on large Juice Shop, crAPI, and Honey-style targets while keeping static
  partitioning available as fallback.
- Add more automatic focused family lanes only after the scanner registry can route those modules
  cleanly and the family has its own safety gate. Auth/BOLA may run in gated family-union campaigns
  when primary/second-user auth and Lab/deep intent are present; otherwise they remain fail-closed.
- Parent scan detail now shows per-shard endpoint contribution, aggregate auth/family rollups, and
  runtime-versus-active-cap budget view from child result summaries. Keep extending these rollups
  only when new scanner telemetry fields are added.

New quality gaps to track:

- **Worker-aware campaign waves:** avoid generating huge pending shard sets when the live worker
  fleet is small. Use allocator waves and larger batches before creating hundreds of scan rows.
- **XSS benchmark gap (partly closed):** Juice Shop hash-route DOM XSS is now browser-proven High;
  stored/reflected XSS beyond the hash route remain the open benchmark gap.
- **Stale workers invalidate benchmarks:** never measure on a build-stale fleet. `/workers` reports
  `build_current` (fingerprint-authoritative); scans stamp `*_at_submit` freshness metadata and can
  fail-closed with `require_current_workers=true`.
- **Coverage mode loses global checks:** parallel `coverage` detects fewer crit/high than a single
  Smart scan (zero-rediscovery children + fragmented global posture checks). Prefer single Smart for
  DAST-quality benchmarking; coverage is for breadth.
- **Workflow/write-BOLA gap:** crAPI read-BOLA is proven; safe non-destructive write/BFLA and
  workflow/object creation remain future Lab/deep-gated work.
- **Family/proof rollups:** `/asm/gaps` now returns `family_coverage` (completed vs attempts) and
  `recommended_campaigns`; it should keep distinguishing "endpoint attempted" from "SQLi proof
  attempted", "XSS browser proof attempted", and "BOLA cross-principal proof attempted".

### Phase D — UX/API/AI Simplification

- Add `Improve coverage`, `gaps`, and `activity` APIs. **Implemented.**
- Add UI presets and hide raw knobs by default. **Implemented.**
- Add a server-backed Dashboard Action Center for cross-product operator attention items.
  **Implemented:** `/dashboard` returns `action_center`, and the dashboard renders worker freshness,
  deploy blockers, failed scans, exception hygiene, ASM coverage/schedule gaps, Model Intake trust
  gaps, and AI control-baseline gaps.
- Update AGENTS/skills guidance so AI agents use presets instead of hand-crafted budgets.
  **Implemented.**
- Add a deterministic AI operations router for safe DAST/ASM intent-to-API planning with dry-run
  defaults and gated execution. **Implemented.**
- Hide ASM batch/recon implementation rows from the default Scans list once ASM activity is available.
  **Implemented.**
- Add a compact Settings view for safe automation defaults: auto-sharding, default ASM policy, and
  active-depth confirmation boundaries. **Implemented:** `/settings/automation` exposes the combined
  API for UI/API/AI callers; the Settings page shows a compact Automation Defaults card with
  auto-sharding, default Continuous ASM for new web targets, safe ASM presets, and read-only
  Lab/deep confirmation boundaries.

Remaining product work from the 2026-07-05 audit:

- ASM schedule editing now covers advanced batch fields, endpoint filter, focused family selection,
  and Lab/deep BOLA gating, and scheduled execution applies those settings during claimable-work
  selection and batch enqueue. Remaining schedule work is direct remediation/action wiring from the
  campaign timeline.
- Enrich the target campaign timeline with direct remediation/edit actions once each action has a
  tested confirmation boundary. Phase 1 derives timeline facts from scheduler state, schedules,
  active scans, and implementation scan/activity rows.
- Add component-level UI tests for ASM schedule creation/editing and skip-reason display once the UI
  test harness grows beyond helper-script coverage; current verification is TypeScript build plus
  browser QA.

### Phase E — Multi-Node Readiness

- Shared token buckets and endpoint leases are now used by local/owned worker processes for
  known-endpoint ASM and Full Coverage execution.
- Add worker placement metadata, reliable queue leases, and object-storage-backed artifacts before
  remote VPS workers are allowed to run high-volume ASM/coverage campaigns.

---

## Test Strategy

Unit tests:

- `asm_inventory`: fingerprint includes auth state and parameter location; volatile IDs still dedupe;
  replay preserves query/form/JSON/body shape; priority is stable.
- `parallel_scan`: coverage shard planning preserves every endpoint per auth state; explicit caps grow
  slices instead of dropping endpoints; auth state credentials do not leak between users.
- Dispatcher policy: UTC windows, wrap-midnight windows, min intervals, daily caps, and token-reserve
  decisions.

DB/integration tests:

- Concurrent `claim_test_batch` workers claim disjoint rows.
- Expired leases return to claimable state.
- Rate-token reservation blocks a second batch before completed stamps exist.
- Partial timeout result releases unattempted rows and marks only attempted rows partial/tested.

Worker/API tests:

- `POST /scans` with `parallel:true, shard_strategy:"coverage"` creates one parent and hidden shards.
- Parent cancellation cancels/reconciles shards and releases leases.
- `POST /targets/{id}/asm/test` creates an ASM activity row, not noisy user-facing scan spam.
- `GET /targets/{id}/asm/gaps` explains untested/auth-blocked/rate-limited/partial rows.
- Focused ASM family requests (`sqli`, `xss`, `bola`) only set the matching scanner options; BOLA
  also requires Lab/deep intent plus primary and second-user credentials.
- Default scan listing hides shard and ASM implementation rows unless the caller asks for internals.

UI tests:

- New Scan stays simple: Auto/Normal/Parallel/Full Coverage, advanced tuning collapsed.
- `/asm` shows rollup, coverage, new surface, and policy presets without exposing all raw knobs.
- Scans list shows one logical scan by default and no child shard flood.
- Settings communicates safe defaults without exposing allocator internals.

Live smoke tests before declaring the target architecture production-ready:

- Juice Shop: full-coverage campaign discovers a large worklist, fans out many shards/batches, and
  merges one parent with stable coverage counts.
- crAPI: authenticated user1/user2 coverage keeps auth states separate and exercises BOLA/IDOR paths.
- Honey/demo app: continuous ASM recon -> inventory -> improve coverage -> new-surface diff loop works.
- Slow endpoint fixture: timeout produces partial coverage, not false-clean coverage.

---

## AI Agent Task Appendix

Use this appendix when asking an AI coding/review agent to implement or audit ASM, campaign, or
check-family work. The goal is to keep complex automation safe and incremental.

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
State what API responses, ASM pages, scan detail pages, logs, reports, and hidden implementation rows
should show after the change.

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

Hard rule: exactly one architecture increment per implementation task. Do not combine attempt
ledger, dynamic coverage allocation, check registry, AI router, and multi-node fleet work in the same
change.

### Safety invariants for ASM work

- No endpoint is marked `tested` unless scanner telemetry proves it was attempted/completed.
- Partial timeout preserves findings but does not mark unattempted endpoints clean.
- Root-domain and target rate tokens are reserved before queueing active work.
- Endpoint identity includes auth state and parameter location/shape.
- Replay specs preserve query vs. form vs. JSON vs. multipart semantics.
- Shard/batch rows stay hidden from normal user-facing scan lists.
- Parent/merge logic is idempotent under retries.
- Active exploitation remains bounded unless an explicit Lab/deep policy is selected.
- Missing credentials mark matching auth-state rows auth_missing/auth_failed, never tested
  anonymously.
- Focused family campaigns must not run unrelated high-risk checks.

### Prompt: harden the campaign allocator and attempt ledger rollups

```text
ROLE
You are a senior backend engineer implementing ShakerScan's campaign allocator and ASM attempt
ledger.

MODE
IMPLEMENT

EDIT PERMISSION
Code and test edits are allowed for this prompt. Do not edit scanner-stage sharding, check registry,
multi-node transport, or public POST /scans API shape unless a verified contract bug requires it.

TASK
Make the shipped campaign/lease/attempt foundation authoritative for coverage rollups and ready for
dynamic Full Coverage allocation.

SOURCE OF TRUTH
Use:
- docs/parallel-scan-architecture.md
- docs/continuous-asm-architecture.md
- docs/multi-node-architecture.md
Verify api/asm_inventory.py, api/worker.py, api/api.py, db/init.sql, runtime migrations, scanner
telemetry producers, report rollups, and tests before editing.

STATUS PREFLIGHT
Confirm:
- target_endpoints contains shipped lease/status/replay/auth fields;
- scan_campaigns and asm_endpoint_attempts exist;
- ASM batches claim durable leases;
- coverage rollups use attempt facts when available;
- missing scanner telemetry does not promote coverage;
- dynamic Full Coverage allocation is the default and static allocation remains the explicit fallback.

CURRENT STATE
- Verify the current shipped behavior before editing.
- target_endpoints exists and includes auth_state, param_location, replay_spec, priority_score,
  test_status, last_attempt_status, last_verdict, campaign_id, lease_owner, lease_expires_at, and
  attempt_count.
- scan_campaigns, scans.campaign_id, and asm_endpoint_attempts exist for ASM recon/test batches.
- ASM batches claim rows with FOR UPDATE SKIP LOCKED, set durable leases, and write batch-level
  attempt rows.
- One-shot coverage defaults to dynamic pull workers and feeds inventory by claiming
  campaign-scoped inventory through the ASM allocator; static shard slices remain available by
  explicit fallback.

TARGET BEHAVIOR
- Coverage percentages derive from attempt records, not scan row status.
- On timeout, mark only attempted endpoints partial and release unattempted endpoints.
- On missing credentials, mark matching auth-state rows auth_missing/auth_failed, never tested
  anonymously.
- Full Coverage can create `full_coverage` campaigns and write attempt facts under the parent scan.
- Scanner telemetry distinguishes claimed, attempted, completed, partial, and unattempted endpoints.

NON-GOALS
- Do not rewrite the whole scanner.
- Do not expose allocator internals as UI knobs.
- Do not remove the existing static coverage path until campaign allocation is stable.

DO NOT TOUCH
- Scanner-stage refactor unless required for telemetry correctness.
- Check registry.
- Multi-node queue transport.
- UI redesign beyond rollup fields.

SAFETY INVARIANTS
- No endpoint is marked tested without scanner telemetry.
- Partial timeout marks only attempted endpoints partial.
- Unattempted rows are released or remain stale/untested, never clean.
- Auth-state and replay semantics are preserved.
- Parent/merge remains idempotent under duplicate delivery.

AUTHORIZATION / BLAST RADIUS
- Target authorization assumption: user owns or is authorized to test the target.
- Allowed preset: Safe/Balanced unless explicitly Lab/deep.
- Credentials: preserve anonymous/user1/user2 rows and missing-credential behavior.
- High-risk families: do not add new families.
- Rate limits: preserve target/root-domain reservation before high-volume active work.
- Confirmation is required before queueing active work outside tests.

DATA CONTRACTS
Define or verify DB rows, API JSON, Redis payloads, scanner telemetry JSON, parent report rollups,
and UI-facing fields. For each changed contract, state producer, consumer, compatibility,
old-row/null behavior, and idempotency key.

MIGRATION / BACKFILL / COMPATIBILITY
- Do not infer historical endpoint attempts from completed scan rows unless telemetry exists.
- Keep existing ASM batch path as fallback during rollout.
- If new scanner telemetry schema is needed, add it in db/init.sql and runtime migrations together.

ROLLOUT / FALLBACK
- Feature flag: name it if behavior changes are not strictly backward compatible.
- Default: existing ASM batch and dynamic Full Coverage paths keep working; static Full Coverage is
  selected only when `coverage_allocation=static` or `COVERAGE_ALLOCATION_DEFAULT=static`.
- Fallback: endpoint-status coverage and assigned-slice partial attempts remain readable.
- Rollback: preserve old rows/reports and avoid destructive backfills.
- Unsafe signals: coverage increases without endpoint telemetry, leases remain stuck, or duplicate
  attempts appear for the same endpoint/campaign/scan.

FAILURE-MODE MATRIX
Cover worker crash, duplicate delivery, parent cancellation, timeout after partial work, missing
credentials, rate budget exhaustion, missing scanner telemetry, and corrupt/missing shard context.
State expected behavior and required tests for each.

OBSERVABILITY / UI / REPORT BEHAVIOR
- GET /targets/{id}/asm/gaps explains untested, partial, auth-blocked, rate-limited, and leased
  states.
- ASM activity shows campaign/batch status without exposing internal scan rows in the default Scans
  list.
- Parent scan reports show tested, partial, untested, auth-blocked, and rate-limited counts.

ACCEPTANCE CRITERIA
- Concurrent workers claim disjoint endpoint leases.
- Expired leases return to claimable state.
- Partial timeout does not create false-clean coverage.
- POST /scans parallel coverage can create a campaign and report tested/partial/untested counts.

TESTS REQUIRED
- DB tests for lease acquisition, expiry, and reclaim.
- API tests for gaps and coverage rollups.
- Worker tests for success, timeout, auth_missing, and retry.
- Regression tests for replay_spec preservation.

TEST COMMANDS
Report exact commands run and any expected commands not run with reasons.

OUTPUT FORMAT
Return status preflight, changed files, behavior summary, safety checks, data contracts changed,
tests run, remaining risks, and follow-up tasks.
```

### Prompt: migrate scanner execution to the check registry

```text
ROLE
You are a senior DAST platform engineer modularizing ShakerScan active/passive checks.

MODE
IMPLEMENT

EDIT PERMISSION
Code and test edits are allowed for this prompt. Do not change vulnerability detection logic, dynamic
coverage allocation, multi-node transport, or public scan API shape unless the registry contract
requires a backward-compatible validation addition.

TASK
Migrate scanner module execution from scattered boolean wiring to the shipped CHECK_REGISTRY
foundation.

SOURCE OF TRUTH
Use:
- docs/parallel-scan-architecture.md
- docs/continuous-asm-architecture.md
- docs/multi-node-architecture.md
Verify scanner flag wiring, ASM check_family API handling, worker options, UI labels, and tests before
editing.

STATUS PREFLIGHT
Confirm:
- focused ASM batches currently support sqli, xss, and explicit gated bola;
- `api/check_registry.py` exists and rejects registered-but-unrunnable families for ASM batches;
- high-risk families are not silently enabled; BOLA requires Lab/deep plus two auth contexts;
- public scan options remain backward compatible;
- AI router and multi-node work are out of scope;
- dynamic Full Coverage allocation is now the default; static fallback and live soak remain in scope.

CURRENT STATE
- Verify the current shipped behavior before editing.
- Focused ASM batches currently support sqli, xss, and explicit gated bola through
  registry-backed validation plus scanner boundary wiring.
- A registry for recon/passive, nuclei, sqli, xss, bola, auth, ssrf/lfi/rce, and business_logic
  exists, but scanner `build_report()` still uses legacy boolean/module wiring.

TARGET BEHAVIOR
Use the registry so:
- scan types select families declaratively;
- focused_family campaigns schedule exactly one family;
- parallel plan stage can assign families to shards;
- API rejects unknown or disallowed families;
- high-risk families require explicit Lab/deep policy.
- scanner `build_report()` iterates runnable registry entries per phase where practical.

NON-GOALS
- Do not change vulnerability detection logic in this task.
- Do not silently enable ssrf/lfi/rce/business_logic.
- Do not expose raw internal registry structure in the default UI.

DO NOT TOUCH
- Exploit payload logic and detection heuristics.
- Dynamic Full Coverage allocator default rollout.
- Multi-node queue transport.
- AI router behavior.

SAFETY INVARIANTS
- Focused family campaigns run only the requested family.
- High-risk families require explicit Lab/deep policy.
- Missing credentials cannot be treated as anonymous success.
- Existing sqli/xss flags remain compatible, and BOLA stays explicit through check_family.

AUTHORIZATION / BLAST RADIUS
- Target authorization assumption: user owns or is authorized to test the target.
- Allowed preset: Safe/Balanced for current sqli/xss focused work; Lab/deep required for BOLA and
  future high-risk families.
- Auth states: preserve requested auth-state scope.
- Rate limits: do not raise target/root-domain caps.
- Confirmation is required before active high-risk family execution.

DATA CONTRACTS
Verify or extend registry entry shape, API validation JSON, Redis/job option mapping, scanner
telemetry family labels, report family scope fields, and UI-facing family names. For each changed
contract, state producer, consumer, compatibility, old-row/null behavior, and uniqueness rule.

MIGRATION / BACKFILL / COMPATIBILITY
- Avoid schema changes unless telemetry storage requires them.
- Keep existing sqli/xss flags compatible until all call sites use the registry; keep BOLA behind
  explicit `check_family=bola` rather than adding legacy boolean flags.

ROLLOUT / FALLBACK
- Feature flag: name it if registry routing can be disabled.
- Default: keep existing sqli/xss behavior and exclude BOLA from automatic family fan-out.
- Fallback: legacy boolean flags for sqli/xss; BOLA remains unavailable unless `check_family=bola`
  reaches the scanner through the registry path.
- Rollback: disable registry routing without changing stored reports.
- Unsafe signals: unrelated families run during focused campaigns or unknown family errors become
  silent defaults.

FAILURE-MODE MATRIX
Cover duplicate job delivery, parent cancellation, timeout after partial work, missing credentials,
rate budget exhaustion, missing scanner telemetry, and corrupt/missing family context. State expected
behavior and required tests for each.

OBSERVABILITY / UI / REPORT BEHAVIOR
- API errors name the rejected family and allowed families.
- UI may display friendly family names and risk tiers, but keeps advanced knobs collapsed.
- Scan reports show the family scope used for focused campaigns.

ACCEPTANCE CRITERIA
- Adding a new check family requires one registry entry plus module integration.
- POST /targets/{id}/asm/test?check_family=sqli only enables SQLi.
- xss and sqli existing behavior remains compatible.
- Unknown families return a clear API error.

TESTS REQUIRED
- Registry unit tests.
- API tests for allowed, unknown, and disallowed families.
- Focused campaign tests proving unrelated scanner flags remain off.

TEST COMMANDS
Report exact commands run and any expected commands not run with reasons.

OUTPUT FORMAT
Return status preflight, changed files, behavior summary, safety checks, data contracts changed,
tests run, remaining risks, and follow-up tasks.
```

### Prompt: soak default dynamic Full Coverage allocation

```text
ROLE
You are a backend engineer unifying one-shot Full Coverage and Continuous ASM execution.

MODE
IMPLEMENT

EDIT PERMISSION
Code and test edits are allowed for this prompt. If status preflight finds that a "shipped" claim is
stale, stop and report before editing.

TASK
Harden default dynamic Full Coverage allocation, continue live parity, and keep static shard slices
as the rollback path.

SOURCE OF TRUTH
Use:
- docs/parallel-scan-architecture.md
- docs/continuous-asm-architecture.md
- docs/multi-node-architecture.md
Before editing, verify shipped behavior in api/parallel_scan.py, worker queue handling, DB
migrations, ASM allocator code, scan_merge, scanner telemetry, API handlers, UI rollups, and tests.

STATUS PREFLIGHT
Confirm:
- coverage parents create full_coverage campaigns;
- child scan rows inherit campaign_id;
- scan_merge writes telemetry-backed asm_endpoint_attempts;
- legacy/no-telemetry children fall back to assigned-slice partial rows;
- one-shot coverage defaults to dynamic pull workers;
- `coverage_allocation=static` still queues legacy static shard slices;
- Continuous ASM already claims target_endpoints through durable leases.

CURRENT STATE
- Summarize the verified shipped behavior in exactly 5 bullets.

TARGET BEHAVIOR
- scan_plan runs discover-once recon and upserts endpoints into target_endpoints.
- coverage workers claim endpoint batches dynamically from the allocator.
- workers continue until campaign budget is exhausted or all eligible endpoint rows are terminal.
- scan_merge reads campaign attempt facts and child result files.
- parent report shows discovered, tested, partial, untested, auth-blocked, rate-limited, and error
  counts.
- static allocation remains available as fallback through `coverage_allocation=static`.

NON-GOALS
- Do not remove static shard fallback.
- Do not rewrite scanner-stage execution.
- Do not add the check registry.
- Do not implement multi-node transport.
- Do not expose allocator internals in the UI.

DO NOT TOUCH
- Scanner-stage refactor unless required for telemetry.
- Check registry.
- Multi-node queue transport.
- UI redesign beyond rollup fields.
- Public POST /scans API shape.

SAFETY INVARIANTS
- No endpoint marked tested without scanner telemetry.
- Partial timeout marks only attempted endpoints partial and releases unattempted rows.
- Missing credentials mark matching auth-state rows auth_missing/auth_failed.
- Rate tokens are reserved before queueing active work.
- Parent/merge remains idempotent under duplicate completion.
- Parent cancellation releases leases and blocks unsafe merge.

AUTHORIZATION / BLAST RADIUS
- Target authorization assumption: user owns or is authorized to test the target.
- Allowed preset: Safe/Balanced by default; Lab/deep only when explicitly requested.
- Credentials: preserve anonymous/user1/user2 auth states and replay specs.
- High-risk families: do not add new families or raise exploit depth implicitly.
- Rate limits: do not raise target/root-domain caps without an explicit budget change.
- Confirmation is required before queueing active work outside tests.

DATA CONTRACTS
Define or verify:
- coverage campaign fields;
- endpoint lease fields;
- coverage batch job payload;
- asm_endpoint_attempts rows;
- scanner endpoint_attempts telemetry;
- parent smart_coverage rollup JSON;
- UI-facing rollup fields.
For each changed contract, state producer, consumer, compatibility, old-row/null behavior, and
idempotency key.

MIGRATION / BACKFILL / COMPATIBILITY
- Keep old static partition path behind a fallback flag.
- Do not reinterpret old completed scan rows as attempted endpoint telemetry.
- Preserve old report readability.
- Add migrations only with db/init.sql and runtime migration parity.

ROLLOUT / FALLBACK
- Feature flag/API option: `coverage_allocation=static` or `COVERAGE_ALLOCATION_DEFAULT=static`.
- Default value: dynamic.
- Static fallback remains available for rollback and live parity comparison.
- Fallback path: static round-robin coverage slices.
- Rollback behavior: existing parent reports and attempt rows remain readable.
- Unsafe signals: duplicate claims, stuck leases, coverage increases without telemetry, or parent
  reports disagree with /asm/gaps.

FAILURE-MODE MATRIX
Cover worker crash, lease expiry, duplicate job delivery, timeout, cancellation, missing telemetry,
auth_missing, rate_limited, corrupt child result files, and object/evidence failure if artifacts move.
For each: expected behavior and required tests.

OBSERVABILITY / UI / REPORT BEHAVIOR
- Scan Detail shows campaign rollup, not raw allocator internals.
- Logs show claim, release, retry, budget exhaustion, and fallback.
- /asm/gaps and parent report agree on tested/partial/untested counts.
- Default scan list still shows one logical scan and hides implementation rows.

ACCEPTANCE CRITERIA
- Concurrent coverage workers claim disjoint endpoint batches.
- Uneven endpoint durations do not create static shard stragglers.
- Expired leases are reclaimed.
- Partial timeout does not create false-clean coverage.
- Static coverage remains available behind a fallback flag.
- Parent coverage derives from attempt facts where available.

TESTS REQUIRED
- DB tests for claim/reclaim/disjoint leases.
- Worker tests for success, timeout, crash/reclaim, cancellation, and missing telemetry.
- API/report tests for parent rollup and /asm/gaps agreement.
- Regression tests for replay_spec and auth_state preservation.
- Slow endpoint fixture proving partial, not false-clean.

TEST COMMANDS
Report exact commands run and any expected commands not run with reasons.

OUTPUT FORMAT
Return status preflight, changed files, behavior summary, safety checks, data contracts changed,
tests run, remaining risks, and follow-up tasks.
```

### AI Intent Router

Implemented endpoint:

```text
POST /ai/ops/route
```

Shipped behavior:

- Maps "run full coverage" to a dry-run `POST /scans` plan with `parallel=true`,
  `shard_strategy=coverage`, `scan_type=smart`, `budget_profile=thorough`, and
  `exploit_depth=false`.
- Maps "keep this target covered" to a dry-run `PUT /targets/{id}/asm/policy` plan using the safe
  Continuous ASM defaults.
- Maps "what is still untested?" to `GET /targets/{id}/asm/gaps`.
- Maps "spend more budget on APIs" to `POST /targets/{id}/asm/improve` with
  `endpoint_filter=api`, a larger one-shot `batch_size`, and no target-wide default changes.
- Maps focused SQLi/XSS/Auth/BOLA requests to `POST /targets/{id}/asm/improve` with the matching
  `check_family`; Auth plans require primary auth context, while BOLA plans include
  `exploit_depth=true` and require primary plus second-user auth context before execution.
- Returns `dry_run=true` by default for active, state-changing, or budget-increasing intents.
  Execution requires `execute=true`, explicit confirmations, and
  `AI_OPS_ROUTER_EXECUTE_ENABLED=true`.
- Returns `planned_api_call`, `planned_api_calls`, `safety_preset`,
  `authorization_assumption`, `blast_radius`, `non_goals`, `missing_inputs`, and an execution result
  with `scan_id`/`campaign_id`/`ui_link` when execution is allowed.

Safety boundaries:

- Ambiguous language never upgrades Safe/Balanced to Lab.
- Missing target, credentials, or auth-state inputs produce `missing_inputs`, not execution.
- High-risk active exploitation requires explicit high-risk confirmation.
- The router does not expose shard/batch implementation rows.

Current limitation:

- `endpoint_filter=api` is a conservative derived filter using path, method, body parameter
  location, and discovery source. A future `endpoint_class` column can make this more precise, but
  the shipped filter is safe because it narrows work instead of broadening target-wide budget.
