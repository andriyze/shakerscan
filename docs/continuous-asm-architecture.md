# Continuous ASM Architecture — Current State and Target Design

**Status:** first continuous ASM loop is shipped; correctness hardening for auth-aware inventory,
replay fidelity, partial-timeout coverage semantics, and dispatcher rate reservation is implemented.
The larger campaign allocator and attempt-ledger design is still proposed.
**Date:** 2026-06-16
**Related design:** [parallel-scan-architecture.md](parallel-scan-architecture.md),
[multi-node-architecture.md](multi-node-architecture.md).

---

## Purpose

ShakerScan should evolve from "a scan is a one-shot job" into "a target has a living attack
surface that is discovered, queued, tested, retried, and aged continuously."

Parallel Full Coverage scans and Continuous ASM should become two views over the same facts:

- **One-shot Full Coverage:** a user asks for a logical scan now; ShakerScan discovers endpoints,
  spends an explicit campaign budget, fans work out across workers, and merges one parent report.
- **Continuous ASM:** the system keeps the target inventory fresh over time; it spends small safe
  budgets during allowed windows and converges toward higher coverage without overwhelming the target.

The user-facing model stays simple: "run Full Coverage now" and "keep this target covered" are
different entry points, not separate engines.

---

## Current Implementation

### Shipped Loop

Shipped pieces:

- `target_endpoints` persists discovered endpoint worklists from standalone scans, coverage recon,
  parallel scan merge, and ASM batches.
- Current APIs:
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
- `asm_dispatcher` periodically decides recon vs. test using target policy: batch size, stale TTL,
  min interval, daily cap, recon cadence, UTC windows, weekday windows, and per-root-domain caps.
- `/asm` gives users a rollup, coverage advisor, one-click Improve Coverage action, target
  inventory, coverage gaps, ASM activity, policy presets, local-time window helper, and
  new-surface feed.
- Gungnir can inherit ASM policy for newly discovered subdomains under an ASM-enabled root.

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
  - first/last seen/tested timestamps

Current fields that do **not** exist yet:

- `credential_ref`
- `campaign_id`
- `lease_owner`
- `lease_expires_at`
- `attempt_count`
- a normalized `asm_endpoint_attempts` table
- per-endpoint/per-parameter attempted telemetry from the scanner

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

Still limited:

- A batch is claimed by status and auth state, but there is no durable lease expiry field yet.
- Coverage stamping is still batch-level. Without scanner-level per-endpoint attempted telemetry, a
  successful batch can only stamp the claimed batch as tested/partial as a group.
- One-shot parallel `coverage` still uses static shard slices. It feeds ASM inventory, but it does not
  yet claim work through the ASM allocator.
- ASM batch scan rows still exist in the `scans` table. Product UI should group or hide them as ASM
  activity as volume grows.

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

Recommended additional fields beyond the current table:

```text
credential_ref              -- reference to current credential, not raw secret
param_shape_hash            -- explicit stable hash of parameter names / JSON paths
source_set                  -- crawl, HAR, JS, OpenAPI, manual, Gungnir, previous scan
campaign_id                 -- optional one-shot coverage campaign that discovered/claimed it
lease_owner
lease_expires_at
attempt_count
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
3. Claim endpoint rows with `FOR UPDATE SKIP LOCKED`, set `lease_owner`, `lease_expires_at`, and
   `coverage_status='leased'`.
4. Queue a worker job that carries claimed endpoint IDs and replay specs.
5. On success, stamp only endpoints the scanner reports as attempted/completed.
6. On timeout/partial, mark attempted endpoints as `partial` and release unattempted rows for retry.
7. On worker crash, a lease reaper returns expired `leased` rows to `untested` or increments
   `attempt_count` with backoff.

This solves the high-risk cases:

- A root-domain rate cap cannot be exceeded by several targets queueing at once.
- A slow batch cannot claim 100 endpoints, time out after 3, and mark all 100 clean.
- Many workers can drain one target without static stragglers.

### Attempt Ledger

Add `asm_endpoint_attempts` or equivalent normalized attempt storage:

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

Coverage percentages should derive from attempt outcomes, not scan status alone.

---

## Relationship to Parallel Scans

Parallel `coverage` should become a campaign over the same allocator.

Current shipped behavior:

- `scan_plan` runs discover-once recon.
- `harvest_endpoints()` partitions the worklist into static coverage shards.
- `scan_shard` workers run lean scans over disjoint endpoint slices.
- `scan_merge` produces one parent report and persists the union into ASM inventory.

Target behavior:

- `scan_plan` creates a coverage campaign tied to the parent scan and upserts discovered endpoints.
- The campaign asks the allocator for work until it hits its budget or all eligible rows are terminal.
- Worker jobs are coverage-batch/ASM-batch equivalents; the difference is the rollup target:
  `parent_scan_id` for one-shot scans, target policy for continuous ASM.
- `scan_merge` reads the attempt ledger for the campaign, not just child scan result JSON.
- The parent report shows tested, partial, untested, auth-blocked, and rate-limited counts so the
  grade can be trusted or clearly marked limited.

Static partitioning is acceptable for the shipped path, but pull-based allocation is the end state
because it handles uneven endpoints, retries, auth-state expansion, and large fleets better.

---

## User-Facing Model

Keep the UI small. Users should not need twenty sharding controls.

Current UI/API:

- `/asm` shows coverage posture, new surface, inventory, policy, and manual test actions.
- `/asm` now leads with a coverage advisor and one-click Improve Coverage action.
- Policy setup is preset-first (`Safe`, `Balanced`, `Lab`) with raw knobs hidden behind Advanced.
- New Scan exposes the parallel/coverage path without requiring users to understand every shard knob.
- Child shard rows are hidden from the main Scans list by default.

Recommended UI:

- **Attack Surface (`/asm`):** one primary action, `Improve coverage`, that chooses recon vs. test
  batch based on current state. Keep manual `Run recon` and `Test next batch` secondary.
- **Continuous policy:** one enable switch plus presets: `Safe`, `Balanced`, `Aggressive lab`.
  Advanced fields stay expandable.
- **Scans list:** keep one logical scan row. Hide child shards by default. Group Continuous ASM batch
  rows under ASM activity so users do not see hundreds of implementation rows.
- **Scan detail:** parent rows show campaign coverage: endpoints discovered, tested, partial,
  untested, auth states, and shard/batch progress.

Current API:

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

AI skills should map natural requests to these APIs:

- "Run full coverage on this target" -> one-shot coverage scan with safe defaults.
- "Keep this target covered" -> enable Continuous ASM with a safe preset and report the policy.
- "What is still untested?" -> gaps response with auth/rate/timeout reasons.
- "Spend more budget on APIs" -> raise endpoint/test budget for the next campaign, not global defaults.

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

Remaining:

- Clean Scans list/ASM activity grouping if batch rows become noisy.

### Phase B — Attempt Ledger + Durable Leases

- Add `asm_endpoint_attempts` keyed by endpoint, job, campaign, worker, status, started/completed
  time, tested parameter counts, and finding IDs.
- Add `lease_owner`, `lease_expires_at`, and a lease reaper.
- Make coverage percentages derive from attempt outcomes.

### Phase C — Parallel Coverage Uses The Allocator

- `coverage` campaigns claim batches dynamically instead of static round-robin partitions.
- Merge consumes attempt ledger and child result files.
- Keep current static partition path as fallback while campaign mode stabilizes.

### Phase D — UX/API/AI Simplification

- Add `Improve coverage`, `gaps`, and `activity` APIs. **Implemented.**
- Add UI presets and hide raw knobs by default. **Implemented.**
- Update AGENTS/skills guidance so AI agents use presets instead of hand-crafted budgets.

### Phase E — Multi-Node Readiness

- Use the same token buckets and leases across fleet workers.
- Add worker placement metadata and object-storage-backed artifacts before remote VPS workers are
  allowed to run high-volume ASM/coverage campaigns.

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

UI tests:

- New Scan stays simple: Auto/Normal/Parallel/Full Coverage, advanced tuning collapsed.
- `/asm` shows rollup, coverage, new surface, and policy presets without exposing all raw knobs.
- Scans list shows one logical scan by default and no child shard flood.

Live smoke tests before declaring the target architecture production-ready:

- Juice Shop: full-coverage campaign discovers a large worklist, fans out many shards/batches, and
  merges one parent with stable coverage counts.
- crAPI: authenticated user1/user2 coverage keeps auth states separate and exercises BOLA/IDOR paths.
- Honey/demo app: continuous ASM recon -> inventory -> improve coverage -> new-surface diff loop works.
- Slow endpoint fixture: timeout produces partial coverage, not false-clean coverage.
