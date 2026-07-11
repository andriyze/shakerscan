# Continuous ASM AI Agent Task Appendix

**Archived:** 2026-07-11. These implementation prompts were removed from the live architecture
document after their bounded work was completed or migrated into the current roadmap. They are
retained for engineering-history and audit context only. Do not treat this file as current status.

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
