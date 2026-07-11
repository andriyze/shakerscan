# Parallel Scan AI Agent Task Appendix

**Archived:** 2026-07-11. These implementation prompts were separated from the live parallel-scan
architecture after the bounded local orchestration shipped. They remain historical input, not a
current roadmap or implementation claim.

## AI Agent Task Appendix

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
