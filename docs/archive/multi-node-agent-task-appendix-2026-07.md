# Multi-Node AI Agent Task Appendix

**Archived:** 2026-07-11. These old execution prompts are preserved for design history. The live
multi-node RFC owns current scope and sequencing; this appendix must not be read as evidence that
the proposed fleet commands or production controls have shipped.

## AI Agent Task Appendix

Use this appendix when asking an AI coding/review agent to implement or audit multi-node work. Fleet
work has a high blast radius, so prompts must separate proof-of-concept overlay work from
production-ready queue, evidence, routing, and security work.

### Required prompt contract

Every prompt should contain:

```text
ROLE
You are a distributed systems engineer hardening ShakerScan multi-node execution.

MODE
Choose exactly one: IMPLEMENT | REVIEW | PLAN | TEST_ONLY | DOCS_ONLY.

EDIT PERMISSION
State whether code edits are allowed. If MODE is REVIEW or PLAN, do not modify files.

TASK
Implement or review exactly one multi-node architecture increment.

SOURCE OF TRUTH
Use these docs as authoritative architecture context:
- docs/parallel-scan-architecture.md
- docs/continuous-asm-architecture.md
- docs/multi-node-architecture.md
Before changing code, verify shipped behavior in the repository, Docker/compose files, API handlers,
worker code, DB migrations, queue use, and tests.
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
For DB rows, API JSON, Redis job payloads, scanner telemetry, report rollups, object/evidence
records, node records, and UI-facing fields changed or verified, state producer, consumer, backward
compatibility, old-row/null behavior, and the idempotency key or uniqueness rule.

MIGRATION / BACKFILL / COMPATIBILITY
State whether schema/data changes are required, how existing installs are upgraded, and what fallback
exists for standalone mode.

ROLLOUT / FALLBACK
State feature flag name, default value, fallback path, rollback behavior, old scan/report readability,
and log/metric signals that indicate unsafe behavior.

FAILURE-MODE MATRIX
Explicitly cover worker crash mid-job, duplicate job delivery, parent cancellation, timeout after
partial work, missing credentials, rate budget exhaustion, missing scanner telemetry,
corrupt/missing shard context, and object-store/evidence failure. For each: expected behavior and
whether a test is required.

OBSERVABILITY / UI / REPORT BEHAVIOR
State what API responses, fleet views, scan detail pages, logs, reports, artifact links, and node
audit fields should show after the change.

FILES / COMPONENTS TO INSPECT
List expected files, but verify with search before editing.

IMPLEMENTATION PLAN
Return a short plan first. Then implement.

ACCEPTANCE CRITERIA
Provide API behavior, DB state, queue behavior, UI/report behavior, node lifecycle behavior, and
failure behavior.

TESTS REQUIRED
Add or update unit, DB/integration, worker/API, queue, object-storage, and UI tests where applicable.

TEST COMMANDS
Before final response, report commands run and commands not run with reasons. Include minimum expected
unit, DB/integration, worker/API, queue/object-storage, UI, and live-smoke coverage for the task.

OUTPUT FORMAT
Return: status preflight; changed files; behavior summary; safety checks; data contracts changed;
tests run; remaining risks; follow-up tasks.
```

Hard rule: exactly one architecture increment per implementation task. Do not combine WireGuard
join flow, node registry, object storage, Redis Streams migration, routing, rate limiting, and HTTPS
broker work in one change.

### Safety invariants for fleet work

- Standalone mode remains the default and must keep working.
- Worker nodes should never require public Redis/Postgres exposure.
- Adding nodes must not multiply target request pressure beyond global rate caps.
- Queue completion must be idempotent under duplicate delivery or retry.
- Reports must not reference artifacts stranded on worker-local filesystems.
- Draining a node stops new work but lets current work finish or return leases.
- Node/version/egress attribution is recorded for scans, shards, and attempts when fleet mode is
  active.
- Untrusted/customer-hosted workers use a broker model later; do not give them direct DB/Redis access.

### Prompt: production-ready multi-node queue, evidence, and rate-limit layer

```text
ROLE
You are a distributed systems engineer hardening ShakerScan multi-node execution.

MODE
IMPLEMENT

EDIT PERMISSION
Code and test edits are allowed for this prompt. Do not implement the HTTPS broker, scanner
detection changes, or cloud provisioning unless explicitly requested in a separate prompt.

TASK
Implement production-owned-fleet primitives for multi-node workers.

SOURCE OF TRUTH
Use:
- docs/parallel-scan-architecture.md
- docs/continuous-asm-architecture.md
- docs/multi-node-architecture.md
Verify Docker/compose files, scanner.sh, API handlers, worker queue code, DB migrations, artifact
storage, rate limiting, UI surfaces, and tests before editing.

STATUS PREFLIGHT
Confirm:
- parallel parent/plan/shard/merge is shipped and queue-backed;
- standalone mode remains default;
- WireGuard owned-fleet mode is proposed/RFC;
- HTTPS broker for untrusted workers is future work;
- Redis/Postgres must not be publicly exposed;
- current evidence/result storage behavior is local or incomplete for remote workers.

CURRENT STATE
- Verify the current shipped behavior before editing.
- Parallel parent/plan/shard/merge is shipped and queue-backed.
- Phase 1 fleet mode is proposed: owned worker VPSs over ShakerScan-managed WireGuard.
- Workers can share Redis/Postgres over the overlay in controlled environments, but this is not
  production-ready because evidence is local/incomplete, queue pop is at-most-once, scaling remote
  nodes is manual, and routing assumes homogeneous workers.

TARGET BEHAVIOR
- Add node registry with node_id, hostname, overlay IP, egress IP, region, version, labels,
  capabilities, capacity, active_worker_count, desired_worker_count, heartbeat, and drain state.
- Add node-agent pull loop for desired state.
- Move evidence to S3/MinIO-compatible object storage.
- Replace or wrap Redis list pop with Redis Streams consumer groups or equivalent ack/reclaim
  semantics.
- Extend the shipped known-endpoint token buckets only for adapters with exact or enforceable
  upper-bound metering; label all other standalone budget enforcement soft or unavailable.
- Add routing labels for region, egress group, private reachability, scan tier, and tool
  requirements.
- Record node/version/egress attribution on scan, shard, and attempt records.

NON-GOALS
- Do not expose Redis/Postgres publicly.
- Do not build a worker mesh.
- Do not implement the HTTPS broker in this task unless explicitly requested.
- Do not change parallel scan planning semantics.

DO NOT TOUCH
- HTTPS broker.
- Cloud provisioning.
- Scanner vulnerability detection logic.
- Public exposure of Redis/Postgres.
- Parallel scan planner semantics.

SAFETY INVARIANTS
- Standalone mode remains the default.
- Workers never require public Redis/Postgres exposure.
- Adding nodes does not multiply target pressure beyond global rate caps.
- Queue completion remains idempotent under duplicate delivery/retry.
- Artifacts are readable from the control plane.

AUTHORIZATION / BLAST RADIUS
- Target authorization assumption: user owns or is authorized to test targets routed to fleet nodes.
- Allowed preset: unchanged by fleet routing.
- Credentials/auth states: preserve existing scan options and storage boundaries.
- Rate limits: distributed target/root-domain caps must be enforced before dispatch.
- Confirmation is required before active live scans in smoke tests.

DATA CONTRACTS
Define or verify node registry rows, queue ack/reclaim payloads, object/evidence records, distributed
rate-token keys, scan/shard/attempt attribution fields, API JSON, and UI fields. For each changed
contract, state producer, consumer, compatibility, old-row/null behavior, and idempotency key.

MIGRATION / BACKFILL / COMPATIBILITY
- Add node/evidence/attribution schema in db/init.sql and runtime migrations together.
- Existing standalone installs should start with one implicit local node or no fleet node requirement.
- Existing local result files remain readable; new fleet artifacts use object storage.
- Keep Redis list mode available as a local/dev fallback until Streams parity tests pass.

ROLLOUT / FALLBACK
- Feature flag: name the fleet queue/evidence mode flag.
- Default: standalone/local Redis list mode remains available.
- Fallback: local workers and local artifact paths.
- Rollback: disable remote node scheduling without losing existing scans/reports.
- Unsafe signals: unreclaimable jobs, missing artifacts, target rate cap bypass, or node attribution
  gaps on fleet jobs.

FAILURE-MODE MATRIX
Cover worker crash mid-job, duplicate job delivery, parent cancellation, timeout after partial work,
missing credentials, rate budget exhaustion, missing scanner telemetry, corrupt/missing shard
context, node drain, heartbeat expiry, and object-store/evidence failure. State expected behavior and
required tests for each.

OBSERVABILITY / UI / REPORT BEHAVIOR
- Fleet view shows node health, capacity, desired/current worker count, version, egress IP, drain
  state, and recent jobs.
- Scan detail shows shard/node attribution when available.
- Artifact links work from the control-plane UI regardless of which node produced them.
- Logs expose lease claim, ack, reclaim, drain, and rate-limit decisions.

ACCEPTANCE CRITERIA
- A worker crash leaves jobs reclaimable.
- Artifacts from any node are visible from the control-plane UI.
- Draining a node stops new work but lets current jobs finish or return leases.
- Jobs can be routed by label.
- Node attribution appears in scan/shard/attempt records.
- Adding workers does not exceed distributed target/root-domain rate caps.

TESTS REQUIRED
- Redis Streams or equivalent ack/reclaim tests.
- Object storage upload/download tests.
- Token bucket concurrency tests across simulated nodes.
- Node drain, heartbeat expiry, and version mismatch tests.
- UI/API tests for fleet view and artifact access.

TEST COMMANDS
Report exact commands run and any expected commands not run with reasons.

OUTPUT FORMAT
Return status preflight, changed files, behavior summary, safety checks, data contracts changed,
tests run, remaining risks, and follow-up tasks.
```

### Prompt: two-VPS WireGuard proof

```text
ROLE
You are implementing the first owned-fleet proof for ShakerScan.

MODE
IMPLEMENT

EDIT PERMISSION
Code and test edits are allowed for this prompt. Do not build production queue replacement, cloud
provisioning, HTTPS broker, or scanner detection changes.

TASK
Implement the smallest safe two-VPS WireGuard join flow.

SOURCE OF TRUTH
Use:
- docs/parallel-scan-architecture.md
- docs/continuous-asm-architecture.md
- docs/multi-node-architecture.md
Verify install/start/remote-mode behavior, scanner.sh, compose files, worker startup, API status
routes, node registration candidates, and tests before editing.

STATUS PREFLIGHT
Confirm:
- standalone mode is default and currently works without fleet init;
- remote mode binds UI/API for VPS access;
- fleet init/join commands are proposed;
- production queue/evidence/routing primitives are not shipped;
- Redis/Postgres must be reachable only over the overlay in the proof;
- cloud provisioning remains future work.

CURRENT STATE
- Verify current install/start/remote-mode behavior before editing.
- Standalone mode is the default.
- The desired product workflow is fleet init -> join token -> fleet join, but the flags are proposed.

TARGET BEHAVIOR
- Control plane can initialize a WireGuard overlay for owned workers.
- Control plane can create a short-lived worker join token.
- Worker can join with one command after ShakerScan install.
- Worker runs worker-only processes and appears in a node list with heartbeat/capacity.
- Worker can consume one normal scan job from the control-plane queue over the overlay.

NON-GOALS
- Do not advertise this as production-ready.
- Do not build cloud provisioning.
- Do not implement the HTTPS broker.
- Do not expose Redis/Postgres publicly.

DO NOT TOUCH
- HTTPS broker.
- Production queue replacement.
- Cloud provisioning.
- Scanner detection logic.
- Public exposure of Redis/Postgres.

SAFETY INVARIANTS
- Standalone mode remains usable after failed init/join.
- Join tokens are short-lived and scoped to owned workers.
- Redis/Postgres are reachable only over WireGuard/overlay.
- Adding one worker does not bypass target/root-domain rate caps.
- Remote worker failure does not strand a normal scan permanently.

AUTHORIZATION / BLAST RADIUS
- Target authorization assumption: user owns or is authorized to test any target routed to the worker.
- Allowed preset: unchanged by fleet join.
- Credentials/auth states: preserve existing scan options.
- Rate limits: keep existing caps; do not multiply pressure by joining a worker.
- Confirmation is required before live two-VPS smoke scans.

DATA CONTRACTS
Define or verify join token shape, node registration fields, worker desired-state payloads, status
JSON, Redis/DB connectivity assumptions, scan job payloads, and UI/status output fields. For each
changed contract, state producer, consumer, compatibility, old-row/null behavior, and idempotency key.

MIGRATION / BACKFILL / COMPATIBILITY
- Standalone installs remain unchanged unless fleet init/join is invoked.
- Existing local workers continue to run without node-agent.

ROLLOUT / FALLBACK
- Feature flag: fleet mode remains opt-in through fleet init/join.
- Default: standalone.
- Fallback: local worker execution.
- Rollback: leave/remove fleet config without breaking local start.
- Unsafe signals: public DB/Redis bind, stale join token accepted, node joins without heartbeat, or
  local scans fail after join failure.

FAILURE-MODE MATRIX
Cover failed WireGuard setup, duplicate join token use, expired token, worker crash mid-job, duplicate
job delivery, parent cancellation, timeout after partial work, missing credentials, rate budget
exhaustion, missing scanner telemetry, and overlay connectivity loss. State expected behavior and
required tests for each.

OBSERVABILITY / UI / REPORT BEHAVIOR
- Status output prints local and fleet URLs/config state.
- Node list shows heartbeat and worker capacity.
- Any missing production hardening is labeled as a known gap.

ACCEPTANCE CRITERIA
- Control plane and one worker VPS connect over ShakerScan-managed WireGuard.
- Redis/Postgres are reachable only over the overlay.
- A scan submitted on the control plane can run on the worker and write results centrally.
- Failure to join leaves the standalone install usable.

TESTS REQUIRED
- CLI/config tests for init/token/join.
- API tests for node registration and heartbeat.
- Smoke test with one remote worker consuming a queued scan.

TEST COMMANDS
Report exact commands run and any expected commands not run with reasons.

OUTPUT FORMAT
Return status preflight, changed files, behavior summary, safety checks, data contracts changed,
tests run, remaining risks, and follow-up tasks.
```
