# DAST Execution and Continuous ASM Architecture

**Status (reconciled 2026-08-29):** current implementation reference. This document describes the
shipped local and broker execution model and its safety boundaries. Future fleet work belongs in
[`multi-node-architecture.md`](multi-node-architecture.md); release gates belong in
[`release-readiness.md`](release-readiness.md).

## Purpose

ShakerScan has two related ways to test web applications:

- **One-shot DAST** runs a bounded scan against a target and produces one logical report.
- **Continuous ASM** retains endpoint inventory and coverage state, then schedules small discovery
  or testing waves to improve that state over time.

They share workers, scanner modules, proof contracts, findings, budgets, cancellation, and build
fingerprints. They do not share the same product lifecycle: DAST answers “what did this assessment
find?”, while ASM answers “what remains untested and what bounded work should run next?”

## Local execution model

The API persists a scan and queues work in Redis. Workers claim jobs, execute scanner modules, write
heartbeats and result state to PostgreSQL, and persist findings through the common evidence and
proof gates.

### One deterministic Scan

Every new assessment uses the same deterministic Scan pipeline. `fast`, `balanced`, `thorough`, and opt-in `deep`
are resource ceilings; active testing, network discovery, and subdomain discovery are explicit
permissions. Historical mode names are translated only at the compatibility boundary and do not
select a second engine or module registry. Phases are ordered where later work depends on earlier
discovery, while individual capabilities may apply their own bounded concurrency.

### Parent, plan, shard, merge

Eligible active scans can use the shipped local scatter/gather path:

1. The **parent** represents the user-visible logical scan.
2. A placed **discovery** job runs on the selected local or broker node and persists its result.
3. A local-only **plan** resolves budgets and commits the complete child set before queue publication.
4. A capability-preserving **backbone** and self-contained endpoint **shards** run concurrently.
5. The **merge** job combines evidence, receipts, findings, coverage, and failure state into the
   parent result.

Child implementation rows are hidden from normal scan lists. Scan detail exposes logical progress
and shard rollups. A parent cannot report stronger completion or coverage than its children support:
failed, cancelled, partial, stale, missing, or malformed shard telemetry degrades the rollup.

Parallel coverage adds breadth across workers without changing Scan identity: the backbone retains
browser, DOM-XSS, posture, and global checks, while endpoint shards avoid repeating them. Use one
deterministic Scan with the benchmark's fixed policy and budget for quality comparisons. Treat
parallel coverage as a separately bounded compound workload when validating scatter/gather
correctness, endpoint breadth, or multi-node execution.

## Continuous ASM loop

Continuous ASM maintains a target-scoped endpoint inventory and selects the next bounded action:

1. **Observe:** normalize endpoints from scans, crawling, JavaScript, API artifacts, discovery, and
   application-graph facts.
2. **Measure:** calculate coverage from completed attempts and family proof, not endpoint presence
   alone.
3. **Explain:** return gaps, blocked prerequisites, scheduler state, and recommended campaigns.
4. **Act:** queue discovery or claim an untested/stale endpoint batch.
5. **Record:** persist attempts, receipts, findings, coverage effects, and the next eligible action.

`POST /targets/{id}/asm/improve` is the normal entry point. It chooses recon, testing, or `wait`
based on inventory and active work. Manual recon and test endpoints remain available for explicit
operator control.

ASM waves are a first-class schedule kind: `schedules.schedule_kind = 'asm_improve'`. Legacy rows
encoded as `scan_options.kind = 'asm_improve'` remain readable for compatibility, but new clients
should use the first-class kind.

## Inventory, claims, and coverage

Endpoint inventory is durable and target-scoped. Normalization prevents equivalent URLs from
becoming competing work, while method, source, API-likeness, auth observations, graph relationships,
and freshness remain available for prioritization.

Workers claim endpoint work with durable ownership. Attempts distinguish at least:

- completed testing;
- skipped or blocked work;
- cancellation;
- timeout or failure;
- partial execution or exhausted budget;
- missing/unobserved telemetry.

Only completed, applicable attempts contribute positive coverage. Missing telemetry never means
clean. Family rollups distinguish completed proof from attempts, and auth/BOLA coverage cannot be
claimed from configured identities alone.

Supported focused ASM families are `all`, `sqli`, `xss`, credential-gated `auth`, and gated `bola`.
Auth requires an accepted primary context. BOLA additionally requires a second distinct accepted
principal and explicit deep/exploit intent.

## Budgets and metering

Every path resolves bounded time, endpoint, parameter, payload, redirect, response-size, and request
controls where the adapter supports them. Receipts report enforcement and metering quality rather
than implying exactness where only an estimate or adapter-reported value exists.

Parallel-coverage discovery is a separate placed job with a three-minute passive budget. It must finish
and persist a non-empty manifest before fan-out; a failed discovery fails the parent visibly instead
of creating empty endpoint shards.

Scope sharding partitions the parent's request ceiling across disjoint children. Parallel coverage is an
explicit compound workload: one complete backbone plus separately bounded endpoint slices. Endpoint
children never inherit the full parent request ceiling and do not repeat crawl/browser/Nuclei work;
the parent records the planned aggregate and backbone request budgets. The merge uses aggregate
receipts and fails conservatively when consumption or completion cannot be trusted.
ASM uses smaller target-scoped batches and applies scheduler limits such as active-work exclusion,
minimum interval, daily caps, allowed windows, and stale-worker rejection.

## Proof and findings

All DAST and ASM findings use the same proof authority:

- deterministic evidence and replay control verified status;
- AI may explain, correlate, plan, or downgrade within policy, but cannot manufacture proof;
- configured or attempted auth does not prove accepted auth;
- a finding label does not prove distinct-principal BOLA;
- incomplete attack chains remain partial rather than rendering as fully observed exploitation.

Registry `severity_rules` may remain advisory with the current wired severity caps. The executable
proof contracts and caps for XSS, SQLi, BOLA, auth, mass assignment, and JWT remain authoritative.

Findings from ordinary assessments use the DAST source. Scanner findings launched by Continuous ASM
use ASM context. Scanner findings driven by Hunt are exposed through the Hunt source so a
single finding does not present competing user-facing origins.

## Cancellation, failure, and stale builds

Cancellation is cooperative across parent, child, tool, and active-check boundaries. A parent waits
for terminal child state or reports an honest degraded result; it does not convert unfinished work
into success.

Workers advertise a build fingerprint. Release and benchmark submissions can require a uniform
current fleet. Scan records stamp the expected fingerprint and stale-worker count at submission so
results cannot later be mistaken for current-build evidence.

Broker fleets add authenticated leases, acknowledgement, fencing, artifact transfer, placement, and
partition behavior around the same self-contained shard contract. Discovery follows placement;
fan-out and merge remain local-only control-plane work. Those requirements are defined in
[`multi-node-architecture.md`](multi-node-architecture.md).

## User-facing surfaces

- **New Scan** selects a resource ceiling, explicit permissions, optional parallel coverage, and
  lower custom ceilings.
- **Scans / Scan Detail** show one logical assessment, progress, partial/failure state, receipts,
  coverage, proof, and report output.
- **Continuous ASM** shows target coverage, family rollups, gaps, recommendations, scheduler state,
  endpoint inventory, and the target campaign timeline.
- **Schedules** manages recurring normal scans and first-class `asm_improve` waves.
- **Dashboard** summarizes queue, worker, stale-build, ASM, and release-relevant operational state.

The normal ASM action is **Improve coverage**. Hunt is a separate AI-driven investigation and
must not be presented as another ASM batch or compatibility `/research` campaign.

## Primary API surface

```text
GET  /scan/contracts
POST /scans
POST /scans/batch
GET  /scans/{id}
POST /scans/{id}/cancel

GET  /targets/{id}/asm/endpoints
GET  /targets/{id}/asm/coverage
GET  /targets/{id}/asm/gaps
GET  /targets/{id}/asm/activity
POST /targets/{id}/asm/improve
POST /targets/{id}/asm/recon
POST /targets/{id}/asm/test

GET  /workers
GET  /queue/stats
```

The exhaustive route, schema, CLI, registry, table, and UI inventory is generated in
[`functionality-reference.md`](functionality-reference.md).

## Acceptance boundaries

A release claim for this architecture requires:

- parent/shard/ASM rollups that fail conservatively under missing or malformed telemetry;
- bounded active work and effective cancellation;
- proof-gated critical/high findings;
- accepted-auth and distinct-principal evidence for authenticated claims;
- a current, uniform worker fleet for benchmark evidence;
- one deterministic fixed-policy scorecard for DAST quality and separate scatter/gather tests for
  parallel safety;
- migration and rollback validation for durable inventory, attempts, schedules, and results.

Future improvements belong in [`proposed-next-steps.md`](proposed-next-steps.md), not in this current
architecture reference.
