# Deferred Work Implementation Plan

> **ARCHIVED (2026-07-11).** This is the completed/partial wave ledger at its final checkpoint.
> Remaining registry, detector, metering, soak, and multi-node gates are maintained only in
> [`../proposed-next-steps.md`](../proposed-next-steps.md).

**Status:** cancellation, telemetry, request-meter infrastructure, and UI contracts are implemented;
registry authority is partial; detector acceptance and Wave 6 soak remain open; Wave 7 is gated
**Created:** 2026-07-10
**Scope:** remaining local/owned-fleet architecture from the reconciled roadmap. Multi-node and
untrusted-worker transport remain a later program and do not block the local proof-first product.

## Ordering rules

1. Preserve detector behavior while changing orchestration.
2. Add truthful stop/attempt telemetry before using it for budgets or coverage.
3. Make the registry authoritative one phase at a time, with a rollback-compatible adapter.
4. Do not mark soak or benchmark work complete without a fingerprint-current artifact.
5. Do not start multi-node execution until local cancellation, leases, budgets, evidence, and fleet
   freshness are stable under load.

## Immediate corrected sequence (2026-07-11)

The current-fleet authenticated crAPI run proved that the benchmark harness can mint two different
JWT identities and schedule both auth lanes. It failed `0/4`, and the expected routes were absent
from the stored result. Treat discovery as a confirmed blocker, but do not call it the only root
cause until seeded detector controls pass.

1. Make benchmark auth and diagnostics evidentiary: redacted identity-validation receipts, bounded
   discovery manifests, and valid completion metrics.
2. Run seeded BOLA/SQLi controls to isolate detector correctness from discovery.
3. Improve authenticated API discovery using universal spec/link/JS/browser techniques; rerun the
   unseeded benchmark.
4. Close registered-family execution bypasses and enforce declared proof/severity contracts.
5. Finish engine-wide cancellation and per-adapter metering-quality contracts, then execute Wave 6.
6. Keep planner authority and multi-node work behind those acceptance gates.

Progress: `53cd5fc` starts item 1. Future benchmark submissions now carry a redacted
`benchmark_principal_validation_v1` receipt and explicitly leave target-accepted authentication
unknown. SQLi completion telemetry no longer double-counts successful body parameters; diagnostic
ratios are bounded and inconsistent input fails a benchmark gate. Bounded discovery manifests and
accepted-auth observation remain open.

## Wave 1: cooperative cancellation for current active families - DONE

**Why first:** registry migration increases the number of modules controlled by shared orchestration.
Those modules need one reliable cooperative stop contract before execution moves.

Deliverables:

- one shared scanner cancellation helper backed by `SHAKERSCAN_CANCEL_FILE`;
- cancellation checkpoints in SQLi, XSS, focused Auth, authz replay/BOLA, and Phase 4 waits;
- partial attempt rows remain partial and carry `cancelled`, never completed/clean;
- worker process-group termination remains the hard backstop;
- focused tests proving no request is issued after a pre-existing cancellation signal.

Done when:

- current active-family loops stop before the next network request;
- reports distinguish cancellation from time-budget exhaustion;
- the focused and complete Python suites pass.

Implemented in the first slice: one shared cancellation helper now drives SQLi/XSS, focused Auth,
authz replay/BOLA, and cancellation-aware Phase 4 waits. Auth/BOLA returns partial attempt telemetry
with `budget_exhausted_reason=cancelled`; Phase 4 records `scanner_cancellation` and cancels the
current task during the worker grace period. Worker process-group termination remains the backstop.
Focused tests and the complete Python suite pass. Additional legacy loops are tracked under Wave 2/3
adapter migration rather than being implied complete.

## Wave 2: registry-owned report execution - PARTIAL

Deliverables:

- a typed sync/async registry phase executor with adapter identity validation;
- phase receipts for enabled, skipped, blocked, failed, cancelled, and completed states;
- migrate recon, template, passive posture, and active adapters behind registry phase iteration in
  small behavior-preserving commits;
- fail closed when an enabled family has no matching scanner adapter;
- retain legacy adapter implementations until parity tests and benchmark artifacts pass.

Done when:

- `build_report()` no longer decides whether a registered family runs outside the registry plan;
- disabling a family in the registry prevents its adapter from executing even if legacy flags say yes;
- every enabled family has a receipt and parser/proof contract.

Implemented foundation: the report phase executor accepts sync or async adapters,
validates each adapter against `SCANNER_REGISTRY_ADAPTER_CONTRACTS`, observes cooperative
cancellation, and emits structured skipped/blocked/cancelled/failed/completed receipts with the
declared telemetry and proof contracts. Generic recon, passive header/config finding emission, and
the Nuclei template phase use this executor. Recon now keeps HTTP probing, Katana/smart discovery,
bounded JS route seeding, and browser crawl behind the `legacy_discovery` registry adapter. Nuclei
keeps its existing standard/comprehensive/staged adapters,
but only the registry template phase can invoke them and its receipt is persisted in the report.
Typed adapter outcomes prevent a returned-but-incomplete tool run from being labeled completed;
Nuclei receipts carry bounded completion/template/finding counts and fail when `scan_completed=false`.
The active executor also supports explicit dependency-point family subsets and typed one-call batch
adapters. JWT and Phase 4 mass-assignment now execute only through their registry adapters and emit
versioned completion/finding/count telemetry. Focused Auth and BOLA/BFLA now execute through the
`asm_endpoint_batch` adapter with blocked/cancelled/budget/access-violation receipts. SQLi and XSS
enter through the shared `legacy_active_loop` registry batch adapter for the main active loop.

Remaining strict-authority gaps: phase-4 `bola_testing -> check_bola`, advanced NoSQL execution, and
endpoint-scoped registered auth/exposure checks can still issue requests and emit registered-family
coverage outside the registry phase decision. Declared `proof_contract` and `severity_rules` are
published but not enforced against emitted findings. Wave 2 is complete only when a registry `NO`
prevents every registered-family request/finding even while each legacy condition says `YES`.

## Wave 3: telemetry schema expansion

**Status: DONE in code.** `mass_assignment_attempt_v1`, `jwt_probe_attempt_v1`, and
`active_endpoint_attempt_v1` are normalized by the shared attempt contract. Scanner reports stamp
the endpoint schema; worker merge rejects missing/unknown versions; ASM family coverage exposes
attempted, completed, proved, blocked, cancelled, partial, and failed counts. Unversioned completed
rows degrade to partial.

Deliverables:

- versioned attempt schemas for mass-assignment and JWT checks;
- normalized endpoint/method/parameter counts, status, skip reason, error summary, proof observation,
  and cancellation/budget reason;
- merge and ASM rollups consume only declared schema versions;
- missing or partial telemetry degrades coverage instead of implying completion.

Done when:

- every current runnable focused family emits attempt facts;
- parent/ASM family coverage distinguishes attempted, completed, proved, blocked, cancelled, and
  partial states.

## Wave 4: standalone request metering and bounded enforcement

**Status: infrastructure DONE; contract formalization and soak OPEN.** Resolved budgets carry
`request_max`. The request meter counts shared curl, httpx, aiohttp, urllib, and Playwright target
traffic, disables hidden redirects when enforcing, and rejects known external network tools whose
internal request counts cannot be observed. Workers reserve enforcing-mode tokens in the shared
root-domain bucket. Reports carry `request_meter_v1` telemetry and an execution receipt.
Compatibility mode remains the default and records unmetered tool invocations.

Do not call this globally request-accurate. Add per-adapter `metering_quality` (`exact`,
`adapter_reported`, `reserved_upper_bound`, `estimated`, `unknown`) and `budget_enforcement` (`hard`,
`soft`, `unavailable`). A hard cap is claimable only for exact or enforceable upper-bound adapters;
opaque subprocess adapters remain disabled or soft/unavailable.

Deliverables:

- a shared request meter used by internal HTTP/browser/tool adapters;
- planned, reserved, attempted, completed, retried, and rejected request counts;
- per-domain token reservation for internally discovered standalone work;
- explicit budget-exhausted receipts and report degradation;
- compatibility mode until parity and rate-limit soak pass.

Done when:

- standalone scans cannot exceed their declared request budget through internally discovered work;
- retries and redirects are counted consistently;
- rate caps remain correct across concurrent local workers.

## Wave 5: UI component and contract harness

**Status: DONE.** Shared UI contracts drive ASM schedule create/edit payloads, bounded skip-reason
labels, internal-only remediation links, parent shard coverage, and family attempt/completion/proof
counts. The Node contract suite and production Next.js build pass. Rebuilt-stack browser QA also
passes for desktop and 390 px mobile views of the scan budget controls, ASM family coverage, and
schedule create/edit flows; wide endpoint tables remain contained in their horizontal scroll areas.

Deliverables:

- component-level tests for ASM schedule create/edit, skip reasons, remediation links, and parent
  coverage rollups;
- keep production build/type checking and desktop/mobile browser QA as separate gates.

## Wave 6: live parity and soak

**Status: NOT YET ACCEPTED.** The complete Python suite passes (`1756 passed, 6 skipped`), the UI
contract suite passes (`20/20`), the production UI build passes, and a full rebuild/restart reports
16/16 current workers on fingerprint `bc6c357126e7fe53`. The idle-worker queue check passed one full
blocking interval without the prior Redis timeout loop. Dynamic/static parity, active cancellation
load, multi-worker rate soak, and fresh detector scorecards still require live artifacts. The local
E2E harness could not run in this session because localhost execution was denied by the execution
environment; no pass is inferred.

Run only on local or explicitly owned targets:

- dynamic versus static allocation parity on Juice Shop, crAPI, and Honey-style targets;
- cancellation under active SQLi/XSS/Auth/BOLA load;
- rate-limit behavior at multiple worker counts;
- current-fleet detector scorecards, including authenticated crAPI.

Artifacts must record build fingerprint, fleet freshness, allocation mode, attempt counts, proof
counts, false-positive risk, and failures/timeouts. Soak is validation, not a substitute for tests.

## Wave 7: multi-node readiness, later program

**Status: NOT STARTED by design.** Ordering rule 5 prohibits this wave until Wave 6 has accepted
artifacts. Existing local leases, external evidence support, scope/approval gates, secret delivery,
and fleet fingerprints are prerequisites, not a two-node production claim.

Prerequisites:

- Waves 1-6 stable;
- node identity and placement metadata;
- reliable queue leases and heartbeat ownership;
- object-storage-backed evidence available to every node;
- brokered scope/approval enforcement and secret delivery;
- two-node failure/recovery POC before production claims.

State-changing MCP, arbitrary agent execution, untrusted raw workers, and post-exploitation tooling
remain excluded unless separately designed and approved.
