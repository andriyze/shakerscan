# Deferred Work Implementation Plan

**Status:** active implementation plan
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

## Wave 2: registry-owned report execution

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

First foundation slice implemented: the report phase executor now accepts sync or async adapters,
validates each adapter against `SCANNER_REGISTRY_ADAPTER_CONTRACTS`, observes cooperative
cancellation, and emits structured skipped/blocked/cancelled/failed/completed receipts with the
declared telemetry and proof contracts. Passive header/config finding emission and the Nuclei
template phase use this executor. Nuclei keeps its existing standard/comprehensive/staged adapters,
but only the registry template phase can invoke them and its receipt is persisted in the report.
Typed adapter outcomes prevent a returned-but-incomplete tool run from being labeled completed;
Nuclei receipts carry bounded completion/template/finding counts and fail when `scan_completed=false`.
Recon and active-family execution still require phase-by-phase migration before Wave 2 is complete.

## Wave 3: telemetry schema expansion

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

## Wave 4: request-accurate standalone budgets

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

Deliverables:

- component-level tests for ASM schedule create/edit, skip reasons, remediation links, and parent
  coverage rollups;
- keep production build/type checking and desktop/mobile browser QA as separate gates.

## Wave 6: live parity and soak

Run only on local or explicitly owned targets:

- dynamic versus static allocation parity on Juice Shop, crAPI, and Honey-style targets;
- cancellation under active SQLi/XSS/Auth/BOLA load;
- rate-limit behavior at multiple worker counts;
- current-fleet detector scorecards, including authenticated crAPI.

Artifacts must record build fingerprint, fleet freshness, allocation mode, attempt counts, proof
counts, false-positive risk, and failures/timeouts. Soak is validation, not a substitute for tests.

## Wave 7: multi-node readiness, later program

Prerequisites:

- Waves 1-6 stable;
- node identity and placement metadata;
- reliable queue leases and heartbeat ownership;
- object-storage-backed evidence available to every node;
- brokered scope/approval enforcement and secret delivery;
- two-node failure/recovery POC before production claims.

State-changing MCP, arbitrary agent execution, untrusted raw workers, and post-exploitation tooling
remain excluded unless separately designed and approved.
