# Operator-complete Hunt workflows

**Status:** active implementation plan, following merged PRs #214–#216. Checked items are implemented in this PR; unchecked items remain planned, not shipped capabilities.

## Goal

Carry an explicitly authorized investigation through to useful evidence without repeated consent
prompts, avoidable restarts, or all-or-nothing methodology failures. Preserve cancellation, selected
identities, target binding, measured budgets, and the distinction between evidence and proof.
A missing executor is a capability gap, not an authorization problem.

## Workstreams and acceptance

- [x] Correct Hunt consent and public start examples. Reuse standing authorization; otherwise obtain
  explicit target-specific consent once. Test public inputs through standing-authorization resolution.
- [x] Retire leftover `CLAUDE.md` files during upgrades and workspace preparation, including
  pre-manifest installs. Preserve local edits under non-loaded backup names and never follow links.
- [x] Make MI-6 a real release gate. Verify that the release workflow executes the lifecycle and
  rejects missing, skipped, failed, or waived trust-anchor assertions.
- [x] Separate expected NSE optional-method omissions from execution errors. Preserve `coverage_gaps`,
  actual request accounting, normal successful read checks, and genuine failures.
- [x] Document and test NSE's anonymous same-frozen-asset redirect exception. It does not apply to
  credentialed HTTP, expand the saved Hunt binding, or authorize a foreign asset.
- [x] Make useful partial methodologies selectable with explicit missing-executor and permission
  gaps. A missing technique must not discard the entire methodology or be called a clean test.
- [x] Let web/interface knowledge apply to appropriate device and network services without granting
  their capabilities. Integrate device/protocol methodology discovery rather than adding an engine.
- [x] Prioritize fresh caller signals, normalize retained service observations, and prevent older
  context from crowding out an explicitly requested new direction.
- [x] Adapt the methodology bodies to real ShakerScan contracts. Preserve hypotheses, pivots,
  evidence interpretation, and false-positive checks; remove nonexistent upstream adapter/schema
  instructions and duplicated approval/budget machinery.
- [ ] Distinguish submission-only requests from end-to-end Hunts. Follow queued child results during
  a full investigation, with bounded checks and checkpoints rather than new user prompts.
- [ ] Build authorized state-changing collection and multi-step browser execution with real
  credential handling, accounting, cancellation, and evidence. Visibility alone is not implementation.
- [x] Add operator-requested total-budget extensions above startup presets and resume unfinished
  exhausted Hunts. Preserve live holds, usage, identity, permissions, initial snapshots and history.
- [ ] Extend resource amendments to additional selected identities and request collections. Budget
  amendments do not attach credentials/collections or enable additional capabilities.
- [x] Reuse normalized Hunt service observations in shared durable knowledge through canonical
  settlement receipts, with idempotent action identity, provenance, locator checks and existing
  owner/receipt deletion and retention. No duplicate store or write-on-read backfill.
- [ ] Improve the investigation frontier: unresolved leads, untested work, explicit coverage gaps,
  freshness, and requested retests. Prior proof is not a ban on retesting or investigating a chain.
- [ ] Make HTTPS-to-HTTP credential consequences visible and test actual synthetic transmission,
  revocation, and foreign-host non-contact. Preserve intentional authorized same-asset testing.
- [x] Repair the historical 0.8.0 readiness link without presenting old validation as current.
- [ ] Run efficacy evaluations in addition to plumbing tests: useful selection, continuation after
  partial failure, reproducible findings, patched controls, and operator-intervention count.

## Validation rules

Use the repository generators for manifests and inventories; never hand-author digests. Run affected
behavioral tests before publishing a batch and report native/infrastructure tests separately when
not run locally. Keep implementation status honest: a query signpost is not durable ingestion, a
methodology is not an executor, and green unit tests are not a vulnerability-recall measurement.

## First implementation batch

Web methodology read/bind now also works for device/network interfaces; suggestions require an
observed web signal or an explicit web objective. Native device/protocol methodology integration
remains open. Submission-only versus full-investigation and requested-retest guidance is corrected;
a durable amendment/execution driver and the independent efficacy runs are not implemented yet.

Local validation: 271 affected tests passed across both repository import layouts, without skips.
Generated contracts, inventory, install manifest, documentation policy, module size, installed import
closure and canonical target transport passed. Native Nmap and full locked-dependency acceptance
run separately in CI; local success is not a production or physical-device certification.


## Shared evidence continuation

Implemented: `service_intelligence` now projects canonical persisted Hunt receipts alongside Scan
and device evidence. This reuses the existing atomic settlement store rather than adding a second
ledger or write-on-read backfill. Ownership/hash/budget validation, positive partial output, frozen
address checks, historical locator handling, no raw content exposure, and source-Hunt links are
covered by focused tests. Real PostgreSQL persistence/join/deletion checks run in the existing Hunt
record-integrity workflow. Reads remain bounded and publish truncation/invalid-source warnings.

This closes the supported-receipt reuse loop, not unlimited history or legacy reconstruction.
Output without a canonical settled receipt remains an explicit gap; Scan planning is unchanged.
Budget/resource amendments, browser/replay execution and methodology-body adaptation remain open.

## Methodology integration continuation

All 28 remaining upstream-style execution sections now reference the canonical Hunt API and
current shared core guidance rather than nonexistent package schemas or a second approval/budget
engine. Testing hypotheses, technique modules, focused test matrices, false-positive controls,
remediation and source references are retained. Previously adapted crawl/SQL guidance is aligned
with requested retests and partial methodology binding.

Native service/device methodology is discoverable through the same library and installed agent
kit. MQTT, SSH, SMB, SNMP, UPnP and DLNA signals guide retained-evidence/fingerprint checks and
web-interface pivots. Arbitrary native protocol messages remain explicit executor gaps; this is
methodology integration, not implementation of a generic packet or protocol executor.

The integration check and regression tests cover dead links, retired execution contracts,
declaration/body agreement, all delivered body hashes, protocol selection/read/bind/pivot,
priority-only web signals, installation and unchanged run authority. Independent vulnerability
recall measurements, general workflow execution and operator amendments remain open.


## Operator budget extensions

The Hunt UI now offers **Extend this Hunt's budget** for unfinished active, awaiting-planner and
budget-exhausted runs. An explicit operator edit sets a new **total**, not a delta. Startup profiles
remain convenient defaults; this endpoint can increase their limits, including total TCP attempts
for full-port work. Actual calls still use their existing per-action limits and batching.

Read the current run's `budget_revision`, `budget`, `budget_used`, and
`budget_amendable_dimensions`. Submit `POST /hunts/{id}/budget-amendments`, for example:

```json
{
  "schema_version": "hunt-budget-amendment/v1",
  "limits": {"max_tcp_ports": 65535},
  "expected_revision": 0,
  "idempotency_key": "operator-port-range-extension-1",
  "operator_confirmed": true,
  "resume": true,
  "reason": "Operator requested all TCP ports on the same authorized asset"
}
```

Use the revision actually returned by the server, and a fresh retry key for each distinct operator
edit. Reuse the same body/key after a lost response; it cannot apply the increase twice. A concurrent
edit returns a revision conflict rather than overwriting another operator's choice. The API accepts
multiple dimensions in one transaction; the UI edits one dimension at a time.

`resume: true` moves an unfinished budget-exhausted run to `awaiting_planner` only when its reported
exhausted dimension has headroom. No action is started automatically. Without resume, exhaustion
remains until deliberately addressed. After extending without resuming, use the existing
`POST /hunts/{id}/resume` or **Resume with current budget**; it checks current headroom without
another increase or resetting usage. Completed, failed, cancelled or finalized exhausted runs
are not reopened. Exhausted unfinished runs remain cancellable, including their owned child jobs.

The existing Hunt row lock serializes amendments with admission/settlement/cancellation. Usage and
outstanding holds never reset; earlier action/reservation objects and the admission snapshot stay
unchanged. The denormalized current policy budget mirrors the new limits, but its permissions and
capability allowlist do not change. Increased device request/fragility ceilings preserve pacing,
health/traffic freezes and all usage; device daily and child-scan limits remain independent. A zero
ceiling can be increased only where the saved policy already permits it; this does not add a
capability originally excluded from the run.

`GET /hunts/{id}/budget-amendments?after_revision=0&limit=50` pages the durable history, which also
appears in `/record` with explicit truncation. Events retain before/after limits, the usage snapshot,
redacted reason and status transition. Retry-key hashes are internal. Deleting the owning Hunt or
target cascades the event history; this audit table is not a second traffic ledger.

This completes budget-only amendments, not adding principals/collections, clearing device health
pauses, arbitrary protocol execution, or an autonomous child-result driver. Each remains separate
unfinished work above. Budget extensions must reflect a real operator request, never an agent's
silent response to an exhausted allowance.
