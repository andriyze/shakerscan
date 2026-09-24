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
- [ ] Add deliberate operator budget/resource amendments, including complete port-range work,
  additional selected identities, and request collections. Preserve earlier action snapshots/history.
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
