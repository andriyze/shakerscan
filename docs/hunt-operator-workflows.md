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
- [ ] Let web/interface knowledge apply to appropriate device and network services without granting
  their capabilities. Integrate device/protocol methodology discovery rather than adding an engine.
- [x] Prioritize fresh caller signals, normalize retained service observations, and prevent older
  context from crowding out an explicitly requested new direction.
- [ ] Adapt the methodology bodies to real ShakerScan contracts. Preserve hypotheses, pivots,
  evidence interpretation, and false-positive checks; remove nonexistent upstream adapter/schema
  instructions and duplicated approval/budget machinery.
- [ ] Distinguish submission-only requests from end-to-end Hunts. Follow queued child results during
  a full investigation, with bounded checks and checkpoints rather than new user prompts.
- [ ] Build authorized state-changing collection and multi-step browser execution with real
  credential handling, accounting, cancellation, and evidence. Visibility alone is not implementation.
- [ ] Add deliberate operator budget/resource amendments, including complete port-range work,
  additional selected identities, and request collections. Preserve earlier action snapshots/history.
- [ ] Persist normalized Hunt service observations into shared durable knowledge with idempotent
  ingestion, provenance, asset-generation checks, and deletion/retention integration.
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
