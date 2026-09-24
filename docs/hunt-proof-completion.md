# Hunt authorization proof completion

**Status:** Implemented follow-up; full-stack acceptance pending.

This follow-up to #217 improves the existing read-only authorization path. It does not add a
second scanner, change entitlement predicates, add permissions, or change execution budgets.

## Implemented

- Resource-aware replay routing preserves parent identifiers, prefers a matching consumer before
  truncation, and prioritizes the canonical item route over collection action suffixes.
- Hunt uses Scan's existing canonical authorization-proof projection. Only a valid settled receipt
  for this Hunt, target, and target kind can feed the existing finding materializer.
- The HTTP worker materializes proof, verification history, action result and measured budget in
  its existing settlement transaction. Both initial responses and idempotent replays retain
  `verified_finding_ids`; history reads do not create findings or rerun verification.
- The methodology directs a supported lead toward its correct producer/consumer verification
  path. Two concrete object reads without entitlement evidence remain observations, not proof.

## Acceptance and interpretation

The focused tests use real loopback HTTP with the production target-bound verifier, its existing
validator, canonical receipts, the shared Scan finding projection, and Hunt persistence. Negative
controls include protected access, intentionally shared sensitive objects, nonsensitive objects,
identical/expired principals, and two-object access without a listing. Configured PostgreSQL tests
exercise web/device ownership, atomic rollback, and verification history in a disposable schema.

Built-stack H-19 establishes two managed sessions and executes `authz.verify` through the real
API and worker, checks the persisted finding and per-Hunt listing, and repeats the same action key
without another verification or budget charge. H-20 executes protected and shared controls. Both
are required actual passes in PR, manual and release acceptance, not allowed skips or declared debt.

These are assisted known-fixture proof-completion tests, not autonomous discovery, physical-device
certification, or Juice Shop recall. Passing them must not be reported as a measured recall gain.
The release must still pass normal final-head CI, including the complete Python and built-stack
suites. A local run without PostgreSQL reports its missing-DSN skips separately.

## Remaining efficacy work

Run the observed Juice Shop leads with two principals through this path and retain their exact
reasons and finding IDs. Evaluate deterministic Scan, assisted proof completion, and planner-driven
Hunt separately against a held-out answer key with equal models, credentials, starting knowledge,
and budgets. Count additional unique verified findings, conversion rate, operator interventions,
and request/time cost, rather than candidates or HTTP successes.

General child-result continuation, state-changing workflows, candidate-to-finding attribution
through the separate family-proof workflow, historical service-replay projection, and richer
investigation-frontier tracking are not implemented by this focused change. It does not rewrite
sessions, grant new authority, or silently extend exhausted runs.
