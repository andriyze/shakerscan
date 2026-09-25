# Hunt verified-discovery work

**Status:** first implementation slice on PR #220, following merged PR #217 (`d5c9955`).
Component tests and live-target efficacy are different evidence; this is not a recall certification.

## Objective

Increase unique deterministically verified bugs beyond the deterministic Scan baseline while
reducing operator interventions. Keep existing authorization, budget and proof contracts. No
parallel scanner, target-specific production logic or new repeated consent requirement.

## Implemented in this slice

- The existing Hunt deterministic-finding bridge now accepts canonical, verified `authz.verify`
  differentials. The HTTP capability worker calls it inside the existing settlement transaction
  and returns the persisted `verified_finding_ids`. Previously the bridge handled only XSS and
  the HTTP worker did not call it at all: successful authorization proof could remain only a receipt.
- Content-free proof controls are mapped through the existing object-authorization validator;
  findings, verification history, deduplication, inventory counts and budget settlement reuse the
  existing stores. The actual selected HTTP service origin is used, including nonstandard ports.
- `GET /findings?hunt_id=...` also includes actual deterministic verifications attributed to the
  run by retained verification records. This covers family-proof findings with null direct Hunt
  attribution and findings subsequently reverified by another run, without write-on-read backfill.
  The opt-in candidate union is now filtered by the same Hunt rather than including unrelated leads.
- Shared service intelligence accepts real `request_replay` observations from safe collections.
  It projects the reached final origin/address/status, never a guessed destination or raw secrets.
  Positive partial evidence remains presence evidence, not complete coverage or vulnerability proof.
- The authorization methodology explains how to drive collection-backed proof with existing
  selected identities instead of stopping at a candidate or rebuilding working sessions.

## What this does not prove or change

Own-object comparisons without a listing still do not establish entitlement. The three initially
reported Juice Shop candidates are not automatically verified by this change. No session/cookie
rewrite, weakened proof, synthetic absence assertion, new permission requirement or automatic
budget increase was added. Two observations of shared/public data must not become a vulnerability.

Tests exercise a real loopback frozen-socket authorization verifier with vulnerable, patched,
public/shared, expired-session and same-principal controls; database doubles cover the component
boundary. Separate isolated-schema PostgreSQL tests execute real materialization, deduplication,
rollback and run-attribution SQL in Hunt record CI. These are neither a deployed-worker acceptance
nor blind Juice Shop discovery. Report exact-head CI results separately from local runs and skips.

## Efficacy evaluation and next work

The operator's two Juice Shop runs are directional evidence, not a recall denominator.
`scripts/benchmark_targets.py juice_shop --auth` submits the deterministic **Scan** baseline;
it is not a Hunt benchmark. Reuse its answer key only on the evaluator side, after an external
planner has driven the Hunt. Do not pass expected routes or bug classes to the planner and call
scripted proof a blind discovery result.

Next acceptance is a current-worker, two-principal Juice Shop run using the existing sessions.
Separate candidate discovery, attempted verification, canonical proof, persisted finding and
per-Hunt retrieval. Inspect the exact missing control when `authz.verify` stays inconclusive.
Compare parent and branch with identical model, target state, initial knowledge and budgets;
repeat fresh runs and include a patched control. Measure unique verified findings beyond Scan,
verified expected-class recall, operator interventions, completion rate, request/time cost and
coverage gaps. Hold stronger and weaker planner results separately.

Still deferred: independent paired Hunt scoring/benchmark automation, durable child-result
continuation, state-changing multi-step workflows and broader protocol execution. None is implied
by a green component test.
