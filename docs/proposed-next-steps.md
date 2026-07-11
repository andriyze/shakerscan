# Proposed Next Steps - Current Status and Hardening Roadmap

**Status (2026-07-11):** the bounded local/owned-target product is implemented, but it is not
release-complete. Detector acceptance, strict registry authority, engine-wide cancellation,
metering-quality contracts, and Wave 6 live parity/soak remain open. Multi-node and planner execution
authority remain gated.

This is the single live DAST/ASM status and dependency document. Historical implementation detail is
preserved in the [archive](archive/README.md), including the completed deferred-wave plan and the
evidence-grounded 2026-07-11 architecture review.

## Current acceptance snapshot

| Area | Current status | Evidence boundary |
|---|---|---|
| Unit and contract tests | Passing at the 2026-07-11 documentation checkpoint | Python `1762 passed, 6 skipped`; UI contracts `20/20` |
| UI production build and browser QA | Passed | Next.js build plus desktop and 390 px scan/ASM/schedule QA |
| Fleet freshness | Passed at last rebuild | 16/16 workers on `957b688918e9ea58`, zero stale at verification time |
| Full current-build E2E | Open | Older Model Intake/AI Gate/DAST result counts have not been rerun on the latest rebuilt fleet |
| Juice Shop benchmark | Non-current pass | `6/9` on anonymous fleet `ddc6173b`; not a current-fleet claim |
| Authenticated crAPI benchmark | Corrected rescore fails | scan `94ac5c7f` was previously marked passing from an identity-only BOLA heuristic. The 2026-07-11 corrected rescore is `1/4` but fails `require_verified_bola`: no persisted distinct-principal receipt and no independent authorization control. |
| Auth bootstrap | Partially proven | Harness minted different JWT identity claims and scheduled two auth lanes; server acceptance is not yet receipt-backed |
| Registry authority | Partial | Main adapters are registry-dispatched, but phase-4 BOLA, NoSQL, and endpoint-scoped registered coverage still bypass the strict decision boundary |
| Request budgets | Compatibility by default | Meter exists; known opaque tools are rejected in enforce mode; per-adapter quality and soak remain open |
| Multi-node | Design only | No fencing, stale-owner-write prevention, partition/skew acceptance, or brokered short-lived secrets |

Current implementation progress: commit `53cd5fc` adds redacted principal-validation receipts for
future benchmark submissions and fixes SQLi's double completion count. Completion ratios are bounded,
and inconsistent telemetry now fails an explicit benchmark gate. The existing `85d3bafb` artifact
predates that receipt and remains historical evidence with the limitations recorded in the ledger.

## 1. Detector acceptance

The first authenticated crAPI scorecard on the then-current fleet is an honest failure. The four required routes
were absent from the stored scan result, so authenticated API discovery is a confirmed blocker. That
does not prove the BOLA or SQLi detector would succeed if those routes were supplied.

Required next artifacts:

1. A seeded, benchmark-controlled detector-isolation run that supplies replayable endpoint contracts
   outside detector inputs and records whether BOLA/SQLi proof contracts succeed.
2. An unseeded run after universal authenticated OpenAPI, link, JS, and browser discovery improves.
3. A current-fleet authenticated Juice Shop run preserving an anonymous baseline where required.

Benchmark hostnames, product nouns, answer-key routes, object IDs, and expected findings remain
prohibited detector inputs.

## 2. Canonical report truth

Every report block, count, grade, deployment decision, and parent rollup must derive from the same
canonical finding set and declared execution receipts. Missing or invalid telemetry degrades the
report; it never implies clean, completed, or covered.

The crAPI artifact exposed an invalid `probe_parameter_completion_ratio` above `1.0`. Commit
`53cd5fc` removed SQLi's double-count and made inconsistent completion telemetry fail the benchmark
gate. Future scorecards still need to prove the corrected receipt through the full submission path.

## 3. Fleet and build truth

Worker build fingerprints are authoritative. Validation scans require a uniform current fleet and
record the expected fingerprint and stale-worker count at submission. Historical benchmark or E2E
artifacts retain their original fingerprint and cannot be relabeled as current-build results.

## 4. Execution honesty, cancellation, and budgets

Registry receipts distinguish skipped, blocked, cancelled, failed, and completed execution. This is
implemented for the migrated adapters, but cancellation is still module-scoped and strict registry
authority is incomplete.

Request accounting must expose per-adapter:

- `metering_quality`: `exact`, `adapter_reported`, `reserved_upper_bound`, `estimated`, or `unknown`;
- `budget_enforcement`: `hard`, `soft`, or `unavailable`;
- planned, reserved, attempted, completed, retried, redirected, and rejected counts.

Only exact or enforceable upper-bound adapters may claim a hard request cap. Compatibility mode stays
the fallback until multi-worker rate and cancellation soak passes.

## 5. Finding identity and evidence

Canonical finding identity must preserve materially different routes, methods, principals, workflow
steps, and proof instances while collapsing retry/shard duplicates. Evidence remains append-only,
redacted, hashed, and linked to its proof and invocation receipts. Post-processing or retest verdicts
must not erase the evidence that established an earlier state.

## 6. Authentication and retest contracts

`two_principal_observed` currently means that user1/user2 lanes appeared in coverage telemetry. It
does not prove server acceptance or identity observation. Replace it with explicit additive states:

- principal contexts configured;
- distinct identities validated by the submitter;
- authenticated responses accepted;
- principal contexts attempted by family;
- cross-principal proof produced.

Persist only redacted identity fingerprints and validation outcomes. Never persist tokens or raw
identity claims in scorecards.

## 7. Continuous ASM and application graph

Continuous ASM remains the operating loop: inventory, graph, hypotheses, campaigns, attempts,
evidence, canonical findings, retests, and deployment decisions. Dynamic Full Coverage is the shipped
default; static allocation remains the rollback path. Parent reports and `/asm/gaps` must agree in
both modes before parity is accepted.

## 8. Proof taxonomy

AI judgment and source context are advisory. Only deterministic family proof contracts may mint
verified findings. Declared registry `proof_contract` and `severity_rules` must become enforced
runtime validators rather than descriptive metadata.

## 9. AI boundary

AI may propose, prioritize, correlate, and explain. ShakerScan-owned deterministic contracts decide
scope, approval, request construction, execution, proof, evidence, severity promotion, finding state,
and deployment gates. A shadow planner has no execution authority. One-step action selection remains
gated behind detector, registry, cancellation, budget, and parity acceptance.

## 10. Registry and invocation contracts

Close every registered-family bypass before calling registry execution authoritative. Then add typed
resource references and `AdapterInvocationSpec` contracts covering accepted resource kinds, argument
construction, safe flags, interaction mode, output/parser schema, cancellation, metering quality,
smoke fixtures, and a spec hash.

No runnable adapter may inherit a generic `<binary> <target>` invocation or treat process exit zero as
parser, evidence, or proof success.

## 11. Coverage honesty

Coverage obligations close only as proved, refuted, completed without proof, blocked with a declared
precondition, cancelled, partial/failed, or explicitly unattempted because of budget. Endpoint and
family coverage consume only supported telemetry schemas. Static and dynamic parent rollups must
reproduce the Continuous ASM attempt ledger.

## 12. Detector strategy

Prioritize universal response-guided request completion, authenticated API/spec discovery, workflow
and producer/consumer graph induction, replay-safe sibling-field preservation, and deterministic
benign-alternative controls. Do not optimize directly against benchmark routes or labels.

## Ordered next work

1. Benchmark truth contract: principal-validation receipt, bounded discovery manifest, valid
   completion metrics.
2. Seeded BOLA/SQLi detector controls, followed by universal authenticated discovery.
3. Registry bypass closure and runtime proof/severity validation.
4. Engine-wide cancellation plus per-adapter metering-quality contracts.
5. Quantitative dynamic/static parity, cancellation, rate, and current-fleet detector soak.
6. ObservationPack/DecisionEpisode schemas, then shadow planner evaluation only.
7. One-step gated planner selection only after all local gates remain green.
8. Multi-node fencing/idempotency proof last.

## Intentionally excluded

- Raw shell or arbitrary-code planner actions.
- AI-only or source-only verified findings.
- State-changing MCP without a separately designed approval model.
- Password spraying, post-exploitation automation, and benchmark-specific detector fitting.
- Multi-node production claims before fencing and stale-owner-write prevention are proven.
