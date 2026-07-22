# Proposed Next Steps - Current Status and Hardening Roadmap

**Status (2026-07-17):** the bounded local/owned-target product is implemented, but it is not
release-complete. Detector acceptance, strict registry authority, engine-wide cancellation,
metering-quality contracts, current-fleet validation, and live parity/soak remain open. The Research
Agent now ships immutable one-decision observations, current-agent/configured-provider/local-Codex
planner modes, durable multi-episode campaigns, anonymous read-only HTTP differentials, and
principal-bound HTTP/browser workflows. Credential-tier workflows may use bounded same-origin
state-changing steps with server-resolved principals, cleanup/restoration contracts, two-run
corroboration, deterministic family proof, and proof-gated finding promotion. The server can
materialize selected create-based mass-assignment leads using per-run credentials and discovered
create/read-back shapes. This remains bounded authorized-target execution, not unrestricted or
unattended production autonomy.

This is the single live implementation/hardening status document. Historical implementation detail
is preserved in the [archive](archive/README.md), including the completed adaptive-research wave
ledger, deferred-wave plan, and evidence-grounded 2026-07-11 architecture review. The separate
[`release-readiness.md`](release-readiness.md) checklist owns release validation, metadata, installer,
and publication prerequisites.

## Current acceptance snapshot

| Area | Current status | Evidence boundary |
|---|---|---|
| Unit and contract tests | No current release-candidate claim | Earlier checkpoints passed, but product work continued after them; rerun on the frozen candidate |
| Documentation and skill checks | Passing at the 2026-07-17 documentation reconciliation | Generated inventory, local-link/index checks, skill validation, shell syntax, and focused documentation tests; rerun after final candidate changes |
| UI production build and browser QA | Open for the release candidate | Older desktop/narrow-view acceptance predates the current dashboard and recent research changes |
| Fleet freshness | No current release-candidate claim | Worker fingerprints must be checked immediately before every benchmark/E2E run |
| Full current-build E2E | Open | Historical Model Intake/AI Gate/DAST counts are not current-build evidence; implemented versus planned cases are explicit in `E2E_TEST_PLAN.md` |
| Juice Shop benchmark | Non-current pass | `6/9` on anonymous fleet `ddc6173b`; not a current-fleet claim |
| Authenticated crAPI benchmark | Corrected rescore fails | scan `94ac5c7f` was previously marked passing from an identity-only BOLA heuristic. The 2026-07-11 corrected rescore is `1/4` but fails `require_verified_bola`: no persisted distinct-principal receipt and no independent authorization control. |
| Auth bootstrap | Partially proven | Harness minted different JWT identity claims and scheduled two auth lanes; server acceptance is not yet receipt-backed |
| Registry authority | Partial | Main adapters are registry-dispatched, but phase-4 BOLA, NoSQL, and endpoint-scoped registered coverage still bypass the strict decision boundary |
| Request budgets | Compatibility by default | Meter exists; known opaque tools are rejected in enforce mode; per-adapter quality and soak remain open |
| Multi-node | Design only | No fencing, stale-owner-write prevention, partition/skew acceptance, or brokered short-lived secrets |

Current implementation progress includes redacted principal-validation receipts and bounded
completion ratios (`53cd5fc`), the trusted adaptive workflow/promotion loop, and create-based
mass-assignment materialization through `2d0dde4`. None of those commits upgrades an older benchmark
or E2E artifact into a current-build claim. Limitations and reinterpretations remain preserved in the
[`Benchmark Integrity Ledger`](../results/benchmark-runs/INTEGRITY_LEDGER.md).

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
and deployment gates. The shipped Research Agent binds each single decision to an immutable
`ObservationPack` hash, injects target, principal, and receipt authority server-side, rejects
model-supplied control fields, reserves bounded budget, and dispatches only the explicit research
allowlist through the Arsenal gateway. Shadow mode never dispatches; read-only mode cannot select
gated commands; gated mode additionally requires target-matching approval/scope receipts. Standard
installs enable gated execution; `AI_OPS_ROUTER_EXECUTE_ENABLED=false` is the global kill switch.
Anonymous HTTP differentials remain read-only. Credential-tier
workflows can use server-authorized writes only through typed same-origin steps and restoration/
cleanup rules. AI output cannot create or verify findings; trusted live re-execution and the family
promotion gate control any autonomous finding.

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

## 13. Research discovery and loop acceptance

The create-based mass-assignment dispatcher, server materializer, per-run credentials, read-back
proof, and proof-gated promotion are implemented. The 2026-07-17 live-drive ledger also established
that a normal campaign can still stop before dispatch because the persistent target surface does not
contain the object-instance read-back route or the create-based lead is absent from the ranked live
board. Treat the dispatcher proof and autonomous campaign acceptance as separate boundaries.

Required next increments:

1. Infer object-instance routes only from target-observed collection/concrete-route facts; do not
   invent a delete capability merely because an API looks REST-like.
2. Persist authorized operator/OpenAPI/custom-endpoint ingestion into the canonical target surface
   used by decision validation.
3. Design an explicit Lab-only create-surface probe if passive/schema/browser discovery cannot
   establish the returned object route. Keep server-generated credentials, labels, budgets, and
   best-effort cleanup visible.
4. Admit a create-object read-back sibling only through a family-specific, server-derived rule with
   tests proving unrelated off-surface routes remain rejected.
5. Keep create-based/net-new and operator-seeded high-severity leads visible under family-balanced
   ranking without allowing untrusted priority to bypass evidence/provability.
6. Prove the same server-materialized workflow works with the configured-provider planner, not only
   the current-agent path.
7. Rerun a clean live campaign from ordinary discovery to promotion and record findings plus test
   objects left behind. Do not hand-seed routes/rank to manufacture a green acceptance result.

## Ordered next work

1. Close the release-blocking evidence redaction, proof-authority, attack-path semantics, and active
   authorization contracts tracked in `release-readiness.md`.
2. Freeze a candidate and rerun unit, UI build/browser, release-gate, E2E, and current-fleet
   benchmark acceptance. Preserve exact fingerprints and content-free receipts.
3. Seed BOLA/SQLi detector-isolation controls, followed by universal authenticated discovery and an
   unseeded scorecard.
4. Close registered-family bypasses and enforce runtime proof/severity validation uniformly.
5. Complete engine-wide cancellation plus per-adapter metering-quality contracts.
6. Run quantitative dynamic/static parity, cancellation, rate, and current-fleet detector soak.
7. Close the research discovery/surface/ranking items in §13, then expand held-out Research Agent
   evaluations beyond contract/scope/risk fixtures. Measure useful
   action selection, verified net-new yield, false promotion, model cost, retry behavior, cleanup,
   and stop quality across current-agent, configured-provider, and isolated-local planners.
8. Wire the named release gates and version-specific release notes into release automation, correct
   image license metadata, then deploy and fresh-install-smoke the hosted bootstrap.
9. Multi-node fencing/idempotency proof last.

## Intentionally excluded

- Raw shell or arbitrary-code planner actions.
- AI-only or source-only verified findings.
- State-changing MCP without a separately designed approval model.
- Password spraying, post-exploitation automation, and benchmark-specific detector fitting.
- Multi-node production claims before fencing and stale-owner-write prevention are proven.
