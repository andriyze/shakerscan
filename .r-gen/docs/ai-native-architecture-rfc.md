# AI-Native Scan and Hunt Architecture RFC

The normative deterministic-Scan traffic classification is recorded in
[ADR 0001: Scan traffic risk classes](decisions/0001-scan-traffic-risk-classes.md).
The immutable post-discovery planning model is recorded in
[ADR 0002: Bounded Scan continuation amendments](decisions/0002-bounded-scan-continuation-amendments.md).

**Status:** implemented; legacy web/device Hunt engines quarantined for migration reads and cancellation
**Plan date:** 2026-08-19
**Pinned `origin/smart` baseline:** `84c185538990e9403b5c972ff91b5f212799910d`

## Decision

ShakerScan will expose two primary application-security workflows:

1. **Scan**: one deterministic and reproducible DAST pipeline.
2. **Hunt**: one durable AI-driven investigation runtime, filtered by target kind and policy.

Legacy Quick, Standard, Deep, Full, Aggressive, and Smart names are compatibility inputs only.
They map to a Scan budget plus explicit policy and must not remain separate execution engines.
Deep Hunt and Device Hunt similarly become compatibility names for the shared Hunt runtime.

The AI owns hypotheses, prioritization, capability selection, adaptation, and attack-chain
reasoning. ShakerScan owns target binding, scope, approvals, credentials, capabilities, budgets,
placement, execution, persistence, evidence, deterministic proof, finding promotion, and audit.

## Canonical runtime

The migration converges on one authoritative implementation for each concept:

- capability registry and typed adapters;
- multi-dimensional budget ledger and execution receipts;
- runtime scope and destination enforcement;
- target-bound credential/principal resolution;
- observation and candidate persistence;
- deterministic family-proof promotion;
- deterministic Scan pipeline;
- planner-independent Hunt session runtime.

Tool binaries are adapter details. Planner-facing names describe capabilities such as
`web.probe`, `web.crawl`, `templates.scan`, `ports.discover`, `service.fingerprint`,
`tls.inspect`, `sqli.verify`, and `xss.verify`. The runtime constructs argv and injects the
approved destination; callers never provide arbitrary flags or destinations.

## Scan contract

The canonical Scan request contains a target, budget profile or explicit limits, policy,
authentication references, request-collection bindings, and optional advanced family/worker
limits. The deterministic phases are prepare, discover, normalize manifest, baseline checks,
authorized active checks, verify/promote, and finalize.

Coverage budget changes ceilings only. Active testing is permitted only by explicit policy and a
valid approval receipt. Parallelism and sharding are internal planner decisions. Run status is
separate from coverage status so safe partial discovery can still produce a completed scan.

Legacy mappings during the compatibility window are:

| Legacy input | Canonical mapping |
|---|---|
| `quick` | active off, fast budget |
| `standard` | active off, balanced budget |
| `deep` | active off, thorough budget |
| `full` | active on, thorough budget |
| `aggressive` | active on, thorough budget plus explicit larger ceilings |
| `smart` | active on, thorough budget |

`smart` never maps implicitly to Hunt.

## Hunt contract

A Hunt is a durable target-bound session. The external coding agent is normally the planner and
uses a bounded context pack plus typed capability schemas. ShakerScan validates each call, binds
the target, resolves credentials, reserves budget, places and executes the capability, records a
receipt, normalizes observations, and exposes remaining budget.

Target kinds (`web`, `api`, `device`, and `network`) select capabilities and safety policy without
creating new orchestration engines. Device fragility, pacing, health circuit breakers, exact
origin binding, SSH confirmation, and cleanup contracts remain deterministic runtime policy.

## Evidence and reliability invariants

- AI prose, a tool label, an HTTP 200 response, or an anomaly cannot verify a finding.
- Candidates require evidence references and pass through family-specific deterministic proof.
- Budgets are reserved before sockets or tool dispatch and reconciled after execution.
- Valid partial streaming output is preserved on timeout with explicit partial/timeout metadata.
- Soft, flush, and hard discovery deadlines stop scheduling, allow bounded flushing, then kill
  remaining process groups while preserving trustworthy records.
- User cancellation does not continue normal scan execution.
- Secrets are resolved late, target-bound, encrypted at rest, redacted, and never returned to the
  planner by default.

## Migration sequence

1. Lock this baseline and compatibility behavior.
2. Introduce the canonical capability registry.
3. Introduce the shared budget ledger and typed receipts.
4. Migrate network/TLS tools to target-bound capabilities.
5. Generalize request collections with separate import, replay, preview, and page limits.
6. Add incremental discovery manifests and graceful deadlines.
7. Build deterministic Scan V2 behind a flag, then make it the default and deprecate old names.
8. Add unified Hunt V2. Route compatibility URLs in the UI to it; quarantine incompatible legacy
   API writes with an explicit `410 Gone` response rather than translating authority-bearing requests.
9. Consolidate Hunt skills and expose the same runtime through API/MCP.
10. Delete quarantined legacy engine code after the published migration sunset. Until then, historical
    reads and emergency cancellation remain available and carry deprecation headers, but cannot create
    or advance work.

New work must not add scan-type branching or a second target-specific Hunt engine during this
migration.
