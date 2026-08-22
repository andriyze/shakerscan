# ShakerScan product model

This document is the canonical user-facing vocabulary for ShakerScan. API namespaces and database
values may retain older names for compatibility, but the UI, README, agent skills, and live
documentation should use the terms below.

## Four primary workflows

| User goal | Product workflow | Execution |
|---|---|---|
| Run established automated checks | **DAST Scan** | `/scans`, scanner workers |
| Let an AI investigate adaptively | **Hunt** | canonical `/hunts/*` runtime |
| Test manually with a browser or multiple users | **Interactive Testing** | `/session/*` |
| Review and triage results | **Findings** | `/findings*`, `/retests*` |

Specialized scanners remain first-class:

- **Continuous ASM** keeps a target’s endpoint inventory and coverage current.
- **AI Gate** tests chat, RAG, agent, and MCP systems.
- **Model Intake** checks model artifacts, provenance, signatures, and policy.
- Connected devices use the same **Hunt** runtime with stricter capability, credential, fragility,
  health-circuit-breaker, and exact-confirmation policy.

The web **Targets** inventory contains HTTP(S) applications only. Model repositories and artifacts stay in
Model Intake, where their exact revision and content digests are the identity. They may still appear in
Exposure as model-artifact nodes, but never as DAST/ASM targets or domain-filter entries.

## Natural-language routing

Agents must preserve these distinctions:

| User phrase | Route |
|---|---|
| “scan example.com” | DAST Scan with the default resource budget |
| “quick/standard/deep/full/aggressive/smart scan” | Compatibility input mapped to a Scan budget and explicit policy |
| “deep hunt”, “autonomous hunt”, “investigate autonomously” | Hunt |
| “device hunt”, “investigate/hunt this TV, camera, printer, router, or device” | Hunt with `target_kind=device` |
| “verify this finding” | Deterministic finding verifier/retest |
| “interactive testing”, “test manually”, “browser session” | Interactive Testing |

`deep scan` is a legacy DAST budget alias. `Deep Hunt` and `Device Hunt` are compatibility names for Hunt.

## Device targets in Hunt

The current coding-agent session plans a bounded investigation of one registered device through
`/hunts/*`. ShakerScan fixes the durable device identity, current locator, safety
profile, credentials, traffic budgets, and health circuit breaker. Deterministic device scans remain
authoritative; AI leads are evidence-cited hypotheses.

Hunt may propose exact remote-device SSH commands only when an authenticated profile and
pinned host key are available. A proposal is inert until the user separately confirms the immutable
command plan in the UI. Imported Postman, HAR 1.2, OpenAPI 3.x, and Swagger 2.0 request documents
are encrypted and pinned to the device; Hunt sees only their redacted request inventory and
can include them in a scan only when the user fixed that authority at session start. Postman scripts,
HAR responses, and external specification references never execute, and state-changing HTTP
methods require a separate authenticated-active approval. The old `device-agent` API is migration-only:
historical reads and cancellation remain available, but new starts, replies, and shell confirmations
always return `410 Gone` and point to `/hunts`.

## Hunt

Hunt is one user workflow. The current coding-agent session:

1. reads a redacted target context;
2. composes its own probes against an explicit HTTP(S) origin on the selected target host;
3. queries stored endpoints, findings, leads, and principal state;
4. runs bounded active scanner templates when authorized;
5. can compare responses across controls and principals when managed principals are configured;
6. records only findings backed by tool-output evidence;
7. asks the server’s deterministic proof workflows to verify supported claims.

The user does not choose between “Operator” and “Explorer.” Those were implementation concepts.
The `/research/*` controller remains available only for specialized guided verification and the
advanced Test Builder. It is not a Hunt launcher. A Hunt request creates one `/hunts` run.

Active Hunt capabilities require explicit confirmation that the target is owned or authorized and a
target-bound, expiring approval. Every Hunt retains hard ceilings for capability calls, requests,
active actions, wall time, ports, hosts, browser actions, device fragility, and candidates.

DAST and Hunt treat a web host as one durable target across schemes and ports. Concrete origins
remain explicit execution choices, so `http://app:8080` and `https://app:9090` share history without
silently redirecting requests between them.

The free-form loop may use approved active scanner templates. Arbitrary state-changing HTTP remains
blocked; controlled mutations belong to typed workflows with cleanup, restoration, and proof
contracts.

## Findings

The primary source labels are:

- DAST
- Deep Hunt
- Interactive
- AI Gate
- Model Intake
- ASM
- Manual

Deep Hunt includes direct AI-investigator findings and scanner findings created as part of a hunt.
Compatibility API values such as `autonomous`, `ai_session`, and the
`evidence.research.driven_by` marker are normalized to those display labels.

Finding dimensions stay separate:

- **Severity:** Critical, High, Medium, Low, Info
- **Proof:** Verified, Suspected, Unverified, Inconclusive, Refuted
- **Source:** the workflow above
- **Lifecycle:** Active, Resolved, False positive, Accepted risk

Do not show both `DAST` and `Deep Hunt` as equal source badges for the same row. If a hunt launched
the DAST work, the user-facing source is Deep Hunt; the underlying scanner remains available in
technical metadata.

## Supporting surfaces

- **Leads** is the hypothesis backlog used by Hunt and verification.
- **Test Builder** is an advanced, hand-crafted experiment tool.
- **Mission Ledger** is the read-only `/campaigns` action history; it does not launch Deep Hunt.
- **Evidence** stores proof objects and export/retention records.
- **Timeline** combines activity across products.

## Compatibility terminology

| Compatibility term | User-facing term |
|---|---|
| Autonomous Hunt | Hunt |
| Deep Hunt | Hunt |
| Device Hunt | Hunt (`target_kind=device`) |
| Explorer | Retired Hunt implementation name |
| Operator | Guided verifier implementation |
| Research Agent | Hunt or guided verifier, depending on route |
| AI Device Investigation / device agent | Hunt (`target_kind=device`) |
| AI Session / `ai_session` | Interactive |
| Autonomous / `autonomous` finding source | Hunt |
| Plan a test | Test Builder |
| Campaigns | Mission Ledger |

Archived documents may retain historical terminology. New product copy and agent instructions must
follow this document.
