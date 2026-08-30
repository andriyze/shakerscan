# ShakerScan product model

**Status:** canonical product vocabulary; reconciled 2026-08-29.

This document is the canonical user-facing vocabulary for ShakerScan. API namespaces and database
values may retain older names for compatibility, but the UI, README, agent skills, and live
documentation should use the terms below.

## Two core security workflows

| User goal | Product workflow | Execution |
|---|---|---|
| Run established automated checks | **DAST Scan** | `/scans`, scanner workers |
| Let an AI investigate adaptively | **Hunt** | canonical `/hunts/*` runtime |

**Findings** (`/findings*`, `/retests*`) is the shared review and triage surface, not another
execution engine. Manual browser work through `/session*` is an agent/Command Arsenal compatibility
API with no standalone 2.0 UI; prefer Hunt for new adaptive investigations.

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
| “fast/balanced/thorough scan” | Scan with the named resource ceiling |
| “investigate autonomously”, “hunt this target” | Hunt |
| “investigate/hunt this TV, camera, printer, router, or device” | Hunt with `target_kind=device` |
| “verify this finding” | Deterministic finding verifier/retest |
| “interactive testing”, “test manually”, “browser session” | Compatibility `/session*` only when bounded manual browser work is specifically required; otherwise Hunt |

Older names are accepted only at explicitly documented compatibility boundaries. They never select a
different engine. See [`compatibility.md`](compatibility.md); current clients should discover Scan and
Hunt request shapes from `GET /scan/contracts` and `GET /hunts/contract`.

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
- Hunt
- Interactive (compatibility/manual provenance)
- AI Gate
- Model Intake
- ASM
- Manual

Hunt includes direct AI-investigator findings and scanner findings created as part of a hunt.
Compatibility API values such as `autonomous`, `ai_session`, and the
`evidence.research.driven_by` marker are normalized to those display labels.

Finding dimensions stay separate:

- **Severity:** Critical, High, Medium, Low, Info
- **Proof:** Verified, Suspected, Unverified, Inconclusive, Refuted
- **Source:** the workflow above
- **Lifecycle:** Active, Resolved, False positive, Accepted risk

Do not show both `DAST` and `Hunt` as equal source badges for the same row. If a hunt launched
the DAST work, the user-facing source is Hunt; the underlying scanner remains available in
technical metadata.

## Supporting surfaces

- **Leads** is the hypothesis backlog used by Hunt and verification.
- **Test Builder** is an advanced, hand-crafted experiment tool.
- **Mission Ledger** is the read-only `/campaigns` action history; it does not launch Hunt.
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
| AI Session / `ai_session` | Interactive (compatibility/manual provenance) |
| Autonomous / `autonomous` finding source | Hunt |
| Plan a test | Test Builder |
| Campaigns | Mission Ledger |

Archived documents may retain historical terminology. New product copy and agent instructions must
follow this document.
