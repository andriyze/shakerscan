# ShakerScan product model

This document is the canonical user-facing vocabulary for ShakerScan. API namespaces and database
values may retain older names for compatibility, but the UI, README, agent skills, and live
documentation should use the terms below.

## Four primary workflows

| User goal | Product workflow | Execution |
|---|---|---|
| Run established automated checks | **DAST Scan** | `/scans`, scanner workers |
| Let an AI investigate autonomously | **Deep Hunt** | keyless `/agent/hunt/*` loop |
| Test manually with a browser or multiple users | **Interactive Testing** | `/session/*` |
| Review and triage results | **Findings** | `/findings*`, `/retests*` |

Specialized scanners remain first-class:

- **Continuous ASM** keeps a target’s endpoint inventory and coverage current.
- **AI Gate** tests chat, RAG, agent, and MCP systems.
- **Model Intake** checks model artifacts, provenance, signatures, and policy.
- **Device Hunt** is the agentic investigation workflow for one registered connected device. It is
  separate from web-focused Deep Hunt and runs through the connected-device safety boundary.

The web **Targets** inventory contains HTTP(S) applications only. Model repositories and artifacts stay in
Model Intake, where their exact revision and content digests are the identity. They may still appear in
Exposure as model-artifact nodes, but never as DAST/ASM targets or domain-filter entries.

## Natural-language routing

Agents must preserve these distinctions:

| User phrase | Route |
|---|---|
| “scan example.com” | Quick DAST, the documented default |
| “quick/standard/deep/full/aggressive/smart scan” | Exact DAST scan type |
| “deep hunt”, “autonomous hunt”, “investigate autonomously” | Deep Hunt |
| “device hunt”, “investigate/hunt this TV, camera, printer, router, or device” | Device Hunt |
| “verify this finding” | Deterministic finding verifier/retest |
| “interactive testing”, “test manually”, “browser session” | Interactive Testing |

`deep scan` is DAST. `Deep Hunt` is AI-driven exploration and bounded exploitation.

## Device Hunt

Device Hunt is the connected-device counterpart to Deep Hunt. The current coding-agent session
plans a bounded investigation of one registered device through `/devices/{device_id}/agent/session`
and `/device-agent/session/*`. ShakerScan fixes the durable device identity, current locator, safety
profile, credentials, traffic budgets, and health circuit breaker. Deterministic device scans remain
authoritative; AI leads are evidence-cited hypotheses.

Device Hunt may propose exact remote-device SSH commands only when an authenticated profile and
pinned host key are available. A proposal is inert until the user separately confirms the immutable
command plan in the UI. The internal `device-agent` API name remains for compatibility; UI and
documentation use **Device Hunt**.

## Deep Hunt

Deep Hunt is one user workflow. The current coding-agent session:

1. reads a redacted target context;
2. composes its own probes against an explicit HTTP(S) origin on the selected target host;
3. queries stored endpoints, findings, leads, and principal state;
4. runs bounded active scanner templates when authorized;
5. can compare responses across controls and principals when managed principals are configured;
6. records only findings backed by tool-output evidence;
7. asks the server’s deterministic proof workflows to verify supported claims.

The user does not choose between “Operator” and “Explorer.” Those were implementation concepts.
The compatibility `/research/*` controller remains available for specialized guided verification,
but a Deep Hunt request launches `/agent/hunt/{target_id}/session` with `mode:"deep_hunt"`.

Deep Hunt requires:

- explicit confirmation that the target is owned or authorized;
- a target-bound, expiring credential-tier approval;
- the server gated-execution policy, enabled in standard installs and globally disabled with
  `AI_OPS_ROUTER_EXECUTE_ENABLED=false` when required;
- hard turn, request, and active-action ceilings.

DAST and Deep Hunt treat a web host as one durable target across schemes and ports. Concrete origins
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

- **Leads** is the hypothesis backlog used by Deep Hunt and verification.
- **Test Builder** is an advanced, hand-crafted experiment tool.
- **Mission Ledger** is the read-only `/campaigns` action history; it does not launch Deep Hunt.
- **Evidence** stores proof objects and export/retention records.
- **Timeline** combines activity across products.

## Compatibility terminology

| Compatibility term | User-facing term |
|---|---|
| Autonomous Hunt | Deep Hunt |
| Explorer | Deep Hunt implementation |
| Operator | Guided verifier implementation |
| Research Agent | Deep Hunt or guided verifier, depending on route |
| AI Device Investigation / device agent | Device Hunt |
| AI Session / `ai_session` | Interactive |
| Autonomous / `autonomous` finding source | Deep Hunt |
| Plan a test | Test Builder |
| Campaigns | Mission Ledger |

Archived documents may retain historical terminology. New product copy and agent instructions must
follow this document.
