# ShakerScan documentation

**Status:** maintained documentation index; reviewed 2026-09-23.

The root [README](../README.md) is intentionally a short operator quick start. This directory is
for maintained engineering, architecture, and advanced-operation references.

Runtime behavior is authoritative in code, database migrations, tests, and the live API contracts.
Point-in-time plans, release readiness notes, completed implementation diaries, and obsolete claims
belong in Git history or immutable release notes rather than the active documentation set.

## Core architecture

- [Product model](product-model.md) — canonical product names and boundaries.
- [Functionality reference](functionality-reference.md) — exhaustive generated/current product map.
- [AI-native architecture](ai-native-architecture-rfc.md) — Scan/Hunt architecture direction.
- [Hunt architecture](hunt-architecture.md) — adaptive investigation model.
- [DAST and ASM architecture](dast-asm-architecture.md) — deterministic Scan and attack-surface model.
- [Service intelligence](service-intelligence.md) — service observations and investigation handoff.
- [Multi-node architecture](multi-node-architecture.md) — distributed execution design.

## Hunt and authenticated testing

- [Hunt authorization behavior](hunt-authorization-behavior.md)
- [Hunt authorization workflow](hunt-authorization-workflow.md)
- [Hunt investigation evaluation](hunt-investigation-evaluation.md)
- [Operator-complete Hunt implementation](hunt-operator-workflows.md)
- [Hunt review integrity](hunt-review-integrity.md)
- [Authenticated assurance](authenticated-assurance.md)
- [Browser login QA](browser-login-qa.md)
- [Browser session integrity](browser-session-integrity.md)

## Devices, AI, and model security

- [Connected-device security](connected-device-security.md)
- [AI test workflows](AI_TEST_WORKFLOWS.md)
- [Model Intake security roadmap](model-intake-security-review-roadmap.md)

## Operations

- [Client](client.md)
- [LAN access](lan-access.md)
- [Clean reinstall](clean-reinstall.md)
- [Upgrade and rollback](upgrade-and-rollback.md)
- [Release process](release-process.md)
- [Release notes](releases/README.md)
- [SBOM](sbom.md)
- [MCP](mcp.md)
- [Multi-node guide](multi-node-guide.md)
- [Data lifecycle](data-lifecycle-retention-and-portability-plan.md)

## Engineering references

- [End-to-end test plan](E2E_TEST_PLAN.md)
- [API image boundary](api-image-boundary.md)
- [Compatibility](compatibility.md)
- [Hosted connector](hosted-connector.md)
- [OWASP coverage matrix](owasp-coverage-matrix.md)
- [Decisions](decisions/)
- [Integrity ledgers](ledgers/)
- [Generated contracts and inventories](generated/)

Historical release plans and superseded operating documents are intentionally not maintained here.
Use Git history or immutable release notes when investigating an older release.
