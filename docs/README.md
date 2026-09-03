# Documentation Index

**Reconciled:** 2026-08-29. This directory contains maintained product references, operating policy,
release material, and active architecture. Point-in-time audits, completed prompts, implementation
ledgers, and obsolete screenshots are kept in Git history rather than copied into the release docs.
Code, database schemas, runtime receipts, and tests remain authoritative when a document disagrees.

## Start Here

| Document | Audience and purpose |
|---|---|
| [`../README.md`](../README.md) | Install, first scan, workflow selection, UI/CLI/API orientation, safety, and troubleshooting |
| [`../WALKTHROUGH.md`](../WALKTHROUGH.md) | Current text walkthrough for first run, findings, UI workflows, and agent requests |
| [`../skills/README.md`](../skills/README.md) | Agent skill catalog, setup, and maintenance |
| [`../AGENTS.md`](../AGENTS.md) | Compact, always-loaded coding-agent policy and operating decisions |
| [`product-model.md`](product-model.md) | Canonical product names, natural-language routing, source labels, and compatibility terms |
| [`functionality-reference.md`](functionality-reference.md) | Exhaustive product map plus generated code-surface inventory |

## Product And Operations

| Document | Purpose |
|---|---|
| [`proposed-next-steps.md`](proposed-next-steps.md) | Short future-only roadmap; completed plans move to the archive |
| [`release-readiness.md`](release-readiness.md) | Single release scope, stop-ship, validation, publishing, installer, and documentation checklist |
| [`release-process.md`](release-process.md) | Enforced candidate, required exact-SHA physical gates, digest promotion, public smoke, and stable-channel sequence |
| [`upgrade-and-rollback.md`](upgrade-and-rollback.md) | Backup, upgrade, verification, and rollback runbook for source and installer deployments |
| [`multi-node-guide.md`](multi-node-guide.md) | Operate the supported outbound-HTTPS Fleet; WireGuard is preview-only |
| [`releases/README.md`](releases/README.md) | Immutable release-note index, including published and failed/cancelled candidates |
| [`releases/2.0.0.md`](releases/2.0.0.md) | Pending 2.0.0 notes and exact validation boundary |
| [`releases/0.8.18.md`](releases/0.8.18.md) | Current stable-line release notes until 2.0.0 promotion succeeds |
| [`owasp-coverage-matrix.md`](owasp-coverage-matrix.md) | Implemented DAST mechanisms mapped to OWASP categories |
| [`E2E_TEST_PLAN.md`](E2E_TEST_PLAN.md) | Real-stack E2E contract, implemented/planned cases, and freshness rules |
| [`mcp.md`](mcp.md) | MCP's separate read-only Arsenal and state-changing target-bound Hunt trust levels |
| [`compatibility.md`](compatibility.md) | Internal legacy-input/read compatibility boundary; not a second product surface |
| [`data-lifecycle-retention-and-portability-plan.md`](data-lifecycle-retention-and-portability-plan.md) | Implemented retention/export safety boundary and genuinely remaining lifecycle work |

## Acceptance And Integrity Ledgers

| Document | Purpose |
|---|---|
| [`ledgers/benchmark-integrity-ledger.md`](ledgers/benchmark-integrity-ledger.md) | Benchmark contamination, stale-fleet, scoring, and interpretation corrections |
| [`ledgers/planner-evals-integrity-ledger.md`](ledgers/planner-evals-integrity-ledger.md) | Planner-evaluation limitations, invalidations, and rerun requirements |

## AI Security

| Document | Purpose |
|---|---|
| [`AI_TEST_WORKFLOWS.md`](AI_TEST_WORKFLOWS.md) | Generic AI workflows and optional Honey calibration contract |
| [`INTERACTIVE_SESSIONS_GUIDE.md`](INTERACTIVE_SESSIONS_GUIDE.md) | Compatibility-only `/session*` boundary; prefer Hunt for new investigations |
| [`model-intake-security-review-roadmap.md`](model-intake-security-review-roadmap.md) | Current Model Intake subject, trust, isolation, and acceptance boundary |

## Architecture

| Document | Status |
|---|---|
| [`ai-native-architecture-rfc.md`](ai-native-architecture-rfc.md) | Scan V2 and unified Hunt architecture, pinned baseline, migration boundary, and acceptance contract |
| [`dast-asm-architecture.md`](dast-asm-architecture.md) | Current one-shot DAST, local scatter/gather, and Continuous ASM execution model |
| [`connected-device-security.md`](connected-device-security.md) | Connected-device inventory, safe service assessment, policy evaluation, isolated execution, and web-origin handoff |
| [`multi-node-architecture.md`](multi-node-architecture.md) | Implemented multi-node trust, transport, scheduling, lifecycle, evidence, and acceptance design authority |
| [`decisions/README.md`](decisions/README.md) | Normative architecture-decision index |

## Historical Archive

Point-in-time audits, completed implementation ledgers, retired engines, and pre-V2 policy live under
[`archive/`](archive/README.md). They are migration evidence, not current product instructions or
release proof.

## Maintenance Rule

- Update a live document when behavior, schema, safety boundaries, or acceptance status changes.
- Run `python3 scripts/generate_capability_inventory.py` after changing API, registry, CLI/wrapper,
  Make/release-gate, runtime configuration, UI, skill/agent, adapter, scanner-module, or durable-table
  surfaces; CI checks the generated block.
- Remove point-in-time reviews, completed plans, execution prompts, and stale screenshots from the
  maintained set; Git history and release tags preserve them when needed.
- Update [`release-readiness.md`](release-readiness.md) when an audit blocker, validation gate, or
  release/deployment prerequisite changes.
- Never convert an old benchmark or E2E artifact into a current-build claim.
- Keep benchmark hostnames, product nouns, answer-key routes, and expected findings out of detector inputs.
