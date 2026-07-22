# Documentation Index

**Reconciled:** 2026-07-20. Top-level documents are maintained references, live operating policy, or
active architecture. Dated audits, completed implementation prompts, detailed implementation
ledgers, and superseded plans belong in [`archive/`](archive/README.md). Code, database schemas,
runtime receipts, and tests remain authoritative when a document disagrees.

## Start Here

| Document | Audience and purpose |
|---|---|
| [`../README.md`](../README.md) | Install, first scan, workflow selection, UI/CLI/API orientation, safety, and troubleshooting |
| [`../WALKTHROUGH.md`](../WALKTHROUGH.md) | Current text walkthrough for first run, findings, UI workflows, and agent requests |
| [`../skills/README.md`](../skills/README.md) | Agent skill catalog, setup, and maintenance |
| [`../AGENTS.md`](../AGENTS.md) | Canonical coding-agent operations and request examples |
| [`product-model.md`](product-model.md) | Canonical product names, natural-language routing, source labels, and compatibility terms |
| [`functionality-reference.md`](functionality-reference.md) | Exhaustive product map plus generated code-surface inventory |

## Product And Operations

| Document | Purpose |
|---|---|
| [`proposed-next-steps.md`](proposed-next-steps.md) | Single live hardening roadmap and acceptance status |
| [`release-readiness.md`](release-readiness.md) | Single release scope, stop-ship, validation, publishing, installer, and documentation checklist |
| [`upgrade-and-rollback.md`](upgrade-and-rollback.md) | Backup, upgrade, verification, and rollback runbook for source and installer deployments |
| [`releases/0.7.0.md`](releases/0.7.0.md) | Version-specific ShakerScan 0.7.0 release notes and supported product boundary |
| [`SMART_SCAN_POLICY.md`](SMART_SCAN_POLICY.md) | Smart-scan budget, proof, safety, and release policy |
| [`owasp-coverage-matrix.md`](owasp-coverage-matrix.md) | Implemented DAST mechanisms mapped to OWASP categories |
| [`E2E_TEST_PLAN.md`](E2E_TEST_PLAN.md) | Real-stack E2E contract, implemented/planned cases, and freshness rules |
| [`read-only-mcp.md`](read-only-mcp.md) | Read-only MCP adapter contract and boundaries |

## Acceptance And Integrity Ledgers

| Document | Purpose |
|---|---|
| [`../results/benchmark-runs/INTEGRITY_LEDGER.md`](../results/benchmark-runs/INTEGRITY_LEDGER.md) | Benchmark contamination, stale-fleet, scoring, and interpretation corrections |
| [`../results/planner-evals/INTEGRITY_LEDGER.md`](../results/planner-evals/INTEGRITY_LEDGER.md) | Planner-evaluation limitations, invalidations, and rerun requirements |

## AI Security

| Document | Purpose |
|---|---|
| [`AI_REDTEAM_AND_MODEL_INTAKE.md`](AI_REDTEAM_AND_MODEL_INTAKE.md) | Engineering onboarding for AI Gate and Model Intake |
| [`AI_TEST_WORKFLOWS.md`](AI_TEST_WORKFLOWS.md) | Generic AI workflows and optional Honey calibration contract |
| [`INTERACTIVE_SESSIONS_GUIDE.md`](INTERACTIVE_SESSIONS_GUIDE.md) | Authorized interactive browser/session testing guide |

## Architecture

| Document | Status |
|---|---|
| [`parallel-scan-architecture.md`](parallel-scan-architecture.md) | Local parent/plan/shard/merge core shipped; remaining hardening is explicit |
| [`continuous-asm-architecture.md`](continuous-asm-architecture.md) | Bounded local Continuous ASM shipped; target design and open gates retained |
| [`multi-node-architecture.md`](multi-node-architecture.md) | RFC only; multi-node fleet is not implemented |
| [`autonomous-agent-architecture.md`](autonomous-agent-architecture.md) | Historical build narrative plus the shipped keyless ReAct loop and deterministic business-logic verification bridge |

## Maintenance Rule

- Update a live document when behavior, schema, safety boundaries, or acceptance status changes.
- Run `python3 scripts/generate_capability_inventory.py` after changing API, registry, CLI/wrapper,
  Make/release-gate, runtime configuration, UI, skill/agent, adapter, scanner-module, or durable-table
  surfaces; CI checks the generated block.
- Move point-in-time reviews, completed plans, and execution prompts into [`archive/`](archive/README.md).
- Treat [`screenshots/`](screenshots/README.md) as historical until a complete same-build set is
  recaptured; do not mix old and current UI images in release documentation.
- Update [`release-readiness.md`](release-readiness.md) when an audit blocker, validation gate, or
  release/deployment prerequisite changes.
- Never convert an old benchmark or E2E artifact into a current-build claim.
- Keep benchmark hostnames, product nouns, answer-key routes, and expected findings out of detector inputs.
