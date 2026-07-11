# Documentation Index

**Reconciled:** 2026-07-11. Top-level documents are maintained references or active designs. Dated
audits, completed implementation prompts, and superseded plans belong in [`archive/`](archive/README.md).
Code, database schemas, runtime receipts, and tests remain authoritative when a document disagrees.

## Product And Operations

| Document | Purpose |
|---|---|
| [`functionality-reference.md`](functionality-reference.md) | Canonical exhaustive product map plus generated code-surface inventory |
| [`proposed-next-steps.md`](proposed-next-steps.md) | Single live hardening roadmap and acceptance status |
| [`SMART_SCAN_POLICY.md`](SMART_SCAN_POLICY.md) | Smart-scan budget, proof, safety, and release policy |
| [`owasp-coverage-matrix.md`](owasp-coverage-matrix.md) | Implemented DAST mechanisms mapped to OWASP categories |
| [`E2E_TEST_PLAN.md`](E2E_TEST_PLAN.md) | Real-stack E2E scope, cases, and freshness rules |
| [`read-only-mcp.md`](read-only-mcp.md) | Read-only MCP adapter contract and boundaries |

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

## Maintenance Rule

- Update a live document when behavior, schema, safety boundaries, or acceptance status changes.
- Run `python3 scripts/generate_capability_inventory.py` after changing API, registry, CLI/wrapper,
  Make/release-gate, runtime configuration, UI, skill/agent, adapter, scanner-module, or durable-table
  surfaces; CI checks the generated block.
- Move point-in-time reviews, completed plans, and execution prompts into [`archive/`](archive/README.md).
- Never convert an old benchmark or E2E artifact into a current-build claim.
- Keep benchmark hostnames, product nouns, answer-key routes, and expected findings out of detector inputs.
