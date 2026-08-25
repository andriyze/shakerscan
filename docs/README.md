# Documentation Index

**Reconciled:** 2026-08-25. This directory contains maintained product references, operating policy,
release material, and active architecture. Point-in-time audits, completed prompts, implementation
ledgers, and obsolete screenshots are kept in Git history rather than copied into the release docs.
Code, database schemas, runtime receipts, and tests remain authoritative when a document disagrees.

## Start Here

| Document | Audience and purpose |
|---|---|
| [`../README.md`](../README.md) | Install, first scan, workflow selection, UI/CLI/API orientation, safety, and troubleshooting |
| [`../WALKTHROUGH.md`](../WALKTHROUGH.md) | Current text walkthrough for first run, findings, UI workflows, and agent requests |
| [`../skills/README.md`](../skills/README.md) | Agent skill catalog, setup, and maintenance |
| [`../AGENTS.md`](../AGENTS.md) | Canonical coding-agent operations and request examples |
| [`product-model.md`](product-model.md) | Canonical product names, natural-language routing, source labels, and compatibility terms |
| [`functionality-reference.md`](functionality-reference.md) | Exhaustive product map plus generated code-surface inventory |
| [`source-assisted-scanning-and-microvm-isolation-proposal.md`](source-assisted-scanning-and-microvm-isolation-proposal.md) | Proposal for Semgrep-backed source intelligence and narrowly scoped future Firecracker reuse |

## Product And Operations

| Document | Purpose |
|---|---|
| [`proposed-next-steps.md`](proposed-next-steps.md) | Future-only product roadmap and remaining release-validation work |
| [`release-readiness.md`](release-readiness.md) | Single release scope, stop-ship, validation, publishing, installer, and documentation checklist |
| [`release-process.md`](release-process.md) | Enforced candidate, digest promotion, optional physical acceptance, public smoke, and stable-channel sequence |
| [`upgrade-and-rollback.md`](upgrade-and-rollback.md) | Backup, upgrade, verification, and rollback runbook for source and installer deployments |
| [`multi-node-guide.md`](multi-node-guide.md) | Set up and operate WireGuard or outbound-HTTPS multi-node fleets |
| [`releases/2.0.0.md`](releases/2.0.0.md) | Pending ShakerScan 2.0.0 AI-native architecture release notes and validation boundary |
| [`releases/0.8.18.md`](releases/0.8.18.md) | Published ShakerScan 0.8.18 installer-hardening release notes and validation boundary |
| [`releases/0.8.17.md`](releases/0.8.17.md) | Published ShakerScan 0.8.17 corrective release notes and supported product boundary |
| [`releases/0.8.16.md`](releases/0.8.16.md) | Published ShakerScan 0.8.16 patch-release notes and supported product boundary |
| [`releases/0.8.15.md`](releases/0.8.15.md) | Published ShakerScan 0.8.15 patch-release notes and supported product boundary |
| [`releases/0.8.14.md`](releases/0.8.14.md) | Failed, unpublished ShakerScan 0.8.14 candidate notes |
| [`releases/0.8.13.md`](releases/0.8.13.md) | Published ShakerScan 0.8.13 release notes and supported product boundary |
| [`releases/0.8.10.md`](releases/0.8.10.md) | Cancelled, unpublished ShakerScan 0.8.10 candidate notes |
| [`releases/0.8.9.md`](releases/0.8.9.md) | Published ShakerScan 0.8.9 patch notes; not promoted after remote-mode audit |
| [`releases/0.8.8.md`](releases/0.8.8.md) | Unpublished ShakerScan 0.8.8 candidate notes |
| [`releases/0.8.7.md`](releases/0.8.7.md) | ShakerScan 0.8.7 release notes |
| [`releases/0.8.6.md`](releases/0.8.6.md) | Failed, unpublished ShakerScan 0.8.6 candidate notes |
| [`releases/0.8.5.md`](releases/0.8.5.md) | ShakerScan 0.8.5 patch-release notes and supported product boundary |
| [`releases/0.8.4.md`](releases/0.8.4.md) | ShakerScan 0.8.4 patch-release notes and supported product boundary |
| [`releases/0.8.2.md`](releases/0.8.2.md) | ShakerScan 0.8.2 patch-release notes and supported product boundary |
| [`releases/0.8.0.md`](releases/0.8.0.md) | ShakerScan 0.8.0 release notes and supported product boundary |
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
| [`AI_TEST_WORKFLOWS.md`](AI_TEST_WORKFLOWS.md) | Generic AI workflows and optional Honey calibration contract |
| [`INTERACTIVE_SESSIONS_GUIDE.md`](INTERACTIVE_SESSIONS_GUIDE.md) | Authorized interactive browser/session testing guide |
| [`model-intake-security-review-roadmap.md`](model-intake-security-review-roadmap.md) | Model Intake controls, architecture, provider-neutral review procedure, implementation status, limitations, and acceptance gates |
| [`AUDIT-2026-07.md`](AUDIT-2026-07.md) | 2026-07 end-to-end product/security audit: findings, fixes, and verified-good behavior |
| [`audit-evidence-2026-07.md`](audit-evidence-2026-07.md) | Durable evidence index, reproduction commands, and remediation release gates for the 2026-07 audit |

## Architecture

| Document | Status |
|---|---|
| [`ai-native-architecture-rfc.md`](ai-native-architecture-rfc.md) | Scan V2 and unified Hunt architecture, pinned baseline, migration boundary, and acceptance contract |
| [`ai-native-refactor-audit.md`](ai-native-refactor-audit.md) | Baseline inventory and legacy-dependency checklist for the one-Scan/one-Hunt migration |
| [`v2-re-audit-2026-08-20.md`](v2-re-audit-2026-08-20.md) | Point-in-time V2 implementation re-audit and remaining runtime acceptance gates |
| [`dast-asm-architecture.md`](dast-asm-architecture.md) | Current one-shot DAST, local scatter/gather, and Continuous ASM execution model |
| [`connected-device-security.md`](connected-device-security.md) | Connected-device inventory, safe service assessment, policy evaluation, isolated execution, and web-origin handoff |
| [`deep-hunt-architecture.md`](deep-hunt-architecture.md) | Deep Hunt AI-investigator engine: ReAct loop, tool arsenal, provenance gate, two-tier SUSPECTED/VERIFIED bridge, and the §5 improvement backlog |
| [`multi-node-architecture.md`](multi-node-architecture.md) | Implemented multi-node trust, transport, scheduling, lifecycle, evidence, and acceptance design authority |

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
