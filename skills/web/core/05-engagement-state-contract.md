---
id: core.engagement-state
title: "Core 05 \u2014 Engagement State Contract"
version: 2.0.0
kind: core_policy
applies_to: all_skills
---

# Core 05 — Engagement State Contract

## Purpose

Provide a model-independent source of truth for assets, identities, sessions, objects, requests, hypotheses, plans, actions, evidence, findings, approvals, and runtime counters.

## Required entities

```text
Engagement
PolicyRevision
ApprovalToken
Asset / Origin / Service
Identity / Role / Tenant / Session
Object / Owner / LifecycleState
Endpoint / Parameter / Workflow
RequestArtifact / ResponseArtifact / BrowserTrace / OOBEvent
Hypothesis / TestPlan / Action / ToolResult
EvidenceRecord / ValidationRecord / Finding / AttackPath / RegressionTest
```

## Identity and object binding

Every authenticated request, browser context, token, object, and state-verification action must be labeled with controlled identity, role, tenant, and ownership where known. Authorization testing without identity-object provenance is inconclusive.

## Read/write discipline

Each skill manifest declares state it may read and write. The control plane enforces these declarations. Specialist skills normally write plans, observations, evidence, and hypothesis events but cannot write confirmed findings, policy, approvals, or tool permissions.

## Immutability and provenance

- Raw artifacts, policy revisions, approval tokens, action records, and evidence records are immutable.
- Corrections append a superseding record; they do not rewrite history.
- Every derived summary references its source artifacts and transformation version.
- Store content hashes and timestamps for reproducibility.

## Session safety

Sessions are opaque references. The model receives labels and capabilities, not raw cookies or tokens. Adapters verify freshness and refresh legitimate anti-CSRF, nonce, timestamp, or one-time values through authorized workflows.

## Concurrent execution

Use optimistic versioning or locks for mutable test objects and budget counters. An action plan records the state version it assumed. The executor rejects or replans stale state rather than applying a mutation to an unexpected object state.

## Redaction views

Maintain at least:

- Protected raw artifact view for authorized operators.
- Redacted analyst/model view.
- Report-safe view.

Redaction must preserve the security-relevant structure and evidence references.

## Retention and cleanup

Track retention deadlines, test uploads, synthetic records, cache entries, callback tokens, and cleanup status. Cleanup is a recorded action and never silently destroys primary evidence needed by policy.

## Schema

- `../schemas/engagement-state.schema.json`
