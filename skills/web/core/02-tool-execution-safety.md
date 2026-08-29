---
id: core.tool-execution-safety
title: "Core 02 \u2014 Typed Tool Execution and Safety"
version: 2.0.0
kind: core_policy
applies_to: all_skills
---

# Core 02 — Typed Tool Execution and Safety

## Purpose

Ensure the LLM plans security tests while deterministic adapters enforce scope, arguments, budgets, isolation, and evidence capture.

## Execution model

```text
LLM/Planner -> Typed Test Plan -> Policy/Approval Check -> Adapter Validator
            -> Deterministic Tool -> Normalized Result -> Evidence Store
```

The LLM must not directly execute unrestricted shell commands, construct raw process command lines, or invent tool results.

## Adapter requirements

Every adapter must:

- Validate input with its versioned schema.
- Resolve opaque references through the control plane, not through model-provided paths or secrets.
- Re-check scope and approval immediately before execution.
- Enforce the action and remaining engagement budgets.
- Apply rate, concurrency, timeout, redirect, egress, and output-size limits.
- Capture raw inputs and outputs locally before normalization.
- Return a normalized result with timestamps, tool version, exit status, policy decision, safety counters, and artifact references.
- Fail closed on unknown arguments, unsupported modes, stale sessions, or ambiguous destinations.

## Atomic actions

Plans should use small actions with one purpose. An action may contain several protocol messages only when the adapter itself needs an atomic sequence, such as a synchronized race batch or single-connection desynchronization probe. The adapter—not the LLM—controls that sequence.

## Shell policy

`shell.allowlisted` accepts only a registered template identifier and typed artifact references. It must never accept raw shell text, pipes, redirections, command substitution, environment-variable expansion, or unvalidated filenames. Prefer native adapters over shell templates.

## Tool-output policy

Scanner results are observations or hypotheses. They cannot create confirmed findings. Tool-reported severity, exploitability, or remediation is advisory until the evidence validator applies the relevant skill's promotion gate.

## Isolation

High-risk processors, browser payloads, document parsers, source-map execution, dependency analysis, and generated files should run in disposable, least-privileged environments with egress restrictions. Test workers must not possess unrelated production credentials.

## Runtime safety counters

At minimum, track:

```yaml
requests: 0
concurrency_peak: 0
state_changes: 0
auth_attempts: 0
messages: 0
oob_interactions: 0
uploaded_bytes: 0
cost_units: 0
duration_seconds: 0
```

Counters are updated by adapters and cannot be overridden by the model.

## Result statuses

Adapters return `completed`, `blocked`, `failed`, `timed_out`, or `cancelled`. A technical failure is never interpreted as a vulnerability signal without a stable control and explicit validation.

## Schemas

- `../schemas/action.schema.json`
- `../schemas/test-plan.schema.json`
- `../schemas/tool-result.schema.json`
- `../schemas/actions/`
