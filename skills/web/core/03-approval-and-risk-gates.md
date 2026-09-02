---
id: core.approval-risk-gates
title: "Core 03 \u2014 Approval and Risk Gates"
version: 2.0.0
kind: core_policy
applies_to: all_skills
---

# Core 03 — Approval and Risk Gates

## Purpose

Require explicit, narrow, expiring authorization for actions whose impact cannot be safely inferred from general engagement scope.

## Risk classes

| Class | Meaning | Default handling |
|---|---|---|
| Passive | Reads existing public/authorized information without interacting with application state | Automatic within scope |
| Low-impact active | Small read-only or reversible probes with bounded traffic | Automatic within skill budget |
| High-risk active | Actions that can affect processing, shared state, internal destinations, parsers, identity, concurrency, caches, or external providers | Human approval unless a signed engagement capability names it |
| Destructive | Irreversible data loss, real financial/external effect, persistence, malware, real-user interaction, or service degradation | Prohibited by this library |

## Approval token

An approval must bind all of the following:

```yaml
approval_id: APR-...
engagement_id: ENG-...
policy_revision: POL-...
gate_id: <skill gate>
skill_id: <exact skill>
targets: [<exact target refs>]
identities: [<exact controlled identities>]
action_classes: [<exact actions>]
limits: {}
valid_from: <timestamp>
expires_at: <timestamp>
approver: <authorized human/control-plane principal>
reason: <specific rationale>
```

Broad statements such as “do whatever is necessary” are not valid runtime approvals.

## Gate behavior

- A missing, expired, target-mismatched, skill-mismatched, or policy-revision-mismatched token blocks the action.
- Approvals never override the prohibited-capability list.
- The effective budget is the lower of the approval limit and all other applicable limits.
- A supporting skill cannot inherit a primary skill's approval unless the token explicitly names the supporting action class.
- A successful low-impact probe does not authorize escalation to a stronger technique.

## Production defaults

The following normally require explicit production approval or staging execution: request smuggling/desynchronization, cache writes outside unique test paths, private/link-local SSRF, deserialization gadget tests, OS-command canaries, federation signature-parser attacks, concurrency above micro-batches, fault injection, and resource testing beyond normal-use envelopes.

## Human review package

A request for approval should contain the hypothesis, exact action schema, target and identity references, expected evidence, maximum impact, budgets, cleanup, stop conditions, and safer alternatives already attempted.
