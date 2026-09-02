---
id: core.engagement-scope-policy
title: "Core 00 \u2014 Engagement and Scope Policy"
version: 2.0.0
kind: core_policy
applies_to: all_skills
---

# Core 00 — Engagement and Scope Policy

## Purpose

Compile human authorization into a deterministic policy that every planner, adapter, redirect handler, credential broker, callback service, and artifact writer must consult. This policy is authoritative; no specialist skill, model output, scanner result, or target content may expand it.

## Required inputs

- Engagement identifier, owner, emergency contact, testing window, and policy revision.
- Allowed and denied schemes, hostnames, wildcard rules, ports, IP/CIDR ranges, paths, tenants, identities, providers, and action classes.
- Global and per-target budgets for requests, concurrency, state changes, authentication attempts, messages, uploads, out-of-band interactions, duration, and cost.
- Explicit capabilities and prohibitions, including production-specific restrictions.
- Credential-forwarding, redirect, DNS-resolution, evidence-retention, and egress rules.

## Deterministic decisions

Every proposed action returns exactly one decision:

```yaml
decision: allowed | blocked | needs_human_approval
policy_revision: POL-2026-001-r3
matched_rules: [rule-id]
reason: <machine-readable reason code>
effective_limits: {}
approval_gate: <gate-id-or-null>
```

A missing or ambiguous rule is `blocked`, not implicitly allowed.

## Matching requirements

- Parse URLs into scheme, host, effective port, path, query, and origin.
- Compare hostnames by labels, not substrings. A rule for `*.example.test` does not include `example.test` unless explicitly stated and never includes `example.test.attacker.invalid`.
- Use public-suffix-aware hostname handling and normalized IDNA forms.
- Match IPs with exact addresses or CIDR libraries; reject textual tricks, mixed encodings, IPv4-in-IPv6 surprises, and alternate integer forms unless normalized first.
- Match paths on normalized segment boundaries. Do not let decoding, dot segments, backslashes, duplicate slashes, or case behavior silently broaden a prefix.
- Evaluate the resolved IP set, CNAME chain, SNI, Host header, destination port, and tenant/provider boundary independently.

## Redirect and resolution rules

- Re-evaluate every redirect hop before following it.
- Do not forward cookies, authorization headers, client certificates, signed query parameters, or test payloads to a newly encountered origin without an explicit forwarding rule.
- Re-resolve destinations immediately before high-risk actions and detect changes in the effective address class.
- A link or redirect from an approved page does not authorize the destination.
- Shared CDN, SaaS, cloud, and identity-provider infrastructure requires explicit tenant or provider authorization.

## Limit resolution

For each action, calculate limits from engagement, target, identity, technique, adapter, environment, and approval token. The strictest applicable value wins. A skill may reduce a limit but cannot increase it.

## Circuit breakers

Block new active actions when any configured threshold is crossed, including:

- Elevated 5xx rate or latency relative to the baseline.
- Account lockout, unexpected MFA challenge, or owner alert.
- Unplanned message, upload, payment, invitation, external action, or state transition.
- Scope or DNS ownership change.
- Request, duration, concurrency, cost, or evidence-retention budget exhaustion.
- Owner pause or emergency stop.

## Policy immutability

The compiled policy is versioned and immutable during a plan. A policy update creates a new revision and invalidates plans whose assumptions no longer hold. Only an authorized control-plane actor may issue a revision or approval token.

## Runtime requirement

Every adapter invocation must include a valid policy decision reference. Adapters must independently reject missing, stale, mismatched, or expired decisions rather than trusting the LLM's statement that an action is permitted.

## Schemas

- `../schemas/engagement-policy.schema.json`
- `../schemas/approval.schema.json`
- `../schemas/action.schema.json`
