---
id: core.skill-routing-composition
title: "Core 06 \u2014 Skill Routing and Composition"
version: 2.0.0
kind: core_policy
applies_to: all_skills
---

# Core 06 — Skill Routing and Composition

## Purpose

Select the smallest relevant set of skills and technique modules for each hypothesis. Avoid loading all playbooks, spraying unrelated payloads, or allowing a specialist skill to broaden its own authority.

## Routing inputs

The router consumes structured features, not raw target instructions:

- Protocol, content type, method, endpoint and parameter shape.
- Authentication, role, tenant, object, and workflow context.
- Technology and parser hints.
- Browser, API, GraphQL, realtime, file, cache, AI, or identity features.
- Current hypotheses, evidence, risk, remaining budgets, and approvals.

## Selection process

1. Apply scope and environment exclusions.
2. Select one current phase or orchestrator skill.
3. Rank specialist skills by trigger match, preconditions, evidence availability, risk, cost, and expected information gain.
4. Select one primary specialist and at most the primary skill's `max_supporting_skills`.
5. Resolve declared conflicts and approval gates.
6. Select one or more technique IDs within each skill; do not activate every technique by default.
7. Retrieve only the relevant Markdown sections, manifest, schemas, and target-state references.

## Default context set

```text
Core scope policy
+ Core trust boundary
+ Core tool execution
+ Core evidence validation
+ Core state contract
+ One phase/methodology skill
+ One primary specialist
+ Zero to three supporting specialists
+ Relevant target state and evidence references
```

## Scoring example

```yaml
score:
  trigger_match: 0.35
  precondition_readiness: 0.20
  expected_information_gain: 0.15
  impact_relevance: 0.10
  evidence_quality_available: 0.10
  cost_efficiency: 0.05
  safety_margin: 0.05
```

A high trigger score cannot overcome a failed required precondition or a policy exclusion.

## Composition rules

- Supporting skills contribute hypotheses, mutations, or validation requirements; the primary skill owns the plan.
- The strictest budget, risk, stop condition, and approval requirement across selected skills applies.
- A skill conflict blocks simultaneous execution; the orchestrator sequences separate plans if both remain relevant.
- Discovery skills may create candidates but not active-testing authority.
- Skill 30 validates, deduplicates, chains, reports, and creates regressions; it does not bypass specialist gates.

## Router output

```yaml
routing_id: ROUTE-...
primary_skill: skill.web.authorization-idor-bola-bfla-and-property-level-testing
supporting_skills:
  - skill.web.graphql-security-testing
selected_techniques:
  - horizontal-object-read
  - resolver-level-authorization
rejected_skills:
  - skill_id: skill.web.sql-nosql-orm-and-ldap-injection-testing
    reason: no_query_interpreter_indicator
required_approvals: []
effective_budget: {}
state_refs: []
```

## Failure behavior

When no skill satisfies scope and preconditions, return `no_eligible_skill` with missing inputs. Do not select a loosely related high-risk skill merely to continue testing.
