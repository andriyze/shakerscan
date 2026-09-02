---
id: skill.web.graphql-security-testing
name: graphql-security-testing
title: 12. GraphQL Security Testing
description: Test GraphQL schema exposure, resolver authorization, object/property access, mutations,
  batching, aliases, subscriptions, and query-complexity controls.
version: 2.0.0
kind: specialist
phase: active_testing
risk: medium
support: partial
target_kinds:
- web
- api
capabilities:
- http.request
- authz.verify
- candidate.verify
optional_capabilities: []
missing_capabilities:
- graphql.execute
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 180
  max_duration_seconds: 900
  max_state_changing_requests: 10
routing:
  triggers:
  - GraphQL_endpoint
  - GraphQL_operation
  - introspection
  - Apollo_or_graphql_client_artifact
  - GraphQL_WebSocket
  indicators:
  - schema
  - field_argument
  - resolver_authorization
  - alias_or_batch
  - query_cost
  - mutation
  exclusions:
  - unbounded_recursive_query
  - real_data_bulk_query
preconditions:
- compiled_scope_policy
- GraphQL_endpoint
- bounded_operation_or_schema_fragment
techniques:
- schema-and-operation-discovery
- resolver-level-authorization
- field-and-argument-boundary
- alias-and-batch-control
- mutation-state-verification
- subscription-authorization
promotion_gate: core.evidence-validation:confirmed
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
server_satisfied_prerequisites: []
source: web-security-agent-skills v2.0.0 12-graphql-security-testing.md
---

# 12. GraphQL Security Testing

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Treat GraphQL as a graph of resolvers and authorization decisions rather than a single endpoint. Build an operation inventory, test each resolver with controlled identities, and bound all complexity/resource tests.

## Use this skill when

- JavaScript, traffic, documentation, or errors reveal GraphQL endpoints or operations.
- The application uses persisted queries, federation, subscriptions, batching, or mobile-generated operations.
- REST testing misses nested object/property boundaries.
- Introspection is disabled but the client still exposes operation documents.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `GraphQL_endpoint`
- `GraphQL_operation`
- `introspection`
- `Apollo_or_graphql_client_artifact`
- `GraphQL_WebSocket`

**Useful indicators**

- `schema`
- `field_argument`
- `resolver_authorization`
- `alias_or_batch`
- `query_cost`
- `mutation`

**Hard exclusions**

- `unbounded_recursive_query`
- `real_data_bulk_query`

**Required preconditions**

- `compiled_scope_policy`
- `GraphQL_endpoint`
- `bounded_operation_or_schema_fragment`

**Preferred preconditions**

- `controlled_identity`
- `synthetic_objects`
- `query_cost_limit`

## Required context

- Approved GraphQL endpoints, captured queries/mutations/subscriptions, and controlled identities.
- Schema or client operation documents if available.
- Maximum query depth, aliases, batch size, cost, request rate, and subscription count.
- Synthetic objects across users, roles, and tenants.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `graphql.execute`
- `http.request`
- `http.differential_replay`
- `state.verify`

**Optional adapters**

- `realtime.exchange`
- `javascript.analyze`

**Prohibited capabilities**

- `unrestricted_shell`
- `unscoped_egress`
- `real_user_targeting`
- `persistence`
- `denial_of_service`

**Default budget**

| Counter | Maximum |
|---|---:|
| `max_requests` | 180 |
| `max_duration_seconds` | 900 |
| `max_concurrency` | 2 |
| `max_state_changes` | 10 |
| `max_auth_attempts` | 0 |
| `max_messages` | 0 |
| `max_oob_interactions` | 0 |
| `max_uploaded_bytes` | 0 |
| `max_cost_units` | 180 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `high_complexity_graphql` | estimated operation cost or response size exceeds the engagement cap | `block` |

**State access**

- Reads: `compiled_policy`, `GraphQL_schema`, `GraphQL_operations`, `identities`, `object_graph`
- Writes: `GraphQL_operation_inventory`, `resolver_observations`, `cost_observations`, `evidence_records`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- Introspection, suggestions, errors, or client artifacts disclose sensitive schema information.
- Resolver-level authorization is missing on nested fields, nodes, edges, or mutations.
- Aliases, batching, fragments, or persisted-query variants bypass limits or controls.
- Depth/complexity/resource limits are absent or inconsistently enforced.
- Subscriptions expose cross-user or cross-tenant events or survive revocation.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- Do not run unbounded recursive, alias, batch, or complexity queries.
- Use captured or schema-derived operations before guessing field names.
- Test only synthetic data and minimal nested fields needed for proof.
- Introspection exposure alone is usually informational unless it materially reveals sensitive or hidden capabilities.

## Agent workflow

### 1. Discover endpoints and transport

- Identify POST/GET endpoints, content types, persisted-query mechanisms, multipart uploads, WebSocket subprotocols, federation gateways, and alternate versions.
- Capture required headers, CSRF behavior, cookies/tokens, and client identifiers.
- Verify the endpoint with a harmless known operation.

### 2. Build the operation/schema model

- Use authorized introspection when permitted; otherwise extract operations and fragments from clients, docs, errors, and traffic.
- Catalog object types, fields, arguments, IDs, mutations, subscriptions, custom scalars, directives, and role-specific operations.
- Mark sensitive fields and resolver chains.

### 3. Test authorization by resolver

- Create paired synthetic objects and replay node/edge/field queries across controlled users and tenants.
- Test nested fields separately from top-level object access.
- Check mutations, aliases, batch entries, node/global-ID lookups, and property assignment.

### 4. Test parser and operation variants

- Compare named versus anonymous operations, GET versus POST, JSON versus GraphQL body, persisted versus full query, fragments, aliases, and batched requests.
- Change one variant at a time.
- Verify authentication, CSRF, rate, logging, and authorization remain consistent.

### 5. Test complexity safely

- Increase depth, breadth, aliases, batch count, and expensive resolver combinations in small bounded steps.
- Measure server-reported cost, latency, response size, errors, and health signals.
- Stop far below service-degradation thresholds.

### 6. Test subscriptions and uploads

- Verify handshake identity, channel/event authorization, object filters, reconnect, logout, token expiry, and tenant isolation.
- For uploads, hand off file processing while retaining GraphQL-specific authorization and multipart parsing checks.
- Close all subscriptions and clean synthetic state.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `schema-and-operation-discovery` — Schema and operation discovery. Select only when the matching trigger and evidence preconditions are present.
- `resolver-level-authorization` — Resolver level authorization. Select only when the matching trigger and evidence preconditions are present.
- `field-and-argument-boundary` — Field and argument boundary. Select only when the matching trigger and evidence preconditions are present.
- `alias-and-batch-control` — Alias and batch control. Select only when the matching trigger and evidence preconditions are present.
- `mutation-state-verification` — Mutation state verification. Select only when the matching trigger and evidence preconditions are present.
- `subscription-authorization` — Subscription authorization. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| Nested field | Resolver enforces object/property access | Query one sensitive field as peer user | Unauthorized synthetic field returned |
| Mutation | Role/ownership enforced server-side | Replay mutation on paired object | Unauthorized state change |
| Batch/alias | Limits and auth apply per operation | Small bounded batch/aliases | Control bypass or multiplied action |
| Persisted query | Hash and operation are bound | Change variables/operation reference | Unexpected operation accepted |
| Subscription | Events are identity/tenant scoped | Subscribe as second test user | Cross-user synthetic event received |

## Tool strategy

- Use GraphQL-aware clients, Burp extensions, `graphql-cop`, InQL-style extraction, or local schema parsers.
- Prefer operation documents harvested from the client over blind field guessing.
- Measure query cost and response structure with small custom scripts.
- Use `websocat`/browser tooling for subscription transport where appropriate.

## Evidence required for a finding

- Endpoint, transport, exact operation, variables, identity, expected resolver policy, and response.
- For access control, paired synthetic objects and minimal unauthorized field/action.
- For complexity, bounded step sequence and health evidence.
- For subscriptions, event source, subscriber identity, and revocation state.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/graphql-security-testing.schema.json`.

**Skill-specific evidence fields**

- `operation_name`
- `operation_document`
- `variables`
- `identity`
- `estimated_cost`
- `response_summary`
- `authorization_decision`

**Required validation controls**

- `bounded_field_selection`
- `synthetic_data_only`
- `introspection_not_finding_alone`
- `authoritative_mutation_state`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- Schema/introspection visibility is not automatically exploitable.
- A GraphQL 200 can contain errors and no data; inspect both.
- Client-side field hiding is not authorization.
- Latency growth may reflect cold caches rather than exploitable complexity.

## Stop conditions

- Query cost, latency, memory, errors, or service-health counters approach limits.
- A recursive query or batch could affect other users.
- An operation touches real objects or an unapproved tenant.
- Subscription testing begins receiving unrelated real-user events.

## Common remediation patterns

- Enforce authorization in every resolver and data-loader path.
- Use field/property allowlists and tenant scoping derived from authenticated context.
- Apply depth, breadth, alias, batch, response-size, timeout, and cost controls.
- Secure persisted queries and keep controls consistent across transport variants.
- Authorize subscriptions at connection and event-delivery time; revoke on session changes.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/graphql-security-testing.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.graphql-security-testing
supporting_skills: []
selected_techniques: [schema-and-operation-discovery]
hypothesis_id: HYP-example-001
risk: medium
policy_revision: POL-example-r1
approval_refs: []
budget: <copy or reduce the manifest budget>
actions: <typed actions only>
validation:
  positive_conditions: [<skill-specific condition>]
  negative_controls: [<control>]
  confirmation_runs: 1
  authoritative_state_required: false
  evidence_extension_schema: schemas/evidence-extensions/graphql-security-testing.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 09 for object/function/property authorization root cause.
- Skill 13 for subscription transport and realtime lifecycle.
- Skill 20 for multipart file uploads and Skill 25 for resource limits.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
endpoint: https://api.example.test/graphql
identities: [user_a, user_b, admin_test]
schema_source: client_operations_plus_allowed_introspection
complexity_budget: depth_8_aliases_10_batch_5
```

## Authoritative references

- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [PortSwigger — GraphQL API vulnerabilities](https://portswigger.net/web-security/graphql)
- [GraphQL Specification](https://spec.graphql.org/)

---

## ShakerScan runtime notes

**Support: partial.** ShakerScan has no capability for `graphql.execute`, so this skill cannot be bound to a hunt yet. It is published so the gap is visible rather than discovered mid-run.

Bindable capabilities: `http.request`, `authz.verify`, `candidate.verify`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
