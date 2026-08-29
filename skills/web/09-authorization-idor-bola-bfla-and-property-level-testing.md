---
id: skill.web.authorization-idor-bola-bfla-and-property-level-testing
name: authorization-idor-bola-bfla-and-property-level-testing
title: 09. Authorization, IDOR, BOLA, BFLA, and Property-Level Testing
description: Systematically test horizontal, vertical, tenant, function, object, and property-level authorization
  across UI, API, batch, export, file, and realtime surfaces.
version: 2.0.0
kind: specialist
phase: active_testing
risk: medium
support: supported
target_kinds:
- web
- api
capabilities:
- http.request
- authz.verify
- browser.navigate
- candidate.verify
optional_capabilities:
- collections.inspect
missing_capabilities: []
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 160
  max_duration_seconds: 900
  max_state_changing_requests: 12
routing:
  triggers:
  - object_identifier
  - tenant_identifier
  - privileged_function
  - hidden_writable_property
  - signed_object_URL
  - batch_export_or_nested_resource
  indicators:
  - horizontal_access
  - vertical_access
  - cross_tenant_reference
  - property_overposting
  - indirect_channel_leak
  exclusions:
  - intentionally_public_object
  - uncontrolled_real_user_object
  - unapproved_tenant
preconditions:
- compiled_scope_policy
- two_controlled_identities
- synthetic_test_objects
- replayable_baseline_request
techniques:
- horizontal-object-read
- horizontal-object-write
- cross-tenant-boundary
- vertical-function-access
- property-level-read
- property-level-write
- indirect-channel-authorization
promotion_gate: core.evidence-validation:confirmed
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
server_satisfied_prerequisites: []
source: web-security-agent-skills v2.0.0 09-authorization-idor-bola-bfla-and-property-level-testing.md
---

# 09. Authorization, IDOR, BOLA, BFLA, and Property-Level Testing

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Prove whether the server enforces who may read, create, change, delete, invoke, assign, or export every object and property. Replace random identifier swapping with an identity-object-action-property matrix.

## Use this skill when

- Requests contain object IDs, tenant IDs, role-sensitive functions, hidden fields, exports, admin endpoints, or nested resources.
- At least two controlled users can create equivalent synthetic objects.
- APIs, GraphQL, WebSockets, files, batch operations, or signed URLs expose data beyond page access.
- Client-side controls hide operations or properties.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `object_identifier`
- `tenant_identifier`
- `privileged_function`
- `hidden_writable_property`
- `signed_object_URL`
- `batch_export_or_nested_resource`

**Useful indicators**

- `horizontal_access`
- `vertical_access`
- `cross_tenant_reference`
- `property_overposting`
- `indirect_channel_leak`

**Hard exclusions**

- `intentionally_public_object`
- `uncontrolled_real_user_object`
- `unapproved_tenant`

**Required preconditions**

- `compiled_scope_policy`
- `two_controlled_identities`
- `synthetic_test_objects`
- `replayable_baseline_request`

**Preferred preconditions**

- `second_test_tenant`
- `authoritative_state_verifier`
- `expected_authorization_matrix`

## Required context

- Two or more isolated controlled users, relevant roles, and separate tenants where possible.
- Synthetic objects owned by each identity.
- Expected authorization model for actions and properties.
- Replayable baseline requests and an authoritative state-verification method.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `http.request`
- `http.differential_replay`
- `browser.observe`
- `state.verify`

**Optional adapters**

- `graphql.execute`
- `realtime.exchange`
- `api.contract_analyze`

**Prohibited capabilities**

- `unrestricted_shell`
- `unscoped_egress`
- `real_user_targeting`
- `persistence`
- `denial_of_service`

**Default budget**

| Counter | Maximum |
|---|---:|
| `max_requests` | 160 |
| `max_duration_seconds` | 900 |
| `max_concurrency` | 2 |
| `max_state_changes` | 12 |
| `max_auth_attempts` | 0 |
| `max_messages` | 0 |
| `max_oob_interactions` | 0 |
| `max_uploaded_bytes` | 0 |
| `max_cost_units` | 170 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `non_test_object` | identifier may reference a real or uncontrolled object | `block` |
| `destructive_authorization_action` | delete, external share, or irreversible action is requested | `human_approval` |

**State access**

- Reads: `compiled_policy`, `identity_graph`, `object_graph`, `tenant_graph`, `request_corpus`, `expected_authorization_matrix`
- Writes: `authorization_test_matrix`, `observations`, `evidence_records`, `hypothesis_events`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- A peer can read or modify another user's object by changing an identifier.
- A lower role can invoke privileged functions or alternate methods.
- Cross-tenant object references are not consistently scoped.
- Hidden/read-only properties can be assigned or returned without authorization.
- Batch, export, search, file, nested, and realtime paths enforce weaker controls than primary endpoints.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- Use synthetic records and test tenants only.
- Test read and write separately; a masked response does not prove a mutation failed.
- Never infer authorization from UI visibility or client-side role checks.
- Stop after minimal proof; do not enumerate unrelated objects.

## Agent workflow

### 1. Build the authorization matrix

- Enumerate identities, roles, tenant memberships, ownership, object types, actions, properties, and lifecycle states.
- Define expected allow/deny outcomes for anonymous, peer, owner, manager, admin, service account, and cross-tenant contexts.
- Include nested resources, share links, exports, imports, batch operations, and background jobs.

### 2. Create paired test data

- Create equivalent objects under each controlled identity and tenant.
- Capture read, update, delete, share, export, and privileged-function requests.
- Record identifiers in path, query, body, headers, cookies, variables, filenames, signed URLs, and message channels.

### 3. Test horizontal and tenant boundaries

- Replay User A's exact request as User B while changing only the target object reference when required.
- Repeat for reads, writes, deletes, shares, files, exports, and nested endpoints.
- Verify authoritative state under both owners.

### 4. Test vertical and function boundaries

- Replay privileged functions as lower roles and through alternate methods, versions, batch endpoints, GraphQL mutations, or hidden routes.
- Check whether role/tenant fields in the request influence authorization.
- Test administrative reads and state changes separately.

### 5. Test property-level controls

- Add omitted or read-only fields such as role, owner, tenant, status, price, approval, quota, or internal flags using only synthetic objects.
- Check response filtering and write authorization independently.
- Test nested JSON, arrays, merge/patch semantics, serializers, and bulk updates.

### 6. Test indirect channels

- Evaluate search, autocomplete, notifications, activity feeds, logs, exports, signed links, caches, WebSockets, and object counts.
- Verify revoked shares and deleted memberships stop access everywhere.
- Record only the minimum unauthorized synthetic data needed for proof.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `horizontal-object-read` — Horizontal object read. Select only when the matching trigger and evidence preconditions are present.
- `horizontal-object-write` — Horizontal object write. Select only when the matching trigger and evidence preconditions are present.
- `cross-tenant-boundary` — Cross tenant boundary. Select only when the matching trigger and evidence preconditions are present.
- `vertical-function-access` — Vertical function access. Select only when the matching trigger and evidence preconditions are present.
- `property-level-read` — Property level read. Select only when the matching trigger and evidence preconditions are present.
- `property-level-write` — Property level write. Select only when the matching trigger and evidence preconditions are present.
- `indirect-channel-authorization` — Indirect channel authorization. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| Object read | Peer cannot read another object | Replay owned object request as peer | Unauthorized synthetic data returned |
| Object write | Peer cannot alter another object | Change one harmless field on paired object | Authoritative state changes |
| Privileged function | Lower role cannot invoke function | Replay exact admin action on synthetic data | Action succeeds or job is queued |
| Tenant boundary | Object reference is tenant-scoped | Use object ID from second test tenant | Cross-tenant access occurs |
| Property authorization | Sensitive fields are protected | Add one omitted/read-only field | Field is accepted or exposed without permission |

## Tool strategy

- Use an identity-object-action-property matrix and differential replay, not blind numeric enumeration.
- Browser automation helps create paired objects and verify UI state; raw HTTP is required for precise mutations.
- Use JSON-schema-aware mutation for nested and patch requests.
- Capture server logs/audit events when available to verify denied versus silently processed actions.

## Evidence required for a finding

- Two controlled identities, expected policy, paired objects, baseline request, unauthorized replay, and authoritative state result.
- For reads, only synthetic data sufficient to prove access.
- For writes, before/after state and object ownership.
- For property findings, exact field and permission boundary.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/authorization-idor-bola-bfla-and-property-level-testing.schema.json`.

**Skill-specific evidence fields**

- `actor_identity`
- `object_owner`
- `tenant`
- `action`
- `property`
- `expected_decision`
- `observed_decision`
- `state_before`
- `state_after`

**Required validation controls**

- `paired_controlled_objects`
- `read_and_write_separate`
- `semantic_owner_check`
- `authoritative_state_after_write`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- Public/shared objects may intentionally be readable; verify intended visibility.
- A 200 response may return masked or cached data; inspect semantics and ownership.
- A write response may claim success while transaction rolls back.
- Sequential IDs alone are not a vulnerability.

## Stop conditions

- An identifier may reference real customer data.
- A successful write/delete/share could affect a non-test object.
- The only proof requires broad object enumeration.
- Cross-tenant testing reaches an unapproved tenant.

## Common remediation patterns

- Enforce deny-by-default authorization server-side on every object, action, property, and tenant boundary.
- Derive tenant and ownership from authenticated context, not client-supplied fields.
- Centralize policy enforcement across REST, GraphQL, realtime, file, export, and batch paths.
- Use explicit allowlists for writable and readable properties.
- Add negative authorization tests with multiple identities to CI.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/authorization-idor-bola-bfla-and-property-level-testing.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.authorization-idor-bola-bfla-and-property-level-testing
supporting_skills: []
selected_techniques: [horizontal-object-read]
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
  evidence_extension_schema: schemas/evidence-extensions/authorization-idor-bola-bfla-and-property-level-testing.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 10 for workflows that are individually authorized but abusable in sequence.
- Skill 11/12/13 for API, GraphQL, and realtime variants.
- Skill 30 for deduplication into root-cause findings and regression matrices.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
identities: [user_a, user_b, manager_test]
objects: [project_a, project_b, file_a, file_b]
actions: [read, update, delete, export, share]
property_candidates: [owner_id, tenant_id, role, status]
```

## Authoritative references

- [OWASP Top 10 2025 — Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- [OWASP API Security — BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP API Security — Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- [PortSwigger — Access control](https://portswigger.net/web-security/access-control)

---

## ShakerScan runtime notes

**Support: supported.** Every adapter this skill requires maps to a planner-visible capability, so it can be bound to a hunt.

Bindable capabilities: `http.request`, `authz.verify`, `browser.navigate`, `candidate.verify`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
