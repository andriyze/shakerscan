---
id: skill.web.race-condition-concurrency-and-idempotency-testing
name: race-condition-concurrency-and-idempotency-testing
title: 24. Race Condition, Concurrency, and Idempotency Testing
description: Test one-time actions, state transitions, quotas, transactions, uploads, and object creation
  for concurrency, TOCTOU, duplicate execution, and idempotency failures.
version: 2.0.0
kind: specialist
phase: active_testing
risk: high
support: partial
target_kinds:
- web
- api
capabilities:
- http.request
- candidate.verify
optional_capabilities:
- browser.navigate
missing_capabilities:
- http.concurrent_batch
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 60
  max_duration_seconds: 900
  max_state_changing_requests: 15
routing:
  triggers:
  - one_time_action
  - quota_or_limit
  - credit_or_coupon
  - object_creation
  - inventory_or_booking
  - idempotency_key
  - TOCTOU
  indicators:
  - duplicate_success
  - invariant_violation
  - multiple_objects
  - double_credit
  - stale_state_acceptance
  exclusions:
  - real_money_or_inventory
  - destructive_operation
  - large_concurrency
  - shared_production_object
preconditions:
- compiled_scope_policy
- documented_invariant
- synthetic_state
- authoritative_state_verifier
techniques:
- duplicate-execution
- limit-overrun
- one-time-token-race
- idempotency-key-reuse
- TOCTOU-state-change
- object-creation-race
promotion_gate: core.evidence-validation:confirmed
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
server_satisfied_prerequisites: []
source: web-security-agent-skills v2.0.0 24-race-condition-concurrency-and-idempotency-testing.md
---

# 24. Race Condition, Concurrency, and Idempotency Testing

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Find security-relevant state inconsistencies that occur only when valid requests overlap. Use synchronized micro-batches against synthetic low-value state, measure authoritative results, and never load-test the service.

## Use this skill when

- The app performs one-time redemption, transfer, purchase, refund, invitation, approval, verification, reservation, quota, counter, or object creation.
- Requests use idempotency keys, version fields, optimistic locking, queues, or asynchronous processing.
- Sequential replay is safe but may not expose a time-of-check/time-of-use window.
- Duplicate or contradictory states have been observed.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `one_time_action`
- `quota_or_limit`
- `credit_or_coupon`
- `object_creation`
- `inventory_or_booking`
- `idempotency_key`
- `TOCTOU`

**Useful indicators**

- `duplicate_success`
- `invariant_violation`
- `multiple_objects`
- `double_credit`
- `stale_state_acceptance`

**Hard exclusions**

- `real_money_or_inventory`
- `destructive_operation`
- `large_concurrency`
- `shared_production_object`

**Required preconditions**

- `compiled_scope_policy`
- `documented_invariant`
- `synthetic_state`
- `authoritative_state_verifier`

**Preferred preconditions**

- `cleanup_method`
- `transaction_or_log_visibility`

## Required context

- Synthetic accounts/objects/value, exact baseline transaction, and authoritative state view.
- Maximum concurrency, request count, monetary/value ceiling, and cleanup plan.
- Expected idempotency, locking, uniqueness, and state-transition semantics.
- Low-latency synchronized request tooling.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `http.request`
- `http.concurrent_batch`
- `state.verify`

**Optional adapters**

- `browser.observe`
- `log.observe`

**Prohibited capabilities**

- `unrestricted_shell`
- `unscoped_egress`
- `real_user_targeting`
- `persistence`
- `denial_of_service`

**Default budget**

| Counter | Maximum |
|---|---:|
| `max_requests` | 60 |
| `max_duration_seconds` | 900 |
| `max_concurrency` | 8 |
| `max_state_changes` | 15 |
| `max_auth_attempts` | 0 |
| `max_messages` | 0 |
| `max_oob_interactions` | 0 |
| `max_uploaded_bytes` | 0 |
| `max_cost_units` | 150 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `concurrency_above_micro_batch` | batch exceeds the configured small cap or targets production shared state | `human_approval` |

**State access**

- Reads: `compiled_policy`, `business_invariants`, `request_corpus`, `object_graph`, `runtime_health`
- Writes: `sequential_controls`, `concurrency_batches`, `final_state_records`, `evidence_records`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- Two overlapping requests both pass a one-time check before state updates.
- Duplicate submissions create multiple objects, benefits, charges, messages, or jobs.
- Idempotency keys are optional, weakly scoped, reusable, or checked too late.
- Optimistic locking/version checks can be bypassed or are absent.
- Asynchronous workers or retries produce partial, contradictory, or stale authorization state.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- This is not load testing. Begin with 2 requests and increase only to the approved small cap.
- Use synthetic low-value state and test notification/payment providers.
- Do not race destructive operations, real inventory, real money, or shared production objects.
- Stop at the first repeatable invariant violation.

## Agent workflow

### 1. Select candidate invariants

- Identify one-time flags, balances, quotas, stock, approvals, unique memberships, tokens, object versions, and state-machine transitions.
- Write the expected atomic invariant and authoritative final state.
- Choose reversible synthetic data.

### 2. Build a stable sequential control

- Execute the request once, then sequentially repeat to understand normal duplicate handling.
- Record idempotency keys, versions, timestamps, transaction IDs, and asynchronous jobs.
- Reset synthetic state deterministically.

### 3. Synchronize a micro-batch

- Prepare identical or complementary requests with fresh valid state.
- Release 2 requests simultaneously using a barrier or last-byte synchronization where needed.
- Record per-request connection, timestamp, response, and server transaction ID.

### 4. Increase minimally

- If two requests are inconclusive, repeat with controls or increase to 3–5 only within the approved cap.
- Vary idempotency key reuse, omission, identity, endpoint, and retry path one at a time.
- Do not increase rate to compensate for poor synchronization.

### 5. Verify authoritative state

- Inspect final balance, count, status, ownership, job results, messages, and audit records.
- Distinguish duplicate responses from duplicate committed effects.
- Wait for eventual consistency before concluding.

### 6. Test TOCTOU and stale state

- Where safe, change authorization/membership/object version between check and use using controlled actors.
- Test queued/background operations after role removal or object change.
- Confirm worker revalidates current authority and state.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `duplicate-execution` — Duplicate execution. Select only when the matching trigger and evidence preconditions are present.
- `limit-overrun` — Limit overrun. Select only when the matching trigger and evidence preconditions are present.
- `one-time-token-race` — One time token race. Select only when the matching trigger and evidence preconditions are present.
- `idempotency-key-reuse` — Idempotency key reuse. Select only when the matching trigger and evidence preconditions are present.
- `TOCTOU-state-change` — Toctou state change. Select only when the matching trigger and evidence preconditions are present.
- `object-creation-race` — Object creation race. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| One-time redemption | Check-and-update is atomic | 2 synchronized controlled requests | Benefit applied more than once |
| Object creation | Duplicate requests are idempotent/unique | Same request/key concurrently | Multiple committed objects |
| Versioned update | Stale writes are rejected | Two updates with same version | Both commit unexpectedly |
| Queued action | Worker revalidates current state | Queue then revoke test permission | Action executes with stale authority |
| Idempotency key | Key is required and correctly scoped | Reuse/omit across controlled requests | Duplicate or cross-operation effect |

## Tool strategy

- Use small custom async scripts, Burp Turbo Intruder/race tooling, or last-byte synchronization with strict caps.
- Capture authoritative state through API/UI/logs, not responses alone.
- Use sandbox payment/messaging systems and deterministic cleanup.
- Do not run generic concurrency fuzzing across all endpoints.

## Evidence required for a finding

- Expected invariant, sequential control, exact synchronized request set, timestamps, transaction IDs, and final authoritative state.
- Repeatability across reset synthetic state.
- Clear distinction between duplicate response and duplicate committed effect.
- Concurrency and request count used.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/race-condition-concurrency-and-idempotency-testing.schema.json`.

**Skill-specific evidence fields**

- `invariant`
- `sequential_control`
- `batch_size`
- `synchronization_method`
- `individual_responses`
- `duplicate_effects`
- `authoritative_final_state`

**Required validation controls**

- `start_with_two_requests`
- `sequential_control_first`
- `authoritative_final_state`
- `stop_at_first_repeatable_violation`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- Eventual consistency and delayed UI updates can look inconsistent.
- Multiple 2xx responses may map to one idempotent commit.
- Sandbox providers can behave differently from the application.
- Clock timestamps alone may not prove overlap; use synchronization evidence.

## Stop conditions

- An invariant violation is confirmed.
- The test reaches real money, inventory, messages, users, or shared objects.
- Concurrency/latency/errors approach service-health limits.
- Synthetic state cannot be reset or authoritative outcome cannot be measured.

## Common remediation patterns

- Enforce invariants in atomic database transactions with locking or compare-and-swap/version checks.
- Require properly scoped idempotency keys and store completed outcomes.
- Use unique constraints and transactional outbox patterns for side effects.
- Revalidate authorization and state in background workers at execution time.
- Add deterministic concurrent regression tests for each affected flow.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/race-condition-concurrency-and-idempotency-testing.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.race-condition-concurrency-and-idempotency-testing
supporting_skills: []
selected_techniques: [duplicate-execution]
hypothesis_id: HYP-example-001
risk: high
policy_revision: POL-example-r1
approval_refs: []
budget: <copy or reduce the manifest budget>
actions: <typed actions only>
validation:
  positive_conditions: [<skill-specific condition>]
  negative_controls: [<control>]
  confirmation_runs: 1
  authoritative_state_required: false
  evidence_extension_schema: schemas/evidence-extensions/race-condition-concurrency-and-idempotency-testing.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 10 for the underlying business invariant.
- Skill 25 for rate/resource controls without concurrency races.
- Skill 30 for stable regression harnesses and impact ranking.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
workflow: synthetic_coupon_redemption
concurrency: 2
max_concurrency: 5
authoritative_state: account_credit_api
```

## Authoritative references

- [PortSwigger — Race conditions](https://portswigger.net/web-security/race-conditions)
- [OWASP WSTG — Business Logic](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/)
- [RFC 9110 — Idempotent Methods](https://www.rfc-editor.org/rfc/rfc9110)

---

## ShakerScan runtime notes

**Support: partial.** ShakerScan has no capability for `http.concurrent_batch`, so this skill cannot be bound to a hunt yet. It is published so the gap is visible rather than discovered mid-run.

Bindable capabilities: `http.request`, `candidate.verify`. Optional when the hunt already holds them: `browser.navigate`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
