---
id: skill.web.http-baselining-replay-and-differential-analysis
name: http-baselining-replay-and-differential-analysis
title: 05. HTTP Baselining, Replay, and Differential Analysis
description: Turn captured traffic into stable controls and compare mutations across identities, states,
  parsers, protocols, and time without mistaking noise for vulnerabilities.
version: 2.0.0
kind: methodology
phase: modeling
risk: low
support: supported
target_kinds:
- web
- api
capabilities:
- http.request
- authz.verify
- browser.navigate
- candidate.verify
optional_capabilities: []
missing_capabilities: []
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 120
  max_duration_seconds: 600
  max_state_changing_requests: 4
routing:
  triggers:
  - captured_request
  - mutation_test
  - unstable_response
  - timing_signal
  - cross_identity_comparison
  - scanner_alert_validation
  indicators:
  - stable_control
  - response_variance
  - semantic_difference
  - authoritative_state_change
  exclusions:
  - stale_or_expired_baseline
  - unreproducible_session_state
preconditions:
- compiled_scope_policy
- captured_request_or_transaction
techniques:
- transaction-modeling
- baseline-stabilization
- variance-normalization
- one-variable-experiment
- semantic-differential
- authoritative-state-verification
promotion_gate: core.evidence-validation:confirmed
requires_skills: []
server_satisfied_prerequisites:
- skill.web.scope-authorization-and-agent-safety
source: web-security-agent-skills v2.0.0 05-http-baselining-replay-and-differential-analysis.md
---

# 05. HTTP Baselining, Replay, and Differential Analysis

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Provide the experimental method behind reliable DAST. Reproduce the normal transaction, isolate one variable, quantify meaningful differences, and verify authoritative side effects before escalating a hypothesis.

## Use this skill when

- Before parameter mutation, authorization testing, injection probes, cache tests, or timing-based conclusions.
- Captured requests contain volatile tokens, signatures, dynamic JSON, redirects, or asynchronous processing.
- A scanner reported an anomaly that needs independent validation.
- The same endpoint behaves differently across roles, content types, methods, versions, or protocol paths.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `captured_request`
- `mutation_test`
- `unstable_response`
- `timing_signal`
- `cross_identity_comparison`
- `scanner_alert_validation`

**Useful indicators**

- `stable_control`
- `response_variance`
- `semantic_difference`
- `authoritative_state_change`

**Hard exclusions**

- `stale_or_expired_baseline`
- `unreproducible_session_state`

**Required preconditions**

- `compiled_scope_policy`
- `captured_request_or_transaction`

**Preferred preconditions**

- `authoritative_state_verifier`
- `multiple_control_samples`

## Required context

- Raw request/response, browser state, identity, UI action, timestamp, and expected business result.
- Known volatile fields, token refresh steps, signatures, nonces, idempotency behavior, and replay safety.
- Comparison tolerances for status, selected headers, normalized body, JSON schema, timing, and state.
- An authoritative way to verify side effects.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `http.request`
- `http.differential_replay`
- `browser.observe`
- `state.verify`

**Optional adapters**

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
| `max_requests` | 120 |
| `max_duration_seconds` | 600 |
| `max_concurrency` | 2 |
| `max_state_changes` | 4 |
| `max_auth_attempts` | 0 |
| `max_messages` | 0 |
| `max_oob_interactions` | 0 |
| `max_uploaded_bytes` | 0 |
| `max_cost_units` | 120 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| None beyond core policy | — | — |

**State access**

- Reads: `compiled_policy`, `request_corpus`, `browser_sessions`, `identities`, `objects`
- Writes: `baseline_profiles`, `differential_results`, `observations`, `evidence_records`
- Cannot write: `confirmed_findings`

## Core security hypotheses

- A request can be replayed with fresh state and a stable control result.
- A single changed input causes a repeatable semantic, authorization, parser, cache, or timing difference.
- An automated alert survives independent reproduction.
- The immediate HTTP response accurately reflects the authoritative state—or a discrepancy itself is security-relevant.
- Dynamic noise can be normalized without hiding meaningful security differences.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- Never compare a mutation to a stale, expired, unauthenticated, or different-state baseline.
- Refresh anti-CSRF tokens, signatures, timestamps, nonces, and one-time values through the legitimate flow.
- Use multiple interleaved controls for timing or unstable systems.
- Preserve originals; normalization is an analysis layer, not evidence deletion.

## Agent workflow

### 1. Understand the transaction

- Associate the request with user action, preconditions, identity, object, expected state, redirects, polling, and downstream effects.
- Identify cookies, CSRF tokens, bearer tokens, signatures, origins, idempotency keys, and prerequisite requests.
- Classify replay as read-only, reversible, one-time, expensive, or prohibited.

### 2. Create a stable baseline

- Replay the unmodified request with fresh state until the response and side effect are stable.
- Capture several controls for timing, asynchronous processing, load balancing, or dynamic content.
- Record canonical raw HTTP and an independent reproduction command or script.

### 3. Normalize expected variance

- Mask timestamps, request IDs, rotating tokens, analytics, random ordering, and documented dynamic fields.
- Calculate structural fingerprints: status, redirects, selected headers, normalized hash, JSON keys/types, semantic text, and timing distribution.
- Retain security-relevant differences such as Set-Cookie, CORS, cache headers, authorization messages, and object ownership.

### 4. Run one-variable experiments

- Change one parameter, header, identity, method, content type, sequence step, or protocol property at a time.
- Use positive and negative controls with known expected outcomes.
- Repeat unexpected results to rule out WAF challenges, backend instability, token expiry, and race effects.

### 5. Verify authoritative state

- Check database-visible state through approved UI/API, audit logs, object version, balance, file, or message outcome.
- Do not assume a 2xx means success or an error means no side effect.
- Capture delayed jobs and eventual consistency before concluding.

### 6. Interpret and hand off

- Classify the difference as syntactic rejection, validation, authorization, alternate handler, parser discrepancy, cache behavior, resource effect, or confirmed boundary failure.
- Escalate to a specialized skill only when the differential supports a concrete hypothesis.
- Store reusable baselines and control fingerprints for regression.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `transaction-modeling` — Transaction modeling. Select only when the matching trigger and evidence preconditions are present.
- `baseline-stabilization` — Baseline stabilization. Select only when the matching trigger and evidence preconditions are present.
- `variance-normalization` — Variance normalization. Select only when the matching trigger and evidence preconditions are present.
- `one-variable-experiment` — One variable experiment. Select only when the matching trigger and evidence preconditions are present.
- `semantic-differential` — Semantic differential. Select only when the matching trigger and evidence preconditions are present.
- `authoritative-state-verification` — Authoritative state verification. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| Identity | Authorization depends on principal | Replay identical request as isolated users | Outcome follows or violates expected policy |
| Parameter | Field influences server logic | Change one value | Stable semantic/state difference |
| Method/content type | Handlers disagree | Use one approved alternate | Different validation/authorization path |
| Timing | Input causes deterministic extra work | Interleave controls and probes | Statistically separated timing |
| Scanner alert | Automated result is real | Manual minimal reproduction | Repeatable security impact independent of label |

## Tool strategy

- Use raw HTTP clients, Burp/ZAP/mitmproxy replayers, or scripts that preserve connection and browser behavior when relevant.
- Use structural JSON/HTML diffing and robust timing statistics rather than body length alone.
- Store normalized fingerprints next to original evidence.
- Use browser traces when redirects, service workers, client state, or asynchronous requests matter.

## Evidence required for a finding

- At least one stable baseline and one probe differing only in the intended variable.
- Identity, state preconditions, token freshness, normalization rules, and authoritative state verification.
- Repeated interleaved observations for timing, cache, load-balanced, or asynchronous behavior.
- A concise causal statement linking the changed variable to the demonstrated security property.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/http-baselining-replay-and-differential-analysis.schema.json`.

**Skill-specific evidence fields**

- `baseline_sample_ids`
- `normalization_profile`
- `mutation`
- `semantic_diff`
- `timing_samples`
- `authoritative_state`

**Required validation controls**

- `interleaved_controls`
- `minimum_two_confirmations_for_unstable_signal`
- `preserve_raw_artifacts`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- Expired sessions, CSRF failures, WAF challenges, A/B tests, localization, ads, request IDs, and backend load create misleading differences.
- Different status or body length may represent the same security outcome.
- A 200 can contain an authorization failure, while a 403 may occur after a side effect.
- Uncontrolled timing outliers are not evidence.

## Stop conditions

- The baseline cannot be reproduced safely or the action is prohibited/one-time.
- Control variance is too large to support a conclusion.
- The mutation causes unexpected messages, charges, lockout, service degradation, or cross-user effects.
- Fresh state cannot be obtained without leaving scope.

## Common remediation patterns

- Make security decisions consistent across methods, content types, versions, and protocol paths.
- Return explicit, uniform, side-effect-free errors.
- Use idempotency and transactional boundaries for state-changing operations.
- Remove volatile data from security decisions unless it is cryptographically bound and validated.
- Create regression tests that replay the exact vulnerable and control transactions.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/http-baselining-replay-and-differential-analysis.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.http-baselining-replay-and-differential-analysis
supporting_skills: []
selected_techniques: [transaction-modeling]
hypothesis_id: HYP-example-001
risk: low
policy_revision: POL-example-r1
approval_refs: []
budget: <copy or reduce the manifest budget>
actions: <typed actions only>
validation:
  positive_conditions: [<skill-specific condition>]
  negative_controls: [<control>]
  confirmation_runs: 1
  authoritative_state_required: false
  evidence_extension_schema: schemas/evidence-extensions/http-baselining-replay-and-differential-analysis.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Every active vulnerability skill should inherit the baseline and comparison produced here.
- Skill 30 converts validated differentials into deduplicated findings and regression artifacts.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
request_id: captured-req-184
identity: user_a
mutation: "replace object_id only"
control_samples: 3
```

## Authoritative references

- [OWASP WSTG — Testing Framework](https://owasp.org/www-project-web-security-testing-guide/stable/3-The_OWASP_Testing_Framework/)
- [PortSwigger — Essential skills](https://portswigger.net/web-security/essential-skills)
- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110)

---

## ShakerScan runtime notes

**Support: supported.** Every adapter this skill requires maps to a planner-visible capability, so it can be bound to a hunt.

Bindable capabilities: `http.request`, `authz.verify`, `browser.navigate`, `candidate.verify`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
