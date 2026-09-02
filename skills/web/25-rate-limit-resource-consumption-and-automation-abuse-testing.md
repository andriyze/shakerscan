---
id: skill.web.rate-limit-resource-consumption-and-automation-abuse-testing
name: rate-limit-resource-consumption-and-automation-abuse-testing
title: 25. Rate Limit, Resource Consumption, and Automation Abuse Testing
description: Test authentication, expensive APIs, uploads, searches, GraphQL, messages, OTPs, exports,
  and sensitive business flows for bounded rate, cost, quota, and automation controls.
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
optional_capabilities: []
missing_capabilities:
- http.concurrent_batch
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 240
  max_duration_seconds: 1200
  max_state_changing_requests: 20
routing:
  triggers:
  - login_or_OTP
  - expensive_search
  - GraphQL_cost
  - upload_or_conversion
  - message_send
  - export_or_report
  - automation_sensitive_flow
  indicators:
  - missing_limit
  - wrong_limiter_key
  - inconsistent_channel
  - cost_amplification
  - queue_growth
  - provider_side_effect
  exclusions:
  - stress_test
  - DoS
  - distributed_proxy_rotation
  - credential_stuffing
  - real_recipient_or_provider
preconditions:
- compiled_scope_policy
- owner_defined_step_cap
- runtime_health_monitoring
- synthetic_recipients_or_state
techniques:
- bounded-step-rate-test
- limiter-key-consistency
- cross-channel-limit-consistency
- cost-amplification
- OTP-or-message-abuse-test
- expensive-query-budget
promotion_gate: core.evidence-validation:confirmed
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
server_satisfied_prerequisites: []
source: web-security-agent-skills v2.0.0 25-rate-limit-resource-consumption-and-automation-abuse-testing.md
---

# 25. Rate Limit, Resource Consumption, and Automation Abuse Testing

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Determine whether an attacker can cheaply cause disproportionate compute, storage, bandwidth, provider cost, notifications, object growth, or business abuse. Measure controls with small stepped experiments—never denial of service.

## Use this skill when

- Endpoints perform expensive queries, report generation, file conversion, AI inference, search, export, messaging, OTP, signup, reservation, scraping, or bulk operations.
- APIs expose pagination, batch size, GraphQL complexity, uploads, or cost-bearing third-party calls.
- Business flows have value even when each request is technically valid.
- The owner wants to verify throttling, quotas, and abuse-monitoring behavior.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `login_or_OTP`
- `expensive_search`
- `GraphQL_cost`
- `upload_or_conversion`
- `message_send`
- `export_or_report`
- `automation_sensitive_flow`

**Useful indicators**

- `missing_limit`
- `wrong_limiter_key`
- `inconsistent_channel`
- `cost_amplification`
- `queue_growth`
- `provider_side_effect`

**Hard exclusions**

- `stress_test`
- `DoS`
- `distributed_proxy_rotation`
- `credential_stuffing`
- `real_recipient_or_provider`

**Required preconditions**

- `compiled_scope_policy`
- `owner_defined_step_cap`
- `runtime_health_monitoring`
- `synthetic_recipients_or_state`

**Preferred preconditions**

- `resource_metrics`
- `queue_metrics`
- `limiter_observability`

## Required context

- Explicit request/concurrency/cost/storage/message ceilings and service-health monitoring.
- Controlled accounts, IPs/devices where authorized, test providers/channels, and synthetic data.
- Expected limits by user, tenant, token, IP, device, endpoint, operation, and billing unit.
- Authoritative usage/quota/cost counters.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `http.request`
- `http.concurrent_batch`
- `state.verify`

**Optional adapters**

- `graphql.execute`
- `file.upload`
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
| `max_requests` | 240 |
| `max_duration_seconds` | 1200 |
| `max_concurrency` | 10 |
| `max_state_changes` | 20 |
| `max_auth_attempts` | 20 |
| `max_messages` | 15 |
| `max_oob_interactions` | 0 |
| `max_uploaded_bytes` | 5242880 |
| `max_cost_units` | 250 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `resilience_step_increase` | next step exceeds normal-use envelope or owner-defined resource threshold | `human_approval` |

**State access**

- Reads: `compiled_policy`, `resource_cost_model`, `runtime_health`, `request_corpus`, `identities`, `provider_test_channels`
- Writes: `step_test_records`, `limiter_key_observations`, `resource_metrics`, `circuit_breaker_events`, `evidence_records`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- Limits are absent, too high, keyed to one easily changed identifier, or inconsistent across equivalent endpoints.
- A single request permits excessive page size, batch, depth, upload, response, processing time, or downstream cost.
- OTP/email/SMS/webhook/AI/provider actions can be triggered repeatedly against a controlled target.
- Sensitive business flows can be automated without appropriate quotas or anomaly controls.
- Failure/retry paths multiply jobs, storage, charges, or notifications.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- This skill is bounded resilience testing, not DoS, stress testing, credential stuffing, or distributed bypass.
- Start at normal use, increase slowly, and stop at the first clear control boundary or health anomaly.
- Use test providers/channels and synthetic recipients only.
- Do not rotate real proxies/IPs or accounts to simulate botnets unless a separate controlled exercise explicitly permits it.

## Agent workflow

### 1. Model resource and abuse cost

- Identify CPU, memory, database, search, storage, bandwidth, queue, third-party charge, message, and business-value dimensions.
- Map user-controlled multipliers: page size, batch count, depth, file size, retries, destinations, model parameters, and concurrency.
- Write expected per-request and cumulative limits.

### 2. Establish normal controls

- Measure baseline latency, response size, cost units, queue time, and authoritative quota counters at normal use.
- Identify headers, errors, retry guidance, and reset windows.
- Confirm the test account starts with known quota.

### 3. Run bounded step tests

- Increase one dimension in small steps: request rate, page size, batch count, upload size, query cost, or repeated action.
- Keep concurrency low unless specifically testing concurrent enforcement.
- Stop when throttled, quota is reached, or health changes.

### 4. Test keying and consistency

- Compare controlled user, token, session, device, tenant, endpoint, method, version, and content-type variants one at a time.
- Use only approved controlled source IPs.
- Check whether success/failure and retries consume or reset quota correctly.

### 5. Test sensitive-flow automation

- Perform a tiny sequence of synthetic signup, reservation, redemption, message, export, or scrape actions.
- Measure business limit and friction independently from raw request throttling.
- Do not create real scarcity, messages, or market effects.

### 6. Test cost amplification and failure paths

- Compare small input to resulting response/work/storage/provider calls.
- Trigger a controlled timeout/cancel/retry path if safe and observe duplicate jobs/cost.
- Record amplification without pushing the system toward exhaustion.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `bounded-step-rate-test` — Bounded step rate test. Select only when the matching trigger and evidence preconditions are present.
- `limiter-key-consistency` — Limiter key consistency. Select only when the matching trigger and evidence preconditions are present.
- `cross-channel-limit-consistency` — Cross channel limit consistency. Select only when the matching trigger and evidence preconditions are present.
- `cost-amplification` — Cost amplification. Select only when the matching trigger and evidence preconditions are present.
- `OTP-or-message-abuse-test` — Otp or message abuse test. Select only when the matching trigger and evidence preconditions are present.
- `expensive-query-budget` — Expensive query budget. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| Request rate | Per-principal/tenant limits exist | Small stepped sequence | No throttle/quota within approved bound |
| Page/batch size | Single-request multipliers are bounded | Increase one size field | Disproportionate response/work accepted |
| OTP/message | Provider actions are tightly limited | Repeat to controlled recipient | Excess sends accepted |
| Expensive query/AI | Cost is budgeted and capped | Increase one complexity parameter | Unbounded cost/latency accepted |
| Retry/failure | Retries do not duplicate work/cost | Controlled cancel/timeout then retry | Multiple jobs/charges/messages |

## Tool strategy

- Use a rate-aware custom client, authoritative quota/cost telemetry, and service-health dashboards.
- Use `vegeta`/`k6`-style tools only with tiny explicit profiles; generic load tests are outside this skill.
- For GraphQL, integrate cost/depth metrics; for uploads, track storage and worker queues.
- Record every request and stop decision.

## Evidence required for a finding

- Expected policy, baseline, exact bounded step sequence, identity/keying dimensions, and authoritative quota/cost/health metrics.
- Demonstrated amplification or bypass within the approved budget.
- No claim of availability impact unless separately tested and observed.
- Cleanup of synthetic objects/messages/jobs.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/rate-limit-resource-consumption-and-automation-abuse-testing.schema.json`.

**Skill-specific evidence fields**

- `protected_operation`
- `limiter_key_hypothesis`
- `window_or_quota`
- `step_levels`
- `responses`
- `resource_metrics`
- `provider_or_business_side_effects`

**Required validation controls**

- `normal_use_baseline`
- `slow_step_increase`
- `health_circuit_breaker`
- `no_distributed_bypass`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- A high documented limit may be a product choice; severity depends on cost and abuse impact.
- Client-side counters are not enforcement.
- Different IP behavior may be CDN/WAF rather than application policy.
- Temporary 429/503 responses may not prove persistent or correctly keyed controls.

## Stop conditions

- Health, latency, errors, queue depth, or cost counters move beyond approved thresholds.
- A throttle/quota boundary is clearly observed.
- Testing would require distributed sources, many accounts, real recipients, or material provider cost.
- Cleanup cannot keep pace with generated state.

## Common remediation patterns

- Apply layered limits by authenticated principal, tenant, token, device, IP, operation, and business object as appropriate.
- Bound page/batch/depth/response/file/model parameters and enforce server-side cost budgets.
- Use queues, timeouts, cancellation, quotas, idempotency, and backpressure.
- Protect OTP/message/provider calls with strict recipient and account limits plus abuse detection.
- Monitor cost and business abuse signals, not just raw requests.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/rate-limit-resource-consumption-and-automation-abuse-testing.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.rate-limit-resource-consumption-and-automation-abuse-testing
supporting_skills: []
selected_techniques: [bounded-step-rate-test]
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
  evidence_extension_schema: schemas/evidence-extensions/rate-limit-resource-consumption-and-automation-abuse-testing.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 10 for sensitive business-flow logic.
- Skill 12 for GraphQL complexity and Skill 20 for file-processing cost.
- Skill 24 for concurrency/idempotency races.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
endpoint: https://api.example.test/reports
dimensions: [requests_per_minute, page_size, job_count]
max_requests: 60
health_abort: p95_plus_20_percent_or_5xx_spike
```

## Authoritative references

- [OWASP API Security — Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- [OWASP API Security — Sensitive Business Flows](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)

---

## ShakerScan runtime notes

**Support: partial.** ShakerScan has no capability for `http.concurrent_batch`, so this skill cannot be bound to a hunt yet. It is published so the gap is visible rather than discovered mid-run.

Bindable capabilities: `http.request`, `candidate.verify`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
