---
id: skill.web.security-misconfiguration-error-handling-and-logging-testing
name: security-misconfiguration-error-handling-and-logging-testing
title: 28. Security Misconfiguration, Exceptional Conditions, Logging, and Alerting Testing
description: Test exposed configuration, debug/admin surfaces, headers, default content, error paths,
  fail-open behavior, logging quality, and security alert coverage using bounded canaries.
version: 2.0.0
kind: specialist
phase: active_testing
risk: medium_to_high
support: partial
target_kinds:
- web
- api
capabilities:
- http.request
- authz.verify
- browser.navigate
optional_capabilities:
- templates.scan
- tls.inspect
- candidate.verify
missing_capabilities:
- log.observe
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 500
  max_duration_seconds: 1200
  max_state_changing_requests: 5
routing:
  triggers:
  - debug_or_admin_surface
  - default_content
  - security_header_gap
  - exception_or_stack_trace
  - malformed_input
  - dependency_failure
  - logging_or_alerting_control
  indicators:
  - exposed_configuration
  - fail_open
  - sensitive_error
  - unsafe_default
  - missing_security_event
  - alert_gap
  exclusions:
  - intentional_service_crash
  - production_dependency_disable
  - resource_exhaustion
  - write_access_to_logs
preconditions:
- compiled_scope_policy
- bounded_test_case
techniques:
- debug-and-admin-exposure
- security-header-contextual-review
- bounded-malformed-input
- dependency-timeout-and-fail-open
- error-information-leakage
- logging-and-alert-canary
promotion_gate: core.evidence-validation:confirmed
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
server_satisfied_prerequisites: []
source: web-security-agent-skills v2.0.0 28-security-misconfiguration-error-handling-and-logging-testing.md
---

# 28. Security Misconfiguration, Exceptional Conditions, Logging, and Alerting Testing

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Find insecure defaults and security controls that fail under malformed input, dependency errors, timeouts, invalid state, or operational stress. Verify whether security-relevant events are logged and alerted without leaking secrets.

## Use this skill when

- The app exposes debug endpoints, admin consoles, metrics, docs, backups, default files, directory listings, verbose errors, or unsafe headers.
- Malformed requests or dependency failures produce inconsistent security behavior.
- The owner can provide test logs/SIEM visibility for controlled canary events.
- OWASP Top 10 2025 A02, A09, or A10 coverage is required.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `debug_or_admin_surface`
- `default_content`
- `security_header_gap`
- `exception_or_stack_trace`
- `malformed_input`
- `dependency_failure`
- `logging_or_alerting_control`

**Useful indicators**

- `exposed_configuration`
- `fail_open`
- `sensitive_error`
- `unsafe_default`
- `missing_security_event`
- `alert_gap`

**Hard exclusions**

- `intentional_service_crash`
- `production_dependency_disable`
- `resource_exhaustion`
- `write_access_to_logs`

**Required preconditions**

- `compiled_scope_policy`
- `bounded_test_case`

**Preferred preconditions**

- `read_only_observability`
- `owner_fault_simulator`
- `expected_logging_policy`

## Required context

- Approved origins/environments, configuration baseline, expected headers, debug/admin exposure policy, and log/alert requirements.
- Controlled malformed-input budget and optional fault-injection/test dependency endpoints.
- Test accounts and unique event markers.
- Read-only access to relevant logs/alerts where available.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `http.request`
- `http.differential_replay`
- `browser.observe`
- `log.observe`

**Optional adapters**

- `scanner.run`
- `tls.inspect`
- `state.verify`

**Prohibited capabilities**

- `unrestricted_shell`
- `unscoped_egress`
- `real_user_targeting`
- `persistence`
- `denial_of_service`

**Default budget**

| Counter | Maximum |
|---|---:|
| `max_requests` | 500 |
| `max_duration_seconds` | 1200 |
| `max_concurrency` | 5 |
| `max_state_changes` | 5 |
| `max_auth_attempts` | 0 |
| `max_messages` | 0 |
| `max_oob_interactions` | 0 |
| `max_uploaded_bytes` | 0 |
| `max_cost_units` | 210 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `fault_injection` | test requires disabling a dependency or intentionally crashing a component | `staging_owner_approval` |

**State access**

- Reads: `compiled_policy`, `asset_graph`, `endpoint_inventory`, `logging_policy`, `runtime_health`
- Writes: `configuration_observations`, `exception_records`, `log_and_alert_results`, `circuit_breaker_events`, `evidence_records`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- Debug, admin, metrics, documentation, backup, source-control, cloud, or default content is exposed.
- Security headers, cookie flags, CORS, cache, directory, method, or server configuration is unsafe.
- Malformed, null, duplicate, oversized-but-bounded, Unicode, timeout, or unavailable-dependency conditions cause fail-open behavior, data leakage, corruption, or bypass.
- Errors expose stack traces, paths, queries, secrets, internal hosts, or user data.
- Authentication, authorization, validation, fraud, and high-risk events are not logged/alerted—or logs contain secrets and are forgeable.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- Do not intentionally crash services, exhaust resources, or disable dependencies in production.
- Use bounded malformed inputs and owner-provided fault simulators/test dependencies.
- Log testing must use unique controlled events and read-only observability access.
- Do not report every missing header as a standalone vulnerability; connect configuration to the protected asset and threat.

## Agent workflow

### 1. Inventory configuration exposure

- Check approved common and technology-derived paths for debug/admin consoles, metrics, health, docs, backups, source-control remnants, manifests, directory listing, default pages, and environment/config files.
- Calibrate soft 404/default responses.
- Verify authentication, network restriction, data sensitivity, and environment.

### 2. Review HTTP and platform controls

- Inspect security headers, cookies, CORS, cache, MIME sniffing, framing, referrer policy, permissions policy, methods, TLS termination, compression, server banners, and cross-origin isolation where relevant.
- Check alternate hosts/ports and error responses.
- Prioritize controls tied to actual application behavior.

### 3. Test malformed and boundary conditions

- Change one property at a time: missing/duplicate headers, null/empty/wrong type, invalid state, Unicode, malformed JSON/XML, unsupported method/type, bounded large value, disconnect, or retry.
- Observe validation, authorization, transactions, error handling, and final state.
- Stop on elevated errors or health changes.

### 4. Test dependency and timeout behavior safely

- Use owner-controlled mock dependencies, fault flags, or staging to simulate timeout, malformed response, unavailable service, partial success, and duplicate callback.
- Verify fail-closed security decisions, transaction consistency, idempotency, and safe user errors.
- Do not disrupt real dependencies.

### 5. Inspect information leakage

- Review errors, headers, bodies, downloadable diagnostics, logs, tracing IDs, source maps, and generated support bundles.
- Use synthetic secrets/PII to trace leakage.
- Capture minimal fragments and redact.

### 6. Validate logging and alerting

- Generate unique canary events: failed/successful login, access-control denial, privilege change, invalid token, suspicious input, rate limit, admin action, and configuration change where safe.
- Verify who/what/when/where/result, correlation ID, tenant, source, and sufficient context without secrets.
- Confirm alert routing, deduplication, severity, and response ownership for approved high-risk events.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `debug-and-admin-exposure` — Debug and admin exposure. Select only when the matching trigger and evidence preconditions are present.
- `security-header-contextual-review` — Security header contextual review. Select only when the matching trigger and evidence preconditions are present.
- `bounded-malformed-input` — Bounded malformed input. Select only when the matching trigger and evidence preconditions are present.
- `dependency-timeout-and-fail-open` — Dependency timeout and fail open. Select only when the matching trigger and evidence preconditions are present.
- `error-information-leakage` — Error information leakage. Select only when the matching trigger and evidence preconditions are present.
- `logging-and-alert-canary` — Logging and alert canary. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| Debug/admin surface | Sensitive operational surface is restricted | One calibrated request | Unauthenticated/overbroad access |
| Malformed input | Application fails closed and consistently | One bounded invalid variant | Bypass, corruption, or sensitive error |
| Dependency timeout | Security decision remains safe | Controlled mock timeout in staging | Fail-open or partial unsafe state |
| Error response | No sensitive internals leak | Trigger controlled invalid request | Stack/path/query/secret/PII disclosed |
| Security event | Event is logged and alerted appropriately | Unique canary action | Missing, misleading, secret-bearing, or uncorrelated log/alert |

## Tool strategy

- Use raw HTTP/browser checks, technology-aware safe content discovery, configuration scanners, and owner-approved fault injection.
- Use log/SIEM queries with unique canary IDs; do not scrape unrelated events.
- Use structured malformed-input generators with strict size/request bounds.
- Correlate user-facing, edge, application, worker, database, and alerting evidence.

## Evidence required for a finding

- Exact endpoint/control, environment, baseline, one changed condition, response, authoritative state, and health status.
- For exposure, actual accessible sensitive capability/data—not path existence alone.
- For logging, canary event ID, expected record/alert, observed record, latency, and data minimization.
- For exceptional conditions, fail-open/bypass/corruption demonstrated under controlled fault.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/security-misconfiguration-error-handling-and-logging-testing.schema.json`.

**Skill-specific evidence fields**

- `component`
- `configuration_surface`
- `input_or_fault`
- `response_or_failure_mode`
- `sensitive_information`
- `log_event`
- `alert_result`
- `fail_open_effect`

**Required validation controls**

- `bounded_malformed_inputs`
- `owner_canary_event`
- `read_only_observability`
- `header_gap_requires_threat_context`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- Generic headers or version banners may be informational without an exploit path.
- A debug-looking route may be a static placeholder or authenticated redirect.
- A controlled 500 is not a vulnerability unless it leaks, bypasses, corrupts, or threatens availability.
- A missing alert may be intentional for low-risk noise; compare the documented detection policy.

## Stop conditions

- Error rates, latency, health, queues, or worker failures rise beyond the approved threshold.
- A test would disable a real dependency, crash a process, or alter production configuration.
- Sensitive real-user data appears; capture minimal proof and stop.
- Observability access begins exposing unrelated logs or tenants.

## Common remediation patterns

- Harden production configurations, remove default/debug content, restrict operational endpoints, and apply secure headers/cookies/cache.
- Validate inputs centrally and handle all exceptions with fail-closed security decisions and transactional consistency.
- Use safe generic user errors while retaining correlation IDs for internal diagnostics.
- Log security-relevant events with identity, tenant, source, action, result, and correlation—never secrets.
- Create actionable alerts, ownership, retention, integrity protection, and tested incident-response paths.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/security-misconfiguration-error-handling-and-logging-testing.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.security-misconfiguration-error-handling-and-logging-testing
supporting_skills: []
selected_techniques: [debug-and-admin-exposure]
hypothesis_id: HYP-example-001
risk: medium_to_high
policy_revision: POL-example-r1
approval_refs: []
budget: <copy or reduce the manifest budget>
actions: <typed actions only>
validation:
  positive_conditions: [<skill-specific condition>]
  negative_controls: [<control>]
  confirmation_runs: 1
  authoritative_state_required: false
  evidence_extension_schema: schemas/evidence-extensions/security-misconfiguration-error-handling-and-logging-testing.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 26 for cryptographic/data leakage and Skill 27 for artifact/config supply chain.
- Skills 22–25 for protocol, cache, race, and resource exceptional paths.
- Skill 30 for evidence normalization and regression.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
origin: https://app.example.test
malformed_budget: 40_requests
fault_injection: staging_mock_dependencies_only
log_canary_prefix: AISEC_LOG_42
```

## Authoritative references

- [OWASP Top 10 2025 — Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
- [OWASP Top 10 2025 — Security Logging and Alerting Failures](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/)
- [OWASP Top 10 2025 — Mishandling Exceptional Conditions](https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/)
- [OWASP WSTG — Error Handling](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/)

---

## ShakerScan runtime notes

**Support: partial.** ShakerScan has no capability for `log.observe`, so this skill cannot be bound to a hunt yet. It is published so the gap is visible rather than discovered mid-run.

Bindable capabilities: `http.request`, `authz.verify`, `browser.navigate`. Optional when the hunt already holds them: `templates.scan`, `tls.inspect`, `candidate.verify`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
