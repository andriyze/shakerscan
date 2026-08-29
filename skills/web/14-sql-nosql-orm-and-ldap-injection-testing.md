---
id: skill.web.sql-nosql-orm-and-ldap-injection-testing
name: sql-nosql-orm-and-ldap-injection-testing
title: 14. SQL, NoSQL, ORM, and LDAP Injection Testing
description: Detect and safely validate query-language injection across SQL, NoSQL, ORM, search, LDAP,
  and structured-filter contexts using baseline-driven canaries.
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
optional_capabilities:
- templates.scan
- candidate.verify
missing_capabilities:
- oob.allocate
- oob.observe
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 220
  max_duration_seconds: 1200
  max_oob_interactions: 6
routing:
  triggers:
  - database_backed_parameter
  - filter_or_search
  - sort_or_query_expression
  - NoSQL_operator_shape
  - ORM_selector
  - LDAP_filter
  indicators:
  - syntax_error
  - boolean_differential
  - time_differential
  - OOB_callback
  - query_shape_change
  exclusions:
  - data_extraction
  - stacked_destructive_query
  - file_write_or_shell_escape
preconditions:
- compiled_scope_policy
- stable_baseline_request
- identified_parameter
techniques:
- sql-boolean-differential
- sql-error-based-minimal
- sql-time-based-interleaved
- nosql-operator-injection
- orm-filter-injection
- ldap-filter-injection
promotion_gate: core.evidence-validation:confirmed
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
server_satisfied_prerequisites: []
source: web-security-agent-skills v2.0.0 14-sql-nosql-orm-and-ldap-injection-testing.md
---

# 14. SQL, NoSQL, ORM, and LDAP Injection Testing

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Determine whether untrusted input changes the structure or semantics of a backend query. Confirm with minimal independent signals while avoiding data dumping, destructive statements, or uncontrolled time/resource effects.

## Use this skill when

- Inputs affect search, filters, sorting, login, identifiers, reports, exports, JSON query objects, directory lookup, or database-backed business logic.
- Errors, timing, boolean behavior, or technology clues suggest a query interpreter.
- API schemas accept nested objects, arrays, operators, or dynamic field names.
- A scanner reports injection that requires manual validation.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `database_backed_parameter`
- `filter_or_search`
- `sort_or_query_expression`
- `NoSQL_operator_shape`
- `ORM_selector`
- `LDAP_filter`

**Useful indicators**

- `syntax_error`
- `boolean_differential`
- `time_differential`
- `OOB_callback`
- `query_shape_change`

**Hard exclusions**

- `data_extraction`
- `stacked_destructive_query`
- `file_write_or_shell_escape`

**Required preconditions**

- `compiled_scope_policy`
- `stable_baseline_request`
- `identified_parameter`

**Preferred preconditions**

- `database_family_hint`
- `interleaved_timing_controls`
- `controlled_OOB`

## Required context

- Stable baseline requests from Skill 05.
- Parameter locations, observed types, expected result sets, and safe synthetic records.
- Allowed probe classes: syntax, boolean, error, time, and controlled OOB.
- Maximum delay, request count, and prohibition on data extraction/modification.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `http.request`
- `http.differential_replay`
- `oob.allocate`
- `oob.observe`

**Optional adapters**

- `scanner.run`
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
| `max_requests` | 220 |
| `max_duration_seconds` | 1200 |
| `max_concurrency` | 2 |
| `max_state_changes` | 0 |
| `max_auth_attempts` | 0 |
| `max_messages` | 0 |
| `max_oob_interactions` | 6 |
| `max_uploaded_bytes` | 0 |
| `max_cost_units` | 220 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `automated_injection_tool` | sqlmap or equivalent exploitation engine is requested | `human_approval` |
| `time_probe_above_cap` | delay exceeds the configured minimal delay | `block` |

**State access**

- Reads: `compiled_policy`, `request_corpus`, `baseline_profiles`, `parameter_inventory`, `technology_hints`
- Writes: `injection_hypotheses`, `differential_results`, `OOB_events`, `evidence_records`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- A scalar input alters query syntax or predicate semantics.
- Nested JSON/operator objects bypass intended scalar validation.
- ORM/query-builder abstractions allow unsafe dynamic fields, ordering, or raw fragments.
- Authentication or authorization queries can be changed without valid credentials.
- Blind injection produces deterministic boolean, timing, or controlled OOB evidence.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- Do not dump tables, credentials, directory contents, or unrelated records.
- Do not use stacked destructive queries, file writes, shell escapes, or database administration functions.
- Time probes must use the smallest delay and interleaved controls.
- Use automated exploitation tools only after a manual hypothesis exists and configure them for non-extractive confirmation.

## Agent workflow

### 1. Identify interpreter and context

- Classify parameter type and likely backend: SQL dialect, NoSQL/document query, ORM, search DSL, LDAP filter, or unknown.
- Determine whether input appears in value, identifier, order, field name, operator, list, regex, or nested object context.
- Capture normal valid/invalid controls.

### 2. Run syntax and error probes

- Introduce the smallest context-appropriate delimiter or type mismatch.
- Compare normalized errors, status, response schema, and server behavior.
- Do not treat generic 5xx or WAF blocks as confirmation.

### 3. Run boolean differentials

- Construct paired true/false expressions that preserve syntax and use only synthetic or existence-independent conditions.
- Interleave with baselines and repeat.
- Verify semantic differences in result count, authentication outcome, or selected synthetic record.

### 4. Test structured operator injection

- For JSON/NoSQL/ORM APIs, replace one scalar with an object/array/operator form where schema evidence supports it.
- Test duplicate keys, nested properties, dynamic sort/field names, and filter operators one at a time.
- Confirm server processing rather than client-side serialization artifacts.

### 5. Use blind confirmation only when needed

- Apply a very small bounded delay or controlled DNS/HTTP callback if explicitly authorized.
- Run interleaved controls and account for backend load.
- Stop once one independent signal confirms structural query control.

### 6. Assess impact minimally

- Demonstrate only a benign query consequence: selecting a controlled record, changing result truth, or bypassing authentication on a synthetic account.
- Do not escalate to extraction.
- Identify every affected parameter/handler through root-cause grouping rather than repeated exploitation.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `sql-boolean-differential` — Sql boolean differential. Select only when the matching trigger and evidence preconditions are present.
- `sql-error-based-minimal` — Sql error based minimal. Select only when the matching trigger and evidence preconditions are present.
- `sql-time-based-interleaved` — Sql time based interleaved. Select only when the matching trigger and evidence preconditions are present.
- `nosql-operator-injection` — Nosql operator injection. Select only when the matching trigger and evidence preconditions are present.
- `orm-filter-injection` — Orm filter injection. Select only when the matching trigger and evidence preconditions are present.
- `ldap-filter-injection` — Ldap filter injection. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| Scalar query value | Input changes predicate structure | Paired true/false expression | Repeatable semantic difference |
| JSON filter | Operator object bypasses scalar intent | Replace one controlled scalar with one operator object | Filter/auth behavior changes |
| Dynamic sort/field | Identifier is unsafely concatenated | Use invalid then context-specific harmless expression | Interpreter-controlled behavior |
| Blind timing | Query can invoke deterministic delay | Minimal delay with interleaved controls | Separated timing distribution |
| LDAP/search filter | Special characters alter filter | Balanced true/false filter canary | Controlled result-set difference |

## Tool strategy

- Use raw replay and custom paired probes first.
- `sqlmap` may confirm a known candidate with strict scope, low level/risk, no dump, no OS/file options, and request/time caps.
- Use JSON-aware mutation for NoSQL and ORM inputs.
- Log every payload class and control; avoid large generic payload lists.

## Evidence required for a finding

- Stable baseline, exact changed input, inferred context, and at least one repeatable control pair.
- Prefer two independent signals such as boolean plus error, or boolean plus minimal timing/OOB.
- Demonstrated consequence limited to controlled data or authentication state.
- WAF and backend variance ruled out.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/sql-nosql-orm-and-ldap-injection-testing.schema.json`.

**Skill-specific evidence fields**

- `language_family`
- `parameter_location`
- `baseline_artifacts`
- `probe_artifacts`
- `negative_control`
- `response_signal`
- `timing_samples`
- `OOB_event`

**Required validation controls**

- `manual_hypothesis_before_automation`
- `non_extractive_confirmation`
- `interleaved_timing_controls`
- `repeatable_semantic_difference`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- Generic errors, blocked punctuation, response-length changes, and noisy latency are insufficient.
- Search syntax intentionally exposed to users may not be injection; assess authorization and intended grammar.
- Different results can arise from normal filter semantics rather than query-structure escape.
- Client serialization may transform object probes before they reach the server.

## Stop conditions

- A probe causes long queries, locks, high CPU, elevated errors, or service degradation.
- Confirmation would require extracting real data or modifying database state.
- The endpoint is a third-party search/directory service outside scope.
- Automated tooling expands beyond the approved parameter or request budget.

## Common remediation patterns

- Use parameterized queries and safe query-builder APIs; never concatenate untrusted values into query structure.
- Allowlist identifiers, sort fields, operators, and search grammar.
- Validate JSON types and reject unexpected objects/arrays/operators.
- Use least-privileged database/directory accounts and safe error handling.
- Add regression tests for paired true/false and structured-operator cases.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/sql-nosql-orm-and-ldap-injection-testing.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.sql-nosql-orm-and-ldap-injection-testing
supporting_skills: []
selected_techniques: [sql-boolean-differential]
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
  evidence_extension_schema: schemas/evidence-extensions/sql-nosql-orm-and-ldap-injection-testing.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 15 if query injection exposes command, template, or unsafe object execution.
- Skill 29 if an LLM/tool API forwards natural-language input into database operations.
- Skill 30 for root-cause deduplication and regression.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
request_id: search-api-42
parameters: [q, filter.status, sort]
allowed_probes: [syntax, boolean, minimal_time]
max_delay_seconds: 2
```

## Authoritative references

- [OWASP WSTG — Input Validation Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger — SQL injection](https://portswigger.net/web-security/sql-injection)
- [PortSwigger — NoSQL injection](https://portswigger.net/web-security/nosql-injection)

---

## ShakerScan runtime notes

**Support: partial.** ShakerScan has no capability for `oob.allocate`, `oob.observe`, so this skill cannot be bound to a hunt yet. It is published so the gap is visible rather than discovered mid-run.

Bindable capabilities: `http.request`, `authz.verify`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
