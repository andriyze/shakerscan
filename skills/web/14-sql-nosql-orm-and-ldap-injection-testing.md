---
id: skill.web.sql-nosql-orm-and-ldap-injection-testing
name: sql-nosql-orm-and-ldap-injection-testing
title: 14. SQL, NoSQL, ORM, and LDAP Injection Testing
description: Detect and safely validate query-language injection across SQL, NoSQL, ORM, search, LDAP,
  and structured-filter contexts using baseline-driven canaries.
version: 2.1.0
kind: specialist
phase: active_testing
risk: medium_to_high
support: supported
target_kinds:
- web
- api
capabilities:
- http.request
- sqli.verify
optional_capabilities:
- templates.scan
missing_capabilities: []
deferred_techniques:
- technique: NoSQL, ORM-specific operator, and LDAP mutation
  requires: planner-visible typed query-language mutation capability
- technique: Out-of-band confirmation
  requires: target-bound OOB allocation and observation capabilities
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 1000
  max_duration_seconds: 1200
routing:
  triggers:
  - sql_injection
  - sqli
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

# Query-language injection testing

Use stable controls to distinguish interpreter behavior from normal search semantics, WAF blocks,
generic errors, and latency noise. Only the bounded SQL subset is executable through this skill;
NoSQL/ORM-specific operator mutation, LDAP, and OOB confirmation remain deferred where no
planner-visible typed capability supports them.

## Supported SQL workflow

1. Query existing endpoints, candidates, and findings. Establish a stable baseline with
   `http.request` and identify the exact query parameter and concrete route from evidence.
2. Confirm active testing is already authorized and `sqli.verify` appears in the run manifest.
   Inspect its live schema and request/wall-time reservation. Skill budget values are guidance;
   they cannot lower or enlarge the runtime's executable reservation.
3. Invoke `sqli.verify` for that target-bound path. Supply only supported semantic inputs.
   Never request table dumps, filesystem access, stacked destructive statements, shell execution,
   or an unscoped URL. Use managed principal bindings only as supported by the returned schema.
4. Compare the returned observations with baseline/control evidence. Syntax errors, a DBMS guess,
   response-length changes, and one delayed response are not automatically proof of injection.
5. Preserve server receipts, exact locus, controls, and returned proof state. Report verified only
   when a server-owned deterministic contract explicitly returns that verdict. Otherwise retain
   an evidence-backed candidate and name the missing proof.

The generic `candidate.verify` bridge is not a SQL verifier. Do not route an SQL candidate there
merely because that capability exists. `sqli.request_verify` and batch capabilities are internal
worker operations, not planner-callable tools.

## Deferred techniques

Do not invent `oob.allocate`, `oob.observe`, `http.differential_replay`, or upstream schema paths.
Record NoSQL/ORM operator shapes and LDAP filter clues as leads. Execute those techniques only
when a future live manifest provides the required typed capability and the operator has granted
its authority. A missing optional technique must not prevent the supported SQL investigation.

For timing signals, require interleaved controls and repeatability; stop when confirmation would
require resource stress or extracting real data. Normal search/filter behavior is not sufficient
to establish query-structure escape.

## Skill use and handoff

Read the HTTP-baselining prerequisite when using it. Bind this methodology only when its required
capabilities are already permitted; record `used` or `completed` with the actual same-Hunt action ID.
Report the unresolved interpreter/context, smallest next useful test, and coverage limitations.
