---
id: skill.web.command-ssti-expression-and-deserialization-testing
name: command-ssti-expression-and-deserialization-testing
title: 15. Command, SSTI, Expression, and Deserialization Testing
description: Safely identify OS command injection, server-side template/expression injection, and unsafe
  deserialization or object construction without destructive exploitation.
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
  max_http_requests: 120
  max_duration_seconds: 900
  max_oob_interactions: 5
routing:
  triggers:
  - command_like_parameter
  - template_rendering
  - expression_language
  - serialized_object
  - document_conversion
  - job_runner
  indicators:
  - arithmetic_evaluation
  - string_expression_evaluation
  - minimal_time_signal
  - controlled_OOB_callback
  - type_confusion_or_gadget_sink
  exclusions:
  - reverse_shell
  - file_read
  - persistence
  - production_gadget_chain
  - package_or_interpreter_invocation
preconditions:
- compiled_scope_policy
- stable_baseline_request
- candidate_interpreter_or_sink
techniques:
- SSTI-arithmetic-probe
- expression-language-string-probe
- command-injection-minimal-time
- command-injection-controlled-DNS
- deserialization-safe-type-probe
- job-runner-argument-boundary
promotion_gate: core.evidence-validation:confirmed
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
server_satisfied_prerequisites: []
source: web-security-agent-skills v2.0.0 15-command-ssti-expression-and-deserialization-testing.md
---

# 15. Command, SSTI, Expression, and Deserialization Testing

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Determine whether input reaches an execution-capable interpreter or unsafe object loader. Progress from harmless syntax/arithmetic evidence to a minimal controlled canary, then stop—no reverse shells, persistence, file reads, or destructive commands.

## Use this skill when

- Inputs affect system utilities, file conversion, diagnostics, build/deploy tasks, templates, notifications, reports, formulas, rules, serialized state, or opaque binary/base64 objects.
- Errors reveal shell, template engine, expression language, object type, gadget, or deserialization clues.
- An LLM/tool integration can call command-like backend functions.
- A scanner reports possible remote code execution.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `command_like_parameter`
- `template_rendering`
- `expression_language`
- `serialized_object`
- `document_conversion`
- `job_runner`

**Useful indicators**

- `arithmetic_evaluation`
- `string_expression_evaluation`
- `minimal_time_signal`
- `controlled_OOB_callback`
- `type_confusion_or_gadget_sink`

**Hard exclusions**

- `reverse_shell`
- `file_read`
- `persistence`
- `production_gadget_chain`
- `package_or_interpreter_invocation`

**Required preconditions**

- `compiled_scope_policy`
- `stable_baseline_request`
- `candidate_interpreter_or_sink`

**Preferred preconditions**

- `disposable_environment`
- `controlled_OOB`
- `technology_fingerprint`

## Required context

- Stable baseline, suspected interpreter/context, and a disposable test path where possible.
- Allowed probe classes: syntax, arithmetic/string evaluation, minimal command canary, and controlled OOB.
- Controlled callback domain and maximum delays.
- Explicit prohibition on reverse shells, persistence, secret/file reads, privilege changes, and destructive commands.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `http.request`
- `http.differential_replay`
- `oob.allocate`
- `oob.observe`

**Optional adapters**

- `artifact.inspect`
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
| `max_requests` | 120 |
| `max_duration_seconds` | 900 |
| `max_concurrency` | 1 |
| `max_state_changes` | 0 |
| `max_auth_attempts` | 0 |
| `max_messages` | 0 |
| `max_oob_interactions` | 5 |
| `max_uploaded_bytes` | 0 |
| `max_cost_units` | 160 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `OS_command_canary` | arithmetic/string proof is insufficient and an OS-level canary is proposed | `human_approval` |
| `deserialization_gadget_test` | gadget-chain execution is requested | `staging_human_approval` |

**State access**

- Reads: `compiled_policy`, `request_corpus`, `baseline_profiles`, `technology_hints`, `file_processing_graph`
- Writes: `interpreter_hypotheses`, `differential_results`, `OOB_events`, `evidence_records`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- Input breaks out of a shell argument or command context.
- Template/expression syntax is evaluated server-side rather than rendered literally.
- Serialized data allows attacker-selected types, properties, callbacks, or gadget behavior.
- Encoding, quoting, or alternate fields reach a less-protected execution path.
- Execution can be confirmed with a benign marker without accessing sensitive data.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- Begin with arithmetic or string-expression probes; use an OS command canary only when necessary and approved.
- Allowed command proof is limited to a harmless marker such as a short delay or controlled DNS lookup; never open a shell or read files.
- Do not generate or deploy gadget chains against production unless a disposable environment and explicit high-risk approval exist.
- Do not invoke package managers, interpreters, compilers, or remote URLs beyond controlled callbacks.

## Agent workflow

### 1. Identify execution context

- Determine whether input reaches a shell, direct process argument, template engine, expression evaluator, rule engine, serializer, or object mapper.
- Infer engine/dialect from errors, headers, dependencies, source, or controlled syntax differences.
- Map quoting, encoding, and data transformations.

### 2. Use non-executing syntax controls

- Send a literal marker and minimal delimiter/invalid syntax to observe parsing.
- Compare errors and rendering while ruling out reflection and client-side evaluation.
- Use engine-specific arithmetic/string expressions only after context evidence.

### 3. Confirm template/expression evaluation

- Use a harmless deterministic expression whose evaluated result differs from the input text.
- Test relevant contexts such as subject/body templates, filenames, formulas, or preview/render endpoints.
- Avoid object traversal, environment access, or engine internals beyond what is needed to identify evaluation.

### 4. Confirm command execution minimally

- Use a tiny bounded delay or controlled DNS/HTTP callback with a unique canary.
- Interleave controls to exclude normal latency and background callbacks.
- Stop immediately after proof; do not enumerate user, filesystem, network, or environment.

### 5. Assess deserialization safely

- Identify format, signing/encryption, type metadata, compression, and integrity checks.
- Mutate benign fields, type identifiers, or callbacks only in a disposable/test object.
- Prefer source/config review or a local replica for gadget reachability; production proof should be minimal OOB at most.

### 6. Find alternate paths and root cause

- Check equivalent endpoints, content types, job queues, file-processing stages, and admin/legacy variants with the same minimal canary.
- Group affected sinks by shared execution function.
- Record trust boundary and privilege without executing additional commands.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `SSTI-arithmetic-probe` — Ssti arithmetic probe. Select only when the matching trigger and evidence preconditions are present.
- `expression-language-string-probe` — Expression language string probe. Select only when the matching trigger and evidence preconditions are present.
- `command-injection-minimal-time` — Command injection minimal time. Select only when the matching trigger and evidence preconditions are present.
- `command-injection-controlled-DNS` — Command injection controlled dns. Select only when the matching trigger and evidence preconditions are present.
- `deserialization-safe-type-probe` — Deserialization safe type probe. Select only when the matching trigger and evidence preconditions are present.
- `job-runner-argument-boundary` — Job runner argument boundary. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| Template field | Expression is server-evaluated | Harmless arithmetic/string expression | Rendered evaluated result |
| Shell argument | Input changes command structure | Minimal delay or controlled DNS canary | Deterministic delay/OOB event |
| Rule/formula | User controls expression semantics | Benign constant expression | Server computes unexpected result |
| Serialized object | Type/property control reaches dangerous loader | Benign type/property mutation in test object | Unexpected class/callback behavior |
| Alternate worker | Async processor has weaker protection | Same canary through queued path | Worker-specific evaluation/OOB |

## Tool strategy

- Use raw replay, local template parsers, and source/dependency evidence before specialized exploit tools.
- `tplmap`-style or deserialization tooling should be constrained to identification and non-destructive proof in a disposable environment.
- Use a controlled OOB service and correlate unique tokens to exact requests.
- Execute suspicious samples only inside an isolated sandbox with no secrets or network beyond the callback service.

## Evidence required for a finding

- Exact sink/context, baseline, minimal probe, and deterministic evaluated result or correlated OOB event.
- For timing, multiple interleaved controls and the smallest effective delay.
- For deserialization, format/type path and minimal behavior demonstrating unsafe object control.
- Privilege and reachability inferred from architecture/source must be labeled separately from demonstrated execution.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/command-ssti-expression-and-deserialization-testing.schema.json`.

**Skill-specific evidence fields**

- `interpreter_family`
- `input_location`
- `suspected_sink`
- `canary`
- `evaluation_signal`
- `negative_control`
- `OOB_event`

**Required validation controls**

- `least_powerful_probe_first`
- `no_file_read`
- `no_shell`
- `controlled_callback_only`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- Reflected template syntax is not evaluation.
- Background DNS/HTTP activity may be unrelated without a unique token.
- Latency spikes and generic 5xx errors do not prove command execution.
- Deserialization format exposure alone is not a gadget-based vulnerability.

## Stop conditions

- A canary confirms execution or unsafe evaluation—the proof is complete.
- The only remaining proof requires file access, secret retrieval, persistence, reverse shell, or destructive behavior.
- A delay affects service health or queued work accumulates.
- Testing reaches a shared build/worker system outside scope.

## Common remediation patterns

- Avoid shells and dynamic evaluation; use safe APIs with fixed commands/templates and separate arguments.
- Use sandboxed, logic-limited template engines and strict variable allowlists.
- Reject untrusted serialized objects and type metadata; use simple data formats with integrity protection.
- Run processors with least privilege, isolation, egress restrictions, and time/resource limits.
- Add canary regression tests for every affected sink and alternate processing path.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/command-ssti-expression-and-deserialization-testing.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.command-ssti-expression-and-deserialization-testing
supporting_skills: []
selected_techniques: [SSTI-arithmetic-probe]
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
  evidence_extension_schema: schemas/evidence-extensions/command-ssti-expression-and-deserialization-testing.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 20 for file-conversion or upload-triggered execution paths.
- Skill 18 when execution-like behavior is actually server-side URL fetching.
- Skill 29 for LLM tool/plugin execution chains.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
request_id: report-preview-17
suspected_sink: server_template
allowed_proof: [arithmetic, controlled_dns]
max_delay_seconds: 2
```

## Authoritative references

- [OWASP Top 10 2025 — Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [PortSwigger — OS command injection](https://portswigger.net/web-security/os-command-injection)
- [PortSwigger — Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)

---

## ShakerScan runtime notes

**Support: partial.** ShakerScan has no capability for `oob.allocate`, `oob.observe`, so this skill cannot be bound to a hunt yet. It is published so the gap is visible rather than discovered mid-run.

Bindable capabilities: `http.request`, `authz.verify`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
