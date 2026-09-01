---
id: skill.web.xss-dom-and-client-side-injection-testing
name: xss-dom-and-client-side-injection-testing
title: 16. XSS, DOM, Prototype Pollution, and Client-Side Injection Testing
description: Test reflected, stored, DOM-based, and client-side injection paths, including unsafe HTML/URL/JavaScript
  sinks, postMessage, DOM clobbering, and prototype pollution.
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
- browser.interact
optional_capabilities:
- xss.verify
missing_capabilities: []
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 180
  max_duration_seconds: 1200
  max_state_changing_requests: 8
  max_oob_interactions: 3
routing:
  triggers:
  - reflected_input
  - stored_user_content
  - DOM_source_sink_path
  - URL_or_postMessage_input
  - client_template
  - prototype_merge
  indicators:
  - browser_execution
  - DOM_mutation
  - console_canary
  - controlled_callback
  - prototype_property_effect
  exclusions:
  - cookie_or_token_theft
  - real_user_view
  - persistent_payload_outside_test_account
preconditions:
- compiled_scope_policy
- controlled_browser
- test_identity_or_self_visible_context
techniques:
- reflected-XSS-contextual
- stored-XSS-test-account
- DOM-XSS-source-sink
- postMessage-origin-and-sink
- prototype-pollution-client-impact
- unsafe-client-template-rendering
promotion_gate: core.evidence-validation:confirmed
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
server_satisfied_prerequisites: []
source: web-security-agent-skills v2.0.0 16-xss-dom-and-client-side-injection-testing.md
---

# 16. XSS, DOM, Prototype Pollution, and Client-Side Injection Testing

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Prove whether attacker-controlled data executes or changes privileged browser behavior in a relevant origin. Use self-visible markers and controlled browser instrumentation—never cookie theft, destructive actions, or payloads delivered to real users.

## Use this skill when

- Input is reflected, stored, rendered from API/LLM output, inserted into DOM, passed through postMessage, or merged into client objects.
- JavaScript analysis identifies dangerous sources/sinks or prototype merge patterns.
- Markdown, rich text, SVG, HTML email previews, filenames, errors, or third-party widgets render user content.
- CSP, Trusted Types, sanitizers, or encoding behavior need validation.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `reflected_input`
- `stored_user_content`
- `DOM_source_sink_path`
- `URL_or_postMessage_input`
- `client_template`
- `prototype_merge`

**Useful indicators**

- `browser_execution`
- `DOM_mutation`
- `console_canary`
- `controlled_callback`
- `prototype_property_effect`

**Hard exclusions**

- `cookie_or_token_theft`
- `real_user_view`
- `persistent_payload_outside_test_account`

**Required preconditions**

- `compiled_scope_policy`
- `controlled_browser`
- `test_identity_or_self_visible_context`

**Preferred preconditions**

- `identified_source_and_sink`
- `CSP_and_Trusted_Types_snapshot`

## Required context

- Stable request/response and the rendering page/origin.
- Controlled test accounts and self-visible content locations.
- Browser instrumentation, CSP/Trusted Types policy, and observed sanitization.
- Allowed payload behavior limited to console/DOM canaries.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `http.request`
- `http.differential_replay`
- `browser.navigate`
- `browser.interact`
- `browser.observe`

**Optional adapters**

- `javascript.analyze`
- `oob.allocate`
- `oob.observe`

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
| `max_duration_seconds` | 1200 |
| `max_concurrency` | 2 |
| `max_state_changes` | 8 |
| `max_auth_attempts` | 0 |
| `max_messages` | 0 |
| `max_oob_interactions` | 3 |
| `max_uploaded_bytes` | 0 |
| `max_cost_units` | 180 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `stored_client_payload` | payload can be viewed by anyone other than controlled identities | `block` |

**State access**

- Reads: `compiled_policy`, `client_dataflow_graph`, `request_corpus`, `browser_sessions`, `identities`
- Writes: `client_injection_hypotheses`, `browser_execution_records`, `DOM_diffs`, `evidence_records`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- Reflected or stored input breaks out of its HTML, attribute, JavaScript, URL, CSS, SVG, or template context.
- DOM sources reach dangerous sinks without contextual sanitization.
- postMessage or cross-window data is accepted from an untrusted origin.
- Prototype pollution changes security-sensitive client behavior or reaches a code-execution/DOM sink.
- LLM/Markdown or third-party content is rendered without safe output handling.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- Use canaries such as console logging, DOM attribute change, or test-only callback; do not steal cookies/tokens or act as another user.
- Stored tests must remain visible only to controlled accounts.
- Do not declare XSS from reflection alone; confirm execution in the intended browser/origin.
- Respect CSP and Trusted Types as part of the actual execution path rather than assuming bypass.

## Agent workflow

### 1. Classify rendering context

- Locate every reflection/storage/render point and identify HTML text, attribute, JavaScript, JSON-in-script, URL, CSS, SVG, Markdown, or DOM context.
- Record transformations, encodings, sanitizers, frameworks, CSP, Trusted Types, sandboxed frames, and browser behavior.
- Separate server-rendered, client-rendered, and second-order flows.

### 2. Probe context safely

- Use a unique inert marker, then minimal delimiter characters to determine escaping and parsing.
- Select a context-appropriate self-visible payload only after the context is understood.
- Capture final DOM and browser parsing, not only raw response text.

### 3. Test DOM source-to-sink flows

- Instrument URL, referrer, postMessage, storage, API response, WebSocket, and DOM inputs.
- Trace to HTML insertion, script/eval, navigation, event handler, URL assignment, template, and DOM-clobbering sinks.
- Verify whether sanitization/Trusted Types occurs before the sink.

### 4. Test stored and second-order paths

- Store a harmless canary in a controlled object and visit every self-owned rendering context: list, detail, admin-test view, export, notification preview, and realtime update.
- Avoid any page used by real users.
- Check whether asynchronous processors or LLM/Markdown transforms alter encoding.

### 5. Test postMessage and cross-window trust

- Enumerate message listeners, expected origins, data schema, and privileged actions.
- Send a controlled message from an approved foreign-origin harness.
- Verify exact origin/source and message structure checks.

### 6. Test prototype pollution and client integrity

- Identify user-controlled keys merged into global/configuration objects.
- Use benign prototype markers first, then test a known security-relevant gadget only in a controlled browser state.
- Reset page/storage and confirm the effect is repeatable and source-to-gadget connected.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `reflected-XSS-contextual` — Reflected xss contextual. Select only when the matching trigger and evidence preconditions are present.
- `stored-XSS-test-account` — Stored xss test account. Select only when the matching trigger and evidence preconditions are present.
- `DOM-XSS-source-sink` — Dom xss source sink. Select only when the matching trigger and evidence preconditions are present.
- `postMessage-origin-and-sink` — Postmessage origin and sink. Select only when the matching trigger and evidence preconditions are present.
- `prototype-pollution-client-impact` — Prototype pollution client impact. Select only when the matching trigger and evidence preconditions are present.
- `unsafe-client-template-rendering` — Unsafe client template rendering. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| Reflected value | Context can be escaped into executable markup/script | Context-specific console canary | Browser executes in target origin |
| Stored field | Stored content executes for viewer | Self-owned object and self-view only | Execution on controlled rendering path |
| DOM source | Untrusted value reaches dangerous sink | Instrumented unique marker | Runtime source-to-sink trace and execution |
| postMessage | Foreign origin can trigger privileged behavior | Controlled sender origin | Message accepted/action occurs |
| Prototype merge | Attacker key affects security-sensitive gadget | Benign prototype marker then controlled gadget | Repeatable behavior change |

## Tool strategy

- Use Playwright/Chromium DevTools Protocol, DOM breakpoints, CSP console, and instrumented sink hooks.
- Use DOM Invader-like analysis, AST tools, and sanitizer test harnesses locally.
- Use `dalfox`/`kxss` only for candidate generation; browser confirmation is mandatory.
- Capture screenshots, console, DOM snapshot, network trace, CSP violations, and exact origin.

## Evidence required for a finding

- Source, storage point, rendering context, transformations, final sink, origin, and self-visible execution.
- For stored XSS, proof that only controlled users were exposed.
- For postMessage, sender origin/window and accepted message/action.
- For prototype pollution, source-to-prototype-to-gadget chain, not prototype mutation alone.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/xss-dom-and-client-side-injection-testing.schema.json`.

**Skill-specific evidence fields**

- `source`
- `sink`
- `execution_context`
- `encoding_context`
- `payload_canary`
- `browser_trace`
- `CSP_or_Trusted_Types_effect`

**Required validation controls**

- `browser_execution_required`
- `intended_origin_required`
- `self_visible_or_controlled_viewer_only`
- `reflection_not_finding`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- Reflection without browser execution is not XSS.
- Execution in a local preview, browser extension, or different origin may not affect the target.
- A prototype property change without a security-relevant gadget may be low impact/inconclusive.
- Sanitizer bypass in a standalone library version is not proof the deployed flow is vulnerable.

## Stop conditions

- A payload could be rendered to real users, administrators, or external recipients.
- Proof would require session theft, credential capture, destructive actions, or persistence.
- The browser begins navigating or sending data to an unapproved origin.
- A stored canary cannot be reliably cleaned up.

## Common remediation patterns

- Use context-aware output encoding and safe DOM APIs; avoid HTML/script construction.
- Sanitize rich content with a maintained allowlist sanitizer and safe configuration.
- Deploy CSP and Trusted Types as defense in depth.
- Validate postMessage origin, source, schema, and permitted actions.
- Reject dangerous object keys and use safe merge patterns; update affected libraries and gadgets.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/xss-dom-and-client-side-injection-testing.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.xss-dom-and-client-side-injection-testing
supporting_skills: []
selected_techniques: [reflected-XSS-contextual]
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
  evidence_extension_schema: schemas/evidence-extensions/xss-dom-and-client-side-injection-testing.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 17 for cross-origin controls and clickjacking.
- Skill 20 for SVG/HTML/file upload rendering.
- Skill 29 for insecure rendering of LLM output and indirect prompt-injection chains.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
source: profile.display_name
rendering_page: https://app.example.test/profile
identity: user_a
allowed_effect: console_canary
```

## Authoritative references

- [PortSwigger — Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
- [PortSwigger — DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based)
- [PortSwigger — Prototype pollution](https://portswigger.net/web-security/prototype-pollution)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

---

## ShakerScan runtime notes

**Support: supported.** Every adapter this skill requires maps to a planner-visible capability, so it can be bound to a hunt.

Bindable capabilities: `http.request`, `authz.verify`, `browser.navigate`, `browser.interact`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
