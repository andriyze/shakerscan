---
id: skill.web.stateful-crawling-content-and-parameter-discovery
name: stateful-crawling-content-and-parameter-discovery
title: 03. Stateful Crawling, Content, and Parameter Discovery
description: Discover routes, forms, methods, parameters, files, and state transitions through browser-assisted
  crawling and context-aware content discovery.
version: 2.0.0
kind: discovery
phase: discovery
risk: low_to_medium
support: supported
target_kinds:
- web
- api
capabilities:
- web.crawl
- browser.navigate
- browser.interact
- http.request
optional_capabilities:
- templates.scan
missing_capabilities: []
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 2500
  max_duration_seconds: 1200
  max_state_changing_requests: 5
routing:
  triggers:
  - web_application
  - authenticated_ui
  - route_inventory_gap
  - form_or_workflow
  - unknown_parameters
  indicators:
  - links
  - forms
  - XHR_or_fetch
  - hidden_routes
  - alternate_methods
  - content_discovery_candidates
  exclusions:
  - destructive_form
  - unbounded_calendar_or_search_space
  - real_user_workflow
preconditions:
- compiled_scope_policy
- approved_seed_urls
techniques:
- browser-assisted-crawl
- form-and-input-extraction
- context-wordlist-discovery
- method-and-format-variation
- route-corpus-normalization
promotion_gate: core.evidence-validation:confirmed
requires_skills: []
server_satisfied_prerequisites:
- skill.web.scope-authorization-and-agent-safety
source: web-security-agent-skills v2.0.0 03-stateful-crawling-content-and-parameter-discovery.md
---

# 03. Stateful Crawling, Content, and Parameter Discovery

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Build a high-coverage request corpus representing anonymous users and each authorized role. Find hidden input surfaces and workflows without uncontrolled brute force, accidental destructive clicks, or merging security contexts.

## Use this skill when

- A live application origin is approved and downstream testing needs routes, inputs, forms, methods, and workflows.
- Static crawlers miss JavaScript navigation, authenticated pages, multi-step forms, or role-specific content.
- A prior scan has low coverage or cannot explain which UI action produced a request.
- The application exposes sitemaps, documentation, route manifests, or predictable content conventions.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `web_application`
- `authenticated_ui`
- `route_inventory_gap`
- `form_or_workflow`
- `unknown_parameters`

**Useful indicators**

- `links`
- `forms`
- `XHR_or_fetch`
- `hidden_routes`
- `alternate_methods`
- `content_discovery_candidates`

**Hard exclusions**

- `destructive_form`
- `unbounded_calendar_or_search_space`
- `real_user_workflow`

**Required preconditions**

- `compiled_scope_policy`
- `approved_seed_urls`

**Preferred preconditions**

- `controlled_identity`
- `browser_profile`
- `known_prohibited_actions`

## Required context

- Approved origins, start URLs, test identities, authentication bootstrap instructions, and logout boundaries.
- Excluded paths/actions such as checkout, deletion, invitation, message sending, expensive export, or real-user content.
- Permitted crawl depth, duration, request rate, wordlists, file extensions, and maximum state changes.
- Previously captured traffic and known routes to seed deduplication.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `crawler.run`
- `browser.navigate`
- `browser.interact`
- `browser.observe`
- `http.request`

**Optional adapters**

- `scanner.run`
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
| `max_requests` | 2500 |
| `max_duration_seconds` | 1200 |
| `max_concurrency` | 8 |
| `max_state_changes` | 5 |
| `max_auth_attempts` | 0 |
| `max_messages` | 0 |
| `max_oob_interactions` | 0 |
| `max_uploaded_bytes` | 0 |
| `max_cost_units` | 300 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `stateful_submission` | interaction is one-time, expensive, externally visible, or irreversible | `human_approval` |

**State access**

- Reads: `compiled_policy`, `asset_graph`, `identities`, `browser_sessions`, `endpoint_inventory`
- Writes: `endpoint_inventory`, `parameter_inventory`, `request_corpus`, `workflow_graph`, `evidence_records`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- Important routes are reachable only through JavaScript, authentication, role-specific menus, or multi-step state.
- Unlinked directories, files, backup names, alternate extensions, or API versions are exposed.
- Hidden or optional parameters alter server behavior.
- The same path supports additional methods or content types with different controls.
- Crawler output contains soft 404s, generic SPA shells, and duplicate route variants that must be normalized.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- Classify every click or form submission as read-only, reversible synthetic mutation, one-time, expensive, or prohibited before execution.
- Keep cookies, storage, CSRF state, and request corpora separate for each identity.
- Use context-derived words before broad generic wordlists.
- Do not recursively crawl calendars, searches, pagination, or parameter combinations without explicit bounds.

## Agent workflow

### 1. Seed known content

- Fetch robots.txt, sitemaps, security.txt, manifests, well-known paths, supplied documentation, and approved API descriptions.
- Import captured requests and normalize them before initiating new traffic.
- Create hard exclusions for logout, destructive actions, external messages, payments, and infinite navigation patterns.

### 2. Run browser-assisted crawls

- Use a real browser to execute JavaScript, expand menus, follow route changes, and capture navigation, fetch/XHR, forms, WebSockets, downloads, and uploads.
- Crawl separately as anonymous and each test role.
- Record UI labels and workflow context so downstream agents understand the business purpose of requests.

### 3. Extract the input schema

- Catalog path, query, body, multipart, JSON, XML, GraphQL, header, cookie, and message fields with observed types and example values.
- Identify hidden fields, method overrides, pagination, sorting, filters, object IDs, filenames, callback URLs, redirects, and client-generated flags.
- Use controlled omission or documented schemas to infer required versus optional fields.

### 4. Perform calibrated content discovery

- Generate candidate paths from application vocabulary, JavaScript strings, API tags, documentation, technology fingerprints, and existing segments.
- Probe at a bounded rate and compare every result to random nonexistent-path controls.
- Vary case, separators, and extensions only when the platform or observed naming makes them plausible.

### 5. Discover alternate methods and formats

- Use documentation, OPTIONS, browser behavior, and error messages to identify candidate methods or content types.
- Replay one safe alternative at a time while preserving authentication and anti-CSRF state.
- Record parser or authorization differences for specialized testing.

### 6. Normalize and rank the corpus

- Group concrete routes into templates such as `/users/{id}` while retaining examples, roles, and methods.
- Mask volatile values for deduplication but preserve security-relevant headers and states.
- Rank requests by privilege, state change, object references, file/URL inputs, parser complexity, business value, and error behavior.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `browser-assisted-crawl` — Browser assisted crawl. Select only when the matching trigger and evidence preconditions are present.
- `form-and-input-extraction` — Form and input extraction. Select only when the matching trigger and evidence preconditions are present.
- `context-wordlist-discovery` — Context wordlist discovery. Select only when the matching trigger and evidence preconditions are present.
- `method-and-format-variation` — Method and format variation. Select only when the matching trigger and evidence preconditions are present.
- `route-corpus-normalization` — Route corpus normalization. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| SPA navigation | Client routes are absent from static links | Browser crawl with network capture | Stable route/request observed |
| Hidden parameter | Unseen field affects server logic | Add or omit one candidate field | Repeatable semantic/state difference |
| Unlinked content | Context-derived path exists | Calibrated bounded wordlist | Response differs from wildcard controls |
| Role-specific surface | Roles expose distinct routes | Repeat crawl with isolated identities | Route/method appears only for intended role |
| Alternate method/type | A different handler accepts same operation | One approved method/content-type variation | Different validation or authorization path |

## Tool strategy

- Use Playwright or equivalent browser automation with network capture and interception of unsafe actions.
- Use `katana`, `feroxbuster`, `ffuf`, or equivalents with exact scope, calibration, and rate limits.
- Parameter helpers such as `arjun` generate hypotheses only; require a functional differential.
- Export raw HTTP plus structured route, role, state, safety, and UI-context metadata.

## Evidence required for a finding

- Raw request/response, discovery source, role, UI action, and first-seen timestamp.
- Wildcard/soft-404 calibration controls for content discoveries.
- Route template, concrete examples, methods, content types, parameter schema, and replay safety.
- Proof that a hidden parameter is processed, not merely reflected or ignored.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/stateful-crawling-content-and-parameter-discovery.schema.json`.

**Skill-specific evidence fields**

- `route`
- `method`
- `parameter_schema`
- `identity_context`
- `state_transition`
- `discovery_source`

**Required validation controls**

- `identity_isolation`
- `deduplicated_route_key`
- `state_change_verification`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- Soft 404s, login redirects, generic SPA shells, WAF blocks, and CDN errors often look like valid content.
- Browser prefetch, extensions, service workers, and telemetry can create unrelated requests.
- OPTIONS or documentation may describe disabled methods.
- A parameter accepted or echoed is not necessarily used by application logic.

## Stop conditions

- The crawler reaches an excluded action, third-party origin, real-user object, or unbounded navigation space.
- Repeated submissions create external messages, charges, inventory changes, invitations, or other unintended effects.
- Rate limits, health anomalies, or account state changes occur.
- Valid content cannot be distinguished from wildcard responses without substantially increasing impact.

## Common remediation patterns

- Remove obsolete, backup, debug, and undocumented routes from production.
- Enforce server-side authorization and validation consistently across methods and content types.
- Restrict directory listing and sensitive metadata files.
- Use explicit route inventories and API lifecycle management.
- Ensure client-only hidden fields and navigation controls are never security boundaries.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/stateful-crawling-content-and-parameter-discovery.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.stateful-crawling-content-and-parameter-discovery
supporting_skills: []
selected_techniques: [browser-assisted-crawl]
hypothesis_id: HYP-example-001
risk: low_to_medium
policy_revision: POL-example-r1
approval_refs: []
budget: <copy or reduce the manifest budget>
actions: <typed actions only>
validation:
  positive_conditions: [<skill-specific condition>]
  negative_controls: [<control>]
  confirmation_runs: 1
  authoritative_state_required: false
  evidence_extension_schema: schemas/evidence-extensions/stateful-crawling-content-and-parameter-discovery.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 04 for deep JavaScript and source-map analysis.
- Skill 05 to create stable replayable baselines.
- Skills 09–10 for object IDs, role boundaries, and business state.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
origin: https://app.example.test
identities: [anonymous, user_a, manager_test]
excluded_actions: [delete, checkout, invite_external]
max_depth: 6
```

## Authoritative references

- [OWASP WSTG — Map Execution Paths](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/07-Map_Execution_Paths_Through_Application)
- [OWASP WSTG — Review Webpage Content](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage)
- [PortSwigger — API testing](https://portswigger.net/web-security/api-testing)

---

## ShakerScan runtime notes

**Support: supported.** Every adapter this skill requires maps to a planner-visible capability, so it can be bound to a hunt.

Bindable capabilities: `web.crawl`, `browser.navigate`, `browser.interact`, `http.request`. Optional when the hunt already holds them: `templates.scan`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
