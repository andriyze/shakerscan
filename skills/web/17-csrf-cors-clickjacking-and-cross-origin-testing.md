---
id: skill.web.csrf-cors-clickjacking-and-cross-origin-testing
name: csrf-cors-clickjacking-and-cross-origin-testing
title: 17. CSRF, CORS, Clickjacking, and Cross-Origin Trust Testing
description: Test whether browser ambient authority or cross-origin trust permits unwanted state changes,
  credentialed data reads, UI redressing, or login/session confusion.
version: 2.0.0
kind: specialist
phase: active_testing
risk: medium
support: supported
target_kinds:
- web
- api
capabilities:
- browser.navigate
- browser.interact
- http.request
- candidate.verify
optional_capabilities:
- auth.session.establish
missing_capabilities: []
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 140
  max_duration_seconds: 900
  max_state_changing_requests: 8
routing:
  triggers:
  - state_changing_browser_request
  - CORS_headers
  - cross_origin_embed
  - frameable_sensitive_page
  - SameSite_cookie
  - postMessage
  indicators:
  - credentialed_cross_origin_request
  - cross_origin_read
  - server_state_change
  - frame_overlay_action
  - origin_trust_error
  exclusions:
  - real_payment_or_message
  - uncontrolled_foreign_origin
  - real_user_click
preconditions:
- compiled_scope_policy
- controlled_foreign_origin
- controlled_identity
- synthetic_state
techniques:
- CSRF-form-or-fetch
- CORS-origin-reflection
- credentialed-CORS-read
- clickjacking-frameability
- SameSite-context-validation
- postMessage-origin-validation
promotion_gate: core.evidence-validation:confirmed
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
server_satisfied_prerequisites: []
source: web-security-agent-skills v2.0.0 17-csrf-cors-clickjacking-and-cross-origin-testing.md
---

# 17. CSRF, CORS, Clickjacking, and Cross-Origin Trust Testing

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Evaluate the browser security boundary as a system: cookies, SameSite, CSRF tokens, Origin/Referer checks, CORS, framing policy, redirects, and user interaction. Use a controlled foreign-origin harness and synthetic state.

## Use this skill when

- State-changing requests use cookies or browser-managed credentials.
- APIs return CORS headers or support credentialed cross-origin requests.
- Sensitive pages can be framed or rely on UI confirmation.
- Login, logout, account-linking, OAuth, upload, WebSocket, or JSON endpoints may have cross-origin behavior.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `state_changing_browser_request`
- `CORS_headers`
- `cross_origin_embed`
- `frameable_sensitive_page`
- `SameSite_cookie`
- `postMessage`

**Useful indicators**

- `credentialed_cross_origin_request`
- `cross_origin_read`
- `server_state_change`
- `frame_overlay_action`
- `origin_trust_error`

**Hard exclusions**

- `real_payment_or_message`
- `uncontrolled_foreign_origin`
- `real_user_click`

**Required preconditions**

- `compiled_scope_policy`
- `controlled_foreign_origin`
- `controlled_identity`
- `synthetic_state`

**Preferred preconditions**

- `browser_matrix`
- `authoritative_state_verifier`

## Required context

- Controlled foreign-origin test harness and browser profiles.
- Synthetic accounts/objects and reversible actions.
- Cookie SameSite/Domain attributes, CSRF token behavior, CORS responses, and frame policies.
- Explicitly excluded actions and maximum state changes.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `browser.navigate`
- `browser.interact`
- `browser.observe`
- `http.request`
- `state.verify`

**Optional adapters**

- `token.inspect`

**Prohibited capabilities**

- `unrestricted_shell`
- `unscoped_egress`
- `real_user_targeting`
- `persistence`
- `denial_of_service`

**Default budget**

| Counter | Maximum |
|---|---:|
| `max_requests` | 140 |
| `max_duration_seconds` | 900 |
| `max_concurrency` | 2 |
| `max_state_changes` | 8 |
| `max_auth_attempts` | 0 |
| `max_messages` | 0 |
| `max_oob_interactions` | 0 |
| `max_uploaded_bytes` | 0 |
| `max_cost_units` | 150 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `externally_visible_state_change` | cross-origin proof can contact or affect an uncontrolled party | `block` |

**State access**

- Reads: `compiled_policy`, `browser_sessions`, `identities`, `request_corpus`, `cookie_inventory`
- Writes: `cross_origin_observations`, `browser_policy_records`, `state_change_evidence`, `hypothesis_events`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- A cross-site request can perform an authenticated state change without a valid user-intent proof.
- CSRF tokens are missing, predictable, unbound, reusable across users, or bypassed by alternate method/content type.
- CORS reflects or trusts attacker-controlled origins while allowing credentials or sensitive responses.
- Sensitive UI can be framed and overlaid to trigger privileged action.
- Login/logout or account-linking flows can be cross-site initiated to confuse session identity.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- Use only self-owned synthetic state and a controlled foreign origin.
- Do not send real messages, payments, invitations, or destructive operations.
- A request leaving the browser is not enough; verify server-side state and whether browser credentials were included.
- Assess SameSite in the actual navigation/subresource context and browser behavior.

## Agent workflow

### 1. Map browser authority

- Identify cookies, client certificates, HTTP auth, browser storage, and automatic credentials used by each action.
- Classify requests as simple/non-simple, navigation/subresource, same-site/cross-site, and top-level/iframe.
- Record Origin, Referer, Fetch Metadata, CSRF token, custom header, and content type.

### 2. Test CSRF protections

- Replay a state-changing synthetic action without token, with altered token, token from another controlled user, and stale token.
- Test one alternate method/content type only where the server supports it.
- Use an actual cross-origin browser harness to confirm ambient credentials and authoritative state.

### 3. Test CORS behavior

- Send controlled Origin values: exact foreign origin, subdomain, suffix lookalike, `null` where relevant, mixed scheme/port, and preflight variations.
- Check `Access-Control-Allow-Origin`, credentials, methods, headers, Vary behavior, and readable response.
- Confirm whether sensitive data is accessible to JavaScript, not merely sent over the network.

### 4. Test clickjacking and UI redress

- Frame sensitive pages in the controlled harness and inspect CSP `frame-ancestors` and X-Frame-Options.
- Assess whether opaque overlays or minimal clicks can trigger a high-impact action.
- Do not complete real effects; use a reversible test action or stop at demonstrable UI alignment.

### 5. Test login and cross-origin identity flows

- Check login CSRF, logout CSRF, account linking, magic links, and OAuth callbacks using controlled accounts.
- Verify state/nonce and current-user confirmation where identity can change.
- Observe session before and after from the authoritative identity endpoint.

### 6. Evaluate defense combinations

- Determine whether CSRF token, SameSite, Origin/Referer, Fetch Metadata, re-authentication, and UI confirmation form a robust layered control.
- Do not overstate a missing header when another reliable control prevents impact.
- Create a deterministic browser regression harness.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `CSRF-form-or-fetch` — Csrf form or fetch. Select only when the matching trigger and evidence preconditions are present.
- `CORS-origin-reflection` — Cors origin reflection. Select only when the matching trigger and evidence preconditions are present.
- `credentialed-CORS-read` — Credentialed cors read. Select only when the matching trigger and evidence preconditions are present.
- `clickjacking-frameability` — Clickjacking frameability. Select only when the matching trigger and evidence preconditions are present.
- `SameSite-context-validation` — Samesite context validation. Select only when the matching trigger and evidence preconditions are present.
- `postMessage-origin-validation` — Postmessage origin validation. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| State-changing form/API | Cross-site request cannot change state | Foreign-origin browser submission on synthetic object | Authenticated state changes |
| CSRF token | Token is user/session/action bound | Omit/alter/swap controlled token | Request succeeds |
| Credentialed CORS | Foreign JS cannot read sensitive response | Fetch from controlled origin | Response readable with credentials |
| Framing | Sensitive UI resists redress | Frame in controlled harness | High-impact action can be aligned/triggered |
| Login/linking | Cross-site flow cannot change identity/link | Initiate with second controlled account | Victim browser binds wrong identity |

## Tool strategy

- Use a local/controlled HTTPS origin plus Playwright for real browser enforcement.
- Use raw HTTP to enumerate CORS/token variants, then confirm impact in browser.
- Capture browser console, network, cookie context, frame rendering, and authoritative state.
- Test WebSocket Origin behavior through Skill 13.

## Evidence required for a finding

- Foreign-origin proof, browser context, cookie/SameSite state, exact request, and authoritative side effect or readable data.
- For CORS, JavaScript-readable response—not headers alone.
- For clickjacking, frameability plus realistic user interaction and sensitive action.
- For login CSRF, identity before/after using controlled accounts.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/csrf-cors-clickjacking-and-cross-origin-testing.schema.json`.

**Skill-specific evidence fields**

- `attacker_origin`
- `target_origin`
- `credentials_mode`
- `browser_context`
- `expected_policy`
- `observed_headers`
- `state_change_or_read_evidence`

**Required validation controls**

- `actual_browser_context`
- `credential_inclusion_verified`
- `authoritative_state_or_cross_origin_read`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- Missing CSRF token is not exploitable if no browser ambient authority is used or another robust intent control exists.
- Permissive CORS without credentials/sensitive readable data may be low impact.
- Page frameability alone is not meaningful without a sensitive UI action.
- A preflight response does not prove the actual credentialed request succeeds.

## Stop conditions

- A proof would trigger a real external effect or expose non-test data.
- The browser sends credentials to an unapproved origin.
- Clickjacking validation would require tricking a real user.
- Cross-origin testing reaches an out-of-scope identity provider.

## Common remediation patterns

- Use unpredictable, session-bound CSRF tokens and verify Origin/Referer or Fetch Metadata for state changes.
- Set cookies with appropriate SameSite, Secure, HttpOnly, Domain, and Path.
- Allowlist exact CORS origins and avoid credentialed wildcard/reflection behavior; include correct Vary handling.
- Use CSP `frame-ancestors` and/or X-Frame-Options for sensitive pages.
- Require explicit current-user confirmation and protocol state/nonce for login/linking flows.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/csrf-cors-clickjacking-and-cross-origin-testing.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.csrf-cors-clickjacking-and-cross-origin-testing
supporting_skills: []
selected_techniques: [CSRF-form-or-fetch]
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
  evidence_extension_schema: schemas/evidence-extensions/csrf-cors-clickjacking-and-cross-origin-testing.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 07 for cookie/session properties.
- Skill 13 for cross-site WebSocket hijacking.
- Skill 21 for OAuth/OIDC/SAML state and redirect flows.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
target_action: update_test_profile
foreign_origin: https://attacker-harness.example.test
identity: user_a
allowed_state_changes: 3
```

## Authoritative references

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PortSwigger — CSRF](https://portswigger.net/web-security/csrf)
- [PortSwigger — CORS](https://portswigger.net/web-security/cors)
- [PortSwigger — Clickjacking](https://portswigger.net/web-security/clickjacking)

---

## ShakerScan runtime notes

**Support: supported.** Every adapter this skill requires maps to a planner-visible capability, so it can be bound to a hunt.

Bindable capabilities: `browser.navigate`, `browser.interact`, `http.request`, `candidate.verify`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
