---
id: skill.web.session-cookie-token-and-jwt-testing
name: session-cookie-token-and-jwt-testing
title: 07. Session, Cookie, Token, and JWT Testing
description: Verify creation, rotation, binding, browser storage, expiry, revocation, and validation of
  sessions, cookies, bearer tokens, refresh tokens, and JWTs.
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
- auth.session.establish
- browser.navigate
- candidate.verify
optional_capabilities: []
missing_capabilities: []
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 120
  max_duration_seconds: 900
  max_state_changing_requests: 5
routing:
  triggers:
  - session_cookie
  - bearer_token
  - refresh_token
  - JWT
  - logout
  - privilege_change
  - session_rotation
  indicators:
  - token_lifecycle
  - cookie_attribute
  - server_acceptance
  - revocation
  - expiry
  - cross_context_reuse
  exclusions:
  - token_from_real_user
  - external_key_server_not_approved
preconditions:
- compiled_scope_policy
- controlled_account_tokens
techniques:
- session-creation-and-rotation
- cookie-attribute-check
- JWT-validation-mutation
- refresh-token-reuse
- logout-and-revocation
- expiry-control
promotion_gate: core.evidence-validation:confirmed
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
server_satisfied_prerequisites: []
source: web-security-agent-skills v2.0.0 07-session-cookie-token-and-jwt-testing.md
---

# 07. Session, Cookie, Token, and JWT Testing

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Determine whether authenticated state can be fixed, replayed, confused, extended, or retained after it should be invalid. Test the full lifecycle across web, API, background refresh, and realtime channels.

## Use this skill when

- Authentication produces cookies, bearer/refresh tokens, signed URLs, API keys, or JWTs.
- The app supports logout, privilege changes, password reset, device management, remember-me, or concurrent sessions.
- Different clients or services appear to validate tokens differently.
- Browser storage or cross-subdomain cookie scope may expose session material.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `session_cookie`
- `bearer_token`
- `refresh_token`
- `JWT`
- `logout`
- `privilege_change`
- `session_rotation`

**Useful indicators**

- `token_lifecycle`
- `cookie_attribute`
- `server_acceptance`
- `revocation`
- `expiry`
- `cross_context_reuse`

**Hard exclusions**

- `token_from_real_user`
- `external_key_server_not_approved`

**Required preconditions**

- `compiled_scope_policy`
- `controlled_account_tokens`

**Preferred preconditions**

- `two_controlled_sessions`
- `server_side_session_verifier`

## Required context

- Controlled accounts and complete authentication flows.
- Expected idle/absolute lifetimes, concurrency policy, logout semantics, issuer/audience rules, and session-rotation events.
- Browser storage/network traces and optional server-side revocation visibility.
- A secure local artifact store for token references.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `http.request`
- `http.differential_replay`
- `token.inspect`
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
| `max_duration_seconds` | 900 |
| `max_concurrency` | 2 |
| `max_state_changes` | 5 |
| `max_auth_attempts` | 10 |
| `max_messages` | 0 |
| `max_oob_interactions` | 0 |
| `max_uploaded_bytes` | 0 |
| `max_cost_units` | 120 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `external_key_or_issuer_interaction` | test would contact an unapproved JWKS/key/issuer endpoint | `block` |

**State access**

- Reads: `compiled_policy`, `identities`, `sessions`, `token_artifacts`, `request_corpus`
- Writes: `session_lifecycle_graph`, `token_validation_observations`, `evidence_records`, `hypothesis_events`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- Authentication or privilege change fails to rotate attacker-known session state.
- Old sessions/tokens remain valid after logout, password reset, role change, disable, or deletion.
- Cookie scope or client-side storage exposes sensitive session material.
- JWT signature, algorithm, issuer, audience, time, type, or key-selection validation is incomplete.
- Refresh-token rotation or reuse detection is weak or inconsistent.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- Test only tokens issued to controlled accounts.
- Never place live tokens in prompts, report titles, screenshots, or external services.
- Mutate one token element at a time and avoid external key-server interaction unless explicitly authorized.
- A JWT decoding successfully is normal; only server acceptance of an invalid token is relevant.

## Agent workflow

### 1. Inventory session material

- Record cookies, authorization headers, refresh tokens, CSRF tokens, device tokens, signed URLs, local/session storage, IndexedDB, and service-worker caches.
- Classify each by issuer, audience, identity, privilege, lifetime, transport, storage, and revocation mechanism.
- Identify the authoritative token for HTTP, API, WebSocket, and refresh operations.

### 2. Test creation and rotation

- Compare pre-auth and post-auth identifiers for fixation.
- Verify rotation after login, MFA, privilege elevation, password/email change, tenant switch, and role change.
- Replay old state to determine whether it remains authenticated.

### 3. Test browser protections

- Evaluate Secure, HttpOnly, SameSite, Domain, Path, cookie prefixes, persistence, caching, and URL exposure.
- Check whether less-trusted subdomains can set or receive sensitive cookies.
- Verify logout clears browser state and sensitive pages are not exposed via cache/back navigation.

### 4. Test token validation

- For JWTs, test signature enforcement, allowed algorithms, issuer, audience, subject, expiration, not-before, token type, and key selection.
- Use safe single-field mutations: claim change, unsigned form, algorithm change, malformed `kid`, or controlled header URL only when allowed.
- For opaque tokens, test binding to user, client, tenant, device, and intended API.

### 5. Test refresh and revocation

- Verify refresh-token rotation, reuse detection, scope preservation, and access-token expiry.
- Test logout, global logout, password reset, account disable/delete, device removal, and API-key revocation.
- Check HTTP, background refresh, cached data, and realtime channels consistently.

### 6. Test expiry deterministically

- Use a controlled clock or short-lived test configuration when available.
- Distinguish client-side expiry handling from server enforcement.
- Capture idle and absolute timeout behavior without retaining sessions longer than needed.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `session-creation-and-rotation` — Session creation and rotation. Select only when the matching trigger and evidence preconditions are present.
- `cookie-attribute-check` — Cookie attribute check. Select only when the matching trigger and evidence preconditions are present.
- `JWT-validation-mutation` — Jwt validation mutation. Select only when the matching trigger and evidence preconditions are present.
- `refresh-token-reuse` — Refresh token reuse. Select only when the matching trigger and evidence preconditions are present.
- `logout-and-revocation` — Logout and revocation. Select only when the matching trigger and evidence preconditions are present.
- `expiry-control` — Expiry control. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| Session fixation | Login rotates known state | Set controlled pre-auth ID then authenticate | New ID; old state lacks access |
| Privilege event | Session revalidates/rotates | Change test role or complete MFA | Old state cannot retain stale privilege |
| JWT validation | Signature and claims are strict | Change one header/claim | Protected request rejected |
| Refresh rotation | Old refresh token cannot be reused | Replay old token after rotation | Reuse rejected/detected |
| Logout/revocation | All channels lose access | Replay HTTP, refresh, and realtime requests | Consistent denial |

## Tool strategy

- Use browser storage inspection plus raw HTTP replay.
- `jwt-tool` or equivalent may assist decoding/mutation, but every claim requires manual server-side validation.
- Store tokens encrypted and reference them by artifact ID.
- Use a controlled test clock or environment for expiry tests.

## Evidence required for a finding

- Token/cookie metadata with values redacted, issuance event, identity, claims, and channel.
- Before/after identifiers for rotation and exact replay result for old state.
- For JWT findings, the exact validation rule bypassed and protected capability demonstrated.
- For revocation, authoritative results across HTTP, refresh, and realtime.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/session-cookie-token-and-jwt-testing.schema.json`.

**Skill-specific evidence fields**

- `token_type`
- `lifecycle_event`
- `before_token_ref`
- `after_token_ref`
- `server_decision`
- `revocation_or_expiry_state`

**Required validation controls**

- `server_acceptance_required`
- `one_token_element_at_a_time`
- `redacted_token_artifacts`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- Multiple sessions may be intentional; assess revocation and user controls.
- Missing HttpOnly is irrelevant for a non-sensitive cookie.
- A token remaining in storage after logout may be harmless if server-side revoked.
- Client-side expiration messages do not prove server-side enforcement.

## Stop conditions

- A token belongs to a real user or another tenant.
- Testing would contact an unapproved `jku`, `x5u`, key server, or issuer.
- Proof requires token theft, long-term persistence, or impersonation of a non-test user.
- Account state becomes unstable or shared sessions are affected.

## Common remediation patterns

- Rotate session identifiers at authentication and privilege-boundary events.
- Use Secure, HttpOnly, appropriate SameSite, narrow Domain/Path, and cookie prefixes.
- Validate JWT algorithms, signature, issuer, audience, type, time claims, and key sources with strict allowlists.
- Use short-lived access tokens, rotating refresh tokens, reuse detection, and centralized revocation.
- Invalidate all relevant sessions/tokens after logout, reset, disable, deletion, or security-sensitive changes.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/session-cookie-token-and-jwt-testing.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.session-cookie-token-and-jwt-testing
supporting_skills: []
selected_techniques: [session-creation-and-rotation]
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
  evidence_extension_schema: schemas/evidence-extensions/session-cookie-token-and-jwt-testing.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 09 for authorization after a valid session.
- Skill 13 for realtime session lifecycle.
- Skill 21 for OAuth/OIDC/SAML issuance and protocol binding.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
identity: user_a
session_sources: [cookies, bearer, refresh, websocket]
lifecycle_events: [login, mfa, role_change, logout, password_reset]
token_storage: encrypted_local_reference
```

## Authoritative references

- [OWASP WSTG — Session Management](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/06-Session_Management_Testing/)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [RFC 8725 — JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [PortSwigger — JWT attacks](https://portswigger.net/web-security/jwt)

---

## ShakerScan runtime notes

**Support: supported.** Every adapter this skill requires maps to a planner-visible capability, so it can be bound to a hunt.

Bindable capabilities: `http.request`, `authz.verify`, `auth.session.establish`, `browser.navigate`, `candidate.verify`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
