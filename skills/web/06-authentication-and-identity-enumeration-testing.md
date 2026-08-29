---
id: skill.web.authentication-and-identity-enumeration-testing
name: authentication-and-identity-enumeration-testing
title: 06. Authentication and Identity Enumeration Testing
description: Test login and identity-verification controls for enumeration, bypass, weak verification,
  alternate-channel inconsistencies, and unsafe authentication transitions.
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
- candidate.verify
optional_capabilities: []
missing_capabilities: []
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 100
  max_duration_seconds: 600
  max_state_changing_requests: 2
routing:
  triggers:
  - login
  - password_authentication
  - username_or_email_lookup
  - alternate_auth_channel
  - authentication_error_difference
  indicators:
  - identity_existence_signal
  - credential_verification
  - lockout
  - MFA_transition
  - alternate_endpoint
  exclusions:
  - real_account_enumeration
  - credential_stuffing
  - shared_identity_provider_without_scope
preconditions:
- compiled_scope_policy
- controlled_accounts
- lockout_budget
techniques:
- surface-mapping
- enumeration-differential
- credential-verification-control
- incomplete-flow-check
- alternate-channel-consistency
- bounded-anti-automation-check
promotion_gate: core.evidence-validation:confirmed
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
server_satisfied_prerequisites: []
source: web-security-agent-skills v2.0.0 06-authentication-and-identity-enumeration-testing.md
---

# 06. Authentication and Identity Enumeration Testing

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Determine whether the application reliably establishes the claimed identity across every login channel without enabling account discovery, credential attacks, bypass, or inconsistent enforcement.

## Use this skill when

- The application supports passwords, magic links, passkeys, social/enterprise login, device codes, API keys, or multiple login endpoints.
- Web, mobile/API, legacy, admin, or tenant-specific authentication behaves differently.
- Authentication must be mapped before session, authorization, or recovery testing.
- Disabled, locked, unverified, or deprovisioned user states need validation.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `login`
- `password_authentication`
- `username_or_email_lookup`
- `alternate_auth_channel`
- `authentication_error_difference`

**Useful indicators**

- `identity_existence_signal`
- `credential_verification`
- `lockout`
- `MFA_transition`
- `alternate_endpoint`

**Hard exclusions**

- `real_account_enumeration`
- `credential_stuffing`
- `shared_identity_provider_without_scope`

**Required preconditions**

- `compiled_scope_policy`
- `controlled_accounts`
- `lockout_budget`

**Preferred preconditions**

- `controlled_nonexistent_identity`
- `owner_alert_thresholds`

## Required context

- Controlled accounts in valid, disabled, locked, unverified, and different-tenant states where possible.
- Permitted failed-attempt budget, lockout behavior, notification limits, and enumeration scope.
- Expected authentication methods, identity providers, tenant selection, and assurance requirements.
- Browser and raw HTTP access to all approved login channels.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `http.request`
- `http.differential_replay`
- `browser.navigate`
- `browser.interact`
- `state.verify`

**Optional adapters**

- `channel.observe`
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
| `max_requests` | 100 |
| `max_duration_seconds` | 600 |
| `max_concurrency` | 1 |
| `max_state_changes` | 2 |
| `max_auth_attempts` | 20 |
| `max_messages` | 0 |
| `max_oob_interactions` | 0 |
| `max_uploaded_bytes` | 0 |
| `max_cost_units` | 100 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `enumeration_or_lockout_boundary` | test exceeds owned identities or approaches lockout/alert thresholds | `block` |

**State access**

- Reads: `compiled_policy`, `identities`, `auth_surfaces`, `request_corpus`, `runtime_health`
- Writes: `authentication_observations`, `identity_signal_profiles`, `evidence_records`, `hypothesis_events`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- Valid and invalid identities are distinguishable through message, status, timing, redirects, headers, or side effects.
- Alternate endpoints, methods, content types, or API versions enforce weaker verification.
- Partially completed authentication or verification states can access protected resources.
- Disabled, deleted, locked, or deprovisioned accounts retain an alternate login path.
- Anti-automation controls are inconsistently keyed or allow easy account-lockout abuse.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- Never perform credential stuffing, password spraying, or broad enumeration without a separately approved plan and owned dataset.
- Use only test accounts and generated credentials.
- Stay below lockout and alert thresholds unless the lockout mechanism itself is the approved target.
- Do not test shared identity-provider infrastructure unless explicitly included.

## Agent workflow

### 1. Map authentication surfaces

- Identify password, API token, magic-link, passkey, device authorization, SSO, admin, mobile, legacy, and recovery entry points.
- Record pre-auth cookies, CSRF state, tenant selectors, redirects, anti-automation controls, and required verification steps.
- Determine how the identity is selected: email, username, phone, tenant, domain, invitation, or external provider.

### 2. Test enumeration consistently

- Compare owned valid and synthetic invalid identifiers using normalized message, status, timing, redirect, headers, rate-limit behavior, and secondary effects.
- Repeat across login, registration, password reset, invitation, and magic-link endpoints.
- Interleave controls to separate real differences from provider latency or cache effects.

### 3. Test credential verification

- Verify password policy, case/Unicode normalization, disabled/unverified state, tenant binding, and rejected credentials.
- Check alternate content types, API versions, methods, and legacy endpoints for inconsistent verification.
- Use a tiny approved wrong-password set to observe throttling and lockout.

### 4. Test incomplete and alternate flows

- Attempt direct navigation to callbacks, post-login resources, remembered-device paths, and authenticated endpoints before all steps complete.
- Change tenant, return URL, device ID, or flow identifier one at a time.
- Verify disabled/deleted/deprovisioned users cannot authenticate through fallback channels.

### 5. Evaluate anti-automation safely

- Measure small sequences across account, IP, device, session, endpoint, and tenant keys.
- Check whether success resets counters and whether equivalent endpoints share protection.
- Determine whether an attacker could lock out a victim cheaply without attempting broad abuse.

### 6. Confirm authenticated capability

- Do not treat a cookie, token, or redirect as proof of authentication.
- Attempt one benign protected read or identity endpoint.
- Record the established identity, assurance level, tenant, and session material for Skill 07.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `surface-mapping` — Surface mapping. Select only when the matching trigger and evidence preconditions are present.
- `enumeration-differential` — Enumeration differential. Select only when the matching trigger and evidence preconditions are present.
- `credential-verification-control` — Credential verification control. Select only when the matching trigger and evidence preconditions are present.
- `incomplete-flow-check` — Incomplete flow check. Select only when the matching trigger and evidence preconditions are present.
- `alternate-channel-consistency` — Alternate channel consistency. Select only when the matching trigger and evidence preconditions are present.
- `bounded-anti-automation-check` — Bounded anti automation check. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| Login response | Valid/invalid users are indistinguishable | Compare controlled valid and synthetic invalid identifiers | No stable semantic/timing/side-effect difference |
| Disabled account | State is enforced everywhere | Attempt each approved channel | All reject before protected session |
| Alternate parser/version | No weaker handler exists | Replay with one alternate type/version | Same verification outcome |
| Partial flow | All steps are server-enforced | Directly access callback/resource with pre-auth state | Protected access remains denied |
| Rate limiting | Attempts are bounded without trivial lockout abuse | Small stepped sequence | Consistent appropriate throttling |

## Tool strategy

- Use browser automation for complete flows and raw HTTP replay for controlled differentials.
- Inject test credentials from a secret store rather than prompts or shell history.
- Use interleaved samples for timing analysis.
- Track notification and lockout side effects per test account.

## Evidence required for a finding

- Exact endpoint, account state, identity input, and whether a protected capability was obtained.
- Repeated normalized differences for enumeration; a single response is insufficient.
- For bypass, proof of authenticated capability, not merely a redirect or opaque cookie.
- For rate controls, attempt count, keying, reset behavior, and safety cap.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/authentication-and-identity-enumeration-testing.schema.json`.

**Skill-specific evidence fields**

- `auth_surface`
- `controlled_identity_class`
- `control_response`
- `probe_response`
- `auth_result`
- `lockout_or_alert_metric`

**Required validation controls**

- `controlled_existing_and_nonexisting_identities`
- `interleaved_controls`
- `authenticated_capability_confirmation`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- Different messages may have low impact when identities are public; document context.
- Email/SMS/provider timing can mimic enumeration.
- A pre-auth cookie or opaque token is not a valid session.
- A login page returning 200 after failure is normal.

## Stop conditions

- A test account locks unexpectedly or notifications reach non-test recipients.
- The next step requires leaked credentials, broad enumeration, or real-user accounts.
- Testing affects an out-of-scope shared identity provider.
- Service health or fraud monitoring is triggered beyond approved expectations.

## Common remediation patterns

- Use uniform responses and timing for identity-dependent pre-auth flows.
- Centralize authentication and account-state enforcement across all channels and versions.
- Rate limit by multiple signals while avoiding attacker-triggered victim lockout.
- Require all verification steps server-side before issuing a privileged session.
- Disable obsolete or fallback authentication paths and monitor anomalies.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/authentication-and-identity-enumeration-testing.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.authentication-and-identity-enumeration-testing
supporting_skills: []
selected_techniques: [surface-mapping]
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
  evidence_extension_schema: schemas/evidence-extensions/authentication-and-identity-enumeration-testing.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 07 for issued sessions, cookies, tokens, and JWTs.
- Skill 08 for registration, recovery, MFA, and identity changes.
- Skill 21 for OAuth/OIDC/SAML-specific behavior.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
login_url: https://app.example.test/login
accounts: [valid_test, disabled_test, unverified_test]
attempt_budget: 12_total_failures
notification_policy: test_channels_only
```

## Authoritative references

- [OWASP WSTG — Authentication Testing](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [PortSwigger — Authentication vulnerabilities](https://portswigger.net/web-security/authentication)

---

## ShakerScan runtime notes

**Support: supported.** Every adapter this skill requires maps to a planner-visible capability, so it can be bound to a hunt.

Bindable capabilities: `http.request`, `authz.verify`, `browser.navigate`, `browser.interact`, `candidate.verify`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
