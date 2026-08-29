---
id: skill.web.oauth-oidc-saml-and-sso-testing
name: oauth-oidc-saml-and-sso-testing
title: 21. OAuth, OIDC, SAML, and SSO Testing
description: Test authorization-code, token, redirect, issuer, audience, account-linking, logout, and
  assertion validation across OAuth 2.0, OpenID Connect, SAML, and enterprise SSO.
version: 2.0.0
kind: specialist
phase: active_testing
risk: high
support: supported
target_kinds:
- web
- api
capabilities:
- browser.navigate
- browser.interact
- http.request
- authz.verify
- auth.session.establish
- candidate.verify
optional_capabilities: []
missing_capabilities: []
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 220
  max_duration_seconds: 1800
  max_state_changing_requests: 15
routing:
  triggers:
  - OAuth
  - OIDC
  - SAML
  - SSO
  - authorization_code
  - redirect_URI
  - federation_assertion
  - identity_provider
  indicators:
  - state_or_nonce_binding
  - PKCE
  - redirect_validation
  - token_audience_or_issuer
  - account_linking
  - assertion_signature_or_recipient
  exclusions:
  - real_user_token
  - shared_IdP_attack
  - production_signature_wrapping_without_disposable_federation
preconditions:
- compiled_scope_policy
- controlled_client
- controlled_identity
- authorized_RP_and_IdP
techniques:
- OAuth-redirect-and-state
- OIDC-nonce-issuer-audience
- PKCE-binding
- token-and-code-replay
- SAML-recipient-audience-InResponseTo
- account-linking-and-tenant-selection
promotion_gate: core.evidence-validation:confirmed
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
server_satisfied_prerequisites: []
source: web-security-agent-skills v2.0.0 21-oauth-oidc-saml-and-sso-testing.md
---

# 21. OAuth, OIDC, SAML, and SSO Testing

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Verify that every protocol message is bound to the intended client, user, issuer, tenant, redirect, browser session, and transaction. Avoid protocol-level identity confusion, token leakage, account linking flaws, and assertion acceptance errors.

## Use this skill when

- The application uses social login, enterprise SSO, delegated API authorization, mobile deep links, device flow, service accounts, or federated logout.
- Multiple identity providers, tenants, clients, redirect URIs, or custom OAuth brokers are present.
- Authentication/authorization state crosses application and identity-provider origins.
- Account linking or just-in-time provisioning assigns roles or tenant access.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `OAuth`
- `OIDC`
- `SAML`
- `SSO`
- `authorization_code`
- `redirect_URI`
- `federation_assertion`
- `identity_provider`

**Useful indicators**

- `state_or_nonce_binding`
- `PKCE`
- `redirect_validation`
- `token_audience_or_issuer`
- `account_linking`
- `assertion_signature_or_recipient`

**Hard exclusions**

- `real_user_token`
- `shared_IdP_attack`
- `production_signature_wrapping_without_disposable_federation`

**Required preconditions**

- `compiled_scope_policy`
- `controlled_client`
- `controlled_identity`
- `authorized_RP_and_IdP`

**Preferred preconditions**

- `disposable_federation`
- `protocol_trace`
- `second_controlled_identity`

## Required context

- Controlled users at the relying party/client and test identities at each approved IdP/authorization server.
- Client IDs, registered redirect URIs, issuer metadata, expected scopes/claims, tenant mapping, and logout behavior.
- Browser traces and raw protocol messages with secrets redacted.
- Explicit scope for third-party IdP testing; otherwise restrict testing to the application's integration behavior.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `browser.navigate`
- `browser.interact`
- `browser.observe`
- `http.request`
- `http.differential_replay`
- `token.inspect`
- `state.verify`

**Optional adapters**

- `artifact.inspect`
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
| `max_requests` | 220 |
| `max_duration_seconds` | 1800 |
| `max_concurrency` | 2 |
| `max_state_changes` | 15 |
| `max_auth_attempts` | 20 |
| `max_messages` | 0 |
| `max_oob_interactions` | 0 |
| `max_uploaded_bytes` | 0 |
| `max_cost_units` | 240 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `federation_signature_mutation` | signature wrapping, key substitution, or assertion parser ambiguity is proposed | `staging_human_approval` |
| `shared_identity_provider` | action would test provider infrastructure rather than the authorized relying party boundary | `block` |

**State access**

- Reads: `compiled_policy`, `identity_graph`, `SSO_clients`, `protocol_artifacts`, `sessions`, `request_corpus`
- Writes: `SSO_flow_graph`, `protocol_binding_observations`, `identity_link_results`, `evidence_records`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- Authorization responses are not bound to the initiating browser via state, nonce, PKCE, or transaction context.
- Redirect URI validation permits open redirect chains, wildcard abuse, alternate schemes/ports, or client confusion.
- Tokens/assertions are accepted with wrong issuer, audience, client, subject, tenant, signature, time, or token type.
- Account linking/JIT provisioning maps an attacker-controlled identity to an existing or privileged account.
- Tokens leak through URLs, referrers, browser history, logs, front-channel messages, or insecure storage.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- Use controlled clients, users, tenants, and IdPs; do not attack shared provider infrastructure.
- Do not redeem or replay tokens belonging to real users.
- Do not test signature-wrapping or key substitution against production unless a disposable federation setup and explicit high-risk approval exist.
- Preserve protocol values by artifact reference and redact codes, tokens, assertions, cookies, and client secrets.

## Agent workflow

### 1. Map actors and flows

- Identify resource owner, browser/user agent, client/relying party, authorization server/IdP, resource server, broker, and downstream APIs.
- Map authorization code + PKCE, implicit/hybrid legacy, device, client credentials, refresh, OIDC login, SAML POST/Redirect, logout, and account-linking flows.
- Record issuers, endpoints, metadata, keys, client IDs, redirect URIs, scopes, claims, response modes, and tenant selection.

### 2. Test transaction binding

- Verify `state`, OIDC `nonce`, PKCE verifier/challenge, SAML RelayState, request IDs, and browser session are unpredictable, single-use, and correctly bound.
- Use two controlled browser sessions to test login CSRF, response swapping, stale responses, and concurrent transactions.
- Confirm code/assertion cannot be reused.

### 3. Test redirect and front-channel safety

- Compare exact registered redirect rules across case, scheme, port, path, query, fragments, wildcard patterns, and open-redirect chains using controlled destinations.
- Check whether codes/tokens/assertions appear in URLs, referers, history, analytics, error logs, or third-party resources.
- Verify secure response modes and deep-link/app-link ownership.

### 4. Test token/assertion validation

- Validate signature, issuer, audience, authorized party/client, subject, token use/type, time claims, nonce, authentication context, and key source.
- Use one safe controlled mutation at a time.
- Verify ID tokens are not used as API access tokens and tokens for another client/tenant/resource are rejected.

### 5. Test identity mapping and provisioning

- Use controlled identities with matching/case-variant/changed email, subject, domain, tenant, group, and role claims.
- Test account linking, unlinking, JIT provisioning, invitation acceptance, and role/group mapping.
- Confirm immutable issuer+subject identity is not replaced by mutable email alone.

### 6. Test refresh, logout, and revocation

- Verify refresh-token rotation, scope/audience preservation, session termination, back/front-channel logout, and account-disable propagation.
- Check client, IdP, API, and realtime sessions independently.
- Test only controlled sessions.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `OAuth-redirect-and-state` — Oauth redirect and state. Select only when the matching trigger and evidence preconditions are present.
- `OIDC-nonce-issuer-audience` — Oidc nonce issuer audience. Select only when the matching trigger and evidence preconditions are present.
- `PKCE-binding` — Pkce binding. Select only when the matching trigger and evidence preconditions are present.
- `token-and-code-replay` — Token and code replay. Select only when the matching trigger and evidence preconditions are present.
- `SAML-recipient-audience-InResponseTo` — Saml recipient audience inresponseto. Select only when the matching trigger and evidence preconditions are present.
- `account-linking-and-tenant-selection` — Account linking and tenant selection. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| State/nonce/PKCE | Response is bound to initiating transaction | Swap/replay between two controlled sessions | Wrong session accepts response |
| Redirect URI | Only exact registered destination is allowed | One controlled normalization/open-redirect variant | Code/assertion reaches unintended destination |
| Token validation | Issuer/audience/type are strict | Change one controlled claim/token context | Protected request accepted |
| Account linking | Identity mapping cannot collide | Link controlled same-email/different-subject identity | Existing account is taken over/linked |
| Logout/revocation | Federated sessions terminate consistently | Logout/disable then replay controlled sessions | Stale access remains unexpectedly |

## Tool strategy

- Use a browser plus intercepting proxy, OIDC/OAuth test client, SAML message decoder, and local metadata/JWKS inspection.
- Use two isolated browser profiles for transaction swapping and login CSRF.
- Prefer a test IdP/client under owner control for high-risk assertion/key tests.
- Validate current protocol guidance against official RFCs and provider documentation.

## Evidence required for a finding

- Full actor/client/issuer/tenant context and sanitized protocol transcript.
- For transaction flaws, two controlled sessions and exact response swap/replay.
- For token/assertion flaws, the single changed validation property and protected capability.
- For linking, controlled identities and account mapping before/after.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/oauth-oidc-saml-and-sso-testing.schema.json`.

**Skill-specific evidence fields**

- `protocol`
- `flow`
- `client_or_RP`
- `IdP`
- `parameter_or_claim`
- `state_binding`
- `assertion_or_token_decision`
- `resulting_identity`

**Required validation controls**

- `controlled_clients_and_identities`
- `resulting_identity_verified`
- `protocol_values_redacted`
- `provider_boundary_respected`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- A missing nonce may be irrelevant in a pure OAuth authorization flow that does not use an ID token; assess the actual protocol.
- A redirect URI that looks broad may still be constrained server-side.
- Decoding a SAML/JWT message does not bypass its signature.
- Email matching may be an intentional verified-domain policy; verify assurance and takeover conditions.

## Stop conditions

- A token/assertion belongs to a real user or unapproved tenant.
- Testing would target an out-of-scope provider or shared federation infrastructure.
- Proof requires signing malicious assertions, key-server redirection, or provider disruption without explicit approval.
- A controlled identity becomes linked to a production-critical account.

## Common remediation patterns

- Follow OAuth 2.0 Security BCP, use authorization code with PKCE, exact redirect matching, state, and OIDC nonce.
- Validate signature, issuer, audience, client/authorized party, token type, time, nonce, and key source.
- Map identities by stable issuer+subject and require secure confirmation for linking.
- Keep tokens out of URLs/logs, use secure storage, narrow scopes/audiences, short lifetimes, rotation, and revocation.
- Centralize tenant/role provisioning and test logout/disable propagation end to end.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/oauth-oidc-saml-and-sso-testing.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.oauth-oidc-saml-and-sso-testing
supporting_skills: []
selected_techniques: [OAuth-redirect-and-state]
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
  evidence_extension_schema: schemas/evidence-extensions/oauth-oidc-saml-and-sso-testing.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 06 for local login and Skill 07 for resulting sessions/tokens.
- Skill 08 for account linking, invitations, and recovery.
- Skill 17 for cross-origin/login CSRF and Skill 23 for redirect/host poisoning.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
client: web_app_test
issuer: https://idp.example.test
flows: [authorization_code_pkce, oidc_login, logout]
identities: [user_a, user_b]
```

## Authoritative references

- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OASIS SAML 2.0 Technical Overview](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)
- [PortSwigger — OAuth authentication](https://portswigger.net/web-security/oauth)

---

## ShakerScan runtime notes

**Support: supported.** Every adapter this skill requires maps to a planner-visible capability, so it can be bound to a hunt.

Bindable capabilities: `browser.navigate`, `browser.interact`, `http.request`, `authz.verify`, `auth.session.establish`, `candidate.verify`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
