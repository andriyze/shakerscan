---
id: skill.web.account-recovery-mfa-and-lifecycle-testing
name: account-recovery-mfa-and-lifecycle-testing
title: 08. Account Recovery, MFA, Invitation, and Lifecycle Testing
description: Test registration, verification, invitations, password reset, magic links, identity changes,
  MFA enrollment/recovery, deletion, and reactivation.
version: 2.0.0
kind: specialist
phase: active_testing
risk: medium
support: partial
target_kinds:
- web
- api
capabilities:
- http.request
- authz.verify
- browser.navigate
- browser.interact
- candidate.verify
optional_capabilities:
- auth.session.establish
missing_capabilities:
- channel.observe
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 140
  max_duration_seconds: 1200
  max_state_changing_requests: 15
routing:
  triggers:
  - registration
  - email_verification
  - password_reset
  - magic_link
  - MFA_enrollment
  - MFA_recovery
  - invitation
  - identity_change
  - deletion_or_reactivation
  indicators:
  - one_time_token
  - controlled_message
  - account_state_transition
  - factor_binding
  - identity_link
  exclusions:
  - real_account_recovery
  - uncontrolled_email_or_SMS_recipient
  - social_engineering
preconditions:
- compiled_scope_policy
- controlled_accounts
- controlled_delivery_channels
techniques:
- registration-verification
- reset-and-magic-link-lifecycle
- MFA-enrollment-and-recovery
- invitation-and-identity-linking
- disable-delete-reactivate
promotion_gate: core.evidence-validation:confirmed
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
server_satisfied_prerequisites: []
source: web-security-agent-skills v2.0.0 08-account-recovery-mfa-and-lifecycle-testing.md
---

# 08. Account Recovery, MFA, Invitation, and Lifecycle Testing

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Find account-takeover paths that bypass primary login by abusing weaker lifecycle transitions. Verify every token, channel, and transition is bound to the correct user, tenant, intent, and time window.

## Use this skill when

- The app supports registration, invitations, email/phone verification, password reset, magic links, MFA, account linking, or deletion.
- Primary authentication is strong but recovery or identity-change workflows may be weaker.
- Multi-tenant onboarding and invitations determine initial role or tenant access.
- Security-sensitive changes should revoke sessions or require re-authentication.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `registration`
- `email_verification`
- `password_reset`
- `magic_link`
- `MFA_enrollment`
- `MFA_recovery`
- `invitation`
- `identity_change`
- `deletion_or_reactivation`

**Useful indicators**

- `one_time_token`
- `controlled_message`
- `account_state_transition`
- `factor_binding`
- `identity_link`

**Hard exclusions**

- `real_account_recovery`
- `uncontrolled_email_or_SMS_recipient`
- `social_engineering`

**Required preconditions**

- `compiled_scope_policy`
- `controlled_accounts`
- `controlled_delivery_channels`

**Preferred preconditions**

- `synthetic_organization`
- `account_state_verifier`

## Required context

- At least two controlled users, test mailboxes/phone channels, and relevant tenant roles.
- Message-send budget, token lifetime expectations, and prohibited actions.
- Expected re-authentication and approval requirements.
- A lifecycle model covering invited, pending, active, MFA-enrolled, locked, disabled, deleted, and reactivated states.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `http.request`
- `http.differential_replay`
- `browser.navigate`
- `browser.interact`
- `channel.observe`
- `state.verify`

**Optional adapters**

- `token.inspect`
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
| `max_requests` | 140 |
| `max_duration_seconds` | 1200 |
| `max_concurrency` | 2 |
| `max_state_changes` | 15 |
| `max_auth_attempts` | 10 |
| `max_messages` | 12 |
| `max_oob_interactions` | 0 |
| `max_uploaded_bytes` | 0 |
| `max_cost_units` | 150 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `external_message_or_identity_change` | recipient or identity is not a controlled test channel/account | `block` |

**State access**

- Reads: `compiled_policy`, `identities`, `account_state_graph`, `controlled_channels`, `request_corpus`
- Writes: `account_state_graph`, `lifecycle_observations`, `message_events`, `evidence_records`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- Invitation or verification tokens can be retargeted to another user, tenant, or role.
- Reset or magic-link tokens leak, remain reusable, last too long, or are weakly bound.
- MFA can be bypassed, disabled, reset, or replaced through a weaker path.
- Identity changes allow account collision, session retention, or takeover.
- Deletion, disablement, or re-registration restores stale privileges or sessions.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- Send messages only to controlled test channels and keep volumes minimal.
- Do not attempt SIM swapping, mailbox compromise, social engineering, or recovery of real accounts.
- Use synthetic organizations/data for invitations, deletion, and reactivation.
- Never guess or enumerate live reset/verification tokens.

## Agent workflow

### 1. Model account states and transitions

- List states, actors, tokens, approvals, notifications, sessions, and expected side effects.
- Identify parallel web, API, mobile, and SSO paths.
- Record which channel proves control of email, phone, device, organization, or factor.

### 2. Test registration and verification

- Check duplicate, case, Unicode, tenant, invitation, and initial-role handling.
- Try changing email, phone, tenant, role, or object ID one at a time using controlled accounts.
- Verify tokens expire, are single-use, and cannot be replayed after the state changes.

### 3. Test password reset and magic links

- Assess enumeration, token leakage in URLs/referrers/logs, host influence, expiry, reuse, and user/action binding.
- Verify reset invalidates relevant sessions according to policy.
- Test only issued controlled tokens; do not brute force.

### 4. Test MFA enrollment and recovery

- Verify strong re-authentication before enabling, disabling, replacing, or viewing recovery factors.
- Test OTP reuse, expiry, attempts, recovery codes, remembered devices, backup channels, and factor-change notifications.
- Confirm all alternate login and sensitive-action paths enforce MFA consistently.

### 5. Test identity changes and linking

- Check email/phone change confirmations, old-channel notification, session rotation, and collision with existing identities.
- Test social/enterprise account linking only with controlled identities.
- Verify tenant and role bindings survive or reset correctly.

### 6. Test disable, delete, and reactivation

- Replay sessions, tokens, API keys, invitations, and share links after state change.
- Re-register or reactivate controlled identities and check for stale ownership or memberships.
- Confirm cleanup across realtime and background channels.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `registration-verification` — Registration verification. Select only when the matching trigger and evidence preconditions are present.
- `reset-and-magic-link-lifecycle` — Reset and magic link lifecycle. Select only when the matching trigger and evidence preconditions are present.
- `MFA-enrollment-and-recovery` — Mfa enrollment and recovery. Select only when the matching trigger and evidence preconditions are present.
- `invitation-and-identity-linking` — Invitation and identity linking. Select only when the matching trigger and evidence preconditions are present.
- `disable-delete-reactivate` — Disable delete reactivate. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| Invitation | Token is bound to email, tenant, and role | Open owned invitation under another test identity | Server prevents reassignment/escalation |
| Reset token | Single-use, expiring, user-bound | Use once, replay, then alter user ID | Replay/retarget rejected |
| MFA disable | Requires strong re-authentication | Attempt with session only and alternate API | Change blocked |
| Identity change | No collision/hijack | Use second controlled identity with normalization edge case | Ownership remains correct |
| Deletion/reactivation | Old access is fully revoked | Replay sessions/keys then re-register | No stale access returns |

## Tool strategy

- Use controlled inbox APIs or local mail capture for deterministic link/token analysis.
- Use browser automation for cross-tab and login-state behavior; raw HTTP for binding tests.
- Track every message/token by account, purpose, creation time, and consumption state.
- Use test phone/SMS infrastructure only when approved.

## Evidence required for a finding

- State before/after, actor, token purpose, channel, timestamp, and session effects.
- For takeover, control of the synthetic victim account through the flawed lifecycle path.
- For token issues, valid use plus replay/retarget control.
- Only test-controlled notifications and messages.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/account-recovery-mfa-and-lifecycle-testing.schema.json`.

**Skill-specific evidence fields**

- `lifecycle_transition`
- `controlled_channel`
- `token_event`
- `before_state`
- `after_state`
- `message_count`

**Required validation controls**

- `controlled_channel_only`
- `single_use_and_expiry_retest`
- `authoritative_account_state`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- Long random-looking tokens are not proven secure; lifecycle and binding matter.
- A visually reusable link may fail server-side.
- Notification is not the same as approval from the old factor.
- Client-side MFA prompts do not prove server-side enforcement.

## Stop conditions

- Any message would reach a non-test recipient.
- A test could remove access to a shared or production-critical account.
- The next step requires token guessing, provider abuse, or social engineering.
- A state transition affects real tenant membership or data.

## Common remediation patterns

- Use high-entropy, short-lived, single-use, purpose-bound tokens.
- Bind invitations and verification to intended identity, tenant, role, and transaction.
- Require strong re-authentication and independent confirmation for MFA and identity changes.
- Rotate/revoke sessions and keys after resets, factor changes, disablement, or deletion.
- Prevent normalization collisions and carefully define re-registration/reactivation semantics.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/account-recovery-mfa-and-lifecycle-testing.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.account-recovery-mfa-and-lifecycle-testing
supporting_skills: []
selected_techniques: [registration-verification]
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
  evidence_extension_schema: schemas/evidence-extensions/account-recovery-mfa-and-lifecycle-testing.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 06 for primary authentication; Skill 07 for revocation effects.
- Skill 09 for invitation roles and tenant boundaries.
- Skill 23 when reset links may be influenced by Host/proxy headers.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
accounts: [user_a, user_b, invited_user, mfa_user]
channels: [test_mailbox_a, test_mailbox_b]
flows: [invite, verify, reset, magic_link, mfa_recovery, delete]
message_budget: 20
```

## Authoritative references

- [OWASP WSTG — Identity Management](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/03-Identity_Management_Testing/)
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)

---

## ShakerScan runtime notes

**Support: partial.** ShakerScan has no capability for `channel.observe`, so this skill cannot be bound to a hunt yet. It is published so the gap is visible rather than discovered mid-run.

Bindable capabilities: `http.request`, `authz.verify`, `browser.navigate`, `browser.interact`, `candidate.verify`. Optional when the hunt already holds them: `auth.session.establish`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
