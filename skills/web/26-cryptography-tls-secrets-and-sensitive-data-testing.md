---
id: skill.web.cryptography-tls-secrets-and-sensitive-data-testing
name: cryptography-tls-secrets-and-sensitive-data-testing
title: 26. Cryptography, TLS, Secrets, and Sensitive Data Testing
description: Test transport protection, cryptographic use, randomness, secret exposure, browser/storage
  leakage, cache behavior, and sensitive-data handling without using discovered secrets beyond minimal
  validation.
version: 2.0.0
kind: specialist
phase: active_testing
risk: medium
support: supported
target_kinds:
- web
- api
capabilities:
- tls.inspect
- http.request
- browser.navigate
- auth.session.establish
- artifact.inspect
optional_capabilities: []
missing_capabilities: []
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 600
  max_duration_seconds: 1200
routing:
  triggers:
  - TLS_endpoint
  - sensitive_data_flow
  - cookie_or_storage
  - secret_candidate
  - cryptographic_token
  - random_identifier
  - cacheable_sensitive_response
  indicators:
  - weak_transport_policy
  - sensitive_data_in_URL_or_log
  - secret_exposure
  - predictable_value
  - unsafe_crypto_construction
  - retention_gap
  exclusions:
  - use_of_discovered_secret
  - real_user_interception
  - unapproved_downgrade
  - unrelated_system_access
preconditions:
- compiled_scope_policy
- approved_asset_or_artifact
techniques:
- TLS-policy-inspection
- HTTP-browser-data-leakage
- secret-discovery-and-classification
- randomness-and-token-structure
- crypto-construction-review
- sensitive-data-cache-and-retention
promotion_gate: core.evidence-validation:confirmed
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
server_satisfied_prerequisites: []
source: web-security-agent-skills v2.0.0 26-cryptography-tls-secrets-and-sensitive-data-testing.md
---

# 26. Cryptography, TLS, Secrets, and Sensitive Data Testing

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Determine whether sensitive data is protected in transit, at rest where visibility exists, in browser/client storage, and throughout logs, URLs, errors, exports, and backups. Distinguish obsolete cryptography from demonstrable exposure and handle secrets as hazardous evidence.

## Use this skill when

- The application handles credentials, tokens, personal data, financial/health data, documents, encryption keys, signed values, or security-sensitive identifiers.
- TLS, certificate, HSTS, mixed-content, cookie, or browser-storage posture needs review.
- JavaScript, source maps, errors, configuration, backups, or responses may expose secrets.
- The application implements custom encryption, signing, hashing, token generation, or password storage.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `TLS_endpoint`
- `sensitive_data_flow`
- `cookie_or_storage`
- `secret_candidate`
- `cryptographic_token`
- `random_identifier`
- `cacheable_sensitive_response`

**Useful indicators**

- `weak_transport_policy`
- `sensitive_data_in_URL_or_log`
- `secret_exposure`
- `predictable_value`
- `unsafe_crypto_construction`
- `retention_gap`

**Hard exclusions**

- `use_of_discovered_secret`
- `real_user_interception`
- `unapproved_downgrade`
- `unrelated_system_access`

**Required preconditions**

- `compiled_scope_policy`
- `approved_asset_or_artifact`

**Preferred preconditions**

- `data_classification`
- `key_management_context`
- `retention_policy`

## Required context

- Approved origins and service ports, data classification, cryptographic requirements, and retention policy.
- Browser/network traces and optional source/configuration access.
- Rules for secret validation, rotation notification, and evidence redaction.
- Test accounts and synthetic sensitive data.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `tls.inspect`
- `http.request`
- `browser.observe`
- `artifact.inspect`
- `token.inspect`

**Optional adapters**

- `javascript.analyze`
- `dependency.analyze`
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
| `max_requests` | 600 |
| `max_duration_seconds` | 1200 |
| `max_concurrency` | 6 |
| `max_state_changes` | 0 |
| `max_auth_attempts` | 0 |
| `max_messages` | 0 |
| `max_oob_interactions` | 0 |
| `max_uploaded_bytes` | 0 |
| `max_cost_units` | 200 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `secret_validation` | validation would use a discovered credential beyond local format/metadata checks | `block` |

**State access**

- Reads: `compiled_policy`, `asset_graph`, `data_classification`, `client_artifact_graph`, `secret_candidates`
- Writes: `TLS_profiles`, `sensitive_data_observations`, `secret_evidence`, `crypto_review_records`, `evidence_records`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- TLS/certificate configuration permits downgrade, weak protocols/ciphers, hostname errors, mixed content, or missing HSTS where appropriate.
- Credentials/tokens/sensitive fields appear in URLs, browser storage, caches, logs, analytics, referrers, errors, or client bundles.
- Secrets are hard-coded, overprivileged, long-lived, shared across environments, or exposed in downloadable artifacts.
- Password hashing, encryption, signatures, randomness, or key management is weak or incorrectly implemented.
- Sensitive responses are cached, indexed, exported, or retained beyond intended boundaries.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- Do not use a discovered secret to access unrelated systems or data; perform only approved metadata/identity validation and then stop.
- Redact secrets and sensitive data before prompts, screenshots, logs, or reports.
- Do not downgrade or intercept real-user traffic.
- Cryptographic findings must distinguish theoretical weakness, policy noncompliance, and demonstrated exposure.

## Agent workflow

### 1. Map sensitive data and cryptographic boundaries

- Identify data classes, collection points, transit paths, storage locations, browser/client persistence, exports, logs, third parties, and deletion lifecycle.
- Map TLS termination, service-to-service links, encryption/signing functions, key stores, and trust anchors.
- Use synthetic markers to trace data where possible.

### 2. Test transport security

- Inspect protocol versions, ciphers, certificate chain, hostname, expiry, revocation/stapling behavior, ALPN, HSTS, redirects, mixed content, and secure cookie use.
- Check alternate ports, API origins, upload/download hosts, WebSockets, and direct origins.
- Do not overstate minor cipher preferences without practical or policy impact.

### 3. Test browser and HTTP leakage

- Search URLs, query strings, fragments, Referer, history, local/session storage, IndexedDB, service workers, caches, autocomplete, downloaded files, and page source.
- Review Cache-Control, Pragma, content disposition, and sensitive response behavior.
- Use controlled browser profiles and synthetic data.

### 4. Find and classify secrets

- Inspect client bundles, source maps, configuration, error pages, public files, backups, containers/build artifacts where authorized, and repository history if supplied.
- Classify values as public identifier, publishable key, restricted secret, expired/test value, or unknown.
- Validate only the issuer/identity/scope with a non-destructive call if explicitly allowed; notify owner for rotation.

### 5. Review cryptographic construction

- With source/config access, inspect approved algorithms/modes, nonce/IV generation, authentication, key derivation, password hashing, randomness, key rotation, separation, and error handling.
- For black-box tokens, test obvious predictability/reuse only with a small controlled sample.
- Avoid cryptanalysis claims without sufficient samples and expertise.

### 6. Test lifecycle and retention

- Verify logout, reset, deletion, export expiry, share revocation, cache invalidation, and backup/log retention expectations where observable.
- Check that sensitive values are not duplicated into lower-trust systems.
- Record gaps as confirmed, inferred, or requiring internal verification.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `TLS-policy-inspection` — Tls policy inspection. Select only when the matching trigger and evidence preconditions are present.
- `HTTP-browser-data-leakage` — Http browser data leakage. Select only when the matching trigger and evidence preconditions are present.
- `secret-discovery-and-classification` — Secret discovery and classification. Select only when the matching trigger and evidence preconditions are present.
- `randomness-and-token-structure` — Randomness and token structure. Select only when the matching trigger and evidence preconditions are present.
- `crypto-construction-review` — Crypto construction review. Select only when the matching trigger and evidence preconditions are present.
- `sensitive-data-cache-and-retention` — Sensitive data cache and retention. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| TLS endpoint | Strong authenticated transport is enforced | Metadata-only protocol/certificate scan | Weak/downgrade/hostname exposure confirmed |
| Sensitive URL | Secrets are not placed in URLs/referrers | Use synthetic token/value through normal flow | Value appears in URL/history/referrer/log |
| Browser storage | Sensitive tokens use appropriate storage/lifetime | Inspect controlled profile | Long-lived accessible secret exposed |
| Client artifact | Restricted secret is absent | Local secret scan plus approved metadata validation | Live restricted capability confirmed |
| Custom token/randomness | Values are unpredictable and unique | Small controlled sample and reuse checks | Deterministic/repeated structure with exploit consequence |

## Tool strategy

- Use `testssl.sh`, `sslyze`, browser security panels, raw HTTP, local secret scanners, and repository/SBOM tools where authorized.
- Use a secret manager for test credentials and an encrypted evidence store.
- Prefer source/config review for cryptographic correctness over black-box guessing.
- Never submit target secrets to public validation websites.

## Evidence required for a finding

- Endpoint, protocol/certificate metadata, exact data path, storage/cache location, and synthetic marker where applicable.
- For secrets, redacted fingerprint, source location, classification, approved validation result, and rotation status.
- For cryptographic implementation, code/config path and concrete violated property.
- Demonstrated exposure separated from policy recommendations.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/cryptography-tls-secrets-and-sensitive-data-testing.schema.json`.

**Skill-specific evidence fields**

- `asset_or_artifact`
- `data_class`
- `transport_or_storage_boundary`
- `cryptographic_property`
- `secret_location`
- `randomness_or_lifecycle_evidence`
- `demonstrated_exposure`

**Required validation controls**

- `secret_values_redacted`
- `metadata_only_secret_validation`
- `theory_vs_demonstrated_exposure_separated`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- A public API key or client ID is not automatically secret.
- Older cipher support may be low risk when not negotiable by relevant clients or prohibited by policy; verify.
- Entropy cannot be reliably judged from a handful of opaque tokens.
- Sensitive data seen in a tester-controlled debug environment may not exist in production; report environment.

## Stop conditions

- A live restricted secret or real sensitive data is discovered—capture minimal proof, redact, notify, and stop using it.
- Testing would require intercepting real users, downgrading production traffic, or accessing unrelated systems.
- Cryptographic analysis lacks sufficient source/config/sample evidence.
- A scan affects legacy/fragile services or triggers health alerts.

## Common remediation patterns

- Use modern TLS, valid certificates, HSTS where appropriate, secure redirects, and protected service-to-service transport.
- Keep credentials/tokens out of URLs, logs, analytics, client bundles, and long-lived browser storage.
- Use managed secret stores, short-lived credentials, least privilege, environment separation, and rotation.
- Use vetted authenticated encryption, modern password hashing, secure randomness, nonce/key lifecycle, and no custom cryptography.
- Apply no-store/private caching and retention/deletion controls to sensitive data.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/cryptography-tls-secrets-and-sensitive-data-testing.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.cryptography-tls-secrets-and-sensitive-data-testing
supporting_skills: []
selected_techniques: [TLS-policy-inspection]
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
  evidence_extension_schema: schemas/evidence-extensions/cryptography-tls-secrets-and-sensitive-data-testing.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 07 for session/token lifecycle.
- Skill 27 for build/dependency/artifact secret exposure and integrity.
- Skill 28 for headers, debug output, backups, and logging.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
origins: [https://app.example.test, https://api.example.test]
data_classes: [credentials, tokens, profile_pii]
secret_validation: metadata_only
real_user_data: prohibited
```

## Authoritative references

- [OWASP Top 10 2025 — Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [Mozilla TLS Configuration Guidelines](https://wiki.mozilla.org/Security/Server_Side_TLS)

---

## ShakerScan runtime notes

**Support: supported.** Hunt can inspect bounded redacted client-artifact windows while preserving token values as worker-private material. Network validation of a discovered secret remains prohibited unless separate authority and a managed principal exist.

Bindable capabilities: `tls.inspect`, `http.request`, `browser.navigate`, `auth.session.establish`, `artifact.inspect`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
