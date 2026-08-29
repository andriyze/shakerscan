---
id: skill.web.ssrf-url-fetch-and-cloud-metadata-testing
name: ssrf-url-fetch-and-cloud-metadata-testing
title: 18. SSRF, URL Fetch, and Cloud Metadata Testing
description: Identify direct and blind server-side request forgery in URL fetchers, webhooks, previews,
  imports, redirects, integrations, and parsers using controlled callbacks.
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
- candidate.verify
missing_capabilities:
- dns.resolve
- oob.allocate
- oob.observe
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 100
  max_duration_seconds: 1200
  max_oob_interactions: 12
routing:
  triggers:
  - URL_parameter
  - webhook
  - image_or_document_import
  - link_preview
  - PDF_generation
  - callback
  - server_side_fetch
  indicators:
  - controlled_DNS_callback
  - controlled_HTTP_callback
  - redirect_follow
  - DNS_rebinding_behavior
  - private_or_link_local_reachability
  exclusions:
  - internal_port_scan
  - cloud_credential_retrieval
  - unapproved_private_target
  - uncontrolled_redirect_chain
preconditions:
- compiled_scope_policy
- candidate_server_fetch_feature
- controlled_OOB_service
techniques:
- basic-controlled-callback
- scheme-and-parser-variation
- redirect-validation
- DNS-resolution-validation
- owner-internal-canary
- cloud-metadata-blocking-check
promotion_gate: core.evidence-validation:confirmed
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
server_satisfied_prerequisites: []
source: web-security-agent-skills v2.0.0 18-ssrf-url-fetch-and-cloud-metadata-testing.md
---

# 18. SSRF, URL Fetch, and Cloud Metadata Testing

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Determine whether the server can be induced to send unintended requests or cross network/identity boundaries. Confirm with controlled OOB or owned internal canaries; do not retrieve cloud credentials, scan internal networks, or contact unrelated services.

## Use this skill when

- Inputs accept URLs, webhooks, images, avatars, imports, redirects, feeds, documents, repositories, callbacks, proxy targets, or integration endpoints.
- Server-side processors fetch remote resources asynchronously.
- DNS/HTTP callbacks occur after a unique URL is submitted.
- An LLM/agent tool can browse or call APIs on behalf of a user.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `URL_parameter`
- `webhook`
- `image_or_document_import`
- `link_preview`
- `PDF_generation`
- `callback`
- `server_side_fetch`

**Useful indicators**

- `controlled_DNS_callback`
- `controlled_HTTP_callback`
- `redirect_follow`
- `DNS_rebinding_behavior`
- `private_or_link_local_reachability`

**Hard exclusions**

- `internal_port_scan`
- `cloud_credential_retrieval`
- `unapproved_private_target`
- `uncontrolled_redirect_chain`

**Required preconditions**

- `compiled_scope_policy`
- `candidate_server_fetch_feature`
- `controlled_OOB_service`

**Preferred preconditions**

- `owner_provided_internal_canary`
- `egress_monitoring`
- `redirect_test_service`

## Required context

- Controlled HTTP/DNS callback domain and optional owner-provided internal canary service.
- Stable URL-fetch request, redirect behavior, supported schemes, and asynchronous job visibility.
- Explicit permission status for loopback, private ranges, link-local, cloud metadata, redirects, and DNS-rebinding tests.
- Request, redirect, callback, and latency limits.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `http.request`
- `http.differential_replay`
- `oob.allocate`
- `oob.observe`
- `dns.resolve`

**Optional adapters**

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
| `max_requests` | 100 |
| `max_duration_seconds` | 1200 |
| `max_concurrency` | 2 |
| `max_state_changes` | 0 |
| `max_auth_attempts` | 0 |
| `max_messages` | 0 |
| `max_oob_interactions` | 12 |
| `max_uploaded_bytes` | 0 |
| `max_cost_units` | 180 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `private_or_link_local_destination` | probe targets loopback, RFC1918, link-local, metadata, or owner internal canary | `human_approval` |
| `DNS_rebinding_or_redirect_bypass` | multi-stage resolution or redirect bypass is proposed | `high_risk_human_approval` |

**State access**

- Reads: `compiled_policy`, `endpoint_inventory`, `request_corpus`, `OOB_allocations`, `asset_graph`
- Writes: `server_fetch_observations`, `OOB_events`, `redirect_chains`, `evidence_records`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- The server fetches an attacker-controlled URL directly or asynchronously.
- URL parsing/normalization allows bypass of host, scheme, port, or IP restrictions.
- Redirects, DNS resolution, IPv6, userinfo, encoding, or alternate numeric forms change the effective destination.
- The fetcher can reach internal/loopback/link-local services or attach privileged credentials.
- Blind responses leak via timing, OOB callbacks, error messages, or secondary processing.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- Default proof is a unique callback to tester-controlled infrastructure.
- Do not request cloud metadata credentials, internal admin data, or scan internal ports.
- Use loopback/private/link-local targets only when explicitly approved and preferably an owner-provided canary.
- DNS rebinding and redirect chains require specific high-risk approval and tight egress controls.

## Agent workflow

### 1. Map URL-fetch surfaces

- Catalog URL parameters, webhooks, importers, image/document fetchers, link previews, PDF generators, integrations, XML/HTML parsers, and background jobs.
- Determine whether the client or server performs the fetch.
- Record schemes, redirects, DNS behavior, headers, cookies, source IP, and response handling.

### 2. Confirm server-side fetching

- Submit a unique HTTPS callback URL and correlate DNS/HTTP events to the exact request.
- Use unique path/token per probe and account for security scanners, browsers, and email preview bots.
- Distinguish synchronous response, asynchronous worker, and validation-only callbacks.

### 3. Test destination validation

- Change one URL component at a time: scheme, case, trailing dot, userinfo, port, encoded host, IPv4/IPv6 notation, and hostname resolution.
- Use only controlled destinations representing allow/deny categories.
- Record the effective destination observed by the callback service.

### 4. Test redirects and resolution

- Use a controlled redirector to compare validation-before-redirect versus after each hop.
- Where approved, test DNS changes using an owner-controlled rebinding setup that never resolves to unrelated systems.
- Verify every redirect and resolved IP remains policy-checked.

### 5. Test internal reachability safely

- Prefer an owner-provided internal canary that returns a unique marker.
- If no canary exists, use differential errors/timing without broad scanning.
- Cloud metadata endpoints are not queried by default; an owner may supply a safe metadata emulator.

### 6. Assess privilege and response handling

- Observe whether the fetcher adds credentials, internal headers, client certificates, or privileged network identity—without exfiltrating secrets.
- Check whether fetched content is parsed, rendered, stored, or used by another security-sensitive component.
- Stop after minimal boundary proof.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `basic-controlled-callback` — Basic controlled callback. Select only when the matching trigger and evidence preconditions are present.
- `scheme-and-parser-variation` — Scheme and parser variation. Select only when the matching trigger and evidence preconditions are present.
- `redirect-validation` — Redirect validation. Select only when the matching trigger and evidence preconditions are present.
- `DNS-resolution-validation` — Dns resolution validation. Select only when the matching trigger and evidence preconditions are present.
- `owner-internal-canary` — Owner internal canary. Select only when the matching trigger and evidence preconditions are present.
- `cloud-metadata-blocking-check` — Cloud metadata blocking check. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| URL fetcher | Server makes outbound request | Unique controlled HTTPS callback | Correlated DNS/HTTP event |
| Redirect | Every hop is revalidated | Controlled redirect to second controlled classification | Disallowed class fetched |
| Host parsing | Canonical destination validation is robust | One alternate representation of controlled host | Policy bypass observed |
| Internal canary | Fetcher crosses network boundary | Owner-provided internal marker URL | Marker returned/callback confirmed |
| Credential attachment | Fetcher does not add privileged authority | Controlled endpoint logs safe header metadata | Unexpected internal credential/header present |

## Tool strategy

- Use an OAST service you control, with per-request DNS and HTTP tokens.
- Use a controlled redirector and optional internal metadata emulator/canary.
- Use raw replay plus asynchronous job monitoring.
- Do not use automated internal network/port scanners through an SSRF primitive.

## Evidence required for a finding

- Submitted URL, unique token, callback timestamp, source/network metadata, and exact request correlation.
- For bypass, original and effective canonical destination.
- For internal reachability, owner-controlled canary evidence.
- For privilege, only the minimum safe header/identity evidence with secrets redacted.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/ssrf-url-fetch-and-cloud-metadata-testing.schema.json`.

**Skill-specific evidence fields**

- `fetch_feature`
- `supplied_URL`
- `callback_token`
- `DNS_observed`
- `HTTP_observed`
- `redirect_chain`
- `effective_destination`

**Required validation controls**

- `unique_callback_per_probe`
- `no_internal_enumeration`
- `effective_destination_recorded`
- `callback_timestamp_correlation`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- Browser, email, antivirus, link-preview, or security-scanner callbacks can mimic server fetches.
- DNS-only resolution may not mean an HTTP connection occurred.
- Generic timeout/error differences do not prove internal reachability.
- A client-side fetch is not SSRF.

## Stop conditions

- A callback proves unintended server-side fetching or network-boundary crossing.
- The next step would contact cloud metadata, internal admin services, third parties, or scan ports without explicit approval.
- Fetcher behavior creates large downloads, loops, job backlog, or service degradation.
- Credentials or sensitive response data appear; redact and stop.

## Common remediation patterns

- Use strict URL parsing and allowlist destinations by canonical scheme, host, port, and resolved IP.
- Revalidate after every redirect and DNS resolution; block private, loopback, link-local, and metadata ranges where not required.
- Route fetchers through an egress proxy with DNS pinning, network policy, timeouts, size limits, and credential stripping.
- Use separate low-privilege network identities for fetchers.
- Treat fetched content as untrusted and validate/sanitize before downstream processing.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/ssrf-url-fetch-and-cloud-metadata-testing.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.ssrf-url-fetch-and-cloud-metadata-testing
supporting_skills: []
selected_techniques: [basic-controlled-callback]
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
  evidence_extension_schema: schemas/evidence-extensions/ssrf-url-fetch-and-cloud-metadata-testing.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 23 for Host/proxy routing variants.
- Skill 19/20 when document or file parsers trigger URL fetches.
- Skill 29 for LLM browsing/tool SSRF and excessive agency.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
request_id: avatar-fetch-9
callback_domain: oob.example-test.invalid
allowed_targets: [controlled_oob, owner_internal_canary]
cloud_metadata: prohibited
```

## Authoritative references

- [PortSwigger — SSRF](https://portswigger.net/web-security/ssrf)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP API Security — SSRF](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)

---

## ShakerScan runtime notes

**Support: partial.** ShakerScan has no capability for `dns.resolve`, `oob.allocate`, `oob.observe`, so this skill cannot be bound to a hunt yet. It is published so the gap is visible rather than discovered mid-run.

Bindable capabilities: `http.request`, `authz.verify`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
