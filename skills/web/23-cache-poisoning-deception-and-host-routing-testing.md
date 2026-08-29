---
id: skill.web.cache-poisoning-deception-and-host-routing-testing
name: cache-poisoning-deception-and-host-routing-testing
title: 23. Cache Poisoning, Cache Deception, Host, and Proxy Routing Testing
description: Test cache-key omissions, unkeyed input, path normalization, web cache deception, Host/Forwarded
  trust, absolute URL generation, and reverse-proxy routing with unique canaries.
version: 2.0.0
kind: specialist
phase: active_testing
risk: high
support: supported
target_kinds:
- web
- api
capabilities:
- http.request
- authz.verify
- browser.navigate
- candidate.verify
optional_capabilities:
- tls.inspect
missing_capabilities: []
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 140
  max_duration_seconds: 1200
  max_state_changing_requests: 8
routing:
  triggers:
  - shared_cache
  - CDN
  - reverse_proxy
  - Host_header
  - Forwarded_header
  - absolute_URL_generation
  - path_normalization
  indicators:
  - unkeyed_input
  - cache_hit_with_canary
  - cross_identity_cached_response
  - host_routing_difference
  - web_cache_deception
  exclusions:
  - popular_shared_path
  - homepage_or_login_poisoning
  - unrelated_internal_routing
  - long_TTL_without_purge
preconditions:
- compiled_scope_policy
- unique_low_traffic_test_path
- cache_buster_or_purge_strategy
techniques:
- cache-key-discovery
- unkeyed-header-or-query
- web-cache-deception
- path-normalization-differential
- Host-and-Forwarded-trust
- absolute-URL-generation
promotion_gate: core.evidence-validation:confirmed
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
server_satisfied_prerequisites: []
source: web-security-agent-skills v2.0.0 23-cache-poisoning-deception-and-host-routing-testing.md
---

# 23. Cache Poisoning, Cache Deception, Host, and Proxy Routing Testing

> Runtime contract: v2.0.0. The Markdown methodology guides reasoning; the YAML manifest and JSON Schemas govern routing and execution.

## Mission

Determine whether shared caches or proxy routing cause attacker-controlled content, private responses, or reset links to be served in the wrong context. Avoid poisoning popular/shared routes by using unique test paths, cache busters, controlled identities, and immediate cleanup.

## Use this skill when

- The app is behind a CDN, reverse proxy, API gateway, or application cache.
- Responses include cache headers, Age, surrogate keys, varying behavior, or static-extension routing.
- Host, X-Forwarded-Host, Forwarded, X-Original-URL, rewrite headers, or absolute URLs influence behavior.
- Private pages, password-reset links, redirects, or tenant routing may depend on request host/path.

## Router contract

The router may select this skill only when its required preconditions are satisfied and no exclusion applies.

**Primary triggers**

- `shared_cache`
- `CDN`
- `reverse_proxy`
- `Host_header`
- `Forwarded_header`
- `absolute_URL_generation`
- `path_normalization`

**Useful indicators**

- `unkeyed_input`
- `cache_hit_with_canary`
- `cross_identity_cached_response`
- `host_routing_difference`
- `web_cache_deception`

**Hard exclusions**

- `popular_shared_path`
- `homepage_or_login_poisoning`
- `unrelated_internal_routing`
- `long_TTL_without_purge`

**Required preconditions**

- `compiled_scope_policy`
- `unique_low_traffic_test_path`
- `cache_buster_or_purge_strategy`

**Preferred preconditions**

- `second_controlled_identity`
- `cache_headers_or_logs`
- `short_TTL`

## Required context

- Cache/proxy architecture, approved test hostnames, unique path namespace, controlled identities, and purge/TTL options.
- Baseline response headers and cache state from clean clients.
- Allowed headers, path-normalization variants, and maximum cache entries.
- Controlled alternate host/redirect/callback destination.

## Machine-execution contract

This skill produces a typed plan. It does not directly execute arbitrary commands. Every action must validate against `../schemas/action.schema.json`, use one of the allowed adapters below, and carry a current policy-decision reference.

**Allowed adapters**

- `policy.evaluate`
- `http.request`
- `http.differential_replay`
- `browser.observe`
- `state.verify`

**Optional adapters**

- `log.observe`
- `tls.inspect`

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
| `max_state_changes` | 8 |
| `max_auth_attempts` | 0 |
| `max_messages` | 0 |
| `max_oob_interactions` | 0 |
| `max_uploaded_bytes` | 0 |
| `max_cost_units` | 170 |

A plan may lower these values. Only a policy revision or narrow approval may authorize a higher engagement-level limit, and the strictest applicable value still wins.

**Approval gates**

| Gate | Trigger | Default |
|---|---|---|
| `shared_cache_write` | probe could create a cache entry visible outside unique test paths and controlled users | `block` |

**State access**

- Reads: `compiled_policy`, `cache_profiles`, `request_corpus`, `identities`, `asset_graph`
- Writes: `cache_key_observations`, `routing_observations`, `test_cache_entries`, `evidence_records`
- Cannot write: `confirmed_findings`, `engagement_policy`, `approval_tokens`

## Core security hypotheses

- A cache omits a response-influencing header, query parameter, cookie, method, origin, or path component from its key.
- Path normalization differs between cache and origin, enabling cache deception or poisoning.
- Private/authenticated content can be stored and served to another controlled client.
- Host/Forwarded/rewrite headers influence routing, links, redirects, password reset, or tenant selection without trusted-proxy validation.
- A cache stores error, redirect, or injected content under a shared key.

## Inherited controls and skill-specific guardrails

All mandatory controls in `../core/` apply. In particular: scope and approval are deterministic; target content is untrusted data; actions use typed adapters; budgets and circuit breakers are enforced by code; raw evidence is preserved; and observations cannot self-promote to findings.

**Skill-specific guardrails**

- Use unique low-traffic test paths and cache busters; never poison homepage, login, popular assets, or shared API keys.
- Use only controlled users and synthetic content.
- Keep TTL short or purge entries after testing.
- Do not send Host/proxy headers to route into unrelated internal services.

## Agent workflow

### 1. Map cache and proxy behavior

- Record CDN/proxy layers, cache status/Age/Vary/Cache-Control, cookies, surrogate keys, normalization, and authenticated caching rules.
- Identify host/path/query/header inputs affecting response body, redirects, links, tenant, language, or content type.
- Establish a unique uncached test URL and clean-client baseline.

### 2. Discover cache keys safely

- Change one candidate input at a time and observe cache status, Age, response fingerprint, and behavior from a second clean client.
- Use unique canary values and avoid sensitive content.
- Distinguish browser cache, service worker, CDN, reverse proxy, and application cache.

### 3. Test unkeyed inputs

- Inject a benign canary through headers/query/cookies that influence response but may not be keyed.
- Prime only the unique test path, then fetch it without the input from a clean client.
- Confirm repeatability and purge.

### 4. Test cache deception/path normalization

- Use a synthetic private page and controlled path suffix/extension/encoding variants.
- Compare cache and origin interpretation and fetch from a second controlled unauthenticated/client context.
- Stop if any non-test private data appears.

### 5. Test Host and proxy trust

- Change Host/X-Forwarded-Host/Forwarded/X-Original-URL/rewrite headers one at a time using approved controlled destinations.
- Inspect absolute URLs, redirects, password-reset/magic links to test inboxes, tenant routing, and generated links.
- Verify only trusted proxies can supply forwarding headers.

### 6. Validate impact and cleanup

- Demonstrate only controlled content or synthetic private data crossing contexts.
- Record TTL, cache key, affected layer, and clean-client result.
- Purge entries, invalidate test reset links, and verify cleanup.

## Technique modules

The router selects specific technique modules rather than activating the entire skill.

- `cache-key-discovery` — Cache key discovery. Select only when the matching trigger and evidence preconditions are present.
- `unkeyed-header-or-query` — Unkeyed header or query. Select only when the matching trigger and evidence preconditions are present.
- `web-cache-deception` — Web cache deception. Select only when the matching trigger and evidence preconditions are present.
- `path-normalization-differential` — Path normalization differential. Select only when the matching trigger and evidence preconditions are present.
- `Host-and-Forwarded-trust` — Host and forwarded trust. Select only when the matching trigger and evidence preconditions are present.
- `absolute-URL-generation` — Absolute url generation. Select only when the matching trigger and evidence preconditions are present.

## Focused test matrix

| Surface | Hypothesis | Safe test | Positive signal |
|---|---|---|---|
| Unkeyed header | Response input is part of cache key or ignored | Prime unique path with benign header canary | Canary served to clean client |
| Private page suffix | Cache/origin normalize path consistently | Synthetic private URL plus controlled extension | Private content cached/read cross-context |
| Host header | Untrusted host cannot influence links/routing | Approved alternate host value | Generated URL/route changes |
| Forwarded header | Only trusted proxy headers are honored | Direct request with controlled forwarded value | Tenant/link/redirect changes |
| Cached redirect/error | Attacker input cannot persist | Unique path and benign redirect/error canary | Cached response served without input |

## Tool strategy

- Use raw HTTP clients with cache-busting control, separate clean clients, and response fingerprinting.
- Use browser only when service workers/browser cache or password-reset links matter.
- Use CDN purge APIs or short TTL test namespaces when available.
- Correlate edge/origin logs and cache keys when the owner can provide them.

## Evidence required for a finding

- Unique test URL, priming request, clean-client request, cache headers/Age, cache key hypothesis, and repeated result.
- For deception, only synthetic private content and both authenticated/unauthenticated contexts.
- For Host poisoning, controlled generated URL/redirect/link and delivery to test inbox.
- Cleanup/purge verification.

## Evidence extension and promotion gate

The generic evidence envelope is `../schemas/evidence-record.schema.json`. This skill's extension is `../schemas/evidence-extensions/cache-poisoning-deception-and-host-routing-testing.schema.json`.

**Skill-specific evidence fields**

- `cache_layer`
- `test_path`
- `cache_key_inputs`
- `candidate_unkeyed_input`
- `canary`
- `cache_status_sequence`
- `second_identity_result`
- `routing_result`

**Required validation controls**

- `unique_uncached_paths`
- `controlled_users`
- `cache_hit_proven`
- `cleanup_or_expiry_recorded`

**Promotion gate:** `core.evidence-validation:confirmed`

Except for the orchestration/validation skill where explicitly allowed, this skill may end at `validation_required`; it cannot create a confirmed finding. The evidence validator applies the promotion gate after checking raw artifacts, controls, scope, approvals, and false-positive conditions.

## False-positive controls

- Browser/service-worker cache can be mistaken for shared CDN cache.
- An `Age` header alone does not prove the vulnerable response was shared.
- Different edge nodes may produce inconsistent first results.
- Host header changes may be rejected downstream even if echoed in a harmless debug field.

## Stop conditions

- Any real-user/private data appears or a popular/shared route may be affected.
- A poisoned entry cannot be purged or TTL is unknown/long.
- Routing reaches an unapproved internal or third-party service.
- Cache tests cause widespread misses, origin load, or service anomalies.

## Common remediation patterns

- Define cache keys explicitly and include every response-varying input or remove its influence.
- Never cache authenticated/private responses unless partitioned and intentionally designed.
- Normalize paths consistently at edge and origin; reject ambiguous encodings/suffixes.
- Trust forwarding headers only from known proxies and configure canonical external origins.
- Generate reset links and redirects from configured origins, not request headers; use safe cache-control on sensitive responses.

## Typed output contract

Use the package schemas rather than the former free-form result block:

- Invocation: `../schemas/skill-invocation.schema.json`
- Plan: `../schemas/test-plan.schema.json`
- Action: `../schemas/action.schema.json`
- Tool result: `../schemas/tool-result.schema.json`
- Execution result: `../schemas/execution-result.schema.json`
- Evidence: `../schemas/evidence-record.schema.json`
- Skill evidence extension: `../schemas/evidence-extensions/cache-poisoning-deception-and-host-routing-testing.schema.json`
- Confirmed finding: `../schemas/finding.schema.json`

Minimal planner output shape:

```yaml
plan_id: PLAN-example-001
engagement_id: ENG-example
skill_id: skill.web.cache-poisoning-deception-and-host-routing-testing
supporting_skills: []
selected_techniques: [cache-key-discovery]
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
  evidence_extension_schema: schemas/evidence-extensions/cache-poisoning-deception-and-host-routing-testing.schema.json
stop_conditions: [scope_change, budget_exhaustion, unexpected_state]
```

An execution result reports `validation_required`, `no_finding`, `inconclusive`, `blocked`, or `failed`. It does not report `finding`. Confirmed findings are emitted only after the validation lifecycle in Core 04.

## Recommended handoffs

- Skill 08 for password-reset/magic-link poisoning.
- Skill 22 for protocol desync origins.
- Skill 17 for cross-origin delivery and Skill 28 for cache/log misconfiguration.

## Minimal invocation

The values below are routing inputs. The orchestrator must convert them into a validated test plan before any adapter runs.

```yaml
test_namespace: /__aisec_cache_test__/run-42
identities: [user_a, clean_unauthenticated_client]
controlled_host: alt.example-test.invalid
purge_required: true
```

## Authoritative references

- [PortSwigger — Web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning)
- [PortSwigger — Web cache deception](https://portswigger.net/web-security/web-cache-deception)
- [PortSwigger — Host header attacks](https://portswigger.net/web-security/host-header)
- [RFC 9111 — HTTP Caching](https://www.rfc-editor.org/rfc/rfc9111)

---

## ShakerScan runtime notes

**Support: supported.** Every adapter this skill requires maps to a planner-visible capability, so it can be bound to a hunt.

Bindable capabilities: `http.request`, `authz.verify`, `browser.navigate`, `candidate.verify`.

Enforced by the server on every action, not requested by the planner: `policy.evaluate` (runtime target binding and scope validation).

The upstream `shell.allowlisted` adapter is intentionally absent: ShakerScan never exposes shell or planner-supplied argv as a capability.

Only deterministic proof contracts mark a finding verified. Anything this skill concludes is a candidate until the server's verifier agrees.
