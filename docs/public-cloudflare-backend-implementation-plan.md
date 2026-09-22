# ShakerScan Public Service — Cloudflare Backend Implementation Plan

**Status:** implementation specification  
**Audience:** coding agents / maintainers  
**Public origin:** `https://pub.shakerscan.com`

## Goal

Build the public backend that the lightweight client already expects when no local, LAN, Enterprise, or explicitly configured ShakerScan instance exists:

```bash
shakerscan check example.com
shakerscan mcp
```

The service provides useful passive/public Internet posture information without an account, Docker, engine, or token. It must **not** become a free arbitrary DAST/Hunt proxy.

The current client hardcodes `https://pub.shakerscan.com`, sends `POST /v1/check` with `{"target":"example.com"}`, and deliberately sends no saved ShakerScan credential. Preserve that contract.

## Product boundary

Public v1 may normalize a public DNS hostname; inspect DNS; perform a few bounded HTTP(S) requests to that hostname; report redirects and basic HTTP/security-header posture; cache deterministic results; and expose the same bounded check through MCP.

Public v1 must not accept IP/CIDR targets, localhost/private destinations, arbitrary ports, credentials, cookies, arbitrary headers/bodies/paths, or proxy URLs. It must not run Nuclei, SQLMap, ffuf, Katana, browser automation, Hunt, authenticated scans, credential testing, exploit verification, OOB callbacks, port scans, subdomain brute force, or arbitrary commands.

The public service is a **posture lookup**, not hosted ShakerScan.

## Architecture

Use a small TypeScript Cloudflare Worker:

```text
client / MCP host
      |
      v
pub.shakerscan.com
      |
Cloudflare Worker
 |      |       |
 |      |       +-- Rate Limiting binding
 |      +---------- KV result cache
 +----------------- bounded DNS/HTTPS probes
```

Start synchronous. Do not introduce Queues, Durable Objects, D1, R2, or Workers AI merely because they exist. Add a Queue only if measurements show checks need asynchronous work. Use KV only for disposable cache data, not as a strongly consistent quota ledger.

## Repository layout

```text
public-service/
  package.json
  package-lock.json
  tsconfig.json
  wrangler.jsonc
  src/
    index.ts
    routes.ts
    check.ts
    dns.ts
    http.ts
    target.ts
    safety.ts
    response.ts
    mcp.ts
  test/
    target.test.ts
    safety.test.ts
    check.test.ts
    mcp.test.ts
  README.md
```

Keep dependencies small and pinned; commit the lockfile.

## API

### GET /health

Return only stable public metadata:

```json
{"status":"ok","service":"shakerscan-public","version":"..."}
```

Never expose bindings, deployment IDs, environment variables, stack traces, or secrets.

### POST /v1/check

Request:

```json
{"target":"example.com"}
```

Requirements:

- require JSON and reject oversized bodies before parsing;
- reject unknown top-level fields;
- normalize case/trailing dot; make IDNA behavior explicit and tested;
- reject paths, queries, fragments, userinfo, ports, wildcards and IP literals;
- return JSON for expected failures.

Suggested response:

```json
{
  "schema_version": "1",
  "target": "example.com",
  "checked_at": "2026-09-21T00:00:00Z",
  "summary": "HTTPS reachable; HSTS not observed.",
  "checks": [
    {"id":"dns","name":"DNS","status":"pass","detail":"Public DNS records observed."},
    {"id":"https","name":"HTTPS","status":"pass","detail":"HTTPS responded."},
    {"id":"headers","name":"Security headers","status":"warn","detail":"HSTS was not observed."}
  ],
  "cache": {"hit": false},
  "request_id": "..."
}
```

Statuses: `pass | warn | fail | unknown`. Do not invent a security score. Missing headers are posture observations, not proof of vulnerabilities.

Use stable error JSON:

```json
{"error":{"code":"target_not_allowed","message":"Public checks require a public DNS hostname."},"request_id":"..."}
```

Recommended HTTP codes: 200, 400, 403, 405, 413, 415, 429, 502, 504.

## SSRF / destination safety — release blocker

Client validation is convenience only. The Worker independently validates every request and every redirect.

Reject IP literals and any destination resolving to private, loopback, link-local, CGNAT, multicast, documentation/test, unspecified, benchmark, reserved, or otherwise non-public space. Reject internal/metadata destinations, non-HTTP(S) schemes, userinfo and explicit ports.

Resolve/validate immediately before probing. Treat a mixed safe/unsafe DNS answer as unsafe. Validate redirects again and, for v1, preferably refuse cross-host redirects entirely. Never use automatic redirect following blindly.

A pre-fetch DNS lookup alone is not a complete DNS-rebinding defense. Keep the destination primitive extremely narrow and use Cloudflare/platform protections where available. Never add a generic `/fetch?url=` endpoint.

## Probe budget

Give every request a hard upper bound:

- DNS: bounded A/AAAA/CNAME; optional MX/CAA informational records;
- HTTPS: one HEAD or bounded GET to `https://<target>/`;
- optional HTTP request only for HTTP→HTTPS posture;
- at most 3 manually validated redirects, same host only;
- avoid target response bodies; if needed, cap bytes aggressively;
- roughly 4 seconds per outbound operation and 8 seconds overall;
- a small tested maximum outbound-operation count.

Do not infer TLS details the Worker runtime cannot actually observe. Return `unknown` when evidence is unavailable rather than fabricating certificate/protocol facts.

## Cache

Canonical key: `check:v1:<normalized-host>`.

Suggested TTL: 5–15 minutes for success; 30–60 seconds for transient failures; avoid long caching of rejection decisions. Never store target response bodies. Return only a boolean cache-hit diagnostic, not internal keys.

If duplicate expensive checks later become a real problem, consider a per-host Durable Object. Do not start there.

## Abuse controls

Layer controls:

1. Cloudflare edge/WAF rules.
2. Worker Rate Limiting binding keyed primarily by caller IP and route.
3. A stricter MCP budget if MCP can fan out.
4. Cache before expensive work where safe.
5. Emergency configuration to disable probes while keeping health alive.
6. Hard outbound-operation budget.

Start conservatively (burst plus tens of checks/hour/IP) and tune from metrics. Do not build quota accounting on eventually consistent KV. Turnstile may protect a future browser UI, but the CLI/MCP API must not require an interactive CAPTCHA.

## MCP

This needs deliberate integration. The current client starts its vendored stdio MCP adapter and points it at `pub.shakerscan.com`; that adapter was designed to discover a private engine's Arsenal/Hunt contracts.

Do **not** fake the full OSS engine contract.

Preferred design: add a dedicated public mode to the client adapter exposing a tiny fixed allowlist:

- `shakerscan_public_check`: input `target`; invokes the exact `POST /v1/check` pipeline.

No Hunt, scans, arbitrary Arsenal execution, arbitrary HTTP, shell, filesystem, credentials, mutation, or target management.

Alternative: implement only the minimum discovery/dispatch endpoints needed by the existing adapter, with a strict server-side public allowlist. This is less clean because the public service is not an OSS engine.

Before implementation, inspect `scripts/shakerscan_mcp.py` and its tests and choose explicitly. If the dedicated adapter is chosen, change client and backend in the same release sequence. `shakerscan mcp` with no configured instance must pass an end-to-end MCP initialize → tools/list → tools/call test before launch.

## DNS

Use Cloudflare-supported DNS mechanisms. Never allow the caller to select a resolver. Deduplicate and cap record counts/string lengths. Distinguish NXDOMAIN/no-data from timeout/servfail only when reliable. DNS evidence is not proof of ownership.

## HTTP

Construct URLs yourself from the validated hostname:

```text
https://<normalized-host>/
http://<normalized-host>/
```

Never concatenate an unvalidated caller URL. Identify ShakerScan in User-Agent. Send no cookies, Authorization, ShakerScan tokens, arbitrary caller headers, Referer, or target request bodies. Process redirects manually. Bound/sanitize headers before returning or logging them.

## Privacy / logs

Keep only operational telemetry: request ID, coarse outcome, latency, cache status, route and rejection/rate-limit reason. Retain normalized target only if the published privacy policy explicitly permits it.

Never log request bodies, Authorization, cookies, Enterprise tokens, raw target response bodies, or unnecessary client identifiers. Prefer Cloudflare's rate-limit infrastructure over storing IP quota state yourself.

## CORS and response hardening

CLI does not need CORS. Default to no permissive CORS. A future browser integration should allow only explicit ShakerScan origins/methods/headers.

Use JSON content types, `X-Content-Type-Options: nosniff`, appropriate `Cache-Control`, strict route/method handling, and sanitized errors. Do not add application debug/server banners.

## Wrangler shape

Validate against the pinned Wrangler version before committing:

```jsonc
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "shakerscan-public",
  "main": "src/index.ts",
  "compatibility_date": "2026-09-01",
  "workers_dev": false,
  "routes": [{"pattern":"pub.shakerscan.com","custom_domain":true}],
  "kv_namespaces": [{"binding":"RESULT_CACHE","id":"<prod>","preview_id":"<preview>"}],
  "ratelimits": [{
    "name":"CHECK_RATE_LIMITER",
    "namespace_id":"1001",
    "simple":{"limit":10,"period":60}
  }],
  "limits": {"cpu_ms":1000,"subrequests":20},
  "observability": {"enabled":true}
}
```

Never commit production IDs/secrets. Use scoped deployment credentials and protected CI environments.

## Deployment environments

Have local mocked tests, a non-production Worker environment/hostname, and production `pub.shakerscan.com`. Never point a released client at staging. Production deployment must be reproducible from GitHub Actions and gated on tests.

## Required tests

Unit/security tests must cover hostname normalization, IDNA, malformed hosts, unusual IP literal forms, private/reserved IPv4+IPv6, mixed DNS answers, DNS rebinding assumptions, unsafe/cross-host redirects, redirect loops, timeouts, oversized bodies, content types/methods, output truncation, stable schema, and secret non-reflection.

Maintain a table-driven SSRF corpus; every security fix adds a permanent regression.

Contract-test the real Python client against the Worker response:

```bash
shakerscan check example.com --json
```

MCP integration tests must run the actual packaged/vendored adapter and exercise `initialize`, `tools/list`, and the public check tool, asserting that Hunt/private-engine tools are absent.

Test rate limiting, cache hits, repeated targets, invalid/large inputs and concurrency.

## Observability

Measure requests/status by route, p50/p95/p99 latency, rate limits, target-policy rejections, outbound errors/timeouts, cache ratio, Worker exceptions and CPU/subrequest-limit failures. Establish numerical SLOs only after staging data exists.

## Cost controls

Public endpoints are adversarial by default. Set explicit CPU/subrequest limits, cache, rate limit, alert on usage and configure billing notifications. Do not put Workers AI in the v1 request path; the check should be deterministic.

## Implementation stages

### Stage 0 — freeze the contract
Read `client/src/shakerscan/cli.py`, `client/tests/test_public.py`, `scripts/shakerscan_mcp.py`, and `docs/client.md`. Write fixtures first. Do not silently change the released protocol.

### Stage 1 — API skeleton
Implement health, strict routing/method/content-type/body limits, request IDs, JSON errors and target normalization. No outbound fetch yet.

### Stage 2 — destination safety
Implement the public-address classifier, DNS validation, redirect policy and SSRF corpus. Treat failures here as release blockers.

### Stage 3 — bounded checks
Implement DNS + HTTPS + optional HTTP redirect/header observations with hard time/subrequest/output limits. Produce schema v1.

### Stage 4 — cache + abuse
Add KV cache, rate-limit binding, WAF recommendations, emergency kill switch and metrics.

### Stage 5 — public MCP
Implement the chosen dedicated-public or compatibility design. End-to-end test with the real client. Do not expose private-engine tools.

### Stage 6 — staging
Deploy to a non-production hostname. Exercise benign public domains, failure modes, concurrency, cache behavior and SSRF cases. Run ShakerScan/client contract tests against staging.

### Stage 7 — production
Create `pub.shakerscan.com`, configure production bindings/rules, deploy through CI, smoke `/health`, then `shakerscan check`, then MCP. Keep a one-command rollback path.

## Definition of done

Public launch is complete only when:

- `shakerscan check example.com` works from the released client;
- `shakerscan mcp` exposes only explicitly public-safe tools and can perform the same check;
- no ShakerScan credential is sent to the public service;
- SSRF corpus and redirect tests pass;
- private/reserved destinations cannot be reached through the API;
- request/probe/subrequest/time/output budgets are enforced;
- rate limiting and caching are live;
- logs contain no secrets or target response bodies;
- staging and production deployment are reproducible;
- production health/check/MCP smoke tests pass;
- documentation states clearly that public checks are bounded posture observations, not full DAST/Hunt.

## Agent implementation rule

When implementing this plan, prefer the smallest capability that satisfies the public-client contract. Never solve a missing feature by exposing a generic network primitive. If a desired observation cannot be obtained safely or reliably from Cloudflare Workers, mark it unsupported/unknown or move it to a separately designed backend rather than weakening destination validation.
