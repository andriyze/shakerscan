---
id: skill.web.edge-waf-and-origin-exposure-validation
name: edge-waf-and-origin-exposure-validation
title: 31. Edge WAF and Origin Exposure Validation (Cloudflare and equivalents)
description: Validate that a CDN/WAF edge such as Cloudflare is one layer rather than the security
  boundary, by finding routes to the application that never traverse the edge and representations the
  edge and the origin disagree about.
version: 1.0.0
kind: specialist
phase: active_testing
risk: medium
support: supported
target_kinds:
- web
- api
capabilities:
- subdomains.discover
- web.probe
- http.request
- tls.inspect
optional_capabilities:
- ports.discover
- service.fingerprint
- authz.verify
- browser.navigate
- candidate.verify
missing_capabilities: []
server_enforced:
- policy.evaluate
budget:
  max_http_requests: 240
  max_duration_seconds: 1200
routing:
  triggers:
  - cdn_or_waf_detected
  - cloudflare_headers_present
  - edge_blocked_probe
  - dns_only_subdomain
  - alternate_origin_hostname
  - unproxied_application_port
  indicators:
  - origin_reachable_without_edge
  - edge_origin_path_disagreement
  - cacheable_authenticated_response
  - client_ip_header_trusted
  - broad_edge_allowlist
  exclusions:
  - no_edge_in_front_of_target
  - edge_owned_by_third_party_out_of_scope
preconditions:
- compiled_scope_policy
- edge_provider_identified
- origin_ownership_confirmed
techniques:
- origin-exposure-discovery
- direct-origin-request-with-preserved-host
- unproxied-port-inventory
- certificate-and-sni-correlation
- path-normalization-differential
- preflight-and-verb-surface
- cache-identity-confusion
promotion_gate: direct_origin_response_matches_application_without_edge_headers_or_edge_origin_disagreement
requires_skills:
- skill.web.http-baselining-replay-and-differential-analysis
deferred_techniques:
- technique: historical-and-aaaa-dns-enumeration
  requires: a planner-visible dns.resolve capability; dns.inspect exists but is server-only
- technique: method-and-content-type-switching
  requires: a request capability carrying a body; http.request is limited to GET, HEAD and OPTIONS
- technique: body-inspection-boundary-probing
  requires: a body-carrying request capability and a payload-size budget dimension
- technique: request-smuggling-and-desync
  requires: a raw single-connection request capability
- technique: rate-limit-and-bot-evasion
  requires: a synchronized concurrent-batch capability
- technique: websocket-and-grpc-frame-inspection
  requires: a realtime exchange capability
- technique: client-ip-header-trust-probe
  requires: an operator-authorized identity-header tier; the request filter drops X-Forwarded-For,
    X-Real-IP and Forwarded while currently letting CF-Connecting-IP and True-Client-IP through,
    and this skill will not build on that asymmetry
source: authored for ShakerScan from operator-supplied Cloudflare validation methodology
---

# 31. Edge WAF and Origin Exposure Validation

## Mission

Establish whether the application is reachable, or semantically attackable, without the protection
the edge is assumed to provide. The question is not "does Cloudflare return 403 for an obvious SQL
injection". It is "can a dangerous request reach a vulnerable operation through an alternate route,
representation, protocol, or configured exception".

Treat the edge as one layer. A finding here is a *routing or agreement* failure, not a payload that
got through a signature.

## Use this skill when

- The target resolves to a CDN/WAF edge, or responses carry edge headers such as `cf-ray`.
- A probe was blocked at the edge and you need to know whether that block is the only control.
- Discovery surfaced a DNS-only subdomain, an alternate origin hostname, or an application port
  outside the set the edge proxies.
- An authenticated route looks cacheable.

Do not run it when the target sits behind an edge operated by a third party outside your
authorization: the edge itself is then not in scope, only the origin you own.

## The three ways an edge stops mattering

1. **Reach the application without passing through it.** Usually the easiest and the most damaging.
2. **Pass through it but exploit a rule, parser, normalization, or inspection gap.**
3. **Move the attack into behavior the edge does not model** — authorization logic, WebSocket
   frames, gRPC bodies, distributed abuse.

Category one is where this skill spends most of its budget, because it is the one that invalidates
every other control at once.

## What this runtime can and cannot do

The classic bypass proof — `curl --resolve app.example.com:443:203.0.113.10` carrying the original
`Host` — is available, but only against an address the **operator** confirmed when starting the
hunt. Pass one of those addresses as `via_address` on `http.request` and the connection is pinned
to it while SNI and `Host` stay the target's. The planner chooses among confirmed addresses; it
never supplies one.

That requires `policy.allow_direct_origin`, `active_testing`, and a target-bound approval receipt.
Without them, every request goes to the target's resolved address, and this skill is limited to
proving exposure rather than demonstrating the bypass.

Both outcomes are worth reporting, and they are not the same evidence:

- **Exposure.** An origin candidate answering on an unproxied port, presenting the target's
  certificate, or serving the application under a DNS-only name shows the edge is not the only path
  in. Actionable on its own.
- **Demonstrated bypass.** The same application content returned over a `via_address` request, with
  the edge's response headers absent. This is the finding.

Every response records whether it arrived through the resolved address or a confirmed origin. Never
compare the two without saying which is which.

## Agent workflow

> **Authority note.** `subdomains.discover` costs `hosts_attempted` and `tls.inspect` costs
> `tcp_ports_attempted`, so both are withheld unless the hunt carries `network_discovery`
> authority and a target-bound approval receipt. Without it this skill is reduced to steps 4-6.

### 1. Confirm an edge is actually in front

Use `web.probe` and `tls.inspect` on the bound origin. Record the edge product, `cf-ray` or
equivalent, the certificate issuer and its SAN list. The SAN list is the highest-yield artifact in
this skill: it frequently names origin, staging, and internal hostnames the edge does not proxy.

Do not decide from `Server: cloudflare` alone. Its absence is not proof of a bypass and its presence
is not proof of coverage.

### 2. Inventory every ingress name

Use `subdomains.discover` on the root domain. Rank results for names that suggest an unproxied
path: `origin`, `direct`, `direct-connect`, `staging`, `dev`, `test`, `api-internal`, `internal`,
`backend`, `old`, `legacy`, `cpanel`, `mail`, `mx`, `smtp`, `webmail`, `ftp`, `vpn`, `monitor`,
`grafana`, `status`, plus provider-shaped names for ALB/Azure/GCP/Kubernetes ingress.

Mail infrastructure sharing an address with the web origin is a classic disclosure. So is an
`AAAA` record when only IPv4 is proxied — note it as a gap even though enumerating it needs the
deferred DNS capability.

For each name, `web.probe` it and compare against the edge-fronted baseline. A name that serves the
same application while lacking the edge's response headers is the finding.

### 3. Inventory ports the edge does not proxy

With `network_discovery` authority, run `ports.discover` and `service.fingerprint`.

An edge proxies a defined set of web ports. Anything else is either a separate product tier or is
reached directly. Give weight to `3000`, `5000`, `8000`, `8080`, `8443`, `8880`, `9000`, `9443` —
container-published application ports — and to management, monitoring, and backup services.

An HTTP service answering the application on a port the edge does not proxy is a complete bypass
even if you cannot finish the request from here.

### 4. Complete the bypass, where the operator authorized it

For each exposed candidate the operator confirmed as a `direct_origin_address`, send the same
request twice: once normally, and once with `via_address` set to that address. Compare status, body,
and the edge's own response headers.

The application answering identically over `via_address`, without the edge headers, is the
demonstrated bypass. A connection refused or a TLS failure is the control working. A generic origin
denial before application routing is also correct behaviour — the origin recognised traffic that did
not come through the edge.

Keep this to a handful of requests. It exists to confirm the exposure discovered in steps 2 and 3,
not to conduct the rest of the assessment against the origin.

### 5. Path normalization differential

The edge and the application must agree about what path a request names. Where they disagree, an
edge rule guarding `/admin` protects a string the application never sees.

Send the corpus with `http.request`, one representation per request, and compare status, length,
and body shape against the baseline established by skill 05:

```
/admin            /%61dmin          /public/../admin      /public%2f..%2fadmin
/admin%2fsettings /admin%252fsettings /admin;v=1          /AdMiN
//admin           /admin.           /./admin              /admin/.
```

Record for every one: the path as sent, the edge action, whether the origin was reached, and which
application route answered. Two representations that select *different* security policy but the
*same* application route is the defect. `%2F` is a reserved encoded slash that many edges do not
convert, which makes `/admin%2fsettings` and `/admin%252fsettings` the highest-yield pair.

A single anomalous response is not a finding. Re-send both the anomalous and the canonical form
interleaved, and require the difference to reproduce.

### 6. Preflight and verb surface

`http.request` can send `OPTIONS`. Some edge access configurations pass preflight straight to the
origin so CORS works. Check that an unauthenticated `OPTIONS` performs no state-changing or
sensitive processing and discloses nothing in its headers.

`HEAD` is worth sending wherever `GET` is blocked: an edge rule written for one method sometimes
misses the other, and a `HEAD` that returns a different status than a blocked `GET` is a rule-scope
defect.

The remaining method work — `POST`, `PUT`, `DELETE`, and the `X-HTTP-Method-Override` and `_method`
conventions — is deferred; this runtime's `http.request` carries no body.

### 7. Cache and identity confusion

The highest-severity edge finding is one user's authenticated response served to another. Use
`authz.verify` with two principals where the target has them, and `http.request` otherwise:

1. Request a unique authenticated URL as the primary principal; record `cf-cache-status`,
   `cache-control`, `vary`, and any per-user marker in the body.
2. Request the identical URL as the secondary principal or anonymously.
3. If the first principal's marker appears, stop and record it immediately.
4. Repeat with the representations that change the cache key but not the route: a trailing
   `.css`/`.js` extension, a `;` path parameter, an encoded slash, and an extra query parameter.

An authenticated route that looks like a static file is the common cause. Never treat a single
`HIT` as proof — confirm the response body actually crosses identities.

### 8. Client-IP header trust — deferred, and why

The edge supplies a connecting-IP header so the origin can identify the visitor. It is trustworthy
only when the connection is known to have come from the edge. Where it is trusted unconditionally,
an attacker who reaches the origin directly can assert any client address and defeat application
allowlists, internal-user checks, origin rate limits, and audit attribution.

This runtime drops `X-Forwarded-For`, `X-Real-IP`, `Forwarded` and `Host` from planner-supplied
headers, because a planner must not forge identity. `CF-Connecting-IP` and `True-Client-IP` are
not currently dropped even though they serve that same purpose behind the major edges. This skill
does not use that gap: a probe that works only because the header filter is inconsistent would stop
working the moment the filter is corrected, and building on it would argue for leaving it open.
The technique belongs behind an explicit operator-authorized identity-header permission, where the
operator states that forging a connecting address against this target is in scope.

Report the exposure instead. If step 2 or 3 proved a direct path to the origin exists, then origin
trust in any client-suppliable address header is exploitable, and the remediation below applies
whether or not this runtime could send the header.

## Evidence required for a finding

- **Origin exposure:** the alternate name or port, the service identified, the certificate or
  response evidence tying it to the same application, and the contrast with the edge-fronted
  baseline.
- **Demonstrated bypass:** the paired requests, the confirmed address used, the application content
  returned over it, and the edge headers present on one and absent on the other.
- **Normalization disagreement:** both representations, both responses, the shared application
  route, and an interleaved repeat.
- **Cache confusion:** both principals' requests and responses, the marker that crossed, and the
  cache headers on each.
Absence of an edge header is never sufficient on its own. Neither is a single unrepeated response.

## False-positive controls

- Edge providers serve their own error pages; a different body is not automatically a different
  origin.
- A staging hostname may legitimately be a separate deployment. Tie it to the same application by
  content or certificate before calling it an origin disclosure.
- `cf-cache-status: HIT` on a genuinely public asset is correct behavior.
- Rate limiting and edge challenges can make two identical requests differ. Interleave and repeat.
- Some applications legitimately use encoded slashes. A normalization difference matters only when
  it changes which security policy applies.

## Stop conditions

- The edge begins challenging or blocking a large fraction of requests: stop, record the
  observation, and do not rotate representations to evade it. Evasion of the control under test
  invalidates the test.
- An origin candidate turns out to be a third party.
- The request budget is exhausted; exposure findings are already reportable on their own.

## Remediation, strongest first

1. **No public origin listener at all** — an outbound-only tunnel from the origin to the edge.
2. **Custom zone-level or per-hostname authenticated origin pulls, plus network restriction.**
   A *global* origin-pull certificate is shared across the provider's customers: it proves traffic
   came from that network, not from your account.
3. Edge IP allowlisting plus an edge-added origin secret and strict `Host` validation.
4. Edge IP allowlisting alone.

Alongside those:

- Audit DNS-only records and separate mail infrastructure from the web origin.
- Rotate any origin address that was ever public.
- Normalize URLs both at the edge and toward the origin, so both agree on the path.
- Scope every skip/allow exception to one method and one exact path, and test it with the negative
  cases: correct path from an untrusted source, wrong path from a trusted one, and the supposedly
  trusted header supplied by the client.
- Never let a header alone establish internal identity.

## Recommended handoffs

- Cache and cross-origin behavior: skill 23 and skill 17.
- Anything the exposed origin then reveals: whichever specialist matches the surface.
- Authorization on routes the edge was assumed to protect: skill 09.
