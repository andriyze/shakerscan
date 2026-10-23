# ShakerScan DAST — OWASP Coverage Matrix

**Status:** reconciled 2026-10-23 against the Scan family list (`SCAN_V2_FAMILY_NAMES` in
`api/scan/contracts.py`), the check registry (`api/check_registry.py`) and the findings the Scan
finalizer emits (`api/scan/finalizer.py`, `api/scan/posture_findings.py`). This matrix records
which checks a Scan runs, not accepted recall, precision, or proof depth. Candidate acceptance
belongs in the release workflow and current benchmark/evaluation artifacts.

## Scope

This maps the **Scan**, the one deterministic DAST workflow, against the OWASP Top 10 (2021) and
the OWASP API Security Top 10 (2023). A row counts only:

- the eleven Scan families: `recon`, `nuclei_passive`, `nuclei_active`, `xss`, `sqli`, `bola`,
  `sensitive_exposure`, `nosqli`, `authz_surface`, `graphql` and `recon_active`;
- the baseline checks every Scan makes: response headers and session cookies, two CORS probes,
  TLS for an HTTPS origin, and DNS/email records for a host name.

A row does not count:

- detector modules under `scanner/scanner_tools/` that no Scan family runs, such as the older
  SSRF, command-injection, SSTI, XXE, LDAP, XPath, JWT and deserialization probes. They are
  compatibility code, not Scan coverage;
- registered families that are not Scan families. A Scan refuses all of them: the planned `ssrf`,
  `lfi`, `rce` (alias `command_injection`) and `business_logic`, and also `auth`,
  `endpoint_security`, `headers`, `jwt` and `mass_assignment` (header checks run in the baseline
  instead);
- single Nuclei templates for named products (see [Active Nuclei pack](#active-nuclei-pack)). A
  row is not marked covered for any of them;
- Hunt, AI Gate and Model Intake.

**Defaults.** The `passive` preset runs `recon`, `nuclei_passive` and `sensitive_exposure`.
`standard_active` adds `xss` and `sqli`, and the open-redirect probe that runs with `xss`. Every
other family is opt-in (`custom` preset or `include_families`), and every family except `recon`,
`nuclei_passive` and `sensitive_exposure` needs active testing. Some need more:

- a Scan that names `bola` is refused without two distinct credential profiles;
- `authz_surface` runs only when the Scan has a primary credential. Without one it is selected
  but not planned;
- a Scan that names `recon_active` is refused without a target-bound approval receipt. Its
  virtual-host and DNS-name discovery also need subdomain discovery and a declared apex; without
  them only parameter discovery runs;
- request body fields are tested only when state-changing HTTP is allowed, which also needs a
  target-bound approval receipt.

Legend: ✅ a Scan has meaningful checks for this category · 🟡 partial: some sub-classes only,
opt-in, or needs credentials · ❌ no Scan check

> Note: ✅ means a Scan runs meaningful checks for that category, not that every sub-technique is
> covered. Several ✅ rows still name gaps in their last column.

This matrix does not affect a scan score or grade. A category-level mechanism can produce
unverified candidates, and a particular run may have weak assurance or may not examine the
application at all. Use proof state, current coverage, and `risk_and_assurance/v9` result fields for
run-specific claims. A Scan's `resolved_families` names the families selected for it; the scan
page's Testing tile names the active families that ran.

### Active Nuclei pack

`nuclei_active` selects high and critical templates tagged `exposure`, `misconfig`, `auth-bypass`
or `default-login` from the pinned, checksum-verified template bundle, and runs them without
out-of-band callbacks. On the pinned bundle (nuclei-templates `2935d63a`) that is 760 GET-only
templates, or 1,145 when state-changing HTTP is allowed.

A Scan does not always run the whole pack. Each endpoint attempt runs one 30-template window. A
`fast` or `balanced` Scan (`balanced` is the default) runs one window per endpoint in its active
manifest, so a host with fewer endpoints than windows (26 GET-only, 39 with state-changing HTTP)
runs only part of the pack: a host with five endpoints runs about 150 of the 760 GET-only
templates. `thorough` and `deep` Scans run every window. A Scan split into parallel parts runs one
window per endpoint in each part. `nuclei_active.template_windows` on the result says how many
windows ran.

Some templates in the pack also carry another tag. Of those that can match, 11 are tagged `rce`
(19 with state-changing HTTP), 11 `lfi` (15), 5 `jwt` and 2 `sqli` (24), all written for named
products or CVEs. None can match SSRF (both SSRF templates need callbacks), SSTI, XXE or
deserialization. A verify Scan can also run the CVE checks a candidate names (A06).

## OWASP Top 10 (2021)

| ID | Category | Status | What a Scan checks | Not covered by a Scan |
|----|----------|--------|--------------------|-----------------------|
| A01 | Broken Access Control | 🟡 | Object access compared across two credential profiles (`bola`, opt-in). Authenticated API functions that return the same data to an anonymous request (`authz_surface`, opt-in). Open redirect (with `xss`). CORS (see A05). | Mass assignment, vertical privilege escalation, method-override bypass. Without credentials only open redirect and CORS run. Authenticated benchmark recall is not accepted. |
| A02 | Cryptographic Failures | ✅ | TLS on every HTTPS origin: SSL 3.0, TLS 1.0 and 1.1 and weak cipher suites (probed with raw ClientHello messages), certificate expiry, validity window, hostname, chain trust, weak signature and weak key. Missing or weak HSTS. Session cookies without `Secure` on HTTPS. | No Heartbleed, ROBOT, CCS, CRIME, OCSP or post-quantum checks; the analyzers that did these do not run in a Scan. Data at rest and application cryptography are not visible. |
| A03 | Injection | 🟡 | SQL injection with sqlmap (`sqli`). Reflected XSS, and DOM XSS through URL-fragment parameters, proven in a browser (`xss`). MongoDB-style operator injection (`nosqli`, opt-in). Inputs: query parameters found by discovery or declared in the target's OpenAPI spec or in known endpoints, and templated GET path segments (SQL injection only). Request body fields, from the spec, known endpoints, requests the crawl saw the application send, or request collections, are tested only when state-changing HTTP is allowed. | Command injection, SSTI, XXE, LDAP, XPath, CRLF, host-header, SSI/ESI, CSV/formula and RFI have no generic check. Stored XSS: a Scan does not submit the HTML forms it crawls or look for a payload on a later page. Without state-changing HTTP no body field is tested, even from a request collection. |
| A04 | Insecure Design | ❌ | — | `business_logic` is planned; a Scan refuses it. Race-condition and price or coupon probes are not run. Much of this category is out of reach for black-box testing. |
| A05 | Security Misconfiguration | ✅ | Every Scan: missing or weak CSP, HSTS, Referrer-Policy and Permissions-Policy, and a weak X-Frame-Options value; CORS probes for a reflected origin, the `null` origin and a wildcard with credentials. The six-template reviewed passive Nuclei pack (Git config and credentials, missing security headers, OpenAPI, server-status, web.config). `sensitive_exposure` (default): `.env`, `.git`, actuator, API specs with secrets, config and backup files, debug pages, metrics, directory listings, GraphQL introspection, verbose error pages. Active Nuclei `misconfig` and `exposure` templates (opt-in). Subdomain takeover when subdomain discovery is allowed. | Default credentials only through opt-in Nuclei `default-login` templates. No risky-HTTP-method check. No cloud bucket, Kubernetes, Terraform or container-registry checks. No SAML checks. |
| A06 | Vulnerable & Outdated Components | 🟡 | Nuclei templates for named products (`nuclei_active`, opt-in, high and critical, the four tags above; a `fast` or `balanced` Scan of a small host runs only part of them, see [Active Nuclei pack](#active-nuclei-pack)). A verify Scan runs up to ten CVE checks that the vulnerability data names for a candidate ([service intelligence](service-intelligence.md)). Technology and version fingerprints list candidate advisories under Exposure → Services; these are leads, not findings. | No JavaScript library CVE check. No finding from a version number alone. Outside a verify Scan, CVE templates without one of the four tags do not run. |
| A07 | Identification & Authentication Failures | 🟡 | Session cookies without `HttpOnly` or `Secure` (baseline). Nuclei `default-login` and `auth-bypass` templates (`nuclei_active`, opt-in). Default-login templates that use POST or another non-GET method run only with state-changing HTTP permission. GET-only ones run with active testing alone and still send credentials, most of them as HTTP Basic auth (47 of the pack's 306 on the pinned bundle). A `fast` or `balanced` Scan of a small host runs only some of these templates ([Active Nuclei pack](#active-nuclei-pack)). | No JWT, OAuth/OIDC, session-fixation, brute-force, rate-limit, 2FA-bypass or SAML checks. |
| A08 | Software & Data Integrity Failures | ❌ | — | Deserialization, ViewState and prototype-pollution probes are not run. No SRI or unsigned-update check. |
| A09 | Security Logging & Monitoring Failures | 🟡 | Exposed metrics and actuator endpoints, and error pages that show stack traces (`sensitive_exposure`, default). | Whether the application logs, alerts or detects attacks cannot be seen from outside. No CRLF log-injection check. |
| A10 | SSRF | ❌ | — | No Scan family. `ssrf` is registered as planned and a Scan refuses it. A Scan sends no out-of-band callbacks (Nuclei runs with `-no-interactsh`), so no SSRF template can match. |

## OWASP API Security Top 10 (2023)

| ID | Category | Status | Notes |
|----|----------|--------|-------|
| API1 | Broken Object Level Authorization | 🟡 | `bola` (opt-in) requests the same object routes as two credential profiles and compares what each receives. Needs two profiles; authenticated benchmark acceptance remains open. |
| API2 | Broken Authentication | 🟡 | Session cookie flags and opt-in Nuclei `default-login`/`auth-bypass` templates only (see A07). No JWT, OAuth or brute-force checks. |
| API3 | Broken Object Property Level Authorization | 🟡 | One narrow excessive-data-exposure check: `sensitive_exposure` (default) flags a JSON response that lists two or more account records with plaintext passwords (`credential_record_disclosure`, critical). It reads the seed list and the discovered endpoints. No mass-assignment check; `mass_assignment` is not a Scan family. No other check for responses that return more properties than the caller should see. |
| API4 | Unrestricted Resource Consumption | 🟡 | `graphql` (opt-in): missing alias and duplicate-field limits on discovered GraphQL endpoints. No rate-limit detection; resource exhaustion is never attempted, by design. |
| API5 | Broken Function Level Authorization | 🟡 | `authz_surface` (opt-in, needs a primary credential): an authenticated function that returns byte-identical data to an anonymous request, where the app does deny anonymous access elsewhere. No role-to-role comparison. |
| API6 | Unrestricted Access to Sensitive Business Flows | ❌ | `business_logic` is planned; a Scan refuses it. |
| API7 | SSRF | ❌ | Same as A10. |
| API8 | Security Misconfiguration | ✅ | Same as A05, plus GraphQL field suggestions (`graphql`, opt-in). |
| API9 | Improper Inventory Management | 🟡 | `recon` (default): crawl, browser crawl, content discovery and OpenAPI ingestion. `recon_active` (opt-in, needs an approval receipt): parameter discovery, and virtual-host and DNS-name discovery under a declared apex. Subdomain discovery when allowed. Exposed API specs (`sensitive_exposure`). No version or deprecation inventory. |
| API10 | Unsafe Consumption of APIs | ❌ | Trust in upstream APIs is mostly out of reach for black-box testing. |

## Summary

A Scan covers TLS, header, cookie, CORS and exposure posture on every run, and SQL injection and
XSS by default when active testing is allowed. NoSQL injection, object- and function-level
authorization, GraphQL limits and active Nuclei templates are opt-in, and the authorization checks
need credentials. A Scan has no generic check for SSRF, command injection, path traversal, SSTI,
XXE, LDAP or XPath injection, deserialization, JWT, OAuth, mass assignment or business logic. A
few opt-in Nuclei templates test single named products for some of these (see Scope). The largest
acceptance gaps are authenticated access control, authenticated API discovery, stored XSS and HTML
form inputs.

---
