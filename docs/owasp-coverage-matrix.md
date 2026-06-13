# ShakerScan DAST — OWASP Coverage Matrix

Scope: this maps the **DAST engine** (`scanner/scanner_tools/`) against the
OWASP Top 10 (2021) and OWASP API Security Top 10 (2023). AI Gate and Model
Intake are separate products and are out of scope here.

Legend: ✅ Strong coverage — implemented active checks exist (NOT a claim of
exhaustive coverage of the category) · 🟡 Partial / detection-only · ❌ Missing

> Note: ✅ means the engine ships meaningful checks for that category, not that
> every sub-technique is covered. Several ✅ rows still carry named gaps in their
> "Gaps" column.

## OWASP Top 10 (2021)

| ID | Category | Status | What the engine does | Gaps |
|----|----------|--------|----------------------|------|
| A01 | Broken Access Control | ✅ | BOLA/IDOR (multi-user, enumeration, smart compare), forced browsing, vertical priv-esc, mass assignment, CORS, method-based auth bypass | — |
| A02 | Cryptographic Failures | ✅ | Full TLS/SSL suite (protocols, ciphers, PFS, cert sig/key, expiry, OCSP, Heartbleed/ROBOT/CCS/CRIME, PQC readiness), cookie `Secure`, cleartext `ws://` | — |
| A03 | Injection | 🟡→✅ | SQLi (DBMS-aware), NoSQL, LDAP, XPath, command injection, SSTI, XXE, XSS (reflected/stored/DOM), CRLF/log, host-header | **SSI/ESI**, **CSV/formula**, **RFI (active)** — *now implemented* |
| A04 | Insecure Design | 🟡 | Business-logic heuristics (price/qty/coupon), race conditions/TOCTOU | Design review is inherently out of black-box DAST scope |
| A05 | Security Misconfiguration | ✅ | Security headers, CORS, cookies, exposed files/`.git`/`.env`, directory listing, default creds, risky HTTP methods, cloud/k8s/registry exposure | SAML misconfig (see A07) |
| A06 | Vulnerable & Outdated Components | ✅ | JS dependency CVEs (retire.js-style, 30+ libs), server/tech version detection, Nuclei CVE templates | — |
| A07 | Identification & Authentication Failures | ✅ | Default creds, brute-force/rate-limit, 2FA bypass, session mgmt (flags/entropy/fixation), JWT (alg-none/confusion/kid/claims/JWKS), OAuth/OIDC | **SAML / SSO assertion attacks** (signature wrapping, replay) — Phase 2 |
| A08 | Software & Data Integrity Failures | 🟡→✅ | Insecure deserialization (Java/PHP/Python/.NET/Ruby/Node), ViewState | **Server-Side Prototype Pollution** — *now implemented*; SRI / unsigned-update checks — Phase 2 |
| A09 | Logging & Monitoring Failures | ✅ | Exposed logging/actuator/metrics endpoints, sensitive data in errors, stack traces, CRLF log injection, missing correlation headers | DAST observes only the externally-visible subset |
| A10 | SSRF | ✅ | Blind + visible SSRF, cloud-metadata SSRF (AWS/GCP/Azure/k8s) | Blind classes need an external OAST callback (`oob_callback_url`); no bundled collaborator — Phase 2 |

## OWASP API Security Top 10 (2023)

| ID | Category | Status | Notes |
|----|----------|--------|-------|
| API1 | Broken Object Level Authorization | ✅ | Multi-user BOLA, ID enumeration, smart comparison |
| API2 | Broken Authentication | ✅ | JWT, OAuth, session, default creds |
| API3 | Broken Object Property Level Authorization | ✅ | Mass assignment + excessive-data-exposure |
| API4 | Unrestricted Resource Consumption | 🟡 | Rate-limit detection, GraphQL depth/batch/alias; active resource-exhaustion intentionally not run |
| API5 | Broken Function Level Authorization | ✅ | BFLA endpoint probing |
| API6 | Unrestricted Access to Sensitive Business Flows | 🟡 | Business-logic + race-condition heuristics |
| API7 | SSRF | ✅ | Shared with A10 |
| API8 | Security Misconfiguration | ✅ | Shared with A05 |
| API9 | Improper Inventory Management | 🟡 | OPTIONS/OpenAPI/gRPC discovery + scan-delta; no formal version/deprecation inventory |
| API10 | Unsafe Consumption of APIs | ❌ | Upstream-API trust is largely outside black-box DAST; partially touched by SSRF + vendor risk |

## Summary

The engine has **strong coverage** (implemented active checks, not exhaustive)
across A01, A02, A05, A06, A07, A09, A10 and most of the API Top 10 — several of
those still carry named sub-technique gaps. The actionable, implementable gaps are concentrated in
**A03 (Injection)** and **A08 (Integrity)**. The remaining gaps (A04/A06-design,
API4/API6/API10) are either inherent limits of black-box DAST or intentionally
excluded for safety (active DoS).

---

# Implementation Plan

## Phase 1 — Injection & Integrity gaps (this change)

Implemented in a new module `scanner_tools/injection_extra_checks.py`, wired into
the Phase 4 active-testing stage of `build_report()`. All checks are
**differential and false-positive conservative**: a finding requires an injected
payload to produce an observable evaluation/inclusion that a benign control
payload does not.

Active-safety gating (driven by `safe_mode`, set from `exploit_level`):

- **SSI/ESI and CSV** are GET-only reflection probes (same risk profile as the
  existing XSS/open-redirect checks) and run on `full`/`aggressive`/`smart`.
- **RFI** (induces a server-side fetch) and **server-side prototype pollution**
  (sends state-changing POST/PUT bodies) run **only on the aggressive tier**, like
  the engine's SSRF / command-injection probes — never in a default Phase 4 scan.

| Check | OWASP | CWE | Technique | Severity |
|-------|-------|-----|-----------|----------|
| SSI injection | A03 | CWE-97 | `<!--#echo var="DATE_LOCAL"-->` between unique markers; positive only on date/time evaluation, not on tag-stripping | high |
| ESI injection | A03 | CWE-97 | `<esi:vars>$(HTTP_HOST)</esi:vars>` between markers; positive only when the request Host expands inline | high |
| Server-Side Prototype Pollution | A08/A05 | CWE-1321 | "JSON spaces" indentation oracle (`{"__proto__":{"json spaces":7}}`) with baseline diff + automatic revert | high |
| CSV / Formula injection | A03 | CWE-1236 | Formula-prefixed payload (`=`,`+`,`-`,`@`) reflected unescaped at a CSV/Excel cell boundary | medium |
| Remote File Inclusion | A03 | CWE-98 | Self-referential differential: include a same-origin resource and confirm its distinctive content appears inline | high |

## Phase 2 — Deferred (needs external infra or non-HTTP targets)

These are documented but not implemented here because they cannot be honestly
validated against the available test target (OWASP Juice Shop):

- **SAML / SSO assertion attacks** (XML signature wrapping, assertion replay) — needs a SAML IdP/SP target.
- **HTTP/2-specific request smuggling** (h2c upgrade, CONTINUATION flood) — needs an h2-capable origin and carries DoS risk.
- **Built-in OAST/collaborator server** — would upgrade every blind class (SSRF/SQLi/XXE/RFI) from in-band-only to true out-of-band; infra project in its own right.
- **Reflected File Download (RFD)** and **DOM clobbering** — low-prevalence client-side classes; candidates for the static client-side analyzer.

## Validation

Phase 1 checks are validated two ways:
1. **True-positive** — a stdlib mock server (`tests/test_injection_extra.py`) that
   simulates each vulnerability; every check must detect it.
2. **False-positive safety / integration** — run against OWASP Juice Shop
   (`http://localhost:3001`, `host.docker.internal:3001` from the worker) to
   confirm the checks execute end-to-end and do not fire on a target not
   vulnerable to these specific classes.
