# ShakerScan DAST — OWASP Coverage Matrix

**Status:** mechanism inventory reconciled 2026-07-11. This matrix records implemented check
families, not accepted recall, precision, or proof depth. Candidate acceptance belongs in
[`release-readiness.md`](release-readiness.md); future detector priorities are in
[`proposed-next-steps.md`](proposed-next-steps.md).

Scope: this maps the **DAST engine** (`scanner/scanner_tools/`) against the
OWASP Top 10 (2021) and OWASP API Security Top 10 (2023). AI Gate and Model
Intake are separate products and are out of scope here.

Legend: ✅ meaningful implemented checks exist · 🟡 partial, heuristic, or not benchmark-accepted ·
❌ no meaningful direct DAST check

> Note: ✅ means the engine ships meaningful checks for that category, not that
> every sub-technique is covered. Several ✅ rows still carry named gaps in their
> "Gaps" column.

## OWASP Top 10 (2021)

| ID | Category | Status | What the engine does | Gaps |
|----|----------|--------|----------------------|------|
| A01 | Broken Access Control | 🟡 | BOLA/IDOR (multi-user, enumeration, smart compare), forced browsing, vertical priv-esc, mass assignment, CORS, method-based auth bypass | Authenticated crAPI recall is not accepted; workflow/write-BOLA remains thin |
| A02 | Cryptographic Failures | ✅ | Full TLS/SSL suite (protocols, ciphers, PFS, cert sig/key, expiry, OCSP, Heartbleed/ROBOT/CCS/CRIME, PQC readiness), cookie `Secure`, cleartext `ws://` | — |
| A03 | Injection | 🟡 | SQLi (DBMS-aware), NoSQL, LDAP, XPath, command injection, SSTI, XXE, XSS (reflected/stored/DOM), CRLF/log, host-header, SSI/ESI, CSV/formula, gated RFI | Broad/stored XSS and universal authenticated discovery remain benchmark gaps |
| A04 | Insecure Design | 🟡 | Business-logic heuristics (price/qty/coupon), race conditions/TOCTOU | Design review is inherently out of black-box DAST scope |
| A05 | Security Misconfiguration | ✅ | Security headers, CORS, cookies, exposed files/`.git`/`.env`, directory listing, default creds, risky HTTP methods, cloud/k8s/registry exposure | SAML misconfig (see A07) |
| A06 | Vulnerable & Outdated Components | ✅ | JS dependency CVEs (retire.js-style, 30+ libs), server/tech version detection, Nuclei CVE templates | — |
| A07 | Identification & Authentication Failures | ✅ | Default creds, brute-force/rate-limit, 2FA bypass, session mgmt (flags/entropy/fixation), JWT (alg-none/confusion/kid/claims/JWKS), OAuth/OIDC | **SAML / SSO assertion attacks** (signature wrapping, replay) — Phase 2 |
| A08 | Software & Data Integrity Failures | 🟡 | Insecure deserialization (Java/PHP/Python/.NET/Ruby/Node), ViewState, gated server-side prototype pollution | SRI and unsigned-update coverage remain limited |
| A09 | Logging & Monitoring Failures | ✅ | Exposed logging/actuator/metrics endpoints, sensitive data in errors, stack traces, CRLF log injection, missing correlation headers | DAST observes only the externally-visible subset |
| A10 | SSRF | ✅ | Blind + visible SSRF, cloud-metadata SSRF (AWS/GCP/Azure/k8s) | Blind classes need an external OAST callback (`oob_callback_url`); no bundled collaborator — Phase 2 |

## OWASP API Security Top 10 (2023)

| ID | Category | Status | Notes |
|----|----------|--------|-------|
| API1 | Broken Object Level Authorization | 🟡 | Multi-user BOLA, ID enumeration, smart comparison; authenticated benchmark acceptance remains open |
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

The engine has broad implemented mechanisms, but category breadth is not equivalent to accepted
detector quality. The highest current acceptance gaps are authenticated access control, universal
authenticated API discovery, broad/stored XSS, workflow-aware checks, and strict proof-contract
enforcement. A04, API4, API6, and API10 also contain behavior that black-box DAST can only observe
partially or that ShakerScan intentionally excludes for safety, such as active denial of service.

---
