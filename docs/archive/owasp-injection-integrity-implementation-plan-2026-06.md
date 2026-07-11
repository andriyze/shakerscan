# OWASP Injection and Integrity Implementation Plan

**Archived:** 2026-07-11. This is the completed implementation/validation record that was formerly
embedded in the live OWASP mechanism matrix. Current coverage and acceptance caveats belong in
`docs/owasp-coverage-matrix.md` and `docs/proposed-next-steps.md`.

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
1. **True-positive** — a stdlib mock server (`scanner/tests/test_injection_extra.py`) that
   simulates each vulnerability; every check must detect it.
2. **False-positive safety / integration** — run against OWASP Juice Shop
   (`http://localhost:3001`, `host.docker.internal:3001` from the worker) to
   confirm the checks execute end-to-end and do not fire on a target not
   vulnerable to these specific classes.
