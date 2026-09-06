# Hunt architecture — findings and the convergence backlog

This document collects what the A0 baseline measurement (2026-09-06) revealed about the Hunt
runtime, and the architectural fixes it implies. It is the working reference for the 2.3.0
architecture workstreams (A0–A4 in `release-2.3.0-plan.md`). Findings are stated as they were
measured on the live stack, not as design intent.

## The one-line finding

On Juice Shop, the deterministic Scan reaches 4/9 answer-key classes and the Hunt adds **zero**
verified classes over it today. The Hunt's headline capability — the two-principal BOLA/BFLA
differential — cannot run on the target at all, for two structural reasons below. Neither is a
tuning gap; both are convergence gaps the plan already names.

## Finding 1 — the auth/session primitive does not converge (A1)

**Symptom.** A credentialed two-principal Hunt on Juice Shop cannot establish the sessions its
`authz.verify` proof requires. `auth.session.establish` returns
`contract:credential is not an interactive HTTP profile` for a bearer-token profile.

**Root cause.** `authz.verify` (the only deterministic cross-principal proof) requires two
interactive sessions from `auth.session.establish`. That capability's `SESSION_AUTH_KINDS`
(`api/capabilities/auth.py`) is exactly `{form_login, oauth_client_credentials, oauth_password}`:

- `form_login` GETs the login page and parses an HTML `<form>`.
- the OAuth kinds POST a form-encoded grant.

Juice Shop — and the large class of modern JSON APIs — authenticates with a JSON body
(`POST /rest/user/login {email,password}`) that returns a JWT in the **response body**
(`{"authentication":{"token": "..."}}`). No supported kind performs a JSON login, and the existing
body-token extractor in `_session_headers` reads only the OAuth-standard `access_token`, not a
nested `authentication.token`. The Scan authenticates the same target fine with a bearer profile, so
the two engines' credential paths have diverged.

**Why it matters.** `authz.verify`'s proof engine
(`verify_target_bound_object_authorization`) already runs the differential from two **identity
header dicts**, not from session objects — the session wrapper only supplies those headers. So the
proof engine is ready; only the way a principal's identity is obtained is missing for JSON+JWT
targets.

**Fix (A1, in progress).** Add a `json_login` session auth kind: POST a JSON credential body to the
login endpoint and retain the returned JWT as the session's `Authorization: Bearer` header. This
reuses the existing proof engine unchanged (one registry entry, one evidence contract — AGENTS.md
invariant 5/10) and unblocks BOLA/BFLA on JSON+JWT APIs, which is the common modern case, not a
Juice-Shop special case.

## Finding 2 — the endpoint knowledge base is unstructured and phantom-dominated (A2)

**Symptom.** The Hunt's prior-knowledge endpoint inventory for the target is ~3,000 rows. About
two-thirds are content-discovery phantoms: `/api/Cards/admin`, `/api/Addresss/basket`,
`/api/Cards/2fa`, all carrying the identical generic param shape `id,limit,offset,page,token`.

**Root cause.** Discovery writes every probed path into the same endpoint inventory the Hunt reads
back, with no confidence or provenance separation between an observed real route and a wordlist
guess that returned a soft-200. A reasoning loop handed this raw cannot tell a real route from noise
and will spend its budget on phantoms.

**Fix (A2, planned).** Structured target memory: a queryable target-knowledge model with
provenance and confidence, built on the existing evidence store and `/hunts/{id}/query`, so a Hunt
turn receives a compact, ranked, real-route view rather than the raw discovery dump.

## Operational gotchas (save re-learning these)

- A credentialed Hunt needs its approval receipt minted at `risk_tier:"credential"` and with **no**
  `action_name`. An action-bound receipt (e.g. the benchmark's `scan.submit`) is rejected with
  "Approval receipt is bound to a different action"; an `active`-tier receipt is rejected with
  "Approval receipt risk tier does not cover the requested action".
- `http.request` (Hunt) accepts `as_principal: primary|secondary|service` and injects the managed
  credential without a `session_ref`. `authz.verify` and `auth.session.establish` are separate and
  session-based — that asymmetry is Finding 1.
- Juice Shop `/rest/user/whoami` returns `{"user":{}}` even with a valid bearer sent directly, so it
  is a bad authentication oracle. Judge injection by a real authenticated endpoint, not whoami.
- Reuse the benchmark's authority helpers for setup:
  `scripts.benchmark_targets._canonical_benchmark_authority`, `mint_token`,
  `_create_benchmark_bearer_profile`. The Juice Shop lab target is registered as
  `749f7228-87ab-4ebb-bab3-66ec487a7a79` (`http://host.docker.internal:3001`).

## Status

| Finding | Workstream | State |
|---|---|---|
| Auth/session divergence | A1 | fix in progress: `json_login` session kind |
| Phantom-dominated inventory | A2 | planned |
| Hunt adds 0 over Scan | A3 measurement gate | blocked on A1 |
