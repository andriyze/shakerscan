# ShakerScan 2.3.0 plan: make the scanner as good as its architecture

**Status (2026-09-06): scope changed by operator decision.** The DAST recall effort stops at the
measured 4/9; the release quality bar is set to that shipped level (no waiver needed); the work
moves to the architecture workstreams below. Base is published 2.2.0 (`e1bd5058` on `main`). Work
is on `feat/2.3.0-dast-recall`.

## Why this release exists

An external audit of `main` at 2.2.0 reached the same conclusion the 2.2.0 release audit reached
independently: **ShakerScan is more advanced as a security-engineering architecture than it is as a
vulnerability-finding product.** The trust machinery — deterministic proof, budgets, receipts,
provenance, five-image release engineering — is excellent. The core question, *does the scanner
actually find the vulnerabilities*, has lagged. Juice Shop recall has sat at 0.44 (4 of 9 expected
classes) against a 0.67 bar (6 of 9) across 2.0.0, 2.0.1, 2.1.0, and 2.2.0, each shipped with the
DAST quality bar waived as declared debt.

2.3.0 was written with **one objective**: raise real Juice Shop recall from 4/9 to 6/9 and ship
without a DAST quality-bar waiver. **On 2026-09-06 the operator stopped that fight.** Two sessions
of measured work (R1 below) fixed a real crash and restored the 0.44 baseline, and moved recall by
exactly zero above it. The decision: stop improving DAST for the find rate, set the quality bar to
the shipped level so the release certifies without any waiver, and move on to the architecture
workstreams. The answer key is unchanged; the five misses stay declared as the visible distance.

## The governing rule (adopted from the audit)

> **No change merges into detection that does not move recall on the funded thorough authenticated
> benchmark, and no new subsystem ships until finding capability demonstrably improves.**

For every engineering cycle the question is: *did this make ShakerScan find something important it
previously missed?* If the answer is no, the work needs unusually strong justification. The reason
green infrastructure repeatedly hid weak product behavior is that recall was measured only in
certification, after merge.

**Applied on 2026-09-06.** By this rule the detection changes beyond R1 (the synthesizer, the
body-slot work) do not merge: they did not move recall on the funded benchmark. Certification keeps
measuring every candidate; the fixture's regression gates and gap list are the regression detector
at the shipped level. The measurement is deliberately *not* moved onto the PR loop (see R5).

## The five missed classes (ground truth, measured 2026-09-05 against the live app)

| Class | Route | Why it is missed today |
|---|---|---|
| sqli-login | `/rest/user/login` | The worker's own sqlmap PROVES it once the POST `{email,password}` body is known. The endpoint is discovered, but only as a bare GET path — the passive crawl never submits the form, so no body candidate is built. Blocked further by the scheduler defect (R1). |
| xss-dom-search | `#/search` | katana `-jc -jsl` finds 158 routes and ZERO hash routes. The Angular client route lives only in the JS bundle. The browser proof capability exists but never gets a DOM candidate to attempt. |
| xss-reflected | `/rest/track-order` | Route discovered; a payload comes back percent-encoded in an Express error title, not a clean server reflection. Lower confidence. |
| bfla-users | `/api/Users` | Authenticated; needs the two-principal cross-principal differential oracle. The benchmark already mints two users. |
| nosqli-reviews | `PATCH /rest/products/reviews` | Authenticated; needs an operator-injection (`{$ne:...}`) candidate under auth. |

## Workstreams, in dependency order

### R1 — A single failing candidate must not crash the whole verifier batch (the real bug)

**True diagnosis (2026-09-06, from the worker log — after two wrong diagnoses from the coverage
rollup).** The regression was never budget starvation or cross-slice allocation. `GET
/scans/{id}/actions` and the worker log show the base action **crashed**: `verify.sqli.r01` and
`verify.xss.r01` `failed` with "The capability adapter failed" and the worker logged
`[scan] action verify.sqli.r01 adapter raised ValueError`, while the sliced `.001.r01` actions
succeeded. `_external_batch` resolves and executes each candidate with **no per-candidate guard**, so
one candidate that raises (a `ScanWorkManifestError`, which subclasses `ValueError`, from
`execution_request_for_manifest_candidate`) propagates out and the orchestrator fails the entire
action — every candidate in that slice, `sqli-search` included, loses its verdict. Adding the
synthesized login endpoint shifted the manifest so a candidate in the base slice no longer resolved;
without the guard, that one candidate took the family to 0 verified.

Two earlier "diagnoses" in this document's history — a wall-overrun and a cross-slice budget
displacement — were both read from the family-coverage rollup and were both wrong. The lesson is now
a binding rule in AGENTS.md: read the action error and worker log before theorising.

**Change:** wrap per-candidate processing in `_external_batch` so a candidate that fails to resolve
or execute is recorded as a failed attempt and the batch continues to the next candidate. A batch
never fails wholesale because one candidate raised.

**Gate:** unit test — a batch whose one candidate's resolver raises still completes and checkpoints
the others, and the action is `partial`, never `failed`. Live: with the synthesized login body
candidate present, `sqli-search` still verifies and recall does not drop below 0.44. This must be
green before R2 re-lands.

**Kept sub-component (secondary, tested):** `order_batch_rows_by_cost_class` still attempts cheaper
cost classes first within a slice — correct once slices mix cost classes, but it is not what fixed
the regression.

**R1 LANDED (2026-09-06, log-diagnosed then measured; commit d85c29e3).** Two robustness fixes in
`_external_batch`, both unit-proven and measured on the funded authed benchmark: (a) the whole
per-candidate body is wrapped so a candidate that raises anywhere is a failed attempt, not a dead
action; (b) a body candidate's HTTP reservation is bound to its state-changing reservation, because
every body request is a mutation and `capabilities/scanner.py` requires `state_changing_requests >=
http_requests` (the real crash `body scanner requires a conservative state-changing reservation`,
read from the worker log). Result: **zero adapter crashes**, `verify.sqli` is `partial` not
`failed`, `prove.sqli` runs `success`, `sqli-search` verifies, recall holds 0.44 with a synthesized
body candidate present. R1's gate is green.

**Remaining blocker for sqli-login, corrected from the action's own budget record.** An earlier
version of this paragraph blamed a starved proof stage; that was wrong. `prove.sqli.r01` used 4 of
its 104 requests and 1 of 156 seconds, proved `products/search` at once, and had budget to spare.
The binding dimension is **state-changing requests in the verify stage**: `verify.sqli.r01`
consumed exactly 480 of 480 (HTTP 1,844 of 3,200 and wall 765 of 1,440 were left over) and ended
`partial / insufficient_plan_budget`. One request-body SQLi attempt costs a measured 480
state-changing requests (`BATCH_ATTEMPT_BODY_FLOORS`), and the planner's `_BATCH_BODY_HOLD`
reserves exactly one such hold per verify slice, so each slice funds **one** body candidate. On
thorough that is two slots, and the login only verifies if a slot lands on the real login endpoint
rather than a synthesized `/session` or `/signin`. The login then still has to be flagged by the
verifier before proof ever sees it. That is ranking plus funding plus detection, all three, and it
is where the effort was stopped. The synthesizer stays reverted.

### R2 — Re-land the auth-credential body synthesizer (target 5/9: sqli-login)

**STOPPED (operator decision, 2026-09-06).** Not pursued as Scan work. Adaptive login probing is
Hunt's job (workstream A4). The text below is kept as the record of what it needs.

Under state-changing authority, synthesize a `POST <path>` endpoint with a JSON
`{email,username,password}` body for any discovered endpoint whose last path segment is
authentication-semantic (login/signin/authenticate/...). Written and unit-proven (surface synthesizer + candidate build). Reverted twice. The
regression it triggered was the R1 crash, since fixed; with the crash fixed it held 0.44 and still
did not land sqli-login (see R1's corrected blocker: one funded body slot per verify slice).

**Gate:** on the funded benchmark, `sqli-login` verifies as a critical, and total recall rises to
≥ 5/9 with `sqli-search` still verified (no starvation). Depends on R1.

### R3 — SPA client-route extraction (target 6/9: xss-dom-search, bar met)

**STOPPED (operator decision, 2026-09-06).** `xss-dom-search` stays a declared gap. JS route
analysis, if built, lands as a shared capability (A1), not as a Scan feature.

Extract Angular and React client routes and their query parameters from the JS bundle into
fragment XSS candidates, so the existing `xss.browser_prove_batch` capability finally has DOM
candidates to attempt. This closes the discovery gap the crawler cannot: 158 routes found, 0 hash
routes.

**Gate:** `xss-dom-search` becomes browser-proven; recall ≥ 6/9, the bar met without a DAST waiver.

### R4 — The authenticated pair (stretch: bfla-users, nosqli-reviews)

**STOPPED as Scan work (operator decision, 2026-09-06).** These are the first targets of A4: the
BOLA/BFLA differential is the worked example of Hunt's reasoning loop.

Only after R1–R3. The two-principal BFLA differential on `/api/Users` and operator-injection
(`{$ne:...}`) candidates for `nosqli-reviews`. The benchmark already mints two principals.

**Gate:** each class it lands verifies with zero false positives; recall toward 8/9.

### R5 — Make the measurement mechanical (the last gate still living after merge)

**DROPPED.** It conflicts with a characterized decision the repository already made:
`test_the_benchmark_is_not_in_the_build_test_loop` keeps the benchmark out of the PR loop on
purpose, to keep benchmark-fitting pressure low. Certification measures every candidate; that is
enough once the bar is the shipped level.

Run the thorough authenticated benchmark on every pull request touching `api/scan/**` or
`scanner/**`, the way the PR gate now runs the E2E areas and the image vulnerability scan
(workstream from 2.2.0 PR #84). Recall was certify-only; that is why weak product behavior stayed
green until a candidate ran. This closes it.

**Gate:** a PR that lowers recall fails its own check, before merge.

### R6 — Fix the crAPI fixture so it is a real second signal

**DEFERRED (operator decision, 2026-09-06).** crAPI does not gate certification (only the Juice
Shop fixture runs in the installed-stack smoke), so it blocks nothing.

crAPI is structurally zero today: it collides with Juice Shop because web targets dedupe by host,
and the benchmark mints fresh accounts that own nothing to cross-read. Give it a distinct host and
seeded victim data so its BOLA/SQLi numbers mean something.

**Gate:** a crAPI benchmark run produces a non-degraded scorecard with authenticated responses
accepted and the BOLA families actually attempted.

## The bar at the shipped level (2026-09-06)

The threshold that forced the waiver was never the fixture's regression gates (those pass at 0.44
with every miss declared). It was the fixture's `quality_bar`, which `--enforce-quality` binds in
full and which `certify_release_receipt.py` requires as `quality_bar_passed`:

| Check | Was | Now | Why |
|---|---|---|---|
| `min_expected_recall` | 0.67 | 0.44 | the measured, reproducible level on the funded thorough authenticated run |
| `require_browser_proven_xss` | true | false | `xss-dom-search` is a declared gap; no DOM/fragment discovery exists |
| `require_reliable_grade` | true | false | out of reach of budget tuning inside the wall ceiling (fixture comment) |
| `max_known_expectation_gaps` | 0 | 5 | exactly the declared gaps; the list may shrink, never grow |

What still fails a candidate: recall below 0.44, any miss that is not declared, a sixth declared
gap, no verified SQLi, an unverified-high ratio above 0.35, an auth workflow that is not ready, a
selected family with zero attempts. `test_the_release_bar_is_pinned_to_the_declared_shipped_level`
pins the bar to the regression gates so it cannot drift to an arbitrary number, and
`test_the_gap_list_may_shrink_but_never_grow_past_the_shipped_level` proves a sixth gap fails.

**Proof.** Re-scoring the last measured card (scan `5d27b184`, 2026-09-06, current build) under
`--enforce-quality`: every regression gate passes and the quality bar is MET. **Release
consequence:** dispatch 2.3.0 candidates with `waive_dast_quality=false` and `waive_e2e_debt=false`.
The shipped 2.2.0 candidate's E2E scorecard carried zero declared-debt rows, so neither waiver is
needed.

## Frozen for 2.3.0 (maintenance-only)

**1. Freeze DAST feature expansion (operator direction, 2026-09-06).** Keep the current Scan
stable. Only fix recall, auth, discovery, proof, and regressions. Do **not** add a new scanner
family unless it *directly* improves benchmark recall. Scan stays the deterministic baseline for
CI/CD and quick coverage; the architecture already separates deterministic Scan from AI-driven
Hunt, and that separation is kept.

Also frozen, keep working but do not expand: connected-device functionality, ASM functionality,
scoring frameworks, release-process abstractions, policy abstractions, generic UI surfaces, Model
Intake breadth. The release pipeline is sound after 2.2.0; it needs no more machinery.

**2. Scan is primarily a discovery + baseline engine.** R1 served this; R2–R6 are stopped: Scan
should reliably produce endpoints, methods, parameter and body schemas, JS-discovered routes,
OpenAPI/GraphQL surfaces, technologies, authenticated browser traffic, two-principal context, the
obvious deterministic findings, and the HTTP transaction archive. The 2.0.1 OpenAPI ingestion and
authenticated-browser fixes are exactly this direction; R2 (auth-credential body) and R3 (SPA
route extraction) continue it. Deep, open-ended exploitation is Hunt's job, not Scan's.

## Architecture workstreams (the 2.3.0 work from 2026-09-06)

With the recall fight stopped, these are the release's active workstreams, in dependency order.
Each keeps the governing rule's spirit: it must demonstrably improve finding capability, measured
on the same target, before the next one starts.

| # | Workstream | Gate |
|---|---|---|
| A0 | **Baseline table.** Measure Scan alone vs Scan + Hunt on the benchmark target with the existing keyless Hunt flow. No new build. | A recorded table: classes found by Scan, by Hunt, by both; zero false verified findings. |
| A1 | **One shared capability layer.** Audit the registry for Scan-only and Hunt-only primitives; converge one real primitive first (`sqlmap.verify` or `js.analyze`) so both engines call the same registry entry. | Both engines execute the converged capability through one registry entry, one budget reservation, one evidence contract; no parallel registry (invariant 10). |
| A2 | **Structured target memory.** A queryable target-knowledge model the loop reads and updates each turn, built on the existing Hunt evidence and `/hunts/{id}/query`. | A Hunt turn receives compact structured memory, never raw transactions; a repeated hypothesis is recognised as already tried. |
| A3 | **The reasoning loop.** Observe, hypothesize, select, execute, inspect, update, verify, repeat; verifying only through the deterministic proof moat. | On A0's target, Scan + Hunt finds at least one class Scan alone does not, verified, zero false positives. |
| A4 | **Advanced discovery moves into Hunt.** BOLA/BFLA first (the worked loop below), then login probing, NoSQL operator injection, GraphQL, stored XSS, chains. | `bfla-users` or a BOLA class verified by Hunt through the moat; the Scan gap list can shrink by that class. |

### A0 result (measured 2026-09-06, Juice Shop, current build)

| Answer-key class | Scan alone | Hunt today | Why |
|---|---|---|---|
| sqli-search | **verified** (critical) | inherits Scan | deterministic SQLi proof |
| exposed-metrics / -ftp-listing / -confidential | **verified** (high) | inherits Scan | exposure probe cluster |
| sqli-login | miss | miss | Scan: one 480-request body slot per verify slice; Hunt: no login-injection loop |
| xss-dom-search | miss | miss | needs DOM/hash-route discovery |
| xss-reflected | miss | miss | percent-encoded reflection only |
| bfla-users | miss | **miss (blocked)** | Hunt's `authz.verify` needs an interactive session; see below |
| nosqli-reviews | miss | miss | needs authenticated operator-injection |

**Scan alone reaches 4/9. Hunt adds zero verified classes over Scan on this target today**, and the
reason is specific and code-confirmed, not a tuning gap:

1. **The auth/session primitives do not converge (this is what A1 must fix).** The Hunt's only
   deterministic cross-principal proof, `authz.verify`, requires two interactive sessions from
   `auth.session.establish`. That capability supports exactly `form_login` (parses an HTML `<form>`),
   `oauth_client_credentials`, and `oauth_password` (`api/capabilities/auth.py` `SESSION_AUTH_KINDS`).
   Juice Shop — like most modern APIs — authenticates with a JSON login (`POST /rest/user/login`
   with `{email,password}`) that returns a JWT in the response body. A `bearer_token` profile is
   rejected outright (`credential is not an interactive HTTP profile`), and `form_login` finds no
   HTML form. So the Hunt cannot establish the sessions its BOLA/BFLA proof needs, on the exact class
   of target (JSON + JWT) that is the common case. The Scan authenticates the same target fine with a
   bearer profile. **That divergence is the concrete A1 target.**
2. **The endpoint knowledge base is unstructured and noisy (this is what A2 must fix).** The Hunt's
   prior-knowledge inventory for this target is ~3,000 endpoints, of which ~2,000 are
   content-discovery phantoms (`/api/Cards/admin`, `/api/Addresss/basket`, all with an identical
   generic `id,limit,offset,page,token` param shape). A reasoning loop handed this raw cannot tell a
   real route from wordlist noise. This is exactly the motivation for A2's structured target memory.

**Consequence for A1.** A0 reprioritises A1's first convergence. The originally-named candidates
(`sqlmap.verify`, `js.analyze`) are real duplication, but the *blocking* divergence is the
auth/session primitive: a target the Scan can authenticate must also be able to drive the Hunt's
`authz.verify`. A1's first converged primitive is therefore the credential/session layer.

The rationale for each, as the operator stated it:

**3. One shared capability layer.** Scan and Hunt use the *same* primitives; Hunt chooses
capabilities and ShakerScan executes and enforces policy. This is convergence on the capability
registry that already exists (AGENTS.md invariant 5: one canonical registry entry per executable
capability), not a new subsystem. The target primitive set: `http.request`, `browser.navigate`,
`browser.execute`, `credential.use`, `response.diff`, `nuclei.run`, `sqlmap.verify`, `xss.verify`,
`graphql.inspect`, `js.analyze`, `oob.allocate`, `evidence.save`. No Hunt-specific scanners; the
2.3.0 recall work (R2 body verifier, R3 JS route analysis) lands as capabilities both engines share.

**4. Hunt becomes a real reasoning loop.** A persistent loop: observe → hypothesize → select
capability → execute → inspect evidence → update hypothesis → verify → repeat. It verifies through
the same deterministic proof moat, so it depends on R1 (a single failing capability must not crash
the run) being solid first. 2.3.0 does one cheap Hunt thing only: **measure** Scan vs Scan+Hunt on
Juice Shop with the existing keyless flow to establish the audit's baseline table. Measurement only,
no new Hunt build this release.

**5. Give Hunt structured target memory.** A durable target-knowledge model, not raw HTTP records
fed to the agent every turn. It holds: endpoints, parameters, principals, observed objects/IDs,
authentication state, technologies, interesting responses, hypotheses tried, failed hypotheses,
verified attack relationships, and previous Hunt findings. The agent gets compact structured memory
plus retrieval, never thousands of raw transactions. ShakerScan already persists evidence and Hunt
records (`GET /hunts/{id}/query`); this makes that a first-class, queryable target graph the loop
in point 4 reads and updates each turn.

**6. Move advanced vulnerability discovery into Hunt.** Gradually stop expanding giant deterministic
logic for BOLA/IDOR, business logic, multi-step auth flaws, GraphQL abuse, stored XSS, workflow
bypass, and chained vulnerabilities. Deterministic Scan still detects the obvious cases; Hunt handles
the adaptive investigation, verifying through the same deterministic proof moat. The worked loop:

```text
Scan discovers /api/orders/{id}
   -> Hunt notices object IDs + two principals
   -> replay with principal B
   -> compare ownership
   -> enumerate bounded adjacent objects
   -> deterministic proof engine verifies BOLA
```

This is why R4 is stopped as Scan work: those classes are where Scan's deterministic reach ends
and Hunt's adaptive reasoning begins. They are A4's first targets.

## Exit criteria for 2.3.0 (revised 2026-09-06)

- Juice Shop thorough authenticated recall holds at ≥ 0.44 with `sqli-search` verified, no
  undeclared miss, no new false positives, on a current fleet. R1 is in.
- The candidate certifies with **no waivers**: `waive_dast_quality=false`, `waive_e2e_debt=false`.
- A0's baseline table is recorded, and at least A1 has landed with its gate met.
- No new subsystem was added; the frozen list above was not expanded. Hunt work reuses the
  existing registry, ledger, evidence, and proof paths (invariant 10).
