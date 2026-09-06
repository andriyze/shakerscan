# ShakerScan 2.3.0 plan: make the scanner as good as its architecture

**Status (2026-09-05): planning + implementation started.** Base is published 2.2.0 (`e1bd5058` on
`main`). Work is on `feat/2.3.0-dast-recall`.

## Why this release exists

An external audit of `main` at 2.2.0 reached the same conclusion the 2.2.0 release audit reached
independently: **ShakerScan is more advanced as a security-engineering architecture than it is as a
vulnerability-finding product.** The trust machinery — deterministic proof, budgets, receipts,
provenance, five-image release engineering — is excellent. The core question, *does the scanner
actually find the vulnerabilities*, has lagged. Juice Shop recall has sat at 0.44 (4 of 9 expected
classes) against a 0.67 bar (6 of 9) across 2.0.0, 2.0.1, 2.1.0, and 2.2.0, each shipped with the
DAST quality bar waived as declared debt.

2.3.0 has **one objective**: raise real Juice Shop recall from 4/9 to 6/9 and ship without a DAST
quality-bar waiver. Everything else is frozen.

## The governing rule (adopted from the audit)

> **No change merges into detection that does not move recall on the funded thorough authenticated
> benchmark, and no new subsystem ships until finding capability demonstrably improves.**

For every engineering cycle the question is: *did this make ShakerScan find something important it
previously missed?* If the answer is no, the work needs unusually strong justification. The reason
green infrastructure repeatedly hid weak product behavior is that recall was measured only in
certification, after merge. 2.3.0 moves that measurement onto the pull request (workstream R5).

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

### R2 — Re-land the auth-credential body synthesizer (target 5/9: sqli-login)

Under state-changing authority, synthesize a `POST <path>` endpoint with a JSON
`{email,username,password}` body for any discovered endpoint whose last path segment is
authentication-semantic (login/signin/authenticate/...). Written and unit-proven (surface synthesizer + candidate build). Reverted twice because it
regresses recall until R1's **allocator** change lands: on its own it displaces the `sqli-search`
verdict. Re-land only when R1's gate is green.

**Gate:** on the funded benchmark, `sqli-login` verifies as a critical, and total recall rises to
≥ 5/9 with `sqli-search` still verified (no starvation). Depends on R1.

### R3 — SPA client-route extraction (target 6/9: xss-dom-search, bar met)

Extract Angular and React client routes and their query parameters from the JS bundle into
fragment XSS candidates, so the existing `xss.browser_prove_batch` capability finally has DOM
candidates to attempt. This closes the discovery gap the crawler cannot: 158 routes found, 0 hash
routes.

**Gate:** `xss-dom-search` becomes browser-proven; recall ≥ 6/9, the bar met without a DAST waiver.

### R4 — The authenticated pair (stretch: bfla-users, nosqli-reviews)

Only after R1–R3. The two-principal BFLA differential on `/api/Users` and operator-injection
(`{$ne:...}`) candidates for `nosqli-reviews`. The benchmark already mints two principals.

**Gate:** each class it lands verifies with zero false positives; recall toward 8/9.

### R5 — Make the measurement mechanical (the last gate still living after merge)

Run the thorough authenticated benchmark on every pull request touching `api/scan/**` or
`scanner/**`, the way the PR gate now runs the E2E areas and the image vulnerability scan
(workstream from 2.2.0 PR #84). Recall was certify-only; that is why weak product behavior stayed
green until a candidate ran. This closes it.

**Gate:** a PR that lowers recall fails its own check, before merge.

### R6 — Fix the crAPI fixture so it is a real second signal

crAPI is structurally zero today: it collides with Juice Shop because web targets dedupe by host,
and the benchmark mints fresh accounts that own nothing to cross-read. Give it a distinct host and
seeded victim data so its BOLA/SQLi numbers mean something.

**Gate:** a crAPI benchmark run produces a non-degraded scorecard with authenticated responses
accepted and the BOLA families actually attempted.

## Frozen for 2.3.0 (maintenance-only)

**1. Freeze DAST feature expansion (operator direction, 2026-09-06).** Keep the current Scan
stable. Only fix recall, auth, discovery, proof, and regressions. Do **not** add a new scanner
family unless it *directly* improves benchmark recall. Scan stays the deterministic baseline for
CI/CD and quick coverage; the architecture already separates deterministic Scan from AI-driven
Hunt, and that separation is kept.

Also frozen, keep working but do not expand: connected-device functionality, ASM functionality,
scoring frameworks, release-process abstractions, policy abstractions, generic UI surfaces, Model
Intake breadth. The release pipeline is sound after 2.2.0; it needs no more machinery.

**2. Scan is primarily a discovery + baseline engine.** The recall work in R1–R6 serves this: Scan
should reliably produce endpoints, methods, parameter and body schemas, JS-discovered routes,
OpenAPI/GraphQL surfaces, technologies, authenticated browser traffic, two-principal context, the
obvious deterministic findings, and the HTTP transaction archive. The 2.0.1 OpenAPI ingestion and
authenticated-browser fixes are exactly this direction; R2 (auth-credential body) and R3 (SPA
route extraction) continue it. Deep, open-ended exploitation is Hunt's job, not Scan's.

## Architecture direction for 2.4.0 (operator direction, 2026-09-06)

Recorded now so 2.3.0's frozen scope is understood as deliberate, not neglect. These are 2.4.0,
built only after 2.3.0 meets its recall bar.

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

This is why R4 (the authenticated BOLA/NoSQL pair) is the *stretch* end of 2.3.0, not its core: those
classes are where Scan's deterministic reach ends and Hunt's adaptive reasoning begins. 2.3.0 lands
only the deterministic-reachable share; the adaptive remainder is Hunt's in 2.4.0.
## Exit criteria for 2.3.0

- Juice Shop thorough authenticated recall ≥ 0.67 (6 of 9), `sqli-search` still verified, zero new
  false positives, on a current fleet.
- The candidate certifies **without** `waive_dast_quality`. `waive_e2e_debt` may remain only for
  rows R1–R4 do not touch, and each remaining row is re-declared with its new measurement.
- The benchmark runs on every PR touching `api/scan/**` or `scanner/**` and fails a recall drop.
- crAPI produces a non-degraded scorecard.
- No new subsystem was added; the frozen list above was not expanded.

If the bar is not met, ship nothing as 2.3.0; cut 2.2.x patches only.
