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

### R1 — Fix the verifier batch scheduler (prerequisite for everything)

**Defect:** when one expensive proof (a body sqlmap run, ~420 s) overruns the family's wall, the
whole batch action ends `action_incomplete` and **none** of its attempts record a completion —
including cheaper candidates that would have verified. Measured 2026-09-05: adding one login body
candidate took the SQLi family from verifying `sqli-search` to `action_incomplete` (planned 13,
attempted 10, completed 0), dropping recall 0.44 → 0.33.

**Change:** a batch must complete what it can afford within its wall and report the rest as
`unattempted`, checkpointing each finished attempt before starting the next, so a later overrun
never discards an earlier completion.

**Gate:** on the funded thorough authenticated Juice Shop benchmark, `sqli-search` still verifies
and recall does not drop below 0.44. Unit test: a batch whose Nth attempt would overrun the wall
still persists attempts 1..N-1 as completed and marks the rest unattempted, never `action_incomplete`
for the whole action.

### R2 — Re-land the auth-credential body synthesizer (target 5/9: sqli-login)

Under state-changing authority, synthesize a `POST <path>` endpoint with a JSON
`{email,username,password}` body for any discovered endpoint whose last path segment is
authentication-semantic (login/signin/authenticate/...). Written and unit-proven in this session
(reverted only because R1 was not yet done). A universal technique keyed on endpoint semantics, not
any one app's routes.

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

## Frozen for 2.3.0 (maintenance-only, adopted from the audit)

Keep working, do not expand: connected-device functionality, ASM functionality, scoring frameworks,
release-process abstractions, policy abstractions, generic UI surfaces, Model Intake breadth. The
release pipeline is sound after 2.2.0; it needs no more machinery.

## Hunt is the 2.4.0 objective, not 2.3.0

The audit's "make Hunt materially outperform Scan" bet is strategically right, but Hunt verifies
through the same deterministic proof moat and would hit the same starvation R1 fixes. 2.3.0 does one
cheap Hunt thing: **measure** Scan vs Scan+Hunt on Juice Shop with the existing keyless flow to
establish the audit's baseline table. Measurement only, no new Hunt build this release.

## Exit criteria for 2.3.0

- Juice Shop thorough authenticated recall ≥ 0.67 (6 of 9), `sqli-search` still verified, zero new
  false positives, on a current fleet.
- The candidate certifies **without** `waive_dast_quality`. `waive_e2e_debt` may remain only for
  rows R1–R4 do not touch, and each remaining row is re-declared with its new measurement.
- The benchmark runs on every PR touching `api/scan/**` or `scanner/**` and fails a recall drop.
- crAPI produces a non-degraded scorecard.
- No new subsystem was added; the frozen list above was not expanded.

If the bar is not met, ship nothing as 2.3.0; cut 2.2.x patches only.
