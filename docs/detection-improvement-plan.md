# Detection improvement plan

**Status:** plan, opened 2026-11-24 against engine 2.14.1. Work lands on the branch that carries
this file; each phase below records what has been done.

This plan raises what a deterministic Scan proves. It does not change the product model: there is
still one Scan and one Hunt, profiles are ceilings, active testing is a permission, and a finding
is reported as verified only with repeatable proof (see [AGENTS.md](../AGENTS.md)).

## Where a Scan stands

The [OWASP coverage matrix](owasp-coverage-matrix.md) is the maintained statement of what a Scan
checks. In short, at 2.14.1:

- A Scan had eleven families (`api/scan/contracts.py`): recon, passive and active templates, XSS,
  SQL injection, NoSQL injection, object- and function-level authorization, sensitive exposure,
  GraphQL posture and active recon.
- Injection proof exists for SQL injection and XSS only. There is no generic check for command
  injection, server-side template injection, path traversal, XXE, SSRF, JWT weaknesses, mass
  assignment, CSRF or stored XSS through forms.
- The SQL injection proof (`api/capabilities/sqli_proof.py`) has an error pair, a sign-in bypass
  pair, an AND-boolean pair and one time payload written for MySQL.
- Active templates are limited to high and critical severity with four tags, and a template match
  is a candidate, never a proof.
- A candidate records the request content type but not the response media type, so XSS
  verification is also spent on responses a browser would never render.
- Findings are published when the Scan completes.

## Principles

1. **Measure before and after.** Every change in this plan is judged by proven recall, false
   positives and scan time on the same benchmark targets, at the same profile, before and after.
2. **Discovery before verifiers.** A verifier cannot test a request the Scan never learned about.
3. **One proof core.** New classes are payload sets on a shared control/probe/repeat verifier,
   not separate implementations with separate rules for what counts as proof.
4. **Candidates are cheap, proof is strict.** Templates and heuristics may propose; only a
   repeated differential with a control may verify.
5. **No new authority.** Every new request stays inside the existing budgets, traffic risk
   classes ([ADR 0001](decisions/0001-scan-traffic-risk-classes.md)) and target authorization.

## Phases

### Phase 0: a number for detection

- A scorecard per benchmark target: expected entries proven, candidates, false positives, wall
  time and time to first finding, produced by `scripts/benchmark_targets.py` and the miss
  analysis in `tests/benchmark/`.
- The scorecard runs for every detection or budget change and blocks a release when proven
  recall falls.
- More benchmark targets with answer keys beyond Juice Shop, crAPI and honey: one API-only
  application, one GraphQL application and one classic server-rendered application. Answer keys
  are certification gates and change only through the
  [benchmark integrity ledger](ledgers/benchmark-integrity-ledger.md).

Exit: the scorecard is published with each release's notes.

### Phase 1: spend the budget on real candidates

- An OpenAPI document whose server URL is empty resolves to the document's directory, not to the
  document itself (otherwise every route of the specification is requested under the document's
  own path).
- More well-known secret-bearing deployment files in the sensitive-exposure seed list.
- A sign-in request body is proven for SQL injection without waiting for a signal from the
  external verifier.
- Every SQL injection slice keeps at least one funded verifier attempt; body candidates hold
  their own request allowance.
- The response media type is recorded at discovery; a response that is not HTML (and is not
  JSONP) is not an XSS candidate.
- A continuation round that cannot fund an action skips it and says so in coverage; it does not
  fail the Scan.
- A finding is published when its proof settles, not when the Scan ends.

Exit: no regression on any benchmark target, and less wall time on API targets.

### Phase 2: see the application

- Routes and request bodies of a single-page application, the sign-in request included, taken
  from the browser crawl's recorded requests and from static analysis of its scripts.
- HTML forms as request-body candidates.
- Bearer credential profiles placed in the browser crawler's storage, so a signed-in crawl of a
  token-based application is signed in.
- Path parameters tested with real values from specification examples and list endpoints.

Exit: the sign-in request of each benchmark single-page application is a candidate.

### Phase 3: a shared proof core, then the classes

A differential verifier: one control request, one probe, repeated; proof needs the marker (or the
time difference) with the probe and never with the control. Classes are payload sets on it:

| Class | Proof |
|---|---|
| Server-side template injection | the product of two random numbers appears, the literal does not |
| Path traversal | a known file signature against a control path |
| Command injection | a random marker echoed, and a repeated time difference |
| XXE | an external entity returns a known file signature, after an internal entity was seen to expand |
| Request forgery (in-band) | the application's own front page comes back for its loopback address, not for a missing page there |
| Open redirect | allowlist-bypass payloads in the existing verifier |
| JWT | the principal's token with an altered signature, or with `alg: none`, is accepted; or a well-known secret reproduces its signature |
| SQL injection | OR-boolean and numeric contexts; PostgreSQL, SQLite and SQL Server time payloads |

The fuzzing templates that ship in the scanner image may propose candidates for these classes
inside the active budget; they never verify. The same proofs back a Hunt's `candidate.verify`.

Exit: each class is proven on at least one benchmark target and is silent on every target that
does not have it.

### Phase 4: signed-in value

- Sensitive fields (password hashes, tokens, keys) in an authenticated JSON response, as a
  finding that needs one identity.
- Role-to-role comparison for function-level authorization.
- Mass assignment in a Scan, reusing the Hunt's verifier.
- Default-credential sign-in proof: documented defaults only, one attempt each, under
  state-changing permission.
- Stored XSS through forms, proven in the browser.

### Phase 5: out-of-band proof

A self-hosted callback listener for SSRF and for blind command injection and XXE. Off by default;
it needs a deployment and policy decision before any design.

## Open decisions

1. Whether intrusive fuzzing templates may run as candidate generators inside the active budget.
2. Whether an out-of-band listener ships, and where it runs.
3. Whether CORS `*` without credentials and a secret-free API description are reported as
   informational findings.

## Progress

State of each item on this branch. "Main" means the engine already had it when this plan was
opened; "open" means not started.

| Phase | Item | State |
|---|---|---|
| 0 | Scorecard and before/after comparison (`scripts/detection_scorecard.py`) | done |
| 0 | Scorecard run for every detection change, published with release notes | open (process) |
| 0 | More benchmark targets with answer keys | open (needs maintainer approval, see the ledger) |
| 1 | OpenAPI empty server URL | done |
| 1 | Secret-bearing exposure seeds | done, on `thorough` and `deep` only: fast and balanced plans are pinned |
| 1 | Sign-in body SQL injection proof without a verifier signal | done |
| 1 | XSS verifier not run on responses a browser does not render | done for JSON responses, in the existing one-request reflection check |
| 1 | SQL injection slice floor and body allowance | open: any change to slice sizing moves pinned plans and starved active templates when tried |
| 1 | Unfundable continuation action is skipped | open, not reproduced on 2.14.1 |
| 1 | Findings published as proof settles | open |
| 2 | Request bodies the crawl saw the application send; crawled forms | main |
| 2 | Bearer profiles in the browser crawler's storage | open |
| 2 | Real path values from specification examples | dropped: values never enter a manifest by design; the OR pair below covers a value that matches nothing |
| 3 | Differential proof core (`api/capabilities/injection_verify.py`) | done |
| 3 | Template injection, path traversal, command injection, XXE | done, as the opt-in `server_injection` family |
| 3 | SQL injection: numeric and OR pairs, PostgreSQL and SQL Server delays | done; they run where a slice's reservation has room and never on a sign-in endpoint |
| 3 | Open-redirect allow-list bypass destinations | done |
| 3 | JSON Web Token: altered signature, `alg: none`, guessable secret | done, in `authz_surface` |
| 3 | Fuzzing templates as candidate generators | open (decision 1) |
| 3 | The same proofs behind a Hunt's `candidate.verify` | open |
| 4 | Password hashes in an authenticated JSON response | main (`authz_surface`) |
| 4 | Role-to-role comparison, mass assignment, default-credential proof, stored XSS | open |
| 5 | In-band request forgery to the application's own loopback address | done, a class of `server_injection` |
| 5 | Out-of-band callback listener | open (decision 2) |

### What the done items still need

- A benchmark scorecard before and after, on the same targets and profile. Nothing on this
  branch has been run against a live target; every item is proven by unit tests over a fake
  transport.
- `server_injection` is in no preset. Adding it to `standard_active` is a default change and
  waits for that scorecard.
- A `server_injection` finding proved through a GET parameter is retested by the same check,
  one class only. One proved through a request body or a path segment is checked by a new Scan,
  as SQL injection findings of that shape are.
- The blind (time) command-injection probe is for a POSIX shell only; the echoed one covers
  `cmd.exe` too.
