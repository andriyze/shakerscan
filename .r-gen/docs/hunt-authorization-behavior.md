# Hunt: assisted object-authorization behavior

**Status:** implemented and live-validated on `bbaa84c9` (2026-09-08). Describes current behavior of
the selected-object authorization workflow, not a plan.

This document records what Hunt actually does today when an operator asks whether one principal can
read another principal's object. It covers the commit `0356bc4b` feature and the three commits that
complete it, and cites live runs against Juice Shop and crAPI performed on one rebuilt stack.

## The commits in scope

| Commit | Kind | Effect on behavior |
| --- | --- | --- |
| `0356bc4b` | feature | An approved crossing is written to the canonical candidate backlog |
| `d138e78a` | fix | Composite response envelopes can now be examined at all |
| `aa72fbb0` | fix | Reading an investigation reports the candidate it produced |
| `bbaa84c9` | chore | Generated public contract matches the app; no runtime behavior change |

`0356bc4b` arrived from another session. The other three are the subject of this report; `d138e78a`
and `aa72fbb0` were written against defects found by running the workflow rather than by reading it.

## End-to-end behavior

1. **Capture.** Two `http.request` calls under distinct principals record the object the operator
   cares about (primary) and the secondary principal's *own* comparable object.
2. **Propose.** `POST /hunts/{id}/authorization-investigations` binds those two captures, with
   `baseline_kind: own_object` and an operator-declared `expected_access`. No target traffic is sent.
   The response carries a `proposal_digest` over the frozen proposal.
3. **Approve.** `POST .../approve` requires that digest plus `confirm: true`, so a proposal that
   changed since review cannot be confirmed. Approval runs one `authz.verify` action.
4. **Compare.** At most four bounded GETs (below).
5. **Materialize.** A qualifying crossing becomes an explicitly unverified candidate.
6. **Read/resume.** `GET .../{proposal_id}` returns the durable state, now including the candidate.

### The four-request comparison

`api/capabilities/authz_selected.py` issues these in order and stops at the first that settles:

| # | Request | Purpose | Stops if |
| --- | --- | --- | --- |
| 1 | secondary → own object | Prove the attacker session actually works | Baseline is not a complete 200 JSON object |
| 2 | primary → selected object | Establish the owner view | Owner response is not that object |
| 3 | secondary → selected object | The crossing itself | 403 (recorded as denial) or not that object |
| 4 | primary → selected object | Re-read to prove stability | Owner view changed mid-comparison |

Request 1 exists so an expired or broken attacker session cannot be misread as enforcement. Request 4
exists so a shifting object cannot fake equivalence. A run that never reaches request 3 reports that
plainly rather than implying the object is protected.

### What the workflow concludes

`outcome` and `proof_state` both default to `inconclusive`, and the crossing path never raises them.
The interpretation lives in `authorization_assessment`:

| Observation | `authorization_assessment` | `outcome` | `certainty` |
| --- | --- | --- | --- |
| Attacker got the exact object, expectation `denied` | `potential_violation` | `inconclusive` | `observed` |
| Attacker got it, expectation `allowed` | `shared_access_as_declared` | `inconclusive` | `observed` |
| Attacker got it, expectation `unknown` | `entitlement_unknown` | `inconclusive` | `observed` |
| Attacker got 403 on exactly 3 requests | `access_denied` | `refuted` | `observed` |
| Anything incomplete | `inconclusive` | `inconclusive` | `unknown` |

Two properties are worth stating explicitly because they are easy to get wrong:

- **A 403 is the only accepted denial.** A 400, 404 or 500 does not become "enforced"; it lands in
  the incomplete row. Juice Shop's address route returns 400 to the attacker, and the workflow
  correctly declines to call that a demonstrated boundary.
- **The expectation is context, never evidence.** `expectation_source` is recorded as
  `operator_declared_not_proof`. Declaring `denied` changes how a crossing is labelled; it cannot
  make a crossing into proof.

## Composite response envelopes (`d138e78a`)

Previously the comparison unwrapped a JSON envelope only when it contained exactly one object child.
Any response shaped like `{"a": {...}, "b": {...}}` was rejected as `response_object_ambiguous`, and
because request 1 is the baseline, the whole investigation failed with *"the second principal's
own-object baseline was not established"* — even though the replay returned 200 with valid JSON.

That is ordinary API shape, so the effect was that a large class of real APIs could not be examined
at all. crAPI's `GET /workshop/api/shop/orders/{id}` returns `{"order": {...}, "payment": {...}}` and
was unexaminable for this reason.

The comparison now descends into a sibling when **exactly one** of them declares the requested
identifier as its own `id`/`uuid`, reusing the identifier check the leaf already applied. Zero
matches or several stay ambiguous and fail closed. The comparison then covers the identified object,
not the surrounding envelope, so an unrelated sibling can neither mask a real difference nor
manufacture equivalence. This is a JSON-shape rule driven by the identifier already in the request;
no target-specific knowledge is involved.

## Candidate materialization (`0356bc4b`, read path fixed in `aa72fbb0`)

A crossing that clears every gate below becomes a row in the existing `investigation_candidates`
store, so a useful lead is no longer trapped inside one workflow response.

The gates, all required (`candidate_plan` in `api/hunt/authorization_candidate.py`):

- `baseline_kind == own_object` and `expected_access == denied`
- `authorization_assessment == potential_violation` on both the state and the latest attempt
- `cross_access_observed` and `selected_request_examined` both true
- `proof_state == inconclusive` and `certainty == observed`
- a canonical `action_id` and `receipt_id`, at least two evidence refs, and a non-empty route

The resulting candidate is deliberately weak-by-construction:

```
family: bola          status: new          claimed_severity: high
source_kind: hunt_authorization            verifier_contract_id: null
canonical_locus: {"method": "GET", "route": "/rest/basket/<owner-object>"}
```

Its claim says in prose that the technical crossing is evidenced but the business entitlement still
requires human review. The observation context carries `authoritative: false`, `finding_promoted:
false`, `proof_state: inconclusive`, and `expectation_source: operator_declared_not_proof`.

`aa72fbb0` fixed an asymmetry in this: approval returned the candidate, but reading the same
investigation back omitted it, so a resumed session saw nothing and could conclude no lead had ever
been recorded. Approve and read now resolve the same durable graph link through one lookup. The read
path never materializes a candidate, because that route is documented as non-executing — verified
live by repeatedly reading an investigation and confirming the candidate count stayed at 1.

Creation is idempotent per proposal attempt via a deterministic link key, so re-approving the same
attempt does not spam the observation ledger.

## Live validation

Three runs on one rebuilt stack (`bbaa84c9`, six workers, all `build_current`, zero stale, single
fingerprint). Ground truth was measured directly against each application before each run.

| Run | Target / route | Ground truth | Result | Candidate |
| --- | --- | --- | --- | --- |
| `b1ee475b` | Juice Shop `/rest/basket/{id}` | attacker reads owner's basket (200) | `potential_violation`, `certainty: observed` | 1 |
| `f72bd923` | crAPI `/workshop/api/shop/orders/{id}` | attacker reads owner's order (200) | `potential_violation`, `certainty: observed` | 1 |
| `34a3e326` | Juice Shop `/api/Addresss/{id}` | enforced, attacker gets 400 | incomplete crossing, no lead | 0 |

Both positive runs reported `status_codes_by_principal: {primary: [200], secondary: [200]}`,
`selected_request_examined: true`, and charged exactly 1 verification. The negative control reported
`{primary: [200], secondary: [400]}`, produced no candidate, and did not claim an enforced boundary.

The crAPI run is the one that could not complete before `d138e78a`; it is now
indistinguishable in behavior from the Juice Shop run, which is the point of that fix.

## What did not change

The deterministic proof boundary is intact. This workflow produces candidates and leads, never
verified findings:

- `proof_state` stays `inconclusive` on every path, including the strongest crossing.
- `verifier_contract_id` is null; no proof contract is claimed or invented.
- No finding is created or promoted, and no finding proof state can be mutated from here.
- `authz.verify` is metered against `max_verifications` alongside `candidate.verify`, so this
  workflow spends the same budget dimension as any other verification.

## Known limits

- **Object-level only.** This addresses object BOLA. It does not address function-level
  authorization (BFLA), which is the benchmark's actual scored gap on `/api/Users`.
- **One object pair per investigation.** A conclusion covers the exact pair tested; the route's
  untested objects and principal pairs remain unexamined, and the memory layer states this rather
  than generalizing to "route is safe".
- **Denial detection is narrow by design.** Only a 403 on exactly three requests refutes. Real
  applications that deny with 400/404 produce an incomplete result, not a demonstrated boundary.
  This is deliberate — the alternative is inferring enforcement from ambiguous status codes — but it
  means the workflow rarely produces a positive "this is protected" statement.
- **Not yet measured as efficacy.** These are live acceptance runs, not the paired human+AI
  evaluation described in `docs/hunt-investigation-evaluation.md`.
