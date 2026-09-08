# Assisted authorization investigations

**Status**: Implemented REST workflow; receipt-backed attribution has component regression coverage. Live-worker efficacy and pentester-productivity acceptance remain required.

## Status and boundary

The GET-only workflow is connected to the Hunt REST API. Proposal and attempt
references use the existing PostgreSQL `application_graph_nodes` table; canonical
Hunt actions, receipts and HTTP transactions own execution and its evidence.
There is no new registry, credential store, database migration or finding-promotion
path. The API provides collection-based and no-listing selected-object modes.

The no-listing mode is tested against a loopback fixture whose parent endpoint
returns HTTP 500, including vulnerable, protected and shared objects. API tests
exercise the real routes, service, repository SQL and capability comparison with
a substituted queue/transport boundary and SQLite. This is not deployed-worker,
PostgreSQL-locking, Juice Shop recall or pentester-productivity acceptance. Rebuild
the API and workers before live evaluation; an older worker may still execute the
collection verifier and cannot produce the new selected-object evidence.

## Select captured requests

Start a web/API Hunt with the existing policy and approval authority. Establish
primary and secondary sessions with `auth.session.establish`. Use `http.request`
with the respective opaque `session_ref`, then obtain transaction IDs from
`/hunts/{hunt_id}/http-transactions`.

Both captures must belong to this Hunt and the selected sessions, have successful,
complete responses, and refer to the same frozen origin. Requests are body-free
GETs without custom headers, query strings, fragments or request-collection
options. Identifier-addressed paths support numeric, UUID and long hexadecimal
IDs; this shape does not establish ownership or entitlement.

### Collection mode (existing default)

Select the primary object's capture and the secondary principal's collection
listing. The baseline must be the object's direct parent collection. The existing
collection verifier may choose another object: its finding cannot settle the
selection unless canonical evidence attributes it to that exact object and URL.
Successful listing status alone does not prove listing completeness or entitlement.

### Own-object mode (no listing required)

Select the primary capture of object X and the secondary capture of a different
object Y in the same collection. The baseline is **Y itself**, not a collection
endpoint. It need not be possible to list the collection at all.

The bounded comparison makes at most four GETs:

1. Y as secondary: establish a fresh successful reference response.
2. X as primary: establish the selected object's response.
3. X as secondary: test the exact selected object, never a discovered sibling.
4. X as primary again: check that the object remained stable during comparison.

The last request is unnecessary after a denial or unusable response. Responses
must be complete HTTP 200 JSON objects with a matching `id` or `uuid` field
(case-insensitive), optionally inside object wrappers. An array, error/login
response, ambiguous object, missing ID or truncated response cannot establish
cross-access. Canonical object content must match the secondary response and
remain stable across the primary reads. Query/body IDs, slugs, custom-header
replays and arbitrary JSON selectors are not supported by this first mode.

The existing `authz.verify` capability recognizes an ordered `routes` array of
exactly two distinct, same-collection concrete object URLs as this selected-object
comparison: **[primary selection, secondary reference]**. It never invents or
fetches their parent. A collection-plus-object inventory continues to use the
listing verifier. Callers needing collection-driven discovery must provide the
collection route rather than relying on two object URLs as an unordered inventory.
The existing session resolution, frozen transport, approvals, cancellation and
four-request budget remain authoritative. No new MCP tool is needed for the
capability itself; proposal/review/resume remain REST operations.

## Propose and review

`POST /hunts/{hunt_id}/authorization-investigations` accepts capture/session
references. For no-listing testing:

```json
{
  "capture_id": "<primary-object-X transaction UUID>",
  "baseline_capture_id": "<secondary-object-Y transaction UUID>",
  "primary_session_ref": "<primary-session UUID>",
  "secondary_session_ref": "<secondary-session UUID>",
  "baseline_kind": "own_object",
  "expected_access": "denied"
}
```

Omitting `baseline_kind` retains `collection` mode. `expected_access` defaults to
`unknown`; `denied` or `allowed` are supported only in own-object mode. The
expectation is **operator-declared interpretation context, not proof or execution
authority**. A wrong declaration cannot promote a finding.

The response carries the proposal ID/digest, evidence requirements, limitations,
inert reproduction plan and previous attempts. Creating or reading it sends no
target traffic. The digest binds the mode, expectation, capture identities,
sessions and capability input; changing them requires a fresh review.

After reviewing, call `POST .../{proposal_id}/approve`:

```json
{
  "proposal_digest": "<reviewed proposal digest>",
  "confirm": true,
  "attempt": 1,
  "retry_settled": false
}
```

Approval invokes the existing `authz.verify` lifecycle. It neither expands scope
nor bypasses credential/approval/budget checks. `authz.verify` and `candidate.verify`
share the existing `max_verifications` admission counter. Each newly admitted
action spends one slot; an idempotent replay spends none. This counts verification
attempts, not confirmed vulnerabilities. HTTP/time reservations remain separate.
Historical actions are not retroactively charged. `POST .../{proposal_id}/skip`
records a deferral, not an execution or refutation; it does not cancel an already
admitted action.

## Read the result without overclaiming

`GET .../{proposal_id}` reconstructs state from persistent proposal/attempt
references and canonical records. `GET .../{proposal_id}/reproduction` returns
an inert plan using capture references, not a replay or raw secrets.

HTTP workers persist observations in `budget_reservations.receipt_json`; their
`hunt_actions.result_summary` contains execution metadata, not necessarily the
observations. The repository validates the existing receipt's content address,
reservation, action, Hunt, target and capability links before projecting its
observations into the read result. Missing or mismatched worker receipts fail
explicitly; an inline summary cannot substitute for their evidence. Historical
inline results without a worker-reservation reference remain readable.

Existing attempts affected only by this reader mismatch can be read again after
updating the API, without another target request, provided their canonical receipt
and required transactions were retained. Re-reading evidence does not change the
recorded execution, proof state, or original budget usage.

For own-object mode, the API distinguishes:

| Observed result | Meaning |
|---|---|
| `cross_access_observed=true`, `potential_violation` | X was read by secondary contrary to the declared restriction: an evidence-backed lead requiring entitlement review. |
| `entitlement_unknown` | X was read by both; establish the actual access rule before alleging a vulnerability. |
| `shared_access_as_declared` | The observed crossing is consistent with declared shared access; no violation is asserted. |
| `access_denied` | Secondary received 403 for this exact X while reference reads succeeded. This attempt is refuted, not the entire route declared safe. |
| `inconclusive` | Missing/unstable/mismatched content, partial evidence, errors, or invalid authentication prevented the comparison. Inspect `comparison_reason` and action-linked transactions. |

**Cross-access is not authorization proof.** Own-object mode never manufactures
an `absent_from_listing` fact or sets `proof_state=verified`. A complete crossing
sets `evidence_gathering_complete` and directs the pentester to review entitlement
rather than blindly repeat the same requests; its authorization outcome stays
inconclusive until independently adjudicated. Raw content remains in the existing
archive; the comparison exposes hashes and exact action/transaction references.

Attribution requires the canonical action/input/receipt plus the matching object,
reference-request hashes and complete action-linked transaction sequence. Another
object's proof, an aggregate scanner flag, copied observation or client-supplied
`proven=true` cannot settle this proposal. Collection-mode verified evidence retains
its original validator path; this workflow never creates or promotes findings.

## Retry and resume

Reuse the same attempt number after a lost response or interrupted admission.
Canonical idempotency recovers the existing action without another execution.
New attempts use consecutive numbers up to 20; definitive prior outcomes require
`retry_settled=true`. An unfinished admitted attempt must be recovered first.
Changed sessions, captures or target binding require a new reviewed proposal.
Completed Hunts remain readable but cannot authorize fresh traffic.

The in-memory briefing is a request-local projection, not the durable store.
Reopening the database and constructing a new service restores attempt history,
objects, principals, evidence references and unresolved questions without execution.

## Validation

```bash
python -m pytest -q tests/test_authz_selected_objects.py \
  tests/test_hunt_selected_object_workflow.py \
  tests/test_authorization_receipt_resume.py \
  tests/test_hunt_authz_verification_limit.py
```

These tests cover the missing-listing case, protected selections beside vulnerable
siblings, shared objects, status/JSON/fidelity errors, cancellation and deadline,
exact attribution, digest review, idempotency, relational persistence and resume.
They substitute the queue/session-resolution and frozen-address transport boundary;
the loopback HTTP exchange and comparison are real. Receipt-resume regressions
also exercise the real comparison and canonical receipt serialization with the
production metadata-only action layout. SQLite is not PostgreSQL locking
acceptance. Existing collection, authorization API and scope regression suites
must also pass in the full checkout.

Use [the independent evaluation protocol](hunt-investigation-evaluation.md) for a
current-worker live target and human/planner assessment. Do not count a new lead
as a verified finding or convert these tests into a measured recall claim.
