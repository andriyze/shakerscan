# Assisted authorization investigations

## Status and boundary

**Status:** Implemented prototype with live-stack and efficacy acceptance pending.

The GET-only prototype is connected to the Hunt REST API. Proposal and attempt
references are persisted in the existing PostgreSQL `application_graph_nodes`
table; execution and outcomes remain owned by canonical `hunt_actions`, receipts,
and HTTP transactions. No new scanner, capability registry, credential store, or
finding-promotion path is introduced.

This is an integration implementation, not a measured pentester-productivity or
vulnerability-recall result. Local tests exercise the real FastAPI routes and
repository SQL through a SQLite adapter while substituting the canonical worker
boundary. Live PostgreSQL, the deployed API/worker path, and the independent
planner evaluation still require acceptance. New MCP tools and UI controls are
not included. See [Hunt investigation evaluation](hunt-investigation-evaluation.md)
for the separate efficacy protocol.

## Supported captures

Start a web/API Hunt with the existing explicit policy and approval authority.
Establish its primary and secondary sessions through `auth.session.establish`.
Use `http.request` with the resulting opaque `session_ref` to capture both:

- the primary principal's GET of a specific object;
- the secondary principal's GET of that object's collection listing.

Find their transaction IDs in `/hunts/{hunt_id}/http-transactions`. The first
integration accepts only captures from the **same Hunt**, the selected sessions,
and the same frozen origin. The baseline must be the object's direct parent
collection. A successful listing response alone does not prove that the listing
is complete or that an object is exclusively owned.

Requests must be body-free GETs without query strings, fragments, custom headers,
or request-collection/redirect options. Unsupported or redacted captures are
rejected rather than silently reconstructed differently. Numeric IDs, UUIDs and
long hexadecimal IDs are supported; identifier shape is only a proposal hint.
Slugs, nested/query/body IDs, prior-Scan captures and no-listing investigations
remain unsupported by this workflow.

## Propose, review, and approve

`POST /hunts/{hunt_id}/authorization-investigations` accepts references only:

```json
{
  "capture_id": "<primary-object-transaction UUID>",
  "baseline_capture_id": "<secondary-listing-transaction UUID>",
  "primary_session_ref": "<primary-session UUID>",
  "secondary_session_ref": "<secondary-session UUID>"
}
```

The response includes `proposal_id`, `proposal_digest`, evidence requirements,
limitations, captured-request references, and an inert reproduction plan. Creating
or reading a proposal makes no target request.

After reviewing it, call
`POST /hunts/{hunt_id}/authorization-investigations/{proposal_id}/approve`:

```json
{
  "proposal_digest": "<digest returned by the proposal>",
  "confirm": true,
  "attempt": 1,
  "retry_settled": false
}
```

This delegates to the **existing** `authz.verify` lifecycle with the two sessions
and the referenced baseline/object routes. Human confirmation does not grant
additional scope, bypass approval receipts, increase budgets, or permit mutation.
Canonical execution revalidates authority and credentials and owns cancellation,
worker dispatch, idempotency, evidence and budget settlement.

`POST .../{proposal_id}/skip` records a deferral without marking the experiment
executed or refuted. It does not cancel an already admitted action; use the
canonical Hunt cancellation endpoint for that.

## Read, resume, and reproduce

`GET .../{proposal_id}` rebuilds the investigation from persistent references and
canonical action records. It returns all bounded attempts, the latest scoped
explanation, open questions, settled state and evidence references. The in-memory
object is only a request-local projection: losing it does not lose the recorded
investigation.

`GET .../{proposal_id}/reproduction` returns an **inert plan**, not a replay:
secondary collection baseline, primary selected object, secondary selected object.
The steps reference the original captured requests; secrets and raw HTTP bodies
are not copied into the proposal. Execute any retest through the same reviewed
approval path, not through a read endpoint.

Only server-owned action records can supply an outcome. A supported result must
match this attempt's Hunt, canonical action, exact input digest, receipt,
principal pair, collection, selected object digest and canonical verified
observation. Another object's finding, a top-level `vulnerable` flag or a supplied
`proven=true` never confirms the selected object.

An aggregate completed replay does not refute the selection. A scoped denial is
reported only when this action's exact GET transactions show successful primary
access and secondary 403. Missing evidence, authentication errors, other-object
results and incomplete execution stay inconclusive. A denial for one request
never means the whole route is safe.

The existing verifier is collection-oriented and may choose a different object.
This integration preserves that limitation instead of attributing its finding to
the selected request. Canonical verified observations can be reported here, but
this workflow does not itself create or promote a finding. Persisted finding
acceptance and a scored human/planner run remain separate milestones.

## Retries and restart recovery

Re-submit the **same attempt number** to recover a lost response or a crash before
or after admission. A deterministic idempotency key maps it to the existing Hunt
capability action. A completed action is read, not executed again. An admitted
but unfinished action cannot be bypassed by requesting the next attempt.

A genuinely new attempt uses the next consecutive number (up to 20). Definitive
prior outcomes require `retry_settled: true`; inconclusive attempts remain open.
History is append-only through immutable action references. Changed captures,
sessions or target binding require a fresh proposal and review. Finished Hunts
and expired sessions do not erase history, but cannot authorize new execution.

## Validation

```bash
python -m pytest -q tests/test_hunt_authorization_api.py \
  tests/test_authorization_integration_regressions.py \
  tests/test_authorization_workflow.py tests/test_investigation_memory.py
```

The API tests cover proposal isolation, exact input and object attribution,
strict confirmation, rejected request shapes, same-Hunt sessions, denial/error
semantics, bounded sequential retries, idempotency, deferral, and a completely
new service reading file-backed state after restart. Their SQLite transaction
adapter is not evidence of PostgreSQL locking behavior or deployed worker
acceptance. Do not substitute these tests for the live PostgreSQL and current
worker acceptance required by the Hunt evaluation protocol.
