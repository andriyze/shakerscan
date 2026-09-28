# Hunt HTTP workflow writes

The existing `http.request` capability accepts POST, PUT, PATCH and DELETE with
one JSON or form object body, in addition to its baseline GET, HEAD and OPTIONS.
It uses the same target binding, principal references and HTTP worker rather than
a TV-specific engine or an external shell path.

## Operator workflow

Create the Hunt with the operator-requested `allow_state_changing_http: true`
permission. Reuse the target's standing authorization; do not ask for a new
confirmation for each HTTP method or each service port on the authorized asset.
A run admitted without write authority is not silently upgraded: start an
appropriately configured run using the existing authorization.

Call `POST /hunts/{hunt_id}/capabilities/http.request` with the live server schema:

```json
{
  "idempotency_key": "tv-pairing-start-001",
  "input": {
    "origin": "http://tv.test:7345",
    "method": "PUT",
    "path": "/pairing/start",
    "json_body": {"device_name": "ShakerScan lab"}
  }
}
```

This is a synthetic pairing-start example, not a verified protocol for a specific
TV model. A successful HTTP status does not prove that pairing completed.

## Execution contract

The registry checks method/body combinations. The API validates saved active and
state-changing permissions and reuses the existing target-bound approval. It
reserves one HTTP request, state-changing request and active action. The worker
rechecks the saved policy, reservation and approval before sending traffic;
anonymous PUT cannot inherit the passive request's approval shortcut.

Writes use the existing frozen-address transport and selected principals. Existing
same-asset service reuse and invalid target-TLS support are unchanged. Write
redirects are returned as observations, not replayed automatically; issue any
necessary next request explicitly under the same authorization and budget.
An attempted write is charged even if its response is lost; a pre-traffic rejection
does not consume a write. Existing cancellation accounting stays conservative.
Public input summaries and receipts omit body values; raw traffic belongs only
in the pre-existing explicitly sensitive HTTP archive.

## Remaining work and scope

This change addresses direct HTTP workflow writes. It does not wire the hidden
`collections.replay_active` capability into Hunt, add WebSocket pairing, browser
writes or raw XML/byte bodies. Inline bodies are non-secret workflow inputs;
secure injection/storage of new pairing PINs/tokens and capture of newly issued
pairing credentials are separate unfinished work. Use saved principal references
for existing credentials, never secrets in planner inputs.

The regression fixture exercises the real registry, approval checker, pinned
transport and adapter with synthetic HTTP responses. Full API/database/queue/worker
execution, a real TV, and a controlled Sonnet/Astra comparison remain distinct
validation tasks; a model refusal is not proof that the server denied an action.
