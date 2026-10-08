# Hunt HTTP workflows and pairing

**Status**: HTTP writes, active replay and encrypted within-Hunt pairing are implemented;
full-stack, installed-upgrade and physical-device acceptance remain required.

The existing `http.request` capability supports GET, HEAD and OPTIONS plus authorized
POST, PUT, PATCH and DELETE with one JSON or form object body. The same capability,
target binding, standing authorization, worker and ledger serve web, API, network and
device Hunts. No TV-specific executor or external shell escape is needed for these
HTTP workflows. `collections.replay_active` also executes approved captured writes.

## One authorization, then the workflow

Request `allow_state_changing_http: true` when creating a Hunt for an operator-authorized
pairing objective. Reuse the target's standing authorization; do not add confirmation
prompts for each verb, service port or step. A previously admitted passive run has not
gained write authority: create a correctly configured Hunt using the existing approval.
Read the running server's contract rather than an old client description.

Pairing is workflow setup, not necessarily vulnerability proof. Do not require a special
vulnerability verifier to perform an already-authorized HTTP step. A rejected input is
not necessarily a missing permission; distinguish schema, stale-reference, scope, budget,
transport and unsupported-protocol errors. Continue other useful authorized investigation.

## Reference-only multi-step exchange

The following paths and response fields belong to a **synthetic test protocol**, not a
claim of compatibility with a specific television. Use the actual service origin, paths,
field names and protocol sequence established for the device. An origin must be a service
on the Hunt's already-authorized frozen asset.

Start pairing through `POST /hunts/{hunt_id}/capabilities/http.request`:

```json
{
  "idempotency_key": "tv-pairing-start-001",
  "input": {
    "method": "PUT",
    "path": "/pairing/start",
    "json_body": {"client": "ShakerScan lab"},
    "capture": [{"name": "challenge", "json_pointer": "/challenge"}]
  }
}
```

The completed action returns a `captures` list containing only `source_action_id` and
`capture_name`. The challenge value is encrypted on the existing action row; it is not
returned to the planner. JSON pointers use RFC 6901 escaping and support nested objects
and arrays. Captures can instead select one named response header using `header`.

When the operator receives a PIN, save it through the existing encrypted credential-profile
UI/API (`POST /credential-profiles`) for this exact target. Use an HTTP credential kind
such as `api_key_header`, enable `http.request`, and retain the returned profile ID/version.
The profile creation input is sensitive; use the normal secret-entry path, not an inline
Hunt body or shell-history command. Existing standing authorization covers the credentials
attached to this target. A newly supplied PIN does not require restarting this Hunt.

The next `http.request` input may be:

```json
{
  "method": "PUT",
  "path": "/pairing/pair",
  "json_body": {"challenge": null, "pin": null},
  "request_bindings": [
    {"source_action_id": "11111111-1111-4111-8111-111111111111", "capture_name": "challenge", "body_pointer": "/challenge"},
    {"profile_id": "22222222-2222-4222-8222-222222222222", "profile_version": 1, "credential_field": "secret", "body_pointer": "/pin"}
  ],
  "capture": [{"name": "token", "json_pointer": "/auth_token"}]
}
```

Replace the example UUIDs and profile version with returned values. An existing Hunt
principal can be selected instead with `principal` (`primary`, `secondary`, or `service`)
and `credential_field`. Only the worker resolves these sources. Body values are scalars;
parents must exist in the body template, and form bindings name top-level fields.

Follow the successful pairing response with the device's authenticated confirmation call:

```json
{
  "method": "GET",
  "path": "/paired-status",
  "request_bindings": [
    {"source_action_id": "33333333-3333-4333-8333-333333333333", "capture_name": "token", "header": "AUTH"}
  ]
}
```

A bearer-token service may use `header: "Authorization"` and `prefix: "Bearer "`.
The prefix is literal non-secret text, not an expression or token transformation. Captured
values cannot change a target, URL or routing/framing header. Workflow-bound authentication
is labeled as such, not falsely attributed to a verified managed-principal identity.
A captured reference or HTTP 200 alone is not universal proof of successful pairing;
interpret the protocol's confirmation and the authenticated follow-up together.

## Active collection replay

Bind an existing encrypted collection and its `confirmed_active` selection when starting
the write-enabled Hunt. Call the advertised `collections.replay_active` with its
`collection_id` and optionally narrow it by saved `request_ids`, `methods`, `path_regex`,
`limit`, or the bound `selection_id`. The default maximum is 25 requests per call. The saved
selector remains authoritative: a safe-only selector is never widened by choosing this
capability. `collections.replay_safe` remains GET/HEAD/OPTIONS only.

Admission counts the actual selected requests and writes. The worker rechecks the saved
selection digest, target, environment, credentials and authority before decryption and
between active requests. Collection scripts and external references do not execute.
Results retain measured usage and observations; replay itself is not vulnerability proof.
Replay archives identify their fidelity as exact request-plan plus bounded response,
not a complete packet-level recording of automatically added transport headers.

## Persistence, privacy and accounting

Request templates and queue inputs contain references, not injected PINs or tokens.
Captures use the existing encryption key and `hunt_actions.private_http_result`, are bound
to the same Hunt/action/asset, and expire after one hour. Finish/cancel clears the encrypted
capture column; a late worker cannot restore it on a terminated run. These are temporary
workflow credentials, not permanent pairing profiles automatically reusable across Hunts.
Normal evidence/HTTP archive retention is independent of capture expiry.

The worker validates source profile activity, version, capability and exact target before
resolving a field. Cross-Hunt, expired, changed-target and tampered captures are rejected
before traffic. Secret-bearing workflow responses omit body samples, token values and
brute-forceable body digests from public observations. The existing explicitly sensitive
HTTP archive is the only raw traffic output; normal planner records remain redacted.

Each attempted write consumes its HTTP/write allowance even when its response is lost or
capture fails. A known pre-dispatch reference rejection releases the write hold. Completed
worker redelivery returns the saved result/reference without resending or charging again.
An ambiguous in-flight interruption remains subject to the existing conservative lease
recovery rather than a false exactly-once guarantee across a worker crash. Write redirects
are reported without automatic replay; issue a necessary next request explicitly under
the same authorization. Device pacing, cancellation, health checks and frozen-address
transport remain in force, including authorized HTTP and invalid target certificates.

## Validation boundaries

The synthetic pairing regression drives the real admission logic, canonical HTTP worker,
registry, encryption, credential resolver, approval evaluator, durable reservation state
machine and pinned loopback transport. It tests PUT start, encrypted challenge, newly
selected PIN, issued token, authenticated follow-up, archive callback, lost response,
stale references, cancellation and worker redelivery. Storage/queue I/O is doubled; this
is not a deployed PostgreSQL/Redis stack or a test of a physical TV.

Active replay regressions send POST/PUT/PATCH/DELETE over a real loopback socket for all
four target kinds. Full locked-dependency CI, built-stack acceptance, installed upgrade
and a controlled comparison of planner configurations must still validate
the final published commit. WebSocket/native casting protocols, arbitrary raw XML/binary
bodies and browser mutation are not supplied by this change; report a concrete protocol
gap rather than claiming all pairing is prohibited.
