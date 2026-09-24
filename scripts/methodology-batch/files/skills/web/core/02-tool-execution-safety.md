# Hunt execution guide

This is the shared execution contract for the methodology library. The running server is
responsible for capability admission, credentials, transport, accounting and proof. There is
no extra methodology-owned adapter registry, policy token or package-specific action schema.

## One capability path

1. Read `GET /hunts/contract` and the created run's context/capability schemas.
2. Query retained observations with `POST /hunts/{hunt_id}/query` before repeating discovery.
3. Invoke `POST /hunts/{hunt_id}/capabilities/{capability_name}` using the advertised semantic
   inputs and a fresh idempotency key. Reuse the key only when retrying that exact operation.
4. Inspect actual action status, evidence and usage. A queued job is not completed verification.
5. For a full investigation, follow child results with bounded checks, retain checkpoints and
   continue. For a submission-only request, return the job ID without claiming its future result.

Use the capability names in the methodology declaration as a starting point, not a new allowlist.
Other capabilities already admitted to the run remain available when useful. `withheld_capabilities`
means the saved run lacks a required capability; `missing_capabilities` names an implementation
gap. Neither list means the entire methodology must be discarded. Unfiltered catalog metadata is
not an authority grant or proof that execution will succeed on a particular target.

## Current operation boundaries

| Operation | Actual ShakerScan path | Important limit |
|---|---|---|
| Baseline request | `http.request` | Read-only request; not arbitrary body replay or a raw connection |
| Paired object access | `authz.verify` | Read-only, evidence-backed principal comparison; not a generic diff engine |
| Login session | `auth.session.establish` | Managed opaque references; never submit secret values in planner inputs |
| Browser discovery | `browser.navigate`, `browser.interact` | Fresh context per call; up to eight read-only steps; no general writes, uploads or realtime sockets |
| Client artifacts | `artifact.inspect`, `javascript.analyze` | Bounded redacted/static analysis, not arbitrary code or DOM execution |
| Captured traffic | `collections.inspect`, `collections.select`, `collections.replay_safe` | Saved IDs; safe-method replay is not mutation or authentication replay |
| SQL/XSS proof | `sqli.verify`, `xss.verify` | Use the specific live verifier contract; a scanner signal alone is not proof |
| Candidate verification | `candidate.verify` | Only candidate families/contracts actually supported by the server |
| Service discovery | `ports.discover`, `service.fingerprint`, `service.nse_check`, `tls.inspect` | Registered/frozen asset and selected operation; NSE observations are not vulnerability proof |
| Device tasks | `device.inspect`, `device.capabilities.inspect`, `device.service.verify`, `device.ssh.propose` | Device-only schemas; SSH proposal is not execution or approval of a changed plan |

This table is a description, not an execution schema. Read the live contract for the exact fields,
selected principal support, admitted service and resource costs. An operation may require additional
implemented transport/worker prerequisites even when its capability name is present.

## Gaps and recovery

Keep useful hypotheses for unsupported request shapes, token mutations, file uploads, realtime
messages, synchronized races, OOB callbacks or arbitrary protocol exchanges. Do not invent adapters
or disguise the operation as a read-only request. Use another compatible technique when it can
answer the question; otherwise report a specific untested portion and the next required capability.

A capability error, missing optional executor, indeterminate response or skipped method does not
by itself end a full Hunt. Distinguish admission rejection, transport failure, partial observation,
queued work and completed verification. Preserve real usage, health freezes and cancellation.

## Evidence and finish

Submit evidence-linked candidates through `POST /hunts/{hunt_id}/candidates`. Keep severity,
confidence and proof status separate. Record methodology use against real action IDs through
`POST /hunts/{hunt_id}/skills/{skill_id}/usage`. Finish with findings, unresolved leads, coverage
gaps and remaining work; do not report a skipped technique as either vulnerable or clean.
