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
| HTTP request / workflow step | `http.request` | GET/HEAD/OPTIONS are baseline requests; POST/PUT/PATCH/DELETE plus JSON/form bodies require saved state-changing authority and are metered. Opaque captures and profile bindings support pairing; not a raw socket or secret-value export. |
| Paired object access | `authz.verify` | Read-only, evidence-backed principal comparison; not a generic diff engine |
| Login session | `auth.session.establish` | Managed opaque references; never submit secret values in planner inputs |
| Browser discovery | `browser.navigate`, `browser.interact` | Fresh context per call; up to eight read-only steps; no general writes, uploads or realtime sockets |
| Client artifacts | `artifact.inspect`, `javascript.analyze` | Bounded redacted/static analysis, not arbitrary code or DOM execution |
| Captured traffic | `collections.inspect`, `collections.select`, `collections.replay_safe`, `collections.replay_active` | Saved IDs; writes use a bound `confirmed_active` selection and existing write authority; safe replay stays read-only |
| SQL/XSS proof | `sqli.verify`, `xss.verify` | Use the specific live verifier contract; a scanner signal alone is not proof |
| Candidate verification | `candidate.verify` | Only candidate families/contracts actually supported by the server |
| Service discovery | `ports.discover`, `service.fingerprint`, `service.nse_check`, `tls.inspect` | Registered/frozen asset and selected operation; NSE observations are not vulnerability proof |
| Target metadata | `targets.create`, `targets.update` | Explicit operator intent (`operator_confirmed`), independently of network-testing permission. Does not authorize testing or alter the frozen Hunt asset. |
| Target instructions | `targets.skill.read`, `targets.skill.create`, `targets.skill.update`, `targets.skill.delete` | One document per target UUID, automatically snapshotted at Hunt startup. Read the current revision before explicitly requested edits; preserve unrelated instructions. Changes apply to future Hunts and never grant network authority. |
| Reusable input management | `credentials.grant`, `collections.bind` | Explicit operator intent and existing receiving-target authority; exact receiving target and origins; encrypted profiles remain opaque. Changes do not alter the running Hunt's selected inputs. |
| Device tasks | `device.inspect`, `device.capabilities.inspect`, `device.service.verify`, `device.ssh.propose` | Device-only schemas; SSH proposal is not execution or approval of a changed plan |

This table is a description, not an execution schema. Read the live contract for the exact fields,
selected principal support, admitted service and resource costs. An operation may require additional
implemented transport/worker prerequisites even when its capability name is present.

`GET /hunts/contract` lists every registered planner tool call in `tool_calls`, including its
underlying binary (Nmap, Naabu, Nuclei, Dalfox, SQLmap, Subfinder, HTTPX, Katana or FFUF).
The running Hunt's manifest supplies the admitted input schemas and calls; catalog visibility
does not grant authority. Nuclei accepts typed tag/severity filters over its reviewed GET-only
pack. Tool identity is explicit metadata; the runtime owns process arguments and placement.

For “scan my home smart TV's ports with Naabu”, resolve the existing target, start the shared
Hunt with network-discovery permission, and invoke `ports.discover` with the desired port set.
ShakerScan builds the installed Naabu invocation, pins destinations, meters execution, and retains
the receipt. Never submit a command string or argv. Query `service_intelligence` before spending
new traffic; target and Connected Devices views show the same retained service evidence.

When the operator requests sharing a profile or collection from another target, use the registered
grant/binding capability with opaque IDs and explicit receiving origins. Select the saved inputs
when admitting the Hunt that will consume them; a management call does not silently add credentials
or collections to an already admitted run. Granting inputs never authorizes testing another target.

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
