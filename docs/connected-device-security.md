# Connected-device security

ShakerScan treats TVs, cameras, printers, routers, NAS systems, conference equipment, and other
network-connected devices as a separate security product surface. A device is not a Web DAST target,
even when it exposes one or more web interfaces.

Device capacity is opt-in so an existing DAST installation does not lose worker slots or memory.
Start it with `./scanner.sh devices start`; inspect it with `./scanner.sh devices status`, and stop it
with `./scanner.sh devices stop`.

## Product boundary

- Devices live in `device_targets`; their interfaces and observed services live in
  `device_interfaces` and `device_services`.
- Device scans use `run_kind=device_posture` and a dedicated Redis queue and worker.
- Web interfaces discovered on any TCP port are checked by hidden `device_web_dast` children. Those
  children have no Web target, cannot alter Web target or ASM statistics, and do not appear in the
  normal scan list or dashboard totals.
- Device findings use `source=device`, have a device-scoped fingerprint, and are available through
  the Device filter without changing ordinary DAST posture metrics.
- Device-worker build health is stored separately from the Web DAST worker registry. Adding or
  rebuilding device capacity therefore cannot make the ordinary DAST fleet stale or non-uniform.

## Coverage profiles

| Profile | TCP inventory | UDP inventory | Typical use |
|---|---|---|---|
| `inventory` | Nmap top 100 TCP ports | Small common-device set | Fast reachability and first inventory |
| `posture` | All 65,535 TCP ports | Curated discovery/management set | Normal device assessment |
| `thorough` | All 65,535 TCP ports with deeper fingerprinting | Curated discovery/management set | Higher-confidence service posture |

Every profile is scoped to exactly one hostname or IP. URLs, CIDR ranges, paths, credentials, and
shell-like locators are rejected. The operator must explicitly confirm authorization before a scan
is queued.

Coverage and safety are independent controls. `inventory`, `posture`, and `thorough` select how much
of the device is inventoried; they never grant permission for more invasive actions. The separately
recorded safety profiles are:

- `observe_only`: discovery, banners, TLS/HTTP detection, and SSH posture handshakes. Web origins are
  inventoried but no Web DAST children are launched.
- `safe_remote`: bounded non-destructive network checks and passive device-owned Web DAST. This is
  the default and preserves the original connected-device behavior.
- `authenticated_active`: reserved for the supplied-credential, read-only host collector and later
  bounded active checks. It currently fails closed as unavailable.
- `lab_invasive`: reserved for a dedicated recovery-capable lab runner. It currently fails closed as
  unavailable and cannot be enabled by choosing a deeper coverage profile.

Every device action receives a declared safety class. The device safety governor blocks actions not
permitted by the selected profile and records baseline, post-inventory, and final health checkpoints.
If a previously healthy device degrades, the scan is halted and cannot produce an allow decision.

TCP assessment is staged. A bounded priority pass checks common administration, media, printing,
messaging, and nonstandard web ports first. The requested top-100 or all-port discovery then runs
without expensive version detection, and service/version fingerprinting runs only against ports
confirmed open. A timed-out full-range pass remains explicitly incomplete while preserving ports
already confirmed by the priority pass.

The scanner records service name, product/version hints, CPE, transport, port, encryption state,
hostnames, addresses, MAC/vendor evidence when visible, and bounded OS fingerprints. UDP coverage is
deliberately curated because a complete UDP sweep is both slow and ambiguous; the report lists the
exact requested UDP ports instead of claiming full UDP coverage. An Nmap `open|filtered` UDP result
with `no-response` is retained as an inconclusive observation, not a listening service. It is
excluded from policy evaluation and scoring unless a protocol response confirms the port as open.
Scan reports and device details present these observations in a separate uncertainty section, so an
operator can inspect the raw evidence without mistaking UDP silence for an exposed service.
Successful tool execution is reported separately from coverage confidence. Filtered TCP ports or
unresolved UDP observations prevent an `allow` decision and preserve prior service history, but they
do not become findings or reduce the vulnerability score merely because the network path was silent.

Each report also carries a deterministic `device-evidence/v1` graph. It normalizes the device,
interfaces, services, inconclusive observations, web origins, tool executions, and health
checkpoints into stable nodes, edges, and observations. This is the compatibility layer used by
future protocol adapters and the AI-directed device investigator; adapters exchange normalized
observations rather than requiring later stages to parse raw tool strings.

## Web interfaces on any port

ShakerScan does not assume ports 80 or 443. After service inventory, it sends a bounded HTTP probe to
each eligible open TCP service up to the declared profile probe cap, trying cleartext and TLS in the
order suggested by the fingerprint.
This can discover origins such as `http://device:8008`, `https://device:8443`, or an ephemeral vendor
management port.

Discovered origins can receive passive `quick`, `standard`, or `deep` Web DAST coverage. Active Web
DAST families are forcibly disabled, request and time budgets are capped, and at most 32 origins are
handed off. Each merged finding retains the parent device, child scan, origin, connect address, Host
header, and SNI provenance. Any probe or child truncation marks the assessment incomplete and prevents
an allow decision.

## SSH and service policies

SSH is checked on the port where it was actually discovered, not only port 22. The scanner records
the banner, server host-key type and size, authentication methods, negotiated cipher/MAC, password
and keyboard-interactive availability, public-key availability, and weak negotiated algorithms. It
does not guess usernames or passwords and never attempts credential authentication.

Service policies are ordered rules with four outcomes:

- `allow`: the observed service is expected.
- `deny`: the service must not be listening.
- `review`: the service needs an operator decision.
- `require`: the service is permitted only when controls such as encryption, disabled SSH password
  authentication, no weak SSH algorithms, or public-key authentication are proven.

Unmatched confirmed-open services default to review. Required controls fail closed when they cannot be verified.
ShakerScan ships generic, media-device, camera, printer, and network-appliance baselines. A device can
use a selected custom policy; otherwise the closest active built-in policy is chosen by device class,
with the generic fail-closed baseline as fallback.

Policy actions determine the final posture decision: `deny` and failed `require` controls block,
`review` requires review, and `allow` is emitted only when all required inventory stages completed
and no confirmed finding remains. The score and decision therefore cannot report an F-grade review
set as policy-conformant.

Findings are auto-resolved only after a successful all-TCP assessment with untruncated web detection
and complete web-child coverage. A fast or partial inventory never clears older findings.

## REST workflow

```bash
# Read device-worker readiness
curl http://localhost:8080/devices/readiness

# Register one device
curl -X POST http://localhost:8080/devices \
  -H 'Content-Type: application/json' \
  -d '{"name":"Lobby display","primary_locator":"tv.example.lan","device_class":"media"}'

# Queue an authorized full TCP posture scan with passive web handoff
curl -X POST http://localhost:8080/devices/DEVICE_ID/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "profile":"posture",
    "confirm_authorized":true,
    "include_web_dast":true,
    "web_scan_type":"standard",
    "max_web_origins":8
  }'
```

Policy management is available at `GET/POST /device-policies` and
`PATCH /device-policies/{policy_id}`. Device inventory is available at `GET/POST /devices`,
`GET/PATCH/DELETE /devices/{device_id}`, and `GET /device-scans`.

## AI-directed device investigation

Connected devices also have a keyless, turn-based investigator modeled on Deep Hunt. The current
Codex, Claude, or OpenCode session is the planner, while ShakerScan executes a closed device-tool
contract. Start it through `POST /devices/{device_id}/agent/session`; drive turns through
`POST /device-agent/session/{run_id}/reply`; inspect or cancel through the matching GET and cancel
routes. The `/devices/{device_id}/agent` UI shows live state, budgets, evidence-backed leads, and the
exact fixed safety profile.

The initial device-agent tools can inspect the registered device, queue a deterministic device scan,
inspect a device-owned scan, query normalized graph evidence, and retain bounded notes. A run is fixed
to one `device_target_id` and one safety profile at creation. Tool arguments contain no locator,
credential, arbitrary URL, shell, plugin, or safety-escalation field. Sessions are capped at 30 turns,
36 tool actions, six calls per turn, and three queued scans. Concurrent agent sessions and concurrent
device scans for the same device fail closed.

The AI investigator cannot create authoritative findings. Scanner findings continue to come from
deterministic device scans. A final AI debrief may retain evidence-backed hypotheses only when they
cite real `devref_N` references created by device context, scan-result, or evidence-graph reads. Notes,
queue acknowledgements, and model prose are not proof.

## Wireless and non-IP extensions

Bluetooth, BLE, Zigbee, Thread, and passive network telemetry require hardware or network placement
that a normal Docker worker cannot safely assume. The readiness response advertises these as optional
sensor capabilities, but this release does not claim radio coverage. The intended extension point is
a separately enrolled, capability-labeled sensor that submits normalized device/interface/service
evidence into the same device model while preserving the dedicated queue, authorization, provenance,
and policy boundary.

## Current limits

- The scanner observes the network path visible from its device worker; NAT, firewall rules, VLANs,
  and client isolation can hide services.
- Service and OS fingerprints are evidence, not guaranteed product identity. Stable MAC identity is
  unavailable across routed networks and can be randomized.
- UDP coverage is a declared curated set, not all 65,535 ports.
- UDP silence is inconclusive. Firewalls can make closed and open UDP ports look identical from the
  worker's network path, so only a protocol response is treated as confirmed open.
- No credential guessing, firmware extraction, destructive protocol testing, radio probing, or active
  XSS/SQLi is performed by the device workflow.
