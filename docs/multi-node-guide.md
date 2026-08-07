# Multi-Node Fleet Guide

This guide explains how to operate one ShakerScan control plane with worker nodes on other Linux
hosts. For the trust model and implementation details, see
[Multi-Node Architecture](multi-node-architecture.md).

## What You Are Building

A fleet is one coordinated ShakerScan installation, not several independent scanners:

```text
                          one UI / API
                               |
                    control plane + scheduler
                               |
             +-----------------+-----------------+
             |                                   |
     WireGuard worker node              HTTPS broker worker node
     shared Redis/Postgres               outbound HTTPS only
     for owned infrastructure            for lower-trust networks
```

The control plane owns targets, scans, findings, the queue, scheduling, and artifacts. Worker nodes
only execute jobs assigned by that control plane. A scan can be placed on a particular node or class
of nodes, and parallel scan shards can execute across several nodes.

The UI uses these terms deliberately:

| Term | Meaning |
|---|---|
| **Local worker** | A scanner worker running on the control-plane machine. |
| **Remote node** | A joined Linux machine with one node identity and heartbeat. |
| **Remote worker** | A replaceable scanner process/slot running inside a remote node. |

Users select an execution **location** (automatic, the local control plane, or a remote node), not
an individual worker process. Worker processes can be replaced during scaling or upgrades; keeping
selection at node level preserves failover between replicas on the selected machine.

## Availability and UI Behavior

Managed multi-node Fleet hosts require Linux. macOS remains fully supported for standalone
ShakerScan, but it cannot act as a managed Fleet control plane or worker host. A direct visit to
`/fleet` on macOS explains that boundary and recommends a Linux VPS or Linux VM. The Fleet sidebar
entry is hidden on macOS and on ordinary standalone installations.

Fleet is opt-in. Until `shakerscan fleet init` successfully initializes a Linux control plane:

- the Dashboard reports and scales local workers only;
- remote-worker capacity is not shown;
- New Scan does not show remote placement controls;
- the Fleet navigation entry is hidden; and
- a direct `/fleet` visit shows setup guidance instead of empty node counters or authentication
  errors.

After initialization, the API reports Fleet as enabled, the navigation and remote capacity appear,
and the Fleet page becomes the operating surface. On the Dashboard the remote count is deliberately
placed after the local `−` and `+` controls so local scaling remains visually distinct from remote
capacity. `GET /health` and `GET /workers` expose the same non-secret `fleet` capability object with
`enabled`, `supported`, `status`, and `host_platform` fields.

## Choose a Transport

| Transport | Use it when | Worker receives | Network requirement |
|---|---|---|---|
| `wireguard` | You own and trust the worker hosts | Scoped private Redis/PostgreSQL and artifact credentials | Worker must reach the control plane's WireGuard UDP port |
| `broker` | The worker is customer-hosted or should have minimum control-plane access | A node credential and one job-scoped lease at a time; no database, Redis, or object-store credentials | Worker needs outbound HTTPS only |

WireGuard offers the simplest high-throughput owned fleet. Broker mode has the smaller worker trust
boundary. Both modes use digest-pinned worker images, authenticated node identities, leased jobs,
centralized artifacts, and control-plane admission limits.

## Prerequisites

Before initializing a fleet:

| Requirement | Control plane | Worker host |
|---|---|---|
| Operating system | Linux | Linux |
| ShakerScan runtime | Required | Required |
| Docker + Compose | Required | Required |
| `wg`, `wg-quick`, `ip` | WireGuard only | WireGuard only |
| `ss` | Required | Not required |
| `openssl` | WireGuard only | Not required |
| Stable HTTPS control-plane URL | Hosts it | Must reach it |
| Inbound TCP `80` and `443` | Broker with managed HTTPS only | Not required |
| Inbound UDP, normally `51820` | WireGuard only | Not required |

Give the control plane a DNS name such as `scanner.example.com`, create its A/AAAA record, and use
`https://scanner.example.com` as the public URL. In broker mode, ShakerScan automatically starts a
digest-pinned Caddy gateway and obtains and renews a public certificate when that URL does not
already work. Open inbound TCP 80 and 443 in the VPS firewall and cloud security group. Only health,
bounded enrollment, authenticated node state/heartbeat, and authenticated broker routes are
published. The built-in gateway's public `/health` returns only `{"status":"healthy"}` or
`degraded`; build identity and worker counts remain local. The UI and operator API remain on
loopback and are not made public.

If an existing reverse proxy already provides valid HTTPS *and* the protected fleet route passes the
proxy-trust/authentication probe, ShakerScan detects and reuses it. A healthy `/health` response alone
is not enough: when the protected route is missing or cannot convey trusted HTTPS, automatic mode
provisions the built-in gateway instead. Select `--https-mode external` to require an existing-proxy
topology or `--https-mode managed` to require the built-in gateway. Managed HTTPS is currently for
broker fleets; WireGuard enrollment continues to use an operator-provided HTTPS endpoint.

An external proxy must forward every documented worker route and preserve the HTTPS trust boundary.
`fleet preflight` verifies this by requesting a protected node route without credentials and requiring
HTTP 401. If the proxy uses plaintext HTTP upstream, set the same owner-only
`FLEET_GATEWAY_PROXY_SECRET` in ShakerScan and have the proxy overwrite
`X-ShakerScan-Gateway-Secret` with that value and `X-Forwarded-Proto` with `https`. Never trust
forwarded headers from every Docker-network caller.

`fleet init` runs a complete preflight before changing state. It checks the host, dependencies,
Docker Compose, HTTPS/certificate verification, worker image, ports, overlay routes, enrollment
policy, and reconciliation service. To run the same checks without initializing anything:

```bash
shakerscan fleet preflight \
  --network broker \
  --public-url https://scanner.example.com
```

The command reports every failed check together instead of stopping at the first one. Normally it
derives the installed scanner image and persists its immutable digest automatically. Use
`--worker-image registry.example/shakerscan:tag` only when remote nodes should run a custom worker
build; ShakerScan resolves the tag once and stores the digest. You may also supply
`registry.example/shakerscan@sha256:<64 hexadecimal characters>` directly.

Public enrollment is limited to 30 attempts per source address per minute by default. Override it
with `FLEET_JOIN_RATE_LIMIT_PER_MINUTE` when a controlled provisioning workflow needs a different
bounded rate.

When converting a running standalone control plane for the first time, `fleet init` automatically
runs `shakerscan backup` before writing fleet configuration. Initialization stops if that backup
fails. Keep the resulting owner-only backup according to [Upgrade and
Rollback](upgrade-and-rollback.md).

Network policy:

- Allow HTTPS to the control-plane URL from every joining host.
- For WireGuard, allow inbound UDP on the configured WireGuard port, normally `51820`.
- Never expose Redis `6379`, PostgreSQL `5432`, or the artifact store publicly. WireGuard mode binds
  these services to the private overlay; broker mode does not expose them to worker nodes at all.
- Allow each worker's intended outbound scan traffic. Placement labels are useful when nodes have
  different egress or private-network reachability.

The public HTTPS URL normally uses the operating system's CA store. If it uses a private CA, copy
the public CA certificate to the host and add `--ca-cert /path/to/ca.pem` to both `fleet init` and
`join`. This adds trust for that CA; it does not disable certificate or hostname verification.
Preflight reports an explicit `--ca-cert` hint when system trust cannot verify the endpoint.

## 1. Initialize the Control Plane

Run these commands from the ShakerScan runtime. Installer users can use the global `shakerscan`
command from any directory.

### WireGuard fleet

```bash
shakerscan fleet init \
  --network wireguard \
  --endpoint fleet.example.com:51820 \
  --public-url https://scanner.example.com \
  --workers 1
```

`--endpoint` is the externally reachable WireGuard `host:port`. The installed worker image is
resolved and pinned to a digest before mutation. The default private overlay is
`10.77.0.0/24`, and the default private TLS port is `8443`. Set `--overlay` or `--tls-port` during the
first initialization if those defaults conflict with your network. An existing fleet identity
refuses an overlay-CIDR change.

Initialization creates the WireGuard control identity, fleet CA, private TLS certificate, operator
token, strong Redis/PostgreSQL credentials, and artifact-store configuration. It restarts the stack
and verifies the private TLS and artifact paths before succeeding.

On a Linux host without systemd, add `--no-reconcile-service`. This is an explicit manual fallback;
the join-token command reminds you and the Fleet UI flags nodes awaiting their first WireGuard
connection. Run this on the control plane after every WireGuard node joins or is revoked:

```bash
shakerscan fleet reconcile
```

### Outbound HTTPS broker fleet

```bash
shakerscan fleet init \
  --network broker \
  --public-url https://scanner.example.com \
  --workers 1
```

On a fresh VPS, this is the complete HTTPS setup command. If the URL is not already serving a valid
ShakerScan health response, initialization verifies DNS and ports 80/443, enables the pinned Caddy
profile, obtains a public certificate, and then verifies both public health and the route denylist.
It also verifies central artifact storage. If any step fails, ShakerScan restores the previous
configuration and runtime. Broker mode does not create a WireGuard overlay or distribute data-store
credentials.

### Private-CA public URL

For either transport:

```bash
shakerscan fleet init \
  --network broker \
  --public-url https://scanner.internal.example \
  --ca-cert /etc/shakerscan/internal-ca.pem \
  --https-mode external
```

For a WireGuard deployment, use `--skip-public-check` only for a verified split-horizon or
hairpin-DNS limitation. It does not permit HTTP, disable later TLS verification, or weaken
enrollment. Managed broker initialization must verify its public HTTPS URL and restricted routes
after certificate issuance.

## 2. Create an Enrollment Token

Single-use is the safest default: create a new token for each worker. Tokens are stored only as
hashes, returned once, and expire.

WireGuard:

```bash
shakerscan fleet join-token --ttl 24h
```

Broker:

```bash
shakerscan fleet join-token --ttl 24h --transport broker
```

The command prints the worker-side join command. Treat the token as a short-lived secret. Do not put
it in tickets, shell tracing, logs, or shared chat. If it expires or a join fails before state is
durable, create a fresh token.

Control-plane Fleet commands automatically use the host-published API address recorded by
`scanner.sh`. This matters after `./scanner.sh start --remote`, where Docker may publish the API only
on the host's Tailscale address rather than `127.0.0.1`. Use `--local-api` only to override that
persisted address intentionally.

### Enroll several workers with one bounded token

For a controlled rollout, the control plane can print one command that may be run on several worker
hosts. Set `--max-uses` to the exact number of workers and keep the TTL as short as the rollout permits:

```bash
shakerscan fleet join-token \
  --ttl 1h \
  --max-uses 5 \
  --transport broker
```

The command prints one `shakerscan join ...` command. Run that same command on each of the five
intended workers. Enrollment atomically consumes one use, so concurrent joins cannot exceed the
limit. Each successful worker receives its own unique node identity and durable node credential;
workers do not share credentials after enrollment. The token becomes unusable when its use count is
exhausted or its TTL expires. The token is also bound to the transport selected when it is created;
a broker token cannot be exchanged for a WireGuard enrollment or vice versa.

The output also includes a non-secret token ID and a revocation command. Revoke unused capacity as
soon as the rollout is complete:

```bash
shakerscan fleet revoke-join-token <token-id>
```

Best practices:

- prefer the default single-use token for one-off additions;
- set `--max-uses` to the exact host count, never an open-ended allowance;
- prefer a one-hour or shorter TTL for automated rollouts;
- deliver the command through an approved secret channel, not source control, tickets, or chat logs;
- revoke remaining uses immediately if a host is removed from the rollout or the command may have leaked;
- never reuse a node credential—every host must complete enrollment and receive its own credential.

## 3. Join a Worker Host

Run the printed command on the worker VPS.

### WireGuard worker

```bash
shakerscan join https://scanner.example.com \
  --token <enrollment-token> \
  --name worker-us-1 \
  --region us-central
```

The join workflow first verifies Linux, dependencies, Docker Compose, the token shape, and public
HTTPS without consuming the token. It then creates a WireGuard peer, verifies the private fleet API
with the enrolled CA, asserts a recent WireGuard handshake, retrieves the connection bundle exactly
once, pulls the digest-pinned image, and starts only the worker and node-agent containers. A timeout
reports the endpoint, handshake state, interface state, and whether control-plane reconciliation or
inbound UDP is the likely cause.

### Broker worker

```bash
shakerscan join https://scanner.example.com \
  --token <enrollment-token> \
  --transport broker \
  --name broker-customer-1 \
  --region eu-west
```

Production joins pull the immutable worker image selected by the control plane. To test changes from
a full source checkout on the broker worker without publishing an image first, add `--local-build`:

```bash
./scanner.sh join https://scanner.example.com \
  --token <enrollment-token> \
  --transport broker \
  --name broker-local-dev \
  --local-build
```

This builds `scanner/Dockerfile` on the worker and skips the registry image pull. The node keeps the
control plane's immutable production digest as its desired-image identity while recording the local
runtime override explicitly; the node agent uses that override for local scaling. A later fleet image
rollout replaces the development override with the selected registry digest. Local build mode is a
broker development facility, not a production deployment mechanism, and the Docker build can still
download base images and pinned tool dependencies. Keep at least 12 GiB free for a clean local
build. Before and after a successful rebuild, ShakerScan removes only older unused
`shakerscan-fleet-local:*` image tags; Docker protects any image still used by a running container,
and volumes, scan data, configuration, and unrelated images are never pruned. If less than 12 GiB
remains after that scoped cleanup, the command warns with the available space and remediation but
continues, preserving the operator's choice to build on a cache-warm or space-constrained host. A
healthy local-build node remains schedulable
and selectable in **New Scan**, but Fleet labels it **local test build** and keeps it in the image-drift
count. This preserves development freedom without presenting unpublished code as a production-pinned
or benchmark-safe worker.

Do not run `./scanner.sh start` on a dedicated worker first. `join` starts the isolated worker and
node-agent project itself; the worker host does not need its own API, UI, Redis, or PostgreSQL stack.
Fleet Compose projects are forced to a per-node name so they cannot collide with a standalone
`shakerscan` project that happens to exist on the same host.

For a private-CA endpoint, add `--ca-cert /path/to/ca.pem`. The node persists that CA and both the
broker worker and its node agent use it. Without `--ca-cert`, broker mode explicitly uses the system
CA store.

### Add placement labels

Labels let scans select nodes with the right location, network, egress, residency, tools, or scan
tier:

```bash
shakerscan join https://scanner.example.com \
  --token <enrollment-token> \
  --transport broker \
  --name customer-vpc-a \
  --region eu-west \
  --network customer-vpc \
  --egress-group eu-fixed \
  --data-residency eu \
  --capability nuclei \
  --capability playwright \
  --scan-tier smart \
  --label owner=security-platform
```

Repeat token creation and join for every node. Do not copy `.shakerscan-fleet/node/state.json` from
one host to another; it contains a node-specific identity.

## 4. Verify the Fleet

On the control plane:

```bash
shakerscan status

# Run fleet-operator API examples through the API container's actual loopback.
fleet_api() {
  docker compose exec -T api curl -sS "$@"
}

fleet_api http://127.0.0.1:8080/fleet/nodes | jq
fleet_api http://127.0.0.1:8080/workers | jq
```

The `fleet_api` helper is used by the operator examples below. It reaches the API from the API
container's actual loopback without copying an operator secret into command arguments. A host-side
request to a Docker-published port is not necessarily seen as a loopback peer. Other non-loopback
API calls must use HTTPS and the `FLEET_OPERATOR_TOKEN` generated in the control plane's owner-only
`.env`. Node credentials cannot perform operator actions.

In the UI, open **Fleet**. If the browser reaches the API through a non-loopback path, enter the fleet
operator token in **Operator access**. It is kept in browser session storage and is cleared when the
tab session ends. A control plane started with `./scanner.sh start --remote` may use its Tailscale UI
and API addresses directly: `scanner.sh` verifies that the published bind equals the host's live
Tailscale IPv4, and then permits token-authenticated fleet operations over that Tailscale-encrypted
HTTP transport. The exception does not apply to wildcard, public, stale, or manually asserted bind
addresses; those still require HTTPS.

A ready fleet should show:

- every intended node as `healthy`;
- active workers equal to desired workers;
- no state drift, and no image drift unless the node intentionally uses `--local-build` for testing;
- recent heartbeats without `last_error`;
- the expected image digest and placement labels.

The Dashboard worker indicator separates available local and remote workers. The Fleet page shows
remote-node availability, available/desired remote workers, local control-plane workers, and total
execution capacity. `GET /workers` exposes the same aggregate under `execution_capacity`:

```json
{
  "execution_capacity": {
    "local_running": 1,
    "local_available": 1,
    "remote_running": 3,
    "remote_available": 2,
    "total_available": 3,
    "remote_nodes": 2,
    "remote_nodes_available": 1
  }
}
```

"Available" excludes stale, draining, state-drifted, rolling, unexplained image-drifted, and
zero-worker remote nodes. A verified `shakerscan-fleet-local:*` development node is the deliberate
exception: it remains available for operator-selected testing while still reporting image drift and
`local_build_active=true`. It is never production-current or benchmark-safe. The top-level
`/workers.count` remains the local Docker worker count so existing local scaling clients remain
compatible.

Do not benchmark or rely on scan coverage while `/workers` reports stale or pending builds.

## 5. Scale and Operate Nodes

The Fleet UI is the normal operating surface. It supports fleet-wide and per-node scaling,
drain/resume, rolling image updates, activity, lifecycle events, and revocation.

### Set one remote-fleet worker target

The control plane distributes the requested remote-worker total across healthy, non-draining nodes
according to reported capacity. Scale local control-plane workers separately from the Dashboard or
`POST /workers`:

```bash
fleet_api -X POST http://127.0.0.1:8080/fleet/scale \
  -H 'Content-Type: application/json' \
  -d '{"desired_worker_count":24}'
```

### Change one node

```bash
NODE_ID='<node UUID>'

# Scale this node
fleet_api -X PATCH "http://127.0.0.1:8080/fleet/nodes/$NODE_ID/state" \
  -H 'Content-Type: application/json' \
  -d '{"desired_worker_count":4}'

# Gracefully stop it from taking new work
fleet_api -X PATCH "http://127.0.0.1:8080/fleet/nodes/$NODE_ID/state" \
  -H 'Content-Type: application/json' \
  -d '{"drain":true}'

# Resume it
fleet_api -X PATCH "http://127.0.0.1:8080/fleet/nodes/$NODE_ID/state" \
  -H 'Content-Type: application/json' \
  -d '{"drain":false}'
```

Drain is graceful: the agent stops new leases, waits for active work, and preserves busy workers.
Use the Fleet page to confirm active workers reach zero before host maintenance.

### Roll out a new image

Use a new immutable digest, never a tag:

```bash
fleet_api -X PATCH "http://127.0.0.1:8080/fleet/nodes/$NODE_ID/state" \
  -H 'Content-Type: application/json' \
  -d '{"worker_image_digest":"registry.example/shakerscan@sha256:<new-digest>"}'
```

The node drains, pulls the requested image, replaces idle workers one at a time, and resumes only
after an image-confirming heartbeat. Roll through nodes sequentially and wait for `image_current`
and `state_current` before updating the next node.

## 6. Route a Scan

On **New Scan**, choose **Execution location**:

- **Automatic** lets any available local or remote worker execute the scan and provides the widest
  failover.
- **Control plane (local)** keeps the scan on local workers.
- **Specific remote node** keeps it on any healthy worker replica within that node.

Advanced placement constraints can additionally require a region, network, egress group,
data-residency label, scan tier, or tool. A routed scan waits for an eligible healthy worker rather
than silently running in the wrong place. Unavailable remote nodes are visible but cannot be chosen.
Remote inventory requires the session-only operator token entered on the Fleet page.

API example:

```bash
curl -sS -X POST http://127.0.0.1:8080/scans \
  -H 'Content-Type: application/json' \
  -d '{
    "target":"https://authorized.example",
    "options":{
      "scan_type":"standard",
      "placement":{
        "region":"eu-west",
        "network":"customer-vpc",
        "requires":["nuclei"]
      },
      "require_current_workers":true
    }
  }'
```

Keep a scan on the control plane:

```bash
curl -sS -X POST http://127.0.0.1:8080/scans \
  -H 'Content-Type: application/json' \
  -d '{
    "target":"https://authorized.example",
    "options":{"scan_type":"standard","placement":{"node_id":"local"}}
  }'
```

Select one remote node by its Fleet UUID:

```bash
curl -sS -X POST http://127.0.0.1:8080/scans \
  -H 'Content-Type: application/json' \
  -d '{
    "target":"https://authorized.example",
    "options":{"scan_type":"standard","placement":{"node_id":"<remote-node-uuid>"}}
  }'
```

Placement can use `node_scope`, `node_id`, `region`, `network`, `egress_group`, `data_residency`,
`scan_tier`, and `requires`. `node_scope=remote` selects any eligible joined node,
`node_id=local` is the reserved control-plane location, and every other `node_id` is an
enrolled remote-node UUID. HTTPS broker leasing and WireGuard workers use the same canonical node
identity, so node selection behaves consistently across transports. Placement restricts execution
location; it does not grant authorization to scan a target. A node with no `--scan-tier` flags supports every built-in scan tier. The standard worker
image automatically advertises its packaged tool baseline; custom images must use `--capability`
for additional tools. Admission considers current local workers plus non-draining remote nodes with
active workers and a recent heartbeat. Continue to use only targets you are authorized to test.

## 7. Run Physical Acceptance

After at least two physical nodes are healthy, run the preflight from the control plane:

```bash
shakerscan fleet accept \
  --preflight-only \
  --public-host scanner.example.com
```

The acceptance command also resolves the persisted host-published API address automatically. An
explicit `--api-url` remains available when the runner is launched from a different machine.

Then run the passive cross-node test against a target you control:

```bash
shakerscan fleet accept \
  --public-host scanner.example.com \
  --target https://authorized.example \
  --authorized
```

Source-checkout fleets intentionally report image drift because their local worker image is not the
fleet's pinned production digest. To validate physical behavior without weakening that production
signal, add `--allow-local-build`. The command then requires every selected node to run the same
safe `shakerscan-fleet-local:*` image and labels the receipt `local-build-development`; that receipt
is development evidence, not a production release gate. Without the flag, acceptance remains
fail-closed on any image drift.

The acceptance runner verifies node/image health, heartbeats, artifact storage, public data-store
isolation, lease loss/reclaim/ack behavior, cross-node shard execution, execution attribution,
finding deduplication, and central result manifests. It writes a content-free receipt to
`results/fleet-acceptance.json` by default.

The release gate defaults to passive `standard`. A development smoke test may use
`--scan-type quick`; the selected depth is recorded in the receipt and does not replace the default
release-candidate run.

For a controlled failure-injection test, see `shakerscan fleet accept --help`; it can drain a chosen
node and kill the exact worker executing a shard over non-interactive SSH.

## 8. Remove or Recover a Node

Drain before planned removal. When it has no active work, revoke it from the Fleet UI or locally:

```bash
fleet_api -X POST "http://127.0.0.1:8080/fleet/nodes/$NODE_ID/revoke"
```

Revocation is permanent for that node identity: it disables scheduling and revokes every node
credential. Stop the worker runtime on the removed host. Rejoining requires an unexpired enrollment
token with a remaining use, normally a fresh single-use token.

The WireGuard connection bundle is deliberately one-shot. If a node crashes after the bundle is
delivered but before its owner-only local state is durable, revoke the incomplete node and enroll it
again. Do not copy shared credentials or weaken the delivery gate.

## Troubleshooting

| Symptom | Check and action |
|---|---|
| Join cannot reach the control plane | Verify DNS, HTTPS, firewall rules, and the public URL. For a private CA, pass the same `--ca-cert` to initialization and join. |
| WireGuard join times out after enrollment | Read the endpoint/handshake/interface diagnostics printed by `join`; allow inbound UDP and run `shakerscan fleet reconcile` if automatic reconciliation was disabled. The Fleet UI marks nodes awaiting their first WireGuard connection. |
| `fleet CA is not configured` | Overlay state must contain the enrolled CA at `.shakerscan-fleet/node/ca.crt`. Do not switch it to system trust; revoke and rejoin if state is incomplete. |
| Broker reports certificate verification failure | Confirm the public certificate chain and hostname. Supply the correct private CA with `--ca-cert` when applicable. Never disable TLS verification. |
| Broker preflight expects HTTP 401 | The proxy does not publish the protected node route or the API cannot authenticate its HTTPS signal. Use managed HTTPS or configure the external proxy trust secret described above. |
| Join token is expired, revoked, or exhausted | Mint a fresh token. For a multi-worker rollout, verify `--max-uses` matches the intended host count and revoke any superseded token ID. |
| Node is `stale` | Check the node-agent container, host clock, DNS/network reachability, and its `last_error`. A stale node is excluded from fleet-wide scaling. |
| State or image drift persists | Inspect node-agent logs, Docker pull access, local disk/memory, and the digest. A mutable image tag is invalid. |
| Routed scan remains pending | Confirm at least one recently heartbeating, non-draining node with active workers matches every placement constraint and supports the requested scan tier/tools. |
| Bundle retry returns a conflict | The one-time response was already consumed. Revoke and re-enroll the incomplete node. |
| Fleet API returns `403` remotely | Use the control plane's operator token over HTTPS, or use the token over HTTP only through ShakerScan's verified live Tailscale bind. Binding a host port to loopback does not authenticate Docker-network callers. |
| Redis/PostgreSQL is reachable publicly | Treat this as a deployment failure. Close the ports immediately and rerun physical preflight acceptance. |

Useful diagnostics:

```bash
# Control plane
shakerscan status
docker compose logs --tail=200 api
fleet_api http://127.0.0.1:8080/fleet/nodes | jq

# Worker host, from the ShakerScan runtime
NODE_PROJECT="shakerscan-fleet-$(jq -r '.node_id' .shakerscan-fleet/node/state.json | cut -c1-8)"
docker compose -p "$NODE_PROJECT" --env-file .shakerscan-fleet/node/compose.env \
  -f docker-compose.worker.yml logs --tail=200 node-agent worker

# Broker worker host
NODE_PROJECT="shakerscan-fleet-$(jq -r '.node_id' .shakerscan-fleet/node/state.json | cut -c1-8)"
docker compose -p "$NODE_PROJECT" --env-file .shakerscan-fleet/node/compose.env \
  -f docker-compose.broker-worker.yml logs --tail=200 node-agent worker
```

Do not paste `.env`, node state, connection bundles, join tokens, node credentials, or full diagnostic
archives into issues. Fleet activity and acceptance receipts are designed to be content-free.
