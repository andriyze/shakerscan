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

- Use Linux for the control plane and worker hosts. The fleet host provisioner is Linux-only.
- Install ShakerScan on the control plane and every worker host.
- Install Docker. WireGuard mode also needs `wg`, `wg-quick`, and `ip`.
- Give the control plane a stable HTTPS URL, such as `https://scanner.example.com`. Put it behind a
  firewall, VPN, or authenticated reverse proxy; ShakerScan is a trusted-operator product, not a
  public multi-user service.
- Select a worker image by immutable digest:
  `registry.example/shakerscan@sha256:<64 hexadecimal characters>`. A mutable tag such as `latest`
  is rejected.
- Back up the control plane before converting an existing standalone installation. Follow
  [Upgrade and Rollback](upgrade-and-rollback.md).

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

## 1. Initialize the Control Plane

Run these commands from the ShakerScan runtime. Installer users can use the global `shakerscan`
command from any directory.

### WireGuard fleet

```bash
shakerscan fleet init \
  --network wireguard \
  --endpoint fleet.example.com:51820 \
  --public-url https://scanner.example.com \
  --worker-image registry.example/shakerscan@sha256:<digest> \
  --workers 1
```

`--endpoint` is the externally reachable WireGuard `host:port`. The default private overlay is
`10.77.0.0/24`, and the default private TLS port is `8443`. Set `--overlay` or `--tls-port` during the
first initialization if those defaults conflict with your network. An existing fleet identity
refuses an overlay-CIDR change.

Initialization creates the WireGuard control identity, fleet CA, private TLS certificate, operator
token, strong Redis/PostgreSQL credentials, and artifact-store configuration. It restarts the stack
and verifies the private TLS and artifact paths before succeeding.

On a Linux host without systemd, add `--no-reconcile-service`. You must then run this on the control
plane after every WireGuard node joins or is revoked:

```bash
shakerscan fleet reconcile
```

### Outbound HTTPS broker fleet

```bash
shakerscan fleet init \
  --network broker \
  --public-url https://scanner.example.com \
  --worker-image registry.example/shakerscan@sha256:<digest> \
  --workers 1
```

Broker initialization verifies the public HTTPS API and central artifact storage. It does not create
a WireGuard overlay or distribute data-store credentials.

### Private-CA public URL

For either transport:

```bash
shakerscan fleet init \
  --network broker \
  --public-url https://scanner.internal.example \
  --ca-cert /etc/shakerscan/internal-ca.pem \
  --worker-image registry.example/shakerscan@sha256:<digest>
```

For a WireGuard deployment, use `--skip-public-check` only for a verified split-horizon or
hairpin-DNS limitation. It does not permit HTTP, disable later TLS verification, or weaken
enrollment. Broker initialization must be able to verify its public HTTPS URL after restart.

## 2. Create a Single-Use Join Token

Create a new token for each worker. Tokens are stored only as hashes, returned once, and expire.

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

## 3. Join a Worker Host

Run the printed command on the worker VPS.

### WireGuard worker

```bash
shakerscan join https://scanner.example.com \
  --token <single-use-token> \
  --name worker-us-1 \
  --region us-central
```

The join workflow creates a WireGuard peer, verifies the private fleet API with the enrolled CA,
retrieves the connection bundle exactly once, pulls the digest-pinned image, and starts only the
worker and node-agent containers.

### Broker worker

```bash
shakerscan join https://scanner.example.com \
  --token <single-use-token> \
  --transport broker \
  --name broker-customer-1 \
  --region eu-west
```

For a private-CA endpoint, add `--ca-cert /path/to/ca.pem`. The node persists that CA and both the
broker worker and its node agent use it. Without `--ca-cert`, broker mode explicitly uses the system
CA store.

### Add placement labels

Labels let scans select nodes with the right location, network, egress, residency, tools, or scan
tier:

```bash
shakerscan join https://scanner.example.com \
  --token <single-use-token> \
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
curl -sS http://127.0.0.1:8080/workers | jq
```

The `fleet_api` helper is used by the operator examples below. It reaches the API from the API
container's actual loopback without copying an operator secret into command arguments. A host-side
request to a Docker-published port is not necessarily seen as a loopback peer. Other non-loopback
API calls must use HTTPS and the `FLEET_OPERATOR_TOKEN` generated in the control plane's owner-only
`.env`. Node credentials cannot perform operator actions.

In the UI, open **Fleet**. If the browser reaches the API through a non-loopback path, enter the fleet
operator token in **Operator access**. It is kept in browser session storage and is cleared when the
tab session ends.

A ready fleet should show:

- every intended node as `healthy`;
- active workers equal to desired workers;
- no state or image drift;
- recent heartbeats without `last_error`;
- the expected image digest and placement labels.

Do not benchmark or rely on scan coverage while `/workers` reports stale or pending builds.

## 5. Scale and Operate Nodes

The Fleet UI is the normal operating surface. It supports fleet-wide and per-node scaling,
drain/resume, rolling image updates, activity, lifecycle events, and revocation.

### Set one fleet-wide worker target

The control plane distributes the requested total across healthy, non-draining nodes according to
reported capacity:

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

On **New Scan**, open **Advanced Options**, enable **Fleet Placement**, and optionally select a node,
region, network, egress group, data-residency label, or required tools. A routed scan waits for an
eligible healthy worker rather than silently running on the wrong node.

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

Placement can use `node_id`, `region`, `network`, `egress_group`, `data_residency`, `scan_tier`, and
`requires`. Placement restricts execution location; it does not grant authorization to scan a
target. Continue to use only targets you are authorized to test.

## 7. Run Physical Acceptance

After at least two physical nodes are healthy, run the preflight from the control plane:

```bash
shakerscan fleet accept \
  --preflight-only \
  --public-host scanner.example.com
```

Then run the passive cross-node test against a target you control:

```bash
shakerscan fleet accept \
  --public-host scanner.example.com \
  --target https://authorized.example \
  --authorized
```

The acceptance runner verifies node/image health, heartbeats, artifact storage, public data-store
isolation, lease loss/reclaim/ack behavior, cross-node shard execution, execution attribution,
finding deduplication, and central result manifests. It writes a content-free receipt to
`results/fleet-acceptance.json` by default.

For a controlled failure-injection test, see `shakerscan fleet accept --help`; it can drain a chosen
node and kill the exact worker executing a shard over non-interactive SSH.

## 8. Remove or Recover a Node

Drain before planned removal. When it has no active work, revoke it from the Fleet UI or locally:

```bash
fleet_api -X POST "http://127.0.0.1:8080/fleet/nodes/$NODE_ID/revoke"
```

Revocation is permanent for that node identity: it disables scheduling and revokes every node
credential. Stop the worker runtime on the removed host. Rejoining requires a fresh single-use token.

The WireGuard connection bundle is deliberately one-shot. If a node crashes after the bundle is
delivered but before its owner-only local state is durable, revoke the incomplete node and enroll it
again. Do not copy shared credentials or weaken the delivery gate.

## Troubleshooting

| Symptom | Check and action |
|---|---|
| Join cannot reach the control plane | Verify DNS, HTTPS, firewall rules, and the public URL. For a private CA, pass the same `--ca-cert` to initialization and join. |
| WireGuard join times out after enrollment | Confirm UDP reachability to `--endpoint`, inspect `wg show`, and run `shakerscan fleet reconcile` if automatic reconciliation was disabled. |
| `fleet CA is not configured` | Overlay state must contain the enrolled CA at `.shakerscan-fleet/node/ca.crt`. Do not switch it to system trust; revoke and rejoin if state is incomplete. |
| Broker reports certificate verification failure | Confirm the public certificate chain and hostname. Supply the correct private CA with `--ca-cert` when applicable. Never disable TLS verification. |
| Node is `stale` | Check the node-agent container, host clock, DNS/network reachability, and its `last_error`. A stale node is excluded from fleet-wide scaling. |
| State or image drift persists | Inspect node-agent logs, Docker pull access, local disk/memory, and the digest. A mutable image tag is invalid. |
| Routed scan remains pending | Confirm at least one healthy node matches every placement constraint and supports the requested scan tier/tools. |
| Bundle retry returns a conflict | The one-time response was already consumed. Revoke and re-enroll the incomplete node. |
| Fleet API returns `403` remotely | Use HTTPS and the control plane's operator token. Binding a host port to loopback does not authenticate Docker-network callers. |
| Redis/PostgreSQL is reachable publicly | Treat this as a deployment failure. Close the ports immediately and rerun physical preflight acceptance. |

Useful diagnostics:

```bash
# Control plane
shakerscan status
docker compose logs --tail=200 api
fleet_api http://127.0.0.1:8080/fleet/nodes | jq

# Worker host, from the ShakerScan runtime
docker compose --env-file .shakerscan-fleet/node/compose.env \
  -f docker-compose.worker.yml logs --tail=200 node-agent worker

# Broker worker host
docker compose --env-file .shakerscan-fleet/node/compose.env \
  -f docker-compose.broker-worker.yml logs --tail=200 node-agent worker
```

Do not paste `.env`, node state, connection bundles, join tokens, node credentials, or full diagnostic
archives into issues. Fleet activity and acceptance receipts are designed to be content-free.
