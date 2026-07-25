# Multi-Node Architecture

**Status:** Design authority + Phase-1 vertical-slice implementation in progress. The fan-out
substrate is shipped (see the code-grounded capability table below), and the durable node identity,
single-use enrollment, authenticated heartbeat, and one-time connection-bundle API foundation is now
implemented. The digest-pinned worker-only Compose runtime, pull-based node-agent, and versioned
desired-state API are also implemented, along with the fleet-profile CA-verified overlay TLS listener.
The Linux `fleet init` / `fleet join-token` / `join` WireGuard host workflow is implemented. Durable
per-scan worker/node attribution, current-vs-desired node drift derivation, fleet summary, and recent
per-node activity APIs are implemented. The Fleet operations UI is implemented with health/drift,
capacity, current-work, per-node scaling, drain/resume, and revoke controls. The physical two-VPS
proof is not complete. Redis Stream lease/heartbeat/ack/reclaim delivery is implemented. The
remaining artifact, placement, rolling-lifecycle, and Phase-3 broker work remains design-level.
**Scope:** run a coordinated ShakerScan fleet across multiple VMs/VPS hosts so one UI/API
can scan more targets at once and run high-budget Full Coverage scans by using workers
from many machines.
**Related design:** [dast-asm-architecture.md](dast-asm-architecture.md).

## Capability Status

This section is the multi-node **substrate** inventory only — what execution machinery already exists
in code versus what this document specifies as net-new. It deliberately does not restate the DAST/ASM
capability matrix (that lives in [dast-asm-architecture.md](dast-asm-architecture.md) and drifted when
duplicated). Each "Built" row is anchored to a source symbol so it stays verifiable instead of
becoming stale prose. For product priority and phased order, see
[proposed-next-steps.md](proposed-next-steps.md).

| Substrate piece | Status | Where (symbol) |
|---|---|---|
| Intra-target fan-out `scan_plan → scan_shard → scan_merge` (strategies: scope, family, coverage, coverage_family, auth_split, dynamic pull) | **Built** | `parallel_scan.py` planner; `worker.py` `process_scan_{plan,shard,merge}_job` |
| Exactly-once merge trigger (atomic Redis Lua claim-and-enqueue + DB non-terminal-shard source of truth) | **Built** | `reconcile_parallel_parent` (`parallel_scan.py`) |
| Race-safe concurrent finding writes | **Built** | `UNIQUE INDEX idx_findings_target_fingerprint` (`db/init.sql`) |
| Fleet-wide active-scan concurrency cap (lease-based Redis ZSET semaphore; TTL frees a crashed holder) | **Built, but fail-OPEN** — `_take_scan_slot` returns granted on any Redis error and the bounded wait fails open, so the cap is an OOM guard on a healthy shared Redis, **not** an enforceable fleet limit. A partitioned node runs uncapped. | `ACTIVE_SCAN_SLOTS_KEY`, `_take_scan_slot` (`worker.py`) |
| Per-root-domain request reservation (atomic Redis Lua; already coordinates every process on the shared Redis) | **Built** | `reserve_domain_rate` (`asm_inventory.py`) |
| Managed `evidence_objects` backend (SigV4 S3/MinIO client: content-addressed PUT, hash-verified GET, retention DELETE) | **Built but OFF by default** — only covers large managed evidence-object payloads. General scan results, checkpoints, and other `/results` artifacts remain local; Compose does not yet pass the S3 settings through. | `evidence_storage.py`; `worker.py` `save_result_file` |
| Job-queue delivery | **Built with leased delivery** — Redis Streams consumer groups, explicit ack/delete after successful dispatch, lease heartbeats, visibility-timeout reclaim, bounded delivery attempts, and fail-closed execution cancellation when lease ownership/heartbeat authority is lost. Pre-upgrade list entries remain drainable. | `job_queue.py`; `worker.py` `_run_job_under_lease` |
| Remote worker scaling | **Built per node** — the control plane changes versioned desired count/drain state; each authenticated pull agent reconciles only its local labeled containers | `PATCH /fleet/nodes/{id}/state`; `fleet_agent.py` `reconcile_workers` |
| Node identity, enrollment, join tokens, heartbeat, credential rotation/revocation, CA bootstrap, overlay TLS edge, `nodes` table | **Foundation built** — physical two-VPS acceptance remains incomplete | `fleet.py`; `/fleet/*`; `fleet-edge`; `nodes`, `node_join_tokens`, `node_credentials` |
| Worker-only deployment and pull-based node-agent | **Foundation built** — digest-pinned worker/agent-only Compose, owner-only local state, versioned desired state, local Docker reconciliation, drain-to-zero, capacity/error heartbeat | `docker-compose.worker.yml`; `fleet_agent.py`; `GET|PATCH /fleet/nodes/{id}/state` |
| WireGuard/CLI host provisioning | **Built, awaiting physical two-VPS acceptance** — persistent identity, CA/server certificates, overlay/data binding, automatic or manual peer reconciliation, public HTTPS enrollment, overlay proof, one-time bundle persistence, worker-only startup | `scripts/fleet_cli.py`; `scanner.sh fleet`; `scanner.sh join` |
| Per-node execution attribution and fleet rollup | **Built** — scan/shard rows record the executing node and unique worker replica; revoked nodes fail closed and re-enqueue refused work; node API derives state/image drift and exposes recent activity | `scans.executing_node_id`; `worker.py` `_attribute_job_execution`; `GET /fleet/nodes`; `GET /fleet/nodes/{id}/activity` |
| Fleet UI | **Built** — unified health/capacity/drift view, recent attributed work, desired worker scaling, drain/resume, revoke confirmation, and session-only remote operator credential handling | `ui/src/app/fleet/page.tsx`; sidebar `/fleet` |
| Capability/region/egress placement | **Not present** — specified by this document | — |

The takeaways that shape the plan:

- **Do not rebuild** the fan-out, merge-once, finding dedup, active-scan semaphore, or the domain-rate
  primitive. They are real, and the last two already coordinate across a shared Redis. Note the
  differing failure postures before depending on either as a fleet control: `reserve_domain_rate`
  fails **closed** (grants 0 on a Redis error), while the active-scan semaphore fails **open**. Only
  the former is safe to treat as a limit a remote node cannot exceed; making the latter enforceable
  is fleet work, not a rebuild.
- **Do not mistake managed evidence-object storage for a complete artifact plane.** The S3 client is
  reusable, but cross-node results/checkpoints/diagnostics require application and deployment work
  (§8).
- The node identity/enrollment/overlay and leased/acked/reclaimable queue are now implemented. The
  largest remaining production gaps are a general cross-node artifact contract, routing/placement,
  rolling lifecycle, the broker boundary, and physical multi-VPS acceptance.

The parallel-scan design answers: "How does one logical scan fan out into plan, shard, and merge
jobs?" This document answers: "How can those worker jobs run safely on more than one host?"

Important framing: "multiple ShakerScan instances" should not mean several isolated
all-in-one installs with separate databases and queues. That would create several
uncoordinated scanners. The coordinated model is one control-plane instance plus many
worker instances joined to the same fleet.

## Summary

1. **Use one coordinated fleet, not independent scanners.** A control-plane ShakerScan
   instance owns the UI/API, queue, database, and scheduler. Worker ShakerScan instances
   on other VPSs register with it and run scan jobs.
2. **Make VPS enrollment a copy/paste workflow.** The operator should start the control
   plane, create a join token, then run one command on each worker VPS. The command should
   configure networking, register the node, write local worker config, and start workers.
3. **Use a hub-and-spoke topology internally.** Worker instances do not need peer-to-peer
   scan coordination. They connect to the control plane, which distributes work across
   the fleet.
4. **The first useful multi-node version should use built-in WireGuard.** ShakerScan
   should generate the WireGuard control-plane and worker peer configuration during
   `fleet init` / `fleet join`, so remote worker VPSs can reach control-plane services
   without exposing Redis or Postgres to the public internet. Tailscale can remain an
   optional path for operators who already use it.
5. **The long-term zero-trust version should use an HTTPS job broker.** In that model,
   workers never receive database or Redis credentials. They lease jobs, heartbeat, upload
   evidence, and submit results through a narrow API.
6. **Multi-node composes with the parallel-scan work, which has shipped.** Intra-target
   fan-out (`scan_plan -> scan_shard -> scan_merge`, plus the `scope`/`family`/`coverage`
   strategies) is implemented today — see `docs/dast-asm-architecture.md`. Shard jobs are
   plain entries on the shared `scan_jobs` Redis list, so any fleet worker that consumes that
queue already runs shards of one logical scan; the merge reconciles regardless of which node
   ran each shard. Multi-node therefore adds *capacity* (more workers draining the same shard
   queue → more concurrent shards, so `coverage` fan-outs finish faster); it does not change the
   orchestration. The remaining multi-node work is the transport/trust substrate (how remote
   workers reach the queue safely), not the fan-out itself. This is important for the
   Honey/Juice Shop/crAPI class of targets: fleet capacity lets one logical Full Coverage
   scan discover once, queue many endpoint shards, and try many more probes without forcing
   all work through one VPS.
7. **The hard parts are lifecycle, evidence, queue reliability, routing, rate limiting,
   and security.** The existing queue/dedup model is a good substrate, but a production
   fleet needs more than "point workers at the same Redis."

## Operator Goal

The target user experience should be:

```text
# On the main VPS
curl -fsSL https://install.shakerscan.com | sh
shakerscan fleet init --network wireguard
shakerscan fleet join-token --role worker --ttl 24h

# On each additional VPS
curl -fsSL https://install.shakerscan.com | sh
shakerscan join <control-plane-url> --token <join-token>
```

Those commands are the desired product workflow, not a statement that all flags already
exist today.

After joining, the operator should see every VPS in one fleet view:

- node name and health;
- region and egress IP;
- worker capacity and active worker count;
- current scan jobs;
- scanner image version;
- drain/disable controls.

When the operator submits many scans, the control plane should distribute them across
all registered worker instances. For example, five VPSs with four workers each should
support roughly twenty concurrent worker jobs, constrained by global target rate limits and
available memory/CPU. Those jobs may be independent scans, or they may be coverage shards
belonging to one logical scan.

### Instance Roles

| Role | Runs | Purpose |
|---|---|---|
| Control-plane instance | API, UI, Postgres, Redis/queue, scheduler, evidence store, optional local workers | The single source of truth and the only place users submit/list scans. |
| Worker instance | Node-agent plus scanner workers | Adds CPU, memory, browser capacity, tools, egress IPs, and network reachability to the fleet. |
| Standalone instance | Full all-in-one stack | Useful for local/dev/single-box installs, but not coordinated with other standalone instances. |

Coordinated multi-node mode should promote a standalone install to `control-plane` or
`worker`, not ask users to manually stitch together several all-in-one installs.

## Non-Goals

- Do not build a worker mesh. Workers should not call each other.
- Do not make every VPS run a full independent stack in coordinated fleet mode.
- Do not expose Redis or Postgres directly on the public internet.
- Do not require Kubernetes for the first version.
- Do not redesign the parallel scan shard model here. This doc assumes the current local execution
  model in [dast-asm-architecture.md](dast-asm-architecture.md).

## 1. How This Relates To Parallel Scans

The parallel-scan architecture introduces a parent/coordinator model:

```text
POST /scans
  -> scan_plan
  -> N scan_shard jobs
  -> scan_merge
```

Multi-node does not change that shape. It changes where those jobs can execute.

| State | What multi-node gives you |
|---|---|
| Before parallel scan fan-out | More total throughput for independent scans and batch scans. Each scan still runs on one worker, but the shared queue spreads scans across VPSs. |
| After `scan_plan` / `scan_shard` / `scan_merge` | Shards from one logical scan can be consumed by workers on different VPSs. |
| After Full Coverage mode | One target can queue many endpoint shards; more VPSs drain those shards faster while the parent scan still merges into one report. |
| After routing and affinity | The control plane can place jobs by region, egress IP, internal-network reachability, scan tier, or tool capability. |

The shared requirements between the two designs are:

- one shared queue substrate;
- one shared scan/finding database;
- race-safe finding writes;
- shared parent scan context and shard result state;
- global budget, finding-cap, early-stop, and cancellation counters;
- centralized evidence storage so reports can reference artifacts produced on any node.

## 2. Why Run Across Multiple VMs/VPSs

| Driver | Why it matters |
|---|---|
| Throughput | A single host is bounded by CPU, memory, browser capacity, and subprocess fan-out. |
| Egress diversity | Different worker VPSs provide different source IPs, which helps identify per-IP rate limits and WAF behavior. |
| Geography | Workers in different regions can expose CDN, geo-blocking, latency, and regional routing behavior. |
| Private reachability | A worker VPS can sit inside a customer VPN/VPC while the control plane remains elsewhere. |
| Isolation | Aggressive or exploit-tier scans can run on disposable worker instances away from the control plane. |
| Availability | With reliable leases, work can be reclaimed when a worker host disappears. |

## 3. Target Topology

```text
                  Control-plane ShakerScan instance
       +--------------------------------------------------+
       | API / UI                                          |
       | Postgres                                          |
       | Redis or broker queue                             |
       | Evidence store: S3 / MinIO / compatible object API |
       | Node registry / scheduler                         |
       +------------------------+-------------------------+
                                |
             Built-in WireGuard now, HTTPS broker later
                                |
       +------------------------+-------------------------+
       |                        |                         |
+------+-------+        +-------+------+          +-------+------+
| Worker VPS A |        | Worker VPS B |          | Worker VPS N |
| node-agent   |        | node-agent   |          | node-agent   |
| worker procs |        | worker procs |          | worker procs |
| egress IP A  |        | egress IP B  |          | region: eu   |
+--------------+        +--------------+          +--------------+
```

**Control plane:** owns durable state and the product API/UI. It starts as one VPS and can
later move Postgres/Redis/evidence to managed services.

**Worker instance:** owns local execution only. It runs the scanner image, browser/tooling
dependencies, and a small node-agent that reports health/capacity and applies local
worker-count changes.

## 4. Current Architecture Fit

| Concern | Current behavior | Multi-node implication |
|---|---|---|
| Job queue | Scan/retest jobs use Redis Streams consumer groups with ack, heartbeat, bounded reclaim, and a legacy-list drain bridge. | A worker on another VPS can participate if it can reach the same queue; hard loss is reclaimed after the visibility timeout. |
| Finding writes | Findings are deduped with a database uniqueness constraint and conflict-safe inserts. | Concurrent workers can scan the same target without inventing a distributed lock. |
| Parallel scan plan | Parent, shard, and merge jobs are implemented on the queue. | Shard jobs are naturally host-agnostic when remote workers can safely reach the shared queue and state. |
| Worker scaling | `POST /workers` controls replicas on the local Docker host. | This does not scale remote worker instances. Multi-node needs per-node lifecycle control. |
| Evidence | `./results` is a local bind mount. | Artifacts written on worker VPS B are not automatically visible to the control plane. This must be centralized. |
| Queue reliability | Stream messages remain pending while leased, heartbeat during execution, are acknowledged only after successful dispatch, and are reclaimed after owner loss. | Physical partition/kill testing remains required before the production acceptance claim. |
| Networking | The local stack binds API/UI to the configured host; remote mode already parameterizes public/private bind addresses. | Built-in WireGuard should become the default fleet overlay; Redis/Postgres binding and firewall rules must be explicit. |

The important conclusion: the scanner does not need a new distributed execution model.
It needs the existing execution model to be made fleet-aware.

### Coordination For More Concurrent Targets

The first coordination target is simple: one control plane owns the scan queue, and all
joined worker instances pull from that queue.

Flow:

1. User submits scans through the control-plane UI/API.
2. Control plane records each scan in the shared database and enqueues jobs.
3. Worker instances pull jobs as capacity is available.
4. Each worker reports status, logs, findings, and completion back to shared state.
5. The UI shows one unified queue, one scan list, and one findings database.

This immediately improves throughput for batches and independent targets. If there are
four VPSs with five workers each, the fleet can run about twenty worker jobs at once,
subject to scan type, memory, CPU, and global rate limits.
Known-endpoint ASM and Full Coverage work reserves endpoint budget through shared Redis buckets.
Standalone scans now have an opt-in enforcing request meter and root-domain request-token
reservation; compatibility mode remains the default until owned-fleet rate soak is accepted.

The worker instances do not need to coordinate directly with each other to achieve this.
They only need a shared scheduler/queue and a shared source of truth.

## 5. Connectivity Options

### Option A: Built-In WireGuard Overlay + Shared Redis/Postgres

Recommended first version for an owned worker fleet.

Worker instances connect to the control plane's Redis and Postgres over a ShakerScan-managed
WireGuard overlay. The application protocol stays the same; the network boundary changes.
`shakerscan fleet init` creates the control-plane peer and join-token material;
`shakerscan join` creates the worker peer, exchanges keys with the control plane, writes
the worker-only config, and starts local workers.

**Use when:**

- all worker instances are controlled by the ShakerScan operator;
- fast delivery matters;
- direct DB/Redis credentials on workers are acceptable for an internal/private fleet.

**Pros:**

- smallest code change;
- works with the current queue and database model;
- no external Tailscale account or coordination service required;
- ShakerScan can generate deterministic node config and firewall guidance;
- Tailscale can still be supported as an alternate network backend for users who already
  have a tailnet.

**Cons:**

- workers hold database and Redis credentials;
- compromise of a worker has a larger blast radius;
- Redis/Postgres availability still gates the whole fleet;
- flaky links expose the current queue reliability gap.

### Option B: Public Redis/Postgres With TLS And Allowlists

Not recommended.

Redis and Postgres can technically be exposed with TLS, SCRAM/ACLs, and firewall
allowlists. That is still the wrong default for a security scanner. Allowlists drift,
TLS is easy to misconfigure, and these services are too sensitive to be public control
plane endpoints.

Use this only as a last-resort temporary bridge, and prefer Option C instead.

### Option C: HTTPS Broker + Thin Worker Agent

Recommended long-term model for untrusted, customer-hosted, NAT'd, or SaaS-style worker
nodes.

Workers do not reach Redis or Postgres. They make outbound HTTPS calls to a broker API:

- register node;
- long-poll or stream for a job lease;
- heartbeat and extend lease;
- upload evidence;
- submit findings/results;
- complete, fail, or cancel a job.

**Pros:**

- workers need only outbound 443;
- no database or Redis credentials leave the control plane;
- least-privilege per-node and per-job authorization;
- clean fit for third-party or customer-hosted nodes.

**Cons:**

- more engineering work;
- broker protocol, authentication, retries, idempotency, and result ingestion must be
  implemented;
- some queue semantics currently provided by Redis must become explicit product code.

## 6. Recommended Delivery Plan

### Phase 1: Owned Fleet Over Built-In WireGuard

Goal: an operator can attach another VPS to the fleet in minutes and have it consume
scan jobs from the same queue.

Minimum shape:

1. Start the control-plane instance in fleet-control mode.
2. Generate a short-lived worker join token.
3. Create a ShakerScan-managed WireGuard network for the fleet.
4. Bind Redis and Postgres to private overlay addresses only, never to `0.0.0.0`.
5. Run the join command on each worker VPS.
6. The join command registers the node, writes worker-only config, and starts workers:
   no local API, UI, Postgres, or Redis.
7. Point worker `REDIS_URL` and `DATABASE_URL` at the control plane's overlay IP.
8. Pull a digest-pinned scanner image from a trusted registry so all nodes run the same version.
9. Restrict overlay ACLs so worker nodes can reach only the required control-plane ports.

The join command should produce a connection bundle for the worker node:

```text
node_id
control_plane_url
redis_url or broker_url
database_url for Phase 1 overlay mode
evidence_store_url and credentials when enabled
worker_image
desired_worker_count
labels
wireguard_peer_ip
wireguard_public_key
```

This phase proves the multi-host substrate. It is acceptable for a controlled lab or
owned internal fleet, but it is not the full production architecture.

Important limitations in Phase 1:

- the pull-based node-agent applies versioned worker-count and drain desired state on its local Docker
  engine, and the join/install/overlay proof and fleet UI are implemented; physical two-VPS acceptance
  and rolling lifecycle remain incomplete;
- evidence remains incomplete unless storage is centralized;
- Stream lease recovery is implemented, but physical kill/partition acceptance is still pending;
- routing assumes workers are mostly interchangeable.

#### Phase 1 draft vertical-slice specification (Milestone A: two-VPS queue proof)

This is the concrete target shape for Milestone A (§13). It reuses the shipped queue and fan-out
unchanged. The enrollment/bootstrap and durable credential details below are part of the slice, not
follow-up polish; omitting them would leave the advertised one-command join flow unimplementable.
Build order:

**1. `nodes` registry + join tokens (net-new — no node table exists today).** Add to `db/init.sql`
and to the idempotent `run_schema_migrations` path in `api/retest_contract.py`, following the 0.7.0
UPGRADE-01 fail-closed migration pattern (a same-named non-unique index must be dropped before a
unique one is asserted; migrations must fail closed, not silently no-op):

```sql
CREATE TABLE IF NOT EXISTS nodes (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name                 TEXT NOT NULL,
  hostname             TEXT,
  role                 TEXT NOT NULL CHECK (role IN ('control_plane','worker')),
  overlay_ip           INET UNIQUE,
  wireguard_public_key TEXT UNIQUE,
  egress_ip            INET,
  region               TEXT,
  labels               JSONB NOT NULL DEFAULT '{}'::jsonb,
  build_fingerprint    TEXT,
  worker_image_digest  TEXT,
  desired_worker_count INT  NOT NULL DEFAULT 0,
  active_worker_count  INT  NOT NULL DEFAULT 0,
  capacity             JSONB NOT NULL DEFAULT '{}'::jsonb,
  status               TEXT NOT NULL DEFAULT 'joining'
                         CHECK (status IN ('joining','healthy','stale','draining','disabled')),
  drain                BOOLEAN NOT NULL DEFAULT FALSE,
  last_heartbeat_at    TIMESTAMPTZ,
  connection_bundle_delivered_at TIMESTAMPTZ,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS node_join_tokens (
  token_hash  TEXT PRIMARY KEY,           -- store only a hash; the raw token is shown once
  role        TEXT NOT NULL CHECK (role IN ('worker')),
  expires_at  TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,                 -- single-use
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS node_credentials (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  node_id         UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  credential_hash TEXT NOT NULL UNIQUE,       -- hash only; return the raw secret once
  credential_version INT NOT NULL DEFAULT 1,
  expires_at      TIMESTAMPTZ,
  revoked_at      TIMESTAMPTZ,
  last_used_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

Consume a join token with one conditional `UPDATE ... WHERE consumed_at IS NULL AND expires_at >
NOW() RETURNING ...`, then create the node and its credential in the same database transaction. A
concurrent second consumer must receive no row. The API must authenticate heartbeat and lifecycle
calls by hashing the presented node credential and checking expiry/revocation; `node_id` alone is
never authority.

Overlay address allocation is part of that same transaction. It takes a dedicated Postgres
transaction-level advisory lock, reserves the network address, broadcast address, and control-plane
address, and selects the first unused worker address. The database `UNIQUE` constraint remains the
final collision guard. WireGuard public keys are strict base64-encoded 32-byte values and are unique
per node. The control plane persists its private key outside the database with owner-only filesystem
permissions; restart must reuse it, never silently create a new fleet identity.

Each worker reports its `build_fingerprint` on heartbeat so the existing stale-build refusal
(`build_current` / `expected_build_fingerprint_at_submit` / `stale_worker_count_at_submit`) extends to
the fleet: a mixed- or stale-build fleet must stay rejectable, consistent with the DAST-quality rule.

**2. Worker-only deployment contract.** The standalone `worker` service in `docker-compose.yml` still
uses the control plane's service DNS, local build, source mounts, and Redis/Postgres dependencies.
The separate `docker-compose.worker.yml` now provides the remote-node contract: it starts only a
digest-pinned worker image and the pull-based node-agent, has no control-plane services or source
mounts, parameterizes the worker environment through an owner-only file, and labels every container
with its owning node. The installed join workflow still needs to generate that state and environment:

```bash
# worker VPS: worker service only, pointed at the control plane over the overlay
REDIS_URL=redis://<control-plane-overlay-ip>:6379
DATABASE_URL=postgresql://scanner:<password>@<control-plane-overlay-ip>:5432/scanner
EVIDENCE_STORAGE_BACKEND=s3
EVIDENCE_S3_ENDPOINT_URL=http://<artifact-store-overlay-ip>:9000
```

**3. Overlay binding (never expose data stores publicly).** Both Compose variants now separate
`SHAKERSCAN_DATA_BIND_HOST` from the UI/API bind and provide an opt-in `fleet` profile whose
`fleet-edge` listener terminates CA-verified HTTPS on the data address without running duplicate
schedulers. On Linux the edge uses the host network and binds only to the overlay address, preserving
the real socket peer for the one-time bundle gate instead of trusting forwarded headers. The control
plane binds Redis and Postgres to the WireGuard overlay interface only — never `0.0.0.0`.
`SHAKERSCAN_BIND_HOST` continues to control the public API/UI listener; the separate
`SHAKERSCAN_DATA_BIND_HOST` controls Redis/Postgres and the overlay edge. Fleet initialization sets
only the data bind to the control-plane overlay IP, so those ports have no public-interface listener.
Public exposure of 6379/5432 remains a non-goal (§11).

**4. Fleet CLI + pre-overlay bootstrap contract.** These verbs are implemented in `scanner.sh` and
the bounded Linux host provisioner in `scripts/fleet_cli.py`:

```text
shakerscan fleet init [--network wireguard]
    # control plane: create the overlay + control peer, flip data-store bind to the overlay IP, enable fleet mode
shakerscan fleet join-token --role worker --ttl 24h
    # mint a single-use, hashed, expiring token; print the ready-to-paste join command
shakerscan join <control-plane-https-url> --token <join-token>
    # worker VPS: bootstrap over HTTPS, establish the overlay, then start the worker-only profile
```

The worker cannot call an overlay URL before it has an overlay. `join` therefore generates its
WireGuard keypair locally and calls a narrowly exposed `POST /fleet/nodes/join` over an operator-
configured HTTPS control-plane URL. The request carries the raw enrollment token, worker public key,
hostname, and bounded capability summary. In one transaction the endpoint consumes the token,
allocates a unique overlay IP, inserts the node and hashed durable credential, and returns the control
peer information. The worker installs that configuration, proves overlay reachability, and only then
uses the private Redis/Postgres URLs. Plain HTTP is not an enrollment transport.

The API decides transport security from the ASGI request scheme supplied by its trusted listener or
reverse proxy configuration; it does not trust caller-controlled forwarding headers. An explicit
`FLEET_ALLOW_INSECURE_ENROLLMENT=true` escape hatch is permitted only for a loopback/local lab and is
off by default. Production fleet initialization must refuse that setting.

Fleet lifecycle authority is separate from node authority. Join-token creation, credential rotation,
bundle reset, drain, and revoke are accepted from the control-plane loopback listener, or over HTTPS
with an explicit high-entropy `FLEET_OPERATOR_TOKEN`. A node credential can never call those operator
operations. This is required even while the rest of the self-hosted API keeps its trusted-operator,
tokenless CLI model: otherwise any network client that can reach the API could mint its own join
token. Secret-bearing responses set `Cache-Control: no-store`.

`fleet init` persists the control keypair, fleet CA, server certificate, private connection-bundle
JSON, and rendered WireGuard configuration with restrictive modes; refuses an existing fleet CIDR
change; verifies the operator-provided public HTTPS URL; enables the fleet Compose profile; binds the
data stores to the first overlay address; and installs a 10-second systemd peer reconciler. Operators
on Linux systems without systemd can select `--no-reconcile-service` and run `fleet reconcile`
manually. The CLI never silently falls back to plaintext enrollment and production init refuses the
local-lab insecure-enrollment escape hatch.

**5. Bootstrap response + post-overlay connection bundle.** `POST /fleet/nodes/join` returns only
the material needed to establish the overlay plus the one-time node credential (the worker persists
it and never re-uses the enrollment token):

```text
node_id, control_plane_overlay_url, wireguard_overlay_cidr, worker_image_digest, desired_worker_count, labels,
wireguard_peer_ip, wireguard_control_plane_public_key, wireguard_control_plane_endpoint,
node_credential
```

The raw `node_credential`, overlay CIDR, and public fleet CA certificate are returned once over HTTPS, and the
credential is persisted with restrictive filesystem
permissions. It authorizes only node API operations. After installing WireGuard and proving overlay
reachability, the worker calls `POST /fleet/nodes/{id}/connection-bundle` over **overlay HTTPS**, using
that credential. The control plane returns the Phase-1 Redis/Postgres URLs and any artifact-store
credentials once; the response is never available over the public listener and is not logged. Thus
data-store secrets are delivered only after the overlay exists. Rotation and revocation are part of
the node API even if automatic rotation is deferred.

The bundle gate uses the actual socket peer address (`Request.client.host`), never
`X-Forwarded-For`, and requires that address to be inside the configured fleet overlay CIDR. Bundle
consumption is an atomic `UPDATE ... WHERE connection_bundle_delivered_at IS NULL RETURNING ...`; a
retry after a successfully committed response is denied and requires an explicit operator reset or
credential rotation workflow. Neither access logs nor audit payloads may contain the bundle.

**6. Minimal Phase-1 node-agent + fleet view.** The pull-based node-agent is implemented. It keeps
the persisted node credential in an owner-only state file, fetches versioned desired state over
CA-verified HTTPS, reconciles only its own labeled worker containers through the local Docker
socket, drains to zero, and reports capacity, active worker count, image digest, agent version,
applied-state version, and reconciliation errors through `POST /fleet/nodes/{id}/heartbeat`. It has
no inbound listener and clones only an explicit allowlist of worker container settings. The API
supports operator-authenticated desired worker count/drain changes through
`PATCH /fleet/nodes/{id}/state` and node-authenticated reads through the matching `GET`. The join
installer and CA-verified overlay reachability proof are implemented. The Fleet UI and stale-state
presentation are implemented, including current work and state/image drift. Physical two-VPS
acceptance and rolling lifecycle are still incomplete.

**Milestone A done** = a remote worker registers with one command, appears in the fleet view with a
heartbeat, drains the shared `scan_jobs` queue, writes scans/findings to the control-plane database,
and Redis/Postgres are unreachable from the public internet. This is explicitly a **lab proof**, not
an unattended-production claim. The accepted Phase-1 gaps remain: physical multi-host lease/partition
acceptance, worker-local result/checkpoint artifacts even when managed evidence objects use S3 (§8),
and an incomplete rolling lifecycle around the implemented install and per-node scaling primitives.

### Phase 2: Production-Ready Owned Fleet

Goal: operate many owned worker VPSs safely.

Build the fleet layer:

1. **Node registry:** track `node_id`, hostname, overlay IP, egress IP, region, version,
   labels, tool capabilities, capacity, active worker count, desired worker count,
   heartbeat, and drain state.
2. **Node-agent:** the local pull agent, installation, desired-count/drain reconciliation, stale-state
   presentation, and fleet UI are built. Complete rolling upgrades and partition behavior.
   The API never drives a remote Docker socket directly.
3. **Central evidence store:** workers upload screenshots, HAR files, logs, and other
   artifacts to S3/MinIO. Findings and scan results store object keys, not local paths.
4. **Reliable job leases:** **built** with Redis Streams consumer groups, explicit completion ack,
   periodic lease heartbeat, visibility-timeout `XAUTOCLAIM`, bounded attempts, and fail-closed
   cancellation when the worker can no longer prove lease ownership.
5. **Distributed rate limiting:** use Redis token buckets keyed by target/root domain so
   adding worker instances does not accidentally multiply request pressure. Known-endpoint
   ASM/Full Coverage worker batches already reserve endpoint budget this way; standalone scans need
   explicit per-adapter metering quality before any hard distributed-cap claim.
6. **Routing and affinity:** place jobs by labels such as region, egress group,
   private-network reachability, scan tier, or required tools.
7. **Fleet operations:** support drain, disable, rolling image upgrade, version mismatch
   refusal, per-node audit logs, and a fleet-level worker count that can be distributed
   across nodes by capacity.

### Phase 3: HTTPS Broker For Zero-Trust Nodes

Goal: support nodes that should not be trusted with direct control-plane access.

Build a broker API and convert worker communication to job leases over HTTPS. This is the
right architecture for:

- customer-hosted worker instances;
- SaaS or multi-tenant deployments;
- nodes behind unknown NAT/firewall rules;
- environments where direct DB/Redis credentials on workers are unacceptable.

The broker can coexist with the overlay model. Owned nodes may continue to use the
overlay while untrusted nodes use the broker.

### Future Feature: Cloud Fleet Provisioning

Cloud automation is a good future extension, but it should not be built in the first
fleet milestone. The idea is that a user could provide a DigitalOcean, AWS, or similar
cloud credential and ask ShakerScan to create a control-plane VPS plus N worker VPSs,
install ShakerScan on them, connect them with the same fleet join flow, and optionally
destroy or scale the fleet later. This should wait until the core fleet primitives are
solid. The first five primitives are implemented: standalone remains default, `fleet init`, built-in
WireGuard, `fleet join`, and node-agent heartbeat/worker scaling. Evidence storage and safe queue
semantics remain before cloud provisioning.

## 7. Node-Agent Contract

The node-agent is the boundary between fleet scheduling and host-local execution.

Responsibilities:

- register the node and its labels/capabilities;
- exchange a join token for durable per-node identity;
- receive or derive the worker connection bundle;
- heartbeat at a fixed interval;
- report host resources and active worker count;
- pull desired state from the control plane or receive commands over the overlay;
- start/stop local worker containers or processes;
- mark itself draining and stop accepting new work;
- expose local logs/metrics needed for debugging;
- refuse jobs when the local image major version is incompatible.

The implemented foundation uses the preferred pull model: the agent periodically asks the control
plane for versioned desired state and exposes no inbound management port. Registration, overlay and
bundle installation still belong to the pending host CLI; image compatibility refusal and richer
logs/metrics are completed with the rolling-upgrade lifecycle.

Join tokens should be short-lived and preferably single-use. After registration, the
node should use its own node credential, not keep reusing the enrollment token.

Example node labels:

```json
{
  "region": "us-east",
  "egress_group": "standard-pool",
  "network": "public",
  "scan_tiers": ["quick", "standard", "deep"],
  "tools": ["nuclei", "playwright", "sqlmap", "nmap"]
}
```

## 8. Evidence And Artifact Storage

Local `./results` works on one Docker host because the API, workers, and UI see the same
bind mount. It does not work across VMs/VPSs.

Required target state:

- workers upload artifacts to an object store;
- object keys include scan id, shard id when applicable, and artifact type;
- findings store object references rather than local filesystem paths;
- the API signs or proxies downloads for the UI;
- retention policy is enforced centrally;
- failed or canceled shards still upload diagnostic artifacts.

Recommended first implementation: MinIO for self-hosted deployments, using S3-compatible
APIs so cloud S3 can be used later without changing application code.

**Implementation status:** a useful but narrower object-store backend already exists — a hand-rolled
SigV4 S3/MinIO client with content-addressed PUT, hash-verified GET, and retention DELETE
(`evidence_storage.py`). It externalizes large managed `evidence_objects`; small objects remain inline
in Postgres. It does **not** currently own ordinary scan result JSON, checkpoints, cancellation files,
screenshots/HARs, or every diagnostic artifact. On remote-write failure it records the error and
falls back to worker-local `RESULTS_DIR`, which is safe for a single host but is not cross-node
durability. The current Compose file also does not forward the `EVIDENCE_*`/S3 environment into API
and worker services.

Phase 1 must wire the existing settings into the worker deployment and label managed evidence-object
coverage honestly. Production readiness additionally needs a general artifact API/object manifest,
fail-closed proof binding for missing or partial uploads, lifecycle/retention, and signed or proxied UI
downloads. Reusing the SigV4 client reduces this work; it does not make it configuration-only.

Evidence centralization should happen before advertising cross-VM parallel scans as
production-ready. Without it, the logical scan may complete but its report can point at
artifacts stranded on a worker VPS.

## 9. Queue Reliability And Idempotency

**Implementation status:** scan and retest producers now `XADD` JSON payloads to leased Redis Stream
keys. Workers use one consumer group, keep the pending entry alive while executing, acknowledge and
delete only after the handler succeeds, and `XAUTOCLAIM` abandoned work after the visibility timeout.
Delivery attempts come from Redis pending metadata and exhaust into an explicit durable failed state.
If lease refresh fails repeatedly or ownership is gone, the worker cancels its execution rather than
continuing as a stale owner. Existing DB claim predicates, stable shard identity, finding uniqueness,
and atomic merge claim make duplicate/reclaimed dispatch idempotent. Legacy list entries are consumed
only as a rolling-upgrade bridge; all new production enqueue paths use Streams.

Required semantics:

- a job is leased, not destroyed, when a worker starts it;
- the worker heartbeats while the job is active;
- completion explicitly acknowledges the lease;
- stale leases are reclaimed after a visibility timeout;
- retries are bounded and visible;
- duplicate completion attempts are idempotent.

The implemented Redis Streams shape is:

```text
XADD scan_jobs:leased ...
XREADGROUP GROUP shakerscan-workers node-a COUNT 1 BLOCK ...
XACK scan_jobs:leased shakerscan-workers <message-id>
XAUTOCLAIM or XCLAIM stale pending messages
```

For parallel scans, shard jobs should carry stable identity:

```text
parent_scan_id
shard_index
attempt
plan_version
```

The merge step must tolerate retry and duplicate shard completion. Database constraints
and idempotent object keys are part of that contract.

## 10. Routing, Affinity, And Rate Limiting

At first, every worker can consume the same default queue. That is only safe when workers
are homogeneous and have equivalent network reachability.

Production placement needs job labels and node labels.

Common routing labels:

- `region=eu`;
- `egress_group=residential-lab`;
- `network=customer-x-vpn`;
- `tier=aggressive`;
- `requires=playwright`;
- `requires=sqlmap`;
- `data_residency=us`.

Implementation options:

| Option | Fit |
|---|---|
| Queue per capability | Simple and compatible with the current Stream model. Workers can read only streams they qualify for. |
| Redis Streams with routing fields | Current queue substrate; placement fields and scheduler assignment remain to be added. |
| Broker-side scheduler | Best in Phase 3. The broker leases only jobs a node is allowed to run. |

Rate limiting must be global, not per node. Known-endpoint ASM and Full Coverage
batches use Redis token buckets keyed by root domain so local/owned workers do not
multiply endpoint pressure. Standalone enforcing mode now reserves and meters request tokens;
production fleet work still needs live multi-node rate soak before making it the default.

## 11. Security Model

A worker VPS is sensitive. It can hold target credentials, scanner credentials, browser
state, exploit tooling, evidence, and sometimes access to private networks.

Security requirements:

- **Network isolation:** Redis/Postgres are reachable only over the overlay or not
  reachable from workers at all in the broker model.
- **No public data stores:** never expose 6379 or 5432 to the public internet as a normal
  deployment mode.
- **Per-node identity:** use Tailscale identity, WireGuard keys, mTLS certificates, or
  signed node tokens. Avoid one shared fleet secret.
- **Least privilege:** in the overlay model, reduce worker database permissions as much
  as the current code allows. In the broker model, workers should only access their
  leased jobs.
- **Secret delivery:** inject database credentials, API keys, and scan credentials at
  runtime through environment or a secrets manager. Do not bake them into the image.
- **Disposable high-risk nodes:** run aggressive/exploit-tier scans on nodes that can be
  rebuilt frequently and isolated from the control plane.
- **Audit:** record which node, worker version, egress IP, and credential scope ran each
  scan or shard.
- **Egress control:** allow scanner traffic to intended targets, but keep management
  traffic restricted to the control plane and artifact store.

## 12. Component Changes

| Component | Phase 1 | Phase 2+ |
|---|---|---|
| Redis | Bind to overlay only. | Streams, consumer groups, stale lease reclaim, Sentinel/managed Redis if HA matters. |
| Postgres | Bind to overlay only. | Scoped worker role where possible, managed/replicated Postgres if HA matters. |
| API/UI | Stay on control plane. | Add fleet view, node status, drain, placement, and shard rollups. |
| Worker runtime | Worker-only compose/profile on remote VPSs. | Node-agent manages desired/current worker count. |
| Evidence | Temporary local evidence is acceptable only for proof-of-concept. | S3/MinIO object storage required. |
| Image distribution | Private registry with pinned tags. | Rolling upgrade and version compatibility checks. |
| Queue | Shared default queue. | Leases, routing, retry policy, and idempotent shard completion. |
| Rate limiting | Known-endpoint buckets plus opt-in standalone request metering/reservation. | Fleet soak, routing-aware global limits, and enforcing-by-default acceptance. |
| Observability | Per-host logs. | Central logs, metrics, node audit trail, per-node scan attribution. |

## 13. First Milestones

### Milestone A: Two-VPS Queue Proof

Purpose: prove remote workers can consume jobs from the control plane.

Acceptance criteria:

- control plane and one worker VPS are connected over ShakerScan-managed WireGuard;
- control plane can create a short-lived join token;
- worker VPS can join with one command after ShakerScan is installed;
- joined worker instance appears in a fleet/node list with heartbeat and capacity;
- worker instance runs only worker processes;
- worker instance consumes a normal scan job from the shared queue;
- scan state and findings are written to the control-plane database;
- Redis/Postgres are not reachable from the public internet.

Known gaps are acceptable only for this labeled lab proof: incomplete rolling lifecycle,
worker-local general artifacts, and incomplete physical lease/partition acceptance. No unattended or
production-safe claim is allowed.

### Milestone B: Cross-VPS Parallel-Scan Proof

Purpose: prove the related parallel-scan implementation works across hosts.

Acceptance criteria:

- `parallel: true` creates parent, shard, and merge jobs;
- shard jobs are executed by workers on at least two VPSs;
- parent scan status/progress rolls up child shard status;
- findings dedupe correctly under concurrent shard writes;
- merge creates one logical report.

This should not be called production-ready until centralized evidence and physical cross-node lease
recovery acceptance are in place.

### Milestone C: Production Owned Fleet

Purpose: make the overlay-based fleet operationally safe.

Acceptance criteria:

- node registry and node-agent exist;
- API can scale and drain individual nodes;
- evidence is centralized in S3/MinIO;
- queue has ack/reclaim semantics;
- distributed target rate limiting is active;
- jobs can be routed by region/reachability/tier;
- node/version/egress attribution is visible in scan records.

## 14. Open Decisions

| Decision | Recommendation |
|---|---|
| Overlay first or broker first? | Built-in WireGuard overlay first for owned nodes; broker later for untrusted/customer-hosted nodes. |
| Tailscale or WireGuard? | Built-in WireGuard by default for the copy/paste VPS workflow; Tailscale remains optional for operators who already use it. |
| Self-hosted or managed data stores? | Self-host for early internal deployments; managed Postgres/Redis when HA or operational maturity matters. |
| MinIO or cloud S3? | MinIO for self-hosted; S3-compatible API either way. |
| Node-agent or orchestrator first? | Node-agent first. Revisit Nomad, Docker Swarm, or Kubernetes when fleet size and rollout complexity justify it. |
| Queue list or Streams? | **Resolved: Streams.** Lists are read only as an upgrade bridge; all new jobs use leased Streams. |

## Final Recommendation

Begin the post-0.7 multi-node initiative in layers, while keeping DAST/auth quality and execution
contracts as acceptance gates:

1. **Labeled lab proof:** physically prove one digest-pinned remote worker can join, heartbeat, and
   drain the shared leased queue over the implemented HTTPS-to-WireGuard bootstrap. Preserve the
   documented worker-local-artifact limitation; a shared Redis/Postgres deployment alone is not a
   production claim.
2. **Owned-fleet hardening before unattended use:** complete physical lease/fencing acceptance,
   centralized general artifacts,
   executing-node scope revalidation, node-agent lifecycle management, drain/reschedule, partition
   and clock-skew tests, per-adapter budget telemetry, and routing.
3. **Later:** add the HTTPS broker for untrusted or customer-hosted nodes. That is the
   correct zero-trust architecture, but it is more work than needed for the first owned
   multi-VPS fleet.
---
