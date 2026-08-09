# Multi-Node Architecture

**Status:** Design authority + implementation complete; 0.8.9 broker physical-acceptance renewal pending. The fan-out
substrate is shipped (see the code-grounded capability table below), and the durable node identity,
bounded enrollment, authenticated heartbeat, and one-time connection-bundle API foundation is now
implemented. The digest-pinned worker-only Compose runtime, pull-based node-agent, and versioned
desired-state API are also implemented, along with the fleet-profile CA-verified overlay TLS listener.
The Linux `fleet init` / `fleet join-token` / `join` WireGuard and HTTPS-broker host workflows are
implemented, including automatic restricted public HTTPS for broker control planes. Durable
per-scan worker/node attribution, current-vs-desired node drift derivation, fleet summary, and recent
per-node activity APIs are implemented. The Fleet operations UI is implemented with health/drift,
separate local/remote capacity, current-work, per-node scaling, drain/resume, and revoke controls.
Scan submission exposes automatic, control-plane-local, remote-fleet, and specific-remote-node execution location.
A prior exact candidate passed a two-node HTTPS-broker deployment's non-destructive topology/storage/lease preflight,
digest-pinned cross-node execution with centralized results and artifacts, and destructive physical
worker-loss/reclaim acceptance. Because 0.8.9 changes Fleet lease polling, that receipt is historical
and must be renewed on the frozen 0.8.9 SHA before publication. WireGuard physical acceptance is deferred, so WireGuard remains preview code
and is explicitly outside the 0.8.9 supported deployment boundary. Redis Stream
lease/heartbeat/ack/reclaim delivery is implemented. The
general artifact manifest, deterministic result/checkpoint/diagnostic upload, referenced screenshot
centralization, hash-verified proxy download, cross-node stale recovery, fleet-worker fail-closed
persistence, centralized retry-safe retention, and a digest-pinned self-hosted MinIO profile are implemented. Capability/region/egress placement
and enforceable fleet-wide admission/request limits are implemented. Graceful drain and digest-pinned
one-at-a-time worker image rollout are implemented. The outbound-only Phase-3 HTTPS broker, thin
worker runtime, broker enrollment, lease/result/artifact protocol, and control-plane ingestion are
implemented. Capacity-weighted fleet-wide scaling, immutable execution-context snapshots, and
durable per-node lifecycle events are implemented. The broker path is the 0.8.9 production
candidate; its exact-SHA acceptance gate remains mandatory. WireGuard remains outside that supported boundary.
**Scope:** run a coordinated ShakerScan fleet across multiple VMs/VPS hosts so one UI/API
can scan more targets at once and run high-budget Full Coverage scans by using workers
from many machines.
**Operator guide:** [multi-node-guide.md](multi-node-guide.md).
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
| Fleet-wide and per-parent concurrency leases plus request telemetry | **Built and fleet-enforceable** — joined nodes fail closed when Redis cannot authorize a slot or the bounded wait expires. Parent shard slots are stable job-ID ZSET leases, refreshed with the worker heartbeat and safely reacquired after worker loss. Standalone installs retain compatibility fail-open behavior unless enforcement is explicitly enabled. Request-meter receipts include adapter-level attempted/completed/retried/rejected/successful counters and distinguish actual budget exhaustion from intentional blocking of an unmetered network tool. | `ACTIVE_SCAN_SLOTS_KEY`, `_take_scan_slot`, `_try_acquire_parallel_shard_slot`, `_fleet_limits_required` (`worker.py`); `RequestMeter.snapshot` |
| Per-root-domain request reservation (atomic Redis Lua; already coordinates every process on the shared Redis) | **Built** | `reserve_domain_rate` (`asm_inventory.py`) |
| Central artifact plane | **Built** — Compose forwards S3 settings and includes a digest-pinned MinIO profile that `fleet init` configures with generated credentials unless external S3 is already complete. Result JSON, live checkpoints, terminal diagnostics, and bounded referenced screenshots/files use deterministic keys plus a durable `scan_artifacts` manifest. Joined nodes fail closed when required upload/manifest persistence fails; the API hash-verifies proxy downloads, stale recovery reads remote checkpoints, one control-plane sweeper enforces retention, and fleet init requires a real PUT/GET/DELETE probe. | `artifact_storage.py`; `worker.py` `persist_result_artifact`, `_mirror_checkpoint`; `scan_artifact_retention_runner`; `GET /scans/{id}/artifacts` |
| Job-queue delivery | **Built with leased delivery** — Redis Streams consumer groups, explicit ack/delete after successful dispatch, lease heartbeats, visibility-timeout reclaim, bounded delivery attempts, and fail-closed execution cancellation when lease ownership/heartbeat authority is lost. Pre-upgrade list entries remain drainable. | `job_queue.py`; `worker.py` `_run_job_under_lease` |
| Remote worker scaling and rolling lifecycle | **Built per node** — the control plane changes versioned desired count/drain/image state; workers fail closed on drain before leasing and publish host-visible busy markers while executing; the pull agent waits a race-closure grace period, preserves busy workers, starts each digest-pinned successor before stopping its idle predecessor, and resumes scheduling only after the final image-confirming heartbeat. | `PATCH /fleet/nodes/{id}/state`; `worker.py` `_fleet_node_accepts_work`, `_fleet_busy_marker`; `fleet_agent.py` `drain_workers`, `rollout_worker_once` |
| Node identity, enrollment, join tokens, heartbeat, credential rotation/revocation, CA bootstrap, overlay TLS edge, `nodes` table | **Foundation built and broker-tested on two VPSs** — broker fault injection is the 0.8.9 release gate; WireGuard physical acceptance is separately deferred | `fleet.py`; `/fleet/*`; `fleet-edge`; `nodes`, `node_join_tokens`, `node_credentials` |
| Worker-only deployment and pull-based node-agent | **Built for owned-fleet lifecycle** — digest-pinned worker/agent-only Compose, owner-only local state, versioned desired state, local Docker reconciliation, graceful drain-to-zero, rolling image replacement, capacity/error heartbeat | `docker-compose.worker.yml`; `fleet_agent.py`; `GET|PATCH /fleet/nodes/{id}/state` |
| WireGuard/CLI host provisioning | **Built preview; excluded from 0.8.9 production support pending separate physical two-VPS acceptance** — aggregated preflight before mutation, tag-to-digest image resolution, route/port collision checks, automatic standalone backup, persistent identity, CA/server certificates, overlay/data binding, automatic or explicitly manual peer reconciliation, actionable TLS/handshake diagnostics, public HTTPS enrollment, overlay proof, one-time bundle persistence, worker-only startup | `scripts/fleet_cli.py`; `scanner.sh fleet`; `scanner.sh join` |
| Per-node execution attribution and fleet rollup | **Built** — scan/shard rows record the executing node and unique worker replica; revoked nodes fail closed and re-enqueue refused work; node API derives state/image drift and exposes recent activity | `scans.executing_node_id`; `worker.py` `_attribute_job_execution`; `GET /fleet/nodes`; `GET /fleet/nodes/{id}/activity` |
| Fleet-wide scaling and node audit trail | **Built** — one operator request distributes an exact worker total across healthy schedulable nodes using reported CPU/worker weights and optional per-node caps. State changes, join, credential rotation, bundle delivery, heartbeat transitions, rollout completion, broker leases/results, and revocation create bounded credential-free node events. Every scan snapshots node, worker build/image, egress, transport, and credential scope at execution time. | `POST /fleet/scale`; `fleet.py` `distribute_worker_count`; `GET /fleet/nodes/{id}/events`; `fleet_node_events`; `scans.execution_context` |
| Fleet UI | **Built** — host-aware, opt-in visibility hides Fleet navigation, remote counts, and remote placement on standalone installs; direct macOS visits explain the Linux boundary and direct uninitialized Linux visits show setup guidance. Enabled control planes get unified remote-node health/capacity/drift (including an explicit derived unhealthy state for a heartbeating node with reconciliation errors and a first-WireGuard-connection warning), separate local/remote/total available-worker capacity, recent attributed work, desired remote-worker scaling, graceful drain/resume, digest-pinned rollout, revoke confirmation, placement labels, and session-only remote operator credential handling. | `fleet_feature_state`; `ui/src/app/fleet/page.tsx`; `GET /health`/`GET /workers` `fleet`; `GET /workers` `execution_capacity`; sidebar `/fleet` |
| Capability/region/egress placement | **Built** — scan options accept normalized placement constraints; jobs enter deterministic capability Streams; workers dynamically subscribe only to routes matching their node/region/network/residency/tier/tool labels. `node_scope=remote` selects any eligible joined node, `node_id=local` selects control-plane workers, and a Fleet UUID selects any healthy replica on that remote node. Broker-side leasing and overlay workers share the same remote-scope and canonical-node identity, so selection is transport-neutral. Equivalent eligible workers retain normal lease failover. Fleet join persists labels and the UI exposes Automatic, Control plane, Remote fleet, exact-node selection, and advanced constraints. | `job_queue.py` `routed_queue_name`, `qualified_route_queues`; `ScanOptions.placement`; `_broker_node_labels`; `_worker_placement_labels`; `/scan/new`; `/fleet` |
| HTTPS broker for zero-trust nodes | **Built** — `--transport broker` enrolls an outbound-only node without WireGuard, Redis, PostgreSQL, or object-store credentials. Automatic HTTPS mode can provision a digest-pinned Caddy gateway with public-CA certificate renewal, a worker-route allowlist, post-start isolation checks, and rollback. Node/job-scoped HTTPS leases use hashed single-job tokens, Stream ownership heartbeat/reclaim, bounded delivery, global admission and root-domain reservations, progress/log forwarding, cancellation, lease-bound proxy artifact uploads, immutable result hashes, and idempotent control-plane ingestion for normal and shard scans. | `broker_worker.py`; `docker-compose.broker-worker.yml`; `fleet-gateway`; `/fleet/broker/*`; `broker_job_leases`; `broker_job_results` |
| Physical acceptance automation | **Built; 0.8.9 broker acceptance renewal pending on remote Linux nodes** — an older exact-SHA receipt proves digest-pinned execution and physical worker-loss/reclaim, but it cannot qualify the Fleet lease change in this candidate. WireGuard topology has a separate future gate. One command validates node/current-image health, heartbeat/capacity, artifact-store writes, public Redis/PostgreSQL isolation, an isolated Redis server-time lease loss/reclaim/heartbeat/ack sequence, duplicate completion behavior, bounded passive cross-node parallel shards, execution snapshots, finding dedupe, and central result/artifact manifests. The acceptance-specific parent ceiling stays below the default hourly domain reservation while leaving the domain-rate gate enabled. It emits a content-free hashed receipt. | `shakerscan fleet accept`; `scripts/fleet_acceptance.py`; `tests/test_fleet_acceptance.py` |

The takeaways that shape the plan:

- **Do not rebuild** the fan-out, merge-once, finding dedup, active-scan semaphore, or the domain-rate
  primitive. They coordinate through shared Redis. `reserve_domain_rate` fails **closed** (grants 0
  on a Redis error), and joined nodes now also fail closed when the active-scan semaphore cannot
  authorize work. Standalone installs retain the historical fail-open admission fallback.
- **Do not bypass the artifact manifest with worker-local paths.** Managed evidence objects and the
  general result/checkpoint/diagnostic plane now share the S3-compatible store; the database manifest
  and hash-verified proxy are the supported cross-node contract (§8).
- The node identity/enrollment/overlay and leased/acked/reclaimable queue are now implemented. The
  complete digest-pinned broker scan and failure-injection matrix passed on an older exact candidate;
  0.8.9 must renew it because lease polling changed. WireGuard is deliberately deferred rather than
  represented as accepted.

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
4. **Use the HTTPS broker for the supported topology.** Workers never receive database, Redis, or
   object-store credentials; they lease jobs, heartbeat, upload evidence, and submit results
   through a narrow API.
5. **Keep built-in WireGuard as an unpromoted owned-infrastructure option.** Its implementation is
   present, but it remains preview until its independent physical topology matrix passes.
6. **Multi-node composes with the parallel-scan work, which has shipped.** Intra-target
   fan-out (`scan_plan -> scan_shard -> scan_merge`, plus the `scope`/`family`/`coverage`
   strategies) is implemented today — see `docs/dast-asm-architecture.md`. Shard jobs are
   leased messages on the shared `scan_jobs` Redis Stream, so any qualified fleet worker that consumes that
queue already runs shards of one logical scan; the merge reconciles regardless of which node
   ran each shard. Multi-node therefore adds *capacity* (more workers draining the same shard
   queue → more concurrent shards, so `coverage` fan-outs finish faster); it does not change the
   orchestration. The transport/trust substrate is now implemented in both owned-overlay and
   outbound-only broker forms. This is important for the
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

# On each additional VPS (join retires the installer's standalone services and preserves its volumes)
curl -fsSL https://install.shakerscan.com | sh
shakerscan join <control-plane-url> --token <join-token>

# Or, for an outbound-only node that receives no shared-store credentials
shakerscan fleet init --network broker --public-url https://scanner.example.com
shakerscan fleet join-token --role worker --ttl 24h --transport broker
shakerscan join <control-plane-url> --token <join-token> --transport broker

# Optional controlled rollout: one expiring command, exactly five successful enrollments
shakerscan fleet join-token --role worker --ttl 1h --max-uses 5 --transport broker
# Revoke unused capacity after the rollout
shakerscan fleet revoke-join-token <token-id>
```

Those commands are implemented product workflows.

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
          Built-in WireGuard or outbound HTTPS broker
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
| Worker scaling | Local `POST /workers` scales only control-plane workers; fleet desired state scales/drains each remote node through its pull agent. `GET /workers.execution_capacity` reports local, remote, and total running/available capacity without changing the local `count` compatibility field. | Graceful rolling image rollout and capacity-weighted aggregate remote-fleet count distribution are built; UI controls label the two scopes separately. |
| Evidence | Standalone retains `./results`; fleet workers upload to S3/MinIO and commit a durable manifest before completion. | The control plane can proxy artifacts from every node without a shared filesystem. |
| Queue reliability | Stream messages remain pending while leased, heartbeat during execution, are acknowledged only after successful dispatch, and are reclaimed after owner loss. | The acceptance runner automates isolated loss/reclaim and duplicate completion; it must still be executed on the release fleet for a physical production claim. |
| Networking | The local stack binds API/UI to the configured host; remote mode already parameterizes public/private bind addresses. | Built-in WireGuard is the default owned-fleet overlay; fleet init binds Redis/Postgres privately and acceptance verifies their public ports are closed. |

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
Joined workers turn the compatibility request-meter default into enforcement and use shared
root-domain request-token reservation. A broker job deferred by an exhausted domain budget remains
pending with the explicit `waiting_for_request_budget` phase instead of appearing stuck with no
reason. Operators retain the explicit `request_budget_mode=off`
override for authorized local labs and other intentionally unrestricted targets. Standalone scans
retain compatibility mode by default.

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

**Implementation status:** built. `shakerscan join <url> --token <token> --transport broker`
persists only the node credential, public HTTPS URL, image digest, and optional CA path. Its dedicated
Compose file contains a thin broker worker plus the pull node-agent and contains no Redis/PostgreSQL
environment keys. The control plane leases only direct scan/shard execution; plan and merge jobs stay
on database-connected owned workers. Each executable lease receives a distinct hashed server-side
token, owns the underlying Stream entry, refreshes both Stream authority and the global active-scan
slot, and carries a server-side root-domain request reservation. Managed credentials are decrypted
only into that one no-store lease response. Referenced local files, checkpoints, and failure
diagnostics upload through a lease-bound API; object-store credentials never leave the control plane.
Result submission is content-hashed, idempotent, and enters a dedicated ingestion Stream so existing
scan/shard finalization, finding dedupe, manifests, and merge reconciliation remain authoritative.

**Pros:**

- workers need only outbound 443;
- no database or Redis credentials leave the control plane;
- least-privilege per-node and per-job authorization;
- clean fit for third-party or customer-hosted nodes.

**Costs:**

- the control plane owns additional broker lease/result state and ingestion work;
- public HTTPS availability gates zero-trust workers;
- owned-overlay workers remain the lower-overhead option when shared-store credentials are acceptable.

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

- the pull-based node-agent applies versioned worker-count, graceful drain, and image-rollout desired
  state on its local Docker engine, and the join/install/overlay proof and fleet UI are implemented;
  the implementation is complete; run the physical acceptance command below on two VPSs;
- `fleet init` enables private MinIO with generated credentials by default, or validates a configured external S3 store;
- Stream lease recovery and its deterministic loss/reclaim probe are implemented; a release receipt
  from the actual physical fleet is still pending;
- the HTTPS broker boundary for untrusted nodes is not part of Phase 1.

#### Phase 1 implemented vertical-slice contract (Milestone A: two-VPS queue proof)

This is the concrete target shape for Milestone A (§13). It reuses the shipped queue and fan-out
unchanged. The enrollment/bootstrap and durable credential details below are part of the slice, not
follow-up polish; omitting them would leave the advertised one-command join flow unimplementable.
Build order:

**1. `nodes` registry + join tokens.** Implemented in `db/init.sql`
and the idempotent `run_schema_migrations` path in `api/retest_contract.py`, following the 0.8.9
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
  rollout_in_progress  BOOLEAN NOT NULL DEFAULT FALSE,
  last_heartbeat_at    TIMESTAMPTZ,
  connection_bundle_delivered_at TIMESTAMPTZ,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS node_join_tokens (
  token_hash  TEXT PRIMARY KEY,           -- store only a hash; the raw token is shown once
  token_id    UUID NOT NULL UNIQUE,        -- non-secret operator handle for revocation/audit
  role        TEXT NOT NULL CHECK (role IN ('worker')),
  transport   TEXT NOT NULL CHECK (transport IN ('overlay', 'broker')),
  expires_at  TIMESTAMPTZ NOT NULL,
  max_uses    INTEGER NOT NULL DEFAULT 1,
  use_count   INTEGER NOT NULL DEFAULT 0,
  last_used_at TIMESTAMPTZ,
  revoked_at  TIMESTAMPTZ,
  consumed_at TIMESTAMPTZ,                 -- set when exhausted or revoked
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

Consume a join-token use with one conditional `UPDATE ... SET use_count = use_count + 1 WHERE
revoked_at IS NULL AND use_count < max_uses AND expires_at > NOW() RETURNING ...`, then create the
node and its credential in the same database transaction. The default `max_uses = 1` preserves the
single-use workflow; a bounded higher value supports controlled parallel rollouts. Atomic updates
must prevent concurrent consumers from exceeding the cap. New tokens are bound to their intended
transport so a broker enrollment secret cannot be upgraded into an overlay credential exchange.
The API must authenticate heartbeat and lifecycle
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
REDIS_URL=redis://:<generated-password>@<control-plane-overlay-ip>:6379
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
Before making that bind non-loopback, `fleet init` generates owner-only Redis/Postgres credentials,
rotates an initialized Postgres role through stdin, enables Redis authentication, and writes only
credentialed URLs to the one-time connection bundle. Strong operator-provided URL-safe passwords
are preserved. Standalone/local-lab startup also generates owner-only random Redis/Postgres
credentials and migrates the historical Postgres default before startup; Compose has no known
password fallback. The data bind remains loopback unless the operator deliberately changes it.
Public exposure of 6379/5432 remains a non-goal (§11).

**4. Fleet CLI + pre-overlay bootstrap contract.** These verbs are implemented in `scanner.sh` and
the bounded Linux host provisioner in `scripts/fleet_cli.py`:

```text
shakerscan fleet init [--network wireguard]
    # control plane: create the overlay + control peer, flip data-store bind to the overlay IP, enable fleet mode
shakerscan fleet join-token --role worker --ttl 24h [--max-uses N]
    # mint a hashed, expiring, usage-bounded token; print the ready-to-paste join command
shakerscan fleet revoke-join-token <token-id>
    # revoke every unused enrollment from that token without presenting its raw secret
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

Fleet lifecycle authority is separate from node authority. Fleet initialization generates and
persists a high-entropy `FLEET_OPERATOR_TOKEN`. Node listing/activity/events, join-token creation,
credential rotation, bundle reset, scaling, drain, image rollout, and revoke accept either a request
whose actual socket peer is loopback or that bearer token. A loopback Docker host publish is not
treated as proof that a Docker-network caller is local; those calls still need the token. Remote
operator calls additionally require HTTPS. A node credential can never call operator operations.
Secret-bearing responses set `Cache-Control: no-store`. An authenticated operator remains free to
roll out any syntactically valid digest-pinned worker image; authentication, audit events, and exact
digest enforcement are the security boundary rather than a repository policy imposed by ShakerScan.

The connection bundle is deliberately one-shot. If a node fails after delivery but before its
owner-only bundle file is durable, revoke that incomplete node, mint a fresh enrollment token,
and run `shakerscan join` again. Do not weaken the delivery gate or copy a shared bundle by hand.

`fleet init` first runs the same aggregated checks exposed by read-only `fleet preflight`: Linux and
host dependencies, Docker Compose, public HTTPS or managed-gateway prerequisites, worker
tag-to-digest resolution, requested
port availability, overlay route collisions, enrollment policy, and reconciliation support. A
running standalone deployment is backed up before the first fleet mutation. It then persists the control keypair, fleet CA, server certificate, private connection-bundle
JSON, generated operator token, and rendered WireGuard configuration with restrictive modes; refuses an existing fleet CIDR
change; verifies the operator-provided public HTTPS URL; enables the fleet Compose profile; binds the
data stores to the first overlay address; and installs a 10-second systemd peer reconciler. Operators
on Linux systems without systemd can select `--no-reconcile-service` and run `fleet reconcile`
manually; the join-token output reminds those operators and the API/UI flag overlay nodes awaiting
their first connection. The CLI never silently falls back to plaintext enrollment and production init refuses the
local-lab insecure-enrollment escape hatch.

For a broker fleet, HTTPS mode defaults to automatic. A healthy existing HTTPS origin is reused. If
none is reachable, fleet init verifies DNS and TCP 80/443, enables a digest-pinned Caddy profile,
generates a route-restricted configuration, and lets Caddy obtain and renew the public certificate.
The public gateway permits only `/health`, bounded join, authenticated node state/heartbeat, and
authenticated `/fleet/broker/*` operations; it returns 404 for the UI and operator API. Public
health is a content-minimal projection. A generated owner-only secret authenticates Caddy's HTTPS
signal to the API without trusting forwarded headers from workers or the whole Docker network.
Preflight and post-restart acceptance require a credential-free protected-route probe to return 401;
public health, the denylist, and artifact writes are also verified. Enrollment attempts are bounded
per source through Redis. Any failure restores the prior
environment and gateway configuration and restarts the previous runtime.

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
permissions. It authorizes only node API operations. Join verifies public HTTPS before consuming the
bounded enrollment token. After installing WireGuard and proving overlay
reachability, the worker calls `POST /fleet/nodes/{id}/connection-bundle` over **overlay HTTPS**, using
that credential. The control plane returns the Phase-1 Redis/Postgres URLs and any artifact-store
credentials once; the response is never available over the public listener and is not logged. Thus
data-store secrets are delivered only after the overlay exists. Rotation and revocation are part of
the node API even if automatic rotation is deferred.

Node state records an explicit TLS trust mode. Overlay agents require the enrolled fleet CA file;
they never fall back to the system store when that file is missing. Broker workers use the system CA
store for the normal public CA-valid endpoint, or a caller-supplied private CA persisted by
`shakerscan join --ca-cert /path/to/ca.pem`. Both the broker worker and its node agent consume the
same trust policy and surface missing or conflicting CA configuration before making a request.

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
presentation are implemented, including current work, state/image drift, and digest-pinned rollout.
Workers stop leasing before drain, publish busy markers for active work, and the agent replaces one
idle worker per pass by starting its successor first. Physical two-VPS acceptance remains incomplete.

**Milestone A done** = a remote worker registers with one command, appears in the fleet view with a
heartbeat, drains the shared `scan_jobs` queue, writes scans/findings to the control-plane database,
and Redis/Postgres are unreachable from the public internet. This is explicitly a **lab proof**, not
an unattended-production claim. The accepted Phase-1 gaps remain physical multi-host lease/partition
acceptance. General artifacts and owned-node rolling lifecycle are no longer accepted gaps.

### Phase 2: Production-Ready Owned Fleet

Goal: operate many owned worker VPSs safely.

Build the fleet layer:

1. **Node registry:** track `node_id`, hostname, overlay IP, egress IP, region, version,
   labels, tool capabilities, capacity, active worker count, desired worker count,
   heartbeat, and drain state.
2. **Node-agent:** the local pull agent, installation, desired-count/graceful-drain reconciliation,
   one-at-a-time digest rollout, stale-state presentation, and fleet UI are built. Physical partition
   behavior remains an acceptance task.
   The API never drives a remote Docker socket directly.
3. **Central evidence store:** workers upload screenshots, HAR files, logs, and other
   artifacts to S3/MinIO. Findings and scan results store object keys, not local paths.
4. **Reliable job leases:** **built** with Redis Streams consumer groups, explicit completion ack,
   periodic lease heartbeat, visibility-timeout `XAUTOCLAIM`, bounded attempts, and fail-closed
   cancellation when the worker can no longer prove lease ownership.
5. **Distributed rate limiting:** **built for the fleet execution boundary.** Redis token buckets
   are keyed by target/root domain, joined workers enforce standalone request budgets by default,
   and active-scan admission fails closed on joined-node partitions. Operators can explicitly turn
   request metering off for authorized local labs.
6. **Routing and affinity:** **built.** Deterministic capability Streams place jobs by region,
   egress group, private-network reachability, scan tier, data residency, node, and required tools.
   The reserved `local` node identity selects control-plane workers; remote UUID selection retains
   replica failover within the selected node and works identically for broker and overlay transport.
7. **Fleet operations:** **built.** Drain, disable, rolling image upgrade, version mismatch
   refusal, per-node audit logs, and a fleet-level worker count distributed across healthy nodes by
   reported capacity are available through the API and Fleet UI.

### Phase 3: HTTPS Broker For Zero-Trust Nodes — Implemented

Goal: support nodes that should not be trusted with direct control-plane access.

The broker API and outbound-only worker communication use job leases over HTTPS. This is the
right architecture for:

- customer-hosted worker instances;
- SaaS or multi-tenant deployments;
- nodes behind unknown NAT/firewall rules;
- environments where direct DB/Redis credentials on workers are unacceptable.

The broker coexists with the overlay model. Owned nodes may continue to use the overlay while
untrusted nodes use the broker. Control-plane orchestration jobs remain local; executable normal and
shard scans can run over either transport.

### Future Feature: Cloud Fleet Provisioning

Cloud automation is a good future extension, but it should not be built in the first
fleet milestone. The idea is that a user could provide a DigitalOcean, AWS, or similar
cloud credential and ask ShakerScan to create a control-plane VPS plus N worker VPSs,
install ShakerScan on them, connect them with the same fleet join flow, and optionally
destroy or scale the fleet later. This should wait until the core fleet primitives are
solid. The core primitives are implemented: standalone remains default, `fleet init`, built-in
WireGuard, `fleet join`, node-agent heartbeat/worker scaling, leased queue delivery, and centralized
artifacts, placement, rolling lifecycle, and the HTTPS broker. Physical fleet acceptance remains
before cloud provisioning.

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
- mark itself draining, stop accepting new work, and preserve busy workers until completion;
- expose local logs/metrics needed for debugging;
- refuse jobs when the local image major version is incompatible.

The implementation uses the preferred pull model: the agent periodically asks the control
plane for versioned desired state and exposes no inbound management port. Registration, overlay, and
bundle installation are implemented in the host CLI. Digest-pinned image rollout is versioned and
observable. Heartbeats centralize bounded capacity, worker count, image, version, egress, and error
state; meaningful transitions are durable audit events, and broker scan logs stream to the central
scan log. Full arbitrary host-log aggregation remains outside the trust-minimized node-agent scope.

Join tokens are short-lived and usage-bounded; single-use remains the default. A controlled rollout
may set `max_uses` to the exact worker count and revoke remaining uses by non-secret token ID. Each
successful registration receives its own rotatable node credential and does not retain or reuse the
enrollment token.

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

**Implementation status:** the reusable hand-rolled SigV4 S3/MinIO client now backs both managed
`evidence_objects` and the general `scan_artifacts` manifest. Result JSON, live atomic checkpoints,
terminal scanner diagnostics, and bounded worker-local screenshot/file references are uploaded under
deterministic `scan-id/shard/artifact-type` keys before terminal job acknowledgement. Referenced
paths are rewritten to manifest-bound API URLs. The API lists manifests, proxies downloads only
after SHA-256 verification, and recovers stale scans from a remote checkpoint when the worker-local
mount is unavailable. All Compose variants forward the S3 settings, artifact-specific settings may
override them, and joined nodes require remote storage by default. Standalone mode deliberately
retains local `/results` compatibility. The control plane assigns conservative per-type expiry and
claims/deletes/tombstones expired objects with stale-claim recovery; zero days explicitly keeps a
type forever. `fleet init` enables digest-pinned MinIO with generated owner credentials and a private
overlay bind unless a complete external S3 configuration already exists; initialization does not
succeed until PUT/GET/DELETE passes. Reusing the SigV4 client reduces the work; it does not make it
configuration-only.

Evidence centralization should happen before advertising cross-VM parallel scans as
production-ready. Without it, the logical scan may complete but its report can point at
artifacts stranded on a worker VPS.

## 9. Queue Reliability And Idempotency

**Implementation status:** scan and retest producers now `XADD` JSON payloads to leased Redis Stream
keys. Workers use one consumer group, keep only their own pending entry alive while executing,
atomically acknowledge/delete after the handler succeeds, and `XAUTOCLAIM` abandoned work after the
visibility timeout. The ownership check and idle refresh execute in one Redis script, so a stale
worker cannot steal a lease back after another worker reclaims it.
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

For parallel scans, shard jobs carry stable identity:

```text
parent_scan_id
shard_index
attempt
plan_version
```

The merge step tolerates retry and duplicate shard completion through database constraints,
stable shard identities, a merge claim, and idempotent object keys.

## 10. Routing, Affinity, And Rate Limiting

At first, every worker can consume the same default queue. That is only safe when workers
are homogeneous and have equivalent network reachability.

Production placement uses job labels and node labels.

Common routing labels:

- `node_id=local` (control-plane workers);
- `node_id=<fleet UUID>` (one remote node);
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
| Redis Streams with routing fields | **Implemented.** Producers atomically register and enqueue to a deterministic Stream for each normalized constraint set; matching workers discover and subscribe to it. Submissions reject constraint sets that no active enrollment can satisfy. Empty routes and their requirement metadata are removed after drain, stale worker snapshots cannot recreate orphan streams, and the live registry is capped by `SHAKERSCAN_QUEUE_ROUTE_MAX` (default 512, configurable through 4096). Capacity exhaustion returns an actionable HTTP 429 rather than an internal error. |
| Broker-side scheduler | Best in Phase 3. The broker leases only jobs a node is allowed to run. |

Rate limiting is global, not per node. Known-endpoint ASM and Full Coverage batches use Redis
token buckets keyed by root domain so local/owned workers do not multiply endpoint pressure. Joined
workers enforce request metering by default and fail closed if active-scan admission cannot be
authorized. Explicit `off` remains an operator-controlled escape hatch; physical multi-node rate
soak is still an acceptance task, not an implementation gap.

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
  scan or shard. This is persisted as the immutable-at-dispatch `scans.execution_context` snapshot;
  node lifecycle actions are stored separately in `fleet_node_events`.
- **Egress control:** allow scanner traffic to intended targets, but keep management
  traffic restricted to the control plane and artifact store.

## 12. Component Changes

| Component | Phase 1 | Phase 2+ |
|---|---|---|
| Redis | Bind to overlay only. | Streams, consumer groups, stale lease reclaim, Sentinel/managed Redis if HA matters. |
| Postgres | Bind to overlay only. | Scoped worker role where possible, managed/replicated Postgres if HA matters. |
| API/UI | Stay on control plane. | Fleet view, node status, graceful drain, digest rollout, placement, and shard attribution are built. |
| Worker runtime | Worker-only compose/profile on remote VPSs. | Node-agent manages desired/current worker count. |
| Evidence | Temporary local evidence is acceptable only for proof-of-concept. | S3/MinIO object storage required. |
| Image distribution | Private registry with pinned tags. | Rolling upgrade and version compatibility checks. |
| Queue | Shared default queue. | Leases, routing, retry policy, and idempotent shard completion are built. |
| Rate limiting | Known-endpoint buckets plus standalone compatibility request metering/reservation. | Joined nodes enforce global admission/request limits by default; physical fleet soak remains. |
| Observability | Per-host logs. | Heartbeat metrics, transition/error events, broker scan logs, node audit trail, and execution-context scan attribution are built. |
| Zero-trust worker transport | Not required for owned overlay nodes. | HTTPS lease/heartbeat/artifact/result broker is built; nodes receive no Redis/PostgreSQL/object-store credentials. |

## 13. First Milestones

Run the acceptance matrix from the control plane after two real VPS nodes are healthy and current:

```bash
shakerscan fleet accept \
  --api-url https://scanner.example.com \
  --public-host scanner.example.com \
  --node-id <worker-a-node-id> \
  --node-id <worker-b-node-id> \
  --fault-node-id <worker-a-node-id> \
  --fault-node-ssh root@worker-a.example.com \
  --target https://authorized-lab.example.test \
  --authorized \
  --output results/fleet-acceptance.json
```

The acceptance scan is passive `standard` work. `--request-budget-mode enforce` is the default;
operators retain `--request-budget-mode off` for intentionally unrestricted local labs. The
production gate requires every node to run its desired digest-pinned image. A source-checkout test
may explicitly pass `--allow-local-build`; the runner then requires one uniform safe local image and
marks the receipt `local-build-development`, which cannot substitute for production release
evidence. The
authenticated control-plane lease probe uses its own random Stream and deletes it afterward; it
never leases production work and requires no host-side Redis client package. The
physical fault gate waits for an attributed shard, drains that node, kills only the exact Docker
worker over BatchMode SSH, and requires a different node to reclaim and finish its Stream delivery.
The runner resumes the drained node in a `finally` path, and the container restart policy restores
capacity. The receipt stores only node/scan/container identifiers, check
counts, a target hash, and a receipt hash. A passing
receipt proves the listed run, not every future network state, and should be regenerated for each
release candidate. `--preflight-only` checks topology/storage without submitting a scan.
`--scan-type quick` is available for bounded development smoke tests and is recorded in the
receipt; release-candidate acceptance retains the default passive `standard` depth.

### Milestone A: Two-VPS Queue Proof

Purpose: prove remote workers can consume jobs from the control plane.

Acceptance criteria:

- control plane and at least two worker VPSs are connected through the supported HTTPS broker;
- control plane can create a short-lived join token;
- worker VPS can join with one command after ShakerScan is installed;
- joined worker instance appears in a fleet/node list with heartbeat and capacity;
- worker instance runs only worker processes;
- worker instance consumes a normal scan job from the shared queue;
- scan state and findings are written to the control-plane database;
- Redis/Postgres are not reachable from the public internet.

The implementation and acceptance runner are complete. No unattended or production-safe claim is
allowed until the command above passes on the candidate's actual physical topology and its receipt
is retained with release evidence.

### Milestone B: Cross-VPS Parallel-Scan Proof

Purpose: prove the related parallel-scan implementation works across hosts.

Acceptance criteria:

- `parallel: true` creates parent, shard, and merge jobs;
- shard jobs are executed by workers on at least two VPSs;
- parent scan status/progress rolls up child shard status;
- findings dedupe correctly under concurrent shard writes;
- merge creates one logical report.

This should not be called production-ready until the physical cross-node acceptance receipt passes;
centralized evidence and deterministic lease recovery probing are implemented.

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

All Milestone C implementation criteria are built. The physical release-topology receipt remains
the operational gate for an unattended-production claim.

## 14. Open Decisions

| Decision | Recommendation |
|---|---|
| Overlay first or broker first? | **Resolved for 0.8.9:** broker is the supported production transport. WireGuard is built preview code pending separate physical acceptance. |
| Tailscale or WireGuard? | Tailscale may protect operator UI access independently of worker transport. Built-in WireGuard worker transport remains preview. |
| Self-hosted or managed data stores? | Self-host for early internal deployments; managed Postgres/Redis when HA or operational maturity matters. |
| MinIO or cloud S3? | MinIO for self-hosted; S3-compatible API either way. |
| Node-agent or orchestrator first? | Node-agent first. Revisit Nomad, Docker Swarm, or Kubernetes when fleet size and rollout complexity justify it. |
| Queue list or Streams? | **Resolved: Streams.** Lists are read only as an upgrade bridge; all new jobs use leased Streams. |

## Final Recommendation

Ship and extend multi-node in layers while keeping DAST/auth quality and execution contracts as
acceptance gates:

1. **0.8.9 broker gate:** run `shakerscan fleet accept` against two digest-pinned remote workers and
   retain the content-free receipt for the exact frozen SHA.
2. **Broker hardening before unattended use:** the code paths are built: Stream fencing uses
   Redis server idle time (not worker clocks), execution revalidates durable target/terminal state and
   current node/image/placement at dispatch, and request-budget telemetry is broken down by adapter.
   Preserve a passing physical acceptance receipt for the release candidate.
3. **Future WireGuard promotion:** execute and retain the equivalent physical topology matrix before
   promoting the built overlay transport from preview to supported production use.
---
