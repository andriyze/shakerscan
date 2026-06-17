# Multi-Node Architecture

**Status:** RFC / design note. The near-term path is operationally feasible, but the
production-ready fleet work is not implemented yet.
**Scope:** run a coordinated ShakerScan fleet across multiple VMs/VPS hosts so one UI/API
can scan more targets at once and run high-budget Full Coverage scans by using workers
from many machines.
**Related designs:** [parallel-scan-architecture.md](parallel-scan-architecture.md),
[continuous-asm-architecture.md](continuous-asm-architecture.md).

## Shared capability status matrix (agent quick read)

This matrix is duplicated across the architecture docs on purpose. It gives AI coding/review agents
one compact starting point before they choose an implementation increment. The docs describe intended
architecture; the current code, migrations, and tests remain the source of truth for shipped behavior.
Every implementation task must verify the current state with search/tests before editing.

| Capability | Status | Next implementation prompt |
|---|---|---|
| Parallel parent/plan/shard/merge | Shipped | Maintain, harden, and extend only through focused increments. |
| Coverage full-worklist fan-out | Shipped | Keep zero-rediscovery child mode stable while dynamic allocation lands. |
| ASM endpoint inventory | Shipped | Keep replay/auth identity aligned with scanner telemetry. |
| ASM campaign/lease/attempt foundation | Shipped | Broaden scanner telemetry schemas beyond smart active families. |
| Full Coverage campaign linkage | Shipped | Convert static slices to dynamic pull-based allocation. |
| First-class check registry | Proposed | Replace scattered boolean family wiring with registry-backed scheduling. |
| Multi-node WireGuard POC | Proposed/RFC | Build a two-VPS proof only after local queue/worker invariants stay green. |
| Production multi-node fleet | Proposed/RFC | Add node registry, reliable leases, object evidence, routing, and global rate limits. |
| HTTPS broker for untrusted workers | Future | Do not build until owned-fleet primitives are stable. |

The parallel-scan design answers: "How does one logical scan fan out into plan, shard,
and merge jobs?" This document answers: "How can those worker jobs run on more than one
host?"

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
   strategies) is implemented today — see `docs/parallel-scan-architecture.md`. Shard jobs are
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
- Do not redesign the parallel scan shard model here. This doc assumes that work follows
  [parallel-scan-architecture.md](parallel-scan-architecture.md).

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
| Job queue | Scan jobs are pushed to Redis and consumed by workers. | A worker on another VPS can participate if it can reach the same queue. |
| Finding writes | Findings are deduped with a database uniqueness constraint and conflict-safe inserts. | Concurrent workers can scan the same target without inventing a distributed lock. |
| Parallel scan plan | Parent, shard, and merge jobs are implemented on the queue. | Shard jobs are naturally host-agnostic when remote workers can safely reach the shared queue and state. |
| Worker scaling | `POST /workers` controls replicas on the local Docker host. | This does not scale remote worker instances. Multi-node needs per-node lifecycle control. |
| Evidence | `./results` is a local bind mount. | Artifacts written on worker VPS B are not automatically visible to the control plane. This must be centralized. |
| Queue reliability | A plain Redis list with blocking pop is effectively at-most-once after a worker receives a job. | A multi-node fleet needs leases, ack, and reclaim before it is safe for unattended production use. |
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
8. Pull a pinned scanner image from a private registry so all nodes run the same version.
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

- scaling remote nodes is manual unless a node-agent exists;
- evidence remains incomplete unless storage is centralized;
- a worker crash can still lose an in-flight job under list/pop semantics;
- routing assumes workers are mostly interchangeable.

### Phase 2: Production-Ready Owned Fleet

Goal: operate many owned worker VPSs safely.

Build the fleet layer:

1. **Node registry:** track `node_id`, hostname, overlay IP, egress IP, region, version,
   labels, tool capabilities, capacity, active worker count, desired worker count,
   heartbeat, and drain state.
2. **Node-agent:** each worker VPS runs a local agent that reports health and applies
   desired worker count on that VPS. The API should never drive a remote Docker socket
   directly.
3. **Central evidence store:** workers upload screenshots, HAR files, logs, and other
   artifacts to S3/MinIO. Findings and scan results store object keys, not local paths.
4. **Reliable job leases:** replace or wrap plain list pop with ack/reclaim semantics.
   Redis Streams consumer groups are the natural Redis-native option.
5. **Distributed rate limiting:** use Redis token buckets keyed by target/root domain so
   adding worker instances does not accidentally multiply request pressure.
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
solid: standalone remains default, `fleet init`, built-in WireGuard, `fleet join`,
node-agent heartbeat, worker scaling, evidence storage, and safe queue semantics.

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

Prefer a pull model for commands in Phase 2. The agent periodically asks the control
plane for desired state, which avoids opening inbound management ports on worker VPSs.

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

Evidence centralization should happen before advertising cross-VM parallel scans as
production-ready. Without it, the logical scan may complete but its report can point at
artifacts stranded on a worker VPS.

## 9. Queue Reliability And Idempotency

The current queue model is enough to prove multi-node execution, but it is not enough for
a reliable fleet.

Required semantics:

- a job is leased, not destroyed, when a worker starts it;
- the worker heartbeats while the job is active;
- completion explicitly acknowledges the lease;
- stale leases are reclaimed after a visibility timeout;
- retries are bounded and visible;
- duplicate completion attempts are idempotent.

Redis Streams consumer groups provide this shape:

```text
XADD scan_jobs ...
XREADGROUP GROUP workers node-a COUNT 1 BLOCK ...
XACK scan_jobs workers <message-id>
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
| Queue per capability | Simple and compatible with the current list model. Workers block on queues they qualify for. |
| Redis Streams with routing fields | Better once the queue moves to Streams. Scheduler can assign or filter by labels. |
| Broker-side scheduler | Best in Phase 3. The broker leases only jobs a node is allowed to run. |

Rate limiting must be global, not per node. A Redis token bucket keyed by root domain or
target should gate outbound request bursts across the whole fleet.

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
| Rate limiting | Existing local behavior. | Distributed token buckets by target/root domain. |
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

Known gaps are acceptable here: manual scaling, local evidence, and at-most-once job
delivery.

### Milestone B: Cross-VPS Parallel-Scan Proof

Purpose: prove the related parallel-scan implementation works across hosts.

Acceptance criteria:

- `parallel: true` creates parent, shard, and merge jobs;
- shard jobs are executed by workers on at least two VPSs;
- parent scan status/progress rolls up child shard status;
- findings dedupe correctly under concurrent shard writes;
- merge creates one logical report.

This should not be called production-ready until centralized evidence and reliable job
leases are in place.

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
| Queue list or Streams? | Lists are acceptable only for proof-of-concept. Streams or equivalent lease semantics are required for production. |

## Final Recommendation

Build multi-node in two layers:

1. **Now:** owned worker VPSs over a private overlay, sharing Redis/Postgres with the
   control plane. This proves that the current worker fleet can span hosts and gives
   immediate throughput gains for independent scans.
2. **Next:** add node-agent lifecycle management, centralized evidence, reliable queue
   leases, distributed rate limiting, and routing. This makes the owned fleet safe enough
   for production.
3. **Later:** add the HTTPS broker for untrusted or customer-hosted nodes. That is the
   correct zero-trust architecture, but it is more work than needed for the first owned
   multi-VPS fleet.

---

## AI Agent Task Appendix

Use this appendix when asking an AI coding/review agent to implement or audit multi-node work. Fleet
work has a high blast radius, so prompts must separate proof-of-concept overlay work from
production-ready queue, evidence, routing, and security work.

### Required prompt contract

Every prompt should contain:

```text
ROLE
You are a distributed systems engineer hardening ShakerScan multi-node execution.

TASK
Implement or review exactly one multi-node architecture increment.

SOURCE OF TRUTH
Use these docs as authoritative architecture context:
- docs/parallel-scan-architecture.md
- docs/continuous-asm-architecture.md
- docs/multi-node-architecture.md
Before changing code, verify shipped behavior in the repository, Docker/compose files, API handlers,
worker code, DB migrations, queue use, and tests.

CURRENT STATE
Summarize the shipped behavior relevant to this task in 5 bullets before changing code.

TARGET BEHAVIOR
Describe the desired behavior in observable terms.

NON-GOALS
List what must not be changed in this task.

SAFETY INVARIANTS
Preserve the invariants listed below.

MIGRATION / BACKFILL / COMPATIBILITY
State whether schema/data changes are required, how existing installs are upgraded, and what fallback
exists for standalone mode.

OBSERVABILITY / UI / REPORT BEHAVIOR
State what API responses, fleet views, scan detail pages, logs, reports, artifact links, and node
audit fields should show after the change.

FILES / COMPONENTS TO INSPECT
List expected files, but verify with search before editing.

IMPLEMENTATION PLAN
Return a short plan first. Then implement.

ACCEPTANCE CRITERIA
Provide API behavior, DB state, queue behavior, UI/report behavior, node lifecycle behavior, and
failure behavior.

TESTS REQUIRED
Add or update unit, DB/integration, worker/API, queue, object-storage, and UI tests where applicable.

OUTPUT FORMAT
Return changed files, behavior summary, safety checks, tests run, and remaining risks.
```

Hard rule: exactly one architecture increment per implementation task. Do not combine WireGuard
join flow, node registry, object storage, Redis Streams migration, routing, rate limiting, and HTTPS
broker work in one change.

### Safety invariants for fleet work

- Standalone mode remains the default and must keep working.
- Worker nodes should never require public Redis/Postgres exposure.
- Adding nodes must not multiply target request pressure beyond global rate caps.
- Queue completion must be idempotent under duplicate delivery or retry.
- Reports must not reference artifacts stranded on worker-local filesystems.
- Draining a node stops new work but lets current work finish or return leases.
- Node/version/egress attribution is recorded for scans, shards, and attempts when fleet mode is
  active.
- Untrusted/customer-hosted workers use a broker model later; do not give them direct DB/Redis access.

### Prompt: production-ready multi-node queue, evidence, and rate-limit layer

```text
ROLE
You are a distributed systems engineer hardening ShakerScan multi-node execution.

TASK
Implement production-owned-fleet primitives for multi-node workers.

CURRENT STATE
- Verify the current shipped behavior before editing.
- Parallel parent/plan/shard/merge is shipped and queue-backed.
- Phase 1 fleet mode is proposed: owned worker VPSs over ShakerScan-managed WireGuard.
- Workers can share Redis/Postgres over the overlay in controlled environments, but this is not
  production-ready because evidence is local/incomplete, queue pop is at-most-once, scaling remote
  nodes is manual, and routing assumes homogeneous workers.

TARGET BEHAVIOR
- Add node registry with node_id, hostname, overlay IP, egress IP, region, version, labels,
  capabilities, capacity, active_worker_count, desired_worker_count, heartbeat, and drain state.
- Add node-agent pull loop for desired state.
- Move evidence to S3/MinIO-compatible object storage.
- Replace or wrap Redis list pop with Redis Streams consumer groups or equivalent ack/reclaim
  semantics.
- Add distributed token buckets keyed by target and root_domain.
- Add routing labels for region, egress group, private reachability, scan tier, and tool
  requirements.
- Record node/version/egress attribution on scan, shard, and attempt records.

NON-GOALS
- Do not expose Redis/Postgres publicly.
- Do not build a worker mesh.
- Do not implement the HTTPS broker in this task unless explicitly requested.
- Do not change parallel scan planning semantics.

MIGRATION / BACKFILL / COMPATIBILITY
- Add node/evidence/attribution schema in db/init.sql and runtime migrations together.
- Existing standalone installs should start with one implicit local node or no fleet node requirement.
- Existing local result files remain readable; new fleet artifacts use object storage.
- Keep Redis list mode available as a local/dev fallback until Streams parity tests pass.

OBSERVABILITY / UI / REPORT BEHAVIOR
- Fleet view shows node health, capacity, desired/current worker count, version, egress IP, drain
  state, and recent jobs.
- Scan detail shows shard/node attribution when available.
- Artifact links work from the control-plane UI regardless of which node produced them.
- Logs expose lease claim, ack, reclaim, drain, and rate-limit decisions.

ACCEPTANCE CRITERIA
- A worker crash leaves jobs reclaimable.
- Artifacts from any node are visible from the control-plane UI.
- Draining a node stops new work but lets current jobs finish or return leases.
- Jobs can be routed by label.
- Node attribution appears in scan/shard/attempt records.
- Adding workers does not exceed distributed target/root-domain rate caps.

TESTS REQUIRED
- Redis Streams or equivalent ack/reclaim tests.
- Object storage upload/download tests.
- Token bucket concurrency tests across simulated nodes.
- Node drain, heartbeat expiry, and version mismatch tests.
- UI/API tests for fleet view and artifact access.
```

### Prompt: two-VPS WireGuard proof

```text
ROLE
You are implementing the first owned-fleet proof for ShakerScan.

TASK
Implement the smallest safe two-VPS WireGuard join flow.

CURRENT STATE
- Verify current install/start/remote-mode behavior before editing.
- Standalone mode is the default.
- The desired product workflow is fleet init -> join token -> fleet join, but the flags are proposed.

TARGET BEHAVIOR
- Control plane can initialize a WireGuard overlay for owned workers.
- Control plane can create a short-lived worker join token.
- Worker can join with one command after ShakerScan install.
- Worker runs worker-only processes and appears in a node list with heartbeat/capacity.
- Worker can consume one normal scan job from the control-plane queue over the overlay.

NON-GOALS
- Do not advertise this as production-ready.
- Do not build cloud provisioning.
- Do not implement the HTTPS broker.
- Do not expose Redis/Postgres publicly.

MIGRATION / BACKFILL / COMPATIBILITY
- Standalone installs remain unchanged unless fleet init/join is invoked.
- Existing local workers continue to run without node-agent.

OBSERVABILITY / UI / REPORT BEHAVIOR
- Status output prints local and fleet URLs/config state.
- Node list shows heartbeat and worker capacity.
- Any missing production hardening is labeled as a known gap.

ACCEPTANCE CRITERIA
- Control plane and one worker VPS connect over ShakerScan-managed WireGuard.
- Redis/Postgres are reachable only over the overlay.
- A scan submitted on the control plane can run on the worker and write results centrally.
- Failure to join leaves the standalone install usable.

TESTS REQUIRED
- CLI/config tests for init/token/join.
- API tests for node registration and heartbeat.
- Smoke test with one remote worker consuming a queued scan.
```
