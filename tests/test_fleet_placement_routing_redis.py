"""Remote and node-pinned placement is honoured end to end on a real Redis (fleet harness).

The 2.3.7 fleet acceptance saw Scans submitted with ``placement.node_scope=remote`` or a fleet
node's ``node_id`` run on control-plane workers while ``broker_job_leases`` stayed empty. This
module drives the real queue machinery against a disposable Redis (``SHAKERSCAN_TEST_REDIS_URL``):

* the producers' ``enqueue_job`` routing;
* the local worker's own lease set (``worker._worker_lease_queue_keys`` with its real placement
  labels) and ``lease_job``, including the reclaim of abandoned deliveries;
* the broker lease route ``POST /fleet/broker/nodes/{id}/lease`` (database rows are fixtures);
* the worker's dispatch refusal of a remote Scan that reached a local queue, materialized by the
  real ``materialize_canonical_scan_job`` from its persisted row.

A pinned or remote job must wait for a matching fleet node and never run on a local worker.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import sys
import uuid
from contextlib import asynccontextmanager

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import worker
from fleet_routes import router as routes
from job_queue import acknowledge_lease, lease_job, stream_key
from runtime.models import TargetBinding
from scan.contracts import bind_scan_scope_receipt, resolve_scan_contract
from scan.job_runtime import materialize_canonical_scan_job
from scan.jobs import CanonicalScanJob

REDIS_URL = os.environ.get("SHAKERSCAN_TEST_REDIS_URL")
NODE = "10000000-0000-4000-8000-000000000001"
OTHER_NODE = "10000000-0000-4000-8000-000000000002"
LOCAL_CONSUMER = "shakerscan-worker-1:test"

pytestmark = pytest.mark.skipif(
    not REDIS_URL, reason="SHAKERSCAN_TEST_REDIS_URL (a disposable Redis) is not set",
)


def _real_redis_module():
    """redis-py itself, even when an earlier test module left a stand-in in ``sys.modules``."""
    loaded = sys.modules.get("redis")
    if loaded is not None and hasattr(loaded, "Redis"):
        return loaded
    stand_in = sys.modules.pop("redis", None)
    try:
        return importlib.import_module("redis")
    finally:
        if stand_in is not None:
            sys.modules["redis"] = stand_in


@pytest.fixture
def redis_client(monkeypatch):
    client = _real_redis_module().Redis.from_url(REDIS_URL)
    client.flushdb()
    monkeypatch.setattr(routes, "get_redis", lambda: client)
    monkeypatch.setattr(worker, "get_redis", lambda: client)
    # A control-plane (local) worker: no fleet node identity, default labels.
    monkeypatch.delenv("SHAKERSCAN_NODE_ID", raising=False)
    monkeypatch.delenv("SHAKERSCAN_NODE_LABELS_JSON", raising=False)
    worker._worker_placement_labels.cache_clear()
    yield client
    worker._worker_placement_labels.cache_clear()
    client.flushdb()
    client.close()


def _local_worker_lease(client):
    """One poll of the local worker's lease loop; the 1 ms visibility also reclaims any
    abandoned delivery on every queue it reads."""
    keys = worker._worker_lease_queue_keys(client, [worker.QUEUE_NAME])
    return lease_job(client, keys, consumer_name=LOCAL_CONSUMER, block_ms=20, visibility_timeout_ms=1)


def _broker_route(monkeypatch, client):
    """The broker lease route over the real Redis; its database rows are fixtures."""
    inserts: list[tuple] = []

    class Connection:
        @asynccontextmanager
        async def transaction(self):
            yield self

        async def execute(self, *_args):
            return "UPDATE 1"

        async def fetchval(self, *_args):
            return False

        async def fetchrow(self, sql, *args):
            if "FROM scans child" in sql:
                return {"status": "queued", "parent_status": None, "target_url": "https://example.test"}
            if "INSERT INTO broker_job_leases" in sql:
                inserts.append(args)
                return {"id": uuid.uuid4()}
            raise AssertionError(sql)

    class Pool:
        @asynccontextmanager
        async def acquire(self):
            yield Connection()

    async def authenticated(node_id, *_args, **_kwargs):
        return {"id": node_id, "labels": {"transport": "broker"}, "name": "remote node"}

    async def capacity():
        return 4

    async def reserve(*_args):
        return {"granted": 100}

    async def event(*_args, **_kwargs):
        return None

    monkeypatch.setattr(routes, "_pool", lambda: Pool())
    monkeypatch.setattr(routes, "_broker_authenticated_node", authenticated)
    monkeypatch.setattr(routes, "_broker_active_scan_cap", capacity)
    monkeypatch.setattr(routes, "_broker_take_or_refresh_slot", lambda *_a, **_k: True)
    monkeypatch.setattr(routes, "_broker_reserve_request_budget", reserve)
    monkeypatch.setattr(routes, "_record_fleet_node_event", event)

    def lease(node_id):
        return asyncio.run(routes.lease_broker_job(
            node_id, routes.BrokerLeaseRequest(worker_id="remote-worker", wait_seconds=0), None,
        ))

    return lease, inserts


def _queued_messages(client) -> dict[str, int]:
    """Messages per stream (routes included) and how many of them are leased."""
    found = {}
    for key in client.scan_iter(match=f"{worker.QUEUE_NAME}*{':leased'}"):
        name = key.decode()
        found[name] = int(client.xlen(name))
    return {name: count for name, count in found.items() if count}


def _payload(job_type: str, placement: dict) -> dict:
    scan_id = str(uuid.uuid4())
    payload = {
        "type": job_type, "scan_id": scan_id, "job_id": f"job-{scan_id[:8]}",
        "target": "https://example.test", "placement": placement,
        "options": {"auto_auth": False, "disposable_login_credentials": False},
    }
    if job_type == "scan_shard":
        payload.update({"parent_scan_id": str(uuid.uuid4()), "shard_index": 1, "shard_count": 3})
    return payload


@pytest.mark.parametrize("job_type", ["scan", "scan_shard"])
@pytest.mark.parametrize("placement", [{"node_scope": "remote"}, {"node_id": NODE}])
def test_remote_and_pinned_work_waits_for_its_fleet_node_and_never_runs_locally(
    monkeypatch, redis_client, job_type, placement,
):
    lease, inserts = _broker_route(monkeypatch, redis_client)
    payload = _payload(job_type, placement)
    routes.enqueue_job(redis_client, routes.QUEUE_NAME, payload)
    # The job sits on its own placement route, not on the base queue every worker reads.
    assert list(_queued_messages(redis_client)) != [stream_key(worker.QUEUE_NAME)]
    assert stream_key(worker.QUEUE_NAME) not in _queued_messages(redis_client)

    # Repeated local polls (each also reclaiming abandoned deliveries) never see it.
    for _ in range(2):
        assert _local_worker_lease(redis_client) is None

    if "node_id" in placement:
        # Another fleet node cannot take a job pinned to this one; it stays queued for it.
        response = lease(OTHER_NODE)
        assert response.status_code == 204 and inserts == []
        assert sum(_queued_messages(redis_client).values()) == 1
        assert _local_worker_lease(redis_client) is None

    response = lease(NODE)
    assert response.status_code == 200
    assert len(inserts) == 1 and str(inserts[0][0]) == NODE
    assert json.loads(response.body)["job"]["scan_id"] == payload["scan_id"]
    # The one delivery is owned by the broker lease; nothing is left for a local worker.
    assert _local_worker_lease(redis_client) is None


@pytest.mark.parametrize("placement", [{"node_scope": "remote"}, {"node_id": NODE}])
def test_private_inputs_without_a_sealing_key_keep_the_job_waiting_remotely(
    monkeypatch, redis_client, placement,
):
    """2.3.7 rewrote such a job to node_scope=local, where a control-plane worker ran it. A
    missing sealed-input key is not permission to change the node: it waits on its route."""
    lease, inserts = _broker_route(monkeypatch, redis_client)
    payload = _payload("scan", placement)
    payload["options"]["auth_header"] = "Bearer synthetic-test-secret"
    routes.enqueue_job(redis_client, routes.QUEUE_NAME, payload)
    assert lease(NODE).status_code == 204 and inserts == []
    assert _local_worker_lease(redis_client) is None
    waiting = _queued_messages(redis_client)
    assert sum(waiting.values()) == 1 and stream_key(worker.QUEUE_NAME) not in waiting
    broker_labels = routes._broker_node_labels({"id": NODE, "labels": {"transport": "broker"}})
    again = lease_job(
        redis_client, routes._broker_lease_queue_names(redis_client, broker_labels),
        consumer_name=f"broker:{NODE}:remote-worker", block_ms=20, visibility_timeout_ms=60_000,
    )
    assert again is not None and json.loads(again.payload)["placement"] == placement


def test_parallel_orchestration_seen_by_a_broker_moves_to_the_local_route(monkeypatch, redis_client):
    """Merge and plan jobs need the control plane's database: a broker that meets a base-queue
    copy hands them to the local route, and a local worker then takes them."""
    lease, inserts = _broker_route(monkeypatch, redis_client)
    merge = {"type": "scan_merge", "parent_scan_id": str(uuid.uuid4()), "attempt": 1}
    routes.enqueue_job(redis_client, routes.QUEUE_NAME, merge)
    assert lease(NODE).status_code == 204 and inserts == []
    local = _local_worker_lease(redis_client)
    assert local is not None and json.loads(local.payload)["placement"] == {"node_scope": "local"}


def _target() -> TargetBinding:
    return TargetBinding(
        target_id=str(uuid.uuid4()), target_kind="web", canonical_host="api.example.test",
        allowed_origins=("https://api.example.test",), allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",), environment="test", scope_receipt_id="scope-1",
    )


def _canonical_scan_and_row(placement: dict):
    contract = bind_scan_scope_receipt(
        resolve_scan_contract(budget_profile="balanced", policy={"active_testing": False}),
        "scope-1",
    )
    job = CanonicalScanJob.create(
        job_id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()), target=_target(),
        execution_plan=contract.execution_plan, request_collections=(),
        credential_profile_ids=(), endpoint_manifest_id=None,
        created_at="2026-10-15T12:00:00Z",
    )
    options = job.execution_plan.option_metadata()
    options.update({
        "target_scheme_inferred": False,
        "runtime_scope_guard": {
            **job.payload()["target"],
            "requires_runtime_destination_check": True,
            "requires_runtime_dns_check": True,
            "address_binding_source": "submission_dns_snapshot",
        },
        "placement": placement,
    })
    row = {
        "target_id": job.target.target_id, "target_url": "https://api.example.test",
        "job_id": job.job_id, "options": options, "scan_generation": "v2",
        "policy_json": job.execution_plan.canonical_dict()["policy"],
        "budget_json": job.execution_plan.canonical_dict()["budget"],
        "scan_job_payload": job.payload(), "scan_job_digest": job.payload_digest,
    }
    return job, row


@pytest.mark.parametrize("placement", [{"node_scope": "remote"}, {"node_id": NODE}])
def test_a_remote_scan_found_on_a_local_route_is_refused_and_requeued_for_the_fleet(
    monkeypatch, redis_client, placement,
):
    """The 2.3.7 symptom: a remote Scan's copy on the node_scope=local route. The local worker
    that leases it materializes the persisted placement, refuses to run it, and requeues it on
    the remote route, where only the matching fleet node reads it."""
    job, row = _canonical_scan_and_row(placement)
    routes.enqueue_job(redis_client, routes.QUEUE_NAME, job.queue_payload(placement={"node_scope": "local"}))
    local = _local_worker_lease(redis_client)
    assert local is not None  # the local route is legitimately the local worker's

    async def materialize(queue_payload):
        return materialize_canonical_scan_job(queue_payload, row, resolved_addresses=("192.0.2.10",))

    async def must_not_run(*_args, **_kwargs):
        raise AssertionError("a remote-placed Scan ran on a local worker")

    async def no_wait(*_args, **_kwargs):
        return None

    monkeypatch.setattr(worker, "_materialize_scan_job_v2", materialize)
    for handler in ("process_scan_job", "process_scan_shard_job", "_attribute_job_execution",
                    "_refuse_stale_job_if_needed"):
        monkeypatch.setattr(worker, handler, must_not_run)
    monkeypatch.setattr(worker.asyncio, "sleep", no_wait)

    asyncio.run(worker.process_job(json.loads(local.payload)))
    acknowledge_lease(redis_client, local)  # the lease loop acknowledges after dispatch

    # Requeued once, on the route of the persisted placement; the local route is empty.
    assert sum(_queued_messages(redis_client).values()) == 1
    for _ in range(2):
        assert _local_worker_lease(redis_client) is None
    broker_labels = routes._broker_node_labels({"id": NODE, "labels": {"transport": "broker"}})
    remote = lease_job(
        redis_client, routes._broker_lease_queue_names(redis_client, broker_labels),
        consumer_name=f"broker:{NODE}:remote-worker", block_ms=20, visibility_timeout_ms=60_000,
    )
    assert remote is not None
    requeued = json.loads(remote.payload)
    assert requeued["scan_id"] == job.scan_id and requeued["placement"] == placement
    assert CanonicalScanJob.from_queue_payload(requeued).payload() == job.payload()
    if "node_id" in placement:
        other = routes._broker_node_labels({"id": OTHER_NODE, "labels": {"transport": "broker"}})
        acknowledge_lease(redis_client, remote)
        routes.enqueue_job(redis_client, routes.QUEUE_NAME, requeued)
        assert lease_job(
            redis_client, routes._broker_lease_queue_names(redis_client, other),
            consumer_name=f"broker:{OTHER_NODE}:remote-worker", block_ms=20,
            visibility_timeout_ms=60_000,
        ) is None
