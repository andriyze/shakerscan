"""Exercise broker leasing/routing, not just the placement matcher in isolation."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import copy
import json
import uuid

import pytest

from api.fleet_routes import router as routes
from api.fleet_routes.placement import private_input_retry_payload
from tests.test_job_queue import FakeStreams

NODE = "10000000-0000-4000-8000-000000000001"
SCAN = "20000000-0000-4000-8000-000000000001"


def _fixture(monkeypatch, placement, *, private=False):
    inserts = []
    class Redis(FakeStreams):
        def hset(self, *_args, **_kwargs):
            return 1
        def expire(self, *_args):
            return True
    redis = Redis()
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
                return {"id": uuid.UUID("30000000-0000-4000-8000-000000000001")}
            raise AssertionError(sql)
    class Pool:
        @asynccontextmanager
        async def acquire(self):
            yield Connection()
    async def authenticated(*_args, **_kwargs):
        return {"id": NODE, "labels": {"transport": "broker"}, "name": "remote node"}
    async def capacity():
        return 4
    async def reserve(*_args):
        return {"granted": 100}
    async def event(*_args, **_kwargs):
        return None
    monkeypatch.setattr(routes, "_pool", lambda: Pool())
    monkeypatch.setattr(routes, "get_redis", lambda: redis)
    monkeypatch.setattr(routes, "_broker_authenticated_node", authenticated)
    monkeypatch.setattr(routes, "_broker_active_scan_cap", capacity)
    monkeypatch.setattr(routes, "_broker_take_or_refresh_slot", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(routes, "_broker_reserve_request_budget", reserve)
    monkeypatch.setattr(routes, "_record_fleet_node_event", event)
    payload = {"type": "scan", "scan_id": SCAN, "job_id": "job-test",
        "target": "https://example.test", "placement": placement,
        "options": {"auto_auth": False, "disposable_login_credentials": False}}
    if private:
        payload["options"]["auth_header"] = "Bearer synthetic-test-secret"
    routes.enqueue_job(redis, routes.QUEUE_NAME, payload)
    return redis, inserts


@pytest.mark.parametrize("placement", [{"node_scope": "remote"}, {"node_id": NODE}])
def test_healthy_remote_node_leases_a_matching_job_with_disabled_auth_flags(monkeypatch, placement):
    redis, inserts = _fixture(monkeypatch, placement)
    response = asyncio.run(routes.lease_broker_job(NODE,
        routes.BrokerLeaseRequest(worker_id="remote-worker", wait_seconds=0), None))
    assert response.status_code == 200
    assert len(inserts) == 1 and str(inserts[0][0]) == NODE
    body = json.loads(response.body)
    assert body["job"]["scan_id"] == SCAN
    assert body["private_scan_inputs"] is None
    assert len(redis.pending) == 1, "one returned broker lease owns exactly one stream delivery"
    assert not routes.qualified_route_queues(redis, [routes.QUEUE_NAME], worker_labels={"node_id": "local", "node_scope": "local"})


@pytest.mark.parametrize("placement", [{"node_scope": "remote"}, {"node_id": NODE}])
def test_private_job_without_a_sealed_input_path_waits_on_its_requested_node(monkeypatch, placement):
    redis, inserts = _fixture(monkeypatch, placement, private=True)
    response = asyncio.run(routes.lease_broker_job(NODE,
        routes.BrokerLeaseRequest(worker_id="remote-worker", wait_seconds=0), None))
    assert response.status_code == 204
    assert inserts == []
    assert routes.qualified_route_queues(redis, [routes.QUEUE_NAME], worker_labels={"node_scope": "remote", "node_id": NODE})
    assert not routes.qualified_route_queues(redis, [routes.QUEUE_NAME], worker_labels={"node_scope": "local", "node_id": "local"})
    assert not redis.pending


def test_wrong_node_cannot_take_a_pinned_job(monkeypatch):
    redis, inserts = _fixture(monkeypatch, {"node_id": "10000000-0000-4000-8000-000000000002"})
    response = asyncio.run(routes.lease_broker_job(NODE,
        routes.BrokerLeaseRequest(worker_id="remote-worker", wait_seconds=0), None))
    assert response.status_code == 204 and inserts == []
    assert not redis.pending


def test_private_retry_preserves_region_and_pin_without_mutating_the_input():
    original = {"schema_version": "scan-job/v2", "placement": {"node_id": NODE, "region": "eu-west"}}
    snapshot = copy.deepcopy(original)
    retry = private_input_retry_payload(original)
    assert retry["placement"] == original["placement"]
    retry["placement"]["region"] = "other"
    assert original == snapshot
    assert "options" not in retry


def test_default_scan_options_are_not_secret_material():
    from request_models import ScanOptions
    options = ScanOptions().model_dump()
    assert routes._broker_job_has_private_inputs({"options": options}) is False
    public, private = routes._split_broker_private_options(options)
    assert private == {}
    assert "auth_header" not in public
    for value in (True, "Bearer synthetic-test-secret"):
        assert routes._broker_job_has_private_inputs({"options": {"auth_header": value}}) is True
