import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from job_queue import (  # noqa: E402
    CONSUMER_GROUP,
    acknowledge_lease,
    clear_unleased,
    enqueue_job,
    heartbeat_lease,
    lease_job,
    pending_depth,
    qualified_route_queues,
    queue_payloads,
    routed_queue_name,
    stream_key,
)


class BusyGroup(Exception):
    pass


class FakeStreams:
    def __init__(self):
        self.streams = {}
        self.pending = {}
        self.next_id = 1
        self.legacy = {}
        self.values = {}
        self.sets = {}

    def xgroup_create(self, name, group, id="0-0", mkstream=False):
        self.streams.setdefault(name, [])
        if getattr(self, "group_created", False):
            raise BusyGroup("BUSYGROUP already exists")
        self.group_created = True
        return True

    def xadd(self, name, fields):
        message_id = f"{self.next_id}-0"
        self.next_id += 1
        self.streams.setdefault(name, []).append((message_id, dict(fields)))
        return message_id

    def xreadgroup(self, group, consumer, streams, count, block):
        for name in streams:
            for message_id, fields in self.streams.get(name, []):
                if message_id not in self.pending:
                    self.pending[message_id] = {"consumer": consumer, "times_delivered": 1}
                    return [(name, [(message_id, fields)])]
        return []

    def xautoclaim(self, name, group, consumer, min_idle_time, start_id, count):
        for message_id, fields in self.streams.get(name, []):
            if message_id in self.pending and self.pending[message_id].get("stale"):
                self.pending[message_id]["consumer"] = consumer
                self.pending[message_id]["times_delivered"] += 1
                self.pending[message_id]["stale"] = False
                return ["0-0", [(message_id, fields)], []]
        return ["0-0", [], []]

    def xpending_range(self, name, group, min, max, count):
        rows = []
        for message_id, state in self.pending.items():
            if min not in {"-", message_id} or max not in {"+", message_id}:
                continue
            rows.append({"message_id": message_id, **state})
        return rows[:count]

    def xclaim(self, name, group, consumer, min_idle_time, message_ids, idle, justid):
        claimed = []
        for message_id in message_ids:
            if message_id in self.pending:
                self.pending[message_id]["consumer"] = consumer
                self.pending[message_id]["stale"] = False
                claimed.append(message_id)
        return claimed

    def xack(self, name, group, message_id):
        return int(self.pending.pop(message_id, None) is not None)

    def xdel(self, name, message_id):
        before = len(self.streams.get(name, []))
        self.streams[name] = [row for row in self.streams.get(name, []) if row[0] != message_id]
        return int(len(self.streams[name]) != before)

    def xrange(self, name, min="-", max="+"):
        return list(self.streams.get(name, []))

    def xlen(self, name):
        return len(self.streams.get(name, []))

    def xpending(self, name, group):
        ids = {message_id for message_id, _ in self.streams.get(name, [])}
        return {"pending": len(ids & self.pending.keys())}

    def rpush(self, name, value):
        self.legacy.setdefault(name, []).append(value)

    def blpop(self, names, timeout):
        for name in names:
            if self.legacy.get(name):
                return name, self.legacy[name].pop(0)
        return None

    def lrange(self, name, start, end):
        return list(self.legacy.get(name, []))

    def llen(self, name):
        return len(self.legacy.get(name, []))

    def delete(self, *names):
        for name in names:
            self.legacy.pop(name, None)
            self.values.pop(name, None)
            self.streams.pop(name, None)
            self.sets.pop(name, None)

    def set(self, name, value):
        self.values[name] = value

    def get(self, name):
        return self.values.get(name)

    def sadd(self, name, value):
        before = len(self.sets.setdefault(name, set()))
        self.sets[name].add(value)
        return int(len(self.sets[name]) != before)

    def smembers(self, name):
        return set(self.sets.get(name, set()))

    def srem(self, name, value):
        existed = value in self.sets.get(name, set())
        self.sets.setdefault(name, set()).discard(value)
        return int(existed)

    def eval(self, script, numkeys, *values):
        keys = values[:numkeys]
        args = values[numkeys:]
        if "shakerscan:heartbeat-owned-lease" in script:
            message_id, consumer = args[1], args[2]
            state = self.pending.get(message_id)
            if not state or state.get("consumer") != consumer:
                return 0
            state["stale"] = False
            return 1
        if "shakerscan:ack-delete" in script:
            acknowledged = self.xack(keys[0], args[0], args[1])
            if not acknowledged:
                return 0
            self.xdel(keys[0], args[1])
            if len(keys) == 4 and self.xlen(keys[0]) == 0 and self.llen(keys[3]) == 0:
                self.srem(keys[1], args[2])
                self.delete(keys[2], keys[0])
            return 1
        if "shakerscan:routed-enqueue" in script:
            route, requirements, payload, limit = args
            routes = self.sets.setdefault(keys[0], set())
            if route not in routes and len(routes) >= int(limit):
                raise RuntimeError("SHAKERSCAN_ROUTE_CAPACITY_EXCEEDED")
            routes.add(route)
            self.set(keys[1], requirements)
            return self.xadd(keys[2], {"payload": payload})
        if "shakerscan:prune-empty-route" in script:
            if self.xlen(keys[0]) or self.llen(keys[3]):
                return 0
            self.srem(keys[1], args[0])
            self.delete(keys[2], keys[0])
            return 1
        raise AssertionError("unknown Lua script")


def test_stream_job_is_leased_heartbeated_and_acknowledged():
    redis = FakeStreams()
    payload = {"job_id": "job-1", "scan_id": "scan-1"}
    message_id = enqueue_job(redis, "scan_jobs", payload)

    lease = lease_job(
        redis,
        ["scan_jobs"],
        consumer_name="node-a:worker-1",
        block_ms=10,
        visibility_timeout_ms=1000,
    )

    assert lease is not None
    assert lease.message_id == message_id
    assert json.loads(lease.payload) == payload
    assert lease.delivery_attempts == 1
    assert heartbeat_lease(redis, lease, "node-a:worker-1") is True
    assert pending_depth(redis, "scan_jobs") == 0
    assert acknowledge_lease(redis, lease) is True
    assert queue_payloads(redis, "scan_jobs") == []


def test_stale_delivery_is_reclaimed_and_attempt_is_visible():
    redis = FakeStreams()
    message_id = enqueue_job(redis, "scan_jobs", {"job_id": "job-2"})
    first = lease_job(redis, ["scan_jobs"], consumer_name="dead-worker", block_ms=10, visibility_timeout_ms=1000)
    assert first and first.message_id == message_id
    redis.pending[message_id]["stale"] = True

    reclaimed = lease_job(redis, ["scan_jobs"], consumer_name="live-worker", block_ms=10, visibility_timeout_ms=1000)

    assert reclaimed is not None
    assert reclaimed.reclaimed is True
    assert reclaimed.delivery_attempts == 2
    assert heartbeat_lease(redis, first, "dead-worker") is False
    assert redis.pending[message_id]["consumer"] == "live-worker"
    assert heartbeat_lease(redis, reclaimed, "live-worker") is True


def test_clear_removes_only_unleased_stream_messages():
    redis = FakeStreams()
    enqueue_job(redis, "scan_jobs", {"job_id": "leased"})
    enqueue_job(redis, "scan_jobs", {"job_id": "waiting"})
    leased = lease_job(redis, ["scan_jobs"], consumer_name="worker", block_ms=10, visibility_timeout_ms=1000)
    assert leased is not None

    deleted = clear_unleased(redis, "scan_jobs")

    assert [json.loads(item)["job_id"] for item in deleted] == ["waiting"]
    assert [json.loads(item)["job_id"] for item in queue_payloads(redis, "scan_jobs")] == ["leased"]


def test_narrow_legacy_client_keeps_upgrade_compatibility():
    class Legacy:
        def __init__(self):
            self.items = []

        def rpush(self, name, value):
            self.items.append((name, value))

        def blpop(self, names, timeout):
            return self.items.pop(0) if self.items else None

    redis = Legacy()
    enqueue_job(redis, "scan_jobs", {"job_id": "legacy"})
    lease = lease_job(redis, ["scan_jobs"], consumer_name="worker", block_ms=10, visibility_timeout_ms=1000)
    assert lease is not None and lease.legacy
    assert json.loads(lease.payload)["job_id"] == "legacy"


def test_placement_routes_only_to_qualified_worker_streams():
    redis = FakeStreams()
    placement = {
        "region": "eu-west",
        "network": "customer-vpn",
        "requires": ["nuclei", "playwright"],
    }
    payload = {"job_id": "placed", "options": {"placement": placement}}
    enqueue_job(redis, "scan_jobs", payload)
    route = routed_queue_name("scan_jobs", placement)

    assert pending_depth(redis, "scan_jobs") == 1
    assert qualified_route_queues(
        redis,
        ["scan_jobs"],
        worker_labels={
            "region": "us-east",
            "network": "customer-vpn",
            "tools": ["playwright", "nuclei"],
        },
    ) == []
    assert qualified_route_queues(
        redis,
        ["scan_jobs"],
        worker_labels={
            "region": "eu-west",
            "network": "customer-vpn",
            "tools": ["nuclei", "playwright", "sqlmap"],
        },
    ) == [route]

    assert lease_job(
        redis,
        ["scan_jobs"],
        consumer_name="unqualified",
        block_ms=10,
        visibility_timeout_ms=1000,
    ) is None
    lease = lease_job(
        redis,
        ["scan_jobs", route],
        consumer_name="qualified",
        block_ms=10,
        visibility_timeout_ms=1000,
    )
    assert lease is not None and lease.queue_name == route
    decoded = json.loads(lease.payload)
    assert decoded["placement"] == placement
    assert decoded["_base_queue_name"] == "scan_jobs"


def test_final_route_ack_prunes_registry_and_requirement_metadata():
    redis = FakeStreams()
    placement = {"region": "eu-west"}
    route = routed_queue_name("scan_jobs", placement)
    enqueue_job(redis, "scan_jobs", {"job_id": "placed", "placement": placement})
    lease = lease_job(
        redis,
        [route],
        consumer_name="worker",
        block_ms=10,
        visibility_timeout_ms=1000,
    )
    assert lease is not None
    assert acknowledge_lease(redis, lease) is True
    assert route not in redis.smembers("shakerscan:queue-routes:scan_jobs")
    assert redis.get(f"shakerscan:queue-route-requirements:{route}") is None


def test_route_registry_has_a_hard_capacity(monkeypatch):
    redis = FakeStreams()
    monkeypatch.setenv("SHAKERSCAN_QUEUE_ROUTE_MAX", "16")
    for index in range(16):
        enqueue_job(redis, "scan_jobs", {"job_id": str(index), "placement": {"region": f"r-{index}"}})
    with pytest.raises(RuntimeError, match="ROUTE_CAPACITY_EXCEEDED"):
        enqueue_job(redis, "scan_jobs", {"job_id": "overflow", "placement": {"region": "overflow"}})
