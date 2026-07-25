import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from job_queue import (  # noqa: E402
    CONSUMER_GROUP,
    acknowledge_lease,
    clear_unleased,
    enqueue_job,
    heartbeat_lease,
    lease_job,
    pending_depth,
    queue_payloads,
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
        return [message_id for message_id in message_ids if message_id in self.pending]

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

    def delete(self, name):
        self.legacy.pop(name, None)


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
