"""P3-13: fail-closed worker freshness. A worker that cannot PROVE it is current
must refuse a job submitted with require_current_workers — running stale (or
unknown-build) code silently corrupts results. Deterministic: the build
fingerprint is mocked so the test does not depend on /app being present."""
import asyncio
import json
import os
import sys
import types
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *a, **k: None))

import worker  # noqa: E402

CURRENT_FP = "deadbeefcafef00d"


def test_worker_redis_socket_timeout_exceeds_blocking_pop(monkeypatch):
    captured = {}

    def fake_from_url(url, **kwargs):
        captured.update({"url": url, **kwargs})
        return object()

    monkeypatch.setattr(worker.redis, "from_url", fake_from_url)
    worker.get_redis()

    assert captured["socket_timeout"] > worker.WORKER_QUEUE_BLOCK_SECONDS
    assert captured["socket_connect_timeout"] == 10


def _job(expected, require=True, **extra):
    opts = {"require_current_workers": require}
    if expected is not None:
        opts["expected_build_fingerprint_at_submit"] = expected
    return {"type": "scan", "job_id": "j1", "scan_id": "fake", "options": opts, **extra}


def _run(coro):
    return asyncio.run(coro)


def test_normal_job_is_not_refused(monkeypatch):
    monkeypatch.setattr(worker, "_worker_build_fingerprint", lambda: CURRENT_FP)
    # No expected fingerprint / not require_current -> never refused.
    assert _run(worker._refuse_stale_job_if_needed({"options": {}})) is False
    assert _run(worker._refuse_stale_job_if_needed(_job(CURRENT_FP, require=False))) is False


def test_current_worker_runs_matching_job(monkeypatch):
    monkeypatch.setattr(worker, "_worker_build_fingerprint", lambda: CURRENT_FP)
    assert _run(worker._refuse_stale_job_if_needed(_job(CURRENT_FP))) is False


def test_stale_worker_refuses_and_requeues(monkeypatch):
    monkeypatch.setattr(worker, "_worker_build_fingerprint", lambda: "STALE_DIFFERENT")
    pushed = []

    class _FakeRedis:
        def rpush(self, queue, payload):
            pushed.append(queue)

        def hset(self, *a, **k):
            pass

    monkeypatch.setattr(worker, "get_redis", lambda: _FakeRedis())
    job = _job(CURRENT_FP)
    assert _run(worker._refuse_stale_job_if_needed(job)) is True
    assert pushed == [worker.QUEUE_NAME]
    assert job["stale_requeue_attempts"] == 1


def test_unknown_fingerprint_fails_closed(monkeypatch):
    # A worker that cannot fingerprint itself is NOT provably current -> must refuse
    # (this was a fail-OPEN bug: unknown was treated as safe-to-run).
    monkeypatch.setattr(worker, "_worker_build_fingerprint", lambda: None)
    pushed = []
    monkeypatch.setattr(worker, "get_redis",
                        lambda: types.SimpleNamespace(rpush=lambda q, p: pushed.append(q), hset=lambda *a, **k: None))
    assert _run(worker._refuse_stale_job_if_needed(_job(CURRENT_FP))) is True
    assert pushed == [worker.QUEUE_NAME]


def test_worker_runtime_identity_preserves_configured_node_and_unique_replica(monkeypatch):
    monkeypatch.setenv("WORKER_ID", "node-123-worker")
    monkeypatch.setenv("HOSTNAME", "replica-abcdef123456789")
    assert worker._worker_runtime_identity() == "node-123-worker:replica-abcd"

    monkeypatch.delenv("HOSTNAME")
    monkeypatch.setattr("socket.gethostname", lambda: "fallback-host")
    assert worker._worker_runtime_identity() == "node-123-worker:fallback-hos"


class _AcquireContext:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _AttributionConnection:
    def __init__(self, result):
        self.result = result
        self.calls = []

    async def fetchrow(self, sql, *args):
        self.calls.append((" ".join(sql.split()), args))
        return self.result


def test_job_execution_is_attributed_to_worker_and_fleet_node(monkeypatch):
    scan_id = uuid.uuid4()
    node_id = uuid.uuid4()
    conn = _AttributionConnection({"id": scan_id})
    monkeypatch.setattr(worker, "db_pool", types.SimpleNamespace(acquire=lambda: _AcquireContext(conn)))
    monkeypatch.setenv("WORKER_ID", "fleet-worker")
    monkeypatch.setenv("HOSTNAME", "container-123456789")
    monkeypatch.setenv("SHAKERSCAN_NODE_ID", str(node_id))

    _run(worker._attribute_job_execution({"scan_id": str(scan_id)}))

    assert len(conn.calls) == 1
    assert conn.calls[0][1] == (scan_id, "fleet-worker:container-12", node_id)
    assert "status <> 'disabled'" in conn.calls[0][0]


def test_disabled_or_missing_fleet_node_refuses_execution(monkeypatch):
    conn = _AttributionConnection(None)
    monkeypatch.setattr(worker, "db_pool", types.SimpleNamespace(acquire=lambda: _AcquireContext(conn)))
    monkeypatch.setenv("SHAKERSCAN_NODE_ID", str(uuid.uuid4()))

    with pytest.raises(RuntimeError, match="missing or disabled"):
        _run(worker._attribute_job_execution({"scan_id": str(uuid.uuid4())}))


def test_revoked_node_refusal_requeues_job_before_dispatch(monkeypatch):
    pushed = []
    dispatched = []

    async def refuse(_job_data):
        raise RuntimeError("fleet node is missing or disabled")

    async def no_sleep(_seconds):
        return None

    async def dispatch(_job_data):
        dispatched.append(True)

    monkeypatch.setattr(worker, "_refuse_stale_job_if_needed", lambda _job: _async_value(False))
    monkeypatch.setattr(worker, "_attribute_job_execution", refuse)
    monkeypatch.setattr(worker, "process_scan_job", dispatch)
    monkeypatch.setattr(worker.asyncio, "sleep", no_sleep)
    monkeypatch.setattr(
        worker,
        "get_redis",
        lambda: types.SimpleNamespace(rpush=lambda queue, payload: pushed.append((queue, json.loads(payload)))),
    )
    job = {"type": "scan", "job_id": "job-1", "scan_id": str(uuid.uuid4())}

    _run(worker.process_job(job))

    assert pushed == [(worker.QUEUE_NAME, job)]
    assert dispatched == []


async def _async_value(value):
    return value
