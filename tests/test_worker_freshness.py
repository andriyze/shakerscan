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
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *a, **k: None))

import worker  # noqa: E402

CURRENT_FP = "deadbeefcafef00d"


def test_worker_preflight_rejects_admission_private_key_even_when_other_preflight_is_disabled(monkeypatch):
    monkeypatch.setenv("MODEL_INTAKE_ADMISSION_SIGNING_KEY_PEM", "forbidden-private-key")
    monkeypatch.setenv("WORKER_PREFLIGHT_ENABLED", "false")

    with pytest.raises(RuntimeError, match="admission signing material"):
        worker.run_worker_preflight()


@pytest.mark.parametrize("variable", [
    "MODEL_INTAKE_CONTROL_PLANE_SIGNING_KEY_PEM",
    "MODEL_INTAKE_SIGNER_AWS_KMS_KEY_ID",
])
def test_worker_preflight_rejects_v2_signer_authority(monkeypatch, variable):
    monkeypatch.setenv(variable, "forbidden-signer-authority")
    monkeypatch.setenv("WORKER_PREFLIGHT_ENABLED", "false")

    with pytest.raises(RuntimeError, match="admission signing material"):
        worker.run_worker_preflight()


def test_db_timestamps_are_normalized_to_naive_utc_for_duration_math():
    aware = datetime(2026, 7, 26, 7, 30, tzinfo=timezone(timedelta(hours=2)))

    assert worker._naive_utc_timestamp(aware) == datetime(2026, 7, 26, 5, 30)
    assert worker._naive_utc_timestamp(datetime(2026, 7, 26, 5, 30)) == datetime(2026, 7, 26, 5, 30)
    assert worker._naive_utc_timestamp(None) is None


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


def test_stale_worker_requeues_original_canonical_envelope_without_private_options(monkeypatch):
    monkeypatch.setattr(worker, "_worker_build_fingerprint", lambda: "STALE_DIFFERENT")
    pushed = []
    state = {}

    class _FakeRedis:
        def rpush(self, queue, payload):
            pushed.append((queue, json.loads(payload)))

        def hget(self, _key, field):
            return state.get(field)

        def hset(self, _key, mapping):
            state.update(mapping)

    canonical = {
        "schema_version": "scan-job/v2",
        "job_id": "j1",
        "scan_id": "scan-1",
        "target": {"canonical_host": "example.test"},
    }
    job = _job(
        CURRENT_FP,
        _canonical_queue_payload=canonical,
        authentication={"auth_header": "Bearer worker-only-secret"},
    )
    job["options"]["authentication"] = job.pop("authentication")
    monkeypatch.setattr(worker, "get_redis", lambda: _FakeRedis())

    assert _run(worker._refuse_stale_job_if_needed(job)) is True
    assert pushed == [(worker.QUEUE_NAME, canonical)]
    assert "options" not in pushed[0][1]
    assert state["stale_requeue_attempts"] == 1


def test_domain_rate_retry_requeues_original_canonical_envelope_without_private_options(monkeypatch):
    pushed = []
    state = {}

    class _FakeRedis:
        def rpush(self, queue, payload):
            pushed.append((queue, json.loads(payload)))

        def hget(self, _key, field):
            return state.get(field)

        def hset(self, _key, mapping):
            state.update(mapping)

        def expire(self, *_args):
            return True

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr(worker.asyncio, "sleep", no_sleep)
    canonical = {
        "schema_version": "scan-job/v2",
        "job_id": "j1",
        "scan_id": "scan-1",
        "target": {"canonical_host": "example.test"},
    }
    materialized = {
        "job_id": "j1",
        "scan_id": "scan-1",
        "target": "https://example.test",
        "options": {"auth_header": "Bearer worker-only-secret"},
        "_canonical_queue_payload": canonical,
    }
    redis_client = _FakeRedis()

    _run(worker._requeue_for_domain_rate(
        redis_client,
        materialized,
        job_id="j1",
        scan_id="scan-1",
        log_prefix="j1",
        rate={"root_domain": "example.test", "requested": 10, "granted": 0, "cap": 5},
    ))

    assert pushed == [(worker.QUEUE_NAME, canonical)]
    assert "options" not in pushed[0][1]
    assert state["domain_rate_wait_cycles"] == "1"


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


def test_local_worker_has_a_stable_placement_identity(monkeypatch):
    monkeypatch.delenv("SHAKERSCAN_NODE_ID", raising=False)
    monkeypatch.delenv("SHAKERSCAN_NODE_LABELS_JSON", raising=False)
    worker._worker_placement_labels.cache_clear()
    try:
        labels = worker._worker_placement_labels()
        assert labels["node_id"] == "local"
        assert labels["transport"] == "local"
    finally:
        worker._worker_placement_labels.cache_clear()


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


def test_fleet_node_gate_requires_healthy_current_heartbeat_and_image(monkeypatch):
    node_id = uuid.uuid4()
    baseline = {
        "status": "healthy",
        "drain": False,
        "rollout_in_progress": False,
        "desired_state_version": 3,
        "applied_state_version": 3,
        "worker_image_digest": "scanner@sha256:" + "a" * 64,
        "active_worker_image_digest": "scanner@sha256:" + "a" * 64,
        "last_error": None,
        "heartbeat_current": True,
    }
    conn = _AttributionConnection(baseline)
    monkeypatch.setattr(worker, "db_pool", types.SimpleNamespace(acquire=lambda: _AcquireContext(conn)))
    monkeypatch.setenv("SHAKERSCAN_NODE_ID", str(node_id))

    assert _run(worker._fleet_node_accepts_work()) is True
    baseline["active_worker_image_digest"] = "scanner@sha256:" + "b" * 64
    assert _run(worker._fleet_node_accepts_work()) is False
    baseline["active_worker_image_digest"] = baseline["worker_image_digest"]
    baseline["heartbeat_current"] = False
    assert _run(worker._fleet_node_accepts_work()) is False


def test_job_execution_is_attributed_to_worker_and_fleet_node(monkeypatch):
    scan_id = uuid.uuid4()
    node_id = uuid.uuid4()
    conn = _AttributionConnection({
        "id": scan_id,
        "status": "healthy",
        "drain": False,
        "rollout_in_progress": False,
        "last_error": None,
        "desired_state_version": 2,
        "applied_state_version": 2,
        "worker_image_digest": "image@sha256:" + "a" * 64,
        "active_worker_image_digest": "image@sha256:" + "a" * 64,
    })
    monkeypatch.setattr(worker, "db_pool", types.SimpleNamespace(acquire=lambda: _AcquireContext(conn)))
    monkeypatch.setenv("WORKER_ID", "fleet-worker")
    monkeypatch.setenv("HOSTNAME", "container-123456789")
    monkeypatch.setenv("SHAKERSCAN_NODE_ID", str(node_id))

    _run(worker._attribute_job_execution({"scan_id": str(scan_id)}))

    assert len(conn.calls) == 2
    assert "FROM nodes" in conn.calls[0][0]
    assert conn.calls[0][1] == (node_id,)
    assert conn.calls[1][1][:3] == (scan_id, "fleet-worker:container-12", node_id)
    context = json.loads(conn.calls[1][1][3])
    assert context["node_id"] == str(node_id)
    assert context["worker_id"] == "fleet-worker:container-12"
    assert context["credential_scope"] == "overlay_shared_store"


def test_disabled_or_missing_fleet_node_refuses_execution(monkeypatch):
    conn = _AttributionConnection(None)
    monkeypatch.setattr(worker, "db_pool", types.SimpleNamespace(acquire=lambda: _AcquireContext(conn)))
    monkeypatch.setenv("SHAKERSCAN_NODE_ID", str(uuid.uuid4()))

    with pytest.raises(RuntimeError, match="missing or disabled"):
        _run(worker._attribute_job_execution({"scan_id": str(uuid.uuid4())}))


def test_execution_scope_revalidation_accepts_equivalent_target_and_rejects_mismatch(monkeypatch):
    scan_id = uuid.uuid4()
    conn = _AttributionConnection({
        "target_url": "https://Lab.Example.test/path",
        "status": "pending",
        "parent_status": None,
    })
    monkeypatch.setattr(worker, "db_pool", types.SimpleNamespace(acquire=lambda: _AcquireContext(conn)))

    assert _run(worker._revalidate_job_execution_scope({
        "scan_id": str(scan_id),
        "target": "https://lab.example.test:443/path#ignored",
    })) is True
    with pytest.raises(worker.ExecutionScopeError, match="does not match"):
        _run(worker._revalidate_job_execution_scope({
            "scan_id": str(scan_id),
            "target": "https://other.example.test/path",
        }))
    with pytest.raises(worker.ExecutionScopeError, match="missing"):
        _run(worker._revalidate_job_execution_scope({"scan_id": str(scan_id)}))


def test_execution_target_key_normalizes_ipv6_and_survives_invalid_port():
    assert worker._execution_target_key("HTTP://[::1]:80/lab") == "http://[::1]/lab"
    assert worker._execution_target_key("https://lab.example:bad/path") == "https://lab.example:bad/path"


def test_execution_scope_revalidation_skips_terminal_scan(monkeypatch):
    conn = _AttributionConnection({
        "target_url": "http://127.0.0.1:3001/",
        "status": "cancelled",
        "parent_status": None,
    })
    monkeypatch.setattr(worker, "db_pool", types.SimpleNamespace(acquire=lambda: _AcquireContext(conn)))
    assert _run(worker._revalidate_job_execution_scope({
        "scan_id": str(uuid.uuid4()),
        "target": "http://127.0.0.1:3001",
    })) is False


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


def test_canonical_asm_batch_materializes_inner_authority_before_dispatch(monkeypatch):
    scan_id = str(uuid.uuid4())
    target_id = str(uuid.uuid4())
    campaign_id = str(uuid.uuid4())
    endpoint_id = str(uuid.uuid4())
    dispatched = []

    async def materialize(payload):
        assert payload == {"schema_version": "scan-job/v2", "scan_id": scan_id}
        return {
            "job_id": "asm-job-v2",
            "scan_id": scan_id,
            "target": "https://example.test",
            "options": {
                "runtime_scope_guard": {"target_id": target_id},
                "scan_execution_plan": {"policy": {}, "budget": {}},
            },
            "campaign_id": campaign_id,
            "_canonical_queue_payload": payload,
        }

    async def dispatch(job):
        dispatched.append(job)

    monkeypatch.delenv("SHAKERSCAN_NODE_ID", raising=False)
    monkeypatch.setattr(worker, "_materialize_scan_job_v2", materialize)
    monkeypatch.setattr(worker, "_fleet_node_accepts_work", lambda: _async_value(True))
    monkeypatch.setattr(worker, "_refuse_stale_job_if_needed", lambda _job: _async_value(False))
    monkeypatch.setattr(worker, "_attribute_job_execution", lambda _job: _async_value(None))
    monkeypatch.setattr(worker, "process_exploit_batch_job", dispatch)

    outer = {
        "type": worker.asm_inventory.EXPLOIT_BATCH_JOB_TYPE,
        "job_id": "asm-job-v2",
        "scan_id": scan_id,
        "target_id": target_id,
        "campaign_id": campaign_id,
        "claimed_endpoint_ids": [endpoint_id],
        "scan_job": {"schema_version": "scan-job/v2", "scan_id": scan_id},
    }
    _run(worker.process_job(outer))

    assert len(dispatched) == 1
    admitted = dispatched[0]
    assert admitted["claimed_endpoint_ids"] == [endpoint_id]
    assert admitted["options"]["runtime_scope_guard"]["target_id"] == target_id
    assert admitted["_canonical_asm_queue_payload"] == outer
    assert admitted["_canonical_queue_payload"] == outer["scan_job"]


def test_execution_contract_refusal_terminalizes_without_queue_retry(monkeypatch):
    terminal = []

    async def reject(_job):
        raise worker.ExecutionScopeError(
            "canonical parallel action partition rejected: unauthorized action"
        )

    async def fail(job, message, *, phase="scope_revalidation_failed"):
        terminal.append((job["scan_id"], message, phase))

    monkeypatch.delenv("SHAKERSCAN_NODE_ID", raising=False)
    monkeypatch.setattr(worker, "_fleet_node_accepts_work", lambda: _async_value(True))
    monkeypatch.setattr(worker, "_refuse_stale_job_if_needed", lambda _job: _async_value(False))
    monkeypatch.setattr(worker, "_attribute_job_execution", lambda _job: _async_value(None))
    monkeypatch.setattr(worker, "process_scan_plan_job", reject)
    monkeypatch.setattr(worker, "_fail_execution_scope", fail)

    scan_id = str(uuid.uuid4())
    _run(worker.process_job({
        "type": worker.parallel_scan.PLAN_JOB_TYPE,
        "job_id": "plan-contract-refusal",
        "scan_id": scan_id,
    }))

    assert terminal == [(
        scan_id,
        "canonical parallel action partition rejected: unauthorized action",
        "execution_contract_failed",
    )]


async def _async_value(value):
    return value


def test_stream_lease_is_acknowledged_only_after_successful_dispatch(monkeypatch):
    calls = []

    async def dispatch(job):
        calls.append(("dispatch", job["job_id"]))

    def acknowledge(_redis, lease):
        calls.append(("ack", lease.message_id))
        return True

    monkeypatch.setattr(worker, "process_job", dispatch)
    monkeypatch.setattr(worker, "acknowledge_lease", acknowledge)
    lease = worker.QueueLease(
        queue_name=worker.QUEUE_NAME,
        payload='{"job_id":"job-1"}',
        stream_key="scan_jobs:leased",
        message_id="1-0",
    )

    _run(worker._run_job_under_lease(object(), lease, {"job_id": "job-1"}))

    assert calls == [("dispatch", "job-1"), ("ack", "1-0")]


def test_failed_dispatch_remains_pending_for_reclaim(monkeypatch):
    acknowledged = []

    async def fail(_job):
        raise RuntimeError("worker crashed")

    monkeypatch.setattr(worker, "process_job", fail)
    monkeypatch.setattr(worker, "acknowledge_lease", lambda *_args: acknowledged.append(True))
    lease = worker.QueueLease(
        queue_name=worker.QUEUE_NAME,
        payload='{"job_id":"job-2"}',
        stream_key="scan_jobs:leased",
        message_id="2-0",
    )

    with pytest.raises(RuntimeError, match="worker crashed"):
        _run(worker._run_job_under_lease(object(), lease, {"job_id": "job-2"}))

    assert acknowledged == []


def test_failed_dispatch_preserves_the_actionable_delivery_error(monkeypatch):
    class Redis:
        def __init__(self):
            self.values = {}

        def hset(self, key, mapping):
            self.values[key] = dict(mapping)

    async def fail(_job):
        raise RuntimeError(
            "parallel child introduced an action outside parent authority"
        )

    redis_client = Redis()
    monkeypatch.setattr(worker, "process_job", fail)
    lease = worker.QueueLease(
        queue_name=worker.QUEUE_NAME,
        payload='{"job_id":"job-detail"}',
        stream_key="scan_jobs:leased",
        message_id="2-1",
        delivery_attempts=3,
    )

    with pytest.raises(RuntimeError, match="outside parent authority"):
        _run(worker._run_job_under_lease(
            redis_client, lease, {"job_id": "job-detail"},
        ))

    assert redis_client.values["job:job-detail"] == {
        "last_delivery_error": (
            "parallel child introduced an action outside parent authority"
        ),
        "last_delivery_error_type": "RuntimeError",
        "last_delivery_attempt": "3",
    }


def test_lost_stream_lease_cancels_stale_execution(monkeypatch):
    async def never_finishes(_job):
        await asyncio.Future()

    async def immediate_sleep(_seconds):
        return None

    monkeypatch.setattr(worker, "process_job", never_finishes)
    monkeypatch.setattr(worker, "heartbeat_lease", lambda *_args: False)
    monkeypatch.setattr(worker.asyncio, "sleep", immediate_sleep)
    lease = worker.QueueLease(
        queue_name=worker.QUEUE_NAME,
        payload='{"job_id":"job-3"}',
        stream_key="scan_jobs:leased",
        message_id="3-0",
    )

    with pytest.raises(asyncio.CancelledError):
        _run(worker._run_job_under_lease(object(), lease, {"job_id": "job-3"}))
