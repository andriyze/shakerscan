"""
Tests for scan-time AI command/env gating in worker.run_scan.
"""

import asyncio
import json
import os
import sys
import types
import uuid
from datetime import datetime, timezone



sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace())
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *args, **kwargs: None))

import worker  # noqa: E402


class _FakeProcess:
    def __init__(self, stdout_payload: bytes, stderr_payload: bytes = b""):
        self.stdout = asyncio.StreamReader()
        self.stdout.feed_data(stdout_payload)
        self.stdout.feed_eof()

        self.stderr = asyncio.StreamReader()
        if stderr_payload:
            self.stderr.feed_data(stderr_payload)
        self.stderr.feed_eof()
        self.returncode = 0

    async def wait(self):
        return self.returncode


class _CancellableFakeProcess:
    def __init__(self):
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.returncode = None
        self.terminated = False
        self.killed = False
        self._done = asyncio.Event()

    def terminate(self):
        self.terminated = True
        self.returncode = -15
        self.stdout.feed_eof()
        self.stderr.feed_eof()
        self._done.set()

    def kill(self):
        self.killed = True
        self.returncode = -9
        self.stdout.feed_eof()
        self.stderr.feed_eof()
        self._done.set()

    async def wait(self):
        await self._done.wait()
        return self.returncode


class _FakeCredentialPool:
    async def fetchrow(self, query, target_id):
        return {
            "auth_kind": "bearer",
            "header_name": None,
            "secret_value": "runtime-target-secret",
            "metadata_json": {},
        }

    async def fetch(self, query, target_id):
        return []


class _FakePrincipalPool(_FakeCredentialPool):
    async def fetch(self, query, target_id):
        return [
            {
                "id": "00000000-0000-0000-0000-000000000010",
                "label": "tenant-a-user",
                "role": "attacker",
                "tenant_id": "tenant-a",
                "auth_kind": "bearer",
                "header_name": None,
                "secret_value": "principal-runtime-secret",
                "metadata_json": {"purpose": "cross-tenant"},
            }
        ]


class _FakeFinalizeConnection:
    def __init__(self):
        self.executions = []

    async def execute(self, query, *args):
        self.executions.append((query, args))


class _FakeFinalizePool:
    def __init__(self):
        self.conn = _FakeFinalizeConnection()

    def acquire(self):
        return self

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeSlotRedis:
    def __init__(self):
        self.values = {}
        self.expired = []
        self.deleted = []

    def incr(self, key):
        self.values[key] = int(self.values.get(key, 0)) + 1
        return self.values[key]

    def decr(self, key):
        self.values[key] = int(self.values.get(key, 0)) - 1
        return self.values[key]

    def expire(self, key, ttl):
        self.expired.append((key, ttl))

    def delete(self, key):
        self.deleted.append(key)
        self.values.pop(key, None)


class _FakeJobRedis:
    def __init__(self):
        self.hashes = []
        self.expired = []
        self.values = {}
        self.pushed = []
        self.sets = []
        self.deleted = []

    def hset(self, key, *args, mapping=None):
        self.hashes.append((key, args, dict(mapping or {})))

    def expire(self, key, ttl):
        self.expired.append((key, ttl))

    def incr(self, key):
        self.values[key] = int(self.values.get(key, 0)) + 1
        return self.values[key]

    def decr(self, key):
        self.values[key] = int(self.values.get(key, 0)) - 1
        return self.values[key]

    def rpush(self, key, value):
        self.pushed.append((key, value))
        return len(self.pushed)

    def set(self, key, value, nx=False, ex=None):
        self.sets.append((key, value, nx, ex))
        self.values[key] = value
        return True

    def delete(self, key):
        self.deleted.append(key)
        self.values.pop(key, None)


class _FakeCancelRedis:
    def __init__(self, cancelled: bool):
        self.cancelled = cancelled

    def get(self, key):
        return b"1" if self.cancelled else None


class _FakeAsmConn:
    def __init__(self, *, child_status="running", parent_status="running", running_update_result="UPDATE 1"):
        self.executions = []
        self.child_status = child_status
        self.parent_status = parent_status
        self.running_update_result = running_update_result

    async def execute(self, query, *args):
        self.executions.append((query, args))
        if "UPDATE scans SET status='running'" in query and "asm_exploit" in query:
            return self.running_update_result
        return "UPDATE 1"

    async def fetchrow(self, query, *args):
        if "LEFT JOIN scans parent" in query:
            return {"status": self.child_status, "parent_status": self.parent_status}
        return {"status": self.child_status}


class _FakeAsmPool:
    def __init__(self, conn=None):
        self.conn = conn or _FakeAsmConn()

    def acquire(self):
        return self

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakePlanConn:
    def __init__(self, parent_id, target_id, campaign_id):
        self.parent_id = parent_id
        self.target_id = target_id
        self.campaign_id = campaign_id
        self.executions = []
        self.inserted_children = []

    async def fetchrow(self, query, *args):
        if "SELECT target_id, target_url, status FROM scans" in query:
            return {
                "target_id": self.target_id,
                "target_url": "https://example.test",
                "status": "pending",
            }
        return None

    async def fetchval(self, query, *args):
        if "INSERT INTO scan_campaigns" in query:
            return self.campaign_id
        return None

    async def execute(self, query, *args):
        self.executions.append((query, args))
        if "INSERT INTO scans" in query:
            self.inserted_children.append(args)
        return "UPDATE 1"


class _FakePlanPool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return self

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, exc_type, exc, tb):
        return False


def test_parallel_shard_slots_enforce_parent_concurrency(monkeypatch):
    monkeypatch.setattr(worker, "PARALLEL_SHARD_MAX_PER_PARENT", 2)
    monkeypatch.setattr(worker, "PARALLEL_SHARD_CONCURRENCY_HARD_MAX", 5)
    r = _FakeSlotRedis()
    parent_id = "parent-1"

    first, limit = worker._try_acquire_parallel_shard_slot(r, parent_id, {})
    second, _ = worker._try_acquire_parallel_shard_slot(r, parent_id, {})
    third, _ = worker._try_acquire_parallel_shard_slot(r, parent_id, {})

    assert first is True
    assert second is True
    assert third is False
    assert limit == 2
    assert r.values[worker._parallel_shard_slot_key(parent_id)] == 2

    worker._release_parallel_shard_slot(r, parent_id)
    fourth, _ = worker._try_acquire_parallel_shard_slot(r, parent_id, {})
    assert fourth is True
    assert r.values[worker._parallel_shard_slot_key(parent_id)] == 2


def test_parallel_shard_concurrency_override_is_clamped(monkeypatch):
    monkeypatch.setattr(worker, "PARALLEL_SHARD_MAX_PER_PARENT", 4)
    monkeypatch.setattr(worker, "PARALLEL_SHARD_CONCURRENCY_HARD_MAX", 8)

    assert worker._parallel_shard_concurrency_limit({}) == 4
    assert worker._parallel_shard_concurrency_limit({"shard_concurrency": 6}) == 6
    assert worker._parallel_shard_concurrency_limit({"parallel_shard_concurrency": 99}) == 8
    assert worker._parallel_shard_concurrency_limit({"shard_concurrency": 0}) == 1


def test_hydrate_ai_gate_options_loads_secrets_only_in_worker(monkeypatch):
    target_id = "00000000-0000-0000-0000-000000000001"
    monkeypatch.setattr(worker, "db_pool", _FakeCredentialPool())
    monkeypatch.setattr(
        worker,
        "_load_runtime_ai_settings",
        lambda: {
            "ai_url": "https://ai.example/v1/chat/completions",
            "ai_api_key": "runtime-ai-key",
            "ai_model": "model-a",
            "ai_model_fallback": "",
        },
    )

    options = {
        "run_kind": "ai_api",
        "ai_target_id": target_id,
        "ai_target": {
            "id": target_id,
            "endpoint_url": "https://example.test/chat",
            "credential_ref": {"ai_target_id": target_id, "configured": True},
        },
    }

    hydrated = asyncio.run(worker._hydrate_ai_gate_options(options))

    assert hydrated["ai_target"]["credential"]["secret"] == "runtime-target-secret"
    assert "credential_ref" not in hydrated["ai_target"]
    assert hydrated["ai_api_key"] == "runtime-ai-key"


def test_hydrate_ai_gate_options_loads_principal_credentials_in_worker(monkeypatch):
    target_id = "00000000-0000-0000-0000-000000000001"
    monkeypatch.setattr(worker, "db_pool", _FakePrincipalPool())
    monkeypatch.setattr(worker, "_load_runtime_ai_settings", lambda: {})

    options = {
        "run_kind": "ai_rag",
        "ai_target_id": target_id,
        "ai_target": {
            "id": target_id,
            "endpoint_url": "https://example.test/rag",
            "credential_ref": {"ai_target_id": target_id, "configured": True},
            "principal_refs": [
                {
                    "id": "00000000-0000-0000-0000-000000000010",
                    "label": "tenant-a-user",
                    "role": "attacker",
                    "credential_configured": True,
                }
            ],
        },
    }

    hydrated = asyncio.run(worker._hydrate_ai_gate_options(options))

    assert hydrated["ai_target"]["principals"][0]["credential"]["secret"] == "principal-runtime-secret"
    assert hydrated["ai_target"]["principals"][0]["role"] == "attacker"
    assert "principal_refs" not in hydrated["ai_target"]


def test_finalize_ai_finding_retest_marks_reproduced_finding(monkeypatch):
    pool = _FakeFinalizePool()
    monkeypatch.setattr(worker, "db_pool", pool)
    verification_id = "00000000-0000-0000-0000-000000000002"
    finding_id = "00000000-0000-0000-0000-000000000003"

    asyncio.run(worker.finalize_ai_finding_retest(
        options={
            "ai_finding_retest": {
                "verification_id": verification_id,
                "finding_id": finding_id,
                "mode": "same_probe",
                "probe_id": "smoke.prompt-leakage",
                "probe_family": "prompt_leakage",
            }
        },
        result={
            "findings": [
                {
                    "confidence": 0.93,
                    "evidence": {"probe_id": "smoke.prompt-leakage", "probe_family": "prompt_leakage"},
                }
            ],
            "ai_gate": {"errors": [], "transcripts": [], "decision": {"decision": "block"}},
        },
        scan_id="00000000-0000-0000-0000-000000000004",
        completed_at=datetime.now(timezone.utc),
        error=None,
    ))

    verification_update = pool.conn.executions[0][1]
    finding_update = pool.conn.executions[1][1]
    assert verification_update[0] == "completed"
    assert verification_update[1] == "still_vulnerable"
    assert verification_update[2] == "exploited"
    assert finding_update[1] == "exploited"


def test_run_scan_rejects_invalid_explicit_scan_type():
    try:
        asyncio.run(worker.run_scan("https://example.com", {"scan_type": "standard-ish"}))
    except ValueError as exc:
        assert "scan_type must be one of" in str(exc)
    else:
        raise AssertionError("invalid scan_type should be rejected before scanner subprocess starts")


def test_run_scan_maps_explicit_standard_to_standard_flag(monkeypatch):
    captured = {}

    async def _fake_create_subprocess_exec(*cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["kwargs"] = dict(kwargs)
        return _FakeProcess(b'{"ok": true, "findings": []}')

    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", _fake_create_subprocess_exec)
    monkeypatch.setattr(worker, "_load_runtime_ai_settings", lambda: {})

    result = asyncio.run(worker.run_scan("https://example.com", {"scan_type": "standard"}))

    assert result.get("ok") is True
    assert "--standard" in captured["cmd"]
    assert "--quick" not in captured["cmd"]
    if worker.os.name == "posix":
        assert captured["kwargs"]["start_new_session"] is True


def test_run_scan_maps_asm_check_family_to_scanner_flag(monkeypatch):
    captured = {}

    async def _fake_create_subprocess_exec(*cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return _FakeProcess(b'{"ok": true, "findings": []}')

    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", _fake_create_subprocess_exec)
    monkeypatch.setattr(worker, "_load_runtime_ai_settings", lambda: {})

    result = asyncio.run(worker.run_scan(
        "https://example.com",
        {"scan_type": "smart", "asm_check_family": "sqli", "sqli": True, "xss": False},
    ))

    assert result.get("ok") is True
    assert "--check-family" in captured["cmd"]
    assert captured["cmd"][captured["cmd"].index("--check-family") + 1] == "sqli"
    assert "--sqli" in captured["cmd"]
    assert "--xss" not in captured["cmd"]


def test_run_scan_terminates_subprocess_when_scan_cancel_flag_is_set(monkeypatch):
    captured = {}

    async def _fake_create_subprocess_exec(*cmd, **kwargs):
        proc = _CancellableFakeProcess()
        captured["proc"] = proc
        return proc

    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", _fake_create_subprocess_exec)
    monkeypatch.setattr(worker, "_load_runtime_ai_settings", lambda: {})
    monkeypatch.setattr(worker, "get_redis", lambda: _FakeCancelRedis(cancelled=True))
    monkeypatch.setattr(worker, "SCAN_CANCEL_POLL_SECONDS", 0.01)

    result = asyncio.run(worker.run_scan(
        "https://example.com",
        {"scan_type": "standard"},
        scan_id="00000000-0000-0000-0000-000000000123",
        job_id="job-cancel-test",
    ))

    proc = captured["proc"]
    assert proc.terminated is True
    assert proc.killed is False
    assert result["error"] == "Cancelled by user"


def test_run_scan_maps_skip_global_checks_flag(monkeypatch):
    captured = {}

    async def _fake_create_subprocess_exec(*cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return _FakeProcess(b'{"ok": true, "findings": []}')

    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", _fake_create_subprocess_exec)
    monkeypatch.setattr(worker, "_load_runtime_ai_settings", lambda: {})

    result = asyncio.run(worker.run_scan(
        "https://example.com",
        {
            "scan_type": "smart",
            "skip_global_checks": True,
            "focused_endpoints_only": True,
            "zero_rediscovery": True,
        },
    ))

    assert result.get("ok") is True
    assert "--skip-global-checks" in captured["cmd"]
    assert "--focused-endpoints-only" in captured["cmd"]
    assert "--zero-rediscovery" in captured["cmd"]


def test_run_scan_maps_active_worklist_budget_flag(monkeypatch):
    captured = {}

    async def _fake_create_subprocess_exec(*cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return _FakeProcess(b'{"ok": true, "findings": []}')

    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", _fake_create_subprocess_exec)
    monkeypatch.setattr(worker, "_load_runtime_ai_settings", lambda: {})

    result = asyncio.run(worker.run_scan(
        "https://example.com",
        {"scan_type": "smart", "custom_budget": {"active_worklist_max": 50000}},
    ))

    assert result.get("ok") is True
    assert "--budget-active-worklist-max" in captured["cmd"]
    assert captured["cmd"][captured["cmd"].index("--budget-active-worklist-max") + 1] == "50000"


def test_active_endpoint_attempts_from_report_filters_valid_entries():
    attempts = worker._active_endpoint_attempts_from_report(
        {
            "active_checks": {
                "endpoint_attempts": [
                    {"custom_endpoint": "GET /a?id=1", "status": "completed"},
                    {"status": "completed"},
                    "not-a-dict",
                ]
            }
        }
    )

    assert attempts == [{"custom_endpoint": "GET /a?id=1", "status": "completed"}]


def test_active_endpoint_telemetry_present_for_empty_attempt_list():
    report = {"active_checks": {"per_endpoint_telemetry": True, "endpoint_attempts": []}}

    assert worker._active_endpoint_telemetry_present(report) is True
    assert worker._active_endpoint_attempts_from_report(report) == []


def test_ledger_status_from_endpoint_attempt_maps_time_budget_to_timeout():
    status, summary = worker._ledger_status_from_endpoint_attempt(
        {
            "custom_endpoint": "GET /a?id=1",
            "status": "partial",
            "budget_exhausted_reason": "time_budget",
        }
    )

    assert status == "timeout"
    assert summary == "time_budget"


def test_record_endpoint_telemetry_attempts_uses_per_endpoint_counts(monkeypatch):
    calls = {}
    endpoint_id = "11111111-1111-1111-1111-111111111111"

    async def fake_endpoint_ids_for_worklist(conn, target_id, worklist, *, auth_state, limit=20000):
        calls["resolved"] = {
            "target_id": target_id,
            "worklist": worklist,
            "auth_state": auth_state,
        }
        return [endpoint_id]

    async def fake_record_endpoint_attempts(conn, endpoint_ids, **kwargs):
        calls["record"] = {"endpoint_ids": endpoint_ids, **kwargs}
        return len(endpoint_ids)

    monkeypatch.setattr(worker.asm_inventory, "endpoint_ids_for_worklist", fake_endpoint_ids_for_worklist)
    monkeypatch.setattr(worker.asm_inventory, "record_endpoint_attempts", fake_record_endpoint_attempts)

    result = asyncio.run(
        worker._record_endpoint_telemetry_attempts(
            object(),
            target_id="target-1",
            attempts=[
                {
                    "custom_endpoint": "GET /a?id=1",
                    "status": "completed",
                    "attempted_params_count": 1,
                    "completed_params_count": 1,
                }
            ],
            scan_id="scan-1",
            campaign_id="campaign-1",
            auth_state="user1",
            source="test",
        )
    )

    assert result["written"] == 1
    assert result["completed_ids"] == [endpoint_id]
    assert calls["resolved"] == {
        "target_id": "target-1",
        "worklist": ["GET /a?id=1"],
        "auth_state": "user1",
    }
    assert calls["record"]["status"] == "completed"
    assert calls["record"]["attempted_params_count"] == 1
    assert calls["record"]["completed_params_count"] == 1
    assert calls["record"]["scanner_telemetry_json"]["per_endpoint_telemetry"] is True


def test_apply_campaign_coverage_rollup_preserves_assignment_context():
    merged = {
        "smart_coverage": {
            "endpoints": {
                "discovered": 3,
                "tested": 2,
                "coverage": 0.667,
                "basis": "assigned_custom_endpoints",
            },
            "aggregated_from_shards": 2,
        }
    }
    campaign = {
        "total": 3,
        "attempted": 3,
        "completed": 1,
        "tested": 1,
        "untested": 0,
        "partial": 2,
        "auth_blocked": 0,
        "rate_limited": 0,
        "error": 0,
        "coverage": 0.333,
        "basis": "campaign_attempt_ledger",
    }

    assert worker._apply_campaign_coverage_rollup(merged, campaign) is True

    smart = merged["smart_coverage"]
    assert smart["coverage_basis"] == "attempt_ledger"
    assert smart["endpoints"] == campaign
    assert smart["endpoint_assignment_rollup"]["basis"] == "assigned_custom_endpoints"
    assert smart["aggregated_from_shards"] == 2


def test_apply_campaign_coverage_rollup_ignores_empty_attempts():
    merged = {"smart_coverage": {"endpoints": {"basis": "assigned_custom_endpoints"}}}

    assert worker._apply_campaign_coverage_rollup(merged, {"attempted": 0}) is False
    assert merged["smart_coverage"]["endpoints"]["basis"] == "assigned_custom_endpoints"


def test_scan_plan_dynamic_coverage_enqueues_campaign_batch_children(monkeypatch):
    parent_id = "55555555-5555-5555-5555-555555555555"
    target_id = uuid.UUID("33333333-3333-3333-3333-333333333333")
    campaign_id = uuid.UUID("44444444-4444-4444-4444-444444444444")
    conn = _FakePlanConn(parent_id, target_id, campaign_id)
    redis = _FakeJobRedis()

    async def fake_run_scan(target, options, *, scan_id=None, job_id=None):
        return {
            "target": target,
            "findings": [],
            "active_checks": {
                "active_worklist": [
                    "GET /api/a?id=1",
                    "GET /api/b?id=1",
                    "GET /api/c?id=1",
                    "GET /api/d?id=1",
                ]
            },
        }

    monkeypatch.setattr(worker, "db_pool", _FakePlanPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker, "run_scan", fake_run_scan)

    asyncio.run(
        worker.process_scan_plan_job(
            {
                "job_id": "parent-job",
                "scan_id": parent_id,
                "target": "https://example.test",
                "options": {
                    "scan_type": "smart",
                    "parallel": True,
                    "shard_strategy": "coverage",
                    "coverage_allocation": "dynamic",
                    "coverage_dynamic_batch_size": 2,
                },
            }
        )
    )

    child_jobs = [json.loads(payload) for _, payload in redis.pushed]
    assert len(child_jobs) == 2
    assert {job["type"] for job in child_jobs} == {worker.asm_inventory.EXPLOIT_BATCH_JOB_TYPE}
    for job in child_jobs:
        assert job["parent_scan_id"] == parent_id
        assert job["campaign_id"] == str(campaign_id)
        assert job["target_id"] == str(target_id)
        assert job["batch_size"] == 2
        assert job["stale_days"] == 0
        assert job["campaign_only"] is True
        assert job["finish_campaign_on_complete"] is False
        assert job["options"]["coverage_dynamic_worker"] is True
        assert job["options"]["zero_rediscovery"] is True
        assert "custom_endpoints" not in job["options"]
    assert redis.sets[0][0] == worker.parallel_scan.shards_remaining_key(parent_id)
    assert redis.sets[0][1] == 2
    parent_update = [
        args for query, args in conn.executions
        if "UPDATE scans SET status = 'running'" in query and "shard_count" in query
    ][0]
    parent_options = json.loads(parent_update[3])
    assert parent_options["parallel_strategy"] == "coverage"
    assert parent_options["coverage_allocation"] == "dynamic"
    assert parent_options["campaign_id"] == str(campaign_id)


def test_scan_plan_coverage_defaults_to_dynamic_allocation(monkeypatch):
    parent_id = "56565656-5656-5656-5656-565656565656"
    target_id = uuid.UUID("34343434-3434-3434-3434-343434343434")
    campaign_id = uuid.UUID("45454545-4545-4545-4545-454545454545")
    conn = _FakePlanConn(parent_id, target_id, campaign_id)
    redis = _FakeJobRedis()
    monkeypatch.delenv("COVERAGE_ALLOCATION_DEFAULT", raising=False)
    monkeypatch.delenv("FULL_COVERAGE_ALLOCATION_DEFAULT", raising=False)

    async def fake_run_scan(target, options, *, scan_id=None, job_id=None):
        return {
            "target": target,
            "findings": [],
            "active_checks": {
                "active_worklist": [
                    "GET /api/a?id=1",
                    "GET /api/b?id=1",
                    "GET /api/c?id=1",
                    "GET /api/d?id=1",
                ]
            },
        }

    monkeypatch.setattr(worker, "db_pool", _FakePlanPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker, "run_scan", fake_run_scan)

    asyncio.run(
        worker.process_scan_plan_job(
            {
                "job_id": "parent-job-default-dynamic",
                "scan_id": parent_id,
                "target": "https://example.test",
                "options": {
                    "scan_type": "smart",
                    "parallel": True,
                    "shard_strategy": "coverage",
                    "coverage_dynamic_batch_size": 2,
                },
            }
        )
    )

    child_jobs = [json.loads(payload) for _, payload in redis.pushed]
    assert len(child_jobs) == 2
    assert {job["type"] for job in child_jobs} == {worker.asm_inventory.EXPLOIT_BATCH_JOB_TYPE}
    assert all(job["options"]["coverage_dynamic_worker"] is True for job in child_jobs)
    parent_update = [
        args for query, args in conn.executions
        if "UPDATE scans SET status = 'running'" in query and "shard_count" in query
    ][0]
    parent_options = json.loads(parent_update[3])
    assert parent_options["coverage_allocation"] == "dynamic"
    assert parent_options["campaign_id"] == str(campaign_id)


def test_exploit_batch_without_endpoint_telemetry_marks_partial_not_tested(monkeypatch):
    endpoint_id = "11111111-1111-1111-1111-111111111111"
    calls = {"mark_partial": [], "record": []}

    async def fake_claim_test_batch(conn, target_id, **kwargs):
        return [
            {
                "id": endpoint_id,
                "method": "GET",
                "path": "/api/users",
                "param_shape": "id",
                "auth_state": "anonymous",
                "param_location": "query",
                "replay_spec": None,
            }
        ]

    async def fake_run_scan(target, options, *, scan_id=None, job_id=None):
        assert options["custom_endpoints"] == ["GET /api/users?id=1"]
        return {
            "target": target,
            "findings": [],
            "result": {"score": 95, "grade": "A"},
            "active_checks": {},
        }

    async def fake_mark_partial(conn, endpoint_ids, *, verdict):
        calls["mark_partial"].append({"endpoint_ids": endpoint_ids, "verdict": verdict})

    async def fake_mark_tested(*args, **kwargs):
        raise AssertionError("no-telemetry ASM batch must not mark endpoints tested")

    async def fake_record_endpoint_attempts(conn, endpoint_ids, **kwargs):
        calls["record"].append({"endpoint_ids": endpoint_ids, **kwargs})
        return len(endpoint_ids)

    async def fake_finish_campaign(*args, **kwargs):
        return 1

    async def fake_upsert_endpoints(*args, **kwargs):
        return 0

    monkeypatch.setattr(worker, "db_pool", _FakeAsmPool())
    monkeypatch.setattr(worker, "get_redis", lambda: _FakeJobRedis())
    monkeypatch.setattr(worker, "save_result_file", lambda result, job_id: f"/tmp/{job_id}.json")
    monkeypatch.setattr(worker, "run_scan", fake_run_scan)
    monkeypatch.setattr(worker.asm_inventory, "claim_test_batch", fake_claim_test_batch)
    monkeypatch.setattr(worker.asm_inventory, "mark_partial", fake_mark_partial)
    monkeypatch.setattr(worker.asm_inventory, "mark_tested", fake_mark_tested)
    monkeypatch.setattr(worker.asm_inventory, "record_endpoint_attempts", fake_record_endpoint_attempts)
    monkeypatch.setattr(worker.asm_inventory, "finish_campaign", fake_finish_campaign)
    monkeypatch.setattr(worker.asm_inventory, "upsert_endpoints", fake_upsert_endpoints)

    asyncio.run(
        worker.process_exploit_batch_job(
            {
                "job_id": "job-no-telemetry",
                "scan_id": "22222222-2222-2222-2222-222222222222",
                "target_id": "33333333-3333-3333-3333-333333333333",
                "target": "https://example.test",
                "options": {"scan_type": "smart"},
                "campaign_id": "44444444-4444-4444-4444-444444444444",
                "batch_size": 1,
            }
        )
    )

    assert calls["mark_partial"] == [
        {"endpoint_ids": [endpoint_id], "verdict": "missing_endpoint_telemetry"}
    ]
    assert len(calls["record"]) == 1
    record = calls["record"][0]
    assert record["endpoint_ids"] == [endpoint_id]
    assert record["status"] == "partial"
    assert record["attempted_params_count"] == 0
    assert record["completed_params_count"] == 0
    assert record["error_summary"] == "completed_without_endpoint_telemetry"
    assert record["scanner_telemetry_json"]["per_endpoint_telemetry"] is False
    assert record["scanner_telemetry_json"]["completed_without_endpoint_telemetry"] is True


def test_dynamic_coverage_batch_records_parent_attempts_and_reconciles(monkeypatch):
    endpoint_id = "11111111-1111-1111-1111-111111111111"
    calls = {"claim": None, "run": None, "record": None, "mark_tested": None, "reconcile": None}
    redis = _FakeJobRedis()

    async def fake_claim_test_batch(conn, target_id, **kwargs):
        calls["claim"] = {"target_id": target_id, **kwargs}
        return [
            {
                "id": endpoint_id,
                "method": "GET",
                "path": "/api/users",
                "param_shape": "id",
                "auth_state": "anonymous",
                "param_location": "query",
                "replay_spec": None,
            }
        ]

    async def fake_run_scan(target, options, *, scan_id=None, job_id=None):
        calls["run"] = dict(options)
        assert options["custom_endpoints"] == ["GET /api/users?id=1"]
        return {
            "target": target,
            "findings": [{"title": "Proof", "severity": "high", "tool": "test"}],
            "result": {"score": 80, "grade": "B"},
            "active_checks": {
                "per_endpoint_telemetry": True,
                "endpoint_attempts": [
                    {
                        "custom_endpoint": "GET /api/users?id=1",
                        "status": "completed",
                        "attempted_params_count": 1,
                        "completed_params_count": 1,
                    }
                ],
            },
        }

    async def fake_record_endpoint_telemetry_attempts(conn, **kwargs):
        calls["record"] = kwargs
        return {"written": 1, "completed_ids": [endpoint_id], "partial_ids": [], "error_ids": []}

    async def fake_mark_tested(conn, endpoint_ids, *, verdict):
        calls["mark_tested"] = {"endpoint_ids": endpoint_ids, "verdict": verdict}

    async def fake_reconcile(conn, parent_id, r, queue_name):
        calls["reconcile"] = {"parent_id": parent_id, "queue_name": queue_name}
        return True

    async def fake_upsert_endpoints(*args, **kwargs):
        return 0

    monkeypatch.setattr(worker, "db_pool", _FakeAsmPool())
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker, "save_result_file", lambda result, job_id: f"/tmp/{job_id}.json")
    monkeypatch.setattr(worker, "run_scan", fake_run_scan)
    monkeypatch.setattr(worker, "save_findings", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("parent merge owns findings")))
    monkeypatch.setattr(worker.asm_inventory, "claim_test_batch", fake_claim_test_batch)
    monkeypatch.setattr(worker, "_record_endpoint_telemetry_attempts", fake_record_endpoint_telemetry_attempts)
    monkeypatch.setattr(worker.asm_inventory, "mark_tested", fake_mark_tested)
    monkeypatch.setattr(worker.asm_inventory, "upsert_endpoints", fake_upsert_endpoints)
    monkeypatch.setattr(worker.parallel_scan, "reconcile_parallel_parent", fake_reconcile)

    asyncio.run(
        worker.process_exploit_batch_job(
            {
                "job_id": "job-dynamic-coverage",
                "scan_id": "22222222-2222-2222-2222-222222222222",
                "parent_scan_id": "55555555-5555-5555-5555-555555555555",
                "target_id": "33333333-3333-3333-3333-333333333333",
                "target": "https://example.test",
                "campaign_id": "44444444-4444-4444-4444-444444444444",
                "batch_size": 1,
                "stale_days": 0,
                "campaign_only": True,
                "finish_campaign_on_complete": False,
                "options": {
                    "scan_type": "smart",
                    "coverage_dynamic_worker": True,
                    "coverage_dynamic_campaign_only": True,
                    "coverage_dynamic_batch_size": 1,
                },
            }
        )
    )

    assert calls["claim"]["campaign_only"] is True
    assert calls["claim"]["limit"] == 1
    assert calls["claim"]["stale_days"] == 0
    assert calls["run"]["zero_rediscovery"] is True
    assert calls["run"]["focused_endpoints_only"] is True
    assert calls["run"]["skip_global_checks"] is True
    assert calls["run"]["custom_budget"]["nuclei_max_targets"] == 0
    assert calls["record"]["parent_scan_id"] == "55555555-5555-5555-5555-555555555555"
    assert calls["record"]["campaign_id"] == "44444444-4444-4444-4444-444444444444"
    assert calls["record"]["source"] == "dynamic_full_coverage_batch"
    assert calls["mark_tested"] == {"endpoint_ids": [endpoint_id], "verdict": "findings"}
    assert calls["reconcile"]["parent_id"] == "55555555-5555-5555-5555-555555555555"
    assert worker._parallel_shard_slot_key("55555555-5555-5555-5555-555555555555") not in redis.values


def test_dynamic_coverage_batch_parent_cancelled_before_claim_does_not_claim(monkeypatch):
    calls = {"claim": 0, "reconcile": None}
    redis = _FakeJobRedis()
    conn = _FakeAsmConn(child_status="pending", parent_status="cancelled")

    async def fake_claim_test_batch(*args, **kwargs):
        calls["claim"] += 1
        return []

    async def fake_reconcile(conn, parent_id, r, queue_name):
        calls["reconcile"] = {"parent_id": parent_id, "queue_name": queue_name}
        return False

    monkeypatch.setattr(worker, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker.asm_inventory, "claim_test_batch", fake_claim_test_batch)
    monkeypatch.setattr(worker.parallel_scan, "reconcile_parallel_parent", fake_reconcile)

    asyncio.run(
        worker.process_exploit_batch_job(
            {
                "job_id": "job-cancelled-dynamic",
                "scan_id": "22222222-2222-2222-2222-222222222222",
                "parent_scan_id": "55555555-5555-5555-5555-555555555555",
                "target_id": "33333333-3333-3333-3333-333333333333",
                "target": "https://example.test",
                "campaign_id": "44444444-4444-4444-4444-444444444444",
                "batch_size": 1,
                "campaign_only": True,
                "finish_campaign_on_complete": False,
                "options": {"scan_type": "smart", "coverage_dynamic_worker": True},
            }
        )
    )

    assert calls["claim"] == 0
    assert any("Cancelled by parent scan" in query for query, args in conn.executions)
    assert redis.hashes[-1][2]["status"] == "cancelled"
    assert calls["reconcile"]["parent_id"] == "55555555-5555-5555-5555-555555555555"
    assert worker._parallel_shard_slot_key("55555555-5555-5555-5555-555555555555") not in redis.values


def test_dynamic_coverage_batch_cancelled_after_claim_releases_without_running(monkeypatch):
    endpoint_id = "11111111-1111-1111-1111-111111111111"
    calls = {"claim": None, "run": 0, "reconcile": None}
    redis = _FakeJobRedis()
    conn = _FakeAsmConn(
        child_status="pending",
        parent_status="running",
        running_update_result="UPDATE 0",
    )

    async def fake_claim_test_batch(conn, target_id, **kwargs):
        calls["claim"] = kwargs
        return [
            {
                "id": endpoint_id,
                "method": "GET",
                "path": "/api/users",
                "param_shape": "id",
                "auth_state": "anonymous",
                "param_location": "query",
                "replay_spec": None,
            }
        ]

    async def fake_run_scan(*args, **kwargs):
        calls["run"] += 1
        return {}

    async def fake_reconcile(conn, parent_id, r, queue_name):
        calls["reconcile"] = {"parent_id": parent_id, "queue_name": queue_name}
        return False

    monkeypatch.setattr(worker, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker, "run_scan", fake_run_scan)
    monkeypatch.setattr(worker.asm_inventory, "claim_test_batch", fake_claim_test_batch)
    monkeypatch.setattr(worker.parallel_scan, "reconcile_parallel_parent", fake_reconcile)

    asyncio.run(
        worker.process_exploit_batch_job(
            {
                "job_id": "job-cancel-race",
                "scan_id": "22222222-2222-2222-2222-222222222222",
                "parent_scan_id": "55555555-5555-5555-5555-555555555555",
                "target_id": "33333333-3333-3333-3333-333333333333",
                "target": "https://example.test",
                "campaign_id": "44444444-4444-4444-4444-444444444444",
                "batch_size": 1,
                "campaign_only": True,
                "finish_campaign_on_complete": False,
                "options": {"scan_type": "smart", "coverage_dynamic_worker": True},
            }
        )
    )

    assert calls["claim"]["campaign_only"] is True
    assert calls["run"] == 0
    assert any("last_attempt_status='cancelled'" in query for query, args in conn.executions)
    assert redis.hashes[-1][2]["status"] == "cancelled"
    assert calls["reconcile"]["parent_id"] == "55555555-5555-5555-5555-555555555555"
    assert worker._parallel_shard_slot_key("55555555-5555-5555-5555-555555555555") not in redis.values


def test_dynamic_coverage_batch_missing_campaign_id_fails_without_claim(monkeypatch):
    calls = {"claim": 0, "reconcile": None}
    redis = _FakeJobRedis()
    parent_id = "55555555-5555-5555-5555-555555555555"
    redis.values[worker.parallel_scan.shards_remaining_key(parent_id)] = 1
    conn = _FakeAsmConn(child_status="pending", parent_status="running")

    async def fake_claim_test_batch(*args, **kwargs):
        calls["claim"] += 1
        return []

    async def fake_reconcile(conn, parent_id, r, queue_name):
        calls["reconcile"] = {"parent_id": parent_id, "queue_name": queue_name}
        return True

    monkeypatch.setattr(worker, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker.asm_inventory, "claim_test_batch", fake_claim_test_batch)
    monkeypatch.setattr(worker.parallel_scan, "reconcile_parallel_parent", fake_reconcile)

    asyncio.run(
        worker.process_exploit_batch_job(
            {
                "job_id": "job-corrupt-dynamic",
                "scan_id": "22222222-2222-2222-2222-222222222222",
                "parent_scan_id": parent_id,
                "target_id": "33333333-3333-3333-3333-333333333333",
                "target": "https://example.test",
                "batch_size": 1,
                "campaign_only": True,
                "finish_campaign_on_complete": False,
                "options": {"scan_type": "smart", "coverage_dynamic_worker": True},
            }
        )
    )

    assert calls["claim"] == 0
    assert any("corrupt_shard_context" in query for query, args in conn.executions)
    assert redis.hashes[-1][2]["status"] == "failed"
    assert redis.hashes[-1][2]["current_phase"] == "corrupt_shard_context"
    assert calls["reconcile"]["parent_id"] == parent_id
    assert redis.values[worker.parallel_scan.shards_remaining_key(parent_id)] == 0


def test_run_scan_disables_scan_ai_when_classification_disabled(monkeypatch):
    captured = {}

    async def _fake_create_subprocess_exec(*cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["env"] = dict(kwargs.get("env") or {})
        return _FakeProcess(b'{"ok": true, "findings": []}')

    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", _fake_create_subprocess_exec)
    monkeypatch.setattr(
        worker,
        "_load_runtime_ai_settings",
        lambda: {
            "ai_url": "https://ai.example/v1/chat/completions",
            "ai_api_key": "secret",
            "ai_model": "model-a",
            "ai_model_fallback": "model-b",
            "ai_mask_host": "masked.example",
            "ai_scan_classification_enabled": False,
            "ai_classify_min_severity": "medium",
            "ai_verify_min_severity": "medium",
        },
    )

    result = asyncio.run(worker.run_scan("https://example.com", {"scan_type": "smart"}))
    cmd = captured["cmd"]
    env = captured["env"]

    assert result.get("ok") is True
    assert "--ai" not in cmd
    assert env["AI_SCAN_CLASSIFICATION_ENABLED"] == "false"
    assert env["AI_CLASSIFY_MIN_SEVERITY"] == "medium"
    assert env["AI_VERIFY_MIN_SEVERITY"] == "medium"


def test_run_scan_enables_scan_ai_when_classification_enabled(monkeypatch):
    captured = {}

    async def _fake_create_subprocess_exec(*cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["env"] = dict(kwargs.get("env") or {})
        return _FakeProcess(b'{"ok": true, "findings": []}')

    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", _fake_create_subprocess_exec)
    monkeypatch.setattr(
        worker,
        "_load_runtime_ai_settings",
        lambda: {
            "ai_url": "https://ai.example/v1/chat/completions",
            "ai_api_key": "secret",
            "ai_model": "model-a",
            "ai_model_fallback": "model-b",
            "ai_mask_host": "masked.example",
            "ai_scan_classification_enabled": False,
            "ai_classify_min_severity": "high",
            "ai_verify_min_severity": "high",
        },
    )

    options = {
        "scan_type": "smart",
        "ai_scan_classification_enabled": True,
        "ai_classify_min_severity": "low",
        "ai_verify_min_severity": "critical",
    }

    result = asyncio.run(worker.run_scan("https://example.com", options))
    cmd = captured["cmd"]
    env = captured["env"]

    assert result.get("ok") is True
    assert "--ai" in cmd
    assert "--ai-url" in cmd
    assert "--ai-api-key" in cmd
    assert "--model" in cmd
    assert env["AI_SCAN_CLASSIFICATION_ENABLED"] == "true"
    assert env["AI_CLASSIFY_MIN_SEVERITY"] == "low"
    assert env["AI_VERIFY_MIN_SEVERITY"] == "critical"


def test_run_scan_null_classification_option_uses_runtime_setting(monkeypatch):
    captured = {}

    async def _fake_create_subprocess_exec(*cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["env"] = dict(kwargs.get("env") or {})
        return _FakeProcess(b'{"ok": true, "findings": []}')

    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", _fake_create_subprocess_exec)
    monkeypatch.setattr(
        worker,
        "_load_runtime_ai_settings",
        lambda: {
            "ai_url": "https://ai.example/v1/chat/completions",
            "ai_api_key": "secret",
            "ai_model": "model-a",
            "ai_model_fallback": "model-b",
            "ai_mask_host": "masked.example",
            "ai_scan_classification_enabled": True,
            "ai_classify_min_severity": "medium",
            "ai_verify_min_severity": "medium",
        },
    )

    # Simulates persisted scan options that include the key with null value.
    options = {
        "scan_type": "smart",
        "ai_scan_classification_enabled": None,
    }

    result = asyncio.run(worker.run_scan("https://example.com", options))
    cmd = captured["cmd"]
    env = captured["env"]

    assert result.get("ok") is True
    assert "--ai" in cmd
    assert env["AI_SCAN_CLASSIFICATION_ENABLED"] == "true"
    assert env["AI_CLASSIFY_MIN_SEVERITY"] == "medium"
