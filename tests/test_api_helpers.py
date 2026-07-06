"""Unit tests for small helpers in api/api.py.

These cover the env-var coercer, the pagination → COUNT(*) rewriter, and the
JSON-decode helper that have grown enough surface to be worth pinning.
"""

import asyncio
import json
import os
import sys
import types
import uuid
from datetime import datetime, timezone

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
# api/api.py imports asyncpg/redis/fastapi at module load; stub the ones
# missing in the test environment. Stubs mirror tests/test_api_scan_option_masking.py.
sys.modules.setdefault("asyncpg", types.SimpleNamespace())
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *args, **kwargs: None))

if "fastapi" not in sys.modules:
    fastapi_mod = types.ModuleType("fastapi")

    class _FakeFastAPI:
        def __init__(self, *args, **kwargs):
            pass

        def add_middleware(self, *args, **kwargs):
            return None

        def _decorator(self, *args, **kwargs):
            def wrapper(fn):
                return fn
            return wrapper

        get = post = patch = put = delete = on_event = exception_handler = _decorator

    class _FakeHTTPException(Exception):
        def __init__(self, status_code: int = 500, detail=None):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    def _fake_query(default=None, **kwargs):
        return default

    class _FakeRequest:
        def __init__(self, query_params=None):
            self.query_params = query_params or {}

    fastapi_mod.FastAPI = _FakeFastAPI
    fastapi_mod.HTTPException = _FakeHTTPException
    fastapi_mod.Query = _fake_query
    fastapi_mod.Request = _FakeRequest
    sys.modules["fastapi"] = fastapi_mod

    middleware_mod = types.ModuleType("fastapi.middleware")
    cors_mod = types.ModuleType("fastapi.middleware.cors")

    class _FakeCORSMiddleware:
        pass

    cors_mod.CORSMiddleware = _FakeCORSMiddleware
    sys.modules["fastapi.middleware"] = middleware_mod
    sys.modules["fastapi.middleware.cors"] = cors_mod

    responses_mod = types.ModuleType("fastapi.responses")

    class _FakeResponse:
        def __init__(self, content=None, status_code=200, headers=None):
            self.content = content
            self.status_code = status_code
            self.headers = headers or {}

    responses_mod.Response = _FakeResponse
    responses_mod.JSONResponse = _FakeResponse
    sys.modules["fastapi.responses"] = responses_mod

import api as api_module  # noqa: E402
from scan_verification_state import scan_time_verification_fields  # noqa: E402

sys.path.pop(0)


def test_worker_build_current_is_fingerprint_authoritative_over_version_label():
    # The source fingerprint covers all detection/orchestration modules and is the
    # precise currency signal. The git version label is volatile (real commit, and
    # workers snapshot the published value once at startup), so a matching
    # fingerprint means current EVEN IF the version label lags — otherwise a current
    # worker shows false-stale right after a volume-mount restart.
    assert api_module.worker_build_current(
        reported_fingerprint="same",
        reported_version="old",
        expected_fingerprint="same",
        expected_version="new",
    ) is True
    # A genuinely stale fingerprint is still stale regardless of the label.
    assert api_module.worker_build_current(
        reported_fingerprint="stale",
        reported_version="new",
        expected_fingerprint="current",
        expected_version="new",
    ) is False
    # No fingerprint reported -> fall back to the version label.
    assert api_module.worker_build_current(
        reported_fingerprint=None,
        reported_version="old",
        expected_fingerprint="current",
        expected_version="new",
    ) is False


def test_worker_build_current_accepts_matching_version_and_fingerprint():
    assert api_module.worker_build_current(
        reported_fingerprint="same",
        reported_version="new",
        expected_fingerprint="same",
        expected_version="new",
    ) is True


def test_worker_build_current_is_unknown_until_worker_registers():
    assert api_module.worker_build_current(
        reported_fingerprint=None,
        reported_version=None,
        expected_fingerprint="same",
        expected_version="new",
    ) is None


# ----- manual / session finding evidence redaction ------------------------

def test_create_manual_finding_redacts_live_auth_material(monkeypatch):
    """Regression: live auth material (bearer tokens / JWTs) in a manual finding's
    evidence, request, and response must be redacted before DB persistence — the
    same guarantee save_findings gives scanner findings. create_manual_finding and
    create_session_finding share this redaction block, so driving the self-contained
    manual endpoint covers both."""
    import json as _json

    captured = {}
    target_uuid = uuid.uuid4()
    finding_uuid = uuid.uuid4()

    class _FakeConn:
        async def fetchrow(self, query, *args):
            if "FROM targets WHERE url" in query:
                return {"id": target_uuid}
            # No pre-existing finding -> proceed to INSERT.
            return None

        async def fetchval(self, query, *args):
            if "INSERT INTO findings" in query:
                captured["args"] = args
                return finding_uuid
            return None

        async def execute(self, query, *args):
            return "UPDATE 1"

    class _FakePool:
        def acquire(self):
            conn = _FakeConn()

            class _Ctx:
                async def __aenter__(self_inner):
                    return conn

                async def __aexit__(self_inner, *exc):
                    return False

            return _Ctx()

    monkeypatch.setattr(api_module, "db_pool", _FakePool())

    token = "eyJabc123.def456.ghi789"
    request = types.SimpleNamespace(
        target="example.com",
        title="BOLA on basket",
        description="cross-user read",
        severity="critical",
        cvss_score=9.1,
        category="BOLA",
        cwe="CWE-639",
        url="https://example.com/rest/basket/9",
        evidence=f"GET /rest/basket/9 with Authorization: Bearer {token} returns User1 data",
        remediation=None,
        request=f"GET /rest/basket/9 HTTP/1.1\nAuthorization: Bearer {token}",
        response=f"200 OK\nx-token: {token}",
        notes=None,
    )

    result = asyncio.run(api_module.create_manual_finding(request))
    assert result["status"] == "created"

    args = captured["args"]
    evidence_arg, redacted_request, redacted_response = args[9], args[10], args[11]
    # Evidence column is JSON; the proof string must be sanitised.
    assert token not in evidence_arg
    assert "[REDACTED]" in evidence_arg
    assert "[REDACTED]" in _json.loads(evidence_arg)["proof"]
    # Separate request/response columns must be sanitised too.
    assert token not in redacted_request and "[REDACTED]" in redacted_request
    assert token not in redacted_response and "[REDACTED]" in redacted_response


# ----- _int_env -----------------------------------------------------------

def test_int_env_returns_default_when_unset(monkeypatch):
    monkeypatch.delenv("X_NOT_SET", raising=False)
    assert api_module._int_env("X_NOT_SET", 42) == 42


def test_int_env_returns_default_on_blank(monkeypatch):
    monkeypatch.setenv("X_BLANK", "")
    assert api_module._int_env("X_BLANK", 42) == 42


def test_int_env_returns_default_on_garbage(monkeypatch):
    monkeypatch.setenv("X_GARBAGE", "not-an-int")
    assert api_module._int_env("X_GARBAGE", 42) == 42


def test_int_env_parses_value(monkeypatch):
    monkeypatch.setenv("X_OK", "17")
    assert api_module._int_env("X_OK", 42) == 17


# ----- _strip_pagination_for_count ---------------------------------------

def test_strip_pagination_for_count_drops_order_limit_offset():
    query = (
        "SELECT f.*, COUNT(*) OVER() AS total_count\n"
        "FROM findings f\n"
        "WHERE 1=1 AND f.severity = $1\n"
        "ORDER BY f.last_seen_at DESC NULLS LAST\n"
        "LIMIT $2 OFFSET $3"
    )
    params = ["high", 100, 0]

    count_sql, count_params = api_module._strip_pagination_for_count(query, params)

    # SELECT is rewritten to COUNT(*) and the FROM/WHERE survive.
    assert count_sql.startswith("SELECT COUNT(*) FROM findings")
    assert "ORDER BY" not in count_sql
    assert "LIMIT" not in count_sql
    assert "OFFSET" not in count_sql
    # Last two params (the LIMIT and OFFSET placeholders) are dropped.
    assert count_params == ["high"]


def test_strip_pagination_for_count_preserves_filter_params():
    query = (
        "SELECT f.*, COUNT(*) OVER() AS total_count "
        "FROM findings f WHERE f.status = $1 AND f.target_id = $2 "
        "ORDER BY f.severity LIMIT $3 OFFSET $4"
    )
    params = ["active", "uuid-1", 50, 100]

    count_sql, count_params = api_module._strip_pagination_for_count(query, params)

    assert "$1" in count_sql
    assert "$2" in count_sql
    assert count_params == ["active", "uuid-1"]


# ----- _decode_json_value -------------------------------------------------

def test_decode_json_value_handles_string_json():
    assert api_module._decode_json_value('{"a": 1, "b": [2, 3]}') == {"a": 1, "b": [2, 3]}


def test_decode_json_value_passes_dict_through():
    payload = {"already": "decoded"}
    assert api_module._decode_json_value(payload) is payload


def test_decode_json_value_passes_non_json_string_through():
    # Strings that don't look like JSON return as-is rather than raising.
    assert api_module._decode_json_value("just a string") == "just a string"


def test_decode_json_value_handles_none():
    assert api_module._decode_json_value(None) is None


# ----- scan-time verification overrides -------------------------------------

def test_scan_result_verification_overrides_promote_raw_scan_proof():
    overrides = api_module._scan_result_verification_overrides({
        "findings": [
            {
                "id": "smart_sqli:abc",
                "verified": True,
                "proof_of_exploitation": True,
                "confidence": 0.95,
                "last_verification_verdict": None,
            }
        ]
    })

    assert overrides["smart_sqli:abc"]["last_verification_status"] == "still_vulnerable"
    assert overrides["smart_sqli:abc"]["last_verification_verdict"] == "exploited"
    assert overrides["smart_sqli:abc"]["last_verification_confidence"] == 0.95


def test_scan_result_verification_overrides_ignore_stale_false_positive_without_proof():
    overrides = api_module._scan_result_verification_overrides({
        "findings": [
            {
                "id": "smart_sqli:abc",
                "verified": False,
                "last_verification_verdict": "false_positive",
            }
        ]
    })

    assert overrides == {}


def test_scan_time_verification_fields_preserves_zero_confidence():
    fields = scan_time_verification_fields(
        {"proof_of_exploitation": True, "verification_confidence": 0.0, "confidence": 0.95}
    )

    assert fields["last_verification_verdict"] == "exploited"
    assert fields["last_verification_confidence"] == 0.0


def test_scan_time_verification_fields_generic_verified_is_not_proof():
    assert scan_time_verification_fields({"verified": True, "confidence": 0.95}) is None
    assert scan_time_verification_fields({"evidence": {"verified": True}, "confidence": 0.95}) is None


def test_scan_time_verification_fields_failed_browser_proof_is_not_proof():
    assert scan_time_verification_fields(
        {"verified": True, "browser_proof": {"proven": False, "confidence": 0.2}}
    ) is None


def test_scan_time_verification_fields_strong_proof_is_exploited():
    for finding in (
        {"poe": {"proven": True}},
        {"browser_proof": {"proven": True, "confidence": 0.99}},
        {"verification_verdict": "exploited"},
        {"result_status": "verified_vulnerable"},
    ):
        assert scan_time_verification_fields(finding)["last_verification_verdict"] == "exploited"


def test_scan_time_verification_fields_weak_proof_is_not_exploited():
    # Soft signals must not be flattened up to "exploited".
    for finding in (
        {"verification_verdict": "likely_vulnerable", "confidence": 0.6},
        {"result_status": "still_vulnerable"},
        {"confidence_tier": "verified"},
    ):
        fields = scan_time_verification_fields(finding)
        assert fields is not None
        assert fields["last_verification_verdict"] == "likely_vulnerable"
        assert fields["last_verification_status"] == "still_vulnerable"


def test_scan_time_verification_fields_returns_none_without_proof():
    assert scan_time_verification_fields({"verification_verdict": "false_positive"}) is None
    assert scan_time_verification_fields({}) is None


def test_normalize_scan_result_backfills_staged_nuclei_coverage():
    report = {
        "discovery": {
            "nuclei": {
                "scan_completed": True,
                "templates_executed": 0,
                "waves_completed": 2,
                "total_duration_seconds": 75,
                "wave_stats": [
                    {"tags": ["default-login", "rce", "cve", "takeover", "critical"]},
                    {"tags": ["auth", "exposure", "misconfig"]},
                ],
            }
        },
        "smart_coverage": {
            "nuclei_templates": {"run": 0, "matched": 0, "hit_rate": 0.0, "by_category": {}}
        },
        "coverage_gaps": {
            "count": 2,
            "issues": [
                "Low endpoint coverage (0.18) - increase crawl depth or authenticated coverage",
                "Nuclei templates not executed - check nuclei configuration or timeouts",
            ],
        },
    }

    normalized = api_module._normalize_scan_result_for_api(report)

    assert normalized["smart_coverage"]["nuclei_templates"]["run"] == 8
    assert normalized["coverage_gaps"]["count"] == 1
    assert normalized["coverage_gaps"]["issues"] == [
        "Low endpoint coverage (0.18) - increase crawl depth or authenticated coverage"
    ]


def test_scan_worker_container_name_filter_excludes_gungnir_worker():
    assert api_module._is_scan_worker_container_name("shakerscan-worker-1") is True
    assert api_module._is_scan_worker_container_name("/shakerscan-worker-5") is True
    assert api_module._is_scan_worker_container_name("shakerscan-gungnir-worker-1") is False
    assert api_module._is_scan_worker_container_name("other-worker-1") is False


# ----- dashboard action center -------------------------------------------

class _ActionCenterConn:
    def __init__(self, *, ai_rows=None):
        self.ai_rows = ai_rows or []

    async def fetchrow(self, query, *args):
        if "FROM findings" in query and "severity IN ('critical', 'high')" in query:
            return {"critical": 2, "high": 1}
        if "FROM finding_exceptions" in query:
            return {"expired": 1, "expiring": 2, "weak_records": 3}
        if "WITH per_target AS" in query:
            return {
                "enabled_targets": 4,
                "no_inventory_targets": 1,
                "targets_with_gaps": 2,
                "endpoints_needing_work": 25,
                "sample_target_id": "11111111-1111-4111-8111-111111111111",
            }
        if "FROM schedules" in query:
            return {
                "id": uuid.uuid4(),
                "next_run_at": "2026-07-05T02:00:00",
                "target_url": "https://app.example.test",
            }
        return {}

    async def fetch(self, query, *args):
        if "FROM scans" in query and "status = 'failed'" in query:
            return [{
                "id": uuid.uuid4(),
                "target_url": "https://broken.example.test",
                "error_message": "worker exited",
                "created_at": "2026-07-05T01:00:00",
            }]
        if "run_kind = 'model_intake'" in query:
            return [{
                "id": uuid.uuid4(),
                "target_url": "https://models.example.test/model.safetensors",
                "signature_status": "untrusted_root",
                "signature_verified": "false",
                "completed_at": "2026-07-05T01:30:00",
            }]
        if "FROM ai_targets" in query:
            return self.ai_rows
        return []


def test_dashboard_action_center_prioritizes_server_derived_items():
    conn = _ActionCenterConn()
    snapshot = {
        "available": True,
        "stale_count": 1,
        "pending_count": 1,
        "stale_names": ["worker-old"],
        "pending_names": ["worker-booting"],
    }

    items = asyncio.run(api_module._build_dashboard_action_center(conn, worker_snapshot=snapshot))
    by_id = {item["id"]: item for item in items}

    assert items[0]["id"] == "deploy-gate-blockers"
    assert by_id["deploy-gate-blockers"]["priority"] == "critical"
    assert by_id["deploy-gate-blockers"]["actions"][0]["href"] == "/findings?status=active&severity=critical"
    assert by_id["worker-build-freshness"]["count"] == 2
    assert by_id["worker-build-freshness"]["actions"][0]["label"] == "Adjust workers"
    assert by_id["policy-exception-hygiene"]["count"] == 6
    assert by_id["policy-exception-hygiene"]["href"] == "/settings/exceptions"
    assert by_id["policy-exception-hygiene"]["actions"][0]["href"] == "/settings/exceptions?queue_filter=expired"
    assert by_id["asm-coverage-gaps"]["href"] == "/asm?target_id=11111111-1111-4111-8111-111111111111"
    assert by_id["asm-coverage-gaps"]["actions"][0]["label"] == "Improve coverage"
    assert by_id["next-asm-schedule"]["priority"] == "info"
    assert by_id["recent-failed-scans"]["actions"][1]["label"] == "Latest failed scan"
    assert by_id["model-intake-untrusted-signatures"]["samples"][0]["detail"] == "signature status: untrusted_root"
    assert by_id["model-intake-untrusted-signatures"]["actions"][0]["href"] == "/settings/model-intake?remediate=trust"
    assert by_id["model-intake-untrusted-signatures"]["actions"][1]["label"] == "Latest scan"


def test_dashboard_action_center_surfaces_ai_control_baseline_gaps():
    conn = _ActionCenterConn(ai_rows=[{
        "id": uuid.uuid4(),
        "name": "Production RAG",
        "target_type": "rag",
        "endpoint_url": "https://ai.example.test/rag",
        "production_mode": True,
        "metadata_json": {"risk_tier": "high"},
    }])

    items = asyncio.run(api_module._build_dashboard_action_center(
        conn,
        worker_snapshot={"available": False},
    ))
    ai_item = next(item for item in items if item["id"] == "ai-control-baseline-gaps")

    assert ai_item["count"] == 1
    assert ai_item["href"] == "/settings/ai-gate"
    assert ai_item["actions"][1]["href"] == "/findings?source_type=ai&status=active"
    assert "AI asset owner" in ai_item["samples"][0]["detail"]


class _ProductStatusConn:
    async def fetchrow(self, query, *args):
        if "COALESCE(source, 'scan')" in query:
            return {"blockers": 3, "active_findings": 5}
        if "COALESCE(run_kind, 'dast')" in query:
            return {"active_scans": 2, "recent_failed": 1}
        if "WITH per_target AS" in query:
            return {
                "enabled_targets": 4,
                "no_inventory_targets": 1,
                "targets_with_gaps": 2,
                "endpoints_needing_work": 25,
                "sample_target_id": "11111111-1111-4111-8111-111111111111",
            }
        if "source = 'ai_gate'" in query:
            return {"active_findings": 0}
        if "source = 'model_intake'" in query:
            return {"active_findings": 1}
        if "untrusted_latest" in query:
            return {"untrusted_latest": 2}
        if "FROM finding_exceptions" in query:
            return {"expired": 1, "expiring": 2, "weak_records": 3}
        if "severity = 'critical'" in query and "severity = 'high'" in query:
            return {"critical": 1, "high": 4}
        return {}

    async def fetch(self, query, *args):
        if "FROM ai_targets" in query:
            return [{
                "id": uuid.uuid4(),
                "name": "Production RAG",
                "target_type": "rag",
                "endpoint_url": "https://ai.example.test/rag",
                "production_mode": True,
                "metadata_json": {"risk_tier": "high"},
            }]
        return []


def test_dashboard_product_status_summarizes_cross_product_state():
    snapshot = {
        "available": True,
        "running": 5,
        "stale_count": 1,
        "pending_count": 2,
        "stale_names": ["worker-old"],
        "pending_names": ["worker-booting-a", "worker-booting-b"],
    }

    items = asyncio.run(api_module._build_dashboard_product_status(
        _ProductStatusConn(),
        worker_snapshot=snapshot,
    ))
    by_id = {item["id"]: item for item in items}

    assert [item["id"] for item in items] == [
        "dast",
        "asm",
        "ai_gate",
        "model_intake",
        "exceptions",
        "deployment",
        "workers",
    ]
    assert by_id["dast"]["status"] == "critical"
    assert by_id["dast"]["primary_count"] == 3
    assert by_id["dast"]["actions"][0]["href"] == "/findings?status=active&source_type=dast"
    assert by_id["asm"]["href"] == "/asm?target_id=11111111-1111-4111-8111-111111111111"
    assert by_id["asm"]["secondary_count"] == 25
    assert by_id["ai_gate"]["status"] == "warning"
    assert by_id["ai_gate"]["secondary_label"] == "control gaps"
    assert by_id["model_intake"]["status"] == "critical"
    assert by_id["model_intake"]["href"] == "/settings/model-intake?remediate=trust"
    assert by_id["model_intake"]["actions"][0]["label"] == "Fix trust"
    assert by_id["model_intake"]["actions"][1]["href"] == "/findings?source_type=model_intake&status=active"
    assert by_id["exceptions"]["href"] == "/settings/exceptions?queue_filter=expired"
    assert by_id["deployment"]["primary_count"] == 1
    assert by_id["workers"]["status"] == "critical"
    assert by_id["workers"]["metadata"]["total"] == 5


# ----- run_due_schedules --------------------------------------------------

class _FakeAcquire:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *exc):
        return False


class _FakePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return _FakeAcquire(self.conn)


class _FakeConn:
    def __init__(self, schedules):
        self.schedules = schedules
        self.executes = []

    async def fetch(self, query, *args):
        if "FROM schedules" in query:
            return self.schedules
        return []

    async def fetchval(self, query, *args):
        return 0

    async def fetchrow(self, query, *args):
        if "SELECT asm_config FROM targets" in query:
            return {"asm_config": {}}
        return {}

    async def execute(self, query, *args):
        self.executes.append((query, args))
        return "OK"


class _FailingRedis:
    def __init__(self):
        self.rpush_calls = []

    def rpush(self, *args):
        self.rpush_calls.append(args)
        raise RuntimeError("redis down")

    def hset(self, *args, **kwargs):
        raise AssertionError("hset should not run after rpush fails")


class _RecordingRedis:
    def __init__(self):
        self.rpush_calls = []
        self.hset_calls = []

    def rpush(self, *args):
        self.rpush_calls.append(args)

    def hset(self, *args, **kwargs):
        self.hset_calls.append((args, kwargs))


def _due_schedule():
    return {
        "id": uuid.uuid4(),
        "target_id": uuid.uuid4(),
        "target_url": "https://example.test",
        "schedule_kind": "normal_scan",
        "scan_type": "smart",
        "scan_options": {"budget_profile": "fast"},
        "frequency": "daily",
        "day_of_week": None,
        "time_of_day": "02:00",
        "timezone": "UTC",
        "jitter_minutes": 0,
    }


def test_schedule_kind_normalizer_supports_typed_and_legacy_contracts():
    assert api_module._normalize_schedule_kind("normal_scan", {}) == "normal_scan"
    assert api_module._normalize_schedule_kind("asm_improve", {}) == "asm_improve"
    assert api_module._normalize_schedule_kind(None, {"kind": "asm_improve"}) == "asm_improve"

    with pytest.raises(ValueError):
        api_module._normalize_schedule_kind("normal_scan", {"kind": "asm_improve"})

    with pytest.raises(ValueError):
        api_module._normalize_schedule_kind("bad_kind", {})


def test_run_due_schedules_does_not_advance_schedule_on_redis_failure(monkeypatch):
    conn = _FakeConn([_due_schedule()])
    redis_client = _FailingRedis()
    monkeypatch.setattr(api_module, "get_redis", lambda: redis_client)

    asyncio.run(api_module.run_due_schedules(_FakePool(conn)))

    executed_sql = "\n".join(query for query, _args in conn.executes)
    assert "INSERT INTO scans" in executed_sql
    assert "UPDATE scans" in executed_sql
    assert "scheduled enqueue failed" in str(conn.executes)
    assert "UPDATE schedules SET last_run_at" not in executed_sql
    assert redis_client.rpush_calls


def test_run_due_schedules_advances_schedule_after_successful_enqueue(monkeypatch):
    conn = _FakeConn([_due_schedule()])
    redis_client = _RecordingRedis()
    monkeypatch.setattr(api_module, "get_redis", lambda: redis_client)

    asyncio.run(api_module.run_due_schedules(_FakePool(conn)))

    executed_sql = "\n".join(query for query, _args in conn.executes)
    assert "INSERT INTO scans" in executed_sql
    assert "UPDATE schedules SET last_run_at" in executed_sql
    assert "UPDATE scans" not in executed_sql
    assert len(redis_client.rpush_calls) == 1
    assert len(redis_client.hset_calls) == 1


def test_run_due_schedules_uses_typed_asm_schedule_kind(monkeypatch):
    schedule = _due_schedule()
    schedule["schedule_kind"] = "asm_improve"
    schedule["scan_options"] = {
        "batch_size": 25,
        "stale_days": 7,
        "check_family": "sqli",
        "endpoint_filter": "api",
        "exploit_depth": True,
    }
    conn = _FakeConn([schedule])
    redis_client = _RecordingRedis()
    queued = {}

    async def fake_claimable_count(_conn, target_id, **kwargs):
        queued["claimable_target_id"] = target_id
        queued["claimable_kwargs"] = kwargs
        return 3

    async def fake_enqueue_asm_exploit_batch(
        _conn, _redis, target_id, target_url, asm_opts, *,
        batch_size, stale_days, exploit_depth, check_family=None,
        endpoint_filter=None, triggered_by,
    ):
        queued["target_id"] = target_id
        queued["target_url"] = target_url
        queued["asm_opts"] = asm_opts
        queued["batch_size"] = batch_size
        queued["stale_days"] = stale_days
        queued["exploit_depth"] = exploit_depth
        queued["check_family"] = check_family
        queued["endpoint_filter"] = endpoint_filter
        queued["triggered_by"] = triggered_by
        return {"scan_id": "11111111-1111-4111-8111-111111111111"}

    async def fake_enqueue_asm_recon(_conn, _redis, target_id, target_url, asm_opts, *, triggered_by):
        queued["unexpected_recon"] = {
            "target_id": target_id,
            "target_url": target_url,
            "asm_opts": asm_opts,
            "triggered_by": triggered_by,
        }
        return {"scan_id": "11111111-1111-4111-8111-111111111111"}

    monkeypatch.setattr(api_module, "get_redis", lambda: redis_client)
    monkeypatch.setattr(api_module.asm_inventory, "claimable_count", fake_claimable_count)
    monkeypatch.setattr(api_module, "_enqueue_asm_exploit_batch", fake_enqueue_asm_exploit_batch)
    monkeypatch.setattr(api_module, "_enqueue_asm_recon", fake_enqueue_asm_recon)

    asyncio.run(api_module.run_due_schedules(_FakePool(conn)))

    executed_sql = "\n".join(query for query, _args in conn.executes)
    assert "INSERT INTO scans" not in executed_sql
    assert "UPDATE schedules SET last_run_at" in executed_sql
    assert queued["triggered_by"] == "schedule"
    assert queued["claimable_kwargs"] == {
        "stale_days": 7,
        "check_family": "sqli",
        "endpoint_filter": "api",
    }
    assert queued["asm_opts"] == {
        "batch_size": 25,
        "stale_days": 7,
        "check_family": "sqli",
        "endpoint_filter": "api",
        "exploit_depth": True,
    }
    assert queued["batch_size"] == 3
    assert queued["stale_days"] == 7
    assert queued["exploit_depth"] is True
    assert queued["check_family"] == "sqli"
    assert queued["endpoint_filter"] == "api"
    assert "unexpected_recon" not in queued


def test_asm_campaign_timeline_merges_scheduler_schedule_active_and_activity():
    timeline = api_module._build_asm_campaign_timeline(
        scheduler_state={
            "decision": {
                "action": "none",
                "blocked_by": "daily_cap",
                "reason": "daily cap reached",
                "next_eligible_at": "2026-07-05T12:00:00",
            },
            "last_decision": {
                "action": "test",
                "reason": "scheduled ASM test queued",
                "recorded_at": "2026-07-05T01:00:00",
                "active_scan_id": "scan-active",
            },
        },
        active_scans=[{
            "id": "scan-active",
            "scan_role": api_module.asm_inventory.ASM_BATCH_ROLE,
            "status": "running",
            "current_phase": "Testing endpoint batch",
            "created_at": "2026-07-05T00:50:00",
            "campaign_id": "campaign-active",
        }],
        next_schedule={
            "id": "sched-1",
            "frequency": "daily",
            "time_of_day": "02:00",
            "next_run_at": "2026-07-06T02:00:00",
        },
        activity=[{
            "id": "scan-old",
            "scan_role": api_module.asm_inventory.ASM_RECON_ROLE,
            "status": "completed",
            "campaign_requested_by": "improve",
            "campaign_id": "campaign-old",
            "completed_at": "2026-07-04T02:05:00",
            "attempt_status_counts": {"completed": 3},
        }],
    )

    kinds = [event["kind"] for event in timeline]
    assert kinds[:4] == ["active_scan", "scheduler_decision", "next_eligible", "scheduled_wave"]
    assert "last_scheduler_decision" in kinds
    assert "activity" in kinds
    assert timeline[0]["href"] == "/scans/scan-active"
    assert timeline[3]["href"] == "/schedules"
    assert any(event["detail"] == "daily cap reached" for event in timeline)


def test_ai_scan_replay_plan_selects_skipped_probe_ids():
    plan = api_module._build_ai_scan_replay_plan(
        {
            "ai_gate": {
                "probe_pack": "shaker-rag-lite",
                "scan_profile": "standard",
                "decision": {"environment": "staging"},
                "coverage_matrix": {
                    "summary": {"planned": 3, "executed": 1, "skipped": 2, "errors": 0},
                    "skipped": [
                        {"probe_id": "rag-1", "family": "rag", "reason": "request_budget"},
                        {"probe_id": "mcp-1", "family": "mcp", "reason": "request_budget"},
                    ],
                },
            }
        },
        api_module.AIScanReplayRequest(mode="skipped"),
    )

    assert plan["probe_ids"] == ["rag-1", "mcp-1"]
    assert plan["probe_family"] is None
    assert plan["probe_pack"] == "shaker-rag-lite"
    assert plan["environment"] == "staging"


def test_ai_scan_replay_plan_selects_errored_family():
    plan = api_module._build_ai_scan_replay_plan(
        {
            "ai_gate": {
                "coverage_matrix": {
                    "by_family": {
                        "rag": {"planned": 2, "executed": 2, "errors": 0},
                        "mcp": {"planned": 1, "executed": 0, "errors": 1},
                    },
                    "summary": {"errors": 1},
                    "skipped": [{"probe_id": "mcp-1", "family": "mcp", "reason": "error"}],
                },
            }
        },
        api_module.AIScanReplayRequest(mode="errors"),
    )

    assert plan["probe_family"] == "mcp"
    assert plan["probe_ids"] == []


def test_ai_scan_replay_plan_rejects_unknown_family():
    with pytest.raises(api_module.HTTPException) as exc:
        api_module._build_ai_scan_replay_plan(
            {
                "ai_gate": {
                    "coverage_matrix": {
                        "by_family": {"rag": {"planned": 1}},
                    },
                }
            },
            api_module.AIScanReplayRequest(mode="family", probe_family="mcp"),
        )

    assert exc.value.status_code == 400
    assert "was not planned" in exc.value.detail


def test_ai_scan_replay_plan_rejects_non_ai_gate_result():
    with pytest.raises(api_module.HTTPException) as exc:
        api_module._build_ai_scan_replay_plan(
            {"result": {"score": 90}},
            api_module.AIScanReplayRequest(mode="skipped"),
        )

    assert exc.value.status_code == 400
    assert "AI Gate result" in exc.value.detail


def test_ai_scan_replay_plan_selects_transcript_by_index():
    plan = api_module._build_ai_scan_replay_plan(
        {
            "ai_gate": {
                "coverage_matrix": {"summary": {"planned": 2, "executed": 2}},
                "transcripts": [
                    {"probe_id": "rag-1", "probe_family": "rag", "turns": [{"role": "user"}]},
                    {"probe_id": "mcp-1", "probe_family": "mcp", "status_code": 200, "turn_count": 1},
                ],
            }
        },
        api_module.AIScanReplayRequest(mode="transcript", transcript_index=1),
    )

    assert plan["probe_ids"] == ["mcp-1"]
    assert plan["probe_family"] is None
    assert plan["transcript"]["transcript_index"] == 1
    assert plan["transcript"]["probe_family"] == "mcp"
    assert plan["transcript"]["status_code"] == 200


def test_ai_scan_replay_plan_selects_transcript_by_probe_id():
    plan = api_module._build_ai_scan_replay_plan(
        {
            "ai_gate": {
                "transcripts": [
                    {"probe_id": "rag-1", "probe_family": "rag"},
                    {"probe_id": "mcp-1", "probe_family": "mcp"},
                ],
            }
        },
        api_module.AIScanReplayRequest(mode="transcript", probe_id="rag-1"),
    )

    assert plan["probe_ids"] == ["rag-1"]
    assert plan["transcript"]["transcript_index"] == 0


def test_ai_scan_replay_plan_rejects_transcript_without_probe_context():
    with pytest.raises(api_module.HTTPException) as exc:
        api_module._build_ai_scan_replay_plan(
            {"ai_gate": {"transcripts": [{"probe_family": "rag"}]}},
            api_module.AIScanReplayRequest(mode="transcript", transcript_index=0),
        )

    assert exc.value.status_code == 400
    assert "missing probe_id" in exc.value.detail


def _ai_history_row(
    scan_id: str,
    *,
    pack: str = "shaker-rag-lite",
    profile: str = "standard",
    environment: str = "staging",
    decision: str = "needs_review",
    planned: int = 4,
    executed: int = 3,
    skipped: int = 1,
    errors: int = 0,
    findings_count: int = 1,
) -> dict:
    return {
        "id": scan_id,
        "ai_target_id": "target-ai",
        "target_url": "https://ai.example/rag",
        "run_kind": "ai_rag",
        "status": "completed",
        "score": 80,
        "grade": "B",
        "findings_count": findings_count,
        "created_at": f"2026-07-05T0{scan_id[-1]}:00:00Z",
        "completed_at": f"2026-07-05T0{scan_id[-1]}:05:00Z",
        "options": {
            "ai_probe_pack": pack,
            "ai_scan_profile": profile,
            "ai_environment": environment,
        },
        "result": {
            "ai_gate": {
                "probe_pack": pack,
                "scan_profile": profile,
                "decision": {"decision": decision, "environment": environment},
                "coverage_matrix": {
                    "summary": {
                        "planned": planned,
                        "executed": executed,
                        "skipped": skipped,
                        "errors": errors,
                        "with_transcripts": executed,
                        "with_findings": findings_count,
                    },
                },
                "evidence_manifest": {"evidence": {"transcripts_hash": f"hash-{scan_id}"}},
            },
        },
    }


def test_ai_campaign_history_filters_context_and_computes_deltas():
    current = _ai_history_row("scan-3", executed=4, skipped=0, errors=0, findings_count=2)
    previous = _ai_history_row("scan-2", executed=2, skipped=2, errors=1, findings_count=1)
    unrelated_pack = _ai_history_row("scan-1", pack="shaker-agent-abuse", executed=4, findings_count=9)

    history = api_module._build_ai_campaign_history(
        current,
        [current, previous, unrelated_pack],
        limit=6,
    )

    assert history["scan_id"] == "scan-3"
    assert history["context"] == {
        "probe_pack": "shaker-rag-lite",
        "scan_profile": "standard",
        "environment": "staging",
    }
    assert [run["id"] for run in history["runs"]] == ["scan-3", "scan-2"]
    assert history["previous_run"]["id"] == "scan-2"
    assert history["deltas"]["findings_count"] == 1
    assert history["deltas"]["executed"] == 2
    assert history["deltas"]["skipped"] == -2
    assert history["deltas"]["errors"] == -1
    assert history["deltas"]["coverage_pct"] == 50


def test_ai_campaign_history_reports_decision_change():
    current = _ai_history_row("scan-4", decision="allow", findings_count=0)
    previous = _ai_history_row("scan-3", decision="block", findings_count=2)

    history = api_module._build_ai_campaign_history(current, [current, previous], limit=6)

    assert history["deltas"]["decision_changed"] is True
    assert history["previous_run"]["decision"] == "block"


def test_ai_target_campaign_history_groups_contexts_and_summarizes_latest_runs():
    latest_rag = _ai_history_row("scan-4", decision="allow", executed=4, findings_count=0)
    previous_rag = _ai_history_row("scan-3", decision="block", executed=2, skipped=1, findings_count=2)
    latest_agent = _ai_history_row(
        "scan-2",
        pack="shaker-agent-abuse",
        profile="deep",
        environment="production",
        decision="block",
        errors=1,
        findings_count=3,
    )

    history = api_module._build_ai_target_campaign_history(
        "target-ai",
        [latest_rag, previous_rag, latest_agent],
        limit=12,
    )

    assert history["ai_target_id"] == "target-ai"
    assert history["summary"] == {
        "total_runs": 3,
        "contexts": 2,
        "blocked_runs": 2,
        "errored_runs": 1,
        "budget_stopped_runs": 0,
    }
    assert [run["id"] for run in history["runs"]] == ["scan-4", "scan-3", "scan-2"]
    rag_context = next(ctx for ctx in history["contexts"] if ctx["probe_pack"] == "shaker-rag-lite")
    assert rag_context["runs_count"] == 2
    assert rag_context["latest_run"]["id"] == "scan-4"
    assert rag_context["previous_run"]["id"] == "scan-3"
    assert rag_context["deltas"]["findings_count"] == -2
    assert rag_context["deltas"]["executed"] == 2
    assert rag_context["deltas"]["decision_changed"] is True


def test_deployment_decision_exception_hygiene_summary():
    decision = api_module.build_deployment_decision(
        {
            "id": "scan-exception-summary",
            "status": "completed",
            "scan_type": "smart",
            "run_kind": "web_dast",
            "result": {"findings": [{"id": "f-high", "severity": "high", "title": "x"}]},
        },
        db_exceptions=[
            {
                "finding_id": "f-high",
                "status": "active",
                "approver": "sec",
                "owner": "appsec",
                "compensating_controls": "WAF rule",
                "expires_at": "2999-01-01T00:00:00+00:00",
            },
            {"finding_id": "f-high", "status": "active", "expires_at": "2000-01-01T00:00:00+00:00"},
            {"finding_id": "f-high", "status": "revoked", "approver": "sec", "expires_at": "2999-01-01T00:00:00+00:00"},
            {"finding_id": "f-high", "status": "active", "owner": "appsec"},
        ],
    )

    assert decision["exception_summary"]["total"] == 4
    assert decision["exception_summary"]["applied_count"] == 1
    assert decision["exception_summary"]["expired"] == 1
    assert decision["exception_summary"]["inactive_or_revoked"] == 1
    assert decision["exception_summary"]["missing_expiry"] == 1
    assert decision["exception_summary"]["missing_approver"] == 2
    assert decision["exception_summary"]["missing_owner"] == 2
    assert decision["exception_summary"]["missing_compensating_controls"] == 3
    assert decision["exception_summary"]["review_required"] == 3


def test_deployment_decision_model_intake_policy_anchor_gap():
    decision = api_module.build_deployment_decision(
        {
            "id": "scan-policy-anchor-gap",
            "status": "completed",
            "scan_type": "model_intake",
            "run_kind": "model_intake",
            "options": {"environment": "production"},
            "result": {
                "model_intake": {
                    "checks": {"signature_verification": True},
                    "summary": {
                        "signature_verified": True,
                        "signature_trusted_root": False,
                        "signature_verification_status": "verified_untrusted_root",
                    },
                },
                "result": {"decision": "allow"},
            },
        },
        db_policy_profiles={
            "production": {
                "name": "strict-prod",
                "environment": "production",
                "minimum_block_severity": "high",
                "expires_days": 30,
                "strict_model_intake": True,
                "id": "production",
                "required_trust_anchor_ids": ["11111111-1111-4111-8111-111111111111"],
            }
        },
    )

    assert decision["decision"] == "needs_review"
    gap = next(item for item in decision["required_evidence_missing"] if item["id"] == "policy_required_trust_anchors")
    assert gap["status"] == "untrusted"
    assert gap["required_trust_anchor_ids"] == ["11111111-1111-4111-8111-111111111111"]
    assert gap["signature_trusted_root"] is False


def test_model_intake_trust_anchor_merge_adds_saved_material_and_audit_metadata():
    request = api_module.ModelIntakeScanRequest(
        artifact_url="https://models.example/model.safetensors",
        signature_trusted_key_sha256=["a" * 64],
        metadata_json={"license": "apache-2.0"},
    )
    merged = api_module._merge_model_intake_trust_anchor_material(
        request,
        [{
            "id": "anchor-1",
            "name": "prod-release-key",
            "policy_profile": "production",
            "public_key_pem": "-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----",
            "public_key_sha256": "b" * 64,
        }],
    )

    assert merged.signature_trusted_keys == ["-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----"]
    assert merged.signature_trusted_key_sha256 == ["a" * 64, "b" * 64]
    assert merged.metadata_json["license"] == "apache-2.0"
    assert merged.metadata_json["selected_trust_anchors"] == [{
        "id": "anchor-1",
        "name": "prod-release-key",
        "policy_profile": "production",
    }]


def test_model_intake_policy_profile_requirements_add_required_anchor_ids():
    explicit = "11111111-1111-4111-8111-111111111111"
    required = "22222222-2222-4222-8222-222222222222"
    request = api_module.ModelIntakeScanRequest(
        artifact_url="https://models.example/model.safetensors",
        policy_profile="production",
        trust_anchor_ids=[explicit],
        metadata_json={"license": "apache-2.0"},
    )

    updated = api_module._apply_model_intake_policy_profile_requirements(
        request,
        {
            "name": "Production strict",
            "product_area": "model_intake",
            "environment": "production",
            "strict_model_intake": True,
            "required_trust_anchor_ids": [required],
        },
    )

    assert updated.trust_anchor_ids == [explicit, required]
    assert updated.metadata_json["license"] == "apache-2.0"
    assert updated.metadata_json["policy_required_trust_anchor_ids"] == [required]
    assert updated.metadata_json["policy_required_trust_anchor_profile"] == "Production strict"


def test_model_intake_policy_profile_requirements_ignore_non_strict_or_other_products():
    request = api_module.ModelIntakeScanRequest(
        artifact_url="https://models.example/model.safetensors",
        policy_profile="production",
    )
    other_product = api_module._apply_model_intake_policy_profile_requirements(
        request,
        {
            "product_area": "ai_gate",
            "strict_model_intake": True,
            "required_trust_anchor_ids": ["22222222-2222-4222-8222-222222222222"],
        },
    )
    non_strict = api_module._apply_model_intake_policy_profile_requirements(
        request,
        {
            "product_area": "model_intake",
            "strict_model_intake": False,
            "required_trust_anchor_ids": ["22222222-2222-4222-8222-222222222222"],
        },
    )

    assert other_product.trust_anchor_ids is None
    assert non_strict.trust_anchor_ids is None


def test_state_changing_request_models_accept_approval_receipt_id():
    receipt_id = "11111111-1111-4111-8111-111111111111"

    assert api_module.ModelIntakeScanRequest(
        artifact_url="https://models.example/model.safetensors",
        approval_receipt_id=receipt_id,
    ).approval_receipt_id == receipt_id
    assert api_module.AITargetScanRequest(approval_receipt_id=receipt_id).approval_receipt_id == receipt_id
    assert api_module.FindingRetestRequest(approval_receipt_id=receipt_id).approval_receipt_id == receipt_id
    assert api_module.AIFindingRetestRequest(approval_receipt_id=receipt_id).approval_receipt_id == receipt_id
    assert api_module.AIScanReplayRequest(approval_receipt_id=receipt_id).approval_receipt_id == receipt_id
    assert api_module.FindingsBulkRetestRequest(
        finding_ids=[receipt_id],
        approval_receipt_id=receipt_id,
    ).approval_receipt_id == receipt_id


def test_operation_plan_canonicalization_redacts_parameters_and_normalizes_lists():
    plan = api_module.OperationPlanRequest(
        objective=" Review target ",
        planner={"kind": "ui", "api_key": "secret-value"},
        context_hash="A" * 64,
        target_scope={"allowed_hosts": ["app.example.com"], "authorization": "Bearer secret"},
        risk_tier="active",
        confirmations=["confirm_authorized", ""],
        actions=[{
            "command": "asm.improve",
            "parameters": {"auth_header": "Bearer secret-token", "batch_size": 10},
            "risk_tier": "active",
        }],
        stop_conditions=["budget_exhausted", ""],
        success_criteria=["plan_validated"],
    )

    canonical = api_module._canonical_operation_plan(plan)

    assert canonical["objective"] == "Review target"
    assert canonical["context_hash"] == "a" * 64
    assert canonical["confirmations"] == ["confirm_authorized"]
    assert canonical["stop_conditions"] == ["budget_exhausted"]
    assert canonical["actions"][0]["command"] == "asm.improve"
    assert canonical["actions"][0]["parameters"]["auth_header"] != "Bearer secret-token"
    assert canonical["planner"]["api_key"] != "secret-value"
    assert canonical["target_scope"]["authorization"] != "Bearer secret"


def test_public_command_result_row_decodes_json_fields():
    row = {
        "id": uuid.uuid4(),
        "command": "scan.submit",
        "status": "queued",
        "dry_run": False,
        "risk_tier": "active",
        "finding_ids": json.dumps(["finding-1"]),
        "hypothesis_ids": json.dumps([]),
        "evidence_object_ids": json.dumps(["evidence-1"]),
        "tool_receipt_ids": json.dumps([]),
        "blocked_by": json.dumps(["worker_stale"]),
        "result_json": json.dumps({"scan_id": "scan-1"}),
    }

    public = api_module._public_command_result_row(row)

    assert public["finding_ids"] == ["finding-1"]
    assert public["evidence_object_ids"] == ["evidence-1"]
    assert public["blocked_by"] == ["worker_stale"]
    assert public["result_json"] == {"scan_id": "scan-1"}


def test_record_command_result_redacts_result_json_and_returns_public_row():
    captured: dict[str, object] = {}

    class _FakeConn:
        async def fetchrow(self, query, *args):
            captured["query"] = query
            captured["args"] = args
            return {
                "id": uuid.uuid4(),
                "command": args[0],
                "status": args[1],
                "dry_run": args[2],
                "risk_tier": args[3],
                "operation_plan_id": args[4],
                "scope_receipt_id": args[5],
                "approval_receipt_id": args[6],
                "campaign_id": args[7],
                "scan_id": args[8],
                "finding_ids": args[9],
                "hypothesis_ids": args[10],
                "evidence_object_ids": args[11],
                "tool_receipt_ids": args[12],
                "blocked_by": args[13],
                "next_action": args[14],
                "operator_message": args[15],
                "result_json": args[16],
                "created_by": args[17],
                "created_at": "now",
            }

    scan_id = uuid.uuid4()
    approval_id = uuid.uuid4()
    result = asyncio.run(api_module._record_command_result(
        _FakeConn(),
        command="scan.submit",
        status="queued",
        risk_tier="active",
        scan_id=scan_id,
        approval_receipt_id=approval_id,
        scope_receipt_id="scope-1",
        finding_ids=["finding-1"],
        blocked_by=["none"],
        operator_message="Queued scan",
        result_json={"authorization": "Bearer secret-token", "scan_id": str(scan_id)},
        next_action=f"/scans/{scan_id}",
        created_by="pytest",
    ))

    assert "INSERT INTO command_results" in str(captured["query"])
    assert result["command"] == "scan.submit"
    assert result["status"] == "queued"
    assert result["scan_id"] == str(scan_id)
    assert result["approval_receipt_id"] == str(approval_id)
    assert result["finding_ids"] == ["finding-1"]
    assert result["blocked_by"] == ["none"]
    assert result["next_action"] == f"/scans/{scan_id}"
    assert result["created_by"] == "pytest"
    assert result["result_json"]["authorization"] != "Bearer secret-token"
    assert result["result_json"]["scan_id"] == str(scan_id)


def test_agent_context_pack_canonicalization_redacts_and_normalizes_commands():
    pack = api_module.AgentContextPackRequest(
        context_hash="B" * 64,
        target_summary={"url": "https://app.example.com", "api_key": "secret-value"},
        current_surface={"endpoint_count": 3, "authorization": "Bearer secret"},
        allowed_commands=["asm.gaps", ""],
        known_preconditions={"cookies": "session=secret"},
    )

    canonical = api_module._canonical_agent_context_pack(pack)

    assert canonical["context_hash"] == "b" * 64
    assert canonical["allowed_commands"] == ["asm.gaps"]
    assert canonical["target_summary"]["api_key"] != "secret-value"
    assert canonical["current_surface"]["authorization"] != "Bearer secret"
    assert canonical["known_preconditions"]["cookies"] != "session=secret"


def test_agent_context_pack_forbidden_raw_fields_are_detected():
    assert api_module._contains_forbidden_context_key({"raw_transcripts": ["secret"]}) is True
    assert api_module._contains_forbidden_context_key({"nested": {"private_key": "secret"}}) is True
    assert api_module._contains_forbidden_context_key({"evidence_ids": ["evidence-1"]}) is False


def test_agent_decision_trace_canonicalization_redacts_reason_and_refs():
    trace = api_module.AgentDecisionTraceRequest(
        context_hash="C" * 64,
        planner={"kind": "local_agent", "api_key": "secret-value"},
        command_schema_version="2026-07-05.v1",
        steps=[{
            "kind": "proposed_action",
            "command": "asm.gaps",
            "status": "planned",
            "reason": "Use bearer token secret-token",
            "refs": [" evidence-1 ", ""],
        }],
        final_rationale="No raw secret-token should remain",
    )

    canonical = api_module._canonical_agent_decision_trace(trace)

    assert canonical["context_hash"] == "c" * 64
    assert canonical["planner"]["api_key"] != "secret-value"
    assert canonical["steps"][0]["command"] == "asm.gaps"
    assert canonical["steps"][0]["refs"] == ["evidence-1"]
    assert "secret-token" not in canonical["steps"][0]["reason"]
    assert "secret-token" not in canonical["final_rationale"]


def test_generated_agent_context_pack_from_target_uses_stored_facts(monkeypatch):
    target_id = "11111111-1111-4111-8111-111111111111"

    class FakeConn:
        async def fetchrow(self, query, *args):
            if "FROM targets" in query:
                return {
                    "id": target_id,
                    "url": "https://app.example.com",
                    "name": "Production app",
                    "root_domain": "example.com",
                    "is_active": True,
                    "last_scanned_at": None,
                    "last_score": 92,
                    "last_grade": "A",
                    "asm_enabled": True,
                    "asm_config": {},
                    "asm_last_test_at": None,
                    "asm_last_recon_at": None,
                    "metadata_json": {"owner": "security", "environment": "staging", "auth_header": "Bearer secret"},
                }
            return None

        async def fetch(self, query, *args):
            if "FROM target_endpoints" in query and "GROUP BY" in query:
                return [{"auth_state": "anonymous", "test_status": "untested", "count": 2}]
            if "FROM target_endpoints" in query:
                return [{
                    "method": "GET",
                    "path": "/api/orders/{id}",
                    "param_location": "path",
                    "auth_state": "user1",
                    "test_status": "untested",
                    "last_attempt_status": None,
                    "last_verdict": None,
                    "priority_score": 10,
                    "last_seen_at": None,
                    "last_tested_at": None,
                }]
            if "FROM findings" in query:
                assert " category" not in query
                assert " proof_state" not in query
                return [{
                    "id": "finding-1",
                    "title": "BOLA candidate",
                    "severity": "high",
                    "status": "active",
                    "tool": "bola",
                    "url": "https://app.example.com/api/orders/1",
                    "last_verification_verdict": None,
                    "last_seen": None,
                    "first_seen": None,
                }]
            return []

    async def fake_coverage_summary(_conn, _target_id):
        return {"total": 3, "untested": 2, "stale": 1, "tested": 0}

    class FakeRedis:
        def hgetall(self, _key):
            return {}

    monkeypatch.setattr(api_module.asm_inventory, "coverage_summary", fake_coverage_summary)
    monkeypatch.setattr(api_module, "get_redis", lambda: FakeRedis())

    req = api_module.AgentContextPackFromTargetRequest(target_id=target_id, created_by="test")
    generated = asyncio.run(api_module._build_agent_context_pack_from_target(FakeConn(), req))

    assert generated.target_id == target_id
    assert generated.redaction_profile == "agent-plan-generated-target"
    assert generated.target_summary["url"] == "https://app.example.com"
    assert generated.target_summary["owner"] == "security"
    assert generated.current_surface["coverage"]["untested"] == 2
    assert generated.current_surface["sample_endpoints"][0]["path"] == "/api/orders/{id}"
    assert generated.findings_summary[0]["category"] == "bola"
    assert generated.findings_summary[0]["proof_state"] == "suspected"
    assert "asm.gaps" in generated.allowed_commands
    assert "auth_header" not in json.dumps(generated.model_dump(mode="json"))
    assert len(generated.context_hash) == 64


def test_local_agent_dry_run_plan_uses_context_pack_without_spawn():
    context_id = "22222222-2222-4222-8222-222222222222"

    class FakeConn:
        async def fetchrow(self, query, *args):
            if "FROM agent_context_packs" in query:
                return {
                    "id": context_id,
                    "context_version": "2026-07-05.v1",
                    "target_id": None,
                    "context_hash": "d" * 64,
                    "target_summary": {
                        "target_id": "target-1",
                        "url": "https://api.example.com",
                        "root_domain": "example.com",
                        "environment": "production",
                    },
                    "current_surface": {},
                    "current_gaps": [],
                    "hypotheses_summary": [],
                    "findings_summary": [],
                    "allowed_commands": ["asm.gaps", "operation_plan.preview"],
                    "disallowed_commands": [{"command": "scan.focused_family", "reason": "gated:active"}],
                    "known_preconditions": {
                        "primary_credentials": "configured",
                        "second_user_credentials": "unknown",
                    },
                    "context_pack": {
                        "target_summary": {
                            "target_id": "target-1",
                            "url": "https://api.example.com",
                            "root_domain": "example.com",
                            "environment": "production",
                        },
                        "allowed_commands": ["asm.gaps", "operation_plan.preview"],
                        "known_preconditions": {
                            "primary_credentials": "configured",
                            "second_user_credentials": "unknown",
                        },
                        "context_hash": "d" * 64,
                    },
                    "validation_errors": [],
                    "validation_warnings": [],
                    "status": "recorded",
                    "created_by": "test",
                }
            return None

    req = api_module.LocalAgentPlanRequest(
        agent="codex",
        context_pack_id=context_id,
        objective="Plan BOLA checks safely",
        created_by="test",
    )
    plan, metadata = asyncio.run(api_module._build_local_agent_dry_run_plan(FakeConn(), req))

    assert plan.planner["kind"] == "local_agent"
    assert plan.planner["agent"] == "codex"
    assert plan.planner["local_agent_spawned"] is False
    assert plan.planner["planner_execution_enabled"] is False
    assert plan.risk_tier == "read_only"
    assert plan.actions[0].command == "asm.gaps"
    assert plan.actions[0].risk_tier == "read_only"
    assert "second_user_credentials" in plan.missing_inputs
    assert "missing_second_user_auth" in metadata["planner_notes"]
    assert plan.target_scope["allowed_hosts"] == ["api.example.com"]


def test_local_agent_dry_run_plan_rejects_unknown_agent():
    class FakeConn:
        async def fetchrow(self, query, *args):
            return None

    req = api_module.LocalAgentPlanRequest(
        agent="unknown-agent",
        context_pack_id="22222222-2222-4222-8222-222222222222",
        objective="Review coverage",
    )
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module._build_local_agent_dry_run_plan(FakeConn(), req))

    assert exc.value.status_code == 400
    assert "Unknown local agent" in exc.value.detail


def test_policy_profile_required_anchor_ids_must_be_valid_uuids():
    req = api_module.PolicyProfileRequest(
        name="strict",
        product_area="model_intake",
        strict_model_intake=True,
        required_trust_anchor_ids=["not-a-uuid"],
    )

    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module._validate_policy_profile_required_anchor_ids(None, req))

    assert exc.value.status_code == 422
    assert "valid UUIDs" in exc.value.detail


def test_model_intake_trust_anchor_request_requires_material():
    with pytest.raises(api_module.HTTPException) as exc:
        api_module._validate_model_intake_trust_anchor_request(
            api_module.ModelIntakeTrustAnchorRequest(name="empty")
        )

    assert exc.value.status_code == 422
    assert "public_key_pem or public_key_sha256" in exc.value.detail


def test_model_intake_trust_anchor_request_validates_fingerprint():
    with pytest.raises(api_module.HTTPException) as exc:
        api_module._validate_model_intake_trust_anchor_request(
            api_module.ModelIntakeTrustAnchorRequest(name="bad", public_key_sha256="not-a-sha")
        )

    assert exc.value.status_code == 422
    assert "64-character" in exc.value.detail


# ----- finding exception queue filters -------------------------------------

class _ExceptionQueueConn:
    def __init__(self):
        self.fetch_calls = []

    async def fetch(self, query, *args):
        self.fetch_calls.append((query, args))
        return []


def test_list_finding_exceptions_adds_hygiene_filters(monkeypatch):
    conn = _ExceptionQueueConn()
    monkeypatch.setattr(api_module, "db_pool", _FakePool(conn))

    asyncio.run(api_module.list_finding_exceptions(queue_filter="missing_controls", limit=25))
    query, args = conn.fetch_calls[-1]
    assert "compensating_controls IS NULL" in query
    assert "LIMIT $1" in query
    assert args == (25,)

    asyncio.run(api_module.list_finding_exceptions(queue_filter="expiring", expiring_within_days=14, limit=50))
    query, args = conn.fetch_calls[-1]
    assert "expires_at >= NOW()" in query
    assert "expires_at <= NOW()" in query
    assert "status IN ('active', 'approved', 'accepted_risk')" in query
    assert args == (14, 50)


# --- Auto-sharding policy: explicit `parallel` intent must survive (P4) ---
#
# P4 ("parallel:true dropped -> standalone") turned out to be a stale-API skew
# symptom, not a submit-logic bug. These lock in the contract so a regression or
# a future skew is caught: explicit parallel=true ALWAYS becomes a parent, and
# the resolved options_payload ALWAYS carries an explicit `parallel` key (never
# left unset, which is what made the original mis-diagnosis possible).


def _resolve_sharding(monkeypatch, *, worker_count=4, auto_enabled=False, **opt_kwargs):
    """Run _build_scan_options_payload + _apply_auto_sharding_policy like submit_scan."""
    monkeypatch.setattr(
        api_module, "_running_scan_worker_count_best_effort", lambda: worker_count
    )
    monkeypatch.setattr(
        api_module,
        "_load_effective_scan_execution_settings",
        lambda: {"auto_sharding_enabled": auto_enabled, "auto_sharding_min_workers": 2},
    )
    scan_type = opt_kwargs.get("scan_type", "smart")
    options = api_module.ScanOptions(**opt_kwargs)
    payload = api_module._build_scan_options_payload(options, scan_type)
    enabled, _count = api_module._apply_auto_sharding_policy(options, payload, scan_type)
    return enabled, payload


def test_explicit_parallel_true_forces_parent(monkeypatch):
    enabled, payload = _resolve_sharding(
        monkeypatch, scan_type="smart", parallel=True, shard_strategy="family"
    )
    assert enabled is True
    assert payload["parallel"] is True
    assert payload["shard_strategy"] == "family"


def test_explicit_parallel_true_defaults_shards_and_strategy(monkeypatch):
    # parallel=true with no shards/strategy still becomes a parent. Active scans
    # resolve to coverage so discovery is harvested once and workers pull batches.
    enabled, payload = _resolve_sharding(monkeypatch, scan_type="smart", parallel=True)
    assert enabled is True
    assert payload["parallel"] is True
    assert payload.get("shards") == "auto"
    assert payload["shard_strategy"] == "coverage"


def test_explicit_parallel_false_stays_standalone(monkeypatch):
    enabled, payload = _resolve_sharding(
        monkeypatch, scan_type="smart", parallel=False, auto_enabled=True
    )
    assert enabled is False
    # Key is always set explicitly, never left unset.
    assert payload["parallel"] is False


def test_omitted_parallel_with_auto_sharding_off_sets_false_key(monkeypatch):
    # parallel omitted entirely + global auto-sharding disabled -> standalone,
    # but the resolved payload still carries an explicit parallel=False key.
    enabled, payload = _resolve_sharding(monkeypatch, scan_type="standard", auto_enabled=False)
    assert enabled is False
    assert "parallel" in payload
    assert payload["parallel"] is False


# ----- §7 ASM recommended campaigns -------------------------------------------
def test_asm_recommended_campaigns_suggests_family_waves_and_credentials():
    # Inventory exists, SQLi never proved, some stale, some auth-missing.
    recs = api_module._asm_recommended_campaigns(
        coverage={"total": 100, "untested": 10, "stale": 5},
        family_coverage={"all": {"completed": 0, "attempts": 20},
                         "xss": {"completed": 3, "attempts": 5}},
        last_attempt_counts={"auth_missing": 4},
        active_scans=0,
    )
    camps = {r["campaign"] for r in recs}
    assert "add_credentials" in camps          # auth_missing > 0
    assert "sqli_wave" in camps                # no completed SQLi
    assert "xss_wave" not in camps             # XSS has completed attempts
    assert "retest_stale" in camps             # stale > 0


def test_asm_recommended_campaigns_recon_when_empty_and_wait_when_active():
    assert api_module._asm_recommended_campaigns(coverage={"total": 0})[0]["campaign"] == "recon"
    assert api_module._asm_recommended_campaigns(coverage={"total": 9}, active_scans=2)[0]["campaign"] == "wait"


# ----- approval-receipt validation (security-critical gate) --------------------
# _validate_approval_receipt_for_action decides whether a provided receipt actually
# authorizes a state-changing action. It is the enforcement point that stops a
# mismatched/expired/denied/blocked receipt from queueing work, so every rejection
# branch is pinned here with a FakeConn (the host has no asyncpg).

APPROVAL_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
SCOPE_ID = "scope-receipt-1"


def _approval_receipt_conn(*, approval_row=None, scope_row=None):
    """Return a FakeConn that routes the two SELECTs the validator issues."""

    class FakeConn:
        async def fetchrow(self, query, *args):
            if "FROM approval_receipts" in query:
                return approval_row
            if "FROM scope_receipts" in query:
                return scope_row
            return None

    return FakeConn()


def _make_approval_row(**overrides):
    row = {
        "id": APPROVAL_ID,
        "scope_receipt_id": SCOPE_ID,
        "risk_tier": "active",
        "confirmations": ["confirm_authorized"],
        "approved_by": "operator",
        "denial_reason": None,
        "expires_at": None,
    }
    row.update(overrides)
    return row


def _make_scope_row(**overrides):
    row = {
        "id": SCOPE_ID,
        "target_id": None,
        "verdict": "allowed",
        "normalized_scope": {"host": "app.example.com"},
        "allowed_hosts": ["app.example.com"],
        "allowed_root_domains": ["example.com"],
        "input_scope": {},
        "blocked_by": [],
        "warnings": [],
        "checks": [],
        "redirect_destinations": [],
    }
    row.update(overrides)
    return row


def _run_validate(conn, receipt_id, **kwargs):
    return asyncio.run(
        api_module._validate_approval_receipt_for_action(conn, receipt_id, **kwargs)
    )


def test_validate_approval_receipt_accepts_valid_receipt():
    conn = _approval_receipt_conn(approval_row=_make_approval_row(), scope_row=_make_scope_row())
    ctx = _run_validate(conn, APPROVAL_ID, target_url="https://app.example.com/x", action_name="scan.submit")

    assert ctx["approval_receipt_id"] == APPROVAL_ID
    assert ctx["scope_receipt_id"] == SCOPE_ID
    assert ctx["approved_by"] == "operator"


def test_validate_approval_receipt_rejects_non_uuid():
    conn = _approval_receipt_conn()
    with pytest.raises(api_module.HTTPException) as exc:
        _run_validate(conn, "not-a-uuid")
    assert exc.value.status_code == 400
    assert "UUID" in exc.value.detail


def test_validate_approval_receipt_missing_row_is_404():
    conn = _approval_receipt_conn(approval_row=None)
    with pytest.raises(api_module.HTTPException) as exc:
        _run_validate(conn, APPROVAL_ID)
    assert exc.value.status_code == 404


def test_validate_approval_receipt_rejects_denial_receipt():
    conn = _approval_receipt_conn(
        approval_row=_make_approval_row(approved_by=None, denial_reason="not authorized"),
        scope_row=_make_scope_row(),
    )
    with pytest.raises(api_module.HTTPException) as exc:
        _run_validate(conn, APPROVAL_ID)
    assert exc.value.status_code == 400
    assert "not an approval" in exc.value.detail


def test_validate_approval_receipt_requires_confirm_authorized():
    conn = _approval_receipt_conn(
        approval_row=_make_approval_row(confirmations=[]),
        scope_row=_make_scope_row(),
    )
    with pytest.raises(api_module.HTTPException) as exc:
        _run_validate(conn, APPROVAL_ID)
    assert exc.value.status_code == 400
    assert "confirm_authorized" in exc.value.detail


def test_validate_approval_receipt_rejects_expired():
    past = datetime(2000, 1, 1, tzinfo=timezone.utc)
    conn = _approval_receipt_conn(
        approval_row=_make_approval_row(expires_at=past),
        scope_row=_make_scope_row(),
    )
    with pytest.raises(api_module.HTTPException) as exc:
        _run_validate(conn, APPROVAL_ID)
    assert exc.value.status_code == 400
    assert "expired" in exc.value.detail


def test_validate_approval_receipt_rejects_blocked_scope():
    conn = _approval_receipt_conn(
        approval_row=_make_approval_row(),
        scope_row=_make_scope_row(verdict="blocked"),
    )
    with pytest.raises(api_module.HTTPException) as exc:
        _run_validate(conn, APPROVAL_ID)
    assert exc.value.status_code == 400
    assert "blocked" in exc.value.detail


def test_validate_approval_receipt_needs_scope_reviewed_for_needs_approval():
    conn = _approval_receipt_conn(
        approval_row=_make_approval_row(confirmations=["confirm_authorized"]),
        scope_row=_make_scope_row(verdict="needs_approval"),
    )
    with pytest.raises(api_module.HTTPException) as exc:
        _run_validate(conn, APPROVAL_ID)
    assert exc.value.status_code == 400
    assert "confirm_scope_reviewed" in exc.value.detail


def test_validate_approval_receipt_rejects_host_mismatch():
    conn = _approval_receipt_conn(approval_row=_make_approval_row(), scope_row=_make_scope_row())
    with pytest.raises(api_module.HTTPException) as exc:
        _run_validate(conn, APPROVAL_ID, target_url="https://evil.example.net/x")
    assert exc.value.status_code == 400
    assert "host" in exc.value.detail


def test_validate_approval_receipt_rejects_target_id_mismatch():
    conn = _approval_receipt_conn(
        approval_row=_make_approval_row(),
        scope_row=_make_scope_row(target_id="11111111-1111-4111-8111-111111111111"),
    )
    with pytest.raises(api_module.HTTPException) as exc:
        _run_validate(conn, APPROVAL_ID, target_id="22222222-2222-4222-8222-222222222222")
    assert exc.value.status_code == 400
    assert "target" in exc.value.detail
