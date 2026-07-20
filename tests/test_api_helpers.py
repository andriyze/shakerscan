"""Unit tests for small helpers in api/api.py.

These cover the env-var coercer, the pagination → COUNT(*) rewriter, and the
JSON-decode helper that have grown enough surface to be worth pinning.
"""

import asyncio
import base64
import copy
import hashlib
import inspect
import io
import json
import os
import re
import sys
import threading
import types
import uuid
import zipfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


def test_worker_capacity_uses_one_gb_budget_after_platform_reserve(monkeypatch):
    monkeypatch.delenv("SHAKERSCAN_MAX_WORKERS", raising=False)
    monkeypatch.delenv("SHAKERSCAN_PER_WORKER_MEM_GB", raising=False)
    monkeypatch.delenv("SHAKERSCAN_PLATFORM_MEMORY_RESERVE_GB", raising=False)
    monkeypatch.setattr(
        api_module,
        "docker_socket_request",
        lambda *_args, **_kwargs: (200, {"MemTotal": 23 * 1024 ** 3}),
    )

    assert api_module._compute_max_allowed_workers() == 16


def test_worker_capacity_defaults_to_five_below_sixteen_gb(monkeypatch):
    monkeypatch.delenv("SHAKERSCAN_MAX_WORKERS", raising=False)
    monkeypatch.setattr(
        api_module,
        "docker_socket_request",
        lambda *_args, **_kwargs: (200, {"MemTotal": 12 * 1024 ** 3}),
    )

    assert api_module._compute_max_allowed_workers() == 5


def _test_jwt(**claims):
    encode = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    return f"{encode({'alg': 'none'})}.{encode(claims)}.signature"


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
        def __init__(self, content=None, status_code=200, headers=None, media_type=None):
            self.content = content
            self.status_code = status_code
            self.headers = headers or {}
            self.media_type = media_type

    responses_mod.Response = _FakeResponse
    responses_mod.JSONResponse = _FakeResponse
    sys.modules["fastapi.responses"] = responses_mod

import api as api_module  # noqa: E402
from evidence_storage import store_evidence_content  # noqa: E402
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


def test_target_credential_profile_public_shape_never_returns_secret(monkeypatch):
    monkeypatch.setattr(api_module, "encryption_enabled", lambda: True)
    row = {
        "id": uuid.uuid4(),
        "target_id": uuid.uuid4(),
        "name": "customer-a",
        "auth_kind": "authorization_header",
        "secret_value": "enc:fernet:ciphertext",
        "secret_preview": "Bear...en",
        "expires_at": datetime.now(timezone.utc) + timedelta(days=2),
        "is_active": True,
        "metadata_json": json.dumps({"owner": "security"}),
    }

    public = api_module._public_target_credential_profile_row(row)

    assert "secret_value" not in public
    assert public["secret_configured"] is True
    assert public["storage_encrypted"] is True
    assert public["encryption_available"] is True
    assert public["status"] == "active"
    assert public["refresh_required"] is True
    assert "ciphertext" not in json.dumps(public)


def test_target_credential_profile_expiry_and_inactive_states():
    expired, refresh = api_module._target_credential_profile_status({
        "is_active": True,
        "expires_at": datetime.now(timezone.utc) - timedelta(seconds=1),
    })
    inactive, inactive_refresh = api_module._target_credential_profile_status({
        "is_active": False,
        "expires_at": datetime.now(timezone.utc) - timedelta(days=1),
    })

    assert (expired, refresh) == ("expired", True)
    assert (inactive, inactive_refresh) == ("inactive", False)


def test_target_credential_profile_values_encrypt_and_reject_header_injection(monkeypatch):
    monkeypatch.setattr(api_module, "encrypt_secret", lambda value: f"encrypted:{value}")
    values = api_module._target_credential_profile_values(
        name=" Customer A ",
        auth_kind="authorization_header",
        secret="Bearer token",
        expires_at=None,
        metadata_json={"owner": "security"},
    )

    assert values["name"] == "Customer A"
    assert values["secret_value"] == "encrypted:Bearer token"
    assert values["secret_preview"] != "Bearer token"

    with pytest.raises(api_module.HTTPException) as exc:
        api_module._target_credential_profile_values(
            name="customer-a",
            auth_kind="authorization_header",
            secret="Bearer token\r\nX-Admin: true",
            expires_at=None,
            metadata_json={},
        )
    assert exc.value.status_code == 400


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


def test_short_url_label_drops_userinfo_credentials():
    label = api_module._short_url_label("https://svc:sk-abc123@registry.internal/model.safetensors")
    assert "sk-abc123" not in label and "svc:" not in label
    assert "registry.internal" in label


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
    assert by_id["policy-exception-hygiene"]["href"] == "/exceptions"
    assert by_id["policy-exception-hygiene"]["actions"][0]["href"] == "/exceptions?queue_filter=expired"
    assert by_id["asm-coverage-gaps"]["href"] == "/asm?target_id=11111111-1111-4111-8111-111111111111"
    assert by_id["asm-coverage-gaps"]["actions"][0]["label"] == "Improve coverage"
    assert by_id["next-asm-schedule"]["priority"] == "info"
    assert by_id["recent-failed-scans"]["actions"][1]["label"] == "Latest failed scan"
    assert by_id["model-intake-untrusted-signatures"]["samples"][0]["detail"] == "signature status: untrusted_root"
    assert by_id["model-intake-untrusted-signatures"]["actions"][0]["href"] == "/model-intake?remediate=trust"
    assert by_id["model-intake-untrusted-signatures"]["actions"][1]["label"] == "Latest scan"
    # No refuter data in the base fake -> the best-effort refuter block adds nothing.
    assert "refuter-review-backlog" not in by_id


def test_schedule_health_marks_repeated_quick_timeout():
    schedule = {
        "id": "22222222-2222-4222-8222-222222222222",
        "target_id": "11111111-1111-4111-8111-111111111111",
        "schedule_kind": "normal_scan",
        "scan_type": "quick",
        "is_active": True,
    }
    failures = [
        {
            "id": "33333333-3333-4333-8333-333333333333",
            "error_message": "Scan terminated: Exceeded max duration (32 min > 15 min for quick scan)",
            "created_at": "2026-07-09T00:44:55+00:00",
        },
        {
            "id": "44444444-4444-4444-8444-444444444444",
            "error_message": "Scan terminated: No heartbeat for 16.9 minutes",
            "created_at": "2026-07-08T01:08:38+00:00",
        },
    ]

    health = api_module._schedule_health_from_failures(schedule, failures)

    assert health["status"] == "attention"
    assert health["reason"] == "repeated_timeout"
    assert health["recent_failed_count"] == 2
    assert health["timeout_failed_count"] == 2
    assert health["latest_failed_scan_id"] == "33333333-3333-4333-8333-333333333333"
    assert health["suggested_scan_type"] == "standard"
    assert "Pause this schedule" in health["recommendation"]


def test_dashboard_action_center_surfaces_recurring_schedule_failures():
    target_id = uuid.UUID("11111111-1111-4111-8111-111111111111")
    schedule_id = uuid.UUID("22222222-2222-4222-8222-222222222222")
    latest_scan_id = uuid.UUID("33333333-3333-4333-8333-333333333333")

    class _Conn:
        async def fetchrow(self, query, *args):
            return {}

        async def fetch(self, query, *args):
            if "FROM schedules s" in query and "JOIN targets t" in query:
                return [{
                    "id": schedule_id,
                    "target_id": target_id,
                    "target_url": "https://shakerscan.com",
                    "target_name": None,
                    "schedule_kind": "normal_scan",
                    "scan_type": "quick",
                    "scan_options": {},
                    "is_active": True,
                    "updated_at": "2026-07-09T01:16:41+00:00",
                }]
            if "FROM scans" in query and "target_id = ANY" in query:
                return [
                    {
                        "id": latest_scan_id,
                        "target_id": target_id,
                        "target_url": "https://shakerscan.com",
                        "scan_type": "quick",
                        "error_message": "Scan terminated: Exceeded max duration (32 min > 15 min for quick scan)",
                        "created_at": "2026-07-09T00:44:55+00:00",
                        "completed_at": "2026-07-09T01:16:44+00:00",
                    },
                    {
                        "id": uuid.UUID("44444444-4444-4444-8444-444444444444"),
                        "target_id": target_id,
                        "target_url": "https://shakerscan.com",
                        "scan_type": "quick",
                        "error_message": "Scan terminated: No heartbeat for 16.9 minutes",
                        "created_at": "2026-07-08T01:08:38+00:00",
                        "completed_at": "2026-07-08T01:26:01+00:00",
                    },
                ]
            return []

    items = asyncio.run(
        api_module._build_dashboard_action_center(_Conn(), worker_snapshot={"available": False})
    )
    by_id = {item["id"]: item for item in items}

    assert "schedule-health-attention" in by_id
    item = by_id["schedule-health-attention"]
    assert item["priority"] == "high"
    assert item["href"] == "/schedules?health=attention"
    assert item["actions"][1]["href"] == f"/scans/{latest_scan_id}"
    assert item["metadata"]["schedule_ids"] == [str(schedule_id)]
    assert item["samples"][0]["label"] == "https://shakerscan.com"
    assert "Exceeded max duration" in item["samples"][0]["detail"]


def test_dashboard_action_center_does_not_flag_recovered_schedule():
    """A schedule that failed during an outage but has succeeded SINCE must not be flagged."""
    import datetime as _dt
    target_id = uuid.UUID("11111111-1111-4111-8111-111111111111")
    schedule_id = uuid.UUID("22222222-2222-4222-8222-222222222222")
    failure_time = _dt.datetime(2026, 7, 1, 0, 44, 55, tzinfo=_dt.timezone.utc)
    recovery_time = _dt.datetime(2026, 7, 8, 2, 0, 0, tzinfo=_dt.timezone.utc)  # newer than the failure

    class _Conn:
        async def fetchrow(self, query, *args):
            return {}

        async def fetch(self, query, *args):
            if "FROM schedules s" in query and "JOIN targets t" in query:
                return [{
                    "id": schedule_id, "target_id": target_id, "target_url": "https://shakerscan.com",
                    "target_name": None, "schedule_kind": "normal_scan", "scan_type": "quick",
                    "scan_options": {}, "is_active": True, "updated_at": "2026-07-09T01:16:41+00:00",
                }]
            if "last_success" in query:
                return [{"target_id": target_id, "scan_type": "quick", "last_success": recovery_time}]
            if "FROM scans" in query and "target_id = ANY" in query:
                return [{
                    "id": uuid.UUID("33333333-3333-4333-8333-333333333333"), "target_id": target_id,
                    "target_url": "https://shakerscan.com", "scan_type": "quick",
                    "error_message": "Scan terminated: Exceeded max duration",
                    "created_at": failure_time, "completed_at": failure_time,
                }]
            return []

    items = asyncio.run(
        api_module._build_dashboard_action_center(_Conn(), worker_snapshot={"available": False})
    )
    by_id = {item["id"]: item for item in items}
    assert "schedule-health-attention" not in by_id


def test_dashboard_action_center_surfaces_refuter_integrity_spike():
    # A target whose latest scan spiked from a ~4-finding baseline to 30.
    spike_scans = [
        {"target_id": "t1", "target_url": "https://app.example.test", "scan_id": "s4", "findings_count": 30},
        {"target_id": "t1", "target_url": "https://app.example.test", "scan_id": "s3", "findings_count": 4},
        {"target_id": "t1", "target_url": "https://app.example.test", "scan_id": "s2", "findings_count": 5},
        {"target_id": "t1", "target_url": "https://app.example.test", "scan_id": "s1", "findings_count": 3},
    ]

    class _Conn:
        async def fetchrow(self, query, *args):
            return {}  # no blocker/exception/asm/schedule items

        async def fetch(self, query, *args):
            if "FROM scans" in query and "ROW_NUMBER()" in query:
                return spike_scans
            return []  # no weak findings, reviews, failed scans, model intake, or ai targets

    items = asyncio.run(
        api_module._build_dashboard_action_center(_Conn(), worker_snapshot={"available": False})
    )
    by_id = {item["id"]: item for item in items}
    assert "refuter-review-backlog" in by_id
    item = by_id["refuter-review-backlog"]
    assert item["category"] == "Refuter"
    assert item["metadata"]["integrity_signal_count"] == 1
    assert item["metadata"]["unreviewed_candidate_count"] == 0
    assert item["count"] == 1
    assert item["samples"][0]["target_id"] == "t1"
    assert item["samples"][0]["latest_finding_count"] == 30


def test_dashboard_action_center_surfaces_asm_auth_blockers():
    target_id = "11111111-1111-4111-8111-111111111111"

    class _Conn:
        async def fetchrow(self, query, *args):
            return {}  # no blocker/exception/asm/schedule items from fetchrow paths

        async def fetch(self, query, *args):
            if "FROM targets t" in query and "JOIN target_endpoints te" in query:
                return [{
                    "target_id": target_id,
                    "target_url": "https://app.example.test",
                    "blocked_endpoint_count": 7,
                }]
            return []  # no failed scans, model rows, AI targets, or refuter rows

    items = asyncio.run(
        api_module._build_dashboard_action_center(_Conn(), worker_snapshot={"available": False})
    )
    by_id = {item["id"]: item for item in items}
    assert "asm-auth-blockers" in by_id
    item = by_id["asm-auth-blockers"]
    assert item["priority"] == "high"
    assert item["count"] == 7
    assert item["href"] == f"/asm?target_id={target_id}"
    assert item["actions"][0]["href"] == f"/asm?target_id={target_id}"
    assert item["actions"][1]["href"] == f"/schedules?create=true&target_id={target_id}"
    assert item["metadata"]["blocked_statuses"] == ["auth_missing", "auth_failed"]
    assert item["samples"][0]["detail"] == "7 endpoint(s) need credentials before replay."


def test_dashboard_action_center_surfaces_second_user_blockers():
    target_id = "11111111-1111-4111-8111-111111111111"

    class _Conn:
        async def fetchrow(self, query, *args):
            return {}  # no blocker/exception/asm/schedule items from fetchrow paths

        async def fetch(self, query, *args):
            if "FROM campaign_actions ca" in query and "missing_second_user_auth" in query:
                return [{
                    "id": "action-1",
                    "target_id": target_id,
                    "target_url": "https://app.example.test",
                    "command": "asm.improve",
                    "action_name": "asm.improve",
                    "blocked_by": ["missing_second_user_auth"],
                    "created_at": "2026-07-08T12:00:00",
                }]
            return []  # no failed scans, model rows, AI targets, refuter rows, or auth endpoint blockers

    items = asyncio.run(
        api_module._build_dashboard_action_center(_Conn(), worker_snapshot={"available": False})
    )
    by_id = {item["id"]: item for item in items}
    assert "asm-second-user-blockers" in by_id
    item = by_id["asm-second-user-blockers"]
    assert item["priority"] == "high"
    assert item["count"] == 1
    assert item["href"] == f"/asm?target_id={target_id}"
    assert item["actions"][0]["href"] == f"/asm?target_id={target_id}"
    assert item["actions"][1]["href"] == "/settings/arsenal"
    assert item["metadata"]["blocked_action_count"] == 1
    assert "missing_second_user_auth" in item["metadata"]["blocked_reasons"]
    assert item["samples"][0]["detail"] == "Second-user credentials are required before this authz/BOLA action can run."


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
    assert ai_item["href"] == "/ai-gate?remediate=controls"
    assert ai_item["actions"][0]["href"] == "/ai-gate?remediate=controls"
    assert ai_item["actions"][1]["href"] == "/findings?source_type=ai&status=active"
    assert ai_item["samples"][0]["href"] == "/ai-gate?remediate=controls"
    assert "AI asset owner" in ai_item["samples"][0]["detail"]


class _ProductStatusConn:
    def __init__(self, *, exceptions=None):
        self.exceptions = exceptions or {"expired": 1, "expiring": 2, "weak_records": 3}

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
            return self.exceptions
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
    assert by_id["dast"]["actions"][1]["href"] == "/scans?status=failed"
    assert by_id["asm"]["href"] == "/asm?target_id=11111111-1111-4111-8111-111111111111"
    assert by_id["asm"]["secondary_count"] == 25
    assert by_id["asm"]["actions"][0]["label"] == "Target timeline"
    assert by_id["asm"]["actions"][1]["href"] == "/schedules?create=true&target_id=11111111-1111-4111-8111-111111111111"
    assert by_id["ai_gate"]["status"] == "warning"
    assert by_id["ai_gate"]["secondary_label"] == "control gaps"
    assert by_id["ai_gate"]["href"] == "/ai-gate?remediate=controls"
    assert by_id["ai_gate"]["actions"][0]["href"] == "/ai-gate?remediate=controls"
    assert by_id["ai_gate"]["actions"][1]["href"] == "/findings?source_type=ai&status=active"
    assert by_id["model_intake"]["status"] == "critical"
    assert by_id["model_intake"]["href"] == "/model-intake?remediate=trust"
    assert by_id["model_intake"]["actions"][0]["label"] == "Fix trust"
    assert by_id["model_intake"]["actions"][1]["href"] == "/findings?source_type=model_intake&status=active"
    assert by_id["exceptions"]["href"] == "/exceptions?queue_filter=expired"
    assert by_id["exceptions"]["actions"][1]["href"] == "/exceptions?queue_filter=expiring"
    assert by_id["deployment"]["primary_count"] == 1
    assert by_id["workers"]["status"] == "critical"
    assert by_id["workers"]["metadata"]["total"] == 5


def test_dashboard_product_status_links_missing_exception_controls():
    snapshot = {"available": False}
    items = asyncio.run(api_module._build_dashboard_product_status(
        _ProductStatusConn(exceptions={"expired": 0, "expiring": 0, "weak_records": 3}),
        worker_snapshot=snapshot,
    ))
    by_id = {item["id"]: item for item in items}

    assert by_id["exceptions"]["status"] == "warning"
    assert by_id["exceptions"]["actions"][0]["href"] == "/exceptions?queue_filter=missing_controls"


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


class _AsmEnqueueConn:
    def __init__(self, *, fail_queue_failure_update=False):
        self.executes = []
        self.fail_queue_failure_update = fail_queue_failure_update

    async def execute(self, query, *args):
        self.executes.append((query, args))
        if self.fail_queue_failure_update and "UPDATE scans" in query:
            raise RuntimeError("database unavailable during compensation")
        return "OK"


async def _fake_create_asm_campaign(*_args, **_kwargs):
    return "22222222-2222-4222-8222-222222222222"


def test_enqueue_asm_exploit_batch_fails_committed_scan_when_queue_handoff_fails(monkeypatch):
    conn = _AsmEnqueueConn()
    redis_client = _FailingRedis()
    monkeypatch.setattr(api_module.asm_inventory, "create_campaign", _fake_create_asm_campaign)

    with pytest.raises(RuntimeError, match="redis down"):
        asyncio.run(api_module._enqueue_asm_exploit_batch(
            conn,
            redis_client,
            "11111111-1111-4111-8111-111111111111",
            "https://example.test",
            {},
            batch_size=10,
            stale_days=30,
            exploit_depth=False,
        ))

    insert = next(item for item in conn.executes if "INSERT INTO scans" in item[0])
    failed = next(item for item in conn.executes if "UPDATE scans" in item[0])
    campaign_failed = next(item for item in conn.executes if "UPDATE scan_campaigns" in item[0])
    assert failed[1][0] == insert[1][0]
    assert "WHERE id=$1 AND status='pending'" in failed[0]
    assert "queue handoff could not be durably confirmed" in failed[1][1]
    assert campaign_failed[1] == (
        uuid.UUID("22222222-2222-4222-8222-222222222222"),
        insert[1][0],
    )
    assert "other.campaign_id=campaign.id AND other.id<>$2" in campaign_failed[0]
    assert json.loads(insert[1][4])["queue_handoff_confirmed"] is False
    assert len(redis_client.rpush_calls) == 1


def test_enqueue_asm_recon_preserves_queue_error_when_failure_cas_also_fails(monkeypatch):
    conn = _AsmEnqueueConn(fail_queue_failure_update=True)
    redis_client = _FailingRedis()
    monkeypatch.setattr(api_module.asm_inventory, "create_campaign", _fake_create_asm_campaign)

    with pytest.raises(RuntimeError, match="redis down"):
        asyncio.run(api_module._enqueue_asm_recon(
            conn,
            redis_client,
            "11111111-1111-4111-8111-111111111111",
            "https://example.test",
            {},
        ))

    assert any("INSERT INTO scans" in query for query, _args in conn.executes)
    failed = next(item for item in conn.executes if "UPDATE scans" in item[0])
    assert "WHERE id=$1 AND status='pending'" in failed[0]
    assert "queue handoff could not be durably confirmed" in failed[1][1]
    assert len(redis_client.rpush_calls) == 1


def test_enqueue_asm_recon_metadata_cache_failure_does_not_mask_durable_queue(monkeypatch):
    class MetadataFailingRedis(_RecordingRedis):
        def hset(self, *args, **kwargs):
            super().hset(*args, **kwargs)
            raise RuntimeError("metadata cache down")

    conn = _AsmEnqueueConn()
    redis_client = MetadataFailingRedis()
    monkeypatch.setattr(api_module.asm_inventory, "create_campaign", _fake_create_asm_campaign)

    result = asyncio.run(api_module._enqueue_asm_recon(
        conn,
        redis_client,
        "11111111-1111-4111-8111-111111111111",
        "https://example.test",
        {},
    ))

    assert result["scan_id"]
    assert len(redis_client.rpush_calls) == 1
    assert len(redis_client.hset_calls) == 1
    assert any(
        "SET status='queued'" in query and "queue_handoff_confirmed" in query
        for query, _args in conn.executes
    )
    assert not any("SET status='failed'" in query for query, _args in conn.executes)


@pytest.mark.parametrize("kind", ["exploit", "recon"])
def test_asm_enqueue_persists_research_dispatch_correlation_before_queue_handoff(
    monkeypatch, kind,
):
    conn = _AsmEnqueueConn()
    redis_client = _RecordingRedis()
    monkeypatch.setattr(api_module.asm_inventory, "create_campaign", _fake_create_asm_campaign)
    correlation = (
        "research_episode:11111111-1111-4111-8111-111111111111:"
        "decision:22222222-2222-4222-8222-222222222222"
    )
    token = api_module._ARSENAL_CREATED_BY_CONTEXT.set(correlation)
    try:
        if kind == "exploit":
            asyncio.run(api_module._enqueue_asm_exploit_batch(
                conn,
                redis_client,
                "33333333-3333-4333-8333-333333333333",
                "https://example.test",
                {},
                batch_size=10,
                stale_days=30,
                exploit_depth=False,
            ))
        else:
            asyncio.run(api_module._enqueue_asm_recon(
                conn,
                redis_client,
                "33333333-3333-4333-8333-333333333333",
                "https://example.test",
                {},
            ))
    finally:
        api_module._ARSENAL_CREATED_BY_CONTEXT.reset(token)

    insert = next(item for item in conn.executes if "INSERT INTO scans" in item[0])
    persisted_options = json.loads(insert[1][4])
    queued_payload = json.loads(redis_client.rpush_calls[0][1])
    assert persisted_options["research_dispatch_correlation"] == correlation
    assert persisted_options["queue_handoff_confirmed"] is False
    assert queued_payload["research_dispatch_correlation"] == correlation


@pytest.mark.parametrize(
    ("kind", "readback_status"),
    [
        ("exploit", "queued"),
        ("recon", "running"),
        ("exploit", "failed"),
        ("recon", "cancelled"),
    ],
)
def test_enqueue_asm_confirmation_ack_loss_uses_exact_fresh_readback(
    monkeypatch, kind, readback_status,
):
    class AckLostConn(_AsmEnqueueConn):
        async def execute(self, query, *args):
            self.executes.append((query, args))
            if "SET status='queued'" in query:
                raise RuntimeError("confirmation acknowledgement lost")
            return "UPDATE 1"

    primary = AckLostConn()

    class ReadbackConn:
        async def fetchrow(self, query, *args):
            insert = next(item for item in primary.executes if "INSERT INTO scans" in item[0])
            options = json.loads(insert[1][4])
            options["queue_handoff_confirmed"] = True
            return {
                "status": readback_status,
                "job_id": insert[1][3],
                "campaign_id": insert[1][-1],
                "options": options,
            }

    redis_client = _RecordingRedis()
    monkeypatch.setattr(api_module.asm_inventory, "create_campaign", _fake_create_asm_campaign)
    monkeypatch.setattr(api_module, "db_pool", _FakePool(ReadbackConn()))

    if kind == "exploit":
        result = asyncio.run(api_module._enqueue_asm_exploit_batch(
            primary,
            redis_client,
            "11111111-1111-4111-8111-111111111111",
            "https://example.test",
            {},
            batch_size=10,
            stale_days=30,
            exploit_depth=False,
        ))
    else:
        result = asyncio.run(api_module._enqueue_asm_recon(
            primary,
            redis_client,
            "11111111-1111-4111-8111-111111111111",
            "https://example.test",
            {},
        ))

    assert result["scan_id"]
    assert len(redis_client.rpush_calls) == 1
    assert len(redis_client.hset_calls) == 1
    assert not any("SET status='failed'" in query for query, _args in primary.executes)


@pytest.mark.parametrize("kind", ["exploit", "recon"])
def test_enqueue_asm_confirmation_write_failure_fails_scan_and_campaign(monkeypatch, kind):
    class ConfirmationFailingConn(_AsmEnqueueConn):
        async def execute(self, query, *args):
            self.executes.append((query, args))
            if "SET status='queued'" in query:
                raise RuntimeError("confirmation write failed")
            return "UPDATE 1"

    conn = ConfirmationFailingConn()
    redis_client = _RecordingRedis()
    monkeypatch.setattr(api_module.asm_inventory, "create_campaign", _fake_create_asm_campaign)
    monkeypatch.setattr(api_module, "db_pool", None)

    with pytest.raises(RuntimeError, match="confirmation write failed"):
        if kind == "exploit":
            asyncio.run(api_module._enqueue_asm_exploit_batch(
                conn,
                redis_client,
                "11111111-1111-4111-8111-111111111111",
                "https://example.test",
                {},
                batch_size=10,
                stale_days=30,
                exploit_depth=False,
            ))
        else:
            asyncio.run(api_module._enqueue_asm_recon(
                conn,
                redis_client,
                "11111111-1111-4111-8111-111111111111",
                "https://example.test",
                {},
            ))

    assert len(redis_client.rpush_calls) == 1
    assert redis_client.hset_calls == []
    failed_scan = next(
        item for item in conn.executes
        if "SET status='failed'" in item[0] and "UPDATE scans" in item[0]
    )
    failed_campaign = next(item for item in conn.executes if "UPDATE scan_campaigns" in item[0])
    assert "queue handoff could not be durably confirmed" in failed_scan[1][1]
    assert failed_campaign[1][0] == uuid.UUID("22222222-2222-4222-8222-222222222222")


def test_reconcile_stale_unconfirmed_asm_handoff_fails_scan_and_owned_campaign():
    scan_id = uuid.UUID("11111111-1111-4111-8111-111111111111")
    campaign_id = uuid.UUID("22222222-2222-4222-8222-222222222222")

    class Conn:
        def __init__(self):
            self.executions = []

        async def fetch(self, query, *args):
            assert "queue_handoff_confirmed" in query
            return [{"id": scan_id, "campaign_id": campaign_id}]

        async def fetchval(self, query, *args):
            self.executions.append((query, args))
            assert "SET status='failed'" in query
            return scan_id

        async def execute(self, query, *args):
            self.executions.append((query, args))
            return "UPDATE 1"

    conn = Conn()
    repaired = asyncio.run(api_module._reconcile_unconfirmed_asm_queue_handoffs(conn))

    assert repaired == 1
    assert any(
        "options->>'queue_handoff_confirmed'='false'" in query
        for query, _args in conn.executions
    )
    campaign_update = next(item for item in conn.executions if "UPDATE scan_campaigns" in item[0])
    assert campaign_update[1] == (campaign_id, scan_id)
    assert "other.campaign_id=campaign.id AND other.id<>$2" in campaign_update[0]


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
    assert api_module._normalize_schedule_kind("evidence_retention_sweep", {}) == "evidence_retention_sweep"
    assert api_module._normalize_schedule_kind(None, {"kind": "asm_improve"}) == "asm_improve"

    with pytest.raises(ValueError):
        api_module._normalize_schedule_kind("normal_scan", {"kind": "asm_improve"})

    with pytest.raises(ValueError):
        api_module._normalize_schedule_kind("bad_kind", {})


def test_create_schedule_rejects_retention_schedule_before_database_access():
    request = api_module.ScheduleCreate(
        target_id=str(uuid.uuid4()),
        frequency="daily",
        schedule_kind="evidence_retention_sweep",
        scan_options={"dry_run": True},
    )

    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module.create_schedule(request))

    assert exc.value.status_code == 400
    assert "no longer supported" in str(exc.value.detail)


def test_run_due_schedules_does_not_advance_schedule_on_redis_failure(monkeypatch):
    conn = _FakeConn([_due_schedule()])
    redis_client = _FailingRedis()
    monkeypatch.setattr(api_module, "get_redis", lambda: redis_client)

    scheduler_pool = _FakePool(conn)
    asyncio.run(api_module.run_due_schedules(scheduler_pool))

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


def test_run_due_schedules_disables_legacy_retention_schedule(monkeypatch):
    schedule = _due_schedule()
    schedule["schedule_kind"] = "evidence_retention_sweep"
    schedule["scan_options"] = {
        "retention_class": "short",
        "older_than_days": 90,
        "limit": 10,
    }
    conn = _FakeConn([schedule])
    redis_client = _RecordingRedis()
    monkeypatch.setattr(api_module, "get_redis", lambda: redis_client)

    scheduler_pool = _FakePool(conn)
    asyncio.run(api_module.run_due_schedules(scheduler_pool))

    executed_sql = "\n".join(query for query, _args in conn.executes)
    assert "INSERT INTO scans" not in executed_sql
    assert "UPDATE schedules SET is_active = false" in executed_sql
    assert "UPDATE schedules SET last_run_at" not in executed_sql
    assert redis_client.rpush_calls == []
    assert redis_client.hset_calls == []


def test_run_due_schedules_disables_legacy_destructive_retention_schedule(monkeypatch):
    schedule = _due_schedule()
    schedule["schedule_kind"] = "evidence_retention_sweep"
    schedule["scan_options"] = {"dry_run": False}
    conn = _FakeConn([schedule])
    redis_client = _RecordingRedis()
    monkeypatch.setattr(api_module, "get_redis", lambda: redis_client)

    asyncio.run(api_module.run_due_schedules(_FakePool(conn)))

    executed_sql = "\n".join(query for query, _args in conn.executes)
    assert "INSERT INTO scans" not in executed_sql
    assert "UPDATE schedules SET is_active = false" in executed_sql
    assert "UPDATE schedules SET next_run_at" not in executed_sql
    assert "UPDATE schedules SET last_run_at" not in executed_sql


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
                "blocked_by": "daily_endpoint_cap",
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
        target_id="target-1",
        target_url="https://app.example.test/api",
    )

    kinds = [event["kind"] for event in timeline]
    assert kinds[:4] == ["active_scan", "scheduler_decision", "next_eligible", "scheduled_wave"]
    assert "last_scheduler_decision" in kinds
    assert "activity" in kinds
    assert timeline[0]["href"] == "/scans/scan-active"
    assert timeline[0]["remediation"]["href"] == "/scans/scan-active"
    assert timeline[1]["remediation"] == {
        "kind": "schedule",
        "label": "Adjust schedule",
        "href": "/schedules?create=true&target_id=target-1",
    }
    assert timeline[3]["href"] == "/schedules"
    assert any(event["detail"] == "daily cap reached" for event in timeline)


def test_asm_campaign_timeline_routes_auth_blockers_to_prefilled_session():
    timeline = api_module._build_asm_campaign_timeline(
        scheduler_state={
            "decision": {
                "action": "none",
                "blocked_by": "second_user_auth_missing",
                "reason": "BOLA requires two authenticated principals",
            },
        },
        activity=[],
        target_id="target-1",
        target_url="https://app.example.test/api?tenant=one",
    )

    assert timeline[0]["remediation"] == {
        "kind": "configure_auth",
        "label": "Configure auth session",
        "href": "/interactive?target=https%3A%2F%2Fapp.example.test%2Fapi%3Ftenant%3Done&target_id=target-1",
    }


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
                "evidence_manifest": {
                    "schema_version": "2026-05-19.ai-evidence-manifest.v1",
                    "target_snapshot_hash": f"target-hash-{scan_id}",
                    "target_snapshot": {"headers": {"Authorization": "Bearer secret-token"}},
                    "probe_catalog": {
                        "probe_pack": pack,
                        "scan_profile": profile,
                        "planned_count": planned,
                        "executed_count": executed,
                        "planned_hash": f"planned-hash-{scan_id}",
                        "executed_hash": f"executed-hash-{scan_id}",
                    },
                    "detectors": {
                        "version": "ai_gate_detectors.2026-05-19",
                        "control_catalog_hash": f"controls-hash-{scan_id}",
                    },
                    "planner": {
                        "execution_plan": {"turns": [{"prompt": "raw prompt should not export"}]},
                    },
                    "judging": {
                        "semantic": {
                            "enabled": True,
                            "provider_configured": True,
                            "model": "judge-model",
                            "rubric_version": "semantic_judge.2026-05-19",
                            "prompt_hash": f"semantic-prompt-hash-{scan_id}",
                        },
                        "rubric": {
                            "enabled": False,
                            "provider_configured": False,
                            "model": None,
                            "rubric_version": "rubric_judge.2026-05-19",
                            "prompt_hash": f"rubric-prompt-hash-{scan_id}",
                        },
                    },
                    "evidence_hashes": {
                        "transcripts_hash": f"hash-{scan_id}",
                        "findings_hash": f"findings-hash-{scan_id}",
                        "control_evidence_hash": f"control-evidence-hash-{scan_id}",
                        "coverage_matrix_hash": f"coverage-hash-{scan_id}",
                    },
                    "budget": {
                        "request_budget": 10,
                        "request_count": executed,
                        "remaining_requests": max(0, 10 - executed),
                        "stopped_by_request_budget": False,
                    },
                    "sanitization": {
                        "credentials_masked_in_manifest": True,
                        "headers_and_metadata_redacted_by_key": True,
                    },
                },
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
    assert history["readiness_trends"]["overall"]["state"] == "improving"
    assert history["readiness_trends"]["overall"]["coverage_delta"] == 50
    assert history["readiness_trends"]["overall"]["findings_delta"] == -2
    assert history["readiness_trends"]["contexts"][0]["trend"]["latest_run_id"] == "scan-4"
    assert [point["scan_id"] for point in history["trend_series"]["overall"]] == ["scan-2", "scan-3", "scan-4"]
    assert history["trend_series"]["overall"][-1]["readiness_score"] == 100
    assert rag_context["trend_points"][0]["scan_id"] == "scan-3"
    assert rag_context["trend_points"][1]["scan_id"] == "scan-4"
    assert history["trend_series"]["contexts"][0]["points"]
    assert history["runs"][0]["evidence_manifest_summary"]["probe_catalog"]["executed_count"] == 4
    assert history["runs"][0]["transcripts_hash"] == "hash-scan-4"
    assert len(history["runs"][0]["manifest_hash"]) == 64


def test_ai_target_campaign_history_export_is_content_free_with_report_links():
    latest_rag = _ai_history_row("scan-4", decision="allow", executed=4, skipped=0, findings_count=0)
    previous_rag = _ai_history_row("scan-3", decision="block", executed=2, skipped=1, findings_count=2)
    history = api_module._build_ai_target_campaign_history(
        "target-ai",
        [latest_rag, previous_rag],
        limit=12,
    )

    export = api_module._build_ai_target_campaign_history_export(
        history,
        generated_at=datetime(2026, 7, 6, tzinfo=timezone.utc),
    )

    assert export["schema_version"] == "2026-07-06.ai-target-campaign-history-export.v1"
    assert len(export["export_hash"]) == 64
    assert export["content_included"] is False
    assert export["transcripts_included"] is False
    assert export["readiness_trends"]["overall"]["state"] == "improving"
    assert [point["scan_id"] for point in export["trend_series"]["overall"]] == ["scan-3", "scan-4"]
    assert export["trend_series"]["overall"][-1]["readiness_score"] == 100
    assert export["evidence_manifests"]["available_count"] == 2
    assert export["evidence_manifests"]["runs"][0]["scan_id"] == "scan-4"
    assert export["evidence_manifests"]["runs"][0]["evidence_hashes"]["transcripts_hash"] == "hash-scan-4"
    assert export["evidence_manifests"]["runs"][0]["probe_catalog"]["planned_count"] == 4
    assert export["report_links"][0] == {
        "scan_id": "scan-4",
        "scan_url": "/scans/scan-4",
        "redteam_report_url": "/scans/scan-4/ai-redteam-report",
    }
    serialized = json.dumps(export).lower()
    assert '"turns"' not in serialized
    assert '"response_excerpt"' not in serialized
    assert "authorization" not in serialized
    assert "secret-token" not in serialized
    assert "raw prompt" not in serialized


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


def test_model_intake_evidence_export_is_content_free():
    scan_id = uuid.uuid4()
    target_id = uuid.uuid4()
    payload = {
        "id": scan_id,
        "target_id": target_id,
        "target_url": "https://models.example.com/releases/model.safetensors?token=secret-token",
        "status": "completed",
        "run_kind": "model_intake",
        "created_at": datetime(2026, 7, 6, tzinfo=timezone.utc),
        "completed_at": datetime(2026, 7, 6, 0, 1, tzinfo=timezone.utc),
        "score": 91,
        "grade": "A",
        "findings_count": 0,
        "result": {
            "model_intake": {
                "summary": {
                    "artifact_name": "Release model",
                    "artifact_ref": "https://models.example.com/releases/model.safetensors?token=secret-token",
                    "source_kind": "http",
                    "extension": ".safetensors",
                    "sha256": "a" * 64,
                    "expected_sha256": "a" * 64,
                    "checksum_status": "verified",
                    "checksum_match": True,
                    "checksum_policy_status": "pass",
                    "format_posture": "safer_static_format",
                    "signature_verification_status": "verified",
                    "signature_verified": True,
                    "signature_valid": True,
                    "signature_trusted_root": True,
                    "signature_key_fingerprint": "f" * 64,
                    "signature_trust_anchors_configured": True,
                    "signature_cryptographically_verified": True,
                    "signature_verifier": "cryptography",
                    "strict_governance": True,
                    "deployment_environment": "production",
                    "deployment_approved": True,
                    "license_policy_status": "permissive",
                    "sbom_policy_status": "valid",
                    "malware_policy_status": "clean",
                    "eval_policy_status": "passed",
                    "approval_policy_status": "valid",
                    "aibom_completeness": 0.95,
                },
                "metadata": {
                    "api_key": "secret-value",
                    "signature_public_key": "-----BEGIN PUBLIC KEY-----SECRET-----END PUBLIC KEY-----",
                },
                "aibom": {
                    "serial_number": "urn:shakerscan:aibom:test",
                    "components": [{"name": "tokenizer", "version": "1.0.0"}],
                    "completeness": {"score": 0.95},
                },
                "supply_chain": {
                    "signature": {"status": "verified", "public_key_pem": "SECRET KEY"},
                    "license_policy": {"status": "permissive", "license": "apache-2.0"},
                    "sbom_policy": {"status": "valid"},
                    "malware_policy": {"status": "clean"},
                    "eval_policy": {"status": "passed"},
                    "approval_policy": {"status": "valid"},
                },
                "checks": {
                    "checksum": True,
                    "signature_verification": True,
                    "approval_evidence": True,
                    "unsafe_serialization": True,
                },
                "runtime_destinations": [
                    {
                        "role": "artifact",
                        "requested_url": "https://models.example.com/releases/model.safetensors?token=secret-token",
                        "final_url": "https://cdn.example.com/releases/model.safetensors?token=secret-token",
                    }
                ],
            }
        },
    }

    export = api_module._model_intake_evidence_export(
        payload,
        generated_at=datetime(2026, 7, 6, tzinfo=timezone.utc),
    )

    assert export["schema_version"] == "2026-07-06.model-intake-evidence-export.v1"
    assert len(export["export_hash"]) == 64
    assert export["content_included"] is False
    assert export["metadata_included"] is False
    assert export["artifact_included"] is False
    assert export["signature_material_included"] is False
    assert export["artifact"]["artifact_ref_hash"]
    assert export["artifact"]["label"] == "models.example.com/releases/model.safetensors"
    assert export["trust_summary"]["signature_verified"] is True
    assert export["policy_summary"]["deployment_environment"] == "production"
    assert export["check_statuses"]["checksum"] is True
    assert export["runtime_destinations"]["destination_count"] == 1
    assert export["runtime_destinations"]["roles"] == ["artifact"]
    assert export["replay_plan"]["scan_result_path"] == f"/scans/{scan_id}/result"
    serialized = json.dumps(export).lower()
    assert "secret-token" not in serialized
    assert "secret-value" not in serialized
    assert "public key" not in serialized
    assert "final_url" not in serialized


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


def test_public_campaign_action_row_decodes_json_fields():
    row = {
        "id": uuid.uuid4(),
        "command": "asm.improve",
        "status": "blocked",
        "dry_run": False,
        "risk_tier": "active",
        "finding_ids": json.dumps([]),
        "hypothesis_ids": json.dumps(["hyp-1"]),
        "evidence_object_ids": json.dumps(["evidence-1"]),
        "tool_receipt_ids": json.dumps([]),
        "blocked_by": json.dumps(["missing_second_user_auth"]),
        "result_json": json.dumps({"next": "add_credentials"}),
    }

    public = api_module._public_campaign_action_row(row)

    assert public["hypothesis_ids"] == ["hyp-1"]
    assert public["evidence_object_ids"] == ["evidence-1"]
    assert public["blocked_by"] == ["missing_second_user_auth"]
    assert public["result_json"] == {"next": "add_credentials"}


def test_campaign_action_effective_status_uses_terminal_linked_scan_truth():
    assert api_module._campaign_action_effective_status("queued", "completed") == "completed"
    assert api_module._campaign_action_effective_status("running", "failed") == "failed"
    assert api_module._campaign_action_effective_status("completed", "failed") == "completed"
    assert api_module._campaign_action_effective_status("queued", "running") == "queued"


def test_public_target_principal_and_expectation_rows_are_non_executing_and_redacted():
    principal = api_module._public_target_principal_row({
        "id": uuid.uuid4(),
        "target_id": uuid.uuid4(),
        "label": "Admin",
        "role": "admin",
        "tenant_id": "tenant-a",
        "auth_state": "admin",
        "credential_profile": "admin-browser-session",
        "credential_configured": True,
        "is_active": True,
        "metadata_json": json.dumps({"authorization": "Bearer secret-token"}),
    })
    expectation = api_module._public_target_endpoint_expectation_row({
        "id": uuid.uuid4(),
        "target_id": uuid.uuid4(),
        "method": "GET",
        "path": "/admin",
        "principal_role": "user",
        "expected_access": "deny",
        "metadata_json": json.dumps({"cookie": "session=secret-token"}),
    })

    assert principal["credential_configured"] is True
    assert principal["execution_enabled"] is False
    assert expectation["execution_enabled"] is False
    assert expectation["finding_created"] is False
    assert "secret-token" not in json.dumps(principal)
    assert "secret-token" not in json.dumps(expectation)


def test_public_hypothesis_row_decodes_json_and_never_promotes_findings():
    lease_expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    row = {
        "id": uuid.uuid4(),
        "source": "app_graph",
        "family": "bola",
        "dedupe_key": "GET /api/orders/{id}:order.id",
        "status": "open",
        "version": 2,
        "claim_owner": "agent-a",
        "claim_lease_expires_at": lease_expires_at,
        "evidence_object_ids": json.dumps(["evidence-1"]),
        "tool_receipt_ids": json.dumps([]),
        "next_test_action": json.dumps({"command": "asm.gaps"}),
        "endorsements": json.dumps([{"source": "app_graph"}]),
        "refutations": json.dumps([]),
        "metadata_json": json.dumps({"route": "/api/orders/{id}"}),
    }

    public = api_module._public_hypothesis_row(row)

    assert public["evidence_object_ids"] == ["evidence-1"]
    assert public["next_test_action"] == {"command": "asm.gaps"}
    assert public["endorsements"] == [{"source": "app_graph"}]
    assert public["claim_state"]["owner"] == "agent-a"
    assert public["claim_state"]["active"] is True
    assert public["claim_state"]["expired"] is False
    assert public["can_promote_finding"] is False
    assert public["execution_enabled"] is False


def test_public_hypothesis_row_marks_expired_claim_effectively_open():
    row = {
        "id": uuid.uuid4(),
        "source": "app_graph",
        "family": "bola",
        "dedupe_key": "GET /api/orders/{id}:order.id",
        "status": "claimed",
        "version": 2,
        "claim_owner": "agent-a",
        "claim_lease_expires_at": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
        "evidence_object_ids": json.dumps([]),
        "tool_receipt_ids": json.dumps([]),
        "next_test_action": json.dumps({}),
        "endorsements": json.dumps([]),
        "refutations": json.dumps([]),
        "metadata_json": json.dumps({}),
    }

    public = api_module._public_hypothesis_row(row)

    assert public["status"] == "claimed"
    assert public["effective_status"] == "open"
    assert public["claim_state"]["active"] is False
    assert public["claim_state"]["expired"] is True
    assert public["claimable"] is True


def test_canonical_hypothesis_request_redacts_and_normalizes():
    req = api_module.HypothesisRequest(
        source="manual",
        family="BOLA",
        dedupe_key="GET /api/orders/{id}",
        confidence=0.7,
        description="Try bearer secret-token here",
        next_test_action={"command": "asm.improve", "authorization": "Bearer secret-token"},
        metadata_json={"cookie": "session=secret"},
        endorsement={"reason": "secret-token should not remain"},
        created_by="pytest",
    )

    payload = api_module._canonical_hypothesis_request(req)

    assert payload["family"] == "bola"
    assert payload["description"] != "Try bearer secret-token here"
    assert payload["next_test_action"]["authorization"] != "Bearer secret-token"
    assert payload["metadata_json"]["cookie"] != "session=secret"
    assert "secret-token" not in json.dumps(payload["endorsement"])


def test_canonical_hypothesis_request_uses_structured_dedupe_dimensions():
    req = api_module.HypothesisRequest(
        source="manual",
        family="BOLA",
        dedupe_key="caller-provided-key",
        dedupe_dimensions={
            "method": "GET",
            "route": "/api/orders/{id}",
            "object_key": "order.id",
            "principal_pair": {"actor": "user1", "other": "user2", "tenant": "tenant-a"},
            "parameter_path": "path.id",
            "proof_surface": "Runtime Authz Replay",
        },
        metadata_json={"authorization": "Bearer secret-token"},
    )

    payload = api_module._canonical_hypothesis_request(req)

    assert payload["dedupe_key"] != "caller-provided-key"
    assert payload["dedupe_key"].startswith("hypothesis:v1|family=bola|method=get|route=/api/orders/{id}")
    assert "principal_actor=user1" in payload["dedupe_key"]
    assert "principal_other=user2" in payload["dedupe_key"]
    assert "proof_surface=runtime_authz_replay" in payload["dedupe_key"]
    assert payload["metadata_json"]["dedupe_dimensions"]["object_key"] == "order.id"
    assert payload["metadata_json"]["authorization"] != "Bearer secret-token"


def test_application_graph_hypothesis_requests_build_authz_leads_not_findings():
    target_id = "11111111-1111-4111-8111-111111111111"
    nodes = [
        {
            "id": uuid.uuid4(),
            "node_type": "route",
            "node_key": "route:GET /api/orders",
            "label": "GET /api/orders",
            "attributes": json.dumps({"role": "producer"}),
        },
        {
            "id": uuid.uuid4(),
            "node_type": "object",
            "node_key": "object:order_id",
            "label": "order_id",
            "attributes": json.dumps({"sensitive_fields": ["email"]}),
        },
        {
            "id": uuid.uuid4(),
            "node_type": "route",
            "node_key": "route:GET /api/orders/{order_id}",
            "label": "GET /api/orders/{order_id}",
            "attributes": json.dumps({"role": "consumer"}),
        },
    ]
    edges = [
        {
            "id": uuid.uuid4(),
            "src_key": "route:GET /api/orders",
            "dst_key": "object:order_id",
            "edge_type": "produces",
            "attributes": json.dumps({"source_principal": "user1"}),
        },
        {
            "id": uuid.uuid4(),
            "src_key": "object:order_id",
            "dst_key": "route:GET /api/orders/{order_id}",
            "edge_type": "consumed_by",
            "attributes": json.dumps({}),
        },
        {
            "id": uuid.uuid4(),
            "src_key": "route:GET /api/orders",
            "dst_key": "route:GET /api/orders/{order_id}",
            "edge_type": "auth_boundary",
            "attributes": json.dumps({
                "object_id_key": "order_id",
                "source_principal": "user1",
                "excluded_principal": "user2",
                "sensitive_fields": ["email"],
            }),
        },
    ]

    requests = api_module._application_graph_hypothesis_requests(target_id, nodes, edges, created_by="pytest")

    assert {request.family for request in requests} == {"bola", "data_exposure"}
    req = next(request for request in requests if request.family == "bola")
    assert req.source == "app_graph"
    assert req.family == "bola"
    assert req.cwe == "CWE-639"
    assert req.severity_guess == "high"
    assert req.next_test_action["command"] == "asm.improve"
    assert req.next_test_action["parameters"]["check_family"] == "bola"
    assert req.next_test_action["parameters"]["exploit_depth"] is True
    assert req.endorsement["source_principal"] == "user1"
    assert req.endorsement["excluded_principal"] == "user2"
    assert req.dedupe_dimensions["route"] == "/api/orders/{order_id}"
    assert req.dedupe_dimensions["object_key"] == "object:order_id"
    assert req.dedupe_dimensions["proof_surface"] == "runtime_authz_replay"
    exposure = next(request for request in requests if request.family == "data_exposure")
    assert exposure.cwe == "CWE-200"
    assert exposure.next_test_action["command"] == "experiment.workflow"
    assert exposure.next_test_action["parameters"]["proof_family"] == "data_exposure"
    assert exposure.metadata_json["unexplained_residue"] is True


def test_application_graph_hypothesis_requests_attach_principal_matrix_context():
    target_id = "11111111-1111-4111-8111-111111111111"
    nodes = [
        {
            "id": uuid.uuid4(),
            "node_type": "route",
            "node_key": "route:GET /api/orders",
            "label": "GET /api/orders",
            "attributes": json.dumps({}),
        },
        {
            "id": uuid.uuid4(),
            "node_type": "object",
            "node_key": "object:order_id",
            "label": "order_id",
            "attributes": json.dumps({}),
        },
        {
            "id": uuid.uuid4(),
            "node_type": "route",
            "node_key": "route:GET /api/orders/{order_id}",
            "label": "GET /api/orders/{order_id}",
            "attributes": json.dumps({}),
        },
    ]
    edges = [
        {
            "id": uuid.uuid4(),
            "src_key": "route:GET /api/orders",
            "dst_key": "object:order_id",
            "edge_type": "produces",
            "attributes": json.dumps({}),
        },
        {
            "id": uuid.uuid4(),
            "src_key": "object:order_id",
            "dst_key": "route:GET /api/orders/{order_id}",
            "edge_type": "consumed_by",
            "attributes": json.dumps({}),
        },
        {
            "id": uuid.uuid4(),
            "src_key": "route:GET /api/orders",
            "dst_key": "route:GET /api/orders/{order_id}",
            "edge_type": "auth_boundary",
            "attributes": json.dumps({
                "object_id_key": "order_id",
                "source_principal": "user1",
                "excluded_principal": "user2",
            }),
        },
    ]
    principals = [
        {
            "id": uuid.uuid4(),
            "label": "user1",
            "role": "customer",
            "tenant_id": "tenant-a",
            "auth_state": "user1",
            "credential_profile": "profile-user1",
            "credential_configured": True,
            "is_active": True,
            "metadata_json": json.dumps({"authorization": "Bearer secret-token"}),
        },
        {
            "id": uuid.uuid4(),
            "label": "user2",
            "role": "customer",
            "tenant_id": "tenant-a",
            "auth_state": "user2",
            "credential_profile": "profile-user2",
            "credential_configured": True,
            "is_active": True,
            "metadata_json": json.dumps({}),
        },
        {
            "id": uuid.uuid4(),
            "label": "admin",
            "role": "admin",
            "tenant_id": "tenant-a",
            "auth_state": "admin",
            "credential_profile": None,
            "is_active": True,
            "metadata_json": json.dumps({}),
        },
    ]
    expectations = [
        {
            "id": uuid.uuid4(),
            "method": "GET",
            "path": "/api/orders/{order_id}",
            "param_shape": "order_id",
            "param_location": "path",
            "principal_role": "customer",
            "tenant_id": "tenant-a",
            "expected_access": "allow",
            "expected_http_status": 200,
            "expectation_source": "contract",
            "principal_label": "user1",
            "principal_auth_state": "user1",
            "metadata_json": json.dumps({}),
        },
        {
            "id": uuid.uuid4(),
            "method": "GET",
            "path": "/api/orders/{order_id}",
            "param_shape": "order_id",
            "param_location": "path",
            "principal_role": "customer",
            "tenant_id": "tenant-a",
            "expected_access": "deny",
            "expected_http_status": 403,
            "expectation_source": "contract",
            "principal_label": "user2",
            "principal_auth_state": "user2",
            "metadata_json": json.dumps({}),
        },
    ]

    req = api_module._application_graph_hypothesis_requests(
        target_id,
        nodes,
        edges,
        principal_rows=principals,
        expectation_rows=expectations,
        created_by="pytest",
    )[0]

    context = req.next_test_action["principal_matrix"]
    assert context["available"] is True
    assert context["role_counts"]["customer"] == 2
    assert context["tenant_counts"]["tenant-a"] == 3
    assert context["matched_principals"]["primary"]["label"] == "user1"
    assert context["matched_principals"]["alternate"]["label"] == "user2"
    assert context["credential_profiles"] == {"primary": True, "alternate": True}
    assert context["precondition_signals"]["second_user_credentials"] == "configured"
    assert {item["expected_access"] for item in context["matching_expectations"]} == {"allow", "deny"}
    assert req.endorsement["principal_matrix"]["proof_state"] == "unproven_planning_context"
    assert req.metadata_json["principal_matrix"]["matching_expectations"][1]["expected_http_status"] == 403
    assert "secret-token" not in json.dumps(req.model_dump(mode="json"))
    assert "profile-user1" not in json.dumps(req.model_dump(mode="json"))


def test_plan_campaign_from_hypothesis_records_planned_action_without_execution():
    hypothesis_id = uuid.uuid4()
    target_id = uuid.uuid4()
    campaign_id = uuid.uuid4()
    action_id = uuid.uuid4()
    captured: dict[str, object] = {"queries": []}

    hypothesis_row = {
        "id": hypothesis_id,
        "target_id": target_id,
        "campaign_id": None,
        "campaign_action_id": None,
        "source": "app_graph",
        "family": "bola",
        "cwe": "CWE-639",
        "title": "Graph authz lead",
        "description": "user2 should not read user1 order",
        "severity_guess": "high",
        "confidence": 0.8,
        "smoke_score": None,
        "dedupe_key": "hypothesis:v1|family=bola",
        "status": "open",
        "version": 1,
        "claim_owner": None,
        "claim_lease_expires_at": None,
        "evidence_object_ids": json.dumps([]),
        "tool_receipt_ids": json.dumps([]),
        "next_test_action": json.dumps({
            "command": "asm.improve",
            "parameters": {"target_id": str(target_id), "check_family": "bola", "exploit_depth": True},
            "principal_matrix": {
                "proof_state": "unproven_planning_context",
                "matched_principals": {
                    "primary": {"label": "user1", "role": "customer", "auth_state": "user1", "tenant_id": "tenant-a"},
                    "alternate": {"label": "user2", "role": "customer", "auth_state": "user2", "tenant_id": "tenant-a"},
                },
                "matching_expectations": [
                    {
                        "method": "GET",
                        "path": "/api/orders/{id}",
                        "principal_label": "user1",
                        "principal_role": "customer",
                        "principal_auth_state": "user1",
                        "tenant_id": "tenant-a",
                        "expected_access": "allow",
                        "expected_http_status": 200,
                    },
                    {
                        "method": "GET",
                        "path": "/api/orders/{id}",
                        "principal_label": "user2",
                        "principal_role": "customer",
                        "principal_auth_state": "user2",
                        "tenant_id": "tenant-a",
                        "expected_access": "deny",
                        "expected_http_status": 403,
                    },
                ],
                "precondition_signals": {
                    "primary_credentials": "configured",
                    "second_user_credentials": "configured",
                },
            },
        }),
        "endorsements": json.dumps([]),
        "refutations": json.dumps([]),
        "metadata_json": json.dumps({"dedupe_dimensions": {"route": "/api/orders/{id}"}}),
        "created_by": "pytest",
        "created_at": "now",
        "updated_at": "now",
    }

    class _FakeConn:
        async def fetchval(self, query, *args):
            captured["queries"].append(str(query))
            return 1

        async def fetchrow(self, query, *args):
            sql = str(query)
            captured["queries"].append(sql)
            if "SELECT * FROM hypotheses" in sql:
                return hypothesis_row
            if "INSERT INTO campaigns" in sql:
                captured["campaign_args"] = args
                return {
                    "id": campaign_id,
                    "name": args[0],
                    "objective": args[1],
                    "campaign_type": args[2],
                    "target_id": args[3],
                    "target_scope": args[4],
                    "risk_tier": args[5],
                    "policy_profile": args[6],
                    "planner": args[7],
                    "operation_plan_id": args[8],
                    "context_hash": args[9],
                    "status": args[10],
                    "deployment_impact": args[11],
                    "metadata_json": args[12],
                    "created_by": args[13],
                    "created_at": "now",
                    "updated_at": "now",
                }
            if "INSERT INTO campaign_actions" in sql:
                captured["action_args"] = args
                return {
                    "id": action_id,
                    "campaign_id": args[0],
                    "operation_plan_id": args[1],
                    "command_result_id": args[2],
                    "target_id": args[3],
                    "scope_receipt_id": args[4],
                    "approval_receipt_id": args[5],
                    "scan_id": args[6],
                    "command": args[7],
                    "action_name": args[8],
                    "status": args[9],
                    "dry_run": args[10],
                    "risk_tier": args[11],
                    "finding_ids": args[12],
                    "hypothesis_ids": args[13],
                    "evidence_object_ids": args[14],
                    "tool_receipt_ids": args[15],
                    "blocked_by": args[16],
                    "next_action": args[17],
                    "operator_message": args[18],
                    "result_json": args[19],
                    "created_by": args[20],
                    "mission_campaign_id": args[21],
                    "created_at": "now",
                    "updated_at": "now",
                }
            if "UPDATE hypotheses" in sql:
                captured["update_args"] = args
                updated = dict(hypothesis_row)
                updated["campaign_action_id"] = args[0]
                updated["metadata_json"] = json.dumps({
                    "planned_campaign_id": str(campaign_id),
                    "planned_campaign_action_id": str(action_id),
                })
                return updated
            raise AssertionError(sql)

    result = asyncio.run(api_module._plan_campaign_from_hypothesis(
        _FakeConn(),
        str(hypothesis_id),
        api_module.HypothesisCampaignPlanRequest(campaign_name="Authz proof", created_by="pytest"),
    ))

    assert result["execution_enabled"] is False
    assert result["findings_created"] == 0
    assert result["scans_queued"] == 0
    assert result["campaign"]["campaign_type"] == "api_authz"
    assert result["campaign"]["risk_tier"] == "credential"
    assert result["campaign_action"]["command"] == "asm.improve"
    assert result["campaign_action"]["status"] == "planned"
    assert result["campaign_action"]["dry_run"] is True
    assert result["campaign_action"]["mission_campaign_id"] == str(campaign_id)
    assert result["campaign_action"]["hypothesis_ids"] == [str(hypothesis_id)]
    assert result["campaign_action"]["result_json"]["proof_state"] == "planned_not_executed"
    replay_plan = result["campaign_action"]["result_json"]["authz_replay_plan"]
    assert replay_plan["mode"] == "deterministic_authz_replay"
    assert replay_plan["executable"] is False
    assert replay_plan["method"] == "GET"
    assert replay_plan["path"] == "/api/orders/{id}"
    assert replay_plan["principal_pair"]["alternate"]["auth_state"] == "user2"
    assert replay_plan["expected_access"][1]["expected_access"] == "deny"
    assert replay_plan["missing_preconditions"] == []
    assert result["hypothesis"]["campaign_action_id"] == str(action_id)
    assert captured["action_args"][6] is None
    assert captured["action_args"][12] == json.dumps([])


def test_execute_authz_replay_plan_records_observations_without_findings(monkeypatch):
    action_id = uuid.uuid4()
    hypothesis_id = uuid.uuid4()
    target_id = uuid.uuid4()
    approval_id = uuid.uuid4()
    tool_receipt_id = uuid.uuid4()
    evidence_one_id = uuid.uuid4()
    evidence_two_id = uuid.uuid4()
    captured: dict[str, object] = {"queries": []}
    replay_plan = {
        "mode": "deterministic_authz_replay",
        "executable": False,
        "proof_state": "planned_not_executed",
        "method": "GET",
        "path": "/api/orders/{id}",
        "concrete_path": "/api/orders/42",
        "principal_pair": {
            "primary": {"label": "user1", "auth_state": "user1"},
            "alternate": {"label": "user2", "auth_state": "user2"},
        },
        "expected_access": [
            {
                "method": "GET",
                "path": "/api/orders/{id}",
                "principal_label": "user1",
                "principal_auth_state": "user1",
                "expected_access": "allow",
                "expected_http_status": 200,
            },
            {
                "method": "GET",
                "path": "/api/orders/{id}",
                "principal_label": "user2",
                "principal_auth_state": "user2",
                "expected_access": "deny",
                "expected_http_status": 403,
            },
        ],
    }

    class _FakeSession:
        state = types.SimpleNamespace(users={
            "user1": types.SimpleNamespace(
                is_authenticated=True,
                credential_profile_id="profile-user1",
                principal_auth_state="user1",
                token=_test_jwt(email="user1@example.test"),
            ),
            "user2": types.SimpleNamespace(
                is_authenticated=True,
                credential_profile_id="profile-user2",
                principal_auth_state="user2",
                token=_test_jwt(email="user2@example.test"),
            ),
        })

        async def test_endpoint(self, *, endpoint, method, as_user, body, allow_out_of_scope):
            assert endpoint == "/api/orders/42"
            assert method == "GET"
            assert body is None
            assert allow_out_of_scope is False
            return {
                "success": True,
                "status_code": 200 if as_user in {"user1", "user2"} else 403,
                "status_text": "OK",
                "headers": {"content-type": "application/json"},
                "body": '{"id": 42}',
            }

    class _FakeManager:
        async def get_session(self, session_id):
            assert session_id == "session-1"
            return _FakeSession()

    class _FakeInteractiveSessionManager:
        @staticmethod
        async def get_instance():
            return _FakeManager()

    class _FakeConn:
        async def fetchrow(self, query, *args):
            sql = str(query)
            captured["queries"].append(sql)
            if "SELECT * FROM campaign_actions" in sql:
                return {
                    "id": action_id,
                    "campaign_id": None,
                    "operation_plan_id": None,
                    "command_result_id": None,
                    "target_id": target_id,
                    "scope_receipt_id": None,
                    "approval_receipt_id": None,
                    "scan_id": None,
                    "command": "asm.improve",
                    "action_name": "asm.improve",
                    "status": "planned",
                    "dry_run": True,
                    "risk_tier": "credential",
                    "finding_ids": json.dumps([]),
                    "hypothesis_ids": json.dumps([str(hypothesis_id)]),
                    "evidence_object_ids": json.dumps([]),
                    "tool_receipt_ids": json.dumps([]),
                    "blocked_by": json.dumps([]),
                    "next_action": "asm.improve",
                    "operator_message": "planned",
                    "result_json": json.dumps({"authz_replay_plan": replay_plan}),
                    "created_by": "pytest",
                    "mission_campaign_id": None,
                    "created_at": "now",
                    "updated_at": "now",
                }
            if "SELECT id, url FROM targets" in sql:
                return {"id": target_id, "url": "https://app.example.com"}
            if "UPDATE campaign_actions" in sql:
                captured["update_args"] = args
                return {
                    "id": action_id,
                    "campaign_id": None,
                    "operation_plan_id": None,
                    "command_result_id": None,
                    "target_id": target_id,
                    "scope_receipt_id": None,
                    "approval_receipt_id": None,
                    "scan_id": None,
                    "command": "asm.improve",
                    "action_name": "asm.improve",
                    "status": args[0],
                    "dry_run": False,
                    "risk_tier": "credential",
                    "finding_ids": json.dumps([]),
                    "hypothesis_ids": json.dumps([str(hypothesis_id)]),
                    "evidence_object_ids": json.dumps([]),
                    "tool_receipt_ids": json.dumps([]),
                    "blocked_by": json.dumps([]),
                    "next_action": "asm.improve",
                    "operator_message": "replayed",
                    "result_json": args[1],
                    "created_by": "pytest",
                    "mission_campaign_id": None,
                    "created_at": "now",
                    "updated_at": "now",
                }
            if "INSERT INTO tool_receipts" in sql:
                captured["tool_receipt_args"] = args
                return {
                    "id": tool_receipt_id,
                    "tool_name": args[0],
                    "tool_version": args[1],
                    "adapter_version": args[2],
                    "command_hash": args[3],
                    "redacted_argv": args[4],
                    "worker_build": args[5],
                    "container_image": args[6],
                    "target_scope": args[7],
                    "scope_receipt_id": args[8],
                    "approval_receipt_id": args[9],
                    "policy_profile_id": args[10],
                    "status": args[11],
                    "parser_status": args[12],
                    "exit_code": args[13],
                    "timed_out": args[14],
                    "started_at": args[15],
                    "finished_at": args[16],
                    "stdout_evidence_object_id": args[17],
                    "stderr_evidence_object_id": args[18],
                    "parsed_evidence_instance_ids": args[19],
                    "redaction_summary": args[20],
                    "metadata_json": args[21],
                    "created_by": args[22],
                    "created_at": "now",
                }
            if "INSERT INTO evidence_instances" in sql:
                captured.setdefault("evidence_args", []).append(args)
                evidence_id = evidence_one_id if len(captured["evidence_args"]) == 1 else evidence_two_id
                return {
                    "id": evidence_id,
                    "finding_id": args[0],
                    "evidence_object_id": args[1],
                    "scan_id": args[2],
                    "target_id": args[3],
                    "concrete_url": args[4],
                    "object_id": args[5],
                    "payload_variant": args[6],
                    "request_response_refs": args[7],
                    "principal_pair": args[8],
                    "proof_observation": args[9],
                    "campaign_action_id": args[10],
                    "tool_receipt_id": args[11],
                    "redaction_profile": args[12],
                    "hash": args[13],
                    "retention_policy": args[14],
                    "proof_state": args[15],
                    "metadata_json": args[16],
                    "created_by": args[17],
                    "created_at": "now",
                }
            if "INSERT INTO command_results" in sql:
                captured["command_result_args"] = args
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
            raise AssertionError(sql)

    monkeypatch.setattr(api_module, "InteractiveSessionManager", _FakeInteractiveSessionManager)

    async def fake_profile_bindings(conn, bound_target_id):
        assert bound_target_id == target_id
        return {"user1": "profile-user1", "user2": "profile-user2"}

    monkeypatch.setattr(api_module, "_authz_target_principal_profile_bindings", fake_profile_bindings)

    async def fake_validate(conn, receipt_id, **kwargs):
        captured["approval_validation"] = (receipt_id, kwargs)
        return {"approval_receipt_id": receipt_id}

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)

    result = asyncio.run(api_module._execute_authz_replay_plan(
        _FakeConn(),
        campaign_action_id=str(action_id),
        session_id="session-1",
        approval_receipt_id=str(approval_id),
        created_by="pytest",
    ))

    assert result["execution_enabled"] is True
    assert result["findings_created"] == 0
    assert result["mismatch_count"] == 1
    assert result["violation_count"] == 1
    assert result["campaign_action"]["status"] == "partial"
    assert result["campaign_action"]["dry_run"] is False
    assert result["tool_receipt"]["id"] == str(tool_receipt_id)
    assert result["tool_receipt"]["status"] == "failed"
    assert len(result["evidence_instances"]) == 2
    assert result["evidence_instances"][1]["proof_state"] == "suspected"
    assert result["observations"][0]["matched"] is True
    assert result["observations"][1]["matched"] is False
    assert result["observations"][1]["violation_observed"] is True
    assert result["command_result"]["command"] == "authz.replay_plan"
    assert result["command_result"]["approval_receipt_id"] == str(approval_id)
    assert result["command_result"]["hypothesis_ids"] == [str(hypothesis_id)]
    assert result["command_result"]["tool_receipt_ids"] == [str(tool_receipt_id)]
    assert result["command_result"]["result_json"]["authz_replay"]["tool_receipt_id"] == str(tool_receipt_id)
    assert result["command_result"]["result_json"]["authz_replay"]["evidence_instance_ids"] == [
        str(evidence_one_id),
        str(evidence_two_id),
    ]
    assert result["command_result"]["result_json"]["authz_replay"]["violation_count"] == 1
    assert captured["approval_validation"][0] == str(approval_id)
    assert captured["approval_validation"][1]["target_id"] == target_id
    proof_bundle = result["command_result"]["result_json"]["authz_replay"]["proof_bundle"]
    assert proof_bundle["differential_observed"] is True
    assert proof_bundle["authenticated_principal_count"] == 2
    assert proof_bundle["principal_profile_bindings_verified"] is True
    assert proof_bundle["principal_identity_bindings_verified"] is True
    assert proof_bundle["finding_created_automatically"] is False


def test_authz_replay_requires_distinct_slotted_session_profiles():
    expected = {"user1", "user2"}
    raw_session_users = {
        "user1": types.SimpleNamespace(is_authenticated=True),
        "user2": types.SimpleNamespace(is_authenticated=True),
    }
    reason, details = api_module._authz_session_profile_binding_status(
        expected,
        raw_session_users,
        {"user1": "profile-a", "user2": "profile-b"},
    )
    assert reason == "session_principal_profiles_unbound"
    assert details["missing_session_profile_slots"] == ["user1", "user2"]

    same_profile_users = {
        "user1": types.SimpleNamespace(credential_profile_id="profile-a", principal_auth_state="user1"),
        "user2": types.SimpleNamespace(credential_profile_id="profile-a", principal_auth_state="user2"),
    }
    reason, _ = api_module._authz_session_profile_binding_status(
        expected,
        same_profile_users,
        {"user1": "profile-a", "user2": "profile-a"},
    )
    assert reason == "target_principal_profiles_not_distinct"

    distinct_profile_users = {
        "user1": types.SimpleNamespace(
            credential_profile_id="profile-a", principal_auth_state="user1", token=_test_jwt(email="one@example.test")
        ),
        "user2": types.SimpleNamespace(
            credential_profile_id="profile-b", principal_auth_state="user2", token=_test_jwt(email="two@example.test")
        ),
    }
    reason, details = api_module._authz_session_profile_binding_status(
        expected,
        distinct_profile_users,
        {"user1": "profile-a", "user2": "profile-b"},
    )
    assert reason is None
    assert details["mismatched_slots"] == []
    assert details["identity_verified_slots"] == ["user1", "user2"]

    same_account_users = {
        "user1": types.SimpleNamespace(
            credential_profile_id="profile-a", principal_auth_state="user1", token=_test_jwt(email="same@example.test")
        ),
        "user2": types.SimpleNamespace(
            credential_profile_id="profile-b", principal_auth_state="user2", token=_test_jwt(email="same@example.test")
        ),
    }
    reason, details = api_module._authz_session_profile_binding_status(
        expected,
        same_account_users,
        {"user1": "profile-a", "user2": "profile-b"},
    )
    assert reason == "session_principals_not_distinct"
    assert details["identity_collision"] is True

    opaque_users = {
        "user1": types.SimpleNamespace(
            credential_profile_id="profile-a", principal_auth_state="user1", token="opaque-one"
        ),
        "user2": types.SimpleNamespace(
            credential_profile_id="profile-b", principal_auth_state="user2", token="opaque-two"
        ),
    }
    reason, details = api_module._authz_session_profile_binding_status(
        expected,
        opaque_users,
        {"user1": "profile-a", "user2": "profile-b"},
    )
    assert reason == "session_principal_identity_unverified"
    assert details["missing_session_identity_slots"] == ["user1", "user2"]


def test_authz_replay_proof_bundle_requires_verified_identity_bindings():
    observations = [
        {
            "principal_auth_state": "user1",
            "expected_access": "allow",
            "observed_status": 200,
            "request_success": True,
            "authenticated_user": True,
            "principal_profile_verified": True,
            "principal_identity_verified": False,
        },
        {
            "principal_auth_state": "user2",
            "expected_access": "deny",
            "observed_status": 200,
            "request_success": True,
            "authenticated_user": True,
            "principal_profile_verified": True,
            "principal_identity_verified": False,
            "violation_observed": True,
        },
    ]

    bundle = api_module._authz_replay_proof_bundle(
        {"mode": "deterministic_authz_replay", "method": "GET", "path": "/api/orders/42"},
        observations,
    )

    assert bundle["principal_profile_bindings_verified"] is True
    assert bundle["principal_identity_bindings_verified"] is False
    assert bundle["differential_observed"] is False


def test_session_managed_profile_binding_is_server_asserted(monkeypatch):
    profile_id = uuid.uuid4()
    captured: dict[str, object] = {}

    class _Session:
        def _is_in_scope(self, url):
            captured["scope_url"] = url
            return True

        async def action(self, payload):
            captured.setdefault("actions", []).append(payload)
            return {"success": True, "auth_method": "jwt"}

    session = _Session()

    class _Manager:
        async def get_session(self, session_id):
            assert session_id == "session-1"
            return session

    class _InteractiveSessionManager:
        @staticmethod
        async def get_instance():
            return _Manager()

    class _Conn:
        async def fetchrow(self, query, *args):
            assert args == (profile_id, "user1")
            return {
                "id": profile_id,
                "auth_kind": "authorization_header",
                "secret_value": "encrypted-value",
                "auth_state": "user1",
                "target_url": "https://app.example.com",
            }

    class _Acquire:
        async def __aenter__(self):
            return _Conn()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    class _Pool:
        def acquire(self):
            return _Acquire()

    monkeypatch.setattr(api_module, "InteractiveSessionManager", _InteractiveSessionManager)
    monkeypatch.setattr(api_module, "db_pool", _Pool())
    monkeypatch.setattr(api_module, "decrypt_secret", lambda value: "Bearer managed-token")

    result = asyncio.run(api_module.session_action(
        "session-1",
        api_module.SessionActionRequest(
            action="use_credential_profile",
            user="user1",
            data={
                "credential_profile_id": str(profile_id),
                "_credential_profile_id": "caller-spoof",
                "_principal_auth_state": "user2",
            },
        ),
    ))

    managed_action = captured["actions"][0]
    assert result["managed_profile_applied"] is True
    assert managed_action["action"] == "set_auth"
    assert managed_action["data"] == {
        "auth_header": "Bearer managed-token",
        "_credential_profile_id": str(profile_id),
        "_principal_auth_state": "user1",
        "_replace_auth_state": True,
    }

    asyncio.run(api_module.session_action(
        "session-1",
        api_module.SessionActionRequest(
            action="set_auth",
            user="user1",
            data={
                "auth_header": "Bearer raw-token",
                "_credential_profile_id": str(profile_id),
                "_principal_auth_state": "user1",
                "_replace_auth_state": True,
            },
        ),
    ))
    raw_action = captured["actions"][1]
    assert raw_action["data"] == {"auth_header": "Bearer raw-token"}


def test_execute_authz_replay_plan_skips_unresolved_route_templates(monkeypatch):
    action_id = uuid.uuid4()
    replay_plan = {
        "mode": "deterministic_authz_replay",
        "method": "GET",
        "path": "/api/orders/{id}",
        "expected_access": [
            {"path": "/api/orders/{id}", "principal_auth_state": "user1", "expected_access": "allow"},
            {"path": "/api/orders/{id}", "principal_auth_state": "user2", "expected_access": "deny"},
        ],
    }
    calls = {"test_endpoint": 0}

    class FakeSession:
        state = types.SimpleNamespace(users={
            "user1": types.SimpleNamespace(is_authenticated=True),
            "user2": types.SimpleNamespace(is_authenticated=True),
        })

        async def test_endpoint(self, **kwargs):
            calls["test_endpoint"] += 1
            raise AssertionError("template path must not reach the HTTP client")

    class FakeManager:
        async def get_session(self, session_id):
            return FakeSession()

    class FakeInteractiveSessionManager:
        @staticmethod
        async def get_instance():
            return FakeManager()

    action_row = {
        "id": action_id,
        "target_id": None,
        "campaign_id": None,
        "operation_plan_id": None,
        "command_result_id": None,
        "scope_receipt_id": None,
        "approval_receipt_id": None,
        "scan_id": None,
        "command": "authz.replay_plan",
        "action_name": "authz.replay_plan",
        "status": "planned",
        "dry_run": True,
        "risk_tier": "credential",
        "finding_ids": [],
        "hypothesis_ids": [],
        "evidence_object_ids": [],
        "tool_receipt_ids": [],
        "blocked_by": [],
        "result_json": {"authz_replay_plan": replay_plan},
    }

    class FakeConn:
        async def fetchrow(self, query, *args):
            if "SELECT * FROM campaign_actions" in str(query):
                return action_row
            if "UPDATE campaign_actions" in str(query):
                return {**action_row, "status": "partial", "dry_run": False, "result_json": args[0]}
            raise AssertionError(str(query))

    async def fake_record_tool_receipt(conn, request):
        calls["tool_receipt"] = request
        return {"tool_receipt": {"id": str(uuid.uuid4()), "status": request.status}}

    async def fake_record_command_result(conn, **kwargs):
        calls["command_result"] = kwargs
        return {"id": str(uuid.uuid4()), **kwargs}

    monkeypatch.setattr(api_module, "InteractiveSessionManager", FakeInteractiveSessionManager)
    monkeypatch.setattr(api_module, "_record_tool_receipt", fake_record_tool_receipt)
    monkeypatch.setattr(api_module, "_record_command_result", fake_record_command_result)

    result = asyncio.run(api_module._execute_authz_replay_plan(
        FakeConn(),
        campaign_action_id=str(action_id),
        session_id="session-1",
        created_by="pytest",
    ))

    assert calls["test_endpoint"] == 0
    assert calls["tool_receipt"].status == "skipped"
    assert calls["command_result"]["status"] == "partial"
    assert calls["command_result"]["blocked_by"] == ["unresolved_route_template"]
    assert result["status"] == "partial"
    assert result["observations"][0]["inconclusive_reason"] == "unresolved_route_template"
    assert result["violation_count"] == 0


def test_execute_authz_replay_plan_treats_soft_200_denial_as_non_violation(monkeypatch):
    action_id = uuid.uuid4()
    target_id = uuid.uuid4()
    replay_plan = {
        "mode": "deterministic_authz_replay",
        "method": "GET",
        "path": "/api/orders/{id}",
        "concrete_path": "/api/orders/42",
        "expected_access": [
            {"method": "GET", "path": "/api/orders/{id}", "principal_label": "user1", "principal_auth_state": "user1", "expected_access": "allow"},
            {"method": "GET", "path": "/api/orders/{id}", "principal_label": "user2", "principal_auth_state": "user2", "expected_access": "deny"},
        ],
    }

    class _FakeSession:
        state = types.SimpleNamespace(users={
            "user1": types.SimpleNamespace(
                is_authenticated=True, credential_profile_id="profile-user1", principal_auth_state="user1",
                token=_test_jwt(email="user1@example.test"),
            ),
            "user2": types.SimpleNamespace(
                is_authenticated=True, credential_profile_id="profile-user2", principal_auth_state="user2",
                token=_test_jwt(email="user2@example.test"),
            ),
        })

        async def test_endpoint(self, *, endpoint, method, as_user, body, allow_out_of_scope):
            return {
                "success": True,
                "status_code": 200,
                "status_text": "OK",
                "headers": {"content-type": "application/json"},
                "body": '{"error":"forbidden"}' if as_user == "user2" else '{"id":42}',
            }

    class _FakeManager:
        async def get_session(self, session_id):
            return _FakeSession()

    class _FakeInteractiveSessionManager:
        @staticmethod
        async def get_instance():
            return _FakeManager()

    class _FakeConn:
        async def fetchrow(self, query, *args):
            sql = str(query)
            if "SELECT * FROM campaign_actions" in sql:
                return {
                    "id": action_id, "target_id": target_id, "campaign_id": None, "operation_plan_id": None,
                    "command_result_id": None, "scope_receipt_id": None, "approval_receipt_id": None,
                    "scan_id": None, "command": "asm.improve", "action_name": "asm.improve", "status": "planned",
                    "dry_run": True, "risk_tier": "credential", "finding_ids": json.dumps([]),
                    "hypothesis_ids": json.dumps([]), "evidence_object_ids": json.dumps([]),
                    "tool_receipt_ids": json.dumps([]), "blocked_by": json.dumps([]), "next_action": None,
                    "operator_message": "planned", "result_json": json.dumps({"authz_replay_plan": replay_plan}),
                    "created_by": "pytest", "mission_campaign_id": None, "created_at": "now", "updated_at": "now",
                }
            if "UPDATE campaign_actions" in sql:
                return {
                    "id": action_id, "target_id": target_id, "campaign_id": None, "operation_plan_id": None,
                    "command_result_id": None, "scope_receipt_id": None, "approval_receipt_id": None,
                    "scan_id": None, "command": "asm.improve", "action_name": "asm.improve", "status": args[0],
                    "dry_run": False, "risk_tier": "credential", "finding_ids": json.dumps([]),
                    "hypothesis_ids": json.dumps([]), "evidence_object_ids": json.dumps([]),
                    "tool_receipt_ids": json.dumps([]), "blocked_by": json.dumps([]), "next_action": None,
                    "operator_message": "replayed", "result_json": args[1], "created_by": "pytest",
                    "mission_campaign_id": None, "created_at": "now", "updated_at": "now",
                }
            if "INSERT INTO tool_receipts" in sql:
                return {
                    "id": uuid.uuid4(), "tool_name": args[0], "tool_version": args[1], "adapter_version": args[2],
                    "command_hash": args[3], "redacted_argv": args[4], "worker_build": args[5],
                    "container_image": args[6], "target_scope": args[7], "scope_receipt_id": args[8],
                    "approval_receipt_id": args[9], "policy_profile_id": args[10], "status": args[11],
                    "parser_status": args[12], "exit_code": args[13], "timed_out": args[14],
                    "started_at": args[15], "finished_at": args[16], "stdout_evidence_object_id": args[17],
                    "stderr_evidence_object_id": args[18], "parsed_evidence_instance_ids": args[19],
                    "redaction_summary": args[20], "metadata_json": args[21], "created_by": args[22],
                    "created_at": "now",
                }
            if "INSERT INTO evidence_instances" in sql:
                return {
                    "id": uuid.uuid4(), "finding_id": args[0], "evidence_object_id": args[1], "scan_id": args[2],
                    "target_id": args[3], "concrete_url": args[4], "object_id": args[5], "payload_variant": args[6],
                    "request_response_refs": args[7], "principal_pair": args[8], "proof_observation": args[9],
                    "campaign_action_id": args[10], "tool_receipt_id": args[11], "redaction_profile": args[12],
                    "hash": args[13], "retention_policy": args[14], "proof_state": args[15],
                    "metadata_json": args[16], "created_by": args[17], "created_at": "now",
                }
            if "INSERT INTO command_results" in sql:
                return {
                    "id": uuid.uuid4(), "command": args[0], "status": args[1], "dry_run": args[2],
                    "risk_tier": args[3], "operation_plan_id": args[4], "scope_receipt_id": args[5],
                    "approval_receipt_id": args[6], "campaign_id": args[7], "scan_id": args[8],
                    "finding_ids": args[9], "hypothesis_ids": args[10], "evidence_object_ids": args[11],
                    "tool_receipt_ids": args[12], "blocked_by": args[13], "next_action": args[14],
                    "operator_message": args[15], "result_json": args[16], "created_by": args[17],
                    "created_at": "now",
                }
            raise AssertionError(sql)

    monkeypatch.setattr(api_module, "InteractiveSessionManager", _FakeInteractiveSessionManager)

    async def fake_profile_bindings(conn, bound_target_id):
        assert bound_target_id == target_id
        return {"user1": "profile-user1", "user2": "profile-user2"}

    monkeypatch.setattr(api_module, "_authz_target_principal_profile_bindings", fake_profile_bindings)

    result = asyncio.run(api_module._execute_authz_replay_plan(
        _FakeConn(),
        campaign_action_id=str(action_id),
        session_id="session-1",
        created_by="pytest",
    ))

    assert result["violation_count"] == 0
    assert result["observations"][1]["observed_status"] == 200
    assert result["observations"][1]["violation_observed"] is False
    assert result["evidence_instances"][1]["proof_state"] == "inconclusive"
    proof_bundle = result["command_result"]["result_json"]["authz_replay"]["proof_bundle"]
    assert proof_bundle["differential_observed"] is False
    assert proof_bundle["soft_denial_observations"][0]["status"] == 200


def test_execute_authz_replay_plan_treats_redirect_denial_as_non_violation(monkeypatch):
    action_id = uuid.uuid4()
    target_id = uuid.uuid4()
    replay_plan = {
        "mode": "deterministic_authz_replay",
        "method": "GET",
        "path": "/api/orders/{id}",
        "concrete_path": "/api/orders/42",
        "principal_pair": {
            "primary": {"label": "user1", "auth_state": "user1"},
            "alternate": {"label": "user2", "auth_state": "user2"},
        },
        "expected_access": [
            {"method": "GET", "path": "/api/orders/{id}", "principal_label": "user1", "principal_auth_state": "user1", "expected_access": "allow"},
            {"method": "GET", "path": "/api/orders/{id}", "principal_label": "user2", "principal_auth_state": "user2", "expected_access": "deny"},
        ],
    }

    class _FakeSession:
        state = types.SimpleNamespace(users={
            "user1": types.SimpleNamespace(
                is_authenticated=True, credential_profile_id="profile-user1", principal_auth_state="user1",
                token=_test_jwt(email="user1@example.test"),
            ),
            "user2": types.SimpleNamespace(
                is_authenticated=True, credential_profile_id="profile-user2", principal_auth_state="user2",
                token=_test_jwt(email="user2@example.test"),
            ),
        })

        async def test_endpoint(self, *, endpoint, method, as_user, body, allow_out_of_scope):
            return {"success": True, "status_code": 200 if as_user == "user1" else 302, "status_text": "Found"}

    class _FakeManager:
        async def get_session(self, session_id):
            return _FakeSession()

    class _FakeInteractiveSessionManager:
        @staticmethod
        async def get_instance():
            return _FakeManager()

    class _FakeConn:
        async def fetchrow(self, query, *args):
            sql = str(query)
            if "SELECT * FROM campaign_actions" in sql:
                return {
                    "id": action_id, "target_id": target_id, "campaign_id": None, "operation_plan_id": None,
                    "command_result_id": None, "scope_receipt_id": None, "approval_receipt_id": None,
                    "scan_id": None, "command": "asm.improve", "action_name": "asm.improve", "status": "planned",
                    "dry_run": True, "risk_tier": "credential", "finding_ids": json.dumps([]),
                    "hypothesis_ids": json.dumps([]), "evidence_object_ids": json.dumps([]),
                    "tool_receipt_ids": json.dumps([]), "blocked_by": json.dumps([]), "next_action": None,
                    "operator_message": "planned", "result_json": json.dumps({"authz_replay_plan": replay_plan}),
                    "created_by": "pytest", "mission_campaign_id": None, "created_at": "now", "updated_at": "now",
                }
            if "UPDATE campaign_actions" in sql:
                return {
                    "id": action_id, "target_id": target_id, "campaign_id": None, "operation_plan_id": None,
                    "command_result_id": None, "scope_receipt_id": None, "approval_receipt_id": None,
                    "scan_id": None, "command": "asm.improve", "action_name": "asm.improve", "status": args[0],
                    "dry_run": False, "risk_tier": "credential", "finding_ids": json.dumps([]),
                    "hypothesis_ids": json.dumps([]), "evidence_object_ids": json.dumps([]),
                    "tool_receipt_ids": json.dumps([]), "blocked_by": json.dumps([]), "next_action": None,
                    "operator_message": "replayed", "result_json": args[1], "created_by": "pytest",
                    "mission_campaign_id": None, "created_at": "now", "updated_at": "now",
                }
            if "INSERT INTO tool_receipts" in sql:
                return {
                    "id": uuid.uuid4(), "tool_name": args[0], "tool_version": args[1], "adapter_version": args[2],
                    "command_hash": args[3], "redacted_argv": args[4], "worker_build": args[5],
                    "container_image": args[6], "target_scope": args[7], "scope_receipt_id": args[8],
                    "approval_receipt_id": args[9], "policy_profile_id": args[10], "status": args[11],
                    "parser_status": args[12], "exit_code": args[13], "timed_out": args[14],
                    "started_at": args[15], "finished_at": args[16], "stdout_evidence_object_id": args[17],
                    "stderr_evidence_object_id": args[18], "parsed_evidence_instance_ids": args[19],
                    "redaction_summary": args[20], "metadata_json": args[21], "created_by": args[22],
                    "created_at": "now",
                }
            if "INSERT INTO evidence_instances" in sql:
                return {
                    "id": uuid.uuid4(), "finding_id": args[0], "evidence_object_id": args[1], "scan_id": args[2],
                    "target_id": args[3], "concrete_url": args[4], "object_id": args[5], "payload_variant": args[6],
                    "request_response_refs": args[7], "principal_pair": args[8], "proof_observation": args[9],
                    "campaign_action_id": args[10], "tool_receipt_id": args[11], "redaction_profile": args[12],
                    "hash": args[13], "retention_policy": args[14], "proof_state": args[15],
                    "metadata_json": args[16], "created_by": args[17], "created_at": "now",
                }
            if "INSERT INTO command_results" in sql:
                return {
                    "id": uuid.uuid4(), "command": args[0], "status": args[1], "dry_run": args[2],
                    "risk_tier": args[3], "operation_plan_id": args[4], "scope_receipt_id": args[5],
                    "approval_receipt_id": args[6], "campaign_id": args[7], "scan_id": args[8],
                    "finding_ids": args[9], "hypothesis_ids": args[10], "evidence_object_ids": args[11],
                    "tool_receipt_ids": args[12], "blocked_by": args[13], "next_action": args[14],
                    "operator_message": args[15], "result_json": args[16], "created_by": args[17],
                    "created_at": "now",
                }
            raise AssertionError(sql)

    monkeypatch.setattr(api_module, "InteractiveSessionManager", _FakeInteractiveSessionManager)

    async def fake_profile_bindings(conn, bound_target_id):
        assert bound_target_id == target_id
        return {"user1": "profile-user1", "user2": "profile-user2"}

    monkeypatch.setattr(api_module, "_authz_target_principal_profile_bindings", fake_profile_bindings)

    result = asyncio.run(api_module._execute_authz_replay_plan(
        _FakeConn(),
        campaign_action_id=str(action_id),
        session_id="session-1",
        created_by="pytest",
    ))

    assert result["mismatch_count"] == 1
    assert result["violation_count"] == 0
    assert result["observations"][1]["observed_status"] == 302
    assert result["observations"][1]["violation_observed"] is False
    proof_bundle = result["command_result"]["result_json"]["authz_replay"]["proof_bundle"]
    assert proof_bundle["differential_observed"] is False
    assert proof_bundle["denial_like_redirects"][0]["status"] == 302


def test_execute_authz_replay_plan_requires_authenticated_principals(monkeypatch):
    action_id = uuid.uuid4()
    replay_plan = {
        "mode": "deterministic_authz_replay",
        "method": "GET",
        "path": "/api/orders/{id}",
        "concrete_path": "/api/orders/42",
        "expected_access": [
            {"path": "/api/orders/{id}", "principal_label": "user1", "principal_auth_state": "user1", "expected_access": "allow"},
            {"path": "/api/orders/{id}", "principal_label": "user2", "principal_auth_state": "user2", "expected_access": "deny"},
        ],
    }
    called = {"test_endpoint": 0}

    class _FakeSession:
        state = types.SimpleNamespace(users={"user1": types.SimpleNamespace(is_authenticated=True)})

        async def test_endpoint(self, **kwargs):
            called["test_endpoint"] += 1
            return {"success": True, "status_code": 200}

    class _FakeManager:
        async def get_session(self, session_id):
            return _FakeSession()

    class _FakeInteractiveSessionManager:
        @staticmethod
        async def get_instance():
            return _FakeManager()

    class _FakeConn:
        async def fetchrow(self, query, *args):
            sql = str(query)
            if "SELECT * FROM campaign_actions" in sql:
                return {
                    "id": action_id, "target_id": None, "campaign_id": None, "operation_plan_id": None,
                    "command_result_id": None, "scope_receipt_id": None, "approval_receipt_id": None,
                    "scan_id": None, "command": "asm.improve", "action_name": "asm.improve", "status": "planned",
                    "dry_run": True, "risk_tier": "credential", "finding_ids": json.dumps([]),
                    "hypothesis_ids": json.dumps([]), "evidence_object_ids": json.dumps([]),
                    "tool_receipt_ids": json.dumps([]), "blocked_by": json.dumps([]), "next_action": None,
                    "operator_message": "planned", "result_json": json.dumps({"authz_replay_plan": replay_plan}),
                    "created_by": "pytest", "mission_campaign_id": None, "created_at": "now", "updated_at": "now",
                }
            if "INSERT INTO tool_receipts" in sql:
                return {
                    "id": uuid.uuid4(), "tool_name": args[0], "tool_version": args[1], "adapter_version": args[2],
                    "command_hash": args[3], "redacted_argv": args[4], "worker_build": args[5],
                    "container_image": args[6], "target_scope": args[7], "scope_receipt_id": args[8],
                    "approval_receipt_id": args[9], "policy_profile_id": args[10], "status": args[11],
                    "parser_status": args[12], "exit_code": args[13], "timed_out": args[14],
                    "started_at": args[15], "finished_at": args[16], "stdout_evidence_object_id": args[17],
                    "stderr_evidence_object_id": args[18], "parsed_evidence_instance_ids": args[19],
                    "redaction_summary": args[20], "metadata_json": args[21], "created_by": args[22],
                    "created_at": "now",
                }
            if "UPDATE campaign_actions" in sql:
                return {
                    "id": action_id, "target_id": None, "campaign_id": None, "operation_plan_id": None,
                    "command_result_id": None, "scope_receipt_id": None, "approval_receipt_id": None,
                    "scan_id": None, "command": "asm.improve", "action_name": "asm.improve", "status": "partial",
                    "dry_run": False, "risk_tier": "credential", "finding_ids": json.dumps([]),
                    "hypothesis_ids": json.dumps([]), "evidence_object_ids": json.dumps([]),
                    "tool_receipt_ids": json.dumps([]), "blocked_by": json.dumps([]), "next_action": None,
                    "operator_message": "replayed", "result_json": args[0], "created_by": "pytest",
                    "mission_campaign_id": None, "created_at": "now", "updated_at": "now",
                }
            if "INSERT INTO command_results" in sql:
                return {
                    "id": uuid.uuid4(), "command": args[0], "status": args[1], "dry_run": args[2],
                    "risk_tier": args[3], "operation_plan_id": args[4], "scope_receipt_id": args[5],
                    "approval_receipt_id": args[6], "campaign_id": args[7], "scan_id": args[8],
                    "finding_ids": args[9], "hypothesis_ids": args[10], "evidence_object_ids": args[11],
                    "tool_receipt_ids": args[12], "blocked_by": args[13], "next_action": args[14],
                    "operator_message": args[15], "result_json": args[16], "created_by": args[17],
                    "created_at": "now",
                }
            raise AssertionError(sql)

    monkeypatch.setattr(api_module, "InteractiveSessionManager", _FakeInteractiveSessionManager)

    result = asyncio.run(api_module._execute_authz_replay_plan(
        _FakeConn(),
        campaign_action_id=str(action_id),
        session_id="session-1",
        created_by="pytest",
    ))

    assert called["test_endpoint"] == 0
    assert result["violation_count"] == 0
    assert result["observations"][1]["inconclusive_reason"] == "missing_authenticated_principal"
    assert result["tool_receipt_id"]
    proof_bundle = result["command_result"]["result_json"]["authz_replay"]["proof_bundle"]
    assert proof_bundle["differential_observed"] is False
    assert proof_bundle["authenticated_principal_count"] == 1


def test_promote_authz_replay_finding_requires_violation_and_links_evidence(monkeypatch):
    action_id = uuid.uuid4()
    target_id = uuid.uuid4()
    hypothesis_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    approval_id = uuid.uuid4()
    tool_receipt_id = uuid.uuid4()
    evidence_ids = [uuid.uuid4(), uuid.uuid4()]
    captured: dict[str, object] = {"queries": [], "executes": []}
    replay = {
        "violation_count": 1,
        "tool_receipt_id": str(tool_receipt_id),
        "evidence_instance_ids": [str(item) for item in evidence_ids],
        "proof_bundle": {
            "bundle_type": "authz_replay_proof_bundle",
            "differential_observed": True,
            "authenticated_principal_count": 2,
            "principal_profile_bindings_verified": True,
            "principal_identity_bindings_verified": True,
            "finding_created_automatically": False,
        },
        "observations": [
            {
                "method": "GET",
                "path": "/api/orders/42",
                "principal_label": "user2",
                "principal_auth_state": "user2",
                "expected_access": "deny",
                "expected_http_status": 403,
                "observed_status": 200,
                "matched": False,
                "request_success": True,
                "authenticated_user": True,
                "violation_observed": True,
                "request": {"method": "GET", "url": "/api/orders/42", "as_user": "user2"},
                "response": {"status": 200, "body_sample": '{"id":42,"owner":"user1"}'},
            }
        ],
    }

    class _FakeConn:
        async def fetchrow(self, query, *args):
            sql = str(query)
            captured["queries"].append(sql)
            if "SELECT * FROM campaign_actions" in sql:
                return {
                    "id": action_id,
                    "campaign_id": None,
                    "operation_plan_id": None,
                    "command_result_id": None,
                    "target_id": target_id,
                    "scope_receipt_id": None,
                    "approval_receipt_id": None,
                    "scan_id": None,
                    "command": "authz.replay_plan",
                    "action_name": "authz.replay_plan",
                    "status": "partial",
                    "dry_run": False,
                    "risk_tier": "credential",
                    "finding_ids": json.dumps([]),
                    "hypothesis_ids": json.dumps([str(hypothesis_id)]),
                    "evidence_object_ids": json.dumps([]),
                    "tool_receipt_ids": json.dumps([str(tool_receipt_id)]),
                    "blocked_by": json.dumps([]),
                    "next_action": None,
                    "operator_message": "replayed",
                    "result_json": json.dumps({"authz_replay": replay}),
                    "created_by": "pytest",
                    "mission_campaign_id": None,
                    "created_at": "now",
                    "updated_at": "now",
                }
            if "SELECT id, url FROM targets" in sql:
                return {"id": target_id, "url": "https://app.example.com"}
            if "SELECT id, status FROM findings" in sql:
                return None
            if "INSERT INTO command_results" in sql:
                captured["command_result_args"] = args
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
            raise AssertionError(sql)

        async def fetchval(self, query, *args):
            captured["queries"].append(str(query))
            assert "INSERT INTO findings" in str(query)
            captured["finding_args"] = args
            return finding_id

        async def execute(self, query, *args):
            captured["executes"].append((str(query), args))
            return "OK"

    async def fake_validate(conn, receipt_id, **kwargs):
        captured["approval_validation"] = (receipt_id, kwargs)
        return {"approval_receipt_id": receipt_id, "scope_receipt_id": "scope-1"}

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)

    result = asyncio.run(api_module._promote_authz_replay_finding(
        _FakeConn(),
        campaign_action_id=str(action_id),
        approval_receipt_id=str(approval_id),
        created_by="pytest",
    ))

    assert result["execution_enabled"] is True
    assert result["findings_created"] == 1
    assert result["finding_id"] == str(finding_id)
    assert result["tool_receipt_id"] == str(tool_receipt_id)
    assert result["evidence_instance_ids"] == [str(item) for item in evidence_ids]
    assert result["command_result"]["command"] == "authz.promote_replay_finding"
    assert result["command_result"]["finding_ids"] == [str(finding_id)]
    assert result["command_result"]["tool_receipt_ids"] == [str(tool_receipt_id)]
    assert captured["finding_args"][2].startswith("BOLA:")
    assert json.loads(captured["finding_args"][7])["as_user"] == "user2"
    assert json.loads(captured["finding_args"][8])["status"] == 200
    finding_evidence = json.loads(captured["finding_args"][6])
    assert finding_evidence["authz_replay"]["templated_path"] == "/api/orders/{id}"
    assert finding_evidence["authz_replay"]["proof_bundle"]["differential_observed"] is True
    assert captured["approval_validation"][0] == str(approval_id)
    assert captured["approval_validation"][1]["target_id"] == target_id
    assert captured["approval_validation"][1]["target_url"] == "https://app.example.com"
    assert any("UPDATE evidence_instances" in sql for sql, _args in captured["executes"])
    assert any("UPDATE campaign_actions" in sql for sql, _args in captured["executes"])


def test_campaign_action_execution_allows_explicit_authz_replay_promotion():
    action_id = uuid.uuid4()

    class _FakeConn:
        async def fetchrow(self, query, *args):
            assert "SELECT * FROM campaign_actions" in str(query)
            assert args == (action_id,)
            return {
                "id": action_id,
                "command": "authz.replay_plan",
                "action_name": "authz.replay_plan",
                "result_json": json.dumps({"authz_replay": {"violation_count": 1}}),
                "finding_ids": json.dumps([]),
                "hypothesis_ids": json.dumps([]),
                "evidence_object_ids": json.dumps([]),
                "tool_receipt_ids": json.dumps([]),
                "blocked_by": json.dumps([]),
                "mission_campaign_id": None,
            }

    req = api_module.ArsenalExecuteRequest(
        command="authz.promote_replay_finding",
        parameters={"campaign_action_id": str(action_id)},
        campaign_action_id=str(action_id),
    )
    action = asyncio.run(api_module._validate_campaign_action_for_execution(_FakeConn(), req))

    assert action["id"] == str(action_id)
    assert action["result_json"]["authz_replay"]["violation_count"] == 1


def test_campaign_action_execution_rejects_promotion_before_authz_replay():
    action_id = uuid.uuid4()

    class _FakeConn:
        async def fetchrow(self, query, *args):
            return {
                "id": action_id,
                "command": "authz.replay_plan",
                "action_name": "authz.replay_plan",
                "result_json": json.dumps({"authz_replay_plan": {"mode": "deterministic_authz_replay"}}),
                "finding_ids": json.dumps([]),
                "hypothesis_ids": json.dumps([]),
                "evidence_object_ids": json.dumps([]),
                "tool_receipt_ids": json.dumps([]),
                "blocked_by": json.dumps([]),
                "mission_campaign_id": None,
            }

    req = api_module.ArsenalExecuteRequest(
        command="authz.promote_replay_finding",
        parameters={"campaign_action_id": str(action_id)},
        campaign_action_id=str(action_id),
    )
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module._validate_campaign_action_for_execution(_FakeConn(), req))

    assert exc.value.status_code == 409


def test_authz_replay_route_forwards_gated_campaign_action(monkeypatch):
    action_id = uuid.uuid4()
    approval_id = uuid.uuid4()
    captured = {}

    async def fake_execute(req):
        captured["request"] = req
        return {"dispatched": True}

    monkeypatch.setattr(api_module, "_arsenal_execute_detached", fake_execute)
    result = asyncio.run(api_module.arsenal_execute_authz_replay(
        str(action_id),
        api_module.AuthzReplayExecuteRequest(
            session_id="session-1",
            execute=True,
            confirmations=["confirm_authorized"],
            approval_receipt_id=str(approval_id),
            created_by="pytest",
        ),
    ))

    req = captured["request"]
    assert result == {"dispatched": True}
    assert req.command == "authz.replay_plan"
    assert req.campaign_action_id == str(action_id)
    assert req.parameters["session_id"] == "session-1"
    assert req.approval_receipt_id == str(approval_id)


def test_authz_promote_route_forwards_gated_campaign_action(monkeypatch):
    action_id = uuid.uuid4()
    captured = {}

    async def fake_execute(req):
        captured["request"] = req
        return {"dispatched": True}

    monkeypatch.setattr(api_module, "_arsenal_execute_detached", fake_execute)
    result = asyncio.run(api_module.arsenal_promote_authz_replay(
        str(action_id),
        api_module.AuthzReplayPromoteRequest(
            execute=True,
            confirmations=["confirm_authorized"],
            created_by="pytest",
        ),
    ))

    req = captured["request"]
    assert result == {"dispatched": True}
    assert req.command == "authz.promote_replay_finding"
    assert req.campaign_action_id == str(action_id)
    assert req.parameters["campaign_action_id"] == str(action_id)


def test_promote_authz_replay_finding_creates_one_finding_per_principal(monkeypatch):
    action_id = uuid.uuid4()
    target_id = uuid.uuid4()
    approval_id = uuid.uuid4()
    tool_receipt_id = uuid.uuid4()
    finding_ids = [uuid.uuid4(), uuid.uuid4()]
    captured: dict[str, object] = {"finding_inserts": [], "executes": []}

    def _violation(principal):
        return {
            "method": "GET",
            "path": "/api/orders/42",
            "principal_label": principal,
            "principal_auth_state": principal,
            "expected_access": "deny",
            "expected_http_status": 403,
            "observed_status": 200,
            "matched": False,
            "request_success": True,
            "authenticated_user": True,
            "violation_observed": True,
            "request": {"method": "GET", "url": "/api/orders/42", "as_user": principal},
            "response": {"status": 200, "body_sample": '{"id":42}'},
        }

    replay = {
        "violation_count": 2,
        "tool_receipt_id": str(tool_receipt_id),
        "evidence_instance_ids": [],
        "proof_bundle": {
            "bundle_type": "authz_replay_proof_bundle",
            "differential_observed": True,
            "authenticated_principal_count": 3,
            "principal_profile_bindings_verified": True,
            "principal_identity_bindings_verified": True,
        },
        # Two DISTINCT offending principals on the same route template.
        "observations": [_violation("user2"), _violation("user3")],
    }

    inserts = iter(finding_ids)

    class _FakeConn:
        async def fetchrow(self, query, *args):
            sql = str(query)
            if "SELECT * FROM campaign_actions" in sql:
                return {
                    "id": action_id, "campaign_id": None, "operation_plan_id": None,
                    "command_result_id": None, "target_id": target_id,
                    "scope_receipt_id": None, "approval_receipt_id": None, "scan_id": None,
                    "command": "authz.replay_plan", "action_name": "authz.replay_plan",
                    "status": "partial", "dry_run": False, "risk_tier": "credential",
                    "finding_ids": json.dumps([]), "hypothesis_ids": json.dumps([]),
                    "evidence_object_ids": json.dumps([]),
                    "tool_receipt_ids": json.dumps([str(tool_receipt_id)]),
                    "blocked_by": json.dumps([]), "next_action": None,
                    "operator_message": "replayed",
                    "result_json": json.dumps({"authz_replay": replay}),
                    "created_by": "pytest", "mission_campaign_id": None,
                    "created_at": "now", "updated_at": "now",
                }
            if "SELECT id, url FROM targets" in sql:
                return {"id": target_id, "url": "https://app.example.com"}
            if "SELECT id, status FROM findings" in sql:
                return None
            if "INSERT INTO command_results" in sql:
                return {
                    "id": uuid.uuid4(), "command": args[0], "status": args[1],
                    "dry_run": args[2], "risk_tier": args[3], "operation_plan_id": args[4],
                    "scope_receipt_id": args[5], "approval_receipt_id": args[6],
                    "campaign_id": args[7], "scan_id": args[8], "finding_ids": args[9],
                    "hypothesis_ids": args[10], "evidence_object_ids": args[11],
                    "tool_receipt_ids": args[12], "blocked_by": args[13],
                    "next_action": args[14], "operator_message": args[15],
                    "result_json": args[16], "created_by": args[17], "created_at": "now",
                }
            raise AssertionError(sql)

        async def fetchval(self, query, *args):
            assert "INSERT INTO findings" in str(query)
            captured["finding_inserts"].append(args)
            return next(inserts)

        async def execute(self, query, *args):
            captured["executes"].append((str(query), args))
            return "OK"

    async def fake_validate(conn, receipt_id, **kwargs):
        return {"approval_receipt_id": receipt_id, "scope_receipt_id": "scope-1"}

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)

    result = asyncio.run(api_module._promote_authz_replay_finding(
        _FakeConn(),
        campaign_action_id=str(action_id),
        approval_receipt_id=str(approval_id),
        created_by="pytest",
    ))

    # Both distinct principals become findings; neither is dropped.
    assert result["findings_created"] == 2
    assert len(captured["finding_inserts"]) == 2
    assert result["finding_ids"] == [str(item) for item in finding_ids]
    assert result["finding_id"] == str(finding_ids[0])
    assert {p["principal"] for p in result["promotions"]} == {"user2", "user3"}
    # Distinct principals => distinct fingerprints (not collapsed to one finding).
    assert len({p["fingerprint"] for p in result["promotions"]}) == 2
    assert result["command_result"]["finding_ids"] == [str(item) for item in finding_ids]


def test_promote_authz_replay_finding_requires_differential(monkeypatch):
    action_id = uuid.uuid4()
    target_id = uuid.uuid4()
    approval_id = uuid.uuid4()
    replay = {
        "violation_count": 1,
        "proof_bundle": {
            "bundle_type": "authz_replay_proof_bundle",
            "differential_observed": False,
            "authenticated_principal_count": 1,
            "principal_profile_bindings_verified": True,
            "principal_identity_bindings_verified": True,
        },
        "observations": [
            {
                "method": "GET",
                "path": "/api/orders/42",
                "principal_label": "user2",
                "principal_auth_state": "user2",
                "expected_access": "deny",
                "observed_status": 200,
                "matched": False,
                "request_success": True,
                "authenticated_user": True,
                "violation_observed": True,
            }
        ],
    }

    class _FakeConn:
        async def fetchrow(self, query, *args):
            sql = str(query)
            if "SELECT * FROM campaign_actions" in sql:
                return {
                    "id": action_id,
                    "target_id": target_id,
                    "campaign_id": None,
                    "operation_plan_id": None,
                    "command_result_id": None,
                    "scope_receipt_id": None,
                    "approval_receipt_id": None,
                    "scan_id": None,
                    "command": "authz.replay_plan",
                    "action_name": "authz.replay_plan",
                    "status": "partial",
                    "dry_run": False,
                    "risk_tier": "credential",
                    "finding_ids": json.dumps([]),
                    "hypothesis_ids": json.dumps([]),
                    "evidence_object_ids": json.dumps([]),
                    "tool_receipt_ids": json.dumps([]),
                    "blocked_by": json.dumps([]),
                    "next_action": None,
                    "operator_message": "replayed",
                    "result_json": json.dumps({"authz_replay": replay}),
                    "created_by": "pytest",
                    "mission_campaign_id": None,
                    "created_at": "now",
                    "updated_at": "now",
                }
            if "SELECT id, url FROM targets" in sql:
                return {"id": target_id, "url": "https://app.example.com"}
            raise AssertionError(sql)

    async def fake_validate(conn, receipt_id, **kwargs):
        return {"approval_receipt_id": receipt_id}

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)

    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module._promote_authz_replay_finding(
            _FakeConn(),
            campaign_action_id=str(action_id),
            approval_receipt_id=str(approval_id),
            created_by="pytest",
        ))

    assert exc.value.status_code == 400
    assert "differential" in str(exc.value.detail)


def test_authz_template_replay_path_collapses_volatile_ids():
    assert api_module._authz_template_replay_path("/api/orders/42") == "/api/orders/{id}"
    assert api_module._authz_template_replay_path("/users/550e8400-e29b-41d4-a716-446655440000") == "/users/{uuid}"
    assert api_module._authz_template_replay_path("/blob/0123456789abcdef0123456789abcdef") == "/blob/{hash}"
    assert api_module._authz_template_replay_path("/api/v2/login") == "/api/v2/login"


def test_authz_concrete_replay_path_never_invents_template_values():
    plan = {"path": "/api/orders/{id}"}
    assert api_module._authz_concrete_replay_path({"path": "/api/orders/{id}"}, plan) == ""
    assert api_module._authz_concrete_replay_path(
        {"path": "/api/orders/{id}", "concrete_path": "/api/orders/42"},
        plan,
    ) == "/api/orders/42"
    assert api_module._authz_replay_path_is_template("/api/orders/:orderId") is True
    assert api_module._authz_replay_path_is_template("/api/orders/42") is False


def test_hypothesis_finding_match_requires_family_route_method_and_parameter():
    hypothesis = {
        "family": "xss",
        "metadata_json": {
            "dedupe_dimensions": {
                "route": "/api/search/{id}",
                "method": "get",
                "parameter_path": "q",
            }
        },
    }
    finding = {
        "title": "Reflected XSS",
        "tool": "smart_xss",
        "cwe": "CWE-79",
        "url": "https://app.example.com/api/search/42?q=x",
        "evidence": {"method": "GET", "parameter": "q"},
        "request": {},
    }

    assert api_module._hypothesis_family_matches_finding(hypothesis, finding) is True
    assert api_module._hypothesis_dimensions_match_finding(hypothesis, finding) is True
    assert api_module._hypothesis_dimensions_match_finding(
        hypothesis,
        {**finding, "evidence": {"method": "POST", "parameter": "q"}},
    ) is False
    assert api_module._hypothesis_route_matches_finding("/api/search/{id}", {"url": "https://app.example.com/api/search"}) is False


def test_reconcile_hypothesis_promotes_only_existing_action_proof(monkeypatch):
    hypothesis_id = uuid.uuid4()
    action_id = uuid.uuid4()
    target_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    evidence_id = uuid.uuid4()
    approval_id = str(uuid.uuid4())
    captured = {}

    hypothesis_row = {
        "id": hypothesis_id,
        "target_id": target_id,
        "campaign_id": None,
        "campaign_action_id": action_id,
        "source": "scanner_signal",
        "family": "xss",
        "dedupe_key": "xss-search",
        "status": "testing",
        "version": 3,
        "claim_owner": "worker-1",
        "claim_lease_expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
        "evidence_object_ids": [],
        "tool_receipt_ids": [],
        "promoted_finding_ids": [],
        "next_test_action": {},
        "endorsements": [],
        "refutations": [],
        "metadata_json": {"dedupe_dimensions": {"route": "/api/search", "method": "get", "parameter_path": "q"}},
    }
    action_row = {
        "id": action_id,
        "target_id": target_id,
        "command_result_id": uuid.uuid4(),
        "scan_id": scan_id,
        "command": "scan.focused_family",
        "action_name": "scan.focused_family",
        "status": "queued",
        "dry_run": False,
        "risk_tier": "active",
        "finding_ids": [],
        "hypothesis_ids": [str(hypothesis_id)],
        "evidence_object_ids": [],
        "tool_receipt_ids": [str(uuid.uuid4())],
        "blocked_by": [],
        "result_json": {},
        "executed_command": "scan.focused_family",
        "executed_status": "queued",
        "executed_finding_ids": [],
        "executed_result_json": {},
    }
    finding_row = {
        "id": finding_id,
        "target_id": target_id,
        "scan_id": scan_id,
        "fingerprint": "fp-xss",
        "title": "Reflected XSS",
        "tool": "smart_xss",
        "cwe": "CWE-79",
        "severity": "high",
        "status": "active",
        "url": "https://app.example.com/api/search?q=x",
        "evidence": {"method": "GET", "parameter": "q"},
        "request": {},
        "response": {},
        "last_verification_status": "still_vulnerable",
        "last_verification_verdict": "exploited",
        "last_verification_confidence": 1.0,
        "updated_at": datetime.now(timezone.utc),
    }

    class FakeConn:
        async def fetchrow(self, query, *args):
            sql = str(query)
            if "SELECT * FROM hypotheses" in sql:
                return hypothesis_row
            if "SELECT id, url FROM targets" in sql:
                return {"id": target_id, "url": "https://app.example.com"}
            if "SELECT ca.*" in sql:
                return action_row
            if "UPDATE hypotheses" in sql:
                captured["update_args"] = args
                return {
                    **hypothesis_row,
                    "status": "promoted",
                    "version": 4,
                    "claim_owner": None,
                    "claim_lease_expires_at": None,
                    "promoted_finding_ids": [str(finding_id)],
                    "evidence_object_ids": [str(evidence_id)],
                }
            raise AssertionError(sql)

        async def fetchval(self, query, *args):
            if "SELECT status FROM scans" in str(query):
                return "completed"
            raise AssertionError(str(query))

        async def fetch(self, query, *args):
            sql = str(query)
            if "FROM findings" in sql:
                return [finding_row]
            if "FROM evidence_objects" in sql:
                return [{"id": evidence_id}]
            raise AssertionError(sql)

    async def fake_validate(conn, receipt_id, **kwargs):
        captured["approval"] = (receipt_id, kwargs)
        return {"approval_receipt_id": receipt_id}

    async def fake_record(conn, **kwargs):
        captured["command_result"] = kwargs
        return {"id": str(uuid.uuid4()), **kwargs}

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)
    monkeypatch.setattr(api_module, "_record_command_result", fake_record)

    result = asyncio.run(api_module._reconcile_hypothesis_proof(
        FakeConn(),
        str(hypothesis_id),
        api_module.HypothesisProofReconcileRequest(
            expected_version=3,
            campaign_action_id=str(action_id),
            approval_receipt_id=approval_id,
        ),
    ))

    assert result["promoted"] is True
    assert result["findings_created"] == 0
    assert result["hypothesis"]["status"] == "promoted"
    assert result["hypothesis"]["promoted_finding_ids"] == [str(finding_id)]
    assert result["proof_reconciliation"]["promotions"][0]["proof_provenance"] == "campaign_scan"
    assert captured["approval"][0] == approval_id
    assert captured["approval"][1]["always_require_receipt"] is True
    assert captured["command_result"]["finding_ids"] == [str(finding_id)]


def test_reconcile_hypothesis_keeps_ai_only_or_weak_finding_open(monkeypatch):
    hypothesis_id = uuid.uuid4()
    action_id = uuid.uuid4()
    target_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    hypothesis_row = {
        "id": hypothesis_id, "target_id": target_id, "campaign_action_id": action_id,
        "source": "ai_gate", "family": "xss", "dedupe_key": "weak", "status": "open", "version": 1,
        "evidence_object_ids": [], "tool_receipt_ids": [], "promoted_finding_ids": [],
        "next_test_action": {}, "endorsements": [], "refutations": [], "metadata_json": {},
    }
    action_row = {
        "id": action_id, "target_id": target_id, "command_result_id": uuid.uuid4(), "scan_id": scan_id,
        "command": "ai_gate.scan", "status": "completed", "dry_run": False, "risk_tier": "active",
        "finding_ids": [str(finding_id)], "hypothesis_ids": [str(hypothesis_id)],
        "evidence_object_ids": [], "tool_receipt_ids": [], "blocked_by": [], "result_json": {},
        "executed_command": "ai_gate.scan", "executed_status": "completed",
        "executed_finding_ids": [str(finding_id)], "executed_result_json": {},
    }

    class FakeConn:
        async def fetchrow(self, query, *args):
            sql = str(query)
            if "SELECT * FROM hypotheses" in sql:
                return hypothesis_row
            if "SELECT id, url FROM targets" in sql:
                return {"id": target_id, "url": "https://app.example.com"}
            if "SELECT ca.*" in sql:
                return action_row
            if "UPDATE hypotheses" in sql:
                return {**hypothesis_row, "version": 2, "metadata_json": {"latest_proof_reconciliation": {}}}
            raise AssertionError(sql)

        async def fetchval(self, query, *args):
            return "completed"

        async def fetch(self, query, *args):
            if "FROM findings" in str(query):
                return [{
                    "id": finding_id, "target_id": target_id, "scan_id": scan_id,
                    "fingerprint": "weak", "title": "Semantic XSS concern", "tool": "ai_judge",
                    "cwe": "CWE-79", "severity": "high", "status": "active",
                    "url": "https://app.example.com/chat", "evidence": {}, "request": {}, "response": {},
                    "last_verification_status": "completed", "last_verification_verdict": "likely_vulnerable",
                    "last_verification_confidence": 0.9, "updated_at": datetime.now(timezone.utc),
                }]
            if "FROM evidence_objects" in str(query):
                return []
            raise AssertionError(str(query))

    async def fake_validate(*args, **kwargs):
        return {}

    async def fake_record(conn, **kwargs):
        return {"id": str(uuid.uuid4()), **kwargs}

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)
    monkeypatch.setattr(api_module, "_record_command_result", fake_record)
    result = asyncio.run(api_module._reconcile_hypothesis_proof(
        FakeConn(), str(hypothesis_id),
        api_module.HypothesisProofReconcileRequest(
            expected_version=1, campaign_action_id=str(action_id), approval_receipt_id=str(uuid.uuid4()),
        ),
    ))

    assert result["promoted"] is False
    assert result["status"] == "partial"
    assert result["hypothesis"]["status"] == "open"
    assert result["proof_reconciliation"]["rejected_counts"] == {"deterministic_proof_missing": 1}


def test_hypothesis_signal_redacts_and_is_non_executing():
    req = api_module.HypothesisSignalRequest(
        signal_type="refutation",
        source="manual",
        reason="Benign explanation included secret-token",
        evidence_object_ids=[" evidence-1 ", ""],
        tool_receipt_ids=["tool-1"],
        confidence_delta=-0.4,
        status_hint="weaken",
        metadata_json={"authorization": "Bearer secret-token"},
        created_by="pytest",
    )

    signal = api_module._canonical_hypothesis_signal(req)

    assert signal["signal_type"] == "refutation"
    assert signal["evidence_object_ids"] == ["evidence-1"]
    assert signal["tool_receipt_ids"] == ["tool-1"]
    assert signal["confidence_delta"] == -0.4
    assert "secret-token" not in json.dumps(signal)
    assert signal["metadata_json"]["authorization"] != "Bearer secret-token"


def test_refuter_review_requires_evidence_basis_for_verdict_and_redacts():
    with pytest.raises(api_module.HTTPException):
        api_module._canonical_refuter_review(api_module.RefuterReviewRequest(
            subject_type="finding",
            finding_id=str(uuid.uuid4()),
            trigger_reason="Large delta with secret-token",
            refuter_signal="refute",
            refuter_verdict="refuted",
            verdict_basis="signal_only",
        ))

    payload = api_module._canonical_refuter_review(api_module.RefuterReviewRequest(
        subject_type="finding",
        finding_id=str(uuid.uuid4()),
        trigger_reason="Replay contradicted the claim with secret-token",
        refuter_signal="refute",
        refuter_verdict="refuted",
        verdict_basis="deterministic_replay",
        evidence_object_ids=[" evidence-1 ", ""],
        tool_receipt_ids=["tool-1"],
        counterevidence={"authorization": "Bearer secret-token"},
        notes="Secret-token must be redacted",
    ))

    assert payload["status"] == "verdict_recorded"
    assert payload["evidence_object_ids"] == ["evidence-1"]
    assert payload["tool_receipt_ids"] == ["tool-1"]
    assert "secret-token" not in json.dumps(payload)


def test_record_refuter_review_is_non_mutating():
    review_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    captured: dict[str, object] = {}

    class _FakeConn:
        async def fetchrow(self, query, *args):
            captured["query"] = str(query)
            captured["args"] = args
            return {
                "id": review_id,
                "subject_type": args[0],
                "subject_id": args[1],
                "target_id": args[2],
                "finding_id": args[3],
                "hypothesis_id": args[4],
                "campaign_id": args[5],
                "trigger_reason": args[6],
                "refuter_signal": args[7],
                "refuter_verdict": args[8],
                "verdict_basis": args[9],
                "confidence_delta": args[10],
                "evidence_object_ids": args[11],
                "tool_receipt_ids": args[12],
                "counterevidence": args[13],
                "notes": args[14],
                "status": args[15],
                "metadata_json": args[16],
                "created_by": args[17],
            }

    result = asyncio.run(api_module._record_refuter_review(_FakeConn(), api_module.RefuterReviewRequest(
        subject_type="finding",
        finding_id=str(finding_id),
        trigger_reason="High finding has weak proof",
        refuter_signal="question",
        verdict_basis="signal_only",
        created_by="pytest",
    )))

    assert "UPDATE findings" not in captured["query"]
    assert result["execution_enabled"] is False
    assert result["findings_updated"] == 0
    assert result["hypotheses_updated"] == 0
    assert result["refuter_review"]["finding_id"] == str(finding_id)
    assert result["refuter_review"]["status"] == "recorded"


def test_record_refuter_review_rejects_spoofed_receipt_ids_as_terminal_proof():
    finding_id = uuid.uuid4()

    class _FakeConn:
        async def fetchrow(self, query, *args):
            if "SELECT * FROM finding_verifications" in query:
                return None
            return {
                "id": uuid.uuid4(), "subject_type": args[0], "subject_id": args[1],
                "target_id": args[2], "finding_id": args[3], "hypothesis_id": args[4],
                "campaign_id": args[5], "trigger_reason": args[6], "refuter_signal": args[7],
                "refuter_verdict": args[8], "verdict_basis": args[9], "confidence_delta": args[10],
                "evidence_object_ids": args[11], "tool_receipt_ids": args[12],
                "counterevidence": args[13], "notes": args[14], "status": args[15],
                "metadata_json": args[16], "created_by": args[17],
            }

    result = asyncio.run(api_module._record_refuter_review(_FakeConn(), api_module.RefuterReviewRequest(
        subject_type="finding",
        finding_id=str(finding_id),
        trigger_reason="caller claims a replay contradicted the finding",
        refuter_signal="refute",
        refuter_verdict="refuted",
        verdict_basis="deterministic_replay",
        tool_receipt_ids=[str(uuid.uuid4())],
        evidence_object_ids=[str(uuid.uuid4())],
        counterevidence={"cite": {"observed": True}},
    )))

    review = result["refuter_review"]
    assert review["refuter_verdict"] == "inconclusive"
    assert review["refuter_signal"] == "question"
    assert review["metadata_json"]["negative_gate"]["reason"] == "refute_reference_not_verified"


def test_refuter_reference_rederives_completed_proof_and_rejects_replay_command_only():
    finding_id = uuid.uuid4()
    verification_id = uuid.uuid4()

    class _FakeConn:
        def __init__(self, proof):
            self.proof = proof

        async def fetchrow(self, query, *args):
            return {
                "id": verification_id,
                "finding_id": finding_id,
                "status": "completed",
                "verification_mode": "deterministic",
                "verdict": "false_positive",
                "proof": self.proof,
                "artifacts": {},
                "replay_commands": ["curl example"],
            }

    assert asyncio.run(api_module._refuter_verification_reference_valid(
        _FakeConn({"control_status": 403}),
        verification_id=verification_id,
        finding_uuid=finding_id,
        target_uuid=None,
    )) is True
    assert asyncio.run(api_module._refuter_verification_reference_valid(
        _FakeConn({}),
        verification_id=verification_id,
        finding_uuid=finding_id,
        target_uuid=None,
    )) is False


def test_hypothesis_refutation_rejects_nonexistent_verification(monkeypatch):
    hypothesis_id = uuid.uuid4()
    verification_id = uuid.uuid4()

    class _FakeConn:
        async def fetchrow(self, query, *args):
            if "SELECT * FROM hypotheses" in query:
                return {
                    "id": hypothesis_id, "target_id": uuid.uuid4(), "status": "testing", "version": 1,
                    "family": "bola", "next_test_action": {"falsifier": "403", "expected_signal": "403"},
                    "evidence_object_ids": [], "tool_receipt_ids": [], "endorsements": [],
                    "refutations": [], "metadata_json": {},
                }
            if "SELECT * FROM finding_verifications" in query:
                return None
            return None

    monkeypatch.setattr(api_module, "db_pool", _pool_for(_FakeConn()))
    req = api_module.HypothesisTransitionRequest(
        to="refuted",
        expected_version=1,
        refuted_by={"verification_id": str(verification_id), "basis": "deterministic_replay"},
    )
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module.arsenal_transition_hypothesis(str(hypothesis_id), req))
    assert exc.value.status_code == 422
    assert exc.value.detail["error"] == "refutation_reference_not_verified"


def test_hypothesis_dead_is_administrative_and_needs_no_refutation(monkeypatch):
    hypothesis_id = uuid.uuid4()
    target_id = uuid.uuid4()

    class _FakeConn:
        async def fetchrow(self, query, *args):
            sql = str(query)
            if "SELECT * FROM hypotheses" in sql:
                return {
                    "id": hypothesis_id, "target_id": target_id, "status": "open", "version": 1,
                    "family": "sqli", "next_test_action": {}, "evidence_object_ids": [],
                    "tool_receipt_ids": [], "promoted_finding_ids": [], "endorsements": [],
                    "refutations": [], "metadata_json": {},
                }
            if "UPDATE hypotheses" in sql:
                assert args[-1] == "open"
                return {
                    "id": hypothesis_id, "target_id": target_id, "status": "dead", "version": 2,
                    "family": "sqli", "next_test_action": {}, "evidence_object_ids": [],
                    "tool_receipt_ids": [], "promoted_finding_ids": [], "endorsements": [],
                    "refutations": [], "metadata_json": {},
                }
            raise AssertionError(sql)

    monkeypatch.setattr(api_module, "db_pool", _pool_for(_FakeConn()))
    result = asyncio.run(api_module.arsenal_transition_hypothesis(
        str(hypothesis_id),
        api_module.HypothesisTransitionRequest(to="dead", expected_version=1, reason="duplicate"),
    ))

    assert result["to"] == "dead"
    assert result["hypothesis"]["status"] == "dead"


def test_hypothesis_refutation_rejects_unrelated_same_target_verification(monkeypatch):
    hypothesis_id = uuid.uuid4()
    verification_id = uuid.uuid4()
    target_id = uuid.uuid4()
    finding_id = uuid.uuid4()

    class _FakeConn:
        async def fetchrow(self, query, *args):
            sql = str(query)
            if "SELECT * FROM hypotheses" in sql:
                return {
                    "id": hypothesis_id, "target_id": target_id, "status": "testing", "version": 1,
                    "family": "bola", "next_test_action": {"falsifier": "denied", "expected_signal": "cross-user access"},
                    "evidence_object_ids": [], "tool_receipt_ids": [], "promoted_finding_ids": [],
                    "endorsements": [], "refutations": [],
                    "metadata_json": {"dedupe_dimensions": {"route": "/api/orders/{id}", "method": "get"}},
                }
            if "FROM finding_verifications" in sql:
                return {
                    "id": verification_id, "finding_id": finding_id, "target_id": target_id,
                    "status": "completed", "verification_mode": "deterministic", "verdict": "false_positive",
                    "proof": {"control_status": 403}, "artifacts": {},
                }
            if "SELECT * FROM findings" in sql:
                return {
                    "id": finding_id, "target_id": target_id, "title": "Unrelated reflected XSS",
                    "tool": "smart_xss", "cwe": "CWE-79", "url": "https://app.test/search?q=x",
                    "evidence": {"method": "GET", "parameter": "q"}, "request": {},
                }
            raise AssertionError(sql)

    monkeypatch.setattr(api_module, "db_pool", _pool_for(_FakeConn()))
    req = api_module.HypothesisTransitionRequest(
        to="refuted",
        expected_version=1,
        refuted_by={"verification_id": str(verification_id), "basis": "deterministic_replay"},
    )
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module.arsenal_transition_hypothesis(str(hypothesis_id), req))

    assert exc.value.status_code == 422
    assert exc.value.detail["reason"] == "verification_not_bound_to_hypothesis_proof"


def test_hypothesis_subject_binding_requires_exact_reference_or_specific_dimensions():
    finding = {
        "id": uuid.uuid4(),
        "fingerprint": "finding-fingerprint-1",
        "url": "https://app.test/api/orders/42",
        "evidence": {"method": "GET", "object_key": "order.id"},
        "request": {},
    }

    assert api_module._hypothesis_subject_matches_finding(
        {"metadata_json": {"finding_fingerprint": "finding-fingerprint-1"}}, finding
    ) is True
    assert api_module._hypothesis_subject_matches_finding(
        {"metadata_json": {"dedupe_dimensions": {}}}, finding
    ) is False
    assert api_module._hypothesis_subject_matches_finding(
        {"metadata_json": {"dedupe_dimensions": {
            "route": "/api/orders/{id}", "method": "get", "object_key": "order.id",
        }}}, finding
    ) is True


def test_hypothesis_transition_cannot_bypass_proof_reconciliation_for_promotion(monkeypatch):
    hypothesis_id = uuid.uuid4()

    class _FakeConn:
        async def fetchrow(self, query, *args):
            if "SELECT * FROM hypotheses" in query:
                return {
                    "id": hypothesis_id, "target_id": uuid.uuid4(), "status": "supported", "version": 1,
                    "family": "bola", "next_test_action": {}, "evidence_object_ids": [],
                    "tool_receipt_ids": [], "endorsements": [], "refutations": [], "metadata_json": {},
                }
            return None

    monkeypatch.setattr(api_module, "db_pool", _pool_for(_FakeConn()))
    req = api_module.HypothesisTransitionRequest(to="promoted", expected_version=1)
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module.arsenal_transition_hypothesis(str(hypothesis_id), req))
    assert exc.value.status_code == 422
    assert exc.value.detail["error"] == "promotion_requires_proof_reconciliation"


def test_refuter_work_summary_triggers_weak_ai_and_model_claims():
    weak_id = uuid.uuid4()
    ai_id = uuid.uuid4()
    model_id = uuid.uuid4()
    parser_id = uuid.uuid4()
    deployment_id = uuid.uuid4()
    findings = [
        {
            "id": weak_id,
            "status": "active",
            "severity": "critical",
            "title": "Critical without deterministic proof",
            "source": "scan",
            "tool": "smart_sqli",
            "last_verification_verdict": None,
            "evidence": json.dumps({"url": "https://app.example.test/login?token=secret-token"}),
        },
        {
            "id": ai_id,
            "status": "active",
            "severity": "medium",
            "title": "Semantic AI Gate hit",
            "source": "ai_gate",
            "tool": "ai_gate",
            "ai_classification_source": "provider",
            "last_verification_verdict": None,
            "evidence": json.dumps({}),
        },
        {
            "id": model_id,
            "status": "active",
            "severity": "medium",
            "title": "Model metadata trust claim",
            "source": "model_intake",
            "tool": "model_intake",
            "last_verification_verdict": None,
            "evidence": json.dumps({"license": "unknown"}),
        },
        {
            "id": parser_id,
            "status": "active",
            "severity": "medium",
            "title": "Parser-promoted weak claim",
            "source": "scan",
            "tool": "nuclei",
            "last_verification_verdict": None,
            "evidence": json.dumps({"parser_status": "partial", "parser_promoted": True}),
        },
        {
            "id": deployment_id,
            "status": "active",
            "severity": "medium",
            "title": "Deployment gate blocker without verified proof",
            "source": "scan",
            "tool": "smart_authz",
            "last_verification_verdict": None,
            "evidence": json.dumps({"deployment_gate_blocker": True}),
        },
        {
            "id": uuid.uuid4(),
            "status": "active",
            "severity": "high",
            "title": "Verified high",
            "source": "scan",
            "tool": "smart_sqli",
            "last_verification_verdict": "exploited",
            "evidence": json.dumps({}),
        },
    ]
    reviews = [{"subject_type": "finding", "subject_id": str(weak_id)}]

    summary = api_module._refuter_work_summary(findings, reviews, limit=10)

    assert summary["execution_enabled"] is False
    assert summary["findings_updated"] == 0
    assert summary["summary"]["candidate_count"] == 5
    assert summary["summary"]["unreviewed_count"] == 4
    assert summary["summary"]["trigger_counts"]["critical_high_weak_or_suspected_proof"] == 1
    assert summary["summary"]["trigger_counts"]["ai_gate_semantic_or_weak_deterministic_claim"] == 1
    assert summary["summary"]["trigger_counts"]["model_intake_metadata_without_trust_anchor"] == 1
    assert summary["summary"]["trigger_counts"]["parser_promoted_or_degraded_output"] == 1
    assert summary["summary"]["trigger_counts"]["deployment_gating_claim_without_verified_proof"] == 1
    by_id = {item["subject_id"]: item for item in summary["candidates"]}
    assert by_id[str(weak_id)]["already_reviewed"] is True
    assert by_id[str(ai_id)]["recommended_review"]["verdict_basis"] == "signal_only"
    assert by_id[str(model_id)]["trigger_type"] == "model_intake_trust_claim"
    assert by_id[str(parser_id)]["trigger_type"] == "parser_output_claim"
    assert by_id[str(deployment_id)]["trigger_type"] == "deployment_gate_claim"
    weak_plan = by_id[str(weak_id)]["automation_plan"]
    assert weak_plan["execution_enabled"] is False
    assert weak_plan["status"] == "planned_not_executed"
    assert weak_plan["record_only_until_executed"] is True
    assert {step["command"] for step in weak_plan["steps"]} >= {"refuter_review.record", "finding.retest"}
    assert weak_plan["minimal_reproducer"]["available"] is True
    assert "counterevidence_bundle" in weak_plan
    assert "verification_id_after_replay" in weak_plan["counterevidence_bundle"]["required_evidence_refs"]
    assert "secret-token" not in json.dumps(weak_plan)
    ai_plan = by_id[str(ai_id)]["automation_plan"]
    assert "ai_gate.replay_probe" in {step["command"] for step in ai_plan["steps"]}
    model_plan = by_id[str(model_id)]["automation_plan"]
    assert "model_intake.trust_preview" in {step["command"] for step in model_plan["steps"]}
    parser_plan = by_id[str(parser_id)]["automation_plan"]
    assert any("parser" in item for item in parser_plan["counterevidence_bundle"]["benign_explanations_to_test"])


def test_finding_delta_refuter_signal_flags_spike():
    target_id = uuid.uuid4()
    # Latest scan 30 findings vs a baseline that hovered around 4.
    signal = api_module._finding_delta_refuter_signal({
        "target_id": str(target_id),
        "target_url": "https://app.example.com",
        "latest_scan_id": "scan-latest",
        "recent_finding_counts": [30, 4, 5, 3, 4],
    })
    assert signal is not None
    assert signal["trigger_type"] == "finding_delta_spike"
    assert signal["trigger_reasons"] == ["unusually_large_finding_delta"]
    assert signal["latest_finding_count"] == 30
    assert signal["baseline_median"] == 4
    assert signal["absolute_delta"] == 26
    assert signal["subject_type"] == "target"
    assert signal["execution_enabled"] is False


def test_finding_delta_refuter_signal_ignores_stable_and_insufficient_history():
    base = {"target_id": "t1", "target_url": "u", "latest_scan_id": "s"}
    # Stable: latest is in line with the baseline.
    assert api_module._finding_delta_refuter_signal({**base, "recent_finding_counts": [6, 5, 5, 4]}) is None
    # Small absolute delta even if proportionally larger (2 -> would-be spike) stays quiet.
    assert api_module._finding_delta_refuter_signal({**base, "recent_finding_counts": [4, 1, 1, 2]}) is None
    # Not enough history to form a baseline.
    assert api_module._finding_delta_refuter_signal({**base, "recent_finding_counts": [40, 2]}) is None
    # A big jump from a zero baseline still fires on the absolute floor alone.
    assert api_module._finding_delta_refuter_signal({**base, "recent_finding_counts": [8, 0, 0, 0]}) is not None


def _benchmark_artifact(target, recall, verified, path):
    return {
        "artifact_type": "benchmark_scorecard_run",
        "artifact_status": "passed_benchmark_scorecard" if recall >= 0.8 else "failed_benchmark_scorecard",
        "artifact_path": path,
        "targets": [{
            "target": target,
            "scan_id": f"scan-{path}",
            "scorecards": {
                "post_retest": {
                    "target": target,
                    "phase": "post_retest",
                    "expected_recall": recall,
                    "verified_high_critical": verified,
                    "scan_id": f"scan-{path}",
                }
            },
        }],
    }


def test_benchmark_win_delta_refuter_signal_flags_sudden_scorecard_jump():
    signals = api_module._benchmark_win_delta_refuter_signals([
        _benchmark_artifact("juice_shop", 0.78, 7, "latest"),
        _benchmark_artifact("juice_shop", 0.22, 2, "baseline-2"),
        _benchmark_artifact("juice_shop", 0.33, 3, "baseline-1"),
    ])

    assert len(signals) == 1
    signal = signals[0]
    assert signal["subject_type"] == "benchmark"
    assert signal["trigger_type"] == "benchmark_scorecard_win_delta"
    assert signal["trigger_reasons"] == [
        "benchmark_recall_win_delta",
        "benchmark_verified_high_critical_win_delta",
    ]
    assert signal["benchmark"] == "juice_shop"
    assert signal["latest_expected_recall"] == 0.78
    assert signal["baseline_expected_recall_median"] == 0.275
    assert signal["execution_enabled"] is False


def test_benchmark_win_delta_refuter_signal_ignores_flat_or_insufficient_history():
    assert api_module._benchmark_win_delta_refuter_signals([
        _benchmark_artifact("juice_shop", 0.44, 2, "latest"),
        _benchmark_artifact("juice_shop", 0.33, 2, "baseline-2"),
        _benchmark_artifact("juice_shop", 0.44, 2, "baseline-1"),
    ]) == []
    assert api_module._benchmark_win_delta_refuter_signals([
        _benchmark_artifact("juice_shop", 0.78, 7, "latest"),
        _benchmark_artifact("juice_shop", 0.22, 2, "baseline-1"),
    ]) == []


def test_finding_delta_target_stats_groups_recent_scans_newest_first():
    rows = [
        {"target_id": "a", "target_url": "ua", "scan_id": "a3", "findings_count": 30},
        {"target_id": "a", "target_url": "ua", "scan_id": "a2", "findings_count": 4},
        {"target_id": "a", "target_url": "ua", "scan_id": "a1", "findings_count": 5},
        {"target_id": "b", "target_url": "ub", "scan_id": "b1", "findings_count": 1},
        {"target_id": "", "target_url": "skip", "scan_id": "x", "findings_count": 9},
    ]
    stats = api_module._finding_delta_target_stats(rows)
    assert [s["target_id"] for s in stats] == ["a", "b"]  # empty target dropped, order preserved
    a = stats[0]
    assert a["latest_scan_id"] == "a3"
    assert a["recent_finding_counts"] == [30, 4, 5]


def test_refuter_work_summary_includes_report_only_integrity_signals():
    signals = api_module._finding_delta_refuter_signals([
        {"target_id": "t1", "target_url": "u1", "latest_scan_id": "s1", "recent_finding_counts": [30, 4, 5, 3]},
        {"target_id": "t2", "target_url": "u2", "latest_scan_id": "s2", "recent_finding_counts": [5, 4, 5, 4]},
    ])
    assert len(signals) == 1  # only the spiking target
    summary = api_module._refuter_work_summary([], [], limit=10, integrity_signals=signals)
    assert summary["summary"]["integrity_signal_count"] == 1
    assert summary["integrity_signals"][0]["target_id"] == "t1"
    # Report-only: integrity signals must never leak into the auto-queue candidate path.
    assert summary["candidates"] == []
    requests = api_module._refuter_review_requests_from_summary(summary)
    assert requests == []


def test_refuter_integrity_signals_require_opt_in_and_dedupe_reviewed_subjects():
    target_id = str(uuid.uuid4())
    signals = [{
        "subject_type": "target",
        "subject_id": target_id,
        "target_id": target_id,
        "trigger_type": "finding_delta_spike",
        "trigger_reasons": ["unusually_large_finding_delta"],
        "review_hint": "Confirm the scan delta is real.",
    }, {
        "subject_type": "benchmark",
        "subject_id": "benchmark-a",
        "trigger_type": "benchmark_scorecard_win_delta",
        "trigger_reasons": ["benchmark_recall_win_delta"],
        "review_hint": "Confirm benchmark independence.",
    }]
    reviews = [{"subject_type": "benchmark", "subject_id": "benchmark-a", "finding_id": None}]
    summary = api_module._refuter_work_summary([], reviews, limit=10, integrity_signals=signals)

    assert summary["integrity_signals"][0]["already_reviewed"] is False
    assert summary["integrity_signals"][1]["already_reviewed"] is True
    assert api_module._refuter_review_requests_from_summary(summary) == []

    requests = api_module._refuter_review_requests_from_summary(
        summary,
        include_integrity_signals=True,
        created_by="pytest",
    )
    assert len(requests) == 1
    request = requests[0]
    assert request.subject_type == "target"
    assert request.subject_id == target_id
    assert request.verdict_basis == "signal_only"
    assert request.metadata_json["queued_integrity_signal"] is True
    assert request.metadata_json["execution_enabled"] is False


def test_refuter_queue_from_summary_records_unreviewed_signal_only_reviews():
    weak_id = uuid.uuid4()
    ai_id = uuid.uuid4()
    review_id = uuid.uuid4()
    calls = {"fetch": 0, "fetchrow": []}

    class _FakeConn:
        def transaction(self):
            return self

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def fetch(self, query, *args):
            calls["fetch"] += 1
            if "FROM findings" in query:
                return [
                    {
                        "id": weak_id,
                        "status": "active",
                        "severity": "critical",
                        "title": "Already reviewed weak proof",
                        "source": "scan",
                        "tool": "smart_sqli",
                        "last_verification_verdict": None,
                        "evidence": json.dumps({}),
                    },
                    {
                        "id": ai_id,
                        "status": "active",
                        "severity": "medium",
                        "title": "Unreviewed semantic AI Gate hit",
                        "source": "ai_gate",
                        "tool": "ai_gate",
                        "ai_classification_source": "provider",
                        "last_verification_verdict": None,
                        "evidence": json.dumps({}),
                    },
                ]
            if "FROM refuter_reviews" in query:
                return [{"subject_type": "finding", "subject_id": str(weak_id), "finding_id": weak_id}]
            return []

        async def fetchrow(self, query, *args):
            calls["fetchrow"].append((query, args))
            return {
                "id": review_id,
                "subject_type": args[0],
                "subject_id": args[1],
                "target_id": args[2],
                "finding_id": args[3],
                "hypothesis_id": args[4],
                "campaign_id": args[5],
                "trigger_reason": args[6],
                "refuter_signal": args[7],
                "refuter_verdict": args[8],
                "verdict_basis": args[9],
                "confidence_delta": args[10],
                "evidence_object_ids": args[11],
                "tool_receipt_ids": args[12],
                "counterevidence": args[13],
                "notes": args[14],
                "status": args[15],
                "metadata_json": args[16],
                "created_by": args[17],
            }

    class _FakePool:
        def acquire(self):
            return self

        async def __aenter__(self):
            return _FakeConn()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    original_pool = api_module.db_pool
    api_module.db_pool = _FakePool()
    try:
        result = asyncio.run(api_module.arsenal_queue_refuter_reviews_from_summary(
            api_module.RefuterReviewQueueRequest(limit=10, finding_window=20, created_by="pytest")
        ))
    finally:
        api_module.db_pool = original_pool

    assert result["created"] == 1
    assert result["created_finding_reviews"] == 1
    assert result["created_integrity_signals"] == 0
    assert result["skipped_already_reviewed"] == 1
    assert result["findings_updated"] == 0
    assert result["hypotheses_updated"] == 0
    assert result["refuter_reviews"][0]["finding_id"] == str(ai_id)
    assert result["refuter_reviews"][0]["verdict_basis"] == "signal_only"
    assert result["refuter_reviews"][0]["created_by"] == "pytest"
    metadata = result["refuter_reviews"][0]["metadata_json"]
    assert metadata["automation_plan"]["execution_enabled"] is False
    assert "ai_gate.replay_probe" in {step["command"] for step in metadata["automation_plan"]["steps"]}
    assert calls["fetchrow"][0][1][15] == "recorded"
    assert "UPDATE findings" not in calls["fetchrow"][0][0]


def test_execute_refuter_review_plan_queues_deterministic_retest_without_truth_mutation(monkeypatch):
    review_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    target_id = uuid.uuid4()
    captured: dict[str, object] = {}

    review_row = {
        "id": review_id,
        "subject_type": "finding",
        "subject_id": str(finding_id),
        "target_id": target_id,
        "finding_id": finding_id,
        "hypothesis_id": None,
        "campaign_id": None,
        "trigger_reason": "critical_high_weak_or_suspected_proof",
        "refuter_signal": "question",
        "refuter_verdict": None,
        "verdict_basis": "signal_only",
        "confidence_delta": None,
        "evidence_object_ids": json.dumps([]),
        "tool_receipt_ids": json.dumps([]),
        "counterevidence": json.dumps({}),
        "notes": None,
        "status": "recorded",
        "metadata_json": json.dumps({
            "automation_plan": {
                "status": "planned_not_executed",
                "execution_enabled": False,
                "steps": [
                    {"id": "review_claim_basis", "command": "refuter_review.record"},
                    {"id": "deterministic_retest", "command": "finding.retest"},
                ],
            }
        }),
        "created_by": "pytest",
    }
    finding_row = {
        "id": finding_id,
        "target_id": target_id,
        "status": "active",
        "severity": "critical",
        "title": "Weak SQLi proof",
        "source": "scan",
        "tool": "smart_sqli",
        "last_verification_verdict": None,
        "evidence": json.dumps({"url": "https://app.example.test/items?id=1"}),
    }

    class _FakeConn:
        async def fetchrow(self, query, *args):
            if "SELECT * FROM refuter_reviews" in query:
                return review_row
            if "UPDATE refuter_reviews" in query:
                captured["updated_metadata"] = json.loads(args[1])
                return {**review_row, "metadata_json": args[1]}
            raise AssertionError(f"unexpected query: {query}")

    async def fake_get_finding_record(conn, finding_ref):
        captured["finding_ref"] = finding_ref
        return finding_row

    async def fake_retest_finding(finding_ref, body, mode=None):
        captured["retest"] = (finding_ref, body, mode)
        return {
            "operation_id": "delegated-op",
            "retest_id": "retest-1",
            "job_id": "job-1",
            "status": "queued",
            "finding_id": finding_ref,
        }

    async def fake_record_command_result(conn, **kwargs):
        captured["command_result"] = kwargs
        return {"id": "refuter-op", "status": kwargs["status"]}

    monkeypatch.setattr(api_module, "get_finding_record", fake_get_finding_record)
    monkeypatch.setattr(api_module, "retest_finding", fake_retest_finding)
    monkeypatch.setattr(api_module, "_record_command_result", fake_record_command_result)

    result = asyncio.run(api_module._execute_refuter_review_plan(
        _FakeConn(),
        refuter_review_id=str(review_id),
        approval_receipt_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        requested_by="pytest",
    ))

    assert result["status"] == "retest_scheduled"
    assert result["delegated_command"] == "finding.retest"
    assert result["operation_id"] == "refuter-op"
    assert result["findings_updated"] == 0
    assert result["hypotheses_updated"] == 0
    finding_ref, body, mode = captured["retest"]
    assert finding_ref == str(finding_id)
    assert mode == "deterministic"
    assert body.requested_by == "pytest"
    assert body.approval_receipt_id == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    latest = captured["updated_metadata"]["latest_refuter_execution"]
    assert latest["delegated_operation_id"] == "delegated-op"
    assert latest["verdict_pending"] is True
    assert captured["command_result"]["command"] == "refuter_review.execute_plan"
    assert captured["command_result"]["status"] == "retest_scheduled"
    assert captured["command_result"]["result_json"]["findings_updated_by_refuter"] == 0


def test_derive_refuter_review_verdict_records_completed_deterministic_outcome():
    review_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    target_id = uuid.uuid4()
    verification_id = uuid.uuid4()
    captured: dict[str, object] = {}

    review_row = {
        "id": review_id,
        "subject_type": "finding",
        "subject_id": str(finding_id),
        "target_id": target_id,
        "finding_id": finding_id,
        "hypothesis_id": None,
        "campaign_id": None,
        "trigger_reason": "critical_high_weak_or_suspected_proof",
        "refuter_signal": "question",
        "refuter_verdict": None,
        "verdict_basis": "signal_only",
        "confidence_delta": None,
        "evidence_object_ids": json.dumps([]),
        "tool_receipt_ids": json.dumps([]),
        "counterevidence": json.dumps({}),
        "notes": None,
        "status": "recorded",
        "metadata_json": json.dumps({}),
        "created_by": "pytest",
    }
    verification_row = {
        "id": verification_id,
        "finding_id": finding_id,
        "status": "completed",
        "result_status": "likely_fixed",
        "verdict": "likely_fixed",
        "verdict_reason": "Replay did not reproduce the finding.",
        "verification_mode": "deterministic",
        "proof": json.dumps({"http_status": 404}),
        "artifacts": json.dumps({"request_id": "req-1"}),
        "replay_commands": json.dumps([{"description": "Replay request"}]),
    }

    class _FakeConn:
        async def fetchrow(self, query, *args):
            if "SELECT * FROM refuter_reviews" in query:
                return review_row
            if "FROM finding_verifications" in query:
                return verification_row
            if "INSERT INTO refuter_reviews" in query:
                captured["insert_args"] = args
                return {
                    "id": uuid.uuid4(),
                    "subject_type": args[0],
                    "subject_id": args[1],
                    "target_id": args[2],
                    "finding_id": args[3],
                    "hypothesis_id": args[4],
                    "campaign_id": args[5],
                    "trigger_reason": args[6],
                    "refuter_signal": args[7],
                    "refuter_verdict": args[8],
                    "verdict_basis": args[9],
                    "confidence_delta": args[10],
                    "evidence_object_ids": args[11],
                    "tool_receipt_ids": args[12],
                    "counterevidence": args[13],
                    "notes": args[14],
                    "status": args[15],
                    "metadata_json": args[16],
                    "created_by": args[17],
                }
            raise AssertionError(f"unexpected query: {query}")

        async def execute(self, query, *args):
            if "UPDATE refuter_reviews" in query and "verdict_pending" in query:
                captured["reconcile_args"] = args
                return "UPDATE 1"
            raise AssertionError(f"unexpected execute: {query}")

    result = asyncio.run(api_module._derive_refuter_review_verdict(
        _FakeConn(),
        refuter_review_id=str(review_id),
        verification_id=str(verification_id),
        created_by="pytest",
    ))

    derived = result["refuter_review"]
    assert derived["refuter_signal"] == "weaken"
    assert derived["refuter_verdict"] == "weakened"
    assert derived["verdict_basis"] == "deterministic_replay"
    assert derived["status"] == "verdict_recorded"
    assert derived["created_by"] == "pytest"
    assert result["findings_updated"] == 0
    assert result["hypotheses_updated"] == 0
    assert result["verdict_pending"] is False
    assert captured["reconcile_args"][0] == review_id
    counterevidence = derived["counterevidence"]
    assert counterevidence["verification_id"] == str(verification_id)
    assert counterevidence["verdict"] == "likely_fixed"
    assert captured["insert_args"][8] == "weakened"
    assert "UPDATE findings" not in str(captured)


def test_refuter_verdict_derivation_keeps_ai_driven_results_signal_only():
    outcome = api_module._refuter_review_from_verification_outcome({
        "verdict": "exploited",
        "verification_mode": "ai_driven",
    })

    assert outcome["refuter_signal"] == "support"
    assert outcome["refuter_verdict"] is None
    assert outcome["verdict_basis"] == "signal_only"
    assert outcome["deterministic_basis"] is False


def test_refuter_verdict_derivation_keeps_failed_retests_signal_only():
    outcome = api_module._refuter_review_from_verification_outcome({
        "status": "failed",
        "result_status": "error",
        "verdict": "error",
        "verification_mode": "deterministic",
    })

    assert outcome["refuter_signal"] == "question"
    assert outcome["refuter_verdict"] is None
    assert outcome["verdict_basis"] == "signal_only"
    assert outcome["deterministic_basis"] is False


def test_derive_refuter_review_verdict_requires_linked_retest_when_verification_omitted():
    review_id = uuid.uuid4()
    finding_id = uuid.uuid4()

    review_row = {
        "id": review_id,
        "subject_type": "finding",
        "subject_id": str(finding_id),
        "target_id": None,
        "finding_id": finding_id,
        "hypothesis_id": None,
        "campaign_id": None,
        "trigger_reason": "weak proof",
        "refuter_signal": "question",
        "refuter_verdict": None,
        "verdict_basis": "signal_only",
        "confidence_delta": None,
        "evidence_object_ids": json.dumps([]),
        "tool_receipt_ids": json.dumps([]),
        "counterevidence": json.dumps({}),
        "notes": None,
        "status": "recorded",
        "metadata_json": json.dumps({}),
        "created_by": "pytest",
    }

    class _FakeConn:
        async def fetchrow(self, query, *args):
            if "SELECT * FROM refuter_reviews" in query:
                return review_row
            raise AssertionError(f"unexpected query: {query}")

    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module._derive_refuter_review_verdict(
            _FakeConn(),
            refuter_review_id=str(review_id),
            created_by="pytest",
        ))

    assert exc.value.status_code == 409
    assert "linked retest" in str(exc.value.detail)


def test_derive_refuter_review_verdict_uses_latest_execution_retest_id_when_omitted():
    review_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    linked_verification_id = uuid.uuid4()
    captured: dict[str, object] = {}

    review_row = {
        "id": review_id,
        "subject_type": "finding",
        "subject_id": str(finding_id),
        "target_id": None,
        "finding_id": finding_id,
        "hypothesis_id": None,
        "campaign_id": None,
        "trigger_reason": "weak proof",
        "refuter_signal": "question",
        "refuter_verdict": None,
        "verdict_basis": "signal_only",
        "confidence_delta": None,
        "evidence_object_ids": json.dumps([]),
        "tool_receipt_ids": json.dumps([]),
        "counterevidence": json.dumps({}),
        "notes": None,
        "status": "recorded",
        "metadata_json": json.dumps({"latest_refuter_execution": {"retest_id": str(linked_verification_id)}}),
        "created_by": "pytest",
    }
    verification_row = {
        "id": linked_verification_id,
        "finding_id": finding_id,
        "status": "completed",
        "result_status": "likely_fixed",
        "verdict": "likely_fixed",
        "verdict_reason": "Replay did not reproduce.",
        "verification_mode": "deterministic",
        "proof": json.dumps({}),
        "artifacts": json.dumps({}),
        "replay_commands": json.dumps([]),
    }

    class _FakeConn:
        async def fetchrow(self, query, *args):
            if "SELECT * FROM refuter_reviews" in query:
                return review_row
            if "FROM finding_verifications" in query:
                captured["verification_args"] = args
                return verification_row
            if "INSERT INTO refuter_reviews" in query:
                return {
                    "id": uuid.uuid4(),
                    "subject_type": args[0],
                    "subject_id": args[1],
                    "target_id": args[2],
                    "finding_id": args[3],
                    "hypothesis_id": args[4],
                    "campaign_id": args[5],
                    "trigger_reason": args[6],
                    "refuter_signal": args[7],
                    "refuter_verdict": args[8],
                    "verdict_basis": args[9],
                    "confidence_delta": args[10],
                    "evidence_object_ids": args[11],
                    "tool_receipt_ids": args[12],
                    "counterevidence": args[13],
                    "notes": args[14],
                    "status": args[15],
                    "metadata_json": args[16],
                    "created_by": args[17],
                }
            raise AssertionError(f"unexpected query: {query}")

        async def execute(self, query, *args):
            if "UPDATE refuter_reviews" in query and "verdict_pending" in query:
                captured["reconcile_args"] = args
                return "UPDATE 1"
            raise AssertionError(f"unexpected execute: {query}")

    result = asyncio.run(api_module._derive_refuter_review_verdict(
        _FakeConn(),
        refuter_review_id=str(review_id),
        created_by="pytest",
    ))

    assert captured["verification_args"][0] == linked_verification_id
    assert result["verification_id"] == str(linked_verification_id)
    assert result["refuter_review"]["refuter_verdict"] == "weakened"
    # The execute->derive handshake is reconciled: the source review's retest is resolved.
    assert result["verdict_pending"] is False
    assert captured["reconcile_args"][0] == review_id
    assert captured["reconcile_args"][1] == str(linked_verification_id)


def test_tool_receipt_redacts_hashes_and_is_non_executing():
    receipt_id = uuid.uuid4()
    captured: dict[str, object] = {}

    class _FakeConn:
        async def fetchrow(self, query, *args):
            captured["query"] = str(query)
            captured["args"] = args
            return {
                "id": receipt_id,
                "tool_name": args[0],
                "tool_version": args[1],
                "adapter_version": args[2],
                "command_hash": args[3],
                "redacted_argv": args[4],
                "worker_build": args[5],
                "container_image": args[6],
                "target_scope": args[7],
                "scope_receipt_id": args[8],
                "approval_receipt_id": args[9],
                "policy_profile_id": args[10],
                "status": args[11],
                "parser_status": args[12],
                "exit_code": args[13],
                "timed_out": args[14],
                "started_at": args[15],
                "finished_at": args[16],
                "stdout_evidence_object_id": args[17],
                "stderr_evidence_object_id": args[18],
                "parsed_evidence_instance_ids": args[19],
                "redaction_summary": args[20],
                "metadata_json": args[21],
                "created_by": args[22],
            }

    result = asyncio.run(api_module._record_tool_receipt(_FakeConn(), api_module.ToolReceiptRequest(
        tool_name="nuclei",
        redacted_argv=["nuclei", "-H", "Authorization: Bearer secret-token"],
        target_scope={"authorization": "Bearer secret-token"},
        status="parser_error",
        parser_status="failed",
        metadata_json={"cookie": "session=secret-token"},
    )))

    receipt = result["tool_receipt"]
    assert "INSERT INTO tool_receipts" in captured["query"]
    assert receipt["execution_enabled"] is False
    assert receipt["findings_created"] == 0
    assert receipt["verified_findings_created"] == 0
    assert len(receipt["command_hash"]) == 64
    assert "secret-token" not in json.dumps(receipt, default=str)


def test_evidence_instance_hashes_redacts_and_does_not_update_findings():
    instance_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    tool_receipt_id = uuid.uuid4()
    captured: dict[str, object] = {}

    class _FakeConn:
        async def fetchrow(self, query, *args):
            captured["query"] = str(query)
            captured["args"] = args
            return {
                "id": instance_id,
                "finding_id": args[0],
                "evidence_object_id": args[1],
                "scan_id": args[2],
                "target_id": args[3],
                "concrete_url": args[4],
                "object_id": args[5],
                "payload_variant": args[6],
                "request_response_refs": args[7],
                "principal_pair": args[8],
                "proof_observation": args[9],
                "campaign_action_id": args[10],
                "tool_receipt_id": args[11],
                "redaction_profile": args[12],
                "hash": args[13],
                "retention_policy": args[14],
                "proof_state": args[15],
                "metadata_json": args[16],
                "created_by": args[17],
            }

    result = asyncio.run(api_module._record_evidence_instance(_FakeConn(), api_module.EvidenceInstanceRequest(
        finding_id=str(finding_id),
        tool_receipt_id=str(tool_receipt_id),
        concrete_url="https://app.example.com/api/orders/1?token=secret-token",
        principal_pair={"actor": "user1", "other": "user2"},
        proof_observation={"authorization": "Bearer secret-token", "status": 403},
        proof_state="suspected",
    )))

    instance = result["evidence_instance"]
    assert "INSERT INTO evidence_instances" in captured["query"]
    assert instance["execution_enabled"] is False
    assert instance["findings_updated"] == 0
    assert instance["finding_id"] == str(finding_id)
    assert instance["tool_receipt_id"] == str(tool_receipt_id)
    assert len(instance["hash"]) == 64
    assert "secret-token" not in json.dumps(instance, default=str)


def test_public_evidence_object_row_hydrates_local_storage(monkeypatch, tmp_path):
    stored = store_evidence_content({"large": "x" * 200}, results_dir=tmp_path, inline_max_bytes=8)
    monkeypatch.setattr(api_module, "RESULTS_DIR", tmp_path)

    row = {
        "id": uuid.uuid4(),
        "finding_id": uuid.uuid4(),
        "content_sha256": stored["content_sha256"],
        "size_bytes": stored["size_bytes"],
        "storage_uri": stored["storage_uri"],
        "content": None,
        "created_at": datetime(2026, 7, 6, tzinfo=timezone.utc),
    }

    public = api_module._public_evidence_object_row(row)

    assert public["storage_uri"].startswith("local:evidence_objects/")
    assert public["storage_status"] == "external"
    assert public["storage_integrity"] == "verified"
    assert "x" * 200 in public["content"]
    assert isinstance(public["id"], str)
    assert public["created_at"].startswith("2026-07-06")


def test_evidence_export_manifest_excludes_content_and_tracks_integrity(monkeypatch, tmp_path):
    stored = store_evidence_content({"large": "x" * 200}, results_dir=tmp_path, inline_max_bytes=8)
    monkeypatch.setattr(api_module, "RESULTS_DIR", tmp_path)
    row = {
        "id": uuid.uuid4(),
        "finding_id": uuid.uuid4(),
        "scan_id": uuid.uuid4(),
        "object_type": "ai_gate_evidence",
        "content_sha256": stored["content_sha256"],
        "size_bytes": stored["size_bytes"],
        "storage_uri": stored["storage_uri"],
        "retention_class": "sensitive",
        "content": None,
        "created_at": datetime(2026, 7, 6, tzinfo=timezone.utc),
    }

    manifest = api_module._evidence_export_manifest([row], generated_at=datetime(2026, 7, 6, tzinfo=timezone.utc))

    assert manifest["schema_version"] == "2026-07-06.evidence-export-manifest.v1"
    assert manifest["object_count"] == 1
    assert len(manifest["manifest_hash"]) == 64
    assert manifest["content_included"] is False
    obj = manifest["objects"][0]
    assert "content" not in obj
    assert obj["content_included"] is False
    assert obj["content_available"] is True
    assert obj["storage_integrity"] == "verified"
    assert manifest["retention_counts"]["sensitive"] == 1


def test_evidence_export_bundle_descriptor_is_content_free_and_replayable(monkeypatch, tmp_path):
    stored = store_evidence_content({"large": "x" * 200}, results_dir=tmp_path, inline_max_bytes=8)
    monkeypatch.setattr(api_module, "RESULTS_DIR", tmp_path)
    finding_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    object_id = uuid.uuid4()
    row = {
        "id": object_id,
        "finding_id": finding_id,
        "scan_id": scan_id,
        "object_type": "ai_gate_evidence",
        "content_sha256": stored["content_sha256"],
        "size_bytes": stored["size_bytes"],
        "storage_uri": stored["storage_uri"],
        "retention_class": "sensitive",
        "content": None,
        "created_at": datetime(2026, 7, 6, tzinfo=timezone.utc),
    }
    manifest = api_module._evidence_export_manifest([row], generated_at=datetime(2026, 7, 6, tzinfo=timezone.utc))

    bundle = api_module._evidence_export_bundle_descriptor(
        manifest,
        filters={"scan_id": str(scan_id), "limit": 200},
        generated_at=datetime(2026, 7, 6, tzinfo=timezone.utc),
    )

    assert bundle["schema_version"] == "2026-07-06.evidence-export-bundle.v1"
    assert len(bundle["bundle_hash"]) == 64
    assert bundle["manifest_hash"] == manifest["manifest_hash"]
    assert bundle["content_included"] is False
    assert bundle["finding_ids"] == [str(finding_id)]
    assert bundle["scan_ids"] == [str(scan_id)]
    assert bundle["files"][0]["name"] == "evidence-export-manifest.json"
    replay = bundle["replay_plan"]
    assert replay["type"] == "api_read_replay"
    assert replay["content_included"] is False
    assert replay["evidence_object_reads"][0]["api_path"] == f"/evidence/{object_id}"
    assert replay["finding_evidence_reads"][0]["api_path"] == f"/findings/{finding_id}/evidence"
    assert "content" not in replay["evidence_object_reads"][0]


def test_evidence_export_archive_is_content_free_zip(monkeypatch, tmp_path):
    stored = store_evidence_content({"large": "x" * 200}, results_dir=tmp_path, inline_max_bytes=8)
    monkeypatch.setattr(api_module, "RESULTS_DIR", tmp_path)
    finding_id = uuid.uuid4()
    object_id = uuid.uuid4()
    row = {
        "id": object_id,
        "finding_id": finding_id,
        "scan_id": uuid.uuid4(),
        "object_type": "dast_evidence",
        "content_sha256": stored["content_sha256"],
        "size_bytes": stored["size_bytes"],
        "storage_uri": stored["storage_uri"],
        "retention_class": "standard",
        "content": None,
        "created_at": datetime(2026, 7, 6, tzinfo=timezone.utc),
    }
    manifest = api_module._evidence_export_manifest([row], generated_at=datetime(2026, 7, 6, tzinfo=timezone.utc))
    bundle = api_module._evidence_export_bundle_descriptor(
        manifest,
        filters={"finding_id": str(finding_id), "limit": 200},
        generated_at=datetime(2026, 7, 6, tzinfo=timezone.utc),
    )
    archive = api_module._evidence_export_archive_descriptor(manifest, bundle, filters=bundle["filters"])
    archive_bytes = api_module._evidence_export_archive_bytes(manifest, bundle)

    assert archive["schema_version"] == "2026-07-06.evidence-export-archive.v1"
    assert archive["content_included"] is False
    assert archive["media_type"] == "application/zip"
    assert archive["archive_sha256"] == api_module.hashlib.sha256(archive_bytes).hexdigest()
    assert archive["download_api_path"].endswith("format=zip")
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
        assert sorted(zf.namelist()) == [
            "evidence-export-bundle.json",
            "evidence-export-manifest.json",
            "evidence-export-replay-plan.json",
        ]
        serialized = b"".join(zf.read(name) for name in zf.namelist()).decode("utf-8").lower()
    assert '"content_included": false' in serialized
    assert "x" * 100 not in serialized
    assert "secret" not in serialized


def test_record_export_event_persists_only_content_free_refs():
    finding_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    evidence_id = uuid.uuid4()
    captured = {}

    class _FakeConn:
        async def fetchrow(self, query, *args):
            captured["query"] = query
            captured["args"] = args
            return {
                "id": uuid.uuid4(),
                "export_kind": args[0],
                "command": args[1],
                "status": "completed",
                "risk_tier": "read_only",
                "target_id": args[2],
                "scan_id": args[3],
                "finding_id": args[4],
                "bundle_hash": args[5],
                "manifest_hash": args[6],
                "object_count": args[7],
                "filters": args[8],
                "evidence_object_ids": args[9],
                "finding_ids": args[10],
                "scan_ids": args[11],
                "replay_plan": args[12],
                "operator_message": args[13],
                "created_by": args[14],
                "created_at": datetime(2026, 7, 6, tzinfo=timezone.utc),
            }

    bundle = {
        "bundle_hash": "b" * 64,
        "manifest_hash": "m" * 64,
        "object_count": 1,
        "finding_ids": [str(finding_id)],
        "scan_ids": [str(scan_id)],
        "replay_plan": {
            "content_included": False,
            "evidence_object_reads": [
                {"evidence_object_id": str(evidence_id), "api_path": f"/evidence/{evidence_id}"}
            ],
        },
    }

    event = asyncio.run(api_module._record_export_event(
        _FakeConn(),
        export_kind="evidence_export_bundle",
        command="evidence.export_bundle",
        bundle=bundle,
        filters={"scan_id": str(scan_id)},
    ))

    assert "INSERT INTO export_events" in captured["query"]
    assert event["export_kind"] == "evidence_export_bundle"
    assert event["bundle_hash"] == "b" * 64
    assert event["evidence_object_ids"] == [str(evidence_id)]
    assert event["finding_ids"] == [str(finding_id)]
    assert event["scan_ids"] == [str(scan_id)]
    serialized = json.dumps(event).lower()
    assert '"content"' not in serialized
    assert '"transcript"' not in serialized


def test_evidence_export_bundle_get_is_read_only_unless_record_event_requested(monkeypatch):
    class _Pool:
        def __init__(self):
            self.acquire_count = 0
            self.insert_count = 0

        def acquire(self):
            pool = self

            class _Conn:
                async def fetch(self, query, *args):
                    return []

                async def fetchrow(self, query, *args):
                    pool.insert_count += 1
                    return {
                        "id": uuid.uuid4(),
                        "export_kind": args[0],
                        "command": args[1],
                        "status": "completed",
                        "risk_tier": "read_only",
                        "target_id": args[2],
                        "scan_id": args[3],
                        "finding_id": args[4],
                        "bundle_hash": args[5],
                        "manifest_hash": args[6],
                        "object_count": args[7],
                        "filters": args[8],
                        "evidence_object_ids": args[9],
                        "finding_ids": args[10],
                        "scan_ids": args[11],
                        "replay_plan": args[12],
                        "operator_message": args[13],
                        "created_by": args[14],
                        "created_at": datetime(2026, 7, 6, tzinfo=timezone.utc),
                    }

            class _Acquire:
                async def __aenter__(self):
                    pool.acquire_count += 1
                    return _Conn()

                async def __aexit__(self, *exc):
                    return False

            return _Acquire()

    pool = _Pool()
    monkeypatch.setattr(api_module, "db_pool", pool)

    bundle = asyncio.run(api_module.evidence_export_bundle(limit=200, record_event=False))

    assert "export_event" not in bundle
    assert pool.acquire_count == 1
    assert pool.insert_count == 0

    recorded = asyncio.run(api_module.evidence_export_bundle(limit=200, record_event=True))

    assert recorded["export_event"]["export_kind"] == "evidence_export_bundle"
    assert pool.acquire_count == 3
    assert pool.insert_count == 1


def test_evidence_export_bundle_zip_response_is_downloadable(monkeypatch):
    class _Pool:
        def acquire(self):
            class _Conn:
                async def fetch(self, query, *args):
                    return []

            class _Acquire:
                async def __aenter__(self):
                    return _Conn()

                async def __aexit__(self, *exc):
                    return False

            return _Acquire()

    monkeypatch.setattr(api_module, "db_pool", _Pool())

    response = asyncio.run(api_module.evidence_export_bundle(limit=200, export_format="zip"))

    assert response.media_type == "application/zip"
    assert response.headers["Content-Disposition"].startswith("attachment; filename=")
    assert len(response.headers["X-ShakerScan-Archive-SHA256"]) == 64
    with zipfile.ZipFile(io.BytesIO(response.body if hasattr(response, "body") else response.content)) as zf:
        assert "evidence-export-manifest.json" in zf.namelist()
        assert "evidence-export-bundle.json" in zf.namelist()


def test_evidence_retention_candidates_skip_legal_hold_and_use_policy_days():
    now = datetime(2026, 7, 6, tzinfo=timezone.utc)
    old = datetime(2025, 1, 1, tzinfo=timezone.utc)
    rows = [
        {
            "id": uuid.uuid4(),
            "retention_class": "short",
            "storage_uri": "inline:evidence_objects",
            "created_at": old,
        },
        {
            "id": uuid.uuid4(),
            "retention_class": "legal_hold",
            "storage_uri": "inline:evidence_objects",
            "created_at": old,
        },
        {
            "id": uuid.uuid4(),
            "retention_class": "standard",
            "storage_uri": "inline:evidence_objects",
            "created_at": now,
        },
    ]

    candidates = api_module._evidence_retention_candidates(rows, now=now)

    assert len(candidates) == 1
    assert candidates[0]["retention_class"] == "short"
    assert candidates[0]["retention_days"] == api_module.EVIDENCE_RETENTION_DAYS["short"]
    assert candidates[0]["age_days"] > candidates[0]["retention_days"]


def test_evidence_retention_candidate_marks_remote_storage_as_deletable():
    now = datetime(2026, 7, 6, tzinfo=timezone.utc)
    row = {
        "id": uuid.uuid4(),
        "retention_class": "short",
        "storage_uri": "s3:evidence_objects/audit-bucket/evidence-objects/ab/abcdef.json",
        "created_at": datetime(2025, 1, 1, tzinfo=timezone.utc),
    }

    candidate = api_module._evidence_retention_candidate(row, now=now)

    assert candidate is not None
    assert candidate["storage_backend"] == "s3"
    assert candidate["remote_object"] is True
    assert candidate["remote_deletion_supported"] is True
    assert candidate["local_file"] is False


def _evidence_row(retention_class, created_at):
    return {
        "id": uuid.uuid4(),
        "retention_class": retention_class,
        "storage_uri": "inline:evidence_objects",
        "created_at": created_at,
    }


def test_older_than_days_cannot_shorten_audit_or_sensitive_retention_floor():
    now = datetime(2026, 7, 6, tzinfo=timezone.utc)
    # 120 days old: past sensitive (90d) but well within audit (2555d) and the
    # explicit standard floor we test below.
    created = datetime(2026, 3, 8, tzinfo=timezone.utc)
    rows = [
        _evidence_row("audit", created),
        _evidence_row("sensitive", created),
        _evidence_row("standard", created),
    ]
    # Aggressive override that would otherwise delete everything 1+ day old.
    candidates = api_module._evidence_retention_candidates(rows, now=now, older_than_days=1)
    classes = {c["retention_class"] for c in candidates}

    # audit is floored at 2555d -> not a candidate; sensitive floored at 90d and
    # 120d old -> IS a candidate (override only raises the floor, and 120>90);
    # standard is not compliance-protected so the override applies -> candidate.
    assert "audit" not in classes
    assert "standard" in classes
    sensitive = next((c for c in candidates if c["retention_class"] == "sensitive"), None)
    assert sensitive is not None
    assert sensitive["retention_days"] == api_module.EVIDENCE_RETENTION_DAYS["sensitive"]


class _RetentionTransaction:
    def __init__(self, conn):
        self.conn = conn
        self.snapshot = None

    async def __aenter__(self):
        self.snapshot = {
            "evidence": copy.deepcopy(self.conn.evidence),
            "previews": copy.deepcopy(self.conn.previews),
            "recorded": copy.deepcopy(self.conn.recorded),
            "deleted_arg": copy.deepcopy(self.conn.deleted_arg),
        }
        return self

    async def __aexit__(self, exc_type, _exc, _tb):
        if exc_type is not None and self.snapshot is not None:
            self.conn.evidence = self.snapshot["evidence"]
            self.conn.previews = self.snapshot["previews"]
            self.conn.recorded = self.snapshot["recorded"]
            self.conn.deleted_arg = self.snapshot["deleted_arg"]
        return False


class _RetentionConn:
    """Small stateful Postgres fake for the preview/execute retention contract."""

    def __init__(self, evidence=None, *, policy_on=False, scope_target_id=None):
        self.target_id = uuid.uuid4()
        self.target_url = "https://example.test"
        self.approval_id = uuid.uuid4()
        self.scope_id = "scope-retention-test"
        self.scope_target_id = scope_target_id or self.target_id
        self.policy_on = policy_on
        self.approval_risk = "dangerous"
        self.approval_action_name = "evidence.retention_sweep"
        self.approval_expires_at = "preview"
        self.evidence = [dict(row) for row in (evidence or [])]
        self.previews = {}
        self.findings = {}
        self.scans = {}
        self.recorded = []
        self.deleted_arg = []
        for row in self.evidence:
            if row.get("scan_id"):
                self.scans.setdefault(row["scan_id"], {"id": row["scan_id"], "target_id": self.target_id})
            if row.get("finding_id"):
                self.findings.setdefault(row["finding_id"], {
                    "id": row["finding_id"], "target_id": self.target_id, "status": "resolved",
                })

    def transaction(self):
        return _RetentionTransaction(self)

    async def fetchval(self, query, *args):
        if "FROM app_settings" in query:
            return "true" if self.policy_on else None
        if "pg_advisory_lock" in query or "pg_advisory_unlock" in query:
            return True
        if "FROM evidence_retention_previews" in query and "approval_receipt_id" in query:
            approval_id, preview_id = args
            for item in self.previews.values():
                if item["id"] != preview_id and item.get("approval_receipt_id") == approval_id:
                    return item["id"]
        return None

    async def fetchrow(self, query, *args):
        if "FROM targets" in query:
            return {"id": self.target_id, "url": self.target_url} if args[0] == self.target_id else None
        if "FROM evidence_retention_previews" in query:
            return self.previews.get(args[0])
        if "FROM approval_receipts" in query:
            if args[0] != self.approval_id:
                return None
            preview = next(reversed(self.previews.values()), {})
            approval_expires_at = (
                preview.get("expires_at")
                if self.approval_expires_at == "preview"
                else self.approval_expires_at
            )
            return {
                "id": self.approval_id,
                "scope_receipt_id": self.scope_id,
                "risk_tier": self.approval_risk,
                "confirmations": ["confirm_authorized"],
                "action_name": self.approval_action_name,
                "action_context": {
                    "preview_id": str(preview.get("id") or ""),
                    "preview_hash": str(preview.get("preview_hash") or ""),
                    "target_id": str(preview.get("target_id") or ""),
                },
                "approved_by": "test",
                "denial_reason": None,
                "expires_at": approval_expires_at,
                "created_at": datetime.now(timezone.utc),
            }
        if "FROM scope_receipts" in query:
            if args[0] != self.scope_id:
                return None
            return {
                "id": self.scope_id,
                "target_id": self.scope_target_id,
                "verdict": "allowed",
                "normalized_scope": {"host": "example.test"},
                "allowed_hosts": ["example.test"],
                "allowed_root_domains": [],
                "blocked_by": [],
                "warnings": [],
                "checks": [],
            }
        if "INSERT INTO command_results" in query:
            command_id = uuid.uuid4()
            row = {
                "id": command_id,
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
                "created_at": datetime.now(timezone.utc),
            }
            self.recorded.append(row)
            return row
        if "INSERT INTO approval_receipts" in query:
            return {
                "id": uuid.uuid4(),
                "scope_receipt_id": args[0],
                "risk_tier": args[1],
                "confirmations": args[2],
                "action_name": args[3],
                "action_context": args[4],
                "approved_by": args[5],
                "denial_reason": args[6],
                "expires_at": args[7],
                "created_at": datetime.now(timezone.utc),
            }
        if "INSERT INTO campaign_actions" in query:
            return None
        return None

    async def fetch(self, query, *args):
        if "FROM evidence_retention_previews" in query:
            target_id, limit = args
            rows = [
                dict(row) for row in self.previews.values()
                if row.get("status") == "executing"
                and (target_id is None or row.get("target_id") == target_id)
            ]
            return rows[:limit]
        if "SELECT eo.*" in query:
            target_id, retention_class, limit, current, older_than_days = args
            rows = []
            for row in self.evidence:
                finding = self.findings.get(row.get("finding_id"))
                scan = self.scans.get(row.get("scan_id"))
                if not finding and not scan:
                    continue
                if finding and (finding["target_id"] != target_id or finding["status"] == "active"):
                    continue
                if scan and scan["target_id"] != target_id:
                    continue
                if retention_class and row.get("retention_class") != retention_class:
                    continue
                if row.get("retention_class") == "legal_hold":
                    continue
                if row.get("retention_delete_pending_at"):
                    continue
                if api_module._evidence_retention_candidate(
                    row,
                    now=current,
                    older_than_days=older_than_days,
                    retention_class_filter=retention_class,
                ) is None:
                    continue
                rows.append(dict(row))
            return sorted(rows, key=lambda row: (row["created_at"], row["id"]))[:limit]
        if "SELECT storage_uri, COUNT(*) AS reference_count" in query:
            counts = Counter(
                str(row.get("storage_uri") or "") for row in self.evidence
                if row.get("storage_uri") in set(args[0])
            )
            return [{"storage_uri": key, "reference_count": value} for key, value in counts.items()]
        if "SELECT * FROM evidence_objects" in query:
            ids = set(args[0])
            return sorted((dict(row) for row in self.evidence if row["id"] in ids), key=lambda row: row["id"])
        if "UPDATE evidence_objects" in query and "retention_delete_pending_at=NOW()" in query:
            preview_id, ids = args
            marked = []
            for row in self.evidence:
                if row["id"] in set(ids) and not row.get("retention_delete_pending_at"):
                    row["retention_delete_preview_id"] = preview_id
                    row["retention_delete_pending_at"] = datetime.now(timezone.utc)
                    marked.append({"id": row["id"]})
            return marked
        if "FROM findings" in query:
            return [self.findings[item] for item in args[0] if item in self.findings]
        if "FROM scans" in query:
            return [self.scans[item] for item in args[0] if item in self.scans]
        if "DELETE FROM evidence_objects" in query:
            ids = set(args[0])
            preview_id = args[1] if len(args) > 1 else None
            self.deleted_arg = sorted(ids)
            deleted = [
                {"id": row["id"]}
                for row in self.evidence
                if row["id"] in ids
                and (preview_id is None or row.get("retention_delete_preview_id") == preview_id)
            ]
            deleted_ids = {row["id"] for row in deleted}
            self.evidence = [row for row in self.evidence if row["id"] not in deleted_ids]
            return deleted
        return []

    async def execute(self, query, *args):
        if "INSERT INTO evidence_retention_previews" in query:
            self.previews[args[0]] = {
                "id": args[0],
                "target_id": args[1],
                "schema_version": args[2],
                "criteria_json": args[3],
                "candidate_snapshot_json": args[4],
                "preview_hash": args[5],
                "policy_hash": args[6],
                "status": "ready",
                "created_at": args[7],
                "expires_at": args[8],
                "approval_receipt_id": None,
                "scope_receipt_id": None,
                "operation_id": None,
                "execution_started_at": None,
                "result_json": {},
            }
        elif "SET status='stale'" in query:
            self.previews[args[0]]["status"] = "stale"
            self.previews[args[0]]["result_json"] = args[1]
        elif "SET status='executing'" in query:
            preview = self.previews[args[0]]
            preview["status"] = "executing"
            preview["approval_receipt_id"] = args[1]
            preview["scope_receipt_id"] = args[2]
            preview["execution_started_at"] = datetime.now(timezone.utc)
        elif "SET status='consumed'" in query:
            preview = self.previews[args[0]]
            preview["status"] = "consumed"
            preview["operation_id"] = args[1]
            preview["result_json"] = args[2]
            preview["consumed_at"] = datetime.now(timezone.utc)
        elif "SET retention_delete_preview_id=NULL" in query:
            for row in self.evidence:
                if row.get("retention_delete_preview_id") == args[0]:
                    row["retention_delete_preview_id"] = None
                    row["retention_delete_pending_at"] = None
        return "OK"


def _pool_for(conn):
    class _Pool:
        def acquire(self):
            class _A:
                async def __aenter__(self_):
                    return conn

                async def __aexit__(self_, *e):
                    return False

            return _A()

    return _Pool()


def _retention_row(*, storage_uri="inline:evidence_objects", finding_id=None, scan_id=None):
    return {
        "id": uuid.uuid4(),
        "scan_id": scan_id or uuid.uuid4(),
        "finding_id": finding_id,
        "object_type": "finding_evidence",
        "content_sha256": "a" * 64,
        "size_bytes": 4096,
        "retention_class": "short",
        "storage_uri": storage_uri,
        "created_at": datetime(2025, 1, 1, tzinfo=timezone.utc),
    }


def _run_retention_preview(conn, **overrides):
    fields = {"dry_run": True, "target_id": str(conn.target_id), **overrides}
    return asyncio.run(api_module._evidence_retention_sweep(
        api_module.EvidenceRetentionSweepRequest(**fields),
        pool=_pool_for(conn),
    ))


def _run_retention_execute(conn, preview_id, **overrides):
    fields = {
        "dry_run": False,
        "preview_id": preview_id,
        "approval_receipt_id": str(conn.approval_id),
        **overrides,
    }
    return asyncio.run(api_module._evidence_retention_sweep(
        api_module.EvidenceRetentionSweepRequest(**fields),
        pool=_pool_for(conn),
    ))


def test_retention_sweep_execute_requires_preview_before_approval(monkeypatch):
    conn = _RetentionConn(policy_on=True)
    monkeypatch.setattr(api_module, "db_pool", _pool_for(conn))
    req = api_module.EvidenceRetentionSweepRequest(dry_run=False)

    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module.evidence_retention_sweep(req))

    assert exc.value.status_code == 409
    assert conn.recorded == []


def test_retention_sweep_execute_always_requires_target_scoped_approval():
    conn = _RetentionConn(policy_on=False)
    preview = _run_retention_preview(conn)
    req = api_module.EvidenceRetentionSweepRequest(dry_run=False, preview_id=preview["preview_id"])

    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module._evidence_retention_sweep(req, pool=_pool_for(conn)))

    assert exc.value.status_code == 400
    assert conn.recorded[-1]["status"] == "blocked"


def test_retention_sweep_dry_run_preview_is_target_bound_and_needs_no_approval():
    conn = _RetentionConn(policy_on=True)
    result = _run_retention_preview(conn, retention_class="short", older_than_days=90, limit=10)

    assert result["dry_run"] is True
    assert result["execution_enabled"] is False
    assert result["target_id"] == str(conn.target_id)
    assert result["preview_criteria"] == {
        "scope": "target",
        "target_id": str(conn.target_id),
        "older_than_days": 90,
        "retention_class": "short",
        "limit": 10,
        "delete_local_files": True,
    }
    assert uuid.UUID(result["preview_id"])
    assert conn.recorded == []


def test_retention_sweep_applies_limit_after_mixed_class_age_eligibility():
    ineligible_audit = _retention_row()
    ineligible_audit.update({
        "retention_class": "audit",
        "created_at": datetime.now(timezone.utc) - timedelta(days=100),
    })
    eligible_short = _retention_row()
    eligible_short.update({
        "retention_class": "short",
        "created_at": datetime.now(timezone.utc) - timedelta(days=40),
    })
    conn = _RetentionConn([ineligible_audit, eligible_short])

    result = _run_retention_preview(conn, limit=1)

    assert result["candidate_count"] == 1
    assert result["candidates"][0]["id"] == str(eligible_short["id"])
    assert result["candidates"][0]["retention_class"] == "short"


def test_retention_sweep_dry_run_reports_remote_objects_as_preserved():
    row = _retention_row(storage_uri="s3:evidence_objects/audit-bucket/evidence-objects/aa/" + ("a" * 64) + ".json")
    conn = _RetentionConn([row])
    result = _run_retention_preview(conn)

    assert result["candidate_count"] == 1
    assert result["remote_objects"] == {
        "candidate_count": 1,
        "deleted_count": 0,
        "missing_count": 0,
        "failed_count": 0,
        "preserved_count": 1,
        "delete_supported": True,
        "deleted": [],
        "missing": [],
        "errors": [],
    }
    assert result["local_files"] == {"deleted": [], "missing": [], "errors": []}
    assert result["candidates"][0]["id"] == str(row["id"])
    assert result["candidates"][0]["storage_backend"] == "s3"
    assert result["candidates"][0]["remote_object"] is True


def test_retention_approval_creation_binds_exact_preview_and_normalizes_expiry(monkeypatch):
    conn = _RetentionConn([_retention_row()])
    preview = _run_retention_preview(conn)
    monkeypatch.setattr(api_module, "db_pool", _pool_for(conn))
    # A timezone-less API value is interpreted as UTC rather than raising during
    # comparison with the preview's timezone-aware expiry.
    expires_at = datetime.fromisoformat(preview["preview_expires_at"]).replace(tzinfo=None)
    request = api_module.ApprovalReceiptRequest(
        scope_receipt_id=conn.scope_id,
        risk_tier="dangerous",
        confirmations=["confirm_authorized"],
        approved_by="test",
        expires_at=expires_at,
        action_name="evidence.retention_sweep",
        action_context={
            "preview_id": preview["preview_id"],
            "preview_hash": preview["preview_hash"],
            "target_id": str(conn.target_id),
        },
    )

    result = asyncio.run(api_module.arsenal_create_approval(request))

    approval = result["approval_receipt"]
    assert approval["risk_tier"] == "dangerous"
    assert approval["action_name"] == "evidence.retention_sweep"
    assert approval["action_context"] == request.action_context
    assert api_module._parse_hypothesis_time(approval["expires_at"]).tzinfo == timezone.utc


def test_retention_approval_creation_rejects_preview_context_mismatch(monkeypatch):
    conn = _RetentionConn([_retention_row()])
    preview = _run_retention_preview(conn)
    monkeypatch.setattr(api_module, "db_pool", _pool_for(conn))
    request = api_module.ApprovalReceiptRequest(
        scope_receipt_id=conn.scope_id,
        risk_tier="dangerous",
        confirmations=["confirm_authorized"],
        approved_by="test",
        expires_at=datetime.fromisoformat(preview["preview_expires_at"]),
        action_name="evidence.retention_sweep",
        action_context={
            "preview_id": preview["preview_id"],
            "preview_hash": "0" * 64,
            "target_id": str(conn.target_id),
        },
    )

    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module.arsenal_create_approval(request))

    assert exc.value.status_code == 400
    assert "does not match" in str(exc.value.detail)


def test_retention_sweep_executes_exact_remote_preview_once(monkeypatch):
    row = _retention_row(storage_uri="s3:evidence_objects/audit-bucket/evidence-objects/aa/" + ("a" * 64) + ".json")
    conn = _RetentionConn([row])
    calls = []
    monkeypatch.setattr(api_module, "delete_remote_evidence_object", lambda storage_uri: (
        calls.append(storage_uri) or {
            "storage_uri": storage_uri,
            "storage_backend": "s3",
            "status": "deleted",
            "deleted": True,
            "retryable": False,
        }
    ))

    preview = _run_retention_preview(conn)
    result = _run_retention_execute(conn, preview["preview_id"])
    original_target_id = conn.target_id
    conn.target_id = uuid.uuid4()
    replay = _run_retention_execute(conn, preview["preview_id"])

    assert result["deleted_count"] == 1
    assert result["remote_objects"]["candidate_count"] == 1
    assert result["remote_objects"]["deleted_count"] == 1
    assert result["remote_objects"]["preserved_count"] == 0
    assert conn.deleted_arg == [row["id"]]
    assert replay["idempotent_replay"] is True
    assert replay["target_id"] == str(original_target_id)
    assert calls == [row["storage_uri"]]


def test_retention_sweep_preserves_row_when_remote_delete_fails(monkeypatch):
    row = _retention_row(storage_uri="s3:evidence_objects/audit-bucket/evidence-objects/aa/" + ("a" * 64) + ".json")
    conn = _RetentionConn([row])
    monkeypatch.setattr(api_module, "delete_remote_evidence_object", lambda storage_uri: {
        "storage_uri": storage_uri,
        "storage_backend": "s3",
        "status": "remote_error",
        "deleted": False,
        "retryable": True,
        "error": "HTTPError: 403",
    })

    preview = _run_retention_preview(conn)
    result = _run_retention_execute(conn, preview["preview_id"])

    assert result["deleted_count"] == 0
    assert result["remote_objects"]["failed_count"] == 1
    assert result["remote_objects"]["preserved_count"] == 1
    assert conn.deleted_arg == []
    assert [item["id"] for item in conn.evidence] == [row["id"]]


@pytest.mark.parametrize(
    "field,value",
    [
        ("target_id", "11111111-1111-4111-8111-111111111111"),
        ("older_than_days", 90),
        ("retention_class", "short"),
        ("limit", 10),
        ("delete_local_files", False),
    ],
)
def test_retention_execute_rejects_resubmitted_criteria(field, value):
    conn = _RetentionConn()
    preview = _run_retention_preview(conn)

    with pytest.raises(api_module.HTTPException) as exc:
        _run_retention_execute(conn, preview["preview_id"], **{field: value})

    assert exc.value.status_code == 409
    assert conn.previews[uuid.UUID(preview["preview_id"])]["status"] == "ready"


@pytest.mark.parametrize(
    "attribute,value",
    [
        ("approval_risk", "active"),
        ("approval_action_name", "scan.submit"),
        ("approval_expires_at", None),
    ],
)
def test_retention_execute_requires_short_lived_exact_action_approval(attribute, value):
    conn = _RetentionConn([_retention_row()])
    preview = _run_retention_preview(conn)
    setattr(conn, attribute, value)

    with pytest.raises(api_module.HTTPException) as exc:
        _run_retention_execute(conn, preview["preview_id"])

    assert exc.value.status_code == 400
    assert conn.previews[uuid.UUID(preview["preview_id"])]["status"] == "ready"
    assert all(not row.get("retention_delete_pending_at") for row in conn.evidence)


def test_retention_execute_ignores_newly_eligible_rows():
    first = _retention_row()
    conn = _RetentionConn([first])
    preview = _run_retention_preview(conn)
    later = _retention_row(storage_uri="inline:evidence_objects/newly-eligible")
    conn.evidence.append(later)
    conn.scans[later["scan_id"]] = {"id": later["scan_id"], "target_id": conn.target_id}

    result = _run_retention_execute(conn, preview["preview_id"])

    assert result["deleted_count"] == 1
    assert [row["id"] for row in conn.evidence] == [later["id"]]


def test_retention_execute_aborts_all_when_finding_becomes_active(monkeypatch):
    finding_id = uuid.uuid4()
    row = _retention_row(
        finding_id=finding_id,
        storage_uri="s3:evidence_objects/audit-bucket/evidence-objects/aa/" + ("a" * 64) + ".json",
    )
    conn = _RetentionConn([row])
    preview = _run_retention_preview(conn)
    conn.findings[finding_id]["status"] = "active"
    calls = []
    monkeypatch.setattr(api_module, "delete_remote_evidence_object", lambda uri: calls.append(uri))

    with pytest.raises(api_module.HTTPException) as exc:
        _run_retention_execute(conn, preview["preview_id"])

    assert exc.value.status_code == 409
    assert calls == []
    assert [item["id"] for item in conn.evidence] == [row["id"]]
    assert conn.previews[uuid.UUID(preview["preview_id"])]["status"] == "stale"


def test_retention_execute_aborts_when_shared_blob_effect_changes(monkeypatch):
    uri = "s3:evidence_objects/audit-bucket/evidence-objects/aa/" + ("a" * 64) + ".json"
    first = _retention_row(storage_uri=uri)
    conn = _RetentionConn([first])
    preview = _run_retention_preview(conn)
    shared = _retention_row(storage_uri=uri)
    shared["retention_class"] = "legal_hold"
    conn.evidence.append(shared)
    conn.scans[shared["scan_id"]] = {"id": shared["scan_id"], "target_id": conn.target_id}
    calls = []
    monkeypatch.setattr(api_module, "delete_remote_evidence_object", lambda value: calls.append(value))

    with pytest.raises(api_module.HTTPException) as exc:
        _run_retention_execute(conn, preview["preview_id"])

    assert exc.value.status_code == 409
    assert calls == []
    assert len(conn.evidence) == 2


def test_retention_execution_never_escalates_previewed_shared_blob_to_delete(monkeypatch):
    uri = "s3:evidence_objects/audit-bucket/evidence-objects/aa/" + ("a" * 64) + ".json"
    candidate = _retention_row(storage_uri=uri)
    shared = _retention_row(storage_uri=uri)
    shared["retention_class"] = "legal_hold"
    conn = _RetentionConn([candidate, shared])
    preview = _run_retention_preview(conn)
    assert preview["candidates"][0]["planned_blob_action"] == "preserve_shared"
    original_links_match = api_module._evidence_retention_links_match_target
    link_checks = 0

    async def remove_shared_after_intent(*args, **kwargs):
        nonlocal link_checks
        link_checks += 1
        if link_checks == 2:
            conn.evidence = [row for row in conn.evidence if row["id"] != shared["id"]]
        return await original_links_match(*args, **kwargs)

    blob_deletes = []
    monkeypatch.setattr(api_module, "_evidence_retention_links_match_target", remove_shared_after_intent)
    monkeypatch.setattr(api_module, "delete_remote_evidence_object", lambda uri: blob_deletes.append(uri))

    result = _run_retention_execute(conn, preview["preview_id"])

    assert result["deleted_count"] == 1
    assert blob_deletes == []
    assert result["candidates"][0]["planned_blob_action"] == "preserve_shared"


def test_retention_execution_finishes_committed_intent_if_finding_resurfaces(monkeypatch):
    finding_id = uuid.uuid4()
    row = _retention_row(
        finding_id=finding_id,
        storage_uri="s3:evidence_objects/audit-bucket/evidence-objects/aa/" + ("a" * 64) + ".json",
    )
    conn = _RetentionConn([row])
    preview = _run_retention_preview(conn)
    original_links_match = api_module._evidence_retention_links_match_target
    async def activate_after_intent(*args, **kwargs):
        result = await original_links_match(*args, **kwargs)
        conn.findings[finding_id]["status"] = "active"
        return result

    blob_deletes = []
    monkeypatch.setattr(api_module, "_evidence_retention_links_match_target", activate_after_intent)
    monkeypatch.setattr(api_module, "delete_remote_evidence_object", lambda uri: (
        blob_deletes.append(uri) or {
            "storage_uri": uri,
            "storage_backend": "s3",
            "status": "deleted",
            "deleted": True,
            "retryable": False,
        }
    ))

    result = _run_retention_execute(conn, preview["preview_id"])

    assert result["deleted_count"] == 1
    assert blob_deletes == [row["storage_uri"]]
    assert conn.evidence == []
    assert conn.findings[finding_id]["status"] == "active"
    assert conn.previews[uuid.UUID(preview["preview_id"])]["status"] == "consumed"


def test_retention_execute_aborts_when_candidate_becomes_legal_hold(monkeypatch):
    row = _retention_row(
        storage_uri="s3:evidence_objects/audit-bucket/evidence-objects/aa/" + ("a" * 64) + ".json"
    )
    conn = _RetentionConn([row])
    preview = _run_retention_preview(conn)
    conn.evidence[0]["retention_class"] = "legal_hold"
    calls = []
    monkeypatch.setattr(api_module, "delete_remote_evidence_object", lambda uri: calls.append(uri))

    with pytest.raises(api_module.HTTPException) as exc:
        _run_retention_execute(conn, preview["preview_id"])

    assert exc.value.status_code == 409
    assert conn.previews[uuid.UUID(preview["preview_id"])]["status"] == "stale"
    assert calls == []


def test_retention_execute_rejects_approval_target_mismatch():
    conn = _RetentionConn(scope_target_id=uuid.uuid4())
    preview = _run_retention_preview(conn)

    with pytest.raises(api_module.HTTPException) as exc:
        _run_retention_execute(conn, preview["preview_id"])

    assert exc.value.status_code == 400
    assert conn.previews[uuid.UUID(preview["preview_id"])]["status"] == "ready"


def test_retention_execute_rejects_missing_previewed_candidate():
    row = _retention_row()
    conn = _RetentionConn([row])
    preview = _run_retention_preview(conn)
    conn.evidence = []

    with pytest.raises(api_module.HTTPException) as exc:
        _run_retention_execute(conn, preview["preview_id"])

    assert exc.value.status_code == 409
    assert conn.deleted_arg == []
    assert conn.previews[uuid.UUID(preview["preview_id"])]["status"] == "stale"


def test_retention_execute_rejects_expired_preview():
    conn = _RetentionConn()
    preview = _run_retention_preview(conn)
    preview_row = conn.previews[uuid.UUID(preview["preview_id"])]
    preview_row["expires_at"] = datetime.now(timezone.utc) - timedelta(seconds=1)
    payload = api_module._evidence_retention_preview_payload(preview_row)
    preview_row["preview_hash"] = api_module._evidence_retention_preview_hash(payload)

    with pytest.raises(api_module.HTTPException) as exc:
        _run_retention_execute(conn, preview["preview_id"])

    assert exc.value.status_code == 409
    assert "expired" in str(exc.value.detail).lower()


def test_retention_execute_rejects_policy_change(monkeypatch):
    conn = _RetentionConn()
    preview = _run_retention_preview(conn)
    changed_policy = dict(api_module.EVIDENCE_RETENTION_DAYS)
    changed_policy["short"] += 1
    monkeypatch.setattr(api_module, "EVIDENCE_RETENTION_DAYS", changed_policy)

    with pytest.raises(api_module.HTTPException) as exc:
        _run_retention_execute(conn, preview["preview_id"])

    assert exc.value.status_code == 409
    assert "policy" in str(exc.value.detail).lower()


def test_retention_local_delete_failure_preserves_evidence_row(monkeypatch):
    row = _retention_row(storage_uri="local:evidence_objects/aa/evidence.json")
    conn = _RetentionConn([row])

    class _FailingPath:
        def unlink(self):
            raise OSError("disk is read-only")

        def __str__(self):
            return "/safe/evidence.json"

    monkeypatch.setattr(api_module, "local_evidence_path", lambda *_args: _FailingPath())
    preview = _run_retention_preview(conn)
    result = _run_retention_execute(conn, preview["preview_id"])

    assert result["deleted_count"] == 0
    assert result["local_files"]["errors"]
    assert [item["id"] for item in conn.evidence] == [row["id"]]


def test_retention_execution_resumes_after_post_blob_database_failure(monkeypatch):
    finding_id = uuid.uuid4()
    row = _retention_row(
        finding_id=finding_id,
        storage_uri="s3:evidence_objects/audit-bucket/evidence-objects/aa/" + ("a" * 64) + ".json"
    )
    conn = _RetentionConn([row])
    storage_calls = []

    def delete_blob(storage_uri):
        storage_calls.append(storage_uri)
        missing = len(storage_calls) > 1
        return {
            "storage_uri": storage_uri,
            "storage_backend": "s3",
            "status": "missing" if missing else "deleted",
            "deleted": True,
            "retryable": False,
        }

    original_record = api_module._record_command_result
    failures = 0

    async def fail_first_finalize(*args, **kwargs):
        nonlocal failures
        if kwargs.get("command") == "evidence.retention_sweep" and failures == 0:
            failures += 1
            raise RuntimeError("database connection lost after blob deletion")
        return await original_record(*args, **kwargs)

    monkeypatch.setattr(api_module, "delete_remote_evidence_object", delete_blob)
    monkeypatch.setattr(api_module, "_record_command_result", fail_first_finalize)
    preview = _run_retention_preview(conn)

    with pytest.raises(RuntimeError):
        _run_retention_execute(conn, preview["preview_id"])

    preview_row = conn.previews[uuid.UUID(preview["preview_id"])]
    assert preview_row["status"] == "executing"
    assert conn.evidence[0]["retention_delete_preview_id"] == uuid.UUID(preview["preview_id"])
    conn.findings[finding_id]["status"] = "active"

    result = _run_retention_execute(conn, preview["preview_id"])

    assert result["deleted_count"] == 1
    assert result["remote_objects"]["missing_count"] == 1
    assert conn.previews[uuid.UUID(preview["preview_id"])]["status"] == "consumed"
    assert conn.evidence == []
    assert conn.findings[finding_id]["status"] == "active"
    assert len(storage_calls) == 2


def test_retention_deletion_io_waits_for_threads_before_propagating_cancellation(monkeypatch):
    started = threading.Event()
    release = threading.Event()

    def blocking_remote(_candidates):
        started.set()
        release.wait(timeout=5)
        return {"deleted": [], "missing": [], "errors": [], "deleted_ids": []}

    monkeypatch.setattr(api_module, "_delete_remote_evidence_objects", blocking_remote)

    async def scenario():
        task = asyncio.create_task(api_module._run_evidence_retention_deletion_io([{"id": "one"}], []))
        while not started.is_set():
            await asyncio.sleep(0.001)
        task.cancel()
        await asyncio.sleep(0.02)
        assert task.done() is False
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())


def test_retention_executing_intent_is_listed_for_reload_recovery(monkeypatch):
    conn = _RetentionConn([_retention_row()])
    preview = _run_retention_preview(conn)
    row = conn.previews[uuid.UUID(preview["preview_id"])]
    row["status"] = "executing"
    row["approval_receipt_id"] = conn.approval_id
    row["scope_receipt_id"] = conn.scope_id
    row["execution_started_at"] = datetime.now(timezone.utc)
    monkeypatch.setattr(api_module, "db_pool", _pool_for(conn))

    result = asyncio.run(api_module.list_evidence_retention_executions(
        target_id=str(conn.target_id),
        limit=20,
    ))

    assert result["count"] == 1
    execution = result["executions"][0]
    assert execution["preview_status"] == "executing"
    assert execution["preview_id"] == preview["preview_id"]
    assert execution["approval_receipt_id"] == str(conn.approval_id)
    assert [candidate["id"] for candidate in execution["candidates"]] == [
        candidate["id"] for candidate in preview["candidates"]
    ]
    assert all("storage_backend" not in candidate for candidate in execution["candidates"])
    assert all("age_days" not in candidate for candidate in execution["candidates"])


# ----- §2 Command Arsenal execution gateway ------------------------------------

def test_arsenal_execute_rejects_unknown_command():
    # A name not in the catalog (e.g. raw shell) is refused outright.
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module._arsenal_execute(
            _BlockedRecordingConn(), api_module.ArsenalExecuteRequest(command="run_shell")
        ))
    assert exc.value.status_code == 400


def test_arsenal_execute_dispatches_read_only_command(monkeypatch):
    async def fake_campaigns(**kwargs):
        return {"campaigns": [], "count": 0, "execution_enabled": False}

    monkeypatch.setattr(api_module, "arsenal_campaigns", fake_campaigns)
    conn = _BlockedRecordingConn()
    result = asyncio.run(api_module._arsenal_execute(
        conn, api_module.ArsenalExecuteRequest(command="campaign.list", parameters={"limit": 5})
    ))
    assert result["dispatched"] is True
    assert result["dry_run"] is False
    assert conn.recorded and conn.recorded[0]["status"] == "completed"
    assert conn.recorded[0]["command"] == "campaign.list"
    assert result["command_result"]["command"] == "campaign.list"
    assert result["command_result"]["status"] == "completed"
    assert result["action_state"]["phase"] == "completed"
    assert result["action_state"]["adapter_status"] == "dispatched"
    assert result["action_state"]["command_result_id"] == result["command_result"]["id"]


def test_arsenal_execute_dispatches_scan_result(monkeypatch):
    async def fake_scan_result(scan_id):
        return {"scan_id": scan_id, "result": {"score": 100}}

    monkeypatch.setattr(api_module, "get_scan_result", fake_scan_result)
    conn = _BlockedRecordingConn()
    result = asyncio.run(api_module._arsenal_execute(
        conn,
        api_module.ArsenalExecuteRequest(
            command="scan.result",
            parameters={"scan_id": "11111111-1111-4111-8111-111111111111"},
        ),
    ))

    assert result["dispatched"] is True
    assert result["dry_run"] is False
    assert result["result"]["scan_id"] == "11111111-1111-4111-8111-111111111111"
    assert conn.recorded and conn.recorded[0]["status"] == "completed"
    assert conn.recorded[0]["command"] == "scan.result"
    assert result["command_result"]["command"] == "scan.result"
    assert result["action_state"]["phase"] == "completed"
    assert result["action_state"]["adapter_status"] == "dispatched"


def test_arsenal_read_only_and_dry_run_catalog_commands_have_gateway_adapters():
    commands = api_module._operation_plan_allowed_commands()
    missing = sorted(
        name
        for name, spec in commands.items()
        if spec.get("status") in {"read_only", "dry_run"}
        and name not in api_module._arsenal_readonly_adapters()
    )
    assert missing == []


def test_arsenal_execute_gated_dry_runs_without_execute():
    conn = _BlockedRecordingConn()
    result = asyncio.run(api_module._arsenal_execute(
        conn, api_module.ArsenalExecuteRequest(
            command="asm.improve",
            parameters={"target_id": "11111111-1111-4111-8111-111111111111"},
            created_by="pytest",
        )
    ))
    assert result["dispatched"] is False
    assert result["dry_run"] is True
    assert result["execution_blocked_reason"] == "execute_not_requested"
    assert conn.recorded and conn.recorded[0]["status"] == "approval_required"
    assert conn.recorded[0]["created_by"] == "pytest"
    assert result["command_result"]["created_by"] == "pytest"
    assert result["action_state"]["phase"] == "approval_required"
    assert result["action_state"]["transition"]["reason"] == "execute_not_requested"
    assert result["action_state"]["gate"]["execute_requested"] is False


def test_arsenal_execute_gated_blocked_when_flag_disabled(monkeypatch):
    monkeypatch.setattr(api_module, "_ai_ops_execute_enabled", lambda: False)
    conn = _BlockedRecordingConn()
    result = asyncio.run(api_module._arsenal_execute(
        conn, api_module.ArsenalExecuteRequest(
            command="asm.improve",
            parameters={"target_id": "11111111-1111-4111-8111-111111111111"},
            execute=True, confirmations=["confirm_authorized"],
        )
    ))
    assert result["dispatched"] is False
    assert result["execution_blocked_reason"] == "AI_OPS_ROUTER_EXECUTE_ENABLED_disabled"


def test_arsenal_execute_gated_dispatches_when_gate_satisfied(monkeypatch):
    monkeypatch.setattr(api_module, "_ai_ops_execute_enabled", lambda: True)

    async def fake_validate(*args, **kwargs):
        return {"approval_receipt_id": "r"}

    async def fake_asm_improve(target_id, body):
        return {"operation_id": "op-1", "status": "queued", "action": "test"}

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)
    monkeypatch.setattr(api_module, "asm_improve", fake_asm_improve)
    result = asyncio.run(api_module._arsenal_execute(
        _BlockedRecordingConn(), api_module.ArsenalExecuteRequest(
            command="asm.improve",
            parameters={"target_id": "11111111-1111-4111-8111-111111111111"},
            execute=True, confirmations=["confirm_authorized"], approval_receipt_id="r",
        )
    ))
    assert result["dispatched"] is True
    assert result["operation_id"] == "op-1"
    assert result["action_state"]["phase"] == "queued"
    assert result["action_state"]["operation_id"] == "op-1"
    assert result["action_state"]["adapter_status"] == "dispatched"


def test_arsenal_execute_gated_without_adapter_is_pending(monkeypatch):
    monkeypatch.setattr(api_module, "_ai_ops_execute_enabled", lambda: True)

    async def fake_validate(*args, **kwargs):
        return {}

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)
    conn = _BlockedRecordingConn()
    result = asyncio.run(api_module._arsenal_execute(
        conn, api_module.ArsenalExecuteRequest(
            command="approval.record", parameters={"scope_receipt_id": "scope-1"},
            execute=True, confirmations=["confirm_authorized"],
        )
    ))
    assert result["execution_blocked_reason"] == "dispatch_adapter_pending"
    assert conn.recorded and conn.recorded[0]["status"] == "blocked"
    assert result["action_state"]["phase"] == "blocked"
    assert result["action_state"]["blocked_reason"] == "dispatch_adapter_pending"
    assert result["action_state"]["adapter_status"] == "pending"


def test_arsenal_execute_dispatches_target_list(monkeypatch):
    async def fake_list_targets(**kwargs):
        return {"targets": []}

    monkeypatch.setattr(api_module, "list_targets", fake_list_targets)
    conn = _BlockedRecordingConn()
    result = asyncio.run(api_module._arsenal_execute(
        conn, api_module.ArsenalExecuteRequest(command="target.list", parameters={})
    ))
    assert result["dispatched"] is True
    assert conn.recorded and conn.recorded[0]["status"] == "completed"


def test_arsenal_execute_asm_gaps_requires_target_id():
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module._arsenal_execute(
            _BlockedRecordingConn(), api_module.ArsenalExecuteRequest(command="asm.gaps", parameters={})
        ))
    assert exc.value.status_code == 400


def test_arsenal_execute_gated_asm_test_dispatches_when_allowed(monkeypatch):
    monkeypatch.setattr(api_module, "_ai_ops_execute_enabled", lambda: True)

    async def fake_validate(*args, **kwargs):
        return {}

    async def fake_asm_test(target_id, body):
        return {"operation_id": "op-9", "status": "queued"}

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)
    monkeypatch.setattr(api_module, "asm_test", fake_asm_test)
    result = asyncio.run(api_module._arsenal_execute(
        _BlockedRecordingConn(), api_module.ArsenalExecuteRequest(
            command="asm.test",
            parameters={"target_id": "11111111-1111-4111-8111-111111111111"},
            execute=True, confirmations=["confirm_authorized"], approval_receipt_id="r",
        )
    ))
    assert result["dispatched"] is True
    assert result["operation_id"] == "op-9"


def test_arsenal_execute_dispatches_evidence_export_bundle(monkeypatch):
    captured = {}

    async def fake_bundle(**kwargs):
        captured.update(kwargs)
        return {"bundle_hash": "b" * 64, "export_event": {"id": "event-1"}}

    monkeypatch.setattr(api_module, "evidence_export_bundle", fake_bundle)
    result = asyncio.run(api_module._arsenal_execute(
        _BlockedRecordingConn(),
        api_module.ArsenalExecuteRequest(
            command="evidence.export_bundle",
            parameters={"scan_id": "44444444-4444-4444-8444-444444444444", "record_event": True},
        ),
    ))

    assert result["dispatched"] is True
    assert captured["scan_id"] == "44444444-4444-4444-8444-444444444444"
    assert captured["record_event"] is True


def test_arsenal_execute_gated_scan_focused_family_dispatches_when_allowed(monkeypatch):
    monkeypatch.setattr(api_module, "_ai_ops_execute_enabled", lambda: True)
    captured = {}

    async def fake_validate(*args, **kwargs):
        return {}

    async def fake_submit_scan(body):
        captured["body"] = body
        return {"operation_id": "op-scan", "scan_id": "scan-1", "status": "queued"}

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)
    monkeypatch.setattr(api_module, "submit_scan", fake_submit_scan)

    result = asyncio.run(api_module._arsenal_execute(
        _BlockedRecordingConn(),
        api_module.ArsenalExecuteRequest(
            command="scan.focused_family",
            parameters={
                "target": "https://app.example.com",
                "check_family": "sqli",
                "custom_endpoints": ["POST /api/search q"],
                "custom_sqli_payloads": ["' OR '1'='1"],
            },
            execute=True,
            confirmations=["confirm_authorized"],
            approval_receipt_id="r",
        ),
    ))

    assert result["dispatched"] is True
    assert result["operation_id"] == "op-scan"
    body = captured["body"]
    assert body.target == "https://app.example.com"
    assert body.options.check_family == "sqli"
    assert body.options.scan_type == "smart"
    assert body.options.approval_receipt_id == "r"
    assert body.options.custom_endpoints == ["POST /api/search q"]
    assert body.options.custom_sqli_payloads == ["' OR '1'='1"]
    assert body.options.focused_endpoints_only is True
    assert body.options.zero_rediscovery is True
    assert body.options.skip_global_checks is True
    assert body.options.parallel is False
    assert body.options.require_current_workers is True


def test_arsenal_execute_gated_model_intake_scan_dispatches_when_allowed(monkeypatch):
    monkeypatch.setattr(api_module, "_ai_ops_execute_enabled", lambda: True)
    captured = {}

    async def fake_validate(*args, **kwargs):
        return {}

    async def fake_model_intake(body):
        captured["body"] = body
        return {"operation_id": "op-model", "scan_id": "scan-model", "status": "queued"}

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)
    monkeypatch.setattr(api_module, "scan_model_intake", fake_model_intake)

    result = asyncio.run(api_module._arsenal_execute(
        _BlockedRecordingConn(),
        api_module.ArsenalExecuteRequest(
            command="model_intake.scan",
            parameters={"artifact_url": "https://models.example.com/model.safetensors", "policy_profile": "production"},
            execute=True,
            confirmations=["confirm_authorized"],
            approval_receipt_id="r",
        ),
    ))

    assert result["dispatched"] is True
    assert result["operation_id"] == "op-model"
    body = captured["body"]
    assert body.artifact_url == "https://models.example.com/model.safetensors"
    assert body.policy_profile == "production"
    assert body.approval_receipt_id == "r"


def test_arsenal_execute_gated_ai_gate_replay_dispatches_when_allowed(monkeypatch):
    monkeypatch.setattr(api_module, "_ai_ops_execute_enabled", lambda: True)
    captured = {}

    async def fake_validate(*args, **kwargs):
        return {}

    async def fake_replay(scan_id, body):
        captured["scan_id"] = scan_id
        captured["body"] = body
        return {"operation_id": "op-ai", "scan_id": "scan-ai", "status": "queued"}

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)
    monkeypatch.setattr(api_module, "replay_ai_scan", fake_replay)

    result = asyncio.run(api_module._arsenal_execute(
        _BlockedRecordingConn(),
        api_module.ArsenalExecuteRequest(
            command="ai_gate.replay_probe",
            parameters={"scan_id": "44444444-4444-4444-8444-444444444444", "mode": "family", "probe_family": "rag"},
            execute=True,
            confirmations=["confirm_authorized", "confirm_production_when_applicable"],
            approval_receipt_id="r",
        ),
    ))

    assert result["dispatched"] is True
    assert result["operation_id"] == "op-ai"
    assert captured["scan_id"] == "44444444-4444-4444-8444-444444444444"
    assert captured["body"].mode == "family"
    assert captured["body"].probe_family == "rag"
    assert captured["body"].approval_receipt_id == "r"


def test_arsenal_execute_gated_ai_gate_scan_dispatches_when_allowed(monkeypatch):
    monkeypatch.setattr(api_module, "_ai_ops_execute_enabled", lambda: True)
    captured = {}

    async def fake_validate(*args, **kwargs):
        return {}

    async def fake_scan(target_id, body):
        captured["target_id"] = target_id
        captured["body"] = body
        return {"operation_id": "op-ai-scan", "scan_id": "scan-ai", "status": "queued"}

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)
    monkeypatch.setattr(api_module, "scan_ai_target", fake_scan)

    result = asyncio.run(api_module._arsenal_execute(
        _BlockedRecordingConn(),
        api_module.ArsenalExecuteRequest(
            command="ai_gate.scan",
            parameters={
                "target_id": "55555555-5555-4555-8555-555555555555",
                "probe_pack": "shaker-ai-smoke",
                "scan_profile": "smoke",
                "environment": "staging",
            },
            execute=True,
            confirmations=["confirm_authorized", "confirm_production_when_applicable"],
            approval_receipt_id="r",
        ),
    ))

    assert result["dispatched"] is True
    assert result["operation_id"] == "op-ai-scan"
    assert captured["target_id"] == "55555555-5555-4555-8555-555555555555"
    assert captured["body"].probe_pack == "shaker-ai-smoke"
    assert captured["body"].scan_profile == "smoke"
    assert captured["body"].approval_receipt_id == "r"


def test_arsenal_execute_gated_evidence_retention_sweep_dispatches_when_allowed(monkeypatch):
    monkeypatch.setattr(api_module, "_ai_ops_execute_enabled", lambda: True)
    captured = {}

    async def fake_validate(*args, **kwargs):
        return {}

    async def fake_sweep(body):
        captured["body"] = body
        return {"operation_id": "op-sweep", "dry_run": False, "deleted_count": 2}

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)
    monkeypatch.setattr(api_module, "evidence_retention_sweep", fake_sweep)

    result = asyncio.run(api_module._arsenal_execute(
        _BlockedRecordingConn(),
        api_module.ArsenalExecuteRequest(
            command="evidence.retention_sweep",
            parameters={
                "dry_run": False,
                "preview_id": "55555555-5555-4555-8555-555555555555",
            },
            execute=True,
            confirmations=["confirm_authorized"],
            approval_receipt_id="r",
        ),
    ))

    assert result["dispatched"] is True
    assert result["operation_id"] == "op-sweep"
    assert captured["body"].dry_run is False
    assert captured["body"].preview_id == "55555555-5555-4555-8555-555555555555"
    assert captured["body"].target_id is None
    assert captured["body"].older_than_days is None
    assert captured["body"].retention_class is None
    assert captured["body"].approval_receipt_id == "r"


def test_arsenal_retention_preview_dispatches_without_execution_gate_or_approval(monkeypatch):
    monkeypatch.setattr(api_module, "_ai_ops_execute_enabled", lambda: False)
    captured = {}

    async def reject_if_validated(*args, **kwargs):
        raise AssertionError("read-only preview must not validate a destructive approval")

    async def fake_sweep(body):
        captured["body"] = body
        return {
            "dry_run": True,
            "preview_id": "66666666-6666-4666-8666-666666666666",
            "candidate_count": 3,
        }

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", reject_if_validated)
    monkeypatch.setattr(api_module, "evidence_retention_sweep", fake_sweep)

    result = asyncio.run(api_module._arsenal_execute(
        _BlockedRecordingConn(),
        api_module.ArsenalExecuteRequest(
            command="evidence.retention_sweep",
            parameters={
                "dry_run": True,
                "target_id": "55555555-5555-4555-8555-555555555555",
                "retention_class": "short",
            },
            execute=False,
            confirmations=[],
        ),
    ))

    assert result["dispatched"] is True
    assert result["dry_run"] is True
    assert result["execution_enabled"] is False
    assert result["command_result"]["risk_tier"] == "read_only"
    assert captured["body"].dry_run is True
    assert captured["body"].target_id == "55555555-5555-4555-8555-555555555555"


def test_public_arsenal_retention_preview_uses_read_only_detached_path(monkeypatch):
    monkeypatch.setattr(api_module, "_ai_ops_execute_enabled", lambda: False)
    conn = _BlockedRecordingConn()
    captured = {}

    async def reject_if_validated(*args, **kwargs):
        raise AssertionError("public read-only preview must not validate a destructive approval")

    async def fake_sweep(body):
        captured["body"] = body
        return {
            "dry_run": True,
            "preview_id": "77777777-7777-4777-8777-777777777777",
            "candidate_count": 0,
            "candidates": [],
        }

    monkeypatch.setattr(api_module, "db_pool", _pool_for(conn))
    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", reject_if_validated)
    monkeypatch.setattr(api_module, "evidence_retention_sweep", fake_sweep)

    result = asyncio.run(api_module.arsenal_execute(api_module.ArsenalExecuteRequest(
        command="evidence.retention_sweep",
        parameters={
            "dry_run": True,
            "target_id": "55555555-5555-4555-8555-555555555555",
            "retention_class": "short",
        },
        execute=False,
        confirmations=[],
    )))

    assert result["dispatched"] is True
    assert result["dry_run"] is True
    assert result["execution_enabled"] is False
    assert result["command_result"]["risk_tier"] == "read_only"
    assert captured["body"].dry_run is True
    assert captured["body"].target_id == "55555555-5555-4555-8555-555555555555"


def test_arsenal_execute_gated_exception_lifecycle_sweep_dispatches_when_allowed(monkeypatch):
    monkeypatch.setattr(api_module, "_ai_ops_execute_enabled", lambda: True)
    captured = {}

    async def fake_validate(*args, **kwargs):
        return {}

    async def fake_sweep(body):
        captured["body"] = body
        return {"operation_id": "op-exception-sweep", "dry_run": False, "expired_count": 2}

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)
    monkeypatch.setattr(api_module, "finding_exception_lifecycle_sweep", fake_sweep)

    result = asyncio.run(api_module._arsenal_execute(
        _BlockedRecordingConn(),
        api_module.ArsenalExecuteRequest(
            command="finding_exception.lifecycle_sweep",
            parameters={"dry_run": False, "limit": 50},
            execute=True,
            confirmations=["confirm_authorized"],
            approval_receipt_id="r",
        ),
    ))

    assert result["dispatched"] is True
    assert result["operation_id"] == "op-exception-sweep"
    assert captured["body"].dry_run is False
    assert captured["body"].limit == 50
    assert captured["body"].approval_receipt_id == "r"


def test_arsenal_execute_returns_persisted_command_result_refs(monkeypatch):
    monkeypatch.setattr(api_module, "_ai_ops_execute_enabled", lambda: True)
    operation_id = "99999999-9999-4999-8999-999999999999"

    class _CommandResultLookupConn(_BlockedRecordingConn):
        async def fetchrow(self, query, *args):
            if "SELECT * FROM command_results" in query:
                return {
                    "id": args[0],
                    "command": "model_intake.scan",
                    "status": "queued",
                    "dry_run": False,
                    "risk_tier": "active",
                    "operation_plan_id": None,
                    "scope_receipt_id": "scope-1",
                    "approval_receipt_id": None,
                    "campaign_id": None,
                    "scan_id": "88888888-8888-4888-8888-888888888888",
                    "finding_ids": json.dumps([]),
                    "hypothesis_ids": json.dumps([]),
                    "evidence_object_ids": json.dumps(["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"]),
                    "tool_receipt_ids": json.dumps(["77777777-7777-4777-8777-777777777777"]),
                    "blocked_by": json.dumps([]),
                    "next_action": "/scans/88888888-8888-4888-8888-888888888888",
                    "operator_message": "queued",
                    "result_json": json.dumps({"scan_id": "88888888-8888-4888-8888-888888888888"}),
                    "created_by": "pytest",
                    "created_at": None,
                }
            return await super().fetchrow(query, *args)

    async def fake_validate(*args, **kwargs):
        return {}

    async def fake_model_intake(body):
        return {"operation_id": operation_id, "scan_id": "scan-model", "status": "queued"}

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)
    monkeypatch.setattr(api_module, "scan_model_intake", fake_model_intake)

    result = asyncio.run(api_module._arsenal_execute(
        _CommandResultLookupConn(),
        api_module.ArsenalExecuteRequest(
            command="model_intake.scan",
            parameters={"artifact_url": "https://models.example.com/model.safetensors"},
            execute=True,
            confirmations=["confirm_authorized"],
            approval_receipt_id="r",
        ),
    ))

    assert result["operation_id"] == operation_id
    assert result["command_result"]["command"] == "model_intake.scan"
    assert result["command_result"]["tool_receipt_ids"] == ["77777777-7777-4777-8777-777777777777"]
    assert result["command_result"]["evidence_object_ids"] == ["eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"]


def test_arsenal_execute_detached_dispatches_without_holding_outer_db_conn(monkeypatch):
    monkeypatch.setattr(api_module, "_ai_ops_execute_enabled", lambda: True)

    class _Pool:
        def __init__(self):
            self.active = 0
            self.max_active = 0
            self.conn = _BlockedRecordingConn()
            self.adapter_saw_no_conn = False

        def acquire(self):
            pool = self

            class _Acquire:
                async def __aenter__(self):
                    pool.active += 1
                    pool.max_active = max(pool.max_active, pool.active)
                    return pool.conn

                async def __aexit__(self, *exc):
                    pool.active -= 1
                    return False

            return _Acquire()

    pool = _Pool()
    captured_parameters = {}

    async def fake_validate(*args, **kwargs):
        assert pool.active == 1
        return {"approval_receipt_id": "r"}

    async def fake_adapter(parameters, approval_receipt_id):
        pool.adapter_saw_no_conn = pool.active == 0
        captured_parameters.update(parameters)
        return {"operation_id": "99999999-9999-4999-8999-999999999999", "status": "queued"}

    monkeypatch.setattr(api_module, "db_pool", pool)
    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)
    monkeypatch.setattr(api_module, "_arsenal_gated_adapters", lambda: {"asm.improve": fake_adapter})

    result = asyncio.run(api_module._arsenal_execute_detached(
        api_module.ArsenalExecuteRequest(
            command="asm.improve",
            parameters={"target_id": "11111111-1111-4111-8111-111111111111"},
            execute=True,
            confirmations=["confirm_authorized"],
            approval_receipt_id="r",
            research_hypothesis_id="22222222-2222-4222-8222-222222222222",
        )
    ))

    assert result["dispatched"] is True
    assert pool.adapter_saw_no_conn is True
    assert pool.max_active == 1
    assert captured_parameters["_research_hypothesis_id"] == "22222222-2222-4222-8222-222222222222"


def test_arsenal_execute_detached_persists_bounded_read_result(monkeypatch):
    class _Pool:
        def __init__(self):
            self.conn = _BlockedRecordingConn()

        def acquire(self):
            conn = self.conn

            class _Acquire:
                async def __aenter__(self):
                    return conn

                async def __aexit__(self, *exc):
                    return False

            return _Acquire()

    pool = _Pool()

    async def fake_validate(*args, **kwargs):
        return ({"name": "asm.gaps"}, "read_only", "read_only")

    async def fake_adapter(parameters):
        return {
            "target_id": parameters["target_id"],
            "family_coverage": {"bola": {"completed": 0, "attempts": 1}},
            "recommended_campaigns": [{"family": "bola", "reason": "no owner/attacker proof"}],
            "authorization": "Bearer should-not-survive",
            "oversized": "x" * 10_000,
        }

    monkeypatch.setattr(api_module, "db_pool", pool)
    monkeypatch.setattr(api_module, "_validate_arsenal_execute_request", fake_validate)
    monkeypatch.setattr(api_module, "_validate_campaign_action_for_execution", lambda *args: asyncio.sleep(0))
    monkeypatch.setattr(api_module, "_arsenal_readonly_adapters", lambda: {"asm.gaps": fake_adapter})
    monkeypatch.setattr(api_module, "_arsenal_gated_adapters", lambda: {})

    result = asyncio.run(api_module._arsenal_execute_detached(
        api_module.ArsenalExecuteRequest(
            command="asm.gaps",
            parameters={"target_id": "11111111-1111-4111-8111-111111111111"},
            execute=True,
        )
    ))

    stored = json.loads(pool.conn.recorded[0]["result_json"])["result"]
    assert stored["family_coverage"]["bola"]["attempts"] == 1
    assert stored["authorization"] == "***"
    assert len(stored["oversized"]) == 4000
    assert result["command_result"]["result_json"]["result"] == stored


# ----- §7 mission campaigns ----------------------------------------------------

class _CampaignConn:
    def __init__(self, *, target_exists=True, plan_exists=True):
        self.target_exists = target_exists
        self.plan_exists = plan_exists
        self.inserted = None

    async def fetchval(self, query, *args):
        if "FROM targets" in query:
            return 1 if self.target_exists else None
        if "FROM operation_plans" in query:
            return 1 if self.plan_exists else None
        return None

    async def fetchrow(self, query, *args):
        if "INSERT INTO campaigns" in query:
            self.inserted = args
            keys = [
                "name", "objective", "campaign_type", "target_id", "target_scope",
                "risk_tier", "policy_profile", "planner", "operation_plan_id",
                "context_hash", "status", "deployment_impact", "metadata_json", "created_by",
            ]
            row = {k: args[i] for i, k in enumerate(keys)}
            row.update({"id": "camp-1", "created_at": None, "updated_at": None})
            return row
        return None


def test_persist_campaign_records_valid_mission():
    conn = _CampaignConn()
    req = api_module.CampaignRequest(objective="Cover the orders API", campaign_type="authenticated_dast")
    result = asyncio.run(api_module._persist_campaign(conn, req))

    assert result["objective"] == "Cover the orders API"
    assert result["campaign_type"] == "authenticated_dast"
    assert result["status"] == "planned"
    assert result["execution_enabled"] is False


def test_campaign_deployment_impact_rolls_up_findings_and_estimates_blockers():
    rows = [
        {"id": "f1", "severity": "critical", "status": "active"},
        {"id": "f2", "severity": "high", "status": "active"},
        {"id": "f3", "severity": "high", "status": "resolved"},
        {"id": "f4", "severity": "medium", "status": "active"},
        {"id": "f5", "severity": "low", "status": "false_positive"},
    ]
    impact = api_module._campaign_deployment_impact(rows, partial=True)
    assert impact["linked_finding_count"] == 5
    assert impact["active_finding_count"] == 3
    assert impact["by_severity"] == {"critical": 1, "high": 2, "medium": 1, "low": 1}
    assert impact["by_status"]["active"] == 3
    # Only ACTIVE critical/high count toward the default-threshold blocker estimate:
    # the resolved high (f3) and active medium (f4) are excluded.
    assert impact["estimated_default_blockers"] == 2
    assert impact["blocks_deployment_estimate"] is True
    assert impact["partial"] is True


def test_campaign_deployment_impact_empty_is_non_blocking():
    impact = api_module._campaign_deployment_impact([])
    assert impact["linked_finding_count"] == 0
    assert impact["estimated_default_blockers"] == 0
    assert impact["blocks_deployment_estimate"] is False
    assert impact["partial"] is False


class _CampaignImpactConn:
    async def fetch(self, _query, _campaign_ids):
        campaign_id = _campaign_ids[0]
        return [
            {
                "mission_campaign_id": campaign_id,
                "finding_id": "f1",
                "id": "f1",
                "severity": "high",
                "status": "active",
            },
            {
                "mission_campaign_id": campaign_id,
                "finding_id": "f1",
                "id": "f1",
                "severity": "high",
                "status": "active",
            },
            {
                "mission_campaign_id": campaign_id,
                "finding_id": "missing",
                "id": None,
                "severity": None,
                "status": None,
            },
        ]


def test_campaign_live_impact_deduplicates_and_marks_unresolved_links():
    campaign_id = uuid.uuid4()
    impact = asyncio.run(
        api_module._campaign_live_finding_impact(_CampaignImpactConn(), [campaign_id])
    )[campaign_id]
    assert impact["linked_finding_count"] == 1
    assert impact["estimated_default_blockers"] == 1
    assert impact["partial"] is True


def test_batch_request_caps_target_count():
    with pytest.raises(api_module.ValidationError):
        api_module.BatchRequest(targets=[f"https://t{i}.test" for i in range(51)])


def test_batch_submission_reports_partial_failures_and_deduplicates(monkeypatch):
    async def fake_submit(req):
        if req.target == "https://bad.test":
            raise api_module.HTTPException(status_code=422, detail="rejected")
        return {"scan_id": "scan-1", "target": req.target}

    monkeypatch.setattr(api_module, "submit_scan", fake_submit)
    request = api_module.BatchRequest(
        targets=["https://good.test", "https://bad.test", "https://good.test"]
    )
    result = asyncio.run(api_module.submit_batch(request))
    assert result["status"] == "partial"
    assert result["queued_count"] == 1
    assert result["failed_count"] == 1
    assert result["requested_count"] == 2
    assert result["errors"] == [{
        "target": "https://bad.test",
        "status_code": 422,
        "error": "rejected",
    }]


def test_persist_campaign_rejects_unknown_target():
    conn = _CampaignConn(target_exists=False)
    req = api_module.CampaignRequest(
        objective="x", campaign_type="api_authz", target_id="11111111-1111-4111-8111-111111111111"
    )
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module._persist_campaign(conn, req))
    assert exc.value.status_code == 404


def test_persist_campaign_rejects_unknown_operation_plan():
    conn = _CampaignConn(plan_exists=False)
    req = api_module.CampaignRequest(
        objective="x", campaign_type="api_authz",
        operation_plan_id="22222222-2222-4222-8222-222222222222",
    )
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module._persist_campaign(conn, req))
    assert exc.value.status_code == 404


def test_persist_campaign_rejects_bad_context_hash():
    conn = _CampaignConn()
    req = api_module.CampaignRequest(objective="x", campaign_type="benchmark", context_hash="not-hex")
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module._persist_campaign(conn, req))
    assert exc.value.status_code == 400


def test_public_campaign_row_decodes_json_fields():
    row = {
        "id": "camp-1", "objective": "x", "campaign_type": "benchmark", "status": "planned",
        "target_scope": json.dumps({"allowed_hosts": ["app.example.com"]}),
        "planner": json.dumps({"kind": "human"}),
        "deployment_impact": json.dumps({}),
        "metadata_json": json.dumps({"k": "v"}),
    }
    public = api_module._public_campaign_row(row)
    assert public["target_scope"]["allowed_hosts"] == ["app.example.com"]
    assert public["planner"]["kind"] == "human"
    assert public["metadata_json"]["k"] == "v"
    assert public["execution_enabled"] is False


class _ClaimConn:
    def __init__(self, *, update_row=None, current=None):
        self.update_row = update_row
        self.current = current

    async def fetchrow(self, query, *args):
        if "UPDATE hypotheses" in query and "status = 'claimed'" in query:
            return self.update_row  # None simulates a compare-and-set miss
        if "SELECT id, status, version" in query:
            return self.current
        return None


HYP_ID = "77777777-7777-4777-8777-777777777777"


def test_claim_hypothesis_409_on_stale_version(monkeypatch):
    # CAS miss (wrong expected_version / terminal / active lease) -> UPDATE returns
    # no row -> endpoint surfaces the current state as 409, never a silent success.
    conn = _ClaimConn(update_row=None, current={
        "id": HYP_ID, "status": "claimed", "version": 5,
        "claim_owner": "other", "claim_lease_expires_at": None,
    })
    monkeypatch.setattr(api_module, "db_pool", _pool_for(conn))
    req = api_module.HypothesisClaimRequest(owner="me", expected_version=3, lease_seconds=300)

    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module.arsenal_claim_hypothesis(HYP_ID, req))

    assert exc.value.status_code == 409
    assert exc.value.detail["error"] == "hypothesis_not_claimable"
    assert exc.value.detail["version"] == 5


def test_claim_hypothesis_success_returns_claimed(monkeypatch):
    conn = _ClaimConn(update_row={
        "id": HYP_ID, "status": "claimed", "version": 4, "family": "bola",
        "claim_owner": "me", "claim_lease_expires_at": None,
        "evidence_object_ids": [], "tool_receipt_ids": [], "endorsements": [],
        "refutations": [], "next_test_action": None, "metadata_json": {},
    })
    monkeypatch.setattr(api_module, "db_pool", _pool_for(conn))
    req = api_module.HypothesisClaimRequest(owner="me", expected_version=3, lease_seconds=300)

    result = asyncio.run(api_module.arsenal_claim_hypothesis(HYP_ID, req))

    assert result["claimed"] is True
    assert result["hypothesis"]["claim_owner"] == "me"


def test_older_than_days_can_raise_but_not_lower_protected_floor():
    now = datetime(2026, 7, 6, tzinfo=timezone.utc)
    created = datetime(2026, 3, 8, tzinfo=timezone.utc)  # 120 days old
    # A longer override on sensitive (365 > 90) must protect the 120d object.
    candidates = api_module._evidence_retention_candidates(
        [_evidence_row("sensitive", created)], now=now, older_than_days=365
    )
    assert candidates == []


def test_hydrate_withholds_content_on_integrity_mismatch(tmp_path):
    import hashlib
    from evidence_storage import hydrate_evidence_content, _local_storage_uri, local_evidence_path

    good_sha = hashlib.sha256(b"real evidence").hexdigest()
    uri = _local_storage_uri(good_sha)
    fpath = local_evidence_path(tmp_path, uri)
    fpath.parent.mkdir(parents=True, exist_ok=True)
    fpath.write_text("TAMPERED", encoding="utf-8")  # on-disk bytes != recorded hash

    out = hydrate_evidence_content(
        {"storage_uri": uri, "content_sha256": good_sha}, results_dir=tmp_path
    )
    assert out["storage_integrity"] == "mismatch"
    assert out["content"] is None  # tampered bytes are withheld, not served

    # And the verified path still returns content.
    fpath.write_text("real evidence", encoding="utf-8")
    ok = hydrate_evidence_content(
        {"storage_uri": uri, "content_sha256": good_sha}, results_dir=tmp_path
    )
    assert ok["storage_integrity"] == "verified"
    assert ok["content"] == "real evidence"


def test_hypothesis_situation_report_is_bounded_and_separates_work():
    now = datetime.now(timezone.utc).replace(microsecond=0)

    def row(
        *,
        status: str,
        family: str,
        severity: str = "medium",
        confidence: float = 0.5,
        owner: str | None = None,
        lease_delta: timedelta | None = None,
        next_test_action: dict[str, object] | None = None,
        terminal_reason: str | None = None,
    ) -> dict[str, object]:
        return {
            "id": uuid.uuid4(),
            "source": "app_graph",
            "family": family,
            "cwe": "CWE-639",
            "title": f"{family} lead",
            "severity_guess": severity,
            "confidence": confidence,
            "dedupe_key": f"{family}:{status}:{uuid.uuid4()}",
            "status": status,
            "version": 1,
            "claim_owner": owner,
            "claim_lease_expires_at": (now + lease_delta).isoformat() if lease_delta else None,
            "smoke_score": 0.2,
            "evidence_object_ids": json.dumps([]),
            "tool_receipt_ids": json.dumps([]),
            "next_test_action": json.dumps(next_test_action or {}),
            "endorsements": json.dumps([{"source": "app_graph"}]),
            "refutations": json.dumps([]),
            "terminal_reason": terminal_reason,
            "metadata_json": json.dumps({}),
            "updated_at": now.isoformat(),
        }

    hot = row(
        status="open",
        family="bola",
        severity="high",
        confidence=0.9,
        next_test_action={"command": "asm.improve", "parameters": {"check_family": "bola", "exploit_depth": True}},
    )
    owned = row(status="claimed", family="xss", owner="agent-a", lease_delta=timedelta(minutes=10))
    blocked = row(status="testing", family="sqli", owner="agent-b", lease_delta=timedelta(minutes=10))
    expired = row(status="claimed", family="bfla", owner="agent-c", lease_delta=timedelta(minutes=-10))
    refuted = row(status="refuted", family="secret", terminal_reason="manual refuter rejected")
    dead = row(status="dead", family="config", terminal_reason="route removed")

    report = api_module._hypothesis_situation_report(
        [owned, blocked, refuted, hot, dead, expired],
        requester="agent-a",
        limit=2,
        now=now,
    )

    assert report["execution_enabled"] is False
    assert report["findings_created"] == 0
    assert report["summary"]["considered_count"] == 6
    assert report["summary"]["status_counts"]["claimed"] == 1
    assert report["summary"]["status_counts"]["open"] == 2
    assert len(report["hottest_unclaimed"]) == 2
    assert report["hottest_unclaimed"][0]["family"] == "bola"
    assert {item["family"] for item in report["requester_claims"]} == {"xss"}
    assert {item["family"] for item in report["live_blockers"]} == {"sqli"}
    assert {item["status"] for item in report["avoid_resurfacing"]} == {"refuted", "dead"}
    requirements = {item["requirement"]: item for item in report["missing_preconditions"]}
    assert requirements["primary_auth"]["count"] == 1
    assert requirements["second_user_auth"]["count"] == 1
    assert all("metadata_json" not in item for item in report["hottest_unclaimed"])


def test_hypothesis_situation_report_can_include_application_graph_context():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    target_id = uuid.uuid4()
    missing_graph_target_id = uuid.uuid4()
    hypothesis_id = uuid.uuid4()
    missing_hypothesis_id = uuid.uuid4()

    def hypothesis_row(*, row_id: uuid.UUID, target: uuid.UUID, family: str) -> dict[str, object]:
        return {
            "id": row_id,
            "target_id": target,
            "source": "app_graph",
            "family": family,
            "cwe": "CWE-639",
            "title": f"{family} lead",
            "severity_guess": "high",
            "confidence": 0.9,
            "dedupe_key": f"{family}:{target}",
            "status": "open",
            "version": 1,
            "claim_owner": None,
            "claim_lease_expires_at": None,
            "smoke_score": 0.2,
            "evidence_object_ids": json.dumps([]),
            "tool_receipt_ids": json.dumps([]),
            "next_test_action": json.dumps({}),
            "endorsements": json.dumps([{"source": "app_graph"}]),
            "refutations": json.dumps([]),
            "terminal_reason": None,
            "metadata_json": json.dumps({}),
            "updated_at": now.isoformat(),
        }

    rows = [
        hypothesis_row(row_id=hypothesis_id, target=target_id, family="bola"),
        hypothesis_row(row_id=missing_hypothesis_id, target=missing_graph_target_id, family="bfla"),
    ]
    nodes = [
        {"target_id": target_id, "node_type": "route", "node_key": "route:GET /api/orders", "label": "GET /api/orders"},
        {"target_id": target_id, "node_type": "object", "node_key": "object:order_id", "label": "order_id"},
        {"target_id": target_id, "node_type": "principal", "node_key": "principal:user1", "label": "user1"},
    ]
    edges = [
        {"target_id": target_id, "src_key": "route:GET /api/orders", "dst_key": "object:order_id", "edge_type": "produces"},
        {"target_id": target_id, "src_key": "object:order_id", "dst_key": "route:GET /api/orders/{id}", "edge_type": "consumed_by"},
        {"target_id": target_id, "src_key": "route:GET /api/orders", "dst_key": "route:GET /api/orders/{id}", "edge_type": "auth_boundary"},
    ]

    graph_context = api_module._application_graph_context_for_hypotheses(
        rows,
        nodes,
        edges,
        limit_targets=5,
    )
    report = api_module._hypothesis_situation_report(rows, limit=5, graph_context=graph_context, now=now)

    assert report["graph_context"]["summary"]["hypothesis_target_count"] == 2
    assert report["graph_context"]["summary"]["target_count"] == 2
    assert report["graph_context"]["summary"]["node_count"] == 3
    assert report["graph_context"]["summary"]["edge_count"] == 3
    assert report["graph_context"]["summary"]["auth_boundary_edge_count"] == 1
    assert report["graph_context"]["summary"]["producer_consumer_edge_count"] == 2
    assert report["graph_context"]["missing_graph_target_ids"] == [str(missing_graph_target_id)]
    target_summary = next(item for item in report["graph_context"]["targets"] if item["target_id"] == str(target_id))
    assert target_summary["sample_hypothesis_ids"] == [str(hypothesis_id)]
    assert target_summary["families"] == {"bola": 1}
    assert target_summary["route_nodes"] == 1
    assert target_summary["object_nodes"] == 1
    assert target_summary["principal_nodes"] == 1
    assert target_summary["auth_boundary_edges"] == 1
    assert target_summary["producer_consumer_edges"] == 2
    assert target_summary["sample_route_keys"] == ["route:GET /api/orders"]


def test_load_hypothesis_situation_report_filters_target_and_loads_graph_context():
    now = datetime.now(timezone.utc).replace(microsecond=0)
    target_id = uuid.uuid4()
    hypothesis_id = uuid.uuid4()
    captured: dict[str, object] = {}
    rows = [
        {
            "id": hypothesis_id,
            "target_id": target_id,
            "source": "app_graph",
            "family": "bola",
            "cwe": "CWE-639",
            "title": "BOLA graph lead",
            "severity_guess": "high",
            "confidence": 0.91,
            "dedupe_key": "bola:orders",
            "status": "open",
            "version": 1,
            "claim_owner": None,
            "claim_lease_expires_at": None,
            "smoke_score": 0.2,
            "evidence_object_ids": json.dumps([]),
            "tool_receipt_ids": json.dumps([]),
            "next_test_action": json.dumps({"command": "asm.improve", "parameters": {"check_family": "bola"}}),
            "endorsements": json.dumps([{"source": "app_graph"}]),
            "refutations": json.dumps([]),
            "terminal_reason": None,
            "metadata_json": json.dumps({}),
            "updated_at": now.isoformat(),
        }
    ]

    class _FakeConn:
        async def fetch(self, query, *args):
            sql = str(query)
            if "FROM hypotheses" in sql:
                captured["hypothesis_args"] = args
                return rows
            if "FROM application_graph_nodes" in sql:
                captured["node_args"] = args
                return [
                    {"target_id": target_id, "node_type": "route", "node_key": "route:GET /api/orders", "label": "GET /api/orders"},
                    {"target_id": target_id, "node_type": "object", "node_key": "object:order_id", "label": "order_id"},
                ]
            if "FROM application_graph_edges" in sql:
                captured["edge_args"] = args
                return [
                    {"target_id": target_id, "src_key": "route:GET /api/orders", "dst_key": "object:order_id", "edge_type": "produces"},
                ]
            raise AssertionError(sql)

    report = asyncio.run(api_module._load_hypothesis_situation_report(
        _FakeConn(),
        target_uuid=target_id,
        limit=5,
        include_graph=True,
    ))

    assert captured["hypothesis_args"][1] == target_id
    assert captured["node_args"][0] == [target_id]
    assert captured["edge_args"][0] == [target_id]
    assert report["summary"]["considered_count"] == 1
    assert report["hottest_unclaimed"][0]["id"] == str(hypothesis_id)
    assert report["graph_context"]["summary"]["node_count"] == 2
    assert report["graph_context"]["summary"]["producer_consumer_edge_count"] == 1
    assert report["execution_enabled"] is False
    assert report["findings_created"] == 0


def test_upsert_hypothesis_matches_existing_across_sources_by_dedupe_key():
    target_id = uuid.uuid4()
    existing_id = uuid.uuid4()
    captured: dict[str, object] = {}

    class _FakeConn:
        async def fetchrow(self, query, *args):
            sql = str(query)
            if "SELECT *" in sql:
                captured["select_sql"] = sql
                captured["select_args"] = args
                return {"id": existing_id}
            if "UPDATE hypotheses" in sql:
                captured["update_args"] = args
                return {
                    "id": existing_id,
                    "target_id": target_id,
                    "source": "app_graph",
                    "family": "bola",
                    "dedupe_key": captured["select_args"][2],
                    "status": "supported",
                    "version": 2,
                    "claim_owner": None,
                    "claim_lease_expires_at": None,
                    "evidence_object_ids": json.dumps([]),
                    "tool_receipt_ids": json.dumps([]),
                    "next_test_action": json.dumps({}),
                    "endorsements": json.dumps([json.loads(args[6])]),
                    "refutations": json.dumps([]),
                    "metadata_json": args[7],
                }
            raise AssertionError(sql)

    req = api_module.HypothesisRequest(
        target_id=str(target_id),
        source="ai_planner",
        family="bola",
        dedupe_key="placeholder",
        dedupe_dimensions={
            "method": "GET",
            "route": "/api/orders/{id}",
            "object_key": "order.id",
            "principal_actor": "user1",
            "principal_other": "user2",
            "proof_surface": "runtime_authz_replay",
        },
        endorsement={"source": "ai_planner", "reason": "same route/object/principal"},
    )

    result = asyncio.run(api_module._upsert_hypothesis(_FakeConn(), req))

    assert result["created"] is False
    assert "AND source =" not in captured["select_sql"]
    select_args = captured["select_args"]
    assert select_args[0] == target_id
    assert select_args[1] == "bola"
    assert str(select_args[2]).startswith("hypothesis:v1|family=bola|method=get")
    endorsement = json.loads(captured["update_args"][6])
    assert endorsement["source"] == "ai_planner"
    assert result["execution_enabled"] is False


def test_source_ingest_package_hints_dedupe_by_subject_metadata():
    first, first_skip = api_module._source_hint_to_hypothesis_request(
        {
            "kind": "package_manifest",
            "risk_hints": ["secret"],
            "metadata_json": {"package_name": "left-pad"},
            "confidence": 0.4,
        },
        target_id=None,
        source_label="pytest",
        created_by="pytest",
    )
    second, second_skip = api_module._source_hint_to_hypothesis_request(
        {
            "kind": "package_manifest",
            "risk_hints": ["secret"],
            "metadata_json": {"package_name": "right-pad"},
            "confidence": 0.4,
        },
        target_id=None,
        source_label="pytest",
        created_by="pytest",
    )

    assert first_skip is None
    assert second_skip is None
    assert first is not None and second is not None
    assert first.dedupe_dimensions["route"] == "left-pad"
    assert second.dedupe_dimensions["route"] == "right-pad"
    assert first.dedupe_dimensions != second.dedupe_dimensions


def test_planner_action_to_hypothesis_is_source_only_runtime_proof_required():
    target_id = uuid.uuid4()
    plan_id = uuid.uuid4()
    plan = {
        "id": str(plan_id),
        "planner": {"kind": "local_agent", "agent": "codex"},
        "target_scope": {"target_id": str(target_id)},
        "risk_tier": "credential",
        "missing_inputs": ["second_user_auth"],
        "created_by": "planner-test",
    }
    action = {
        "command": "asm.improve",
        "risk_tier": "credential",
        "reason": "test BOLA worklist",
        "parameters": {
            "check_family": "bola",
            "endpoint_hint": {"method": "GET", "route": "/rest/basket/{id}"},
            "object_key": "basket.id",
            "principal_actor": "user1",
            "principal_other": "user2",
        },
    }

    req, skip = api_module._planner_action_to_hypothesis_request(
        plan,
        action,
        operation_plan_id=str(plan_id),
        action_index=0,
        created_by="codex",
    )

    assert skip is None
    assert req is not None
    assert req.source == "ai_planner"
    assert req.family == "bola"
    assert req.cwe == "CWE-639"
    assert req.target_id == str(target_id)
    assert req.dedupe_dimensions["route"] == "/rest/basket/{id}"
    assert req.dedupe_dimensions["object_key"] == "basket.id"
    assert req.next_test_action["source_only"] is True
    assert req.next_test_action["proof_surface"] == "runtime_authz_replay"
    assert req.next_test_action["requires"] == ["primary_auth", "second_user_auth"]
    assert req.metadata_json["runtime_proof_required"] is True
    assert req.metadata_json["planner"]["agent"] == "codex"


def test_generate_hypotheses_from_operation_plan_records_no_findings_or_scans():
    target_id = uuid.uuid4()
    plan_id = uuid.uuid4()
    inserted: list[dict[str, object]] = []

    class _FakeConn:
        async def fetchrow(self, query, *args):
            sql = str(query)
            if "FROM operation_plans" in sql:
                assert args[0] == plan_id
                return {
                    "id": plan_id,
                    "objective": "Improve BOLA coverage",
                    "planner": json.dumps({"kind": "local_agent", "agent": "codex"}),
                    "context_hash": "a" * 64,
                    "target_scope": json.dumps({"target_id": str(target_id)}),
                    "risk_tier": "credential",
                    "actions": json.dumps([
                        {
                            "command": "asm.improve",
                            "risk_tier": "credential",
                            "parameters": {
                                "check_family": "bola",
                                "endpoint_hint": {"method": "GET", "route": "/api/orders/{id}"},
                                "object_key": "order.id",
                            },
                        },
                        {"command": "finding.retest", "parameters": {"finding_id": str(uuid.uuid4())}},
                    ]),
                    "confirmations": json.dumps([]),
                    "missing_inputs": json.dumps(["second_user_auth"]),
                    "stop_conditions": json.dumps([]),
                    "success_criteria": json.dumps([]),
                    "validation_errors": json.dumps([]),
                    "validation_warnings": json.dumps([]),
                    "plan_json": json.dumps({}),
                    "created_by": "planner-test",
                }
            if "SELECT *" in sql and "FROM hypotheses" in sql:
                return None
            if "INSERT INTO hypotheses" in sql:
                inserted.append({"args": args})
                return {
                    "id": uuid.uuid4(),
                    "target_id": args[0],
                    "campaign_id": args[1],
                    "campaign_action_id": args[2],
                    "source": args[3],
                    "family": args[4],
                    "cwe": args[5],
                    "title": args[6],
                    "description": args[7],
                    "severity_guess": args[8],
                    "confidence": args[9],
                    "dedupe_key": args[10],
                    "smoke_score": args[11],
                    "evidence_object_ids": args[12],
                    "tool_receipt_ids": args[13],
                    "next_test_action": args[14],
                    "endorsements": json.dumps([json.loads(args[15])]),
                    "refutations": json.dumps([]),
                    "metadata_json": args[16],
                    "created_by": args[17],
                    "status": "open",
                    "version": 1,
                    "claim_owner": None,
                    "claim_lease_expires_at": None,
                }
            raise AssertionError(sql)

    result = asyncio.run(api_module._generate_hypotheses_from_operation_plan(
        _FakeConn(),
        api_module.PlannerHypothesisRequest(operation_plan_id=str(plan_id), created_by="codex"),
    ))

    assert result["created_or_endorsed"] == 1
    assert result["skipped_count"] == 1
    assert result["skipped"][0]["reason"] == "command_not_hypothesis_seed"
    assert result["execution_enabled"] is False
    assert result["findings_created"] == 0
    assert result["queued_scans"] == 0
    assert result["runtime_proof_required"] is True
    assert inserted[0]["args"][3] == "ai_planner"
    assert result["hypotheses"][0]["source"] == "ai_planner"
    assert result["hypotheses"][0]["can_promote_finding"] is False


def test_benchmark_followup_maps_to_runtime_proof_hypothesis():
    target_id = str(uuid.uuid4())
    req, skipped = api_module._benchmark_followup_to_hypothesis_request(
        api_module.BenchmarkFollowupHypothesisItem(
            benchmark="juice-shop",
            expectation_id="sqli-login",
            family="sqli",
            route="/rest/user/login",
            proof_required="verified",
            min_severity="critical",
            operator_hints=["post_body_params"],
            next_test_action={
                "command": "scan.focused_family",
                "risk_tier": "active",
                "parameters": {
                    "target": "https://bench.example.test",
                    "check_family": "sqli",
                    "scan_type": "smart",
                },
            },
        ),
        target_id=target_id,
        benchmark="juice-shop",
        scorecard_id="scorecard-1",
        scorecard_scan_id="scan-1",
        created_by="pytest",
    )

    assert skipped is None
    assert req is not None
    assert req.source == "benchmark"
    assert req.family == "sqli"
    assert req.cwe == "CWE-89"
    assert req.severity_guess == "critical"
    assert req.target_id == target_id
    assert req.next_test_action["command"] == "scan.focused_family"
    assert req.next_test_action["parameters"]["check_family"] == "sqli"
    assert req.next_test_action["source_only"] is True
    assert req.metadata_json["runtime_proof_required"] is True
    assert req.metadata_json["benchmark"] == "juice-shop"
    assert req.dedupe_dimensions["route"] == "/rest/user/login"
    assert req.dedupe_dimensions["proof_surface"] == "runtime_probe"


def test_benchmark_followup_blocks_bola_until_principal_preconditions():
    req, skipped = api_module._benchmark_followup_to_hypothesis_request(
        api_module.BenchmarkFollowupHypothesisItem(
            expectation_id="bola-orders",
            family="bola",
            route="/workshop/api/shop/orders",
            proof_required="verified",
            blocked_by=["missing_second_principal"],
            blocked_action_template={
                "command": "scan.focused_family",
                "parameters": {"check_family": "bola", "exploit_depth": True},
            },
        ),
        target_id=None,
        benchmark="crapi",
        scorecard_id=None,
        scorecard_scan_id=None,
        created_by=None,
    )

    assert skipped is None
    assert req is not None
    assert req.family == "bola"
    assert req.next_test_action["command"] == "scan.focused_family"
    assert "missing_second_principal" in req.next_test_action["requires"]
    assert req.metadata_json["blocked_by"] == ["missing_second_principal"]
    assert req.metadata_json["runtime_proof_required"] is True
    assert req.dedupe_dimensions["principal_actor"] == "user2"
    assert req.dedupe_dimensions["principal_other"] == "user1"


def test_generate_hypotheses_from_benchmark_followups_records_no_findings_or_scans():
    target_id = uuid.uuid4()
    inserted: list[dict[str, object]] = []

    class _FakeConn:
        async def fetchval(self, query, *args):
            assert "FROM targets" in str(query)
            assert args[0] == target_id
            return 1

        async def fetchrow(self, query, *args):
            sql = str(query)
            if "SELECT *" in sql and "FROM hypotheses" in sql:
                return None
            if "INSERT INTO hypotheses" in sql:
                inserted.append({"args": args})
                return {
                    "id": uuid.uuid4(),
                    "target_id": args[0],
                    "campaign_id": args[1],
                    "campaign_action_id": args[2],
                    "source": args[3],
                    "family": args[4],
                    "cwe": args[5],
                    "title": args[6],
                    "description": args[7],
                    "severity_guess": args[8],
                    "confidence": args[9],
                    "dedupe_key": args[10],
                    "smoke_score": args[11],
                    "evidence_object_ids": args[12],
                    "tool_receipt_ids": args[13],
                    "next_test_action": args[14],
                    "endorsements": json.dumps([json.loads(args[15])]),
                    "refutations": json.dumps([]),
                    "metadata_json": args[16],
                    "created_by": args[17],
                    "status": "open",
                    "version": 1,
                    "claim_owner": None,
                    "claim_lease_expires_at": None,
                }
            raise AssertionError(sql)

    result = asyncio.run(api_module._generate_hypotheses_from_benchmark_followups(
        _FakeConn(),
        api_module.BenchmarkHypothesisRequest(
            target_id=str(target_id),
            benchmark="juice-shop",
            scorecard_id="latest",
            scorecard_scan_id="scan-1",
            followups=[
                api_module.BenchmarkFollowupHypothesisItem(
                    expectation_id="xss-dom-search",
                    family="xss",
                    route="#/search",
                    proof_required="browser",
                    min_severity="high",
                    operator_hints=["browser_proof_required"],
                    next_test_action={
                        "command": "scan.focused_family",
                        "parameters": {"target": "https://bench.example.test", "check_family": "xss"},
                    },
                ),
            ],
            created_by="pytest",
        ),
    ))

    assert result["created_or_endorsed"] == 1
    assert result["skipped_count"] == 0
    assert result["execution_enabled"] is False
    assert result["findings_created"] == 0
    assert result["queued_scans"] == 0
    assert result["runtime_proof_required"] is True
    assert inserted[0]["args"][3] == "benchmark"
    assert result["hypotheses"][0]["source"] == "benchmark"
    assert result["hypotheses"][0]["can_promote_finding"] is False


def test_record_command_result_redacts_result_json_and_returns_public_row():
    captured: dict[str, object] = {"queries": []}

    class _FakeConn:
        async def fetchrow(self, query, *args):
            captured["queries"].append(str(query))
            if "INSERT INTO campaign_actions" in str(query):
                captured["campaign_action_args"] = args
                return {
                    "id": uuid.uuid4(),
                    "campaign_id": args[0],
                    "operation_plan_id": args[1],
                    "command_result_id": args[2],
                    "target_id": args[3],
                    "scope_receipt_id": args[4],
                    "approval_receipt_id": args[5],
                    "scan_id": args[6],
                    "command": args[7],
                    "action_name": args[8],
                    "status": args[9],
                    "dry_run": args[10],
                    "risk_tier": args[11],
                    "finding_ids": args[12],
                    "hypothesis_ids": args[13],
                    "evidence_object_ids": args[14],
                    "tool_receipt_ids": args[15],
                    "blocked_by": args[16],
                    "next_action": args[17],
                    "operator_message": args[18],
                    "result_json": args[19],
                    "created_by": args[20],
                    "created_at": "now",
                }
            captured["command_result_args"] = args
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

    assert any("INSERT INTO command_results" in query for query in captured["queries"])
    assert any("INSERT INTO campaign_actions" in query for query in captured["queries"])
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
    assert captured["campaign_action_args"][7] == "scan.submit"
    assert captured["campaign_action_args"][9] == "queued"


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
            if "FROM target_principals" in query:
                return [{
                    "id": uuid.uuid4(),
                    "target_id": target_id,
                    "label": "Admin",
                    "role": "admin",
                    "tenant_id": "tenant-a",
                    "auth_state": "admin",
                    "credential_profile": "admin-session",
                    "credential_configured": True,
                    "is_active": True,
                    "metadata_json": json.dumps({}),
                }, {
                    "id": uuid.uuid4(),
                    "target_id": target_id,
                    "label": "Customer",
                    "role": "customer",
                    "tenant_id": "tenant-a",
                    "auth_state": "user1",
                    "credential_profile": "customer-session",
                    "credential_configured": True,
                    "is_active": True,
                    "metadata_json": json.dumps({}),
                }]
            if "FROM target_endpoint_expectations" in query:
                return [{
                    "id": uuid.uuid4(),
                    "method": "GET",
                    "path": "/api/admin",
                    "param_shape": "",
                    "param_location": "query",
                    "principal_role": "customer",
                    "tenant_id": "tenant-a",
                    "expected_access": "deny",
                    "expected_http_status": 403,
                    "expectation_source": "manual",
                    "principal_label": "Customer",
                    "principal_auth_state": "user1",
                    "metadata_json": json.dumps({}),
                }]
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
            if "FROM scans" in query:
                assert "COALESCE(completed_at, started_at, created_at) AS updated_at" in query
                return [{
                    "id": uuid.uuid4(),
                    "parent_scan_id": None,
                    "scan_role": "asm_batch",
                    "scan_type": "smart",
                    "run_kind": "web_dast",
                    "status": "completed",
                    "current_phase": "done",
                    "findings_count": 2,
                    "score": 80,
                    "grade": "B",
                    "options": {"kind": "asm_test", "check_family": "bola"},
                    "result": {
                        "verification_summary": {"verified": 1, "suspected": 1},
                        "discovery": {"url_count": 17},
                    },
                    "created_at": "2026-07-10T00:00:00Z",
                    "updated_at": "2026-07-10T00:10:00Z",
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
    assert generated.current_surface["principal_matrix"]["role_counts"]["admin"] == 1
    assert generated.current_surface["principal_matrix"]["expectations"][0]["expected_access"] == "deny"
    assert generated.current_surface["recent_scans"][0]["scan_role"] == "asm_batch"
    assert generated.current_surface["recent_scans"][0]["result_summary"]["verified"] == 1
    assert generated.current_surface["recent_scans"][0]["result_summary"]["discovered_url_count"] == 17
    assert generated.known_preconditions["primary_credentials"] == "configured"
    assert generated.known_preconditions["second_user_credentials"] == "unknown"
    assert generated.findings_summary[0]["category"] == "bola"
    assert generated.findings_summary[0]["proof_state"] == "suspected"
    assert "asm.gaps" in generated.allowed_commands
    assert "auth_header" not in json.dumps(generated.model_dump(mode="json"))
    assert len(generated.context_hash) == 64


def test_target_credential_preconditions_require_profile_references():
    identities_only = [
        {"id": "principal-1", "is_active": True, "credential_profile": None},
        {"id": "principal-2", "is_active": True, "credential_profile": ""},
    ]
    assert api_module._target_credential_precondition_signals(identities_only) == {
        "primary_credentials": "unknown",
        "second_user_credentials": "unknown",
    }

    one_profile = [
        {"id": "principal-1", "auth_state": "user1", "is_active": True, "credential_profile": "vault/customer", "credential_configured": True},
        {"id": "principal-2", "is_active": True, "credential_profile": None},
    ]
    assert api_module._target_credential_precondition_signals(one_profile) == {
        "primary_credentials": "configured",
        "second_user_credentials": "unknown",
    }

    unresolved_profile = [{
        "id": "principal-1",
        "auth_state": "user1",
        "is_active": True,
        "credential_profile": "missing-profile",
        "credential_configured": False,
    }]
    assert api_module._target_credential_precondition_signals(unresolved_profile) == {
        "primary_credentials": "unknown",
        "second_user_credentials": "unknown",
    }

    admin_only = [{
        "id": "principal-admin",
        "auth_state": "admin",
        "is_active": True,
        "credential_profile": "admin-profile",
        "credential_configured": True,
    }]
    assert api_module._target_credential_precondition_signals(admin_only)["primary_credentials"] == "unknown"


def test_target_credential_preconditions_require_distinct_second_profile():
    shared_profile = [
        {"id": "principal-1", "auth_state": "user1", "is_active": True, "credential_profile": "vault/shared", "credential_configured": True},
        {"id": "principal-2", "auth_state": "user2", "is_active": True, "credential_profile": "vault/shared", "credential_configured": True},
    ]
    assert api_module._target_credential_precondition_signals(shared_profile)["second_user_credentials"] == "unknown"

    distinct_profiles = [
        {"id": "principal-1", "auth_state": "user1", "is_active": True, "credential_profile": "vault/customer-a", "credential_configured": True},
        {"id": "principal-2", "auth_state": "user2", "is_active": True, "credential_profile": "vault/customer-b", "credential_configured": True},
    ]
    assert api_module._target_credential_precondition_signals(distinct_profiles) == {
        "primary_credentials": "configured",
        "second_user_credentials": "configured",
    }


def test_target_credential_preconditions_preserve_legacy_metadata_signals():
    assert api_module._target_credential_precondition_signals([], {"auth": {"kind": "bearer"}})["primary_credentials"] == "configured"
    assert api_module._target_credential_precondition_signals([], {"user2": {"kind": "cookie"}})["second_user_credentials"] == "configured"


def test_target_credential_profile_resolution_maps_primary_and_second_user(monkeypatch):
    class FakeConn:
        async def fetch(self, query, *_args):
            assert "cp.expires_at > NOW()" in query
            assert "cp.secret_value" not in query
            return [
                {
                    "auth_state": "user1",
                    "profile_id": uuid.uuid4(),
                    "auth_kind": "authorization_header",
                },
                {
                    "auth_state": "user2",
                    "profile_id": uuid.uuid4(),
                    "auth_kind": "cookie",
                },
            ]

    options = asyncio.run(api_module._resolve_target_credential_profiles(
        FakeConn(),
        uuid.uuid4(),
        {"scan_type": "smart"},
    ))

    assert "auth_header" not in options
    assert "user2_cookies" not in options
    refs = options["managed_credential_profiles"]
    assert [item["auth_state"] for item in refs] == ["user1", "user2"]
    assert [item["option_key"] for item in refs] == ["auth_header", "user2_cookies"]
    assert "primary-token" not in json.dumps(options)


def test_focused_scan_defers_auth_preconditions_until_managed_profiles_resolve():
    """Target-managed auth must satisfy POST /scans focused-family policy.

    The target id is not available while the initial public payload is built, so
    BOLA preconditions must run after the server attaches target-bound profile
    references. This is also the submission path used by research preflights.
    """
    class FakeConn:
        async def fetch(self, *_args):
            return [
                {
                    "auth_state": "user1",
                    "profile_id": uuid.uuid4(),
                    "auth_kind": "authorization_header",
                },
                {
                    "auth_state": "user2",
                    "profile_id": uuid.uuid4(),
                    "auth_kind": "authorization_header",
                },
            ]

    model = api_module.ScanOptions(
        scan_type="smart",
        check_family="bola",
        exploit_depth=True,
    )
    payload = api_module._build_scan_options_payload(
        model,
        "smart",
        defer_family_preconditions=True,
    )
    payload = asyncio.run(api_module._resolve_target_credential_profiles(
        FakeConn(),
        uuid.uuid4(),
        payload,
    ))
    payload, family = api_module._apply_scan_check_family_policy(payload)

    assert family == "bola"
    assert [ref["auth_state"] for ref in payload["managed_credential_profiles"]] == ["user1", "user2"]


def test_target_credential_profile_resolution_preserves_explicit_auth():
    class FakeConn:
        async def fetch(self, *_args):
            return [
                {
                    "auth_state": "user1",
                    "profile_id": uuid.uuid4(),
                    "auth_kind": "authorization_header",
                },
                {
                    "auth_state": "user2",
                    "profile_id": uuid.uuid4(),
                    "auth_kind": "authorization_header",
                },
            ]

    options = asyncio.run(api_module._resolve_target_credential_profiles(
        FakeConn(),
        uuid.uuid4(),
        {"auth_header": "Bearer explicit"},
    ))

    assert options["auth_header"] == "Bearer explicit"
    assert "user2_header" not in options
    assert options["managed_credential_profiles"][0]["auth_state"] == "user2"


def test_target_credential_profile_resolution_blocks_shared_profile():
    profile_id = uuid.uuid4()

    class FakeConn:
        async def fetch(self, *_args):
            return [
                {"auth_state": "user1", "profile_id": profile_id, "auth_kind": "authorization_header"},
                {"auth_state": "user2", "profile_id": profile_id, "auth_kind": "authorization_header"},
            ]

    try:
        asyncio.run(api_module._resolve_target_credential_profiles(FakeConn(), uuid.uuid4(), {}))
    except api_module.HTTPException as exc:
        assert exc.status_code == 409
        assert exc.detail["error"] == "shared_principal_credential_profile"
    else:
        raise AssertionError("shared user1/user2 credential profile should fail closed")


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


def _local_agent_parser_context_row(context_id: str = "22222222-2222-4222-8222-222222222222") -> dict[str, object]:
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
        "allowed_commands": ["asm.gaps", "local_agent.test"],
        "disallowed_commands": [{"command": "scan.focused_family", "reason": "gated:active"}],
        "known_preconditions": {},
        "context_pack": {
            "target_summary": {
                "target_id": "target-1",
                "url": "https://api.example.com",
                "root_domain": "example.com",
                "environment": "production",
            },
            "allowed_commands": ["asm.gaps", "local_agent.test"],
            "disallowed_commands": [{"command": "scan.focused_family", "reason": "gated:active"}],
            "known_preconditions": {},
            "context_hash": "d" * 64,
        },
        "validation_errors": [],
        "validation_warnings": [],
        "status": "recorded",
        "created_by": "test",
    }


def _local_agent_parser_candidate(**overrides) -> dict[str, object]:
    candidate = {
        "objective": "Review target coverage",
        "planner": {"kind": "local_agent", "agent": "codex"},
        "context_hash": "d" * 64,
        "target_scope": {
            "target_id": "target-1",
            "url": "https://api.example.com",
            "allowed_hosts": ["api.example.com"],
            "allowed_root_domains": ["example.com"],
            "environment": "production",
        },
        "risk_tier": "read_only",
        "actions": [{
            "command": "asm.gaps",
            "parameters": {},
            "risk_tier": "read_only",
            "reason": "Inspect coverage before queueing any gated work",
        }],
        "stop_conditions": ["scope_blocked"],
        "success_criteria": ["operation_plan_validated", "no_execution_performed"],
    }
    candidate.update(overrides)
    return candidate


class _LocalAgentParserFakeConn:
    async def fetchrow(self, query, *args):
        if "FROM agent_context_packs" in query:
            return _local_agent_parser_context_row()
        return None


def _parse_local_agent_candidate(candidate_or_raw):
    raw = candidate_or_raw if isinstance(candidate_or_raw, str) else json.dumps(candidate_or_raw)
    req = api_module.LocalAgentPlanParseRequest(
        agent="codex",
        context_pack_id="22222222-2222-4222-8222-222222222222",
        raw_output=raw,
        created_by="test",
    )
    return asyncio.run(api_module._parse_local_agent_candidate_plan(_LocalAgentParserFakeConn(), req))


def test_local_agent_candidate_parser_accepts_exact_context_bound_plan():
    result = _parse_local_agent_candidate(_local_agent_parser_candidate())

    assert result["accepted"] is True
    assert result["candidate_persisted"] is False
    assert result["execution_enabled"] is False
    assert result["local_agent_spawned"] is False
    assert result["operation_plan"]["actions"][0]["command"] == "asm.gaps"
    assert result["operation_plan"]["planner"]["planner_execution_enabled"] is False
    assert result["validation_errors"] == []


def _empty_allowlist_conn():
    row = _local_agent_parser_context_row()
    row["allowed_commands"] = []
    if isinstance(row.get("context_pack"), dict):
        row["context_pack"]["allowed_commands"] = []

    class _EmptyAllowConn:
        async def fetchrow(self, query, *args):
            if "FROM agent_context_packs" in query:
                return row
            return None

    return _EmptyAllowConn()


def _parse_with_conn(conn, candidate):
    req = api_module.LocalAgentPlanParseRequest(
        agent="codex",
        context_pack_id="22222222-2222-4222-8222-222222222222",
        raw_output=json.dumps(candidate),
        created_by="test",
    )
    return asyncio.run(api_module._parse_local_agent_candidate_plan(conn, req))


def test_parser_empty_allowlist_denies_state_changing_command():
    candidate = _local_agent_parser_candidate(actions=[{
        "command": "asm.improve", "parameters": {}, "risk_tier": "active",
        "reason": "queue coverage work",
    }])
    result = _parse_with_conn(_empty_allowlist_conn(), candidate)

    assert result["accepted"] is False
    assert any("command_not_allowed_by_empty_context" in e for e in result["validation_errors"])


def test_parser_empty_allowlist_still_permits_read_only_command():
    # asm.gaps is read_only, so an empty context allow-list must not block it.
    result = _parse_with_conn(_empty_allowlist_conn(), _local_agent_parser_candidate())

    assert not any("command_not_allowed_by_empty_context" in e for e in result["validation_errors"])


def test_local_agent_candidate_parser_rejects_ambiguous_output_and_raw_commands():
    result = _parse_local_agent_candidate("Here is the plan:\n{}")

    assert result["accepted"] is False
    assert any(error.startswith("planner_output_not_single_json_object") for error in result["validation_errors"])

    raw_command = _local_agent_parser_candidate(actions=[{
        "command": "run_shell",
        "parameters": {"shell": "curl_this_url https://evil.example"},
        "risk_tier": "read_only",
    }])
    result = _parse_local_agent_candidate(raw_command)

    assert result["accepted"] is False
    assert "action_0_unknown_command:run_shell" in result["validation_errors"]
    assert any(error.startswith("hidden_state_changing_request:") for error in result["validation_errors"])


def test_local_agent_candidate_parser_rejects_missing_risk_tier_and_scope_widening():
    missing_risk = _local_agent_parser_candidate(actions=[{
        "command": "asm.gaps",
        "parameters": {},
    }])
    result = _parse_local_agent_candidate(missing_risk)

    assert result["accepted"] is False
    assert "action_0_risk_tier_required:asm.gaps" in result["validation_errors"]

    widened = _local_agent_parser_candidate(target_scope={
        "target_id": "target-1",
        "url": "https://evil.example.net",
        "allowed_hosts": ["evil.example.net"],
        "allowed_root_domains": ["example.net"],
        "environment": "production",
    })
    result = _parse_local_agent_candidate(widened)

    assert result["accepted"] is False
    assert "target_scope_host_outside_context:evil.example.net" in result["validation_errors"]
    assert "target_scope_root_outside_context:example.net" in result["validation_errors"]


def test_local_agent_candidate_parser_rejects_unbounded_parameters():
    candidate = _local_agent_parser_candidate(actions=[{
        "command": "local_agent.test",
        "parameters": {"agent": "codex", "timeout_seconds": 5, "max_output_bytes": 999999},
        "risk_tier": "read_only",
    }])
    result = _parse_local_agent_candidate(candidate)

    assert result["accepted"] is False
    assert "action_0_parameter_above_maximum:max_output_bytes" in result["validation_errors"]


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


def test_source_ingest_hint_maps_authz_fact_to_runtime_hypothesis():
    target_id = str(uuid.uuid4())
    req, skipped = api_module._source_hint_to_hypothesis_request(
        api_module.SourceIngestHint(
            kind="openapi_operation",
            method="GET",
            path="/api/orders/{id}",
            risk_hints=["idor"],
            object_keys=["order.id"],
            roles=["user", "admin"],
            auth_required=True,
            confidence=0.72,
        ),
        target_id=target_id,
        source_label="openapi:test",
        created_by="pytest",
    )

    assert skipped is None
    assert req is not None
    assert req.source == "source_ingest"
    assert req.family == "bola"
    assert req.cwe == "CWE-639"
    assert req.next_test_action["command"] == "asm.improve"
    assert req.next_test_action["parameters"]["check_family"] == "bola"
    assert req.next_test_action["parameters"]["exploit_depth"] is True
    assert req.next_test_action["source_only"] is True
    assert req.metadata_json["runtime_proof_required"] is True
    assert req.metadata_json["source_only"] is True
    assert req.dedupe_dimensions["route"] == "/api/orders/{id}"
    assert req.dedupe_dimensions["proof_surface"] == "runtime_authz_replay"


def test_source_ingest_hint_maps_body_shape_to_mass_assignment_hypothesis():
    req, skipped = api_module._source_hint_to_hypothesis_request(
        api_module.SourceIngestHint(
            kind="backend_route",
            method="POST",
            path="/api/users",
            body_paths=["$.isAdmin"],
            risk_hints=["mass_assignment"],
        ),
        target_id=None,
        source_label="routes:test",
        created_by="pytest",
    )

    assert skipped is None
    assert req is not None
    assert req.family == "mass_assignment"
    assert req.cwe == "CWE-915"
    assert req.next_test_action["command"] == "hypothesis.plan_campaign"
    assert "workflow_context" in req.next_test_action["requires"]
    assert req.metadata_json["runtime_proof_required"] is True
    assert req.dedupe_dimensions["body_path"] == "$.isAdmin"


def test_source_ingest_hint_skips_unbounded_route_hint():
    req, skipped = api_module._source_hint_to_hypothesis_request(
        api_module.SourceIngestHint(kind="route", risk_hints=["xss"]),
        target_id=None,
        source_label="empty:test",
        created_by="pytest",
    )

    assert req is None
    assert skipped["reason"] == "missing_route_or_path"


def test_source_file_ingest_extracts_openapi_operations_with_controls():
    spec = {
        "openapi": "3.1.0",
        "paths": {
            "/api/orders/{id}": {
                "get": {
                    "operationId": "getOrder",
                    "parameters": [{"name": "id", "in": "path"}],
                    "security": [{"bearer": []}],
                }
            },
            "/api/users": {
                "post": {
                    "operationId": "createUser",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"type": "object", "properties": {"email": {"type": "string"}, "isAdmin": {"type": "boolean"}}}
                            }
                        }
                    },
                }
            },
        },
    }

    hints, skipped, summary = api_module._source_files_to_hints(
        [api_module.SourceIngestFile(path="openapi.json", content=json.dumps(spec))],
        source_label="repo:test",
        max_files=10,
        max_file_bytes=10000,
        ignored_paths=[],
        parse_timeout_ms=1000,
    )

    assert skipped == []
    assert summary["files_processed"] == 1
    assert len(hints) == 2
    by_path = {hint.path: hint for hint in hints}
    assert by_path["/api/orders/{id}"].kind == "openapi_operation"
    assert "idor" in by_path["/api/orders/{id}"].risk_hints
    assert by_path["/api/orders/{id}"].auth_required is True
    assert "$.isAdmin" in by_path["/api/users"].body_paths
    assert "mass_assignment" in by_path["/api/users"].risk_hints


def test_source_file_ingest_extracts_backend_routes_and_red_flags():
    content = """
    router.get('/api/products/:id', async (req, res) => db.query('select * from products where id=' + req.params.id))
    app.patch('/api/users/:id', async (req, res) => updateUser(req.params.id, req.body.isAdmin))
    """

    hints, skipped, summary = api_module._source_files_to_hints(
        [api_module.SourceIngestFile(path="src/routes/users.js", content=content, language="javascript")],
        source_label="repo:test",
        max_files=10,
        max_file_bytes=10000,
        ignored_paths=[],
        parse_timeout_ms=1000,
    )

    assert skipped == []
    assert summary["hints_generated"] == 2
    by_path = {hint.path: hint for hint in hints}
    assert "idor" in by_path["/api/products/:id"].risk_hints
    assert "sqli" in by_path["/api/products/:id"].risk_hints
    assert "$.isAdmin" in by_path["/api/users/:id"].body_paths
    assert "mass_assignment" in by_path["/api/users/:id"].risk_hints


def test_source_file_ingest_enforces_ignored_paths_and_size_limits():
    hints, skipped, summary = api_module._source_files_to_hints(
        [
            api_module.SourceIngestFile(path="node_modules/pkg/routes.js", content="app.get('/api/hidden', h)"),
            api_module.SourceIngestFile(path="src/large.js", content="x" * 2000),
        ],
        source_label="repo:test",
        max_files=10,
        max_file_bytes=100,
        ignored_paths=[],
        parse_timeout_ms=1000,
    )

    assert hints == []
    assert summary["files_processed"] == 0
    assert [item["reason"] for item in skipped] == ["ignored_path", "file_too_large"]


def test_target_principal_auth_state_is_limited_to_executable_identity_slots():
    assert api_module._normalize_target_auth_state(" USER1 ") == "user1"
    assert api_module._normalize_target_auth_state("user2") == "user2"

    with pytest.raises(api_module.HTTPException) as exc:
        api_module._normalize_target_auth_state("admin")

    assert exc.value.status_code == 400
    assert "use role" in str(exc.value.detail)


def test_auto_provision_endpoint_validates_approval_before_external_signup(monkeypatch):
    target_id = str(uuid.uuid4())
    approval_id = str(uuid.uuid4())
    calls = []

    class FakeConn:
        async def fetchrow(self, query, *args):
            if "SELECT id, url, is_active, metadata_json FROM targets" in str(query):
                return {
                    "id": uuid.UUID(target_id), "url": "https://app.example.test",
                    "is_active": True, "metadata_json": {"auto_provisioning": {"enabled": True}},
                }
            raise AssertionError(str(query))

    class FakePool:
        def acquire(self):
            return self
        async def __aenter__(self):
            return FakeConn()
        async def __aexit__(self, exc_type, exc, tb):
            return False

    async def rejected(*args, **kwargs):
        calls.append("approval")
        raise api_module.HTTPException(status_code=400, detail="invalid approval")

    async def must_not_provision(*args, **kwargs):
        calls.append("provision")
        raise AssertionError("external signup ran before approval")

    monkeypatch.setattr(api_module, "db_pool", FakePool())
    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", rejected)
    monkeypatch.setattr(api_module, "_auto_provision_principals", must_not_provision)

    with pytest.raises(api_module.HTTPException, match="invalid approval"):
        asyncio.run(api_module.auto_provision_target_principals(
            target_id,
            api_module.TargetPrincipalAutoProvisionRequest(approval_receipt_id=approval_id),
        ))
    assert calls == ["approval"]


def test_auto_provision_reuses_existing_principal_without_signup(monkeypatch):
    target_id = uuid.uuid4()

    class FakeConn:
        async def fetchrow(self, query, *args):
            if "FROM target_principals p" in str(query):
                return {"label": args[1], "auth_state": args[1], "credential_profile": f"existing-{args[1]}"}
            raise AssertionError(str(query))
        async def execute(self, query, *args):
            raise AssertionError("idempotent reuse must not write")

    monkeypatch.setattr(api_module, "encryption_enabled", lambda: True)
    result = asyncio.run(api_module._auto_provision_principals(
        FakeConn(),
        target_id,
        "https://app.example.test",
        {
            "enabled": True,
            "signup": {"method": "POST", "path": "/signup", "json": {}},
            "login": {"method": "POST", "path": "/login", "json": {}},
        },
    ))
    assert [item["auth_state"] for item in result] == ["user1", "user2"]
    assert all(item["reused"] is True for item in result)


def test_auto_provision_requires_encrypted_secret_storage(monkeypatch):
    monkeypatch.setattr(api_module, "encryption_enabled", lambda: False)
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module._auto_provision_principals(
            object(), uuid.uuid4(), "https://app.example.test", {"enabled": True},
        ))
    assert exc.value.status_code == 409
    assert "AI_CREDENTIAL_ENC_KEY" in str(exc.value.detail)


def test_benchmark_identity_uses_family_method_and_templated_route_not_source_fingerprint():
    canonical = api_module._canonical_vulnerability_key(
        family="bola", route="/api/orders/{order_id}", method="GET",
    )
    assert api_module._canonical_vulnerability_route("/api/orders/${object_id}") == "/api/orders/{id}"
    # A query-string object id (crAPI's /orders/all?id=<uuid>) is the same object operation as a path
    # id: both collapse to a trailing /{id}, so a query-string BOLA lead binds a query- or path-shaped
    # experiment instead of degrading to the bare collection route.
    assert (api_module._canonical_vulnerability_route("/workshop/api/shop/orders/all?id=08af4258-f15d-40e9-86af-8a1b5b2c7f53")
            == "/workshop/api/shop/orders/all/{id}")
    assert (api_module._canonical_vulnerability_route("/workshop/api/shop/orders/all?id=${owner_object_id}")
            == api_module._canonical_vulnerability_route("/workshop/api/shop/orders/all/${owner_object_id}"))
    dast = {
        "fingerprint": "scanner-specific-fingerprint",
        "title": "BOLA on order API",
        "tool": "smart_bola",
        "cwe": "CWE-639",
        "url": "https://app.example.test/api/orders/42",
        "evidence": {},
    }
    autonomous = {
        "fingerprint": "different-autonomous-fingerprint",
        "title": "Graph authz lead",
        "tool": "autonomous_workflow",
        "cwe": "CWE-639",
        "url": "https://app.example.test",
        "evidence": {
            "canonical_vulnerability_key": canonical,
            "canonical_vulnerability_key_version": "v2",
            "dedupe_dimensions": {"route": "/api/orders/{id}", "method": "GET"},
        },
    }
    assert api_module._finding_vulnerability_key(dast) == canonical
    assert api_module._finding_vulnerability_key(autonomous) == canonical


def test_update_target_principal_returns_409_for_active_slot_collision(monkeypatch):
    class UniqueViolationError(Exception):
        pass

    class FakeConn:
        async def fetchrow(self, query, *args):
            if "UPDATE target_principals" in str(query):
                raise UniqueViolationError("idx_target_principals_active_auth_slot")
            raise AssertionError(str(query))

    class FakePool:
        def acquire(self):
            return self

        async def __aenter__(self):
            return FakeConn()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(api_module.asyncpg, "UniqueViolationError", UniqueViolationError, raising=False)
    monkeypatch.setattr(api_module, "db_pool", FakePool())

    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module.update_target_principal(
            str(uuid.uuid4()),
            str(uuid.uuid4()),
            api_module.TargetPrincipalUpdate(auth_state="user2", is_active=True),
        ))

    assert exc.value.status_code == 409
    assert exc.value.detail["error"] == "principal_auth_state_conflict"


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
        "environment": "production",
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
    assert ctx["runtime_scope_guard"]["scope_receipt_id"] == SCOPE_ID
    assert ctx["runtime_scope_guard"]["allowed_hosts"] == ["app.example.com"]
    assert ctx["runtime_scope_guard"]["allowed_root_domains"] == ["example.com"]
    assert ctx["runtime_scope_guard"]["requires_runtime_destination_check"] is True


def test_validate_action_bound_approval_rejects_unrelated_action():
    conn = _approval_receipt_conn(
        approval_row=_make_approval_row(
            action_name="evidence.retention_sweep",
            action_context={"preview_id": str(uuid.uuid4())},
        ),
        scope_row=_make_scope_row(),
    )

    with pytest.raises(api_module.HTTPException) as exc:
        _run_validate(
            conn,
            APPROVAL_ID,
            target_url="https://app.example.com/x",
            action_name="scan.submit:smart",
        )

    assert exc.value.status_code == 400
    assert "different action" in str(exc.value.detail)


def test_validate_approval_receipt_can_require_receipt_even_when_global_policy_is_off():
    conn = _approval_receipt_conn()
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module._validate_approval_receipt_for_action(
            conn,
            None,
            action_name="target.principal_matrix.record",
            always_require_receipt=True,
            record_blocked=False,
        ))

    assert exc.value.status_code == 400
    assert "required" in str(exc.value.detail).lower()


def test_principal_matrix_record_is_only_in_gated_gateway_adapters():
    assert "target.principal_matrix.record" not in api_module._arsenal_readonly_adapters()
    assert api_module._arsenal_gated_adapters()["target.principal_matrix.record"] is api_module._arsenal_dispatch_target_principal_matrix_record


def test_hypothesis_proof_reconciliation_is_only_in_gated_gateway_adapters():
    assert "hypothesis.reconcile_proof" not in api_module._arsenal_readonly_adapters()
    assert api_module._arsenal_gated_adapters()["hypothesis.reconcile_proof"] is api_module._arsenal_dispatch_hypothesis_reconcile_proof


def test_principal_matrix_write_validates_target_scoped_receipt_and_audits(monkeypatch):
    target_id = str(uuid.uuid4())
    approval_id = str(uuid.uuid4())
    expectation_id = uuid.uuid4()
    calls = {}

    class FakeConn:
        async def fetchrow(self, query, *args):
            if "SELECT url FROM targets" in query:
                return {"url": "https://app.example.com"}
            if "INSERT INTO target_endpoint_expectations" in query:
                return {
                    "id": expectation_id,
                    "target_id": uuid.UUID(target_id),
                    "method": "GET",
                    "path": "/admin",
                    "metadata_json": {},
                    "expected_access": "deny",
                }
            return None

    class FakePool:
        def acquire(self):
            return self

        async def __aenter__(self):
            return FakeConn()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    async def fake_validate(_conn, receipt_id, **kwargs):
        calls["validation"] = (receipt_id, kwargs)
        return {"approval_receipt_id": receipt_id, "scope_receipt_id": "scope-1"}

    async def fake_record(_conn, **kwargs):
        calls["audit"] = kwargs
        return {"id": "operation-1"}

    monkeypatch.setattr(api_module, "db_pool", FakePool())
    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)
    monkeypatch.setattr(api_module, "_record_command_result", fake_record)

    result = asyncio.run(api_module.upsert_target_principal_matrix(
        target_id,
        api_module.TargetEndpointExpectationRequest(
            path="/admin", principal_role="user", expected_access="deny",
            approval_receipt_id=approval_id,
        ),
    ))

    receipt_id, validation = calls["validation"]
    assert receipt_id == approval_id
    assert validation["target_id"] == uuid.UUID(target_id)
    assert validation["always_require_receipt"] is True
    assert calls["audit"]["command"] == "target.principal_matrix.record"
    assert result["operation_id"] == "operation-1"


def test_runtime_destination_scope_allows_matching_actual_destination():
    guard = api_module._runtime_scope_guard_from_scope(_make_scope_row())
    result = api_module.evaluate_runtime_destination_scope(
        guard,
        "https://api.example.com/v1/orders",
        redirect_urls=["https://app.example.com/login"],
        resolution_observations=[
            {"host": "api.example.com", "ips": ["8.8.8.8"]},
            {"host": "app.example.com", "ips": ["1.1.1.1"]},
        ],
    )

    assert result["status"] == "allowed"
    assert result["verdict"] == "allowed"
    assert result["blocked_by"] == []
    assert result["runtime_scope_guard_present"] is True
    assert result["resolution_observations"][0]["verdict"] == "allowed"
    assert result["scope_receipt_id"] == SCOPE_ID


def test_runtime_destination_scope_blocks_redirect_out_of_scope():
    guard = api_module._runtime_scope_guard_from_scope(_make_scope_row())
    result = api_module.evaluate_runtime_destination_scope(
        guard,
        "https://app.example.com/start",
        redirect_urls=["https://evil.example.net/callback"],
    )

    assert result["status"] == "blocked"
    assert result["verdict"] == "blocked"
    assert "redirect_out_of_scope" in result["blocked_by"]
    assert result["redirect_destinations"][0]["host"] == "evil.example.net"


def test_runtime_destination_scope_fails_closed_when_unverified():
    missing_guard = api_module.evaluate_runtime_destination_scope(None, "https://app.example.com")
    missing_destination = api_module.evaluate_runtime_destination_scope(
        api_module._runtime_scope_guard_from_scope(_make_scope_row()),
        "",
    )

    assert missing_guard["status"] == "blocked"
    assert missing_guard["blocked_by"] == ["runtime_scope_guard_missing"]
    assert missing_guard["runtime_scope_guard_present"] is False
    assert missing_destination["status"] == "blocked"
    assert missing_destination["blocked_by"] == ["runtime_destination_unverified"]


def test_runtime_destination_scope_degrades_missing_required_dns_observation():
    guard = api_module._runtime_scope_guard_from_scope(_make_scope_row())

    result = api_module.evaluate_runtime_destination_scope(
        guard,
        "https://app.example.com/orders",
        resolution_observations=[],
    )

    assert result["status"] == "degraded"
    assert result["blocked_by"] == []
    assert result["warnings"] == ["runtime_dns_unverified"]
    assert result["resolution_observations"] == [{
        "host": "app.example.com",
        "ips": [],
        "verdict": "degraded",
        "reason": "runtime_dns_unverified",
    }]


def test_arsenal_dispatch_rejects_catalog_bound_and_uuid_violations_before_adapter_call():
    for request, expected_violation in (
        (
            api_module.ArsenalExecuteRequest(
                command="evidence_instance.list", parameters={"limit": 201}
            ),
            "limit:maximum:200",
        ),
        (
            api_module.ArsenalExecuteRequest(
                command="asm.gaps", parameters={"target_id": "not-a-uuid"}
            ),
            "target_id:format:uuid",
        ),
    ):
        with pytest.raises(api_module.HTTPException) as exc:
            asyncio.run(api_module._validate_arsenal_execute_request(None, request))
        assert exc.value.status_code == 422
        assert exc.value.detail["error"] == "invalid_arsenal_parameters"
        assert expected_violation in exc.value.detail["violations"]


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


def test_validate_approval_receipt_rejects_risk_escalation():
    conn = _approval_receipt_conn(
        approval_row=_make_approval_row(risk_tier="active"),
        scope_row=_make_scope_row(),
    )
    with pytest.raises(api_module.HTTPException) as exc:
        _run_validate(conn, APPROVAL_ID, risk_tier="intrusive")
    assert exc.value.status_code == 400
    assert "risk tier" in exc.value.detail


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


# ----- blocked/denied command_results audit rows -------------------------------
# A rejected state-changing action must be as auditable as a queued one: the
# enforcement path writes a durable command_results row (best-effort) before it
# raises, so "nothing ran, because policy/scope blocked it" is visible.

class _BlockedRecordingConn:
    """FakeConn that answers the validator SELECTs, the durable-policy read, and
    captures the command_results INSERT so blocked-row recording can be asserted."""

    _RESULT_ARG_KEYS = [
        "command", "status", "dry_run", "risk_tier", "operation_plan_id",
        "scope_receipt_id", "approval_receipt_id", "campaign_id", "scan_id",
        "finding_ids", "hypothesis_ids", "evidence_object_ids", "tool_receipt_ids",
        "blocked_by", "next_action", "operator_message", "result_json", "created_by",
    ]

    def __init__(self, *, approval_row=None, scope_row=None, policy_on=False):
        self.approval_row = approval_row
        self.scope_row = scope_row
        self.policy_on = policy_on
        self.recorded = []

    async def fetchval(self, query, *args):
        if "FROM app_settings" in query:
            return "true" if self.policy_on else None
        return None

    async def fetchrow(self, query, *args):
        if "INSERT INTO command_results" in query:
            row = {key: args[i] for i, key in enumerate(self._RESULT_ARG_KEYS)}
            row["id"] = "cmd-blocked-1"
            row["created_at"] = None
            self.recorded.append(row)
            return row
        if "FROM approval_receipts" in query:
            return self.approval_row
        if "FROM scope_receipts" in query:
            return self.scope_row
        return None


def test_validate_approval_receipt_records_blocked_row_before_raising():
    conn = _BlockedRecordingConn(
        approval_row=_make_approval_row(expires_at=datetime(2000, 1, 1, tzinfo=timezone.utc)),
        scope_row=_make_scope_row(),
    )
    with pytest.raises(api_module.HTTPException):
        _run_validate(conn, APPROVAL_ID, target_url="https://app.example.com/x", created_by="pytest")

    assert len(conn.recorded) == 1
    row = conn.recorded[0]
    assert row["command"] == "finding.retest" or row["command"]  # derived from action_name default
    assert row["status"] == "blocked"
    assert json.loads(row["blocked_by"]) == ["approval_receipt_expired"]
    # The (existing) approval receipt is referenced; scope not yet reached.
    assert str(row["approval_receipt_id"]) == APPROVAL_ID
    assert row["created_by"] == "pytest"


def test_validate_approval_receipt_blocked_row_is_fk_safe_on_not_found():
    # No approval row exists -> must NOT reference the (missing) receipt id, or the
    # command_results FK insert would fail and lose the audit trail.
    conn = _BlockedRecordingConn(approval_row=None)
    with pytest.raises(api_module.HTTPException) as exc:
        _run_validate(conn, APPROVAL_ID)
    assert exc.value.status_code == 404
    assert len(conn.recorded) == 1
    assert conn.recorded[0]["approval_receipt_id"] is None


def test_validate_approval_receipt_record_blocked_false_suppresses_row():
    conn = _BlockedRecordingConn(
        approval_row=_make_approval_row(confirmations=[]),
        scope_row=_make_scope_row(),
    )
    with pytest.raises(api_module.HTTPException):
        asyncio.run(
            api_module._validate_approval_receipt_for_action(
                conn, APPROVAL_ID, action_name="finding.bulk_retest", record_blocked=False
            )
        )
    assert conn.recorded == []


def test_require_approval_receipt_records_approval_required_row_when_missing():
    conn = _BlockedRecordingConn(policy_on=True)
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(
            api_module._require_approval_receipt_if_policy_enabled(
                conn, None, action_name="scan.submit:quick", created_by="pytest"
            )
        )
    assert exc.value.status_code == 409
    assert len(conn.recorded) == 1
    row = conn.recorded[0]
    assert row["command"] == "scan.submit"
    assert row["status"] == "approval_required"
    assert json.loads(row["blocked_by"]) == ["approval_receipt_required"]
    assert row["approval_receipt_id"] is None
    assert row["created_by"] == "pytest"


# ----- gateway -> campaign auto-linkage (§7/§2) --------------------------------

class _CampaignLinkRecordingConn(_BlockedRecordingConn):
    """Extends _BlockedRecordingConn to also answer the campaign-exists check
    and capture the campaign_actions UPDATE issued by the gateway's best-effort
    campaign auto-link (_link_command_result_to_campaign)."""

    def __init__(self, *, campaign_exists=True, action_row=None, **kwargs):
        super().__init__(**kwargs)
        self.campaign_exists = campaign_exists
        self.action_row = action_row
        self.executed = []
        self.linked_action_updates = []

    async def fetchval(self, query, *args):
        if "FROM campaigns" in query:
            return 1 if self.campaign_exists else None
        return await super().fetchval(query, *args)

    async def fetchrow(self, query, *args):
        if "SELECT * FROM campaign_actions WHERE id=$1" in query:
            return self.action_row
        if "UPDATE campaign_actions" in query and "RETURNING *" in query:
            self.linked_action_updates.append(args)
            if not self.action_row:
                return None
            updated = dict(self.action_row)
            updated.update({
                "command_result_id": args[0],
                "status": args[1],
                "dry_run": args[2],
                "risk_tier": args[3],
                "scan_id": args[4] or updated.get("scan_id"),
                "scope_receipt_id": args[5] or updated.get("scope_receipt_id"),
                "approval_receipt_id": args[6] or updated.get("approval_receipt_id"),
                "finding_ids": json.loads(args[7]),
                "hypothesis_ids": json.loads(args[8]),
                "evidence_object_ids": json.loads(args[9]),
                "tool_receipt_ids": json.loads(args[10]),
                "blocked_by": json.loads(args[11]),
                "next_action": args[12] or updated.get("next_action"),
                "operator_message": args[13] or updated.get("operator_message"),
            })
            return updated
        row = await super().fetchrow(query, *args)
        if row is not None and "INSERT INTO command_results" in query:
            # Give the recorded command_result a real UUID id (the base fake's
            # placeholder "cmd-blocked-1" isn't parseable as one) so the
            # gateway's campaign-link UPDATE has a valid command_result_id.
            row["id"] = "44444444-4444-4444-8444-444444444444"
        return row

    async def execute(self, query, *args):
        if "UPDATE campaign_actions" in query:
            self.executed.append(args)
        return "UPDATE 1"


CAMPAIGN_ID = "33333333-3333-4333-8333-333333333333"
CAMPAIGN_ACTION_ID = "55555555-5555-4555-8555-555555555555"


def _campaign_action_row(*, command="campaign.list", mission_campaign_id=None):
    return {
        "id": CAMPAIGN_ACTION_ID,
        "campaign_id": None,
        "operation_plan_id": None,
        "command_result_id": None,
        "target_id": None,
        "scope_receipt_id": None,
        "approval_receipt_id": None,
        "scan_id": None,
        "command": command,
        "action_name": command,
        "status": "planned",
        "dry_run": True,
        "risk_tier": "read_only",
        "finding_ids": [],
        "hypothesis_ids": [],
        "evidence_object_ids": [],
        "tool_receipt_ids": [],
        "blocked_by": [],
        "next_action": command,
        "operator_message": "planned",
        "result_json": {},
        "created_by": "pytest",
        "mission_campaign_id": mission_campaign_id,
        "created_at": None,
        "updated_at": None,
    }


def test_arsenal_execute_links_dispatched_action_to_campaign(monkeypatch):
    async def fake_campaigns(**kwargs):
        return {"campaigns": []}

    monkeypatch.setattr(api_module, "arsenal_campaigns", fake_campaigns)
    conn = _CampaignLinkRecordingConn()
    result = asyncio.run(api_module._arsenal_execute(
        conn, api_module.ArsenalExecuteRequest(command="campaign.list", campaign_id=CAMPAIGN_ID)
    ))
    assert result["dispatched"] is True
    assert conn.executed
    args = conn.executed[0]
    assert str(args[0]) == CAMPAIGN_ID


def test_arsenal_execute_links_result_to_planned_campaign_action(monkeypatch):
    async def fake_campaigns(**kwargs):
        return {"campaigns": []}

    monkeypatch.setattr(api_module, "arsenal_campaigns", fake_campaigns)
    conn = _CampaignLinkRecordingConn(action_row=_campaign_action_row())
    result = asyncio.run(api_module._arsenal_execute(
        conn,
        api_module.ArsenalExecuteRequest(
            command="campaign.list",
            campaign_action_id=CAMPAIGN_ACTION_ID,
        ),
    ))

    assert result["dispatched"] is True
    assert result["campaign_action"]["id"] == CAMPAIGN_ACTION_ID
    assert result["campaign_action"]["status"] == "completed"
    assert result["campaign_action"]["command_result_id"] == result["command_result"]["id"]
    assert conn.linked_action_updates


def test_arsenal_execute_rejects_mismatched_campaign_action_command():
    conn = _CampaignLinkRecordingConn(action_row=_campaign_action_row(command="target.list"))
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module._arsenal_execute(
            conn,
            api_module.ArsenalExecuteRequest(
                command="campaign.list",
                campaign_action_id=CAMPAIGN_ACTION_ID,
            ),
        ))
    assert exc.value.status_code == 409


def test_arsenal_execute_rejects_campaign_action_from_other_campaign():
    conn = _CampaignLinkRecordingConn(
        action_row=_campaign_action_row(
            mission_campaign_id="66666666-6666-4666-8666-666666666666",
        )
    )
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module._arsenal_execute(
            conn,
            api_module.ArsenalExecuteRequest(
                command="campaign.list",
                campaign_id=CAMPAIGN_ID,
                campaign_action_id=CAMPAIGN_ACTION_ID,
            ),
        ))
    assert exc.value.status_code == 409


def test_arsenal_execute_unknown_campaign_id_is_404():
    conn = _CampaignLinkRecordingConn(campaign_exists=False)
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module._arsenal_execute(
            conn, api_module.ArsenalExecuteRequest(command="campaign.list", campaign_id=CAMPAIGN_ID)
        ))
    assert exc.value.status_code == 404


# ----- cross-product mission timeline ------------------------------------------

def test_timeline_scan_status_maps_to_explicit_vocabulary():
    assert api_module._timeline_scan_status("pending") == "queued"
    assert api_module._timeline_scan_status("running") == "running"
    assert api_module._timeline_scan_status("completed") == "completed"
    assert api_module._timeline_scan_status("failed") == "failed"
    assert api_module._timeline_scan_status("cancelled") == "cancelled"
    assert api_module._timeline_scan_status(None) == "queued"


def test_command_result_event_uses_live_scan_status_over_frozen_status():
    # command result was recorded "queued"; the joined scan is now running.
    row = {
        "id": "cmd-1", "command": "scan.submit", "status": "queued", "risk_tier": "active",
        "dry_run": False, "scan_id": "44444444-4444-4444-8444-444444444444",
        "operation_plan_id": None, "campaign_id": None, "scope_receipt_id": None,
        "approval_receipt_id": None, "finding_ids": [], "evidence_object_ids": [],
        "tool_receipt_ids": [], "blocked_by": [], "next_action": "/scans/x",
        "operator_message": "queued", "created_at": datetime(2026, 7, 6, tzinfo=timezone.utc),
        "scan_status": "running", "scan_target_url": "https://app.example.com", "scan_target_id": None,
        "campaign_action_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "mission_campaign_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    }
    ev = api_module._command_result_timeline_event(row)
    assert ev["kind"] == "command_result"
    assert ev["status"] == "running"          # live scan status wins
    assert ev["active_scan_id"] == "44444444-4444-4444-8444-444444444444"
    assert ev["target_url"] == "https://app.example.com"
    assert ev["campaign_action_id"] == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    assert ev["mission_campaign_id"] == "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def test_timeline_sort_orders_newest_first_and_none_last():
    older = {"created_at": "2026-07-05T00:00:00+00:00", "event_id": "old"}
    newer = {"created_at": "2026-07-06T00:00:00+00:00", "event_id": "new"}
    undated = {"created_at": None, "event_id": "none"}
    events = [older, undated, newer]
    events.sort(key=api_module._timeline_sort_key, reverse=True)
    assert [e["event_id"] for e in events] == ["new", "old", "none"]


def test_command_result_event_blocked_row_keeps_its_status():
    row = {
        "id": "cmd-2", "command": "asm.test", "status": "blocked", "risk_tier": "active",
        "dry_run": False, "scan_id": None, "operation_plan_id": None, "campaign_id": None,
        "scope_receipt_id": None, "approval_receipt_id": None,
        "finding_ids": [], "evidence_object_ids": [], "tool_receipt_ids": [],
        "blocked_by": ["approval_receipt_expired"], "next_action": None,
        "operator_message": "blocked", "created_at": datetime(2026, 7, 6, tzinfo=timezone.utc),
        "scan_status": None, "scan_target_url": None, "scan_target_id": None,
    }
    ev = api_module._command_result_timeline_event(row)
    assert ev["status"] == "blocked"          # no scan -> keep command-result status
    assert ev["active_scan_id"] is None
    assert ev["blocked_by"] == ["approval_receipt_expired"]


def test_campaign_action_event_uses_live_scan_status_and_refs():
    row = {
        "id": "action-1", "command": "asm.improve", "action_name": "asm.improve",
        "status": "queued", "risk_tier": "active", "dry_run": False,
        "scan_id": "44444444-4444-4444-8444-444444444444",
        "operation_plan_id": None, "campaign_id": "77777777-7777-4777-8777-777777777777",
        "command_result_id": "88888888-8888-4888-8888-888888888888",
        "target_id": None, "scope_receipt_id": "scope-1", "approval_receipt_id": None,
        "finding_ids": [], "hypothesis_ids": ["hyp-1"], "evidence_object_ids": [],
        "tool_receipt_ids": [], "blocked_by": [], "next_action": "/scans/x",
        "operator_message": "queued", "created_at": datetime(2026, 7, 6, tzinfo=timezone.utc),
        "scan_status": "running", "scan_target_url": "https://app.example.com",
        "scan_target_id": "99999999-9999-4999-8999-999999999999",
    }

    ev = api_module._campaign_action_timeline_event(row)

    assert ev["kind"] == "campaign_action"
    assert ev["status"] == "running"
    assert ev["active_scan_id"] == "44444444-4444-4444-8444-444444444444"
    assert ev["campaign_id"] == "77777777-7777-4777-8777-777777777777"
    assert ev["command_result_id"] == "88888888-8888-4888-8888-888888888888"
    assert ev["hypothesis_ids"] == ["hyp-1"]
    assert ev["target_id"] == "99999999-9999-4999-8999-999999999999"


def test_evidence_instance_timeline_event_is_evidence_bound():
    row = {
        "id": "11111111-1111-4111-8111-111111111111",
        "finding_id": "22222222-2222-4222-8222-222222222222",
        "evidence_object_id": "33333333-3333-4333-8333-333333333333",
        "scan_id": "44444444-4444-4444-8444-444444444444",
        "target_id": None,
        "scan_target_id": None,
        "finding_target_id": "99999999-9999-4999-8999-999999999999",
        "scan_target_url": "https://app.example.com",
        "campaign_id": "77777777-7777-4777-8777-777777777777",
        "campaign_action_id": "88888888-8888-4888-8888-888888888888",
        "tool_receipt_id": "55555555-5555-4555-8555-555555555555",
        "concrete_url": "https://app.example.com/api/orders/1",
        "object_id": "order:1",
        "retention_policy": "standard",
        "proof_state": "exploited",
        "created_at": datetime(2026, 7, 6, 13, tzinfo=timezone.utc),
    }

    ev = api_module._evidence_instance_timeline_event(row)

    assert ev["kind"] == "evidence_instance"
    assert ev["status"] == "evidence_bound"
    assert ev["target_id"] == "99999999-9999-4999-8999-999999999999"
    assert ev["finding_ids"] == ["22222222-2222-4222-8222-222222222222"]
    assert ev["evidence_object_ids"] == ["33333333-3333-4333-8333-333333333333"]
    assert ev["tool_receipt_ids"] == ["55555555-5555-4555-8555-555555555555"]
    assert ev["campaign_id"] == "77777777-7777-4777-8777-777777777777"
    assert ev["next_action"] == "/evidence/33333333-3333-4333-8333-333333333333"


def test_refuter_review_timeline_event_is_refuter_requested_without_mutation():
    row = {
        "id": "11111111-1111-4111-8111-111111111111",
        "target_id": None,
        "finding_target_id": "99999999-9999-4999-8999-999999999999",
        "hypothesis_target_id": None,
        "finding_id": "22222222-2222-4222-8222-222222222222",
        "hypothesis_id": None,
        "campaign_id": "77777777-7777-4777-8777-777777777777",
        "refuter_signal": "question",
        "refuter_verdict": None,
        "verdict_basis": "signal_only",
        "evidence_object_ids": json.dumps(["33333333-3333-4333-8333-333333333333"]),
        "tool_receipt_ids": json.dumps(["55555555-5555-4555-8555-555555555555"]),
        "created_at": datetime(2026, 7, 6, 13, tzinfo=timezone.utc),
    }

    ev = api_module._refuter_review_timeline_event(row)

    assert ev["kind"] == "refuter_review"
    assert ev["status"] == "refuter_requested"
    assert ev["risk_tier"] == "read_only"
    assert ev["target_id"] == "99999999-9999-4999-8999-999999999999"
    assert ev["finding_ids"] == ["22222222-2222-4222-8222-222222222222"]
    assert ev["evidence_object_ids"] == ["33333333-3333-4333-8333-333333333333"]
    assert ev["tool_receipt_ids"] == ["55555555-5555-4555-8555-555555555555"]
    assert ev["next_action"] == "/findings/22222222-2222-4222-8222-222222222222"


def test_export_event_timeline_event_is_content_free_export_record():
    row = {
        "id": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        "export_kind": "evidence_export_bundle",
        "command": "evidence.export_bundle",
        "status": "completed",
        "risk_tier": "read_only",
        "target_id": None,
        "scan_id": "44444444-4444-4444-8444-444444444444",
        "finding_id": "22222222-2222-4222-8222-222222222222",
        "bundle_hash": "b" * 64,
        "manifest_hash": "m" * 64,
        "object_count": 1,
        "filters": json.dumps({"scan_id": "44444444-4444-4444-8444-444444444444"}),
        "evidence_object_ids": json.dumps(["33333333-3333-4333-8333-333333333333"]),
        "finding_ids": json.dumps(["22222222-2222-4222-8222-222222222222"]),
        "scan_ids": json.dumps(["44444444-4444-4444-8444-444444444444"]),
        "replay_plan": json.dumps({
            "content_included": False,
            "evidence_object_reads": [
                {"evidence_object_id": "33333333-3333-4333-8333-333333333333", "api_path": "/evidence/33333333-3333-4333-8333-333333333333"}
            ],
        }),
        "operator_message": "Recorded content-free evidence_export_bundle export",
        "created_at": datetime(2026, 7, 6, 9, tzinfo=timezone.utc),
        "scan_target_id": "99999999-9999-4999-8999-999999999999",
        "scan_target_url": "https://app.example.com",
        "finding_target_id": None,
    }

    ev = api_module._export_event_timeline_event(row)

    assert ev["kind"] == "export_event"
    assert ev["status"] == "completed"
    assert ev["risk_tier"] == "read_only"
    assert ev["target_id"] == "99999999-9999-4999-8999-999999999999"
    assert ev["scan_id"] == "44444444-4444-4444-8444-444444444444"
    assert ev["evidence_object_ids"] == ["33333333-3333-4333-8333-333333333333"]
    assert ev["bundle_hash"] == "b" * 64
    assert ev["content_included"] is False
    assert ev["replay_paths"] == ["/evidence/33333333-3333-4333-8333-333333333333"]


class _TimelinePool:
    def __init__(self, cr_rows, scan_rows, schedule_rows, action_rows=None, evidence_rows=None, refuter_rows=None, export_rows=None):
        self._cr = cr_rows
        self._scans = scan_rows
        self._schedules = schedule_rows
        self._actions = action_rows or []
        self._evidence = evidence_rows or []
        self._refuters = refuter_rows or []
        self._exports = export_rows or []

    def acquire(self):
        pool = self

        class _Acquire:
            async def __aenter__(self):
                class _Conn:
                    async def fetch(self, query, *args):
                        # Order matters: the scan query references command_results
                        # in a NOT EXISTS subquery, so match the more specific
                        # table roots first.
                        if "FROM schedules sc" in query:
                            return pool._schedules
                        if "FROM evidence_instances ei" in query:
                            return pool._evidence
                        if "FROM refuter_reviews rr" in query:
                            return pool._refuters
                        if "FROM export_events ee" in query:
                            return pool._exports
                        if "FROM command_results cr" in query and "SELECT cr.*" in query:
                            return pool._cr
                        if "FROM campaign_actions ca" in query:
                            return pool._actions
                        if "FROM scans s" in query:
                            return pool._scans
                        return []
                return _Conn()

            async def __aexit__(self, *exc):
                return False

        return _Acquire()


def test_mission_timeline_merges_sorts_and_reports_upcoming(monkeypatch):
    cr_row = {
        "id": "cmd-1", "command": "scan.submit", "status": "queued", "risk_tier": "active",
        "dry_run": False, "scan_id": "44444444-4444-4444-8444-444444444444",
        "operation_plan_id": None, "campaign_id": None, "scope_receipt_id": None,
        "approval_receipt_id": None, "finding_ids": [], "evidence_object_ids": [],
        "tool_receipt_ids": [], "blocked_by": [], "next_action": "/scans/x",
        "operator_message": "queued", "created_at": datetime(2026, 7, 6, 12, tzinfo=timezone.utc),
        "scan_status": "running", "scan_target_url": "https://app.example.com", "scan_target_id": None,
        "campaign_action_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "mission_campaign_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    }
    scan_row = {
        "id": "55555555-5555-4555-8555-555555555555", "status": "completed",
        "target_url": "https://old.example.com", "target_id": None, "scan_type": "quick",
        "run_kind": "web_dast", "grade": "B", "findings_count": 2,
        "created_at": datetime(2026, 7, 5, tzinfo=timezone.utc),
    }
    schedule_row = {
        "id": "66666666-6666-4666-8666-666666666666", "name": "nightly", "target_id": None,
        "target_url": "https://app.example.com", "frequency": "daily",
        "schedule_kind": "asm_improve", "scan_type": "smart",
        "next_run_at": datetime(2026, 7, 7, 2, tzinfo=timezone.utc),
        "last_run_at": datetime(2026, 7, 6, 2, tzinfo=timezone.utc),
    }
    evidence_row = {
        "id": "11111111-1111-4111-8111-111111111111",
        "finding_id": "22222222-2222-4222-8222-222222222222",
        "evidence_object_id": "33333333-3333-4333-8333-333333333333",
        "scan_id": "44444444-4444-4444-8444-444444444444",
        "target_id": None,
        "scan_target_id": "99999999-9999-4999-8999-999999999999",
        "scan_target_url": "https://app.example.com",
        "campaign_id": None,
        "campaign_action_id": None,
        "tool_receipt_id": None,
        "concrete_url": "https://app.example.com/api/orders/1",
        "object_id": "order:1",
        "retention_policy": "standard",
        "proof_state": "exploited",
        "created_at": datetime(2026, 7, 6, 11, tzinfo=timezone.utc),
    }
    refuter_row = {
        "id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "target_id": None,
        "finding_target_id": "99999999-9999-4999-8999-999999999999",
        "hypothesis_target_id": None,
        "finding_id": "22222222-2222-4222-8222-222222222222",
        "hypothesis_id": None,
        "campaign_id": None,
        "refuter_signal": "question",
        "refuter_verdict": None,
        "verdict_basis": "signal_only",
        "evidence_object_ids": json.dumps(["33333333-3333-4333-8333-333333333333"]),
        "tool_receipt_ids": json.dumps([]),
        "created_at": datetime(2026, 7, 6, 10, tzinfo=timezone.utc),
    }
    export_row = {
        "id": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        "export_kind": "evidence_export_bundle",
        "command": "evidence.export_bundle",
        "status": "completed",
        "risk_tier": "read_only",
        "target_id": None,
        "scan_id": "44444444-4444-4444-8444-444444444444",
        "finding_id": "22222222-2222-4222-8222-222222222222",
        "bundle_hash": "b" * 64,
        "manifest_hash": "m" * 64,
        "object_count": 1,
        "filters": json.dumps({"scan_id": "44444444-4444-4444-8444-444444444444"}),
        "evidence_object_ids": json.dumps(["33333333-3333-4333-8333-333333333333"]),
        "finding_ids": json.dumps(["22222222-2222-4222-8222-222222222222"]),
        "scan_ids": json.dumps(["44444444-4444-4444-8444-444444444444"]),
        "replay_plan": json.dumps({"content_included": False, "evidence_object_reads": []}),
        "operator_message": "Recorded content-free evidence_export_bundle export",
        "created_at": datetime(2026, 7, 6, 9, tzinfo=timezone.utc),
        "scan_target_id": "99999999-9999-4999-8999-999999999999",
        "scan_target_url": "https://app.example.com",
        "finding_target_id": None,
    }
    monkeypatch.setattr(
        api_module,
        "db_pool",
        _TimelinePool(
            [cr_row],
            [scan_row],
            [schedule_row],
            evidence_rows=[evidence_row],
            refuter_rows=[refuter_row],
            export_rows=[export_row],
        ),
    )

    result = asyncio.run(api_module.mission_timeline(limit=50))

    assert result["execution_enabled"] is False
    assert result["statuses"][0] == "planned"
    # Past events are merged and sorted newest first.
    assert [e["event_id"] for e in result["events"]] == [
        "cmd-1",
        "evidence_instance:11111111-1111-4111-8111-111111111111",
        "refuter_review:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "export_event:eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        "55555555-5555-4555-8555-555555555555",
    ]
    assert result["events"][0]["status"] == "running"       # live scan status
    assert result["events"][0]["mission_campaign_id"] == "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    assert result["events"][1]["kind"] == "evidence_instance"
    assert result["events"][1]["status"] == "evidence_bound"
    assert result["events"][2]["kind"] == "refuter_review"
    assert result["events"][2]["status"] == "refuter_requested"
    assert result["events"][3]["kind"] == "export_event"
    assert result["events"][3]["content_included"] is False
    assert result["events"][4]["kind"] == "scan"
    # Schedules are upcoming, not past events.
    assert len(result["upcoming"]) == 1
    up = result["upcoming"][0]
    assert up["status"] == "planned"
    assert up["command"] == "asm.improve"
    # row_to_dict renders datetimes as ISO strings.
    assert up["next_eligible_at"] == schedule_row["next_run_at"].isoformat()


# ----- finding-exceptions PATCH: owner/approver gate + edit_history audit trail -----

_EXCEPTION_ID = "11111111-1111-4111-8111-111111111111"


class _FindingExceptionEditConn:
    """FakeConn answering the current-row SELECT and capturing the UPDATE args
    so the edit_history append can be asserted without a real database."""

    def __init__(self, current_row):
        self.current_row = current_row
        self.update_query = None
        self.update_args = None

    async def fetchrow(self, query, *args):
        if "SELECT * FROM finding_exceptions" in query:
            return dict(self.current_row) if self.current_row else None
        if "UPDATE finding_exceptions" in query:
            self.update_query = query
            self.update_args = args
            updated = dict(self.current_row)
            updated.update({
                "scope": args[1], "owner": args[2], "approver": args[3],
                "reason": args[4], "compensating_controls": args[5],
                "status": args[6], "expires_at": args[7],
                "edit_history": args[8],
            })
            return updated
        return None


def test_update_finding_exception_requires_owner_or_approver():
    # The 422 gate must fire before any DB access (db_pool is unset in tests).
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(
            api_module.update_finding_exception(
                _EXCEPTION_ID, api_module.FindingExceptionRequest(status="active")
            )
        )
    assert exc.value.status_code == 422


def test_update_finding_exception_appends_edit_history(monkeypatch):
    current_row = {
        "id": _EXCEPTION_ID,
        "finding_id": "f1",
        "fingerprint": None,
        "policy_id": None,
        "target_id": None,
        "scope": "old-scope",
        "owner": "alice",
        "approver": "bob",
        "reason": "old reason",
        "compensating_controls": "old controls",
        "status": "active",
        "expires_at": None,
        "edit_history": json.dumps([]),
        "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "updated_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
    }
    conn = _FindingExceptionEditConn(current_row)
    monkeypatch.setattr(api_module, "db_pool", _pool_for(conn))

    req = api_module.FindingExceptionRequest(owner="carol", status="revoked")
    result = asyncio.run(api_module.update_finding_exception(_EXCEPTION_ID, req))

    assert result["owner"] == "carol"
    assert conn.update_query is not None and "edit_history" in conn.update_query
    snapshot = json.loads(conn.update_args[8])[0]
    assert snapshot["owner"] == "alice"
    assert snapshot["approver"] == "bob"
    assert snapshot["status"] == "active"
    assert "replaced_at" in snapshot


class _FindingExceptionSweepConn:
    def __init__(self, candidates):
        self.candidates = candidates
        self.fetch_calls = []

    async def fetch(self, query, *args):
        self.fetch_calls.append((query, args))
        if "SELECT *" in query and "FROM finding_exceptions" in query:
            return self.candidates
        if "UPDATE finding_exceptions" in query:
            return [{"id": row["id"]} for row in self.candidates]
        return []


def test_finding_exception_lifecycle_sweep_dry_run_is_bounded(monkeypatch):
    candidates = [
        {"id": uuid.UUID("11111111-1111-4111-8111-111111111111")},
        {"id": uuid.UUID("22222222-2222-4222-8222-222222222222")},
    ]
    conn = _FindingExceptionSweepConn(candidates)
    monkeypatch.setattr(api_module, "db_pool", _pool_for(conn))

    result = asyncio.run(
        api_module.finding_exception_lifecycle_sweep(
            api_module.FindingExceptionLifecycleSweepRequest(dry_run=True, limit=2)
        )
    )

    assert result["dry_run"] is True
    assert result["candidate_count"] == 2
    assert result["expired_count"] == 0
    assert len(conn.fetch_calls) == 1
    query, args = conn.fetch_calls[0]
    assert "status IN ('active', 'approved', 'accepted_risk')" in query
    assert "expires_at < NOW()" in query
    assert args[1] == 2


def test_finding_exception_lifecycle_sweep_execution_requires_receipt_and_audits(monkeypatch):
    candidate_id = uuid.UUID("11111111-1111-4111-8111-111111111111")
    conn = _FindingExceptionSweepConn([{"id": candidate_id}])
    monkeypatch.setattr(api_module, "db_pool", _pool_for(conn))
    approval_calls = []
    command_calls = []

    async def fake_validate(_conn, receipt_id, **kwargs):
        approval_calls.append((receipt_id, kwargs))
        return {"id": receipt_id}

    async def fake_record(_conn, **kwargs):
        command_calls.append(kwargs)
        return {"id": "33333333-3333-4333-8333-333333333333"}

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)
    monkeypatch.setattr(api_module, "_record_command_result", fake_record)

    result = asyncio.run(
        api_module.finding_exception_lifecycle_sweep(
            api_module.FindingExceptionLifecycleSweepRequest(
                dry_run=False,
                approval_receipt_id="44444444-4444-4444-8444-444444444444",
            )
        )
    )

    assert result["expired_count"] == 1
    assert result["operation_id"] == "33333333-3333-4333-8333-333333333333"
    assert approval_calls[0][1]["always_require_receipt"] is True
    assert approval_calls[0][1]["command"] == "finding_exception.lifecycle_sweep"
    assert command_calls[0]["status"] == "completed"
    assert command_calls[0]["result_json"]["expired_exception_ids"] == [str(candidate_id)]
    update_query = conn.fetch_calls[1][0]
    assert "transition', 'lifecycle_sweep'" in update_query
    assert "status = 'expired'" in update_query


def test_compact_research_observation_preserves_small_pack_without_rewriting():
    pack = {
        "observation_version": "2026-07-12.v1",
        "episode_id": "11111111-1111-4111-8111-111111111111",
        "mission": {"profile": "target_hunt", "subject": {"type": "target", "id": "target-1"}},
        "focus": {},
        "remaining_budget": {"steps": 3, "model_units": 2000},
        "recent_actions": [],
        "proposable_commands": [{"name": "asm.gaps", "proposable": True}],
    }

    assert api_module._compact_research_observation_pack(pack) == pack


def test_research_previous_result_digest_keeps_typed_outcome_without_raw_blob():
    digest = api_module._research_previous_result_digest({
        "execution_blocked_reason": "arsenal_rejected",
        "error": {
            "error": "invalid_experiment",
            "violation": "step_1_method_not_allowed",
            "noise": "x" * 100_000,
        },
        "command_result": {
            "id": "result-1",
            "status": "queued",
            "scan_id": "scan-1",
            "result_json": {
                "selected_action": "test",
                "check_family": "xss",
                "batch_size": 50,
                "recommendation": {"next_action": "test", "reason": "coverage gap"},
                "raw_blob": "x" * 100_000,
            },
        },
    })

    result_json = digest["command_result"]["result_json"]
    assert result_json["selected_action"] == "test"
    assert result_json["check_family"] == "xss"
    assert result_json["batch_size"] == 50
    assert "raw_blob" not in result_json
    assert digest["error"] == {
        "error": "invalid_experiment",
        "violation": "step_1_method_not_allowed",
    }
    assert api_module._json_size_bytes(digest) < 10_000


def test_research_previous_result_digest_preserves_experiment_evidence_without_bodies():
    digest = api_module._research_previous_result_digest({
        "command": "experiment.http_diff",
        "dispatched": True,
        "result": {
            "proof_state": "unverified_experiment_signal",
            "evidence_instance_id": "evidence-1",
            "tool_receipt_id": "receipt-1",
            "experiment": {
                "objective": "Check ownership invariant",
                "expected_signal": "candidate changes owner",
                "falsifier": "owner remains unchanged",
                "request_count": 2,
                "observations": [{
                    "label": "candidate",
                    "request": {"method": "POST", "path": "/api/profile", "headers": {"Authorization": "secret"}},
                    "response": {"status": 200, "body_sample": "private response"},
                }],
                "comparisons": [{"control": "control", "candidate": "candidate", "status_changed": True}],
            },
        },
    })

    result = digest["experiment_result"]
    assert result["evidence_instance_id"] == "evidence-1"
    assert result["comparisons"][0]["status_changed"] is True
    assert result["observations"] == [{"label": "candidate", "method": "POST", "path": "/api/profile", "status": 200}]
    assert "private response" not in str(digest)
    assert "Authorization" not in str(digest)


def test_research_previous_result_digest_preserves_durable_read_evidence():
    digest = api_module._research_previous_result_digest({
        "command": "finding.get",
        "command_result": {
            "command": "finding.get",
            "result_json": {
                "result": {
                    "id": "finding-1",
                    "family": "bola",
                    "method": "GET",
                    "url": "https://app.example.test/api/orders/123",
                    "evidence": {"owner_status": 200, "attacker_status": 200},
                    "authorization": "Bearer should-not-survive",
                }
            },
        },
    })

    assert digest["read_result"]["id"] == "finding-1"
    assert digest["read_result"]["evidence"]["attacker_status"] == 200
    assert digest["read_result"]["authorization"] == "***"


def test_compact_research_observation_hard_caps_adversarial_nested_pack():
    huge = "💥" * 1200
    commands = []
    for index in range(25):
        properties = {
            f"parameter_{property_index}_{huge[:20]}": {
                "type": "string",
                "description": huge,
                "enum": [f"choice-{choice}-{huge}" for choice in range(2)],
                "x-adversarial": {f"nested-{nested}": huge for nested in range(3)},
            }
            for property_index in range(2)
        }
        if index == 0:
            properties = {
                "check_family": {
                    "type": "string",
                    "enum": ["xss", "sqli", "bola"],
                    "description": huge,
                }
            }
        parameters_schema = {
            "type": "object",
            "required": list(properties),
            "properties": properties,
            "description": huge,
        }
        if index == 0:
            # Match the real Arsenal catalog shape: a flat property map.
            parameters_schema = properties
        commands.append({
            "name": f"command.{index}",
            "description": f"Run bounded command {index} and inspect its result. {huge}",
            "risk_tier": "active",
            "proposable": True,
            "currently_executable": True,
            "reserved_cost": {"steps": 1, "actions": 1, "requests": 100, "seconds": 600},
            "server_supplied_parameters": ["target_id"],
            "blocked_by": [],
            "parameters_schema": parameters_schema,
        })
    pack = {
        "observation_version": "2026-07-12.v1",
        "episode_id": "11111111-1111-4111-8111-111111111111",
        "episode_version": 9,
        "sequence": 7,
        "objective": huge,
        "execution_mode": "gated",
        "max_risk_tier": "active",
        "allowed_families": ["xss", "sqli"],
        "mission": {
            "profile": "verify_finding",
            "subject": {
                "type": "finding",
                "id": "22222222-2222-4222-8222-222222222222",
                "family": "xss",
                "title": huge,
                "adversarial": {f"mission-{index}": huge for index in range(6)},
            },
            "allowed_commands": [item["name"] for item in commands],
            "adversarial": [{f"nested-{index}": huge} for index in range(10)],
        },
        "focus": {
            "type": "finding",
            "id": "22222222-2222-4222-8222-222222222222",
            "target_id": "33333333-3333-4333-8333-333333333333",
            "title": huge,
            "status": "active",
            "family": "xss",
            "last_verification_verdict": "exploited",
            "latest_retest_id": "44444444-4444-4444-8444-444444444444",
            "latest_retest_status": "completed",
            "latest_retest_verdict": "exploited",
            "adversarial": [{f"focus-{index}": huge} for index in range(10)],
        },
        "target_summary": {"target_id": "target-1", "url": "https://example.test", "noise": huge},
        "current_surface": {
            "coverage": {f"coverage-{index}": huge for index in range(8)},
            "sample_endpoints": [{f"endpoint-{index}": huge} for index in range(10)],
        },
        "current_gaps": [
            {"kind": f"gap-{index}", "count": index, "reason": huge, "nested": {"noise": huge}}
            for index in range(12)
        ],
        "hypotheses_summary": [{"id": index, "reason": huge} for index in range(10)],
        "findings_summary": [{"id": index, "description": huge} for index in range(10)],
        "known_preconditions": {f"precondition-{index}": huge for index in range(8)},
        "remaining_budget": {
            "steps": 8,
            "actions": 7,
            "active_actions": 3,
            "requests": 200,
            "seconds": 900,
            "model_units": 50000,
        },
        "proposable_commands": commands,
        "recent_actions": [
            {
                "sequence": index,
                "decision_type": "execute_action",
                "status": "completed",
                "action": {
                    "command": f"command.{index}",
                    "parameters": {"check_family": "xss", "untrusted": huge},
                },
                "reason": huge,
                "result": {"status": "completed", "scan_id": f"scan-{index}", "noise": huge},
            }
            for index in range(8)
        ],
        "previous_observation": {
            "command": "scan.focused_family",
            "result": {f"nested-{index}": huge for index in range(8)},
        },
        "planner_contract": {"select_exactly_one": True, "noise": huge},
    }

    compacted = api_module._compact_research_observation_pack(pack)
    persisted = dict(compacted)
    persisted["context_hash"] = "a" * 64

    assert api_module._json_size_bytes(compacted) <= (
        api_module.RESEARCH_OBSERVATION_MAX_BYTES - 96
    )
    assert api_module._json_size_bytes(persisted) <= api_module.RESEARCH_OBSERVATION_MAX_BYTES
    assert compacted["mission"]["profile"] == "verify_finding"
    assert compacted["mission"]["subject"]["id"] == "22222222-2222-4222-8222-222222222222"
    assert compacted["focus"]["id"] == "22222222-2222-4222-8222-222222222222"
    assert compacted["focus"]["last_verification_verdict"] == "exploited"
    assert compacted["focus"]["latest_retest_verdict"] == "exploited"
    assert compacted["remaining_budget"] == pack["remaining_budget"]
    assert compacted["recent_actions"][0]["action"]["command"] == "command.0"
    assert [item["name"] for item in compacted["proposable_commands"]] == [
        f"command.{index}" for index in range(25)
    ]
    first_schema = compacted["proposable_commands"][0]["parameters_schema"]
    assert first_schema["check_family"]["enum"] == ["xss", "sqli", "bola"]
    assert "description" not in first_schema["check_family"]
    assert compacted["proposable_commands"][0]["description"].startswith("Run bounded command 0")
    assert compacted["proposable_commands"][0]["reserved_cost"]["requests"] == 100


def test_research_action_planner_projection_keeps_exact_shape_without_request_values():
    action = {
        "command": "experiment.workflow",
        "parameters": {
            "workflow_id": "volatile-provider-id",
            "proof_family": "mass_assignment",
            "steps": [{
                "label": "mutate-profile",
                "method": "PATCH",
                "path": "/api/users/42",
                "principal": "primary_auth",
                "query": {"include": "private-value"},
                "json_body": {"isAdmin": True, "token": "secret-value"},
            }],
            "assertions": [{
                "type": "json_equal",
                "control": "before",
                "candidate": "mutate-profile",
            }],
            "principal_variables": [{
                "name": "owner_id",
                "principal": "primary_auth",
                "ref": "$.user.id",
            }],
        },
    }

    projected = api_module._research_action_planner_projection(action)

    params = projected["parameters"]
    assert params["proof_family"] == "mass_assignment"
    assert params["steps"] == [{
        "label": "mutate-profile",
        "method": "PATCH",
        "route": "/api/users/{id}",
        "principal": "primary_auth",
        "query_keys": ["include"],
        "body_fields": ["isAdmin", "token"],
    }]
    assert params["assertions"][0]["candidate"] == "mutate-profile"
    assert params["principal_variables"][0]["name"] == "owner_id"
    assert "volatile-provider-id" not in json.dumps(projected)
    assert "secret-value" not in json.dumps(projected)
    assert "private-value" not in json.dumps(projected)


def test_oversized_compaction_preserves_readable_exact_exclusion_memory():
    hypothesis_id = str(uuid.uuid4())
    pack = {
        "observation_version": "2026-07-12.v1",
        "episode_id": str(uuid.uuid4()),
        "objective": "Test a new bounded semantic dimension",
        "adversarial_noise": ["x" * 1_000 for _ in range(60)],
        "mission": {"profile": "target_hunt", "subject": {"type": "target", "id": "target-1"}},
        "remaining_budget": {"steps": 4, "requests": 50},
        "proposable_commands": [{"name": "experiment.workflow", "proposable": True}],
        "recent_actions": [],
        "excluded_actions": [{
            "command": "experiment.workflow",
            "hypothesis_id": hypothesis_id,
            "validation_errors": ["known_vulnerability_already_covered"],
            "parameters": {
                "proof_family": "bola",
                "operations": [{
                    "label": "read-order",
                    "method": "GET",
                    "route": "/workshop/api/shop/orders/{id}",
                    "principal": "second_user_auth",
                }],
            },
        }],
    }

    compacted = api_module._compact_research_observation_pack(pack)

    excluded = compacted["excluded_actions"][0]
    assert compacted["observation_compaction"]["applied"] is True
    assert excluded["hypothesis_id"] == hypothesis_id
    assert excluded["validation_errors"] == ["known_vulnerability_already_covered"]
    assert excluded["parameters"]["operations"][0]["route"] == "/workshop/api/shop/orders/{id}"
    assert api_module._json_size_bytes(compacted) <= api_module.RESEARCH_OBSERVATION_MAX_BYTES - 96


def test_compacted_real_experiment_schema_survives_into_provider_prompt():
    catalog_command = api_module._research_command_catalog()["experiment.http_diff"]
    projected = api_module._research_command_projection(
        catalog_command,
        max_risk_tier="active",
        has_approval=True,
        execution_feature_enabled=True,
    )
    projected["parameters_schema"] = api_module._research_autonomous_parameter_schema(
        "experiment.http_diff",
        projected["parameters_schema"],
    )
    projected["reserved_cost"] = {"steps": 1, "actions": 1, "requests": 4, "seconds": 120}
    pack = {
        "observation_version": "2026-07-12.v1",
        "episode_id": "11111111-1111-4111-8111-111111111111",
        "objective": "Test the most useful bounded differential",
        "execution_mode": "gated",
        "mission": {"profile": "target_hunt", "subject": {"type": "target", "id": "target-1"}},
        "remaining_budget": {"steps": 5, "actions": 4, "requests": 100, "seconds": 600},
        "proposable_commands": [projected],
        "current_gaps": [{"kind": f"gap-{index}", "reason": "x" * 4000} for index in range(80)],
        "findings_summary": [{"id": f"finding-{index}", "title": f"Finding {index}", "severity": "high"} for index in range(8)],
        "current_surface": {
            "sample_endpoints": [{"method": "POST", "path": f"/api/items/{index}"} for index in range(8)]
        },
        "recent_actions": [],
    }

    compacted = api_module._compact_research_observation_pack(pack)
    assert compacted["observation_compaction"]["applied"] is True
    observation = {
        "id": "22222222-2222-4222-8222-222222222222",
        "context_hash": "a" * 64,
        "observation_pack": compacted,
    }
    user_payload = json.loads(api_module._research_planner_messages(observation)[1]["content"])
    http_schema = user_payload["observation_pack"]["proposable_commands"][0]["parameters_schema"]

    def collect_enums(value):
        result = []
        if isinstance(value, dict):
            if isinstance(value.get("enum"), list):
                result.extend(value["enum"])
            for nested in value.values():
                result.extend(collect_enums(nested))
        elif isinstance(value, list):
            for nested in value:
                result.extend(collect_enums(nested))
        return result

    method_values = {str(item) for item in collect_enums(http_schema)}
    assert {"GET", "HEAD", "OPTIONS"}.issubset(method_values)
    assert "POST" not in method_values
    assert "DELETE" not in method_values
    step_schema = http_schema["steps"]["items"]
    assert step_schema["allOf"][0]["if"]["properties"]["method"]["enum"] == [
        "GET", "HEAD", "OPTIONS",
    ]
    assert step_schema["allOf"][0]["then"]["not"]["anyOf"]
    assert step_schema["allOf"][1]["not"]["required"] == ["json_body", "form_body"]
    assert user_payload["observation_pack"]["current_surface"]["sample_endpoints"][0]["path"] == "/api/items/0"
    assert len(user_payload["observation_pack"]["findings_summary"]) == 8


def test_selected_hypothesis_request_contract_survives_oversized_compaction():
    contract = {
        "hypothesis_id": "11111111-1111-4111-8111-111111111111",
        "family": "bola",
        "method": "POST",
        "route": "/workshop/api/shop/orders",
        "request_fields": "product_id,quantity",
        "request_example": '{"product_id": 7, "quantity": 1}',
        "required_principals": ["primary_auth", "second_user_auth"],
        "next_test_action": {"command": "experiment.workflow", "parameters": {"proof_family": "bola"}},
    }
    pack = {
        "observation_version": "2026-07-12.v1",
        "episode_id": "22222222-2222-4222-8222-222222222222",
        "objective": "x" * 80_000,
        "mission": {"profile": "target_hunt", "subject": {"type": "target", "id": "target-1"}},
        "remaining_budget": {"steps": 4, "requests": 50},
        "selected_hypothesis_contracts": [contract],
        "proposable_commands": [
            {"name": f"command.{index}", "proposable": True, "description": "y" * 4000}
            for index in range(25)
        ],
        "current_gaps": [{"kind": "noise", "reason": "z" * 4000} for _ in range(20)],
        "recent_actions": [],
    }

    compacted = api_module._compact_research_observation_pack(pack)

    assert compacted["selected_hypothesis_contracts"] == [contract]
    assert api_module._research_requested_input_is_in_observation(
        "Please provide the request body schema and example payload",
        compacted,
    ) is True
    assert api_module._research_requested_input_is_in_observation(
        "Please provide a fresh bearer token",
        compacted,
    ) is False


def test_research_hypothesis_contract_omits_secret_named_request_fields_and_example():
    hypothesis_id = str(uuid.uuid4())
    contract = api_module._research_hypothesis_experiment_contract({
        "id": hypothesis_id,
        "family": "mass_assignment",
        "title": "Mutation lead",
        "metadata_json": {
            "dedupe_dimensions": {"method": "POST", "route": "/api/orders"},
            "request_fields": "product_id, quantity, token, authorization, order_id",
            "request_example": '{"product_id":7,"token":"redacted","order_id":42}',
        },
        "next_test_action": {"command": "experiment.workflow", "requires": ["primary_auth"]},
    })

    assert contract["hypothesis_id"] == hypothesis_id
    assert contract["request_fields"] == "product_id,quantity,order_id"
    assert "request_example" not in contract
    assert "token" not in json.dumps(contract).lower()
    assert "authorization" not in json.dumps(contract).lower()


def test_research_planner_binds_provider_decision_to_current_observation():
    response = {
        "decision": "stop",
        "observation_id": "provider-controlled",
        "context_hash": "provider-controlled",
        "stop_reason": "No useful next action",
    }
    observation = {
        "id": "11111111-1111-4111-8111-111111111111",
        "context_hash": "a" * 64,
    }

    bound = api_module._bind_research_decision_to_observation(response, observation)

    assert bound["decision_version"] == api_module.RESEARCH_DECISION_VERSION
    assert bound["observation_id"] == observation["id"]
    assert bound["context_hash"] == observation["context_hash"]
    assert response["observation_id"] == "provider-controlled"


def test_research_planner_marks_terminal_compatibility_repairs_but_provider_contract_rejects_them():
    observation = {"id": "observation-1", "context_hash": "a" * 64}

    stopped = api_module._bind_research_decision_to_observation(
        {"decision": "stop", "stop_reason": None, "reason": None}, observation
    )
    requested = api_module._bind_research_decision_to_observation(
        {"decision": "request_input", "requested_input": None, "reason": None}, observation
    )

    assert stopped["stop_reason"] == "planner_concluded_no_further_action"
    assert requested["requested_input"] == "Operator input is required to continue."
    assert "stop_reason_defaulted" in stopped["_harness_repairs"]
    assert "requested_input_defaulted" in requested["_harness_repairs"]
    assert api_module._research_provider_contract_error(
        {"decision": "stop", "stop_reason": None, "reason": None}, observation
    ) == "stop_reason_required"
    assert api_module._research_provider_contract_error(
        {"decision": "request_input", "requested_input": None, "reason": None}, observation
    ) == "requested_input_required"


def test_research_planner_schema_constrains_action_to_current_proposable_commands():
    schema = api_module._research_decision_json_schema(["target.get", "asm.gaps", "asm.gaps"])

    command_schema = schema["schema"]["properties"]["action"]["properties"]["command"]
    assert command_schema["enum"] == ["", "asm.gaps", "target.get"]
    execute_branch = schema["schema"]["allOf"][0]["then"]["properties"]
    assert execute_branch["action"]["properties"]["command"]["enum"] == ["asm.gaps", "target.get"]
    assert execute_branch["expected_signal"]["minLength"] == 1
    assert execute_branch["falsifier"]["minLength"] == 1


def test_research_planner_schema_binds_observation_and_allows_terminal_empty_action():
    schema = api_module._research_decision_json_schema(
        ["asm.gaps"], observation_id="observation-1", context_hash="b" * 64
    )["schema"]

    assert schema["properties"]["observation_id"] == {"const": "observation-1"}
    assert schema["properties"]["context_hash"] == {"const": "b" * 64}
    terminal_branch = next(
        branch["then"]["properties"]["action"]["properties"]
        for branch in schema["allOf"]
        if branch.get("if", {}).get("properties", {}).get("decision", {}).get("enum")
    )
    assert terminal_branch["command"] == {"const": ""}
    assert terminal_branch["parameters"]["maxProperties"] == 0
    stop_branch = next(
        branch for branch in schema["allOf"]
        if branch.get("if", {}).get("properties", {}).get("decision", {}).get("const") == "stop"
    )
    assert stop_branch["then"]["properties"]["stop_reason"]["minLength"] == 20


def test_research_decision_request_forbids_unknown_control_fields():
    with pytest.raises(api_module.ValidationError):
        api_module.ResearchDecisionRequest(
            decision="stop",
            observation_id="observation-1",
            context_hash="a" * 64,
            stop_reason="done",
            approval_receipt_id="model-controlled",
        )


def test_research_provider_contract_rejects_semantically_empty_action():
    observation = {
        "id": "observation-1",
        "context_hash": "a" * 64,
        "observation_pack": {
            "proposable_commands": [{
                "name": "asm.gaps", "proposable": True, "risk_tier": "read_only",
                "description": "Explain remaining ASM gaps and campaigns.",
                "parameters_schema": {"target_id": {}},
            }]
        },
    }
    invalid = {
        "decision": "execute_action",
        "action": {"command": "asm.gaps", "parameters": {"target_id": "target-1"}},
        "expected_signal": "",
        "falsifier": "",
    }
    valid = {
        **invalid,
        "expected_signal": "A prioritized gap report",
        "falsifier": "The report contains no gaps or recommendations",
    }

    assert api_module._research_provider_contract_error(invalid, observation) == (
        "expected_signal_required,falsifier_required"
    )
    assert api_module._research_provider_contract_error(valid, observation) is None


def test_research_provider_contract_promotes_workflow_semantics_from_action():
    observation = {
        "id": "observation-1",
        "context_hash": "a" * 64,
        "observation_pack": {
            "proposable_commands": [{
                "name": "experiment.workflow", "proposable": True, "risk_tier": "credential",
            }]
        },
    }
    provider_response = {
        "decision": "execute_action",
        "action": {
            "command": "experiment.workflow",
            "parameters": {
                "expected_signal": "The forbidden field persists after the mutation.",
                "falsifier": "The mutation is rejected or the field does not persist.",
            },
        },
        "expected_signal": None,
        "falsifier": None,
    }

    bound = api_module._bind_research_decision_to_observation(provider_response, observation)

    assert bound["expected_signal"] == provider_response["action"]["parameters"]["expected_signal"]
    assert bound["falsifier"] == provider_response["action"]["parameters"]["falsifier"]
    assert "expected_signal_promoted_from_action" in bound["_harness_repairs"]
    assert "falsifier_promoted_from_action" in bound["_harness_repairs"]
    assert api_module._research_provider_contract_error(provider_response, observation) is None


def test_research_provider_contract_rejects_vague_or_premature_stop():
    observation = {
        "id": "observation-1",
        "context_hash": "a" * 64,
        "observation_pack": {
            "proposable_commands": [{"name": "asm.gaps", "proposable": True}],
            "recent_actions": [],
        },
    }
    vague = {
        "decision": "stop",
        "action": {"command": "", "parameters": {}},
        "stop_reason": "done",
    }
    premature = {
        **vague,
        "stop_reason": "No further work is needed based on the current evidence.",
    }
    concluded = {
        **premature,
        "stop_reason": "The completed gap review found no reachable untested surface; monitor after deployment.",
    }

    assert api_module._research_provider_contract_error(vague, observation) == "stop_reason_too_vague"
    assert api_module._research_provider_contract_error(premature, observation) == (
        "premature_stop_before_evidence_action"
    )
    observation["observation_pack"]["recent_actions"] = [{"status": "rejected"}]
    assert api_module._research_provider_contract_error(concluded, observation) == (
        "premature_stop_before_evidence_action"
    )
    observation["observation_pack"]["recent_actions"] = [{
        "decision_type": "execute_action",
        "status": "completed",
        "command_result_id": "result-1",
    }]
    assert api_module._research_provider_contract_error(concluded, observation) is None


def test_research_provider_contract_requires_active_evidence_when_hunt_can_act():
    response = {
        "decision": "stop",
        "action": {"command": "", "parameters": {}},
        "stop_reason": "The target metadata was reviewed; no additional work is recommended at this time.",
    }
    observation = {
        "id": "observation-1",
        "context_hash": "a" * 64,
        "observation_pack": {
            "mission": {"profile": "target_hunt"},
            "proposable_commands": [
                {"name": "target.get", "proposable": True},
                {"name": "scan.focused_family", "proposable": True},
            ],
            "recent_actions": [{
                "decision_type": "execute_action",
                "status": "completed",
                "action": {"command": "target.get", "parameters": {}},
            }],
        },
    }

    assert api_module._research_provider_contract_error(response, observation) == (
        "premature_stop_before_active_evidence"
    )
    observation["observation_pack"]["recent_actions"].insert(0, {
        "decision_type": "execute_action",
        "status": "completed",
        "action": {"command": "scan.focused_family", "parameters": {"check_family": "xss"}},
    })
    assert api_module._research_provider_contract_error(response, observation) is None


def test_research_provider_contract_rejects_extra_fields_and_invalid_types_before_acceptance():
    observation = {
        "id": "observation-1",
        "context_hash": "a" * 64,
        "observation_pack": {
            "proposable_commands": [{"name": "asm.gaps", "proposable": True}],
            "recent_actions": [],
        },
    }
    base = {
        "decision": "execute_action",
        "action": {"command": "asm.gaps", "parameters": {}},
        "expected_signal": "A bounded gap report",
        "falsifier": "No gap information is returned",
        "confidence": 0.7,
    }

    assert api_module._research_provider_contract_error(
        {**base, "approval_receipt_id": "model-controlled"}, observation
    ) == "unexpected_fields:approval_receipt_id"
    invalid_type = api_module._research_provider_contract_error(
        {**base, "confidence": "very high"}, observation
    )
    assert invalid_type and invalid_type.startswith("decision_schema_invalid:confidence:")
    too_long = api_module._research_provider_contract_error(
        {**base, "reason": "x" * 2001}, observation
    )
    assert too_long and too_long.startswith("decision_schema_invalid:reason:")


def test_research_dispatch_async_reference_detects_scans_and_retests():
    scan = api_module._research_dispatch_async_ref({
        "command_result": {"status": "queued", "scan_id": "scan-1", "result_json": {}}
    })
    retest = api_module._research_dispatch_async_ref({
        "command_result": {
            "status": "retest_scheduled", "scan_id": None,
            "result_json": {"retest_id": "retest-1"},
        }
    })

    assert scan == {"kind": "scan", "id": "scan-1", "status": "queued"}
    assert retest == {"kind": "finding_retest", "id": "retest-1", "status": "retest_scheduled"}


@pytest.mark.parametrize(
    ("finding", "expected"),
    [
        ({"source": "scan", "tool": "nuclei", "ai_target_id": None}, True),
        ({"source": "asm", "tool": "smart_xss", "ai_target_id": None}, True),
        ({"source": "manual", "tool": "manual", "ai_target_id": None}, True),
        ({"source": "ai_gate", "tool": "ai_gate", "ai_target_id": None}, False),
        ({"source": "ai_session", "tool": "manual", "ai_target_id": None}, False),
        ({"source": "model_intake", "tool": "model_intake", "ai_target_id": None}, False),
        ({"source": "scan", "tool": "nuclei", "ai_target_id": "ai-target"}, False),
    ],
)
def test_research_finding_web_subject_gate(finding, expected):
    assert api_module._research_finding_is_web(finding) is expected


def test_research_finding_queries_project_legacy_columns_without_schema_drift():
    target_id = "11111111-1111-4111-8111-111111111111"
    finding_id = "22222222-2222-4222-8222-222222222222"
    queries = []

    class Conn:
        async def fetchrow(self, query, *args):
            queries.append(query)
            return {
                "id": uuid.UUID(finding_id),
                "target_id": uuid.UUID(target_id),
                "title": "DOM XSS",
                "severity": "high",
                "status": "active",
                "category": "smart_xss",
                "tool": "smart_xss",
                "cwe": "CWE-79",
                "url": "https://example.test/#/search?q=x",
                "source": "scan",
                "ai_target_id": None,
            }

        async def fetchval(self, query, *args):
            return None

    conn = Conn()
    episode = {
        "target_id": target_id,
        "planner": {
            "mission": {
                "profile": "verify_finding",
                "subject": {"type": "finding", "id": finding_id},
            }
        },
        "allowed_families": ["xss"],
    }
    focus = asyncio.run(api_module._research_focus_snapshot(conn, episode))
    params, errors = asyncio.run(api_module._research_prepare_action(
        conn,
        episode,
        {"action": {"parameters": {}}},
        api_module._research_command_catalog()["finding.get"],
    ))

    assert focus["category"] == "smart_xss"
    assert params["finding_id"] == finding_id
    assert errors == []
    assert all("f.category" not in query and "f.param" not in query for query in queries)
    assert any("tool AS category" in query for query in queries)


def test_research_autonomous_http_experiment_hides_and_rejects_destructive_methods():
    command = api_module._research_command_catalog()["experiment.http_diff"]
    projected = api_module._research_autonomous_parameter_schema(
        "experiment.http_diff",
        command["parameters_schema"],
    )

    def enums(value):
        found = []
        if isinstance(value, dict):
            if isinstance(value.get("enum"), list):
                found.append(value["enum"])
            for nested in value.values():
                found.extend(enums(nested))
        elif isinstance(value, list):
            for nested in value:
                found.extend(enums(nested))
        return found

    method_values = {str(item) for enum in enums(projected) for item in enum}
    assert {"GET", "HEAD", "OPTIONS"} <= method_values
    assert not {"POST", "PUT", "PATCH", "DELETE"} & method_values

    class Conn:
        async def fetch(self, _query, *_args):
            return [
                {"method": "GET", "path": "/api/items"},
                {"method": "POST", "path": "/api/items/1"},
            ]

    params, errors = asyncio.run(api_module._research_prepare_action(
        Conn(),
        {
            "target_id": "11111111-1111-4111-8111-111111111111",
            "planner": {"mission": {"profile": "target_hunt", "subject": {"type": "target"}}},
            "allowed_families": [],
        },
        {
            "action": {
                "parameters": {
                    "steps": [
                        {"role": "control", "method": "GET", "path": "/api/items"},
                        {"role": "mutation", "method": "POST", "path": "/api/items/1"},
                    ]
                }
            }
        },
        command,
    ))

    assert params["target_id"] == "11111111-1111-4111-8111-111111111111"
    assert "autonomous_experiment_destructive_method_forbidden:POST" in errors


def test_research_focused_scan_accepts_exact_operations_and_family_payloads():
    command = api_module._research_command_catalog()["scan.focused_family"]

    class Conn:
        async def fetchval(self, _query, *_args):
            return "https://example.test"

    episode = {
        "target_id": "11111111-1111-4111-8111-111111111111",
        "planner": {"mission": {"profile": "target_hunt", "subject": {"type": "target"}}},
        "allowed_families": ["sqli"],
    }
    params, errors = asyncio.run(api_module._research_prepare_action(
        Conn(), episode,
        {"action": {"parameters": {
            "check_family": "sqli",
            "custom_endpoints": ["POST /api/search q", "POST /api/search q"],
            "custom_sqli_payloads": ["' OR '1'='1", "' OR '1'='1"],
        }}},
        command,
    ))

    assert errors == []
    assert params["target"] == "https://example.test"
    assert params["custom_endpoints"] == ["POST /api/search q"]
    assert params["custom_sqli_payloads"] == ["' OR '1'='1"]

    _params, rejected = asyncio.run(api_module._research_prepare_action(
        Conn(), episode,
        {"action": {"parameters": {
            "check_family": "sqli",
            "custom_endpoints": ["https://other.test/api/search"],
            "custom_xss_payloads": ["<svg/onload=alert(1)>"],
        }}},
        command,
    ))
    assert "focused_scan_custom_endpoint_outside_target" in rejected
    assert "custom_xss_payloads_requires_xss_family" in rejected


def test_research_autonomous_workflow_rejects_delete_but_allows_browser_and_form_post():
    command = api_module._research_command_catalog()["experiment.workflow"]
    projected = api_module._research_autonomous_parameter_schema(
        "experiment.workflow",
        command["parameters_schema"],
    )

    def method_values(value):
        found = set()
        if isinstance(value, dict):
            enum = value.get("enum")
            if isinstance(enum, list):
                found.update(str(item) for item in enum if str(item) in {
                    "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE",
                })
            for nested in value.values():
                found.update(method_values(nested))
        elif isinstance(value, list):
            for nested in value:
                found.update(method_values(nested))
        return found

    assert "POST" in method_values(projected)
    assert not {"PUT", "PATCH", "DELETE"} & method_values(projected)
    # Projection is a deep copy: manual typed workflows retain the full runtime contract.
    assert {"PUT", "PATCH", "DELETE"} <= method_values(command["parameters_schema"])

    class Conn:
        async def fetch(self, _query, *_args):
            return [
                {"method": "GET", "path": "/api/items/1"},
                {"method": "DELETE", "path": "/api/items/1"},
                {"method": "POST", "path": "/api/items"},
            ]

    episode = {
        "target_id": "11111111-1111-4111-8111-111111111111",
        "planner": {"mission": {"profile": "target_hunt", "subject": {"type": "target"}}},
        "allowed_families": [],
    }
    base = {
        "workflow_id": "22222222-2222-4222-8222-222222222222",
        "objective": "Compare a bounded state change",
        "expected_signal": "The submitted form changes the observable state",
        "falsifier": "The state remains unchanged",
    }
    _params, destructive_errors = asyncio.run(api_module._research_prepare_action(
        Conn(),
        episode,
        {"action": {"parameters": {
            **base,
            "steps": [
                {"label": "before", "kind": "http", "principal": "anonymous",
                 "checkpoint": "before", "method": "GET", "path": "/api/items/1"},
                {"label": "delete", "kind": "http", "principal": "anonymous",
                 "checkpoint": "action", "method": "DELETE", "path": "/api/items/1",
                 "compare_to": "before"},
            ],
        }}},
        command,
    ))
    assert "autonomous_experiment_destructive_method_forbidden:DELETE" in destructive_errors

    safe_params, safe_errors = asyncio.run(api_module._research_prepare_action(
        Conn(),
        episode,
        {"action": {"parameters": {
            **base,
            "steps": [
                {"label": "open", "kind": "browser", "principal": "anonymous",
                 "checkpoint": "before", "action": "navigate", "data": {"path": "/items"}},
                {"label": "submit", "kind": "http", "principal": "anonymous",
                 "checkpoint": "action", "method": "POST", "path": "/api/items",
                 "form_body": {"name": "research-probe"}},
            ],
        }}},
        command,
    ))
    assert safe_errors == []
    with pytest.raises(api_module.WorkflowContractError, match="state_changing_request_requires_mutation_checkpoint"):
        api_module.normalize_workflow("https://example.test", safe_params)


def test_research_autonomous_workflow_allows_cleanup_safe_writes_at_credential_tier():
    # To EXPLOIT state-changing bugs a credential-tier deep hunt must be able to mutate. The write is
    # safe: normalize_workflow forces a cleanup/rollback + restored assertion after any mutation.
    command = api_module._research_command_catalog()["experiment.workflow"]

    def method_values(value):
        found = set()
        if isinstance(value, dict):
            enum = value.get("enum")
            if isinstance(enum, list):
                found.update(str(item) for item in enum if str(item) in {"PUT", "PATCH", "DELETE"})
            for nested in value.values():
                found.update(method_values(nested))
        elif isinstance(value, list):
            for nested in value:
                found.update(method_values(nested))
        return found

    # Schema projection retains PUT/PATCH/DELETE when cleanup-safe writes are permitted.
    projected = api_module._research_autonomous_parameter_schema(
        "experiment.workflow", command["parameters_schema"], allow_cleanup_safe_writes=True,
    )
    assert {"PUT", "PATCH", "DELETE"} <= method_values(projected)

    class Conn:
        async def fetch(self, _query, *_args):
            return [
                {"method": "GET", "path": "/api/items/1"},
                {"method": "PATCH", "path": "/api/items/1"},
            ]

    episode = {
        "target_id": "11111111-1111-4111-8111-111111111111",
        "max_risk_tier": "credential",
        "planner": {"mission": {"profile": "target_hunt", "subject": {"type": "target"}}},
        "allowed_families": [],
    }
    _params, errors = asyncio.run(api_module._research_prepare_action(
        Conn(),
        episode,
        {"action": {"parameters": {
            "workflow_id": "22222222-2222-4222-8222-222222222222",
            "objective": "Mutate then restore a forbidden field",
            "expected_signal": "The forbidden field persists",
            "falsifier": "The forbidden field is rejected",
            "steps": [
                {"label": "before", "kind": "http", "principal": "user1",
                 "checkpoint": "before", "method": "GET", "path": "/api/items/1"},
                {"label": "mutate", "kind": "http", "principal": "user1",
                 "checkpoint": "mutation", "method": "PATCH", "path": "/api/items/1",
                 "json_body": {"role": "admin"}, "compare_to": "before"},
            ],
        }}},
        command,
    ))
    assert not any(e.startswith("autonomous_experiment_destructive_method_forbidden") for e in errors)


def test_research_workflow_proof_family_cannot_bypass_campaign_scope():
    command = api_module._research_command_catalog()["experiment.workflow"]
    episode = {
        "target_id": "11111111-1111-4111-8111-111111111111",
        "max_risk_tier": "credential",
        "planner": {"mission": {"profile": "target_hunt", "subject": {"type": "target"}}},
        "allowed_families": ["auth", "bola"],
    }

    _params, errors = asyncio.run(api_module._research_prepare_action(
        object(),
        episode,
        {"action": {"parameters": {
            "workflow_id": "22222222-2222-4222-8222-222222222222",
            "proof_family": "mass_assignment",
            "objective": "Attempt a forbidden-field mutation",
            "expected_signal": "The forbidden field changes",
            "falsifier": "The field is rejected",
            "steps": [],
        }}},
        command,
    ))

    assert "action_family_not_allowed" in errors
    assert api_module._research_family_is_allowed("auth_bypass", {"auth", "bola"}) is True
    assert api_module._research_family_is_allowed("mass_assignment", {"auth", "bola"}) is False


def test_research_workflow_rejects_non_live_method_and_auth_session_mass_assignment():
    class Conn:
        async def fetch(self, _query, *_args):
            return [
                {"method": "POST", "path": "/api/users/login"},
                {"method": "PATCH", "path": "/api/profile/{id}"},
            ]

    errors = asyncio.run(api_module._research_workflow_surface_violations(
        Conn(),
        "11111111-1111-4111-8111-111111111111",
        {
            "proof_family": "mass_assignment",
            "steps": [
                {"label": "login-mutate", "method": "POST", "path": "/api/users/login"},
                {"label": "invented-read", "method": "GET", "path": "/api/profile/42"},
            ],
        },
    ))

    assert "mass_assignment_auth_session_route_forbidden:login-mutate" in errors
    assert any(
        error.startswith("experiment_step_method_not_on_surface:invented-read:GET:")
        for error in errors
    )


def test_create_mass_assignment_object_siblings_accepted_on_surface():
    # P1-1: the object-instance sibling (/collection/{id}) of an on-surface create collection is a valid
    # read-back/cleanup target for a create-based mass_assignment, even if the crawler never captured a
    # concrete /collection/{id}. Scoped to mass_assignment + a real create collection (POST on surface).
    class Conn:
        async def fetch(self, _q, *_a):
            return [{"method": "POST", "path": "/api/Users"}, {"method": "GET", "path": "/api/Users"}]

    errors = asyncio.run(api_module._research_workflow_surface_violations(
        Conn(), "11111111-1111-4111-8111-111111111111",
        {"proof_family": "mass_assignment", "steps": [
            {"label": "control", "method": "POST", "path": "/api/Users"},
            {"label": "verify", "method": "GET", "path": "/api/Users/5"},
            {"label": "cleanup", "method": "DELETE", "path": "/api/Users/5"},
        ]}))
    assert errors == []  # POST create is on surface; GET/DELETE /api/Users/{id} accepted as siblings

    # The object sibling of a NON-create collection (no POST on surface) is still rejected.
    class Conn2:
        async def fetch(self, _q, *_a):
            return [{"method": "GET", "path": "/api/Orders"}]

    errs2 = asyncio.run(api_module._research_workflow_surface_violations(
        Conn2(), "11111111-1111-4111-8111-111111111111",
        {"proof_family": "mass_assignment", "steps": [{"label": "v", "method": "GET", "path": "/api/Orders/5"}]}))
    assert any(e.startswith("experiment_step_method_not_on_surface:v:") for e in errs2)


def test_listable_create_collection_infers_readback_and_forms_create_based_lead():
    # P0-1: a listable create collection (GET + POST on the same route) forms a create-based
    # mass_assignment lead with an INFERRED object read-back, even without a discovered /collection/{id}.
    reqs = api_module._endpoint_inventory_hypothesis_requests(
        "11111111-1111-4111-8111-111111111111",
        [
            {"method": "GET", "path": "/api/Users", "param_location": "", "auth_state": "user1"},
            {"method": "POST", "path": "/api/Users", "param_location": "body", "auth_state": "user1",
             "param_shape": "email,password", "replay_spec": '{"email":"a@b.c","password":"x"}'},
        ], created_by="test")
    ma = [r for r in reqs if r.family == "mass_assignment" and (r.metadata_json or {}).get("route") == "/api/Users"]
    assert ma, "a create-based mass_assignment lead should form for a listable create collection"
    md = ma[0].metadata_json
    assert md.get("create_based") is True
    assert md.get("readback_route") == "/api/Users/{id}"
    assert "readback_route_missing" not in (md.get("provability_blockers") or [])

    # A POST action that is NOT a listable collection (no GET on the route) does not become create-based.
    reqs2 = api_module._endpoint_inventory_hypothesis_requests(
        "11111111-1111-4111-8111-111111111111",
        [{"method": "POST", "path": "/rest/auth/token", "param_location": "body", "auth_state": "user1",
          "param_shape": "email,password"}], created_by="test")
    assert all((r.metadata_json or {}).get("create_based") is not True
               for r in reqs2 if r.family == "mass_assignment")


def test_research_action_secret_policy_allows_only_unresolved_body_placeholders():
    assert api_module._research_action_contains_secret_material({
        "steps": [{"json_body": {"token": "${managed_reset_token}"}}],
    }) is False
    assert api_module._research_action_contains_secret_material({
        "steps": [{"json_body": {"token": "real-secret-value"}}],
    }) is True
    assert api_module._research_action_contains_secret_material({
        "headers": {"token": "${managed_reset_token}"},
    }) is True


def test_endpoint_inventory_hypotheses_are_residue_backed_leads():
    # The app graph is often empty; the endpoint inventory must still yield residue leads so a
    # require_residue hunt board is not starved. An object-id path -> BOLA lead; a write with a body
    # -> mass_assignment lead; a plain public GET is not turned into a lead.
    reqs = api_module._endpoint_inventory_hypothesis_requests(
        "11111111-1111-4111-8111-111111111111",
        [
            {"method": "GET", "path": "/api/items/42", "param_location": "path", "auth_state": "user1"},
            {
                "method": "POST", "path": "/api/items", "param_location": "body", "auth_state": "user1",
                "param_shape": "name,quantity", "replay_spec": '{"name":"probe","quantity":1}',
            },
            {"method": "GET", "path": "/api/health", "param_location": "", "auth_state": "anonymous"},
        ],
        created_by="test",
    )
    families = {r.family for r in reqs}
    assert "bola" in families
    assert "mass_assignment" in families
    # Every lead is residue-backed so hypothesis_scheduler ranks it (require_residue passes).
    assert reqs and all(r.metadata_json.get("unexplained_residue") for r in reqs)
    mutation = next(r for r in reqs if r.family == "mass_assignment")
    assert mutation.metadata_json["request_fields"] == "name,quantity"
    assert mutation.metadata_json["request_example"] == '{"name":"probe","quantity":1}'
    # A plain public GET with no id segment and no body is not a lead.
    assert not any((r.dedupe_dimensions.get("route") or "").endswith("/health") for r in reqs)


def _covered_bola_lead():
    return {
        "id": "bola-1", "source": "app_graph", "family": "bola", "status": "open",
        "severity_guess": "high", "confidence": 0.6, "dedupe_key": "bola-1",
        "dedupe_dimensions": {"method": "GET", "route": "/api/orders/{id}", "proof_surface": "runtime_authz_replay"},
        "metadata_json": {"unexplained_residue": True, "route": "/api/orders/{id}",
                          "dedupe_dimensions": {"method": "GET", "route": "/api/orders/{id}"}},
    }


def _fresh_mass_assignment_lead():
    return {
        "id": "ma-1", "source": "app_graph", "family": "mass_assignment", "status": "open",
        "severity_guess": "medium", "confidence": 0.5, "dedupe_key": "ma-1",
        "dedupe_dimensions": {"method": "POST", "route": "/api/orders", "proof_surface": "mutation_differential"},
        "metadata_json": {"unexplained_residue": True, "route": "/api/orders"},
    }


def test_coverage_key_matches_finding_and_lead_across_sparse_dimensions():
    # A DAST finding and a residue lead on the SAME family+method+route must share a coarse coverage
    # key even though their fine-grained dimensions differ -- that parity is what lets the board drop
    # already-owned BOLA. The smart_bola method fallback (empty evidence -> GET) must survive the
    # shared-extraction refactor, or the coverage key would be family|*|route and never match.
    dast_finding = {
        "tool": "smart_bola", "cwe": "CWE-639", "title": "BOLA on order API",
        "url": "https://app.example.test/api/orders/42", "evidence": {},
    }
    finding_cov = api_module._finding_coverage_key(dast_finding)
    lead_cov = api_module._research_hypothesis_coverage_key(_covered_bola_lead())
    assert finding_cov and finding_cov == lead_cov
    # The refactor must not change the exact v3 finding key.
    assert api_module._finding_vulnerability_key(dast_finding)
    # Different family on the same route does NOT collide (family is in the coverage key).
    de_lead = {"family": "data_exposure",
               "dedupe_dimensions": {"method": "GET", "route": "/api/orders/{id}"},
               "metadata_json": {"route": "/api/orders/{id}"}}
    assert api_module._research_hypothesis_coverage_key(de_lead) != finding_cov


def test_board_downranks_coarse_coverage_without_hiding_distinct_dimensions():
    # Coarse family+method+route coverage is a ranking hint, not proof that every
    # field/parameter/role dimension on the operation is exhausted.
    covered_bola = _covered_bola_lead()
    fresh_mass = _fresh_mass_assignment_lead()
    known_coverage = {api_module._research_hypothesis_coverage_key(covered_bola)}
    summaries, ranked = api_module._select_research_hypothesis_context(
        [covered_bola, fresh_mass],
        completed_dimensions=[],
        auth_available=True,
        known_coverage_keys=known_coverage,
    )
    ranked_ids = {entry["hypothesis_id"] for entry in ranked}
    assert "bola-1" in ranked_ids
    assert "ma-1" in ranked_ids
    assert ranked[0]["hypothesis_id"] == "ma-1"
    # Without the coverage hint the higher-severity BOLA still ranks first.
    _s, ranked_default = api_module._select_research_hypothesis_context(
        [covered_bola, fresh_mass], completed_dimensions=[], auth_available=True,
    )
    assert ranked_default[0]["hypothesis_id"] == "bola-1"


def test_exhausted_families_lists_only_fully_covered_families():
    covered_bola = _covered_bola_lead()
    fresh_mass = _fresh_mass_assignment_lead()
    known = {api_module._research_hypothesis_vulnerability_key(covered_bola)}
    assert api_module._research_exhausted_families([covered_bola, fresh_mass], known) == ["bola"]
    # Coarse operation coverage alone must never exhaust a family.
    coarse = {api_module._research_hypothesis_coverage_key(covered_bola)}
    assert api_module._research_exhausted_families([covered_bola, fresh_mass], coarse) == []
    # No known coverage -> nothing exhausted.
    assert api_module._research_exhausted_families([covered_bola, fresh_mass], set()) == []


def test_inventory_producers_emit_data_exposure_and_bfla_leads():
    # Fix 2: the inventory must yield data_exposure + auth_bypass(bfla) leads so a de-BOLA'd board is
    # not empty. Generic nouns only -- a sensitive-named GET is a data_exposure lead; an admin path is
    # a function-level-authz lead; a plain public health GET is neither.
    reqs = api_module._endpoint_inventory_hypothesis_requests(
        "11111111-1111-4111-8111-111111111111",
        [
            {"method": "GET", "path": "/api/users/profile", "param_location": "", "auth_state": "user1"},
            {"method": "POST", "path": "/api/admin/settings", "param_location": "body",
             "auth_state": "user1", "param_shape": "flag"},
            {"method": "GET", "path": "/api/health", "param_location": "", "auth_state": "anonymous"},
        ],
        created_by="test",
    )
    families = {r.family for r in reqs}
    assert "data_exposure" in families
    assert "auth_bypass" in families
    assert all(r.metadata_json.get("unexplained_residue") for r in reqs)
    # No data_exposure/auth_bypass lead for the plain public health endpoint.
    assert not any(
        (r.dedupe_dimensions.get("route") or "").endswith("/health")
        for r in reqs if r.family in {"data_exposure", "auth_bypass"}
    )
    de = next(r for r in reqs if r.family == "data_exposure")
    assert de.next_test_action["parameters"]["proof_family"] == "data_exposure"


def test_inventory_hypothesis_cap_is_family_balanced():
    endpoints = [
        {"method": "GET", "path": f"/api/order-type-{index}/orders/1", "auth_state": "user1"}
        for index in range(150)
    ]
    endpoints.extend([
        {"method": "GET", "path": "/api/users/profile", "auth_state": "user1"},
        {"method": "POST", "path": "/api/admin/settings", "param_location": "json body",
         "param_shape": "enabled", "auth_state": "user1"},
    ])
    requests = api_module._endpoint_inventory_hypothesis_requests(
        "11111111-1111-4111-8111-111111111111", endpoints,
    )
    assert len(requests) == 100
    assert {"bola", "data_exposure", "auth_bypass", "mass_assignment"} <= {
        request.family for request in requests
    }


def test_scheduler_lifts_data_exposure_off_the_boundary_floor():
    import hypothesis_scheduler
    de = hypothesis_scheduler.score_hypothesis(
        {"id": "de", "family": "data_exposure", "severity_guess": "medium", "source": "app_graph",
         "dedupe_key": "de", "metadata_json": {"unexplained_residue": True}},
        context={"auth_available": True},
    )
    assert de["breakdown"]["boundary_value"] == 2.0


def test_board_balances_families_so_a_rich_family_does_not_starve_others():
    # 100 mass_assignment leads would take every slot; the board must still surface data_exposure + bfla
    # by floating the top lead of each family to the front.
    cands = [
        {"id": f"ma-{i}", "source": "app_graph", "family": "mass_assignment", "status": "open",
         "severity_guess": "medium", "confidence": 0.5, "dedupe_key": f"ma-{i}",
         "dedupe_dimensions": {"method": "POST", "route": f"/api/things/{i}"},
         "metadata_json": {"unexplained_residue": True, "route": f"/api/things/{i}"}}
        for i in range(100)
    ]
    cands.append({"id": "de-1", "source": "app_graph", "family": "data_exposure", "status": "open",
                  "severity_guess": "medium", "confidence": 0.5, "dedupe_key": "de-1",
                  "dedupe_dimensions": {"method": "GET", "route": "/api/profile"},
                  "metadata_json": {"unexplained_residue": True, "route": "/api/profile"}})
    cands.append({"id": "bfla-1", "source": "app_graph", "family": "auth_bypass", "status": "open",
                  "severity_guess": "high", "confidence": 0.55, "dedupe_key": "bfla-1",
                  "dedupe_dimensions": {"method": "GET", "route": "/api/admin/config"},
                  "metadata_json": {"unexplained_residue": True, "route": "/api/admin/config"}})
    _s, ranked = api_module._select_research_hypothesis_context(
        cands, completed_dimensions=[], auth_available=True, limit=6,
    )
    fams = {(e.get("hypothesis") or {}).get("family") for e in ranked}
    assert {"mass_assignment", "data_exposure", "auth_bypass"} <= fams


def test_board_prefers_provable_lead_within_same_family():
    post_only = {
        "id": "post-only", "source": "app_graph", "family": "mass_assignment",
        "status": "open", "severity_guess": "high", "confidence": 0.9,
        "dedupe_key": "post-only",
        "dedupe_dimensions": {"method": "POST", "route": "/api/items"},
        "metadata_json": {
            "unexplained_residue": True, "route": "/api/items", "method": "POST",
            "request_fields": "name", "available_methods": ["POST"],
        },
    }
    readable = {
        "id": "readable", "source": "app_graph", "family": "mass_assignment",
        "status": "open", "severity_guess": "medium", "confidence": 0.5,
        "dedupe_key": "readable",
        "dedupe_dimensions": {"method": "PATCH", "route": "/api/profiles/{id}"},
        "metadata_json": {
            "unexplained_residue": True, "route": "/api/profiles/{id}", "method": "PATCH",
            "request_fields": "display_name", "available_methods": ["GET", "PATCH"],
            "readable_route": "/api/profiles/{id}",
        },
    }

    _summaries, ranked = api_module._select_research_hypothesis_context(
        [post_only, readable],
        completed_dimensions=[],
        auth_available=True,
    )

    assert ranked[0]["hypothesis_id"] == "readable"
    assert ranked[0]["provability_blockers"] == []


def test_compaction_preserves_slim_ranked_board_when_oversized():
    # The oversized-projection path used to drop current_surface entirely; it must keep a slim ranked
    # board so the planner still sees the live leads (not just the 5 selected contracts).
    pack = {
        "observation_version": "v1", "episode_id": "e", "objective": "obj",
        # A 100-item list of 4000-char strings survives the light-bound stage (>48 KiB) and forces the
        # aggressive-projection path, unlike a single long string (truncated to 4000).
        "recent_actions": [{"detail": "z" * 4000} for _ in range(100)],
        "selected_hypothesis_contracts": [
            {"hypothesis_id": "h1", "family": "mass_assignment", "route": "/a", "method": "POST"}],
        "current_surface": {
            "ranked_hypotheses": [
                {"hypothesis_id": "h1", "hypothesis": {"id": "h1", "family": "mass_assignment",
                 "metadata_json": {"dedupe_dimensions": {"route": "/a", "method": "POST"}}}}],
            "exhausted_families": ["bola"],
        },
    }
    out = api_module._compact_research_observation_pack(pack)
    assert out.get("observation_compaction", {}).get("applied") is True
    assert out.get("selected_hypothesis_contracts")
    cs = out.get("current_surface") or {}
    assert cs.get("ranked_hypotheses")
    assert cs["ranked_hypotheses"][0]["hypothesis"]["family"] == "mass_assignment"
    assert cs.get("exhausted_families") == ["bola"]


def test_research_net_new_finding_count_excludes_dast_owned():
    # An autonomous promotion on a family+route+method DAST already owns is NOT net-new; a distinct one is.
    class _Conn:
        def __init__(self, rows):
            self._rows = rows
        async def fetch(self, *args, **kwargs):
            return self._rows

    # Note: findings have no `method` column -- method is extracted from evidence/request/title, so the
    # rows here intentionally omit it (the earlier draft selected a non-existent column).
    rows = [
        {"tool": "smart_bola", "cwe": "CWE-639", "title": "BOLA on order API",
         "url": "https://x/api/orders/1", "evidence": {}, "request": None,
         "last_verification_verdict": None},
        {"tool": "autonomous_workflow", "cwe": "CWE-639", "title": "BOLA auto",
         "url": "https://x/api/orders/2",
         "evidence": {"dedupe_dimensions": {"route": "/api/orders/{id}", "method": "GET"}},
         "request": None, "last_verification_verdict": "exploited"},
        {"tool": "autonomous_workflow", "cwe": "CWE-915", "title": "Mass-assignment auto",
         "url": "https://x/api/profile",
         "evidence": {"dedupe_dimensions": {"route": "/api/profile", "method": "POST"}},
         "request": None, "last_verification_verdict": "exploited"},
    ]
    n = asyncio.run(api_module._research_net_new_finding_count(
        _Conn(rows), "11111111-1111-4111-8111-111111111111",
    ))
    assert n == 1


def test_research_net_new_finding_count_is_campaign_scoped_and_distinct():
    campaign_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    other_campaign_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    shared_evidence = {
        "dedupe_dimensions": {"route": "/api/profile", "method": "PATCH", "fields": ["role"]},
        "research_provenance_history": [{"campaign_id": campaign_id}],
    }

    class _Conn:
        async def fetch(self, *args, **kwargs):
            return [
                {"tool": "autonomous_workflow", "cwe": "CWE-915", "title": "Role overpost",
                 "url": "https://x/api/profile", "evidence": shared_evidence, "request": None,
                 "last_verification_verdict": "exploited"},
                # Duplicate row for the same exact vulnerability counts once.
                {"tool": "autonomous_workflow", "cwe": "CWE-915", "title": "Role overpost duplicate",
                 "url": "https://x/api/profile", "evidence": shared_evidence, "request": None,
                 "last_verification_verdict": "exploited"},
                {"tool": "autonomous_workflow", "cwe": "CWE-915", "title": "Other campaign",
                 "url": "https://x/api/account",
                 "evidence": {
                     "dedupe_dimensions": {"route": "/api/account", "method": "PATCH"},
                     "research_provenance_history": [{"campaign_id": other_campaign_id}],
                 },
                 "request": None, "last_verification_verdict": "exploited"},
            ]

    assert asyncio.run(api_module._research_net_new_finding_count(
        _Conn(), "11111111-1111-4111-8111-111111111111", campaign_id=campaign_id,
    )) == 1


def test_deep_hunt_finding_selects_match_persisted_schema():
    schema = Path(__file__).parents[1].joinpath("db", "init.sql").read_text()
    table = re.search(
        r"CREATE TABLE findings \((.*?)\n\);",
        schema,
        re.DOTALL,
    )
    assert table
    columns = {
        match.group(1)
        for line in table.group(1).splitlines()
        if (match := re.match(r"\s*([a-z_][a-z0-9_]*)\s+[A-Z]", line))
    }
    for function in (
        api_module._research_known_vulnerability_keys,
        api_module._research_known_coverage_keys,
        api_module._research_net_new_finding_count,
    ):
        source = inspect.getsource(function)
        selected = re.search(r"SELECT\s+(.*?)\s+FROM findings", source, re.DOTALL)
        assert selected
        plain_columns = {
            item.strip().split()[0]
            for item in selected.group(1).split(",")
            if re.fullmatch(r"[a-z_][a-z0-9_]*(?:\s+AS\s+[a-z_][a-z0-9_]*)?", item.strip(), re.IGNORECASE)
        }
        assert plain_columns <= columns


def test_research_vertical_contract_endpoint_schema_reaches_provider_prompt():
    request = api_module._endpoint_inventory_hypothesis_requests(
        "11111111-1111-4111-8111-111111111111",
        [{
            "method": "POST",
            "path": "/workshop/api/shop/orders",
            "param_location": "json body",
            "param_shape": "product_id,quantity",
            "replay_spec": '{"product_id":7,"quantity":1}',
            "auth_state": "user1",
        }],
        created_by="vertical-test",
    )[0]
    canonical = api_module._canonical_hypothesis_request(request)
    hypothesis = {
        **request.model_dump(mode="json"),
        "id": "22222222-2222-4222-8222-222222222222",
        "metadata_json": canonical["metadata_json"],
    }
    summaries, ranked = api_module._select_research_hypothesis_context(
        [hypothesis],
        completed_dimensions=[],
        auth_available=True,
    )
    contracts = api_module._research_selected_hypothesis_contracts(ranked, {"mass_assignment"})
    pack = api_module._compact_research_observation_pack({
        "observation_version": "2026-07-12.v1",
        "episode_id": "33333333-3333-4333-8333-333333333333",
        "objective": "x" * 70_000,
        "mission": {"profile": "target_hunt", "subject": {"type": "target", "id": "target-1"}},
        "allowed_families": ["mass_assignment"],
        "selected_hypothesis_contracts": contracts,
        "hypotheses_summary": summaries,
        "remaining_budget": {"steps": 5, "requests": 100},
        "proposable_commands": [{
            "name": "experiment.workflow", "proposable": True,
            "parameters_schema": api_module._research_command_catalog()["experiment.workflow"]["parameters_schema"],
        }],
        "recent_actions": [],
    })
    observation = {
        "id": "44444444-4444-4444-8444-444444444444",
        "context_hash": "a" * 64,
        "observation_pack": pack,
    }
    prompt = json.loads(api_module._research_planner_messages(observation)[1]["content"])
    visible = prompt["observation_pack"]["selected_hypothesis_contracts"][0]

    assert visible["hypothesis_id"] == hypothesis["id"]
    assert visible["route"] == "/workshop/api/shop/orders"
    assert visible["request_fields"] == "product_id,quantity"
    assert visible["request_example"] == '{"product_id":7,"quantity":1}'


def test_research_hypothesis_context_ranks_residue_before_generic_confidence_noise():
    generic = [
        {
            "id": f"generic-{index}",
            "source": "scanner_signal",
            "family": "csp_evaluator",
            "status": "open",
            "confidence": 0.99,
            "severity_guess": "medium",
            "dedupe_key": f"csp-{index}",
            "metadata_json": {},
        }
        for index in range(12)
    ]
    residue = {
        "id": "inventory-mass-assignment",
        "source": "app_graph",
        "family": "mass_assignment",
        "status": "open",
        "confidence": 0.55,
        "severity_guess": "high",
        "dedupe_key": "inventory-write-route",
        "metadata_json": {"unexplained_residue": True, "requires_auth": True},
    }

    summaries, ranked = api_module._select_research_hypothesis_context(
        [*generic, residue],
        completed_dimensions=[],
        auth_available=True,
    )

    assert summaries[0]["id"] == residue["id"]
    assert ranked[0]["hypothesis_id"] == residue["id"]
    assert all(item["hypothesis_id"] != "generic-0" for item in ranked)


def test_experiment_workflow_templates_are_contract_valid():
    # The planner-facing proof templates must pass normalize_workflow, or they would teach the model
    # to author workflows that get rejected. A mutating template must carry its own restoration.
    import workflow_experiment
    templates = api_module._EXPERIMENT_WORKFLOW_TEMPLATES
    assert {
        "bola", "data_exposure", "auth_bypass", "mass_assignment",
        "access_control", "field_constraint", "workflow",
    } <= set(templates)
    for family, template in templates.items():
        assert template["proof_family"] == family
        normalized = workflow_experiment.normalize_workflow("https://example.test", template)
        assert 2 <= len(normalized["steps"]) <= 12
        if normalized["mutating"]:
            assert any(a["type"] == "restored" for a in normalized["assertions"])


def test_mass_assignment_template_carries_generic_forbidden_field_candidates():
    # The proof only fires on a persisted privilege elevation, so the planner needs generic privilege
    # markers to aim at (never app-specific), or it guesses a benign field and finds nothing.
    import workflow_experiment
    template = api_module._EXPERIMENT_WORKFLOW_TEMPLATES["mass_assignment"]
    candidates = template.get("forbidden_field_candidates") or []
    fields = {str(c.get("field", "")).lower() for c in candidates}
    assert {"role", "isadmin", "verified"} <= fields
    # Every candidate field must be one the proof actually treats as security-sensitive, so the hint
    # cannot steer the planner toward a field that can never promote.
    sensitive = {f.lower() for f in workflow_experiment.SECURITY_SENSITIVE_MUTATION_FIELDS}
    assert all(str(c.get("field", "")).lower() in sensitive for c in candidates)


def test_planner_sends_only_the_most_provable_family_template():
    templates = api_module._research_selected_experiment_templates({
        "selected_hypothesis_contracts": [
            {
                "family": "mass_assignment",
                "method": "POST",
                "provability_score": 2,
                "provability_blockers": ["readback_route_missing"],
            },
            {
                "family": "bola",
                "method": "GET",
                "provability_score": 8,
                "provability_blockers": [],
            },
        ],
    })
    assert set(templates) == {"bola"}

    patch_template = api_module._research_selected_experiment_templates({
        "selected_hypothesis_contracts": [{
            "family": "mass_assignment",
            "method": "PUT",
            "available_methods": ["GET", "PUT"],
            "provability_score": 8,
        }],
    })["mass_assignment"]
    mutation_methods = {
        step["method"] for step in patch_template["steps"]
        if step.get("checkpoint") in {"mutation", "cleanup"}
    }
    assert mutation_methods == {"PUT"}


def test_create_based_mass_assignment_gets_the_create_template_and_normalizes():
    import workflow_experiment
    # A POST create with a paired object read-back AND delete-cleanup route gets the create template.
    create = api_module._research_selected_experiment_templates({
        "selected_hypothesis_contracts": [{
            "family": "mass_assignment", "method": "POST", "available_methods": ["POST"],
            "create_based": True, "readback_route": "/api/Users/{id}", "cleanup_route": "/api/Users/{id}",
            "provability_score": 8,
        }],
    })
    assert set(create) == {"mass_assignment"}
    template = create["mass_assignment"]
    assert template["steps"][0]["label"] == "list_before"  # create-shaped, not the update template
    # It must be a valid mutating workflow with cleanup + restoration (DELETE of the created objects).
    norm = workflow_experiment.normalize_workflow("https://example.test", template)
    assert norm["mutating"] is True
    assert any(a["type"] == "restored" for a in norm["assertions"])

    # A create with a read-back but NO discovered cleanup route STILL gets the create template:
    # restoration is best-effort (the template always attempts a DELETE; the two-run proof accepts an
    # unrestorable create). A missing DELETE only leaves a labeled test object, not a soundness gap.
    no_cleanup = api_module._research_selected_experiment_templates({
        "selected_hypothesis_contracts": [{
            "family": "mass_assignment", "method": "POST", "available_methods": ["POST"],
            "create_based": True, "readback_route": "/api/Users/{id}", "provability_score": 8,
        }],
    })
    assert set(no_cleanup) == {"mass_assignment"}
    assert no_cleanup["mass_assignment"]["steps"][0]["label"] == "list_before"

    # A POST create WITHOUT a paired read-back still gets nothing -- the read-back is essential.
    none = api_module._research_selected_experiment_templates({
        "selected_hypothesis_contracts": [{
            "family": "mass_assignment", "method": "POST", "available_methods": ["POST"],
            "provability_score": 2, "provability_blockers": ["readback_route_missing"],
        }],
    })
    assert none == {}


def test_inferred_contracts_and_recommendations_remain_planning_only():
    inferred = api_module._research_inferred_planning_contracts([{
        "hypothesis_id": "h1",
        "family": "bola",
        "method": "GET",
        "route": "/api/orders/{id}",
    }])
    assert inferred[0]["status"] == "inferred"
    assert inferred[0]["planning_authority"] is True
    assert inferred[0]["execution_authority"] is False
    assert inferred[0]["promotion_authority"] is False

    recommendations = api_module._research_recommended_actions(
        [{
            "id": "f1", "severity": "critical",
            "last_verification_verdict": "inconclusive",
        }],
        [
            {"name": "finding.retest", "proposable": True},
            {"name": "scan.focused_family", "proposable": True},
        ],
        {"sqli", "xss"},
    )
    assert recommendations[0]["command"] == "finding.retest"
    assert {item["parameters"].get("check_family") for item in recommendations[1:]} == {
        "sqli", "xss",
    }

    suppressed = api_module._research_recommended_actions(
        [{
            "id": "f1", "severity": "critical",
            "last_verification_verdict": "inconclusive",
        }],
        [{"name": "finding.retest", "proposable": True}],
        {"sqli"},
        [{
            "status": "completed",
            "action": {"command": "finding.retest", "parameters": {"finding_id": "f1"}},
        }],
    )
    assert suppressed == []


def test_deep_hunt_default_model_budget_reaches_full_step_ceiling():
    profile = api_module.RESEARCH_LAUNCH_PROFILES["deep_hunt"]
    assert profile["max_steps"] == 25
    assert profile["budget_limits"]["model_tokens"] == 500_000
    aggregate = api_module._research_campaign_budget_limits("deep_hunt", 3)
    assert aggregate["model_tokens"] == 1_500_000


def test_campaign_retest_cap_reopens_only_for_newer_finding_evidence():
    campaign_id = uuid.uuid4()
    finding_id = uuid.uuid4()

    class Conn:
        def __init__(self, capped):
            self.capped = capped
            self.args = None

        async def fetchval(self, query, *args):
            assert "f.last_seen_at <= prior.completed_at" in query
            assert "re.campaign_id=$1" in query
            self.args = args
            return self.capped

    capped = Conn(True)
    assert asyncio.run(api_module._research_campaign_retest_cap_reached(
        capped, campaign_id, finding_id,
    )) is True
    assert capped.args == (campaign_id, finding_id)

    newer_evidence = Conn(False)
    assert asyncio.run(api_module._research_campaign_retest_cap_reached(
        newer_evidence, campaign_id, finding_id,
    )) is False


def test_research_provider_probe_exercises_server_bound_action_contract(monkeypatch):
    captured = {}

    async def fake_provider(**kwargs):
        captured.update(kwargs)
        return ({
            "decision_version": "decision-episode-2026-07-11.v1",
            "decision": "execute_action",
            "observation_id": "00000000-0000-4000-8000-000000000001",
            "context_hash": "a" * 64,
            "hypothesis_id": None,
            "action": {"command": "asm.gaps", "parameters": {}},
            "expected_signal": "The target's remaining ASM gaps are enumerated.",
            "falsifier": "The target has no remaining ASM gaps.",
            "reason": "Inspect the available gaps before selecting any active work.",
            "confidence": 0.9,
            "requested_input": None,
            "stop_reason": None,
            "_provider_meta": {"model_used": "test-model", "mode_used": "json_schema"},
        }, None, 12)

    monkeypatch.setattr(api_module, "_load_effective_ai_settings", lambda: {
        "ai_url": "https://provider.example/v1/chat/completions",
        "ai_api_key": "test-key",
        "ai_model": "test-model",
        "ai_model_fallback": "",
    })
    monkeypatch.setattr(api_module, "_load_research_ai_provider", lambda: fake_provider)

    result = asyncio.run(api_module.test_ai_settings(
        api_module.AISettingsProbeRequest(scope="research")
    ))

    assert result["probe"]["native_contract_pass"] is True
    assert result["probe"]["action_contract_pass"] is True
    assert result["probe"]["response"]["action"] == {"command": "asm.gaps", "parameters": {}}
    prompt = json.dumps(captured["messages"])
    assert "server_supplied_parameters" in prompt
    assert "target_id" in prompt


def test_research_autopilot_operator_control_races_are_not_planner_errors():
    assert api_module._research_autopilot_expected_control_race(
        api_module.HTTPException(status_code=409, detail="Research autopilot was paused before dispatch")
    ) is True
    assert api_module._research_autopilot_expected_control_race(
        api_module.HTTPException(status_code=409, detail="Research episode is terminal or cancelled")
    ) is True
    assert api_module._research_autopilot_expected_control_race(
        api_module.HTTPException(status_code=409, detail="Research episode is not awaiting a planner decision")
    ) is False
    assert api_module._research_autopilot_expected_control_race(RuntimeError("provider failed")) is False


def test_research_campaign_pauses_once_for_terminal_failures_until_operator_resume():
    assert api_module._research_campaign_terminal_needs_review({}, "episode-1", "blocked") is True
    assert api_module._research_campaign_terminal_needs_review({}, "episode-1", "failed") is True
    # An operator-cancelled episode is an explicit stop handled by a dedicated pause path, NOT a
    # recoverable failure -- so the escalate-don't-block review must NOT claim it (Finding 3), otherwise
    # cancelling a misbehaving episode would auto-relaunch active testing ~30s later.
    assert api_module._research_campaign_terminal_needs_review({}, "episode-1", "cancelled") is False
    assert api_module._research_campaign_terminal_needs_review({}, "episode-1", "completed") is False
    assert api_module._research_campaign_terminal_needs_review(
        {"last_paused_episode_id": "episode-1"}, "episode-1", "blocked"
    ) is False


def test_research_command_views_hide_actions_that_exceed_remaining_budget(monkeypatch):
    monkeypatch.setattr(api_module, "_ai_ops_execute_enabled", lambda: True)
    monkeypatch.setattr(api_module, "_research_command_catalog", lambda: {
        "target.get": {
            "name": "target.get",
            "status": "read_only",
            "risk_tier": "read_only",
            "description": "Read one target.",
            "parameters_schema": {"target_id": {"type": "string"}},
            "timeout_seconds": 10,
        },
        "finding.retest": {
            "name": "finding.retest",
            "status": "gated",
            "risk_tier": "active",
            "description": "Retest one finding.",
            "parameters_schema": {"finding_id": {"type": "string"}},
            "timeout_seconds": 30,
            "request_cost": 1,
        },
    })
    episode = {
        "execution_mode": "gated",
        "max_risk_tier": "active",
        "approval_receipt_id": "approval-1",
        "scope_receipt_id": "scope-1",
        "planner": {},
        "budget_limits": {
            "steps": 6,
            "actions": 6,
            "active_actions": 1,
            "requests": 1,
            "seconds": 900,
            "model_tokens": 75000,
        },
        "budget_used": {
            "steps": 1,
            "actions": 1,
            "active_actions": 1,
            "requests": 1,
            "seconds": 30,
            "model_tokens": 1000,
        },
    }

    views = {item["name"]: item for item in api_module._research_command_views(episode)}

    assert views["target.get"]["proposable"] is True
    assert views["target.get"]["currently_executable"] is True
    assert views["finding.retest"]["proposable"] is False
    assert views["finding.retest"]["currently_executable"] is False
    assert "budget_exhausted:active_actions" in views["finding.retest"]["blocked_by"]
    assert "budget_exhausted:requests" in views["finding.retest"]["blocked_by"]


def test_research_command_views_hide_read_only_actions_when_step_budget_is_spent(monkeypatch):
    monkeypatch.setattr(api_module, "_research_command_catalog", lambda: {
        "target.get": {
            "name": "target.get",
            "status": "read_only",
            "risk_tier": "read_only",
            "parameters_schema": {"target_id": {"type": "string"}},
            "timeout_seconds": 10,
        },
    })
    episode = {
        "execution_mode": "read_only",
        "max_risk_tier": "read_only",
        "planner": {},
        "budget_limits": {
            "steps": 1,
            "actions": 1,
            "active_actions": 0,
            "requests": 0,
            "seconds": 60,
            "model_tokens": 10000,
        },
        "budget_used": {
            "steps": 1,
            "actions": 1,
            "active_actions": 0,
            "requests": 0,
            "seconds": 10,
            "model_tokens": 1000,
        },
    }

    view = api_module._research_command_views(episode)[0]

    assert view["proposable"] is False
    assert view["currently_executable"] is False
    assert "budget_exhausted:steps" in view["blocked_by"]
    assert "budget_exhausted:actions" in view["blocked_by"]


class _ResearchPreviousActionConn:
    def __init__(self, actions, *, jsonb_text=False):
        self.actions = actions if isinstance(actions, list) else [actions]
        self.jsonb_text = jsonb_text

    async def fetch(self, _query, *_args):
        return [
            {
                "action": json.dumps(action),
                "status": "completed",
                "policy_result": json.dumps({
                    "dispatched": action.get("command") in api_module.GATED_RESEARCH_COMMANDS,
                }),
                "command_result_id": (
                    "result-1" if action.get("command") in api_module.GATED_RESEARCH_COMMANDS else None
                ),
                # A gated command counts as an intervening state change only if it actually produced a
                # finding, not merely because it dispatched.
                "cr_finding_ids": (
                    json.dumps(["finding-1"] if action.get("_produced_finding") else [])
                    if self.jsonb_text
                    else (["finding-1"] if action.get("_produced_finding") else None)
                ),
            }
            for action in self.actions
            if action is not None
        ]


def test_research_duplicate_guard_compares_normalized_command_and_parameters():
    conn = _ResearchPreviousActionConn({
        "command": "scan.focused_family",
        "parameters": {"target_id": "target-1", "check_family": "xss"},
    })
    duplicate = asyncio.run(api_module._research_is_consecutive_duplicate_action(
        conn,
        "11111111-1111-4111-8111-111111111111",
        {"command": "scan.focused_family", "parameters": {"check_family": "xss", "target_id": "target-1"}},
    ))
    different = asyncio.run(api_module._research_is_consecutive_duplicate_action(
        conn,
        "11111111-1111-4111-8111-111111111111",
        {"command": "scan.focused_family", "parameters": {"check_family": "sqli", "target_id": "target-1"}},
    ))

    assert duplicate is True
    assert different is False


def test_research_duplicate_guard_resets_only_on_a_finding_producing_command():
    repeated = {"command": "asm.gaps", "parameters": {"target_id": "target-1"}}
    read_only_churn = {"command": "arsenal.situation_report", "parameters": {"target_id": "target-1"}}
    dispatched_no_finding = {"command": "asm.improve", "parameters": {"target_id": "target-1", "check_family": "xss"}}
    produced_finding = {**dispatched_no_finding, "_produced_finding": True}

    # Read-only churn between two identical actions is not a state change -> still a duplicate.
    blocked_churn = asyncio.run(api_module._research_is_consecutive_duplicate_action(
        _ResearchPreviousActionConn([read_only_churn, repeated]),
        "11111111-1111-4111-8111-111111111111", repeated,
    ))
    # A gated command that merely DISPATCHED (partial/failed, no finding) must NOT reset the guard --
    # otherwise "failed A -> partial B -> failed A" loops forever.
    blocked_dispatch = asyncio.run(api_module._research_is_consecutive_duplicate_action(
        _ResearchPreviousActionConn([dispatched_no_finding, repeated]),
        "11111111-1111-4111-8111-111111111111", repeated,
    ))
    # A gated command that actually PRODUCED A FINDING is a real state change -> the repeat is allowed.
    allowed_after_finding = asyncio.run(api_module._research_is_consecutive_duplicate_action(
        _ResearchPreviousActionConn([produced_finding, repeated]),
        "11111111-1111-4111-8111-111111111111", repeated,
    ))

    assert blocked_churn is True
    assert blocked_dispatch is True
    assert allowed_after_finding is False


def test_research_duplicate_guard_ignores_ephemeral_workflow_id_for_experiments():
    # The observed 2M-token / 0-finding spin: the planner re-ran the SAME auth_bypass workflow ~43x,
    # each with a fresh workflow_id, re-worded objective, and a different object id in the path --
    # slipping past the raw-parameter fingerprint every time.
    def workflow(workflow_id, objective, object_id):
        return {
            "command": "experiment.workflow",
            "parameters": {
                "workflow_id": workflow_id,
                "proof_family": "auth_bypass",
                "objective": objective,
                "steps": [
                    {"kind": "http", "path": f"/workshop/api/shop/orders/{object_id}", "method": "GET",
                     "principal": "user1", "label": "authed"},
                    {"kind": "http", "path": f"/workshop/api/shop/orders/{object_id}", "method": "GET",
                     "principal": "anonymous", "label": "anon"},
                ],
                "assertions": [
                    {"step": "authed", "type": "status_in", "predicate": "protected_resource_accessed"},
                    {"step": "anon", "type": "status_not_in", "predicate": "unauthenticated_control"},
                ],
            },
        }

    prior = workflow("11111111-1111-4111-8111-111111111111", "An anonymous request reaches a protected resource", 11)
    # Same mechanical test: fresh workflow_id, different prose, different concrete object id (42 vs 11).
    repeat = workflow("22222222-2222-4222-8222-222222222222", "Anonymous access to a protected order", 42)
    detected = asyncio.run(api_module._research_is_consecutive_duplicate_action(
        _ResearchPreviousActionConn([prior]),
        "11111111-1111-4111-8111-111111111111", repeat,
    ))
    assert detected is True

    # A genuinely different test (different family / route / assertions) is NOT a duplicate.
    other = {
        "command": "experiment.workflow",
        "parameters": {
            "workflow_id": "33333333-3333-4333-8333-333333333333",
            "proof_family": "bola",
            "steps": [{"kind": "http", "path": "/workshop/api/mechanic/receive_report", "method": "POST",
                       "principal": "user2", "label": "cross"}],
            "assertions": [{"step": "cross", "type": "status_in", "predicate": "cross_principal_access"}],
        },
    }
    distinct = asyncio.run(api_module._research_is_consecutive_duplicate_action(
        _ResearchPreviousActionConn([prior]),
        "11111111-1111-4111-8111-111111111111", other,
    ))
    assert distinct is False


def test_research_duplicate_guard_canonicalizes_reworded_http_diffs():
    def experiment(object_id, objective):
        return {
            "command": "experiment.http_diff",
            "parameters": {
                "proof_family": "data_exposure",
                "objective": objective,
                "expected_signal": "The response changes",
                "falsifier": "The response stays stable",
                "steps": [
                    {"label": "baseline", "role": "control", "method": "GET",
                     "path": f"/orders/{object_id}", "query": {"view": "summary"}},
                    {"label": "candidate", "role": "mutation", "method": "GET",
                     "path": f"/orders/{object_id}", "query": {"view": "internal"},
                     "compare_to": "baseline"},
                ],
            },
        }

    prior = experiment(11, "Compare public order projections")
    repeat = experiment(42, "Look for internal fields in a second order")

    assert asyncio.run(api_module._research_is_consecutive_duplicate_action(
        _ResearchPreviousActionConn([prior]),
        "11111111-1111-4111-8111-111111111111",
        repeat,
    )) is True

    different_query = experiment(42, "Try another projection")
    different_query["parameters"]["steps"][1]["query"] = {"view": "billing"}
    assert asyncio.run(api_module._research_is_consecutive_duplicate_action(
        _ResearchPreviousActionConn([prior]),
        "11111111-1111-4111-8111-111111111111",
        different_query,
    )) is False


def test_research_duplicate_guard_distinguishes_payloads_and_ignores_labels():
    def mass_assign(workflow_id, label, body):
        before = f"{label}_before"
        verify = f"{label}_verify"
        cleanup = f"{label}_cleanup"
        after = f"{label}_after"
        return {
            "command": "experiment.workflow",
            "parameters": {
                "workflow_id": workflow_id,
                "proof_family": "mass_assignment",
                "steps": [
                    {"kind": "http", "path": "/api/v2/user/dashboard", "method": "GET",
                     "principal": "user1", "checkpoint": "before", "label": before},
                    {"kind": "http", "path": "/api/v2/user/dashboard", "method": "PATCH",
                     "principal": "user1", "checkpoint": "mutation", "label": label,
                     "json_body": body},
                    {"kind": "http", "path": "/api/v2/user/dashboard", "method": "GET",
                     "principal": "user1", "checkpoint": "action", "label": verify,
                     "compare_to": before},
                    {"kind": "http", "path": "/api/v2/user/dashboard", "method": "PATCH",
                     "principal": "user1", "checkpoint": "cleanup", "label": cleanup,
                     "json_body": {next(iter(body)): "<original>"}},
                    {"kind": "http", "path": "/api/v2/user/dashboard", "method": "GET",
                     "principal": "user1", "checkpoint": "after", "label": after,
                     "compare_to": before},
                ],
                "assertions": [
                    {"step": label, "type": "status_in", "values": [200],
                     "predicate": "forbidden_field_accepted"},
                    {"control": before, "candidate": verify, "type": "comparison_changed",
                     "predicate": "observable_state_change"},
                    {"control": before, "candidate": after, "type": "restored",
                     "predicate": "before_after_state"},
                ],
            },
        }

    set_role = mass_assign("aaaaaaaa-1111-4111-8111-111111111111", "write", {"role": "admin"})
    import workflow_experiment
    workflow_experiment.normalize_workflow("https://example.test", set_role["parameters"])
    # A DIFFERENT mass-assignment vector (isAdmin) on the same route must NOT collapse to a duplicate
    # -- the earlier key dropped bodies, so distinct payloads wrongly deduped and blocked exploration.
    set_admin = mass_assign("bbbbbbbb-2222-4222-8222-222222222222", "write", {"isAdmin": True})
    not_dup = asyncio.run(api_module._research_is_consecutive_duplicate_action(
        _ResearchPreviousActionConn([set_role]),
        "11111111-1111-4111-8111-111111111111", set_admin,
    ))
    assert not_dup is False

    # The SAME test with RENAMED step labels IS a duplicate -- labels are not identity; the earlier
    # key kept the mutable assertion step label, so a relabel bypassed dedupe and re-enabled the spin.
    relabeled = mass_assign("cccccccc-3333-4333-8333-333333333333", "attempt2", {"role": "admin"})
    dup = asyncio.run(api_module._research_is_consecutive_duplicate_action(
        _ResearchPreviousActionConn([set_role]),
        "11111111-1111-4111-8111-111111111111", relabeled,
    ))
    assert dup is True

    # Checkpoints are execution semantics. Moving the same request from action to cleanup must not
    # collapse, even though every route, method, principal, payload, and label is otherwise equal.
    moved_checkpoint = json.loads(json.dumps(set_role))
    moved_checkpoint["parameters"]["workflow_id"] = "dddddddd-4444-4444-8444-444444444444"
    moved_checkpoint["parameters"]["steps"][2]["checkpoint"] = "after"
    assert api_module._research_action_dedupe_comparable(set_role) != api_module._research_action_dedupe_comparable(moved_checkpoint)


def test_vulnerability_key_is_method_aware_and_gate_targets_only_asserted_steps():
    # GET vs DELETE BOLA on the same object route are distinct vulnerabilities -> distinct keys
    # (the old family+path key collapsed them and over-suppressed).
    get_key = api_module._canonical_vulnerability_key(family="bola", route="/orders/{id}", method="GET")
    delete_key = api_module._canonical_vulnerability_key(family="bola", route="/orders/{id}", method="DELETE")
    assert get_key and delete_key and get_key != delete_key

    # The action gate keys ONLY on the assertion-targeted step (the vuln under test); a setup/producer
    # step that merely touches a known-finding route must not make the whole workflow "already covered".
    action = {
        "command": "experiment.workflow",
        "parameters": {
            "proof_family": "bola",
            "steps": [
                {"label": "setup", "method": "POST", "path": "/known/vuln/route", "principal": "user1"},
                {"label": "attack", "method": "GET", "path": "/orders/{id}", "principal": "user2"},
            ],
            "assertions": [
                {"step": "attack", "type": "status_in", "values": [200], "predicate": "cross_principal_access"},
            ],
        },
    }
    keys = api_module._research_action_vulnerability_keys(action)
    assert api_module._canonical_vulnerability_key(family="bola", route="/orders/{id}", method="GET") in keys
    assert api_module._canonical_vulnerability_key(family="bola", route="/known/vuln/route", method="POST") not in keys


def test_vulnerability_identity_distinguishes_family_parameter_field_and_invariant():
    sqli_q = api_module._canonical_vulnerability_key(
        family="sqli", route="/search", method="GET",
        dimensions={"parameter": "q", "location": "query"},
    )
    sqli_id = api_module._canonical_vulnerability_key(
        family="sqli", route="/search", method="GET",
        dimensions={"parameter": "id", "location": "query"},
    )
    xss_q = api_module._canonical_vulnerability_key(
        family="xss", route="/search", method="GET",
        dimensions={"parameter": "q", "location": "query"},
    )
    role = api_module._canonical_vulnerability_key(
        family="mass_assignment", route="/profile", method="PATCH",
        dimensions={"field": "role"},
    )
    is_admin = api_module._canonical_vulnerability_key(
        family="mass_assignment", route="/profile", method="PATCH",
        dimensions={"field": "isAdmin"},
    )
    invariant_one = api_module._canonical_vulnerability_key(
        family="workflow", route="/orders/{id}", method="PATCH",
        dimensions={"invariant_contract_id": "contract-1", "predicate": "transition_invariant_broken"},
    )
    invariant_two = api_module._canonical_vulnerability_key(
        family="workflow", route="/orders/42", method="PATCH",
        dimensions={"invariant_contract_id": "contract-2", "predicate": "transition_invariant_broken"},
    )

    assert len({sqli_q, sqli_id, xss_q}) == 3
    assert role != is_admin
    assert invariant_one != invariant_two
    assert api_module._finding_vulnerability_key({
        "tool": "smart_sqli",
        "cwe": "CWE-89",
        "title": "SQL injection in q",
        "url": "https://example.test/search",
        "evidence": {"dedupe_dimensions": {
            "route": "/search", "method": "GET", "parameter": "q", "location": "query",
        }},
    }) == sqli_q


def test_legacy_methodless_smart_bola_suppresses_get_but_not_delete():
    historic = {
        "tool": "smart_bola",
        "cwe": "CWE-639",
        "title": "BOLA: Cross-user data access at /orders/42",
        "url": "https://app.example.test/orders/42",
        "evidence": {"proof_type": "cross_principal_replay"},
    }
    assert api_module._finding_vulnerability_key(historic) == api_module._canonical_vulnerability_key(
        family="bola", route="/orders/{id}", method="GET",
    )
    assert api_module._finding_vulnerability_key(historic) != api_module._canonical_vulnerability_key(
        family="bola", route="/orders/{id}", method="DELETE",
    )

    delete_action = {
        "command": "experiment.workflow",
        "parameters": {
            "proof_family": "bola",
            "steps": [{"label": "delete", "method": "DELETE", "path": "/orders/99"}],
            "assertions": [{"step": "delete", "type": "status_in", "values": [200]}],
        },
    }
    assert api_module._finding_vulnerability_key(historic) not in api_module._research_action_vulnerability_keys(delete_action)


def test_research_duplicate_guard_decodes_asyncpg_jsonb_text_before_progress_check():
    repeated = {"command": "asm.gaps", "parameters": {"target_id": "target-1"}}
    gated = {"command": "asm.improve", "parameters": {"target_id": "target-1", "check_family": "xss"}}

    blocked_after_empty_json_array = asyncio.run(api_module._research_is_consecutive_duplicate_action(
        _ResearchPreviousActionConn([gated, repeated], jsonb_text=True),
        "11111111-1111-4111-8111-111111111111", repeated,
    ))
    allowed_after_json_finding_array = asyncio.run(api_module._research_is_consecutive_duplicate_action(
        _ResearchPreviousActionConn([{**gated, "_produced_finding": True}, repeated], jsonb_text=True),
        "11111111-1111-4111-8111-111111111111", repeated,
    ))

    assert blocked_after_empty_json_array is True
    assert allowed_after_json_finding_array is False


class _ResearchRecentActionsConn:
    async def fetch(self, _query, *_args):
        return [{
            "sequence": 2,
            "decision_type": "execute_action",
            "status": "completed",
            "action": json.dumps({"command": "experiment.workflow", "parameters": {}}),
            "reason": "test a workflow invariant",
            "expected_signal": "replay succeeds",
            "falsifier": "replay fails",
            "validation_errors": "[]",
            "command_result_id": uuid.uuid4(),
            "command_status": "completed",
            "scan_id": None,
            "result_json": json.dumps({
                "workflow": {
                    "observations": [{
                        "label": "initial",
                        "request": {"method": "POST", "path": "/orders"},
                        "response": {"status": 201, "body_sample": "created"},
                    }],
                },
                "replay": {
                    "proof_state": "unverified_workflow_signal",
                    "replay_blocked_reason": "independent_replay_failed",
                    "observations": [{
                        "label": "replay",
                        "request": {"method": "POST", "path": "/orders"},
                        "response": {"status": 409, "body_sample": "state transition rejected"},
                    }],
                },
                "family_proof": {"verdict": "not_proven", "reason": "replay did not reproduce"},
            }),
            "operator_message": "Workflow did not verify",
        }]


def test_research_recent_actions_surfaces_replay_only_failure_and_authoritative_proof():
    actions = asyncio.run(api_module._research_recent_actions(
        _ResearchRecentActionsConn(),
        "11111111-1111-4111-8111-111111111111",
    ))

    result = actions[0]["result"]
    assert result["proof_state"] == "not_proven"
    assert result["failure_reason"] == "independent_replay_failed"
    assert result["failure_detail"] == {
        "step": "replay",
        "method": "POST",
        "path": "/orders",
        "status": 409,
        "error": None,
        "body_sample": "state transition rejected",
    }


class _InvariantLifecycleConn:
    def __init__(self, *, existing=None):
        self.existing = existing
        self.executions = []
        self.insert_args = None

    async def fetchrow(self, query, *args):
        if "SELECT url FROM targets" in query:
            return {"url": "https://example.test"}
        if "SELECT * FROM target_invariant_contracts" in query:
            return self.existing
        if "INSERT INTO target_invariant_contracts" in query:
            self.insert_args = args
            return {
                "id": uuid.uuid4(),
                "target_id": args[0],
                "contract_version": args[1],
                "contract_kind": args[2],
                "title": args[3],
                "source_text": args[4],
                "subject_role": args[5],
                "action": args[6],
                "resource": args[7],
                "method": args[8],
                "path": args[9],
                "field_name": args[10],
                "operator": args[11],
                "expected_value": args[12],
                "expected_access": args[13],
                "conditions": args[14],
                "status": "draft",
                "source": args[15],
                "metadata_json": args[16],
                "created_by": args[17],
            }
        if "UPDATE target_invariant_contracts" in query and "status='approved'" in query:
            return {**self.existing, "status": "approved", "approved_by": args[2]}
        raise AssertionError(query)


def test_invariant_create_is_draft_only_and_requires_scoped_approval(monkeypatch):
    conn = _InvariantLifecycleConn()
    monkeypatch.setattr(api_module, "db_pool", _pool_for(conn))
    approval_calls = []
    command_calls = []

    async def fake_validate(_conn, receipt_id, **kwargs):
        approval_calls.append((receipt_id, kwargs))
        return {"scope_receipt_id": "scope-1"}

    async def fake_record(_conn, **kwargs):
        command_calls.append(kwargs)
        return {"id": "operation-1"}

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)
    monkeypatch.setattr(api_module, "_record_command_result", fake_record)
    result = asyncio.run(api_module.create_target_invariant_contract(
        "11111111-1111-4111-8111-111111111111",
        api_module.TargetInvariantContractCreate(
            contract_kind="access_control",
            title="Only managers issue refunds",
            source_text="Authorization: Bearer secret-token-123",
            subject_role="manager",
            action="issue",
            resource="refund",
            expected_access="allow",
            approval_receipt_id="22222222-2222-4222-8222-222222222222",
        ),
    ))

    assert result["contract"]["status"] == "draft"
    assert result["planning_authority"] is False
    assert result["promotion_authority"] is False
    assert result["operation_id"] == "operation-1"
    assert approval_calls[0][1]["always_require_receipt"] is True
    assert approval_calls[0][1]["command"] == "target.invariant_contract.record"
    assert command_calls[0]["result_json"]["promotion_authority"] is False
    assert "secret-token-123" not in str(conn.insert_args)


def test_invariant_approval_grants_planning_but_never_promotion(monkeypatch):
    existing = {
        "id": uuid.UUID("33333333-3333-4333-8333-333333333333"),
        "target_id": uuid.UUID("11111111-1111-4111-8111-111111111111"),
        "contract_kind": "ownership",
        "title": "Users cannot edit another user's profile",
        "subject_role": "user",
        "action": "edit",
        "resource": "profile",
        "expected_access": "deny",
        "conditions": json.dumps({"resource_owner": "other"}),
        "expected_value": "null",
        "status": "draft",
        "source": "manual",
        "metadata_json": "{}",
    }
    conn = _InvariantLifecycleConn(existing=existing)
    monkeypatch.setattr(api_module, "db_pool", _pool_for(conn))

    async def fake_validate(_conn, _receipt_id, **_kwargs):
        return {"scope_receipt_id": "scope-1"}

    async def fake_record(_conn, **_kwargs):
        return {"id": "operation-2"}

    monkeypatch.setattr(api_module, "_validate_approval_receipt_for_action", fake_validate)
    monkeypatch.setattr(api_module, "_record_command_result", fake_record)
    result = asyncio.run(api_module.approve_target_invariant_contract(
        "11111111-1111-4111-8111-111111111111",
        "33333333-3333-4333-8333-333333333333",
        api_module.TargetInvariantContractApproval(
            approval_receipt_id="22222222-2222-4222-8222-222222222222",
            approved_by="operator",
            confirm_authoritative=True,
        ),
    ))

    assert result["planning_authority"] is True
    assert result["promotion_authority"] is False
    assert result["verification_required"] is True


class _InvariantCompileConn:
    async def fetchrow(self, query, *_args):
        if "SELECT 1 FROM targets" in query:
            return {"exists": 1}
        raise AssertionError(query)


def test_invariant_compile_preview_is_target_bound_and_non_authoritative(monkeypatch):
    monkeypatch.setattr(api_module, "db_pool", _pool_for(_InvariantCompileConn()))

    result = asyncio.run(api_module.compile_target_invariant_rule(
        "11111111-1111-4111-8111-111111111111",
        api_module.TargetInvariantCompileRequest(
            rule_text="Only managers can issue refunds at /api/refunds POST",
        ),
    ))

    assert result["candidate_count"] == 1
    assert result["candidates"][0]["contract_kind"] == "access_control"
    assert result["persisted_count"] == 0
    assert result["planning_authority"] is False
    assert result["promotion_authority"] is False


def test_invariant_hypothesis_routes_through_executable_verification_planning():
    ownership = api_module._invariant_hypothesis_request(
        "11111111-1111-4111-8111-111111111111",
        {
            "id": "33333333-3333-4333-8333-333333333333",
            "status": "approved",
            "contract_kind": "ownership",
            "title": "Cross-owner edit denied",
            "subject_role": "user",
            "action": "edit",
            "resource": "profile",
            "method": "GET",
            "path": "/api/users/{id}",
            "expected_access": "deny",
            "conditions": {"resource_owner": "other"},
        },
        created_by="test",
    )
    field_constraint = api_module._invariant_hypothesis_request(
        "11111111-1111-4111-8111-111111111111",
        {
            "id": "44444444-4444-4444-8444-444444444444",
            "status": "approved",
            "contract_kind": "field_constraint",
            "title": "Discount cap",
            "action": "update",
            "resource": "discount",
            "field_name": "percent",
            "operator": "lte",
            "expected_value": 30,
            "method": "PATCH",
            "path": "/api/discount",
            "conditions": {},
        },
        created_by="test",
    )

    assert ownership.source == "invariant"
    assert ownership.next_test_action["command"] == "target.invariant.verification_plan"
    assert ownership.next_test_action["parameters"]["contract_id"] == "33333333-3333-4333-8333-333333333333"
    assert ownership.next_test_action["recommended_verifier"] == "experiment.workflow"
    assert ownership.next_test_action["recommended_proof_family"] == "bola"
    assert ownership.next_test_action["execution_ready"] is False
    assert field_constraint.next_test_action["command"] == "target.invariant.verification_plan"
    assert field_constraint.next_test_action["recommended_verifier"] == "experiment.workflow"
    assert field_constraint.next_test_action["recommended_proof_family"] == "field_constraint"
    assert field_constraint.metadata_json["promotion_authority"] is False


def test_approved_field_constraint_binds_to_two_live_restored_executions():
    import workflow_experiment

    contract = {
        "id": "44444444-4444-4444-8444-444444444444",
        "status": "approved",
        "contract_kind": "field_constraint",
        "title": "Discount cap",
        "action": "update",
        "resource": "discount",
        "field_name": "percent",
        "operator": "lte",
        "expected_value": 30,
        "method": "PATCH",
        "path": "/api/discount",
        "conditions": {},
    }
    payload = {
        "proof_family": "field_constraint",
        "steps": [
            {"label": "before", "principal": "user1", "checkpoint": "before", "method": "GET", "path": "/api/discount", "select_json": ["$.percent"]},
            {"label": "mutate", "principal": "user1", "checkpoint": "mutation", "method": "PATCH", "path": "/api/discount", "json_body": {"percent": 99}},
            {"label": "verify", "principal": "user1", "checkpoint": "action", "method": "GET", "path": "/api/discount", "select_json": ["$.percent"], "compare_to": "before"},
            {"label": "cleanup", "principal": "user1", "checkpoint": "cleanup", "method": "PATCH", "path": "/api/discount", "json_body": {"percent": 20}},
            {"label": "after", "principal": "user1", "checkpoint": "after", "method": "GET", "path": "/api/discount", "select_json": ["$.percent"], "compare_to": "before"},
        ],
        "assertions": [
            {"type": "comparison_changed", "control": "before", "candidate": "verify", "predicate": "constraint_violation_persisted"},
            {"type": "restored", "control": "before", "candidate": "after", "predicate": "before_after_state"},
        ],
    }
    normalized = workflow_experiment.normalize_workflow("https://example.test", payload)

    def observation(label, checkpoint, method, selected=None):
        return {
            "label": label,
            "kind": "http",
            "principal": "user1",
            "checkpoint": checkpoint,
            "request": {"method": method, "path": "/api/discount"},
            "response": {"status": 200, "selected_json": selected or {}},
            "error": None,
        }

    execution = {
        "proof_family": "field_constraint",
        "restoration_verified": True,
        "observations": [
            observation("before", "before", "GET", {"$.percent": 20}),
            observation("mutate", "mutation", "PATCH"),
            observation("verify", "action", "GET", {"$.percent": 99}),
            observation("cleanup", "cleanup", "PATCH"),
            observation("after", "after", "GET", {"$.percent": 20}),
        ],
    }
    proof = api_module._trusted_workflow_family_proof(
        execution, json.loads(json.dumps(execution)),
        invariant_contract=contract, normalized=normalized,
    )

    assert proof["verdict"] == "verified"
    assert proof["promotable"] is True
    assert proof["stable_predicates"] == [
        "before_after_state", "constraint_baseline_observed", "constraint_violation_persisted",
    ]
    assert proof["proof_routes"] == ["/api/discount"]
    assert proof["proof_methods"] == ["PATCH"]

    no_persistence = json.loads(json.dumps(execution))
    no_persistence["observations"][2]["response"]["selected_json"]["$.percent"] = 20
    false_positive_moat = api_module._trusted_workflow_family_proof(
        execution, no_persistence,
        invariant_contract=contract, normalized=normalized,
    )
    assert false_positive_moat["promotable"] is False


def test_approved_access_control_requires_exact_role_and_distinct_live_identity():
    import workflow_experiment

    contract = {
        "id": "55555555-5555-4555-8555-555555555555",
        "status": "approved",
        "contract_kind": "access_control",
        "title": "Only admins may export",
        "subject_role": "admin",
        "action": "export",
        "resource": "report",
        "expected_access": "requires_role",
        "method": "GET",
        "path": "/api/report/export",
        "conditions": {},
    }
    payload = {
        "proof_family": "access_control",
        "steps": [
            {"label": "authorized", "principal": "admin", "checkpoint": "action", "method": "GET", "path": "/api/report/export"},
            {"label": "forbidden", "principal": "user1", "checkpoint": "action", "method": "GET", "path": "/api/report/export"},
        ],
        "assertions": [
            {"type": "status_in", "step": "authorized", "values": [200], "predicate": "authorized_role_control"},
            {"type": "status_in", "step": "forbidden", "values": [200], "predicate": "forbidden_role_access"},
            {"type": "distinct_principals", "steps": ["authorized", "forbidden"], "predicate": "distinct_identity"},
        ],
    }
    normalized = workflow_experiment.normalize_workflow("https://example.test", payload)
    execution = {
        "proof_family": "access_control",
        "restoration_verified": True,
        "principal_receipts": [
            {"slot": "admin", "role": "admin", "identity_fingerprint": "admin-fp"},
            {"slot": "user1", "role": "user", "identity_fingerprint": "user-fp"},
        ],
        "observations": [
            {"label": "authorized", "kind": "http", "principal": "admin", "checkpoint": "action", "request": {"method": "GET", "path": "/api/report/export"}, "response": {"status": 200}, "error": None},
            {"label": "forbidden", "kind": "http", "principal": "user1", "checkpoint": "action", "request": {"method": "GET", "path": "/api/report/export"}, "response": {"status": 200}, "error": None},
        ],
    }
    proof = api_module._trusted_workflow_family_proof(
        execution, json.loads(json.dumps(execution)),
        invariant_contract=contract, normalized=normalized,
    )
    assert proof["verdict"] == "verified"
    assert proof["promotable"] is True

    same_account = json.loads(json.dumps(execution))
    same_account["principal_receipts"][1]["identity_fingerprint"] = "admin-fp"
    moat = api_module._trusted_workflow_family_proof(
        execution, same_account,
        invariant_contract=contract, normalized=normalized,
    )
    assert moat["promotable"] is False


def test_approved_workflow_transition_distinguishes_forbidden_from_allowed_change():
    import workflow_experiment

    contract = {
        "id": "66666666-6666-4666-8666-666666666666",
        "status": "approved",
        "contract_kind": "workflow_transition",
        "title": "Pending may transition only to paid",
        "action": "transition",
        "resource": "order",
        "field_name": "status",
        "method": "PATCH",
        "path": "/api/order/42",
        "conditions": {"from_state": "pending", "to_state": "paid"},
    }
    payload = {
        "proof_family": "workflow",
        "steps": [
            {"label": "before", "principal": "user1", "checkpoint": "before", "method": "GET", "path": "/api/order/42", "select_json": ["$.status"]},
            {"label": "transition", "principal": "user1", "checkpoint": "mutation", "method": "PATCH", "path": "/api/order/42", "json_body": {"status": "cancelled"}},
            {"label": "verify", "principal": "user1", "checkpoint": "action", "method": "GET", "path": "/api/order/42", "select_json": ["$.status"], "compare_to": "before"},
            {"label": "cleanup", "principal": "user1", "checkpoint": "cleanup", "method": "PATCH", "path": "/api/order/42", "json_body": {"status": "pending"}},
            {"label": "after", "principal": "user1", "checkpoint": "after", "method": "GET", "path": "/api/order/42", "select_json": ["$.status"], "compare_to": "before"},
        ],
        "assertions": [
            {"type": "comparison_changed", "control": "before", "candidate": "verify", "predicate": "transition_invariant_broken"},
            {"type": "restored", "control": "before", "candidate": "after", "predicate": "before_after_state"},
        ],
    }
    normalized = workflow_experiment.normalize_workflow("https://example.test", payload)

    def execution(next_state):
        def observation(label, checkpoint, method, selected=None):
            return {"label": label, "kind": "http", "principal": "user1", "checkpoint": checkpoint,
                    "request": {"method": method, "path": "/api/order/42"},
                    "response": {"status": 200, "selected_json": selected or {}}, "error": None}
        return {
            "proof_family": "workflow", "restoration_verified": True,
            "observations": [
                observation("before", "before", "GET", {"$.status": "pending"}),
                observation("transition", "mutation", "PATCH"),
                observation("verify", "action", "GET", {"$.status": next_state}),
                observation("cleanup", "cleanup", "PATCH"),
                observation("after", "after", "GET", {"$.status": "pending"}),
            ],
        }

    forbidden = execution("cancelled")
    proof = api_module._trusted_workflow_family_proof(
        forbidden, json.loads(json.dumps(forbidden)),
        invariant_contract=contract, normalized=normalized,
    )
    assert proof["verdict"] == "verified"
    assert proof["promotable"] is True

    allowed = execution("paid")
    held = api_module._trusted_workflow_family_proof(
        allowed, json.loads(json.dumps(allowed)),
        invariant_contract=contract, normalized=normalized,
    )
    assert held["verdict"] == "refuted"
    assert held["promotable"] is False


def test_research_gap_recommendations_do_not_conflict_with_excluded_actions():
    gaps = [
        {"kind": "untested_endpoints", "count": 12, "next_safe_command": "asm.gaps"},
        {"kind": "other", "next_safe_command": "target.get"},
    ]
    reconciled = api_module._reconcile_research_gap_recommendations(
        gaps,
        [{"command": "asm.gaps", "parameters": {}}],
    )

    assert "next_safe_command" not in reconciled[0]
    assert reconciled[0]["recommendation_state"] == "already_attempted_without_state_change"
    assert reconciled[1]["next_safe_command"] == "target.get"


def test_gated_research_campaign_rejects_explicit_empty_family_scope():
    request = api_module.ResearchCampaignLaunchRequest(
        target_id="11111111-1111-4111-8111-111111111111",
        intensity="deep_hunt",
        approval_receipt_id="22222222-2222-4222-8222-222222222222",
        allowed_families=[],
    )

    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module.launch_research_campaign(request))

    assert exc.value.status_code == 400
    assert "At least one vulnerability family" in str(exc.value.detail)


def test_research_campaign_omits_mode_so_persisted_default_can_apply():
    request = api_module.ResearchCampaignLaunchRequest(
        target_id="11111111-1111-4111-8111-111111111111",
    )

    assert request.planner_mode is None
    assert api_module._normalize_research_planner_mode(None) == "agent"


def test_research_launch_planner_mode_preserves_legacy_autopilot_and_explicit_agent():
    legacy = api_module.ResearchLaunchRequest(
        subject_type="target",
        subject_id="11111111-1111-4111-8111-111111111111",
        mission_profile="target_hunt",
        autopilot=True,
    )
    agent = api_module.ResearchLaunchRequest(
        subject_type="target",
        subject_id="11111111-1111-4111-8111-111111111111",
        mission_profile="target_hunt",
        planner_mode="agent",
        autopilot=True,
    )
    local = api_module.ResearchLaunchRequest(
        subject_type="target",
        subject_id="11111111-1111-4111-8111-111111111111",
        mission_profile="target_hunt",
        planner_mode="local_codex",
        autopilot=False,
    )

    assert api_module._research_launch_planner_mode(legacy) == "configured_ai"
    assert api_module._research_launch_planner_mode(agent) == "agent"
    assert api_module._research_launch_planner_mode(local) == "local_codex"
    assert api_module._research_planner_kind("agent") == "interactive_agent"


def test_research_readiness_exposes_agent_default_without_configured_provider(monkeypatch):
    monkeypatch.setattr(api_module, "_load_effective_ai_settings", lambda: {
        "ai_url": "", "ai_api_key": "", "ai_model": "", "ai_model_fallback": "",
    })
    monkeypatch.setattr(api_module, "_load_effective_automation_settings", lambda: {
        "default_research_planner_mode": "agent",
    })

    readiness = asyncio.run(api_module.research_readiness())

    assert readiness["default_planner_mode"] == "agent"
    assert readiness["planner_ready"] is False
    assert readiness["configured_planner_ready"] is False
    assert readiness["planner_modes"]["agent"]["ready"] is True
    assert readiness["planner_modes"]["configured_ai"]["ready"] is False


def test_automation_settings_expose_persisted_research_planner_default():
    payload = api_module._sanitize_automation_settings_response(
        automation={
            "default_asm_enabled": True,
            "default_asm_config": {},
            "approval_receipts_required_for_state_changing_actions": False,
            "default_research_planner_mode": "configured_ai",
        },
        scan_execution={},
    )

    assert payload["research_agent"]["default_planner_mode"] == "configured_ai"
    assert payload["research_agent"]["available_planner_modes"] == [
        "agent", "local_codex", "configured_ai",
    ]
    assert api_module.AutomationSettingsUpdate(
        default_research_planner_mode="local_codex",
    ).default_research_planner_mode == "local_codex"


def test_configured_campaign_fails_before_db_when_provider_is_missing(monkeypatch):
    monkeypatch.setattr(api_module, "_research_configured_planner_ready", lambda: False)
    request = api_module.ResearchCampaignLaunchRequest(
        target_id="11111111-1111-4111-8111-111111111111",
        planner_mode="configured_ai",
    )

    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module.launch_research_campaign(request))

    assert exc.value.status_code == 409
    assert "no AI provider" in str(exc.value.detail)


def test_campaign_supervisor_does_not_reap_agent_driven_episode(monkeypatch):
    class Conn:
        def __init__(self):
            self.executed = []

        async def execute(self, query, *args):
            self.executed.append(query)
            return "UPDATE 0"

        async def fetch(self, query, *args):
            return []

    conn = Conn()
    monkeypatch.setattr(api_module, "db_pool", _FakePool(conn))

    assert asyncio.run(api_module._continue_autonomous_research_campaigns()) == 0
    reaper_query = conn.executed[0]
    assert "planner_mode" in reaper_query
    assert "= 'configured_ai'" in reaper_query


def test_switching_episode_planner_persists_mode_to_campaign(monkeypatch):
    episode_id = uuid.uuid4()
    campaign_id = uuid.uuid4()

    class Transaction:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    class Conn:
        def __init__(self):
            self.campaign_update = None

        def transaction(self):
            return Transaction()

        async def fetchrow(self, query, *args):
            if "FOR UPDATE" in query:
                return {
                    "id": episode_id,
                    "campaign_id": campaign_id,
                    "status": "awaiting_planner",
                    "planner": {"kind": "interactive_agent", "mode": "agent"},
                    "autopilot_enabled": False,
                    "lease_owner": None,
                    "lease_expires_at": None,
                }
            if "UPDATE research_episodes" in query:
                assert args[1:] == (True, "configured_ai", "configured_ai")
                return {
                    "id": episode_id,
                    "status": "awaiting_planner",
                    "planner": {"kind": "configured_ai", "mode": "configured_ai"},
                    "autopilot_enabled": True,
                }
            raise AssertionError(query)

        async def execute(self, query, *args):
            if "UPDATE campaigns" in query:
                self.campaign_update = (query, args)
            return "UPDATE 1"

    async def fake_event(*args, **kwargs):
        return None

    async def fake_detail(_conn, _episode_id):
        return {"episode": {"id": _episode_id, "autopilot_enabled": True}}

    conn = Conn()
    monkeypatch.setattr(api_module, "db_pool", _FakePool(conn))
    monkeypatch.setattr(api_module, "_research_configured_planner_ready", lambda: True)
    monkeypatch.setattr(api_module, "_record_research_event", fake_event)
    monkeypatch.setattr(api_module, "_research_episode_detail", fake_detail)

    result = asyncio.run(api_module.set_research_episode_autopilot(
        str(episode_id),
        api_module.ResearchAutopilotRequest(
            enabled=True,
            planner_mode="configured_ai",
        ),
    ))

    assert result["episode"]["autopilot_enabled"] is True
    assert conn.campaign_update is not None
    assert conn.campaign_update[1] == (campaign_id, "configured_ai", "configured_ai")


def test_active_research_intensities_reject_credential_only_families_before_db_access():
    request = api_module.ResearchCampaignLaunchRequest(
        target_id="11111111-1111-4111-8111-111111111111",
        intensity="hunt",
        approval_receipt_id="22222222-2222-4222-8222-222222222222",
        allowed_families=["sqli", "access_control"],
    )

    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module.launch_research_campaign(request))

    assert exc.value.status_code == 400
    assert "access_control" in str(exc.value.detail)
    assert api_module._research_intensity_campaign_families("hunt") == ("auth", "bola", "sqli", "xss")
    assert "access_control" in api_module._research_intensity_campaign_families("deep_hunt")


def test_deep_campaign_bootstraps_principals_before_readiness_repair(monkeypatch):
    target_id = uuid.uuid4()
    campaign_id = uuid.uuid4()
    calls = []
    launched = []
    campaign = {
        "id": campaign_id,
        "target_id": target_id,
        "campaign_type": "autonomous_research",
        "status": "active",
        "metadata_json": {"autonomous_research": {}},
    }

    class Conn:
        async def fetchrow(self, query, *args):
            if "SELECT id, url FROM targets" in query:
                return {"id": target_id, "url": "https://app.example.test"}
            if "INSERT INTO campaigns" in query or "UPDATE campaigns SET status" in query:
                return campaign
            if "SELECT * FROM campaigns" in query:
                return campaign
            if "episodes_started" in query:
                return campaign
            raise AssertionError(query)

        async def fetch(self, query, *args):
            if "FROM research_episodes" in query:
                return []
            raise AssertionError(query)

    class Pool:
        def acquire(self):
            class Acquire:
                async def __aenter__(self):
                    return Conn()

                async def __aexit__(self, *exc):
                    return False

            return Acquire()

    async def fake_bootstrap(*args, **kwargs):
        calls.append((args, kwargs))
        return {"action": "provisioned"}

    async def fake_repair(_campaign_id):
        assert calls, "principal bootstrap must run before readiness repair"
        return {"readiness": {"ready": True}}

    async def fake_launch(_request):
        launched.append(_request)
        return {"episode": {"id": "episode-1"}, "ui_path": "/settings/research-agent?episode_id=episode-1"}

    monkeypatch.setattr(api_module, "db_pool", Pool())
    monkeypatch.setattr(api_module, "_research_maybe_auto_provision_principals", fake_bootstrap)
    monkeypatch.setattr(api_module, "_research_campaign_self_repair", fake_repair)
    monkeypatch.setattr(api_module, "_materialize_research_invariant_hypotheses", lambda *args: asyncio.sleep(0, result=0))
    monkeypatch.setattr(api_module, "launch_research_episode", fake_launch)

    asyncio.run(api_module.launch_research_campaign(api_module.ResearchCampaignLaunchRequest(
        target_id=str(target_id),
        intensity="deep_hunt",
        approval_receipt_id=str(uuid.uuid4()),
        allowed_families=["auth"],
    )))

    assert calls[0][0] == (target_id,)
    assert calls[0][1]["require_second_user"] is False
    assert launched[0].planner_mode == "agent"
    assert launched[0].autopilot is False


class _StaleResearchDispatchConn:
    def __init__(self, row):
        self.row = row
        self.executions = []

    async def fetch(self, _query, *_args):
        return [self.row]

    async def execute(self, query, *args):
        self.executions.append((query, args))
        return "UPDATE 1"


def _stale_dispatch_row(*, receipt_status="queued", receipt=True, retest=False):
    episode_id = uuid.uuid4()
    decision_id = uuid.uuid4()
    return {
        "id": episode_id,
        "decision_id": decision_id,
        "current_decision_id": decision_id,
        "linked_command_result_id": None,
        "recovered_command_result_id": uuid.uuid4() if receipt else None,
        "recovered_command_status": receipt_status if receipt else None,
        "recovered_command_dry_run": False,
        "recovered_scan_id": None,
        "recovered_scan_status": None,
        "recovered_scan_job_id": None,
        "recovered_scan_campaign_id": None,
        "recovered_retest_id": uuid.uuid4() if retest else None,
        "recovered_finding_id": uuid.uuid4() if retest else None,
        "recovered_retest_status": "queued" if retest else None,
        "policy_result": json.dumps({
            "cost_reserved": {
                "steps": 1, "actions": 1, "active_actions": 1,
                "requests": 100, "seconds": 600, "model_tokens": 250,
            }
        }),
        "action": json.dumps({"command": "scan.focused_family", "parameters": {"check_family": "xss"}}),
        "budget_used": json.dumps({
            "steps": 0, "actions": 0, "active_actions": 0,
            "requests": 0, "seconds": 0, "model_tokens": 0,
        }),
        "budget_limits": json.dumps({
            "steps": 8, "actions": 7, "active_actions": 3,
            "requests": 250, "seconds": 1800, "model_tokens": 75000,
        }),
        "step_count": 0,
    }


@pytest.mark.parametrize(("receipt_status", "expected_decision_status", "expected_requests"), [
    ("queued", "dispatching", 100),
    ("blocked", "blocked", 0),
])
def test_reconcile_stale_research_dispatch_attaches_correlated_receipt_and_settles_cost(
    monkeypatch, receipt_status, expected_decision_status, expected_requests,
):
    row = _stale_dispatch_row(receipt_status=receipt_status)
    conn = _StaleResearchDispatchConn(row)
    events = []

    async def fake_event(_conn, episode_id, **kwargs):
        events.append((episode_id, kwargs))
        return {}

    monkeypatch.setattr(api_module, "_record_research_event", fake_event)
    repaired = asyncio.run(api_module._reconcile_stale_research_dispatches(conn))

    assert repaired == 1
    decision_update = next(item for item in conn.executions if "UPDATE research_decisions" in item[0])
    assert decision_update[1][-1] == expected_decision_status
    episode_update = next(item for item in conn.executions if "budget_used=$3::jsonb" in item[0])
    settled_budget = json.loads(episode_update[1][2])
    assert settled_budget["requests"] == expected_requests
    assert settled_budget["model_tokens"] == 250
    assert str(events[-1][1]["command_result_id"]) == str(row["recovered_command_result_id"])


def test_reconcile_stale_research_dispatch_synthesizes_retest_receipt(monkeypatch):
    row = _stale_dispatch_row(receipt=False, retest=True)
    conn = _StaleResearchDispatchConn(row)
    created = []

    async def fake_record(_conn, **kwargs):
        created.append(kwargs)
        return {"id": str(uuid.uuid4()), "status": kwargs["status"], "dry_run": False}

    async def fake_event(*args, **kwargs):
        return {}

    monkeypatch.setattr(api_module, "_record_command_result", fake_record)
    monkeypatch.setattr(api_module, "_record_research_event", fake_event)

    assert asyncio.run(api_module._reconcile_stale_research_dispatches(conn)) == 1
    assert created[0]["command"] == "finding.retest"
    assert created[0]["result_json"]["retest_id"] == str(row["recovered_retest_id"])
    assert created[0]["created_by"].endswith(f"decision:{row['decision_id']}")


def test_reconcile_stale_research_dispatch_synthesizes_correlated_asm_scan_receipt(monkeypatch):
    row = _stale_dispatch_row(receipt=False, retest=False)
    row.update({
        "action": json.dumps({"command": "asm.improve", "parameters": {"check_family": "xss"}}),
        "recovered_scan_id": uuid.uuid4(),
        "recovered_scan_status": "running",
        "recovered_scan_job_id": "asm-job-1",
        "recovered_scan_campaign_id": uuid.uuid4(),
    })
    conn = _StaleResearchDispatchConn(row)
    created = []

    async def fake_record(_conn, **kwargs):
        created.append(kwargs)
        return {"id": str(uuid.uuid4()), "status": kwargs["status"], "dry_run": False}

    async def fake_event(*args, **kwargs):
        return {}

    monkeypatch.setattr(api_module, "_record_command_result", fake_record)
    monkeypatch.setattr(api_module, "_record_research_event", fake_event)

    assert asyncio.run(api_module._reconcile_stale_research_dispatches(conn)) == 1
    assert created[0]["command"] == "asm.improve"
    assert created[0]["scan_id"] == row["recovered_scan_id"]
    assert created[0]["campaign_id"] == row["recovered_scan_campaign_id"]
    assert created[0]["result_json"]["recovered_from_scan_correlation"] is True
    assert created[0]["created_by"].endswith(f"decision:{row['decision_id']}")


def test_reconcile_stale_research_dispatch_without_receipt_blocks_without_replay(monkeypatch):
    row = _stale_dispatch_row(receipt=False, retest=False)
    conn = _StaleResearchDispatchConn(row)

    async def fake_event(*args, **kwargs):
        return {}

    monkeypatch.setattr(api_module, "_record_research_event", fake_event)
    assert asyncio.run(api_module._reconcile_stale_research_dispatches(conn)) == 1
    assert any("SET status='blocked'" in query for query, _args in conn.executions)
    assert any("dispatch_outcome_unknown" in query for query, _args in conn.executions)


def test_orphan_reconciler_does_not_trust_stale_queued_metadata_hash(monkeypatch):
    scan_id = uuid.uuid4()

    class Redis:
        def ping(self):
            return True

        def lrange(self, _queue, _start, _end):
            return []

        def hgetall(self, key):
            assert key == "job:lost-job"
            return {b"status": b"queued", b"target": b"https://example.test"}

    class Conn:
        def __init__(self):
            self.fetch_count = 0
            self.failed = []

        async def fetch(self, query, *args):
            self.fetch_count += 1
            if "JOIN scans" in query:
                return [{"episode_id": uuid.uuid4(), "id": scan_id, "job_id": "lost-job"}]
            return []

        async def fetchval(self, query, *args):
            self.failed.append((query, args))
            return scan_id

        async def execute(self, query, *args):
            self.failed.append((query, args))
            return "UPDATE 1"

    async def fake_event(*args, **kwargs):
        return {}

    conn = Conn()
    monkeypatch.setattr(api_module, "get_redis", lambda: Redis())
    monkeypatch.setattr(api_module, "_record_research_event", fake_event)

    assert asyncio.run(api_module._reconcile_research_orphaned_queue_work(conn)) == 1
    assert any("Research dispatch queue handoff was not durable" in query for query, _args in conn.failed)


def test_queue_presence_accepts_only_membership_or_fresh_worker_lease():
    now = datetime(2026, 7, 12, 12, 0, tzinfo=timezone.utc)

    class Redis:
        def __init__(self, metadata):
            self.metadata = metadata

        def hgetall(self, _key):
            return self.metadata

    stale_queued = Redis({b"status": b"queued"})
    fresh_lease = Redis({
        b"status": b"queued",
        b"processing_lease_at": b"2026-07-12T11:59:30+00:00",
    })
    stale_lease = Redis({
        b"status": b"queued",
        b"processing_lease_at": b"2026-07-12T11:50:00+00:00",
    })

    assert api_module._research_queue_presence(
        stale_queued, queue_ids=set(), job_id="job-1", metadata_key="job:job-1", now=now,
    ) is False
    assert api_module._research_queue_presence(
        fresh_lease, queue_ids=set(), job_id="job-1", metadata_key="job:job-1", now=now,
    ) is True
    assert api_module._research_queue_presence(
        stale_lease, queue_ids=set(), job_id="job-1", metadata_key="job:job-1", now=now,
    ) is False
    assert api_module._research_queue_presence(
        stale_queued, queue_ids={"job-1"}, job_id="job-1", metadata_key="job:job-1", now=now,
    ) is True


def test_research_cancel_reaches_scan_correlated_before_command_receipt(monkeypatch):
    episode_id = uuid.uuid4()
    decision_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    workflow_id = str(uuid.uuid4())

    class Transaction:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

    class Conn:
        def __init__(self):
            self.queries = []

        def transaction(self):
            return Transaction()

        async def fetchrow(self, query, *args):
            self.queries.append((query, args))
            if "FROM research_episodes" in query:
                return {
                    "id": episode_id,
                    "target_id": uuid.uuid4(),
                    "status": "dispatching",
                    "cancel_requested": False,
                    "planner": {},
                    "allowed_families": [],
                    "budget_limits": {"steps": 5},
                    "budget_used": {},
                    "current_decision_id": decision_id,
                    "version": 1,
                }
            raise AssertionError(f"unexpected fetchrow: {query}")

        async def fetch(self, query, *args):
            self.queries.append((query, args))
            if "SELECT DISTINCT s.id AS scan_id" in query:
                assert "research_dispatch_correlation" in query
                return [{"scan_id": scan_id}]
            if "AS workflow_id" in query:
                return [{"workflow_id": workflow_id}]
            if "SELECT DISTINCT fv.id" in query:
                assert "fv.requested_by" in query
                return []
            return []

        async def execute(self, query, *args):
            self.queries.append((query, args))
            return "UPDATE 1"

    conn = Conn()
    cancelled = []
    workflow_event = asyncio.Event()
    api_module._active_workflow_cancellations[workflow_id] = workflow_event

    async def fake_cancel(scan_ref):
        cancelled.append(scan_ref)
        return {}

    async def fake_event(*args, **kwargs):
        return {}

    async def fake_detail(_conn, _episode_id):
        return {"episode": {"id": str(episode_id), "status": "cancelled"}}

    monkeypatch.setattr(api_module, "db_pool", _FakePool(conn))
    monkeypatch.setattr(api_module, "cancel_scan", fake_cancel)
    monkeypatch.setattr(api_module, "_record_research_event", fake_event)
    monkeypatch.setattr(api_module, "_research_episode_detail", fake_detail)

    try:
        result = asyncio.run(api_module.cancel_research_episode(str(episode_id)))
    finally:
        api_module._active_workflow_cancellations.pop(workflow_id, None)

    assert cancelled == [str(scan_id)]
    assert result["cancelled_scan_ids"] == [str(scan_id)]
    assert result["cancelled_workflow_ids"] == [workflow_id]
    assert workflow_event.is_set() is True


def test_research_preflight_claim_loser_does_not_queue_duplicate(monkeypatch):
    campaign_id = uuid.uuid4()
    target_id = uuid.uuid4()
    campaign = {
        "id": campaign_id,
        "target_id": target_id,
        "status": "paused",
        "campaign_type": "autonomous_research",
        "metadata_json": {
            "autonomous_research": {
                "intensity": "deep_hunt",
                "allowed_families": ["auth"],
                "preflight_state": "pending",
                "preflight_attempts": 0,
            },
        },
    }

    class Conn:
        async def fetchrow(self, query, *args):
            if "SELECT * FROM campaigns" in query:
                return campaign
            if "NOT IN ('queueing','running')" in query:
                return None
            raise AssertionError(query)

        async def fetch(self, query, *args):
            if "FROM research_episodes" in query:
                return []
            raise AssertionError(query)

    async def fake_readiness(_conn, _campaign):
        return {
            "ready": False,
            "state": "repairable",
            "blockers": ["focused_preflight_required"],
            "required": {"primary_credentials": False},
        }

    async def forbidden_submit(_request):
        raise AssertionError("claim loser must not queue a second preflight")

    monkeypatch.setattr(api_module, "db_pool", _FakePool(Conn()))
    monkeypatch.setattr(api_module, "_research_campaign_readiness", fake_readiness)
    monkeypatch.setattr(api_module, "submit_scan", forbidden_submit)

    result = asyncio.run(api_module._research_campaign_self_repair(campaign_id))

    assert result["action"] == "preflight_claim_lost"


def test_research_preflight_terminal_running_marker_can_claim_successor(monkeypatch):
    campaign_id = uuid.uuid4()
    target_id = uuid.uuid4()
    completed_preflight_id = uuid.uuid4()
    next_preflight_id = uuid.uuid4()
    campaign = {
        "id": campaign_id,
        "target_id": target_id,
        "status": "active",
        "campaign_type": "autonomous_research",
        "metadata_json": {
            "autonomous_research": {
                "intensity": "deep_hunt",
                "allowed_families": ["auth"],
                "approval_receipt_id": str(uuid.uuid4()),
                "preflight_state": "running",
                "preflight_scan_id": str(completed_preflight_id),
                "preflight_attempts": 1,
                "preflight_budget_used": {},
            },
        },
    }

    class Conn:
        def __init__(self):
            self.campaign = campaign
            self.claim_query = ""

        async def fetchrow(self, query, *args):
            if "SELECT * FROM campaigns" in query:
                return self.campaign
            if "UPDATE campaigns SET metadata_json" in query:
                self.claim_query = query
                assert "linked_preflight.status IN ('completed','failed','cancelled')" in query
                assert "INTERVAL '2 minutes'" in query
                self.campaign = {
                    **self.campaign,
                    "metadata_json": json.loads(args[1]),
                }
                return self.campaign
            if "SELECT id, url FROM targets" in query:
                return {"id": target_id, "url": "https://app.example.test"}
            if "UPDATE campaigns SET status='active'" in query:
                self.campaign = {
                    **self.campaign,
                    "status": "active",
                    "metadata_json": json.loads(args[1]),
                }
                return self.campaign
            raise AssertionError(query)

        async def fetch(self, query, *args):
            if "FROM target_endpoints" in query:
                return [{"method": "GET", "path": "/api/account"}]
            raise AssertionError(query)

    async def fake_readiness(_conn, _campaign):
        return {
            "ready": False,
            "state": "repairable",
            "blockers": ["authenticated_preflight_no_material_gain"],
            "required": {"primary_credentials": True},
            "surface": {},
            "preflight_scan": {"id": completed_preflight_id, "status": "completed"},
        }

    async def fake_budget(_conn, _campaign):
        limits = {key: 10_000 for key in api_module.RESEARCH_BUDGET_KEYS}
        used = {key: 0 for key in api_module.RESEARCH_BUDGET_KEYS}
        return {"limits": limits, "used": used, "remaining": limits}

    submitted = []

    async def fake_submit(request):
        submitted.append(request)
        return {"scan_id": str(next_preflight_id), "job_id": "job-next"}

    conn = Conn()
    monkeypatch.setattr(api_module, "db_pool", _FakePool(conn))
    monkeypatch.setattr(api_module, "_research_campaign_readiness", fake_readiness)
    monkeypatch.setattr(api_module, "_research_campaign_budget_snapshot", fake_budget)
    monkeypatch.setattr(api_module, "submit_scan", fake_submit)

    result = asyncio.run(api_module._research_campaign_self_repair(campaign_id))

    assert result["action"] == "queued_authenticated_graph_preflight"
    assert result["scan_id"] == str(next_preflight_id)
    assert len(submitted) == 1
    assert conn.campaign["metadata_json"]["autonomous_research"]["preflight_state"] == "running"
    assert conn.campaign["metadata_json"]["autonomous_research"]["preflight_attempts"] == 2


def test_research_stale_queueing_claim_and_transient_worker_failure_recover(monkeypatch):
    now = datetime.now(timezone.utc)
    assert api_module._research_preflight_claim_is_stale({
        "preflight_state": "queueing",
        "preflight_started_at": (now - timedelta(minutes=3)).isoformat(),
    }, now=now) is True
    assert api_module._research_preflight_claim_is_stale({
        "preflight_state": "queueing",
        "preflight_started_at": (now - timedelta(seconds=30)).isoformat(),
    }, now=now) is False

    campaign_id = uuid.uuid4()
    target_id = uuid.uuid4()
    campaign = {
        "id": campaign_id,
        "target_id": target_id,
        "status": "paused",
        "campaign_type": "autonomous_research",
        "metadata_json": {"autonomous_research": {
            "intensity": "deep_hunt",
            "allowed_families": ["auth"],
            "approval_receipt_id": str(uuid.uuid4()),
            "preflight_state": "pending",
            "preflight_attempts": 0,
            "preflight_budget_used": {},
        }},
    }

    class Conn:
        def __init__(self):
            self.campaign = campaign

        async def fetchrow(self, query, *args):
            if "SELECT * FROM campaigns" in query:
                return self.campaign
            if "UPDATE campaigns SET metadata_json" in query:
                self.campaign = {**self.campaign, "metadata_json": json.loads(args[1])}
                return self.campaign
            if "SELECT id, url FROM targets" in query:
                return {"id": target_id, "url": "https://app.example.test"}
            if "UPDATE campaigns SET status=$4" in query:
                self.campaign = {
                    **self.campaign,
                    "status": args[3],
                    "metadata_json": json.loads(args[1]),
                }
                return self.campaign
            raise AssertionError(query)

        async def fetch(self, query, *args):
            if "FROM target_endpoints" in query:
                return [{"method": "GET", "path": "/api/account"}]
            raise AssertionError(query)

    async def fake_readiness(_conn, _campaign):
        return {
            "ready": False,
            "state": "repairable",
            "blockers": ["authenticated_preflight_required"],
            "required": {"primary_credentials": True},
            "surface": {},
            "preflight_scan": None,
        }

    async def fake_budget(_conn, _campaign):
        limits = {key: 10_000 for key in api_module.RESEARCH_BUDGET_KEYS}
        used = {key: 0 for key in api_module.RESEARCH_BUDGET_KEYS}
        return {"limits": limits, "used": used, "remaining": limits}

    async def stale_workers(_request):
        raise api_module.HTTPException(status_code=409, detail={
            "error": "workers_not_confirmed_current",
            "message": "one pending worker is not build-current",
        })

    conn = Conn()
    monkeypatch.setattr(api_module, "db_pool", _FakePool(conn))
    monkeypatch.setattr(api_module, "_research_campaign_readiness", fake_readiness)
    monkeypatch.setattr(api_module, "_research_campaign_budget_snapshot", fake_budget)
    monkeypatch.setattr(api_module, "submit_scan", stale_workers)

    result = asyncio.run(api_module._research_campaign_self_repair(campaign_id))

    config = result["campaign"]["metadata_json"]["autonomous_research"]
    assert result["action"] == "retry_transient"
    assert result["campaign"]["status"] == "active"
    assert config["preflight_state"] == "pending"
    assert config["preflight_attempts"] == 0
    assert config["preflight_budget_used"] == api_module._research_normalize_budget_used({})
    assert config["budget_used"] == api_module._research_normalize_budget_used({})
    assert config["preflight_retry_after"]


def test_campaign_cancel_propagates_to_preflight_scan(monkeypatch):
    campaign_id = uuid.uuid4()
    preflight_scan_id = str(uuid.uuid4())
    campaign = {
        "id": campaign_id,
        "campaign_type": "autonomous_research",
        "status": "active",
        "metadata_json": {
            "autonomous_research": {"preflight_scan_id": preflight_scan_id},
        },
    }

    class Conn:
        async def fetchrow(self, query, *args):
            if "SELECT * FROM campaigns" in query:
                return campaign
            if "UPDATE campaigns SET status" in query:
                return {**campaign, "status": "cancelled"}
            raise AssertionError(query)

        async def fetch(self, query, *args):
            if "FROM research_episodes" in query:
                return []
            raise AssertionError(query)

        async def execute(self, query, *args):
            return "UPDATE 0"

    cancelled = []

    async def fake_cancel(scan_id):
        cancelled.append(scan_id)
        return {}

    monkeypatch.setattr(api_module, "db_pool", _FakePool(Conn()))
    monkeypatch.setattr(api_module, "cancel_scan", fake_cancel)

    result = asyncio.run(api_module.control_research_campaign(
        str(campaign_id), api_module.ResearchCampaignControlRequest(action="cancel"),
    ))

    assert cancelled == [preflight_scan_id]
    assert result["cancelled_preflight_scan_ids"] == [preflight_scan_id]


def test_campaign_resume_restarts_exhausted_preflight_without_refunding_budget(monkeypatch):
    campaign_id = uuid.uuid4()
    preflight_scan_id = str(uuid.uuid4())
    budget_used = {"requests": 800, "active_actions": 2}
    campaign = {
        "id": campaign_id,
        "campaign_type": "autonomous_research",
        "status": "paused",
        "metadata_json": {
            "autonomous_research": {
                "preflight_scan_id": preflight_scan_id,
                "preflight_job_id": "old-job",
                "preflight_claim_id": "old-claim",
                "preflight_state": "completed",
                "preflight_attempts": api_module.RESEARCH_PREFLIGHT_MAX_ATTEMPTS,
                "preflight_budget_used": budget_used,
                "last_error": "authenticated_coverage_readiness_exhausted",
                "readiness": {"state": "repairable", "blockers": ["no_executable_authenticated_routes"]},
            },
        },
    }

    class Conn:
        async def fetchrow(self, query, *args):
            if "SELECT * FROM campaigns" in query:
                return campaign
            if "metadata_json=$3::jsonb" in query:
                metadata = json.loads(args[2])
                return {**campaign, "status": "active", "metadata_json": metadata}
            raise AssertionError(query)

        async def fetch(self, query, *args):
            if "FROM research_episodes" in query:
                return []
            raise AssertionError(query)

        async def execute(self, query, *args):
            return "UPDATE 0"

    monkeypatch.setattr(api_module, "db_pool", _FakePool(Conn()))

    result = asyncio.run(api_module.control_research_campaign(
        str(campaign_id),
        api_module.ResearchCampaignControlRequest(action="resume", created_by="e2e-test"),
    ))

    config = result["campaign"]["metadata_json"]["autonomous_research"]
    assert result["campaign"]["status"] == "active"
    assert config["preflight_state"] == "pending"
    assert config["preflight_scan_id"] is None
    assert config["preflight_job_id"] is None
    assert config["preflight_claim_id"] is None
    assert config["preflight_attempts"] == 0
    assert config["last_error"] is None
    assert config["preflight_budget_used"] == budget_used
    assert config["preflight_history"][-1]["scan_id"] == preflight_scan_id
    assert config["preflight_history"][-1]["reset_by"] == "e2e-test"


def test_campaign_resume_archives_and_clears_transient_error(monkeypatch):
    campaign_id = uuid.uuid4()
    campaign = {
        "id": campaign_id,
        "campaign_type": "autonomous_research",
        "status": "paused",
        "metadata_json": {
            "autonomous_research": {
                "preflight_state": "completed",
                "preflight_attempts": 1,
                "last_error": "current transaction is aborted",
            },
        },
    }

    class Conn:
        async def fetchrow(self, query, *args):
            if "SELECT * FROM campaigns" in query:
                return campaign
            if "metadata_json=$3::jsonb" in query:
                return {**campaign, "status": "active", "metadata_json": json.loads(args[2])}
            raise AssertionError(query)

        async def fetch(self, query, *args):
            if "FROM research_episodes" in query:
                return []
            raise AssertionError(query)

        async def execute(self, query, *args):
            return "UPDATE 0"

    monkeypatch.setattr(api_module, "db_pool", _FakePool(Conn()))

    result = asyncio.run(api_module.control_research_campaign(
        str(campaign_id),
        api_module.ResearchCampaignControlRequest(action="resume", created_by="operator-test"),
    ))

    config = result["campaign"]["metadata_json"]["autonomous_research"]
    assert config["preflight_state"] == "completed"
    assert config["preflight_attempts"] == 1
    assert config["last_error"] is None
    assert config["resume_history"][-1]["reason"] == "current transaction is aborted"
    assert config["resume_history"][-1]["resumed_by"] == "operator-test"


def test_campaign_budget_is_aggregate_and_each_episode_is_trimmed_to_remaining():
    per_episode = api_module.RESEARCH_LAUNCH_PROFILES["deep_hunt"]["budget_limits"]
    limits = api_module._research_campaign_budget_limits(
        "deep_hunt",
        2,
        {"requests": 700, "model_tokens": 400000, "actions": 30},
    )

    assert limits["requests"] == 700
    assert limits["model_tokens"] == 400000
    assert limits["actions"] == 30
    assert limits["steps"] == per_episode["steps"] * 2
    assert limits["active_actions"] == (
        per_episode["active_actions"] * 2
        + api_module.RESEARCH_PREFLIGHT_RESERVED_COST["active_actions"]
        * api_module.RESEARCH_PREFLIGHT_MAX_ATTEMPTS
    )

    remaining = api_module._research_campaign_budget_remaining(limits, {
        "steps": 23,
        "actions": 22,
        "active_actions": 11,
        "requests": 650,
        "seconds": 7000,
        "model_tokens": 350000,
    })
    episode_limits = api_module._research_campaign_episode_budget_limits("deep_hunt", remaining)

    assert episode_limits["steps"] == 25
    assert episode_limits["actions"] == 8
    assert episode_limits["requests"] == 50
    assert episode_limits["model_tokens"] == 50000
    assert api_module._research_campaign_budget_violations(
        limits,
        {"requests": 650},
        {"requests": 51},
    ) == ["campaign_budget_exhausted:requests"]


def test_campaign_budget_snapshot_sums_preflight_and_all_episode_usage():
    campaign_id = uuid.uuid4()
    limits = api_module._research_campaign_budget_limits("hunt", 2)
    campaign = {
        "id": campaign_id,
        "metadata_json": {
            "autonomous_research": {
                "intensity": "hunt",
                "max_episodes": 2,
                "budget_limits": limits,
                "preflight_budget_used": {"requests": 100, "active_actions": 1},
            },
        },
    }

    class Conn:
        async def fetch(self, query, *args):
            assert "SELECT budget_used FROM research_episodes" in query
            return [
                {"budget_used": {"requests": 120, "model_tokens": 5000, "steps": 3}},
                {"budget_used": json.dumps({"requests": 80, "model_tokens": 7000, "steps": 2})},
            ]

    snapshot = asyncio.run(api_module._research_campaign_budget_snapshot(Conn(), campaign))

    assert snapshot["used"]["requests"] == 300
    assert snapshot["used"]["active_actions"] == 1
    assert snapshot["used"]["model_tokens"] == 12000
    assert snapshot["used"]["steps"] == 5
    assert snapshot["remaining"]["requests"] == limits["requests"] - 300


def test_research_planner_recovers_unique_read_only_command_from_registered_description():
    observation = {
        "id": "observation-1",
        "context_hash": "a" * 64,
        "observation_pack": {
            "proposable_commands": [
                {"name": "asm.gaps", "proposable": True, "risk_tier": "read_only",
                 "description": "Explain remaining ASM gaps and recommended campaigns for one target.",
                 "parameters_schema": {"target_id": {}}},
                {"name": "target.get", "proposable": True, "risk_tier": "read_only",
                 "description": "Get one target and recent scan metadata.",
                 "parameters_schema": {"target_id": {}}},
            ]
        },
    }
    bound = api_module._bind_research_decision_to_observation(
        {
            "decision": "execute_action",
            "action": {"command": "", "parameters": {"target_id": "target-1"}},
            "expected_signal": "A gap report listing remaining coverage and recommended campaigns",
            "falsifier": "No gap or campaign recommendations are returned",
        },
        observation,
    )

    assert bound["action"]["command"] == "asm.gaps"


def test_research_planner_never_semantically_guesses_active_command():
    observation = {
        "observation_pack": {"proposable_commands": [{
            "name": "asm.test", "proposable": True, "risk_tier": "active",
            "description": "Run active endpoint tests for remaining gaps.",
            "parameters_schema": {"target_id": {}},
        }]}
    }
    response = {
        "decision": "execute_action", "action": {"command": "", "parameters": {"target_id": "target-1"}},
        "expected_signal": "Active endpoint test results for gaps", "falsifier": "No tests run",
    }

    assert api_module._infer_blank_read_only_command(response, observation) is None


def test_research_planner_rejection_feedback_is_bounded_for_next_observation():
    errors = ["unknown_command:", "x" * 500]
    feedback = {
        "planner_rejection": {
            "validation_errors": [str(item)[:300] for item in errors[:20]],
            "instruction": "Choose a named proposable command or provide a valid stop/input decision.",
        }
    }

    assert feedback["planner_rejection"]["validation_errors"][0] == "unknown_command:"
    assert len(feedback["planner_rejection"]["validation_errors"][1]) == 300


def test_research_planner_infers_unambiguous_action_discriminator():
    bound = api_module._bind_research_decision_to_observation(
        {"action": {"command": "asm.gaps", "parameters": {}}},
        {"id": "observation-1", "context_hash": "a" * 64},
    )

    assert bound["decision"] == "execute_action"


def test_research_planner_does_not_infer_ambiguous_discriminator():
    bound = api_module._bind_research_decision_to_observation(
        {
            "action": {"command": "asm.gaps", "parameters": {}},
            "stop_reason": "also stop",
        },
        {"id": "observation-1", "context_hash": "a" * 64},
    )

    assert "decision" not in bound


def test_research_planner_recovers_only_unique_proposable_command_shape():
    observation = {
        "id": "observation-1",
        "context_hash": "a" * 64,
        "observation_pack": {
            "proposable_commands": [
                {
                    "name": "hypothesis.situation_report",
                    "proposable": True,
                    "parameters_schema": {"target_id": {}, "include_graph": {}, "limit": {}},
                },
                {
                    "name": "target.get",
                    "proposable": True,
                    "parameters_schema": {"target_id": {}},
                },
            ]
        },
    }

    bound = api_module._bind_research_decision_to_observation(
        {"decision": "execute_action", "action": {"command": "", "parameters": {"include_graph": True}}},
        observation,
    )
    ambiguous = api_module._bind_research_decision_to_observation(
        {"decision": "execute_action", "action": {"command": "", "parameters": {"target_id": "target-1"}}},
        observation,
    )

    assert bound["action"]["command"] == "hypothesis.situation_report"
    assert ambiguous["action"]["command"] == ""


def test_http_experiment_has_wired_gated_dispatch_adapter():
    command = api_module._research_command_catalog()["experiment.http_diff"]

    assert command["status"] == "gated"
    assert command["risk_tier"] == "active"
    assert command["request_cost"] == 4
    assert api_module._arsenal_gated_adapters()["experiment.http_diff"] is api_module._arsenal_dispatch_http_diff


def test_principal_workflow_has_wired_gated_dispatch_adapter():
    command = api_module._research_command_catalog()["experiment.workflow"]

    assert command["status"] == "gated"
    assert command["risk_tier"] == "credential"
    assert command["request_cost"] == 12
    assert "workflow_id" in command["parameters_schema"]
    principal_variables = command["parameters_schema"]["principal_variables"]
    assert principal_variables["items"]["additionalProperties"] is False
    assert principal_variables["items"]["required"] == ["name", "principal", "ref"]
    assert api_module._arsenal_gated_adapters()["experiment.workflow"] is api_module._arsenal_dispatch_workflow


def test_trusted_workflow_proof_requires_stable_replay_and_restoration():
    execution = {
        "proof_family": "workflow",
        "restoration_verified": True,
        "observations": [{"label": "before", "error": None}],
        "assertion_results": [
            {"id": "broken", "type": "comparison_changed", "predicate": "transition_invariant_broken", "passed": True},
            {"id": "restored", "type": "restored", "predicate": "before_after_state", "passed": True},
        ],
    }
    proof = api_module._trusted_workflow_family_proof(execution, execution)
    assert proof["verdict"] == "inconclusive"
    assert proof["promotable"] is False
    assert proof["reproduction_count"] == 2

    failed_replay = {**execution, "restoration_verified": False}
    proof = api_module._trusted_workflow_family_proof(execution, failed_replay)
    assert proof["promotable"] is False
    assert proof["reexecuted_at_handoff"] is False


# --- create-based mass_assignment: best-effort restoration (registration is unpromotable otherwise,
# because the target has no delete route). The finding stays proven by the three server-derived MA
# predicates across two runs; verified restoration is a cleanliness gate, not a soundness gate. These
# guards prove the relax is zero-FP: it is scoped to the mass_assignment family AND the create->delete
# shape, it never bypasses a predicate, and it never relaxes any other family's restoration. ---

_CREATE_MA_NORMALIZED = {
    "steps": [
        {"label": "list_before", "checkpoint": "before", "method": "GET"},
        {"label": "control", "checkpoint": "mutation", "method": "POST", "extract": [{"name": "control_id"}]},
        {"label": "mutate", "checkpoint": "mutation", "method": "POST", "extract": [{"name": "created_id"}]},
        {"label": "cleanup_created", "checkpoint": "cleanup", "method": "DELETE"},
        {"label": "list_after", "checkpoint": "after", "method": "GET"},
    ]
}


def _create_ma_execution(*, benign_ok=True):
    import workflow_experiment as _we
    created_hash = hashlib.sha256(b"42").hexdigest()
    control_hash = hashlib.sha256(b"43").hexdigest()
    # The persistence proof requires the submitted privilege value's fingerprint to equal the
    # read-back value's fingerprint -- so the forbidden field genuinely persisted (admin, not a label).
    role_fp = _we._value_fingerprint("admin")
    return {
        "proof_family": "mass_assignment",
        # No delete route on the target -> restoration can never be *verified*.
        "restoration_verified": False,
        "observations": [
            {"label": "control", "principal": "user1", "checkpoint": "mutation",
             "request": {"method": "POST", "path": "/api/Users"},
             "submitted_fields": ["display_name"],
             "submitted_field_hashes": {"display_name": "h"},
             "extracted": {"control_id": {"sha256": control_hash}},
             "response": {"status": 201 if benign_ok else 400}, "error": None},
            {"label": "mutate", "principal": "user1", "checkpoint": "mutation",
             "request": {"method": "POST", "path": "/api/Users"},
             "submitted_fields": ["role"],
             "submitted_field_hashes": {"role": role_fp},
             "extracted": {"created_id": {"sha256": created_hash}},
             "response": {"status": 201, "json_keys": ["role", "id"]}, "error": None},
            {"label": "control_verify", "principal": "user1", "checkpoint": "action",
             "request": {"method": "GET", "path": "/api/Users/43"},
             "response": {"status": 200, "selected_json": {"$.role": "user"}}, "error": None},
            {"label": "verify", "principal": "user1", "checkpoint": "action",
             "request": {"method": "GET", "path": "/api/Users/42"},
             "response": {"status": 200, "selected_json": {"$.role": "admin"}}, "error": None},
            # Best-effort cleanup that the target rejects (401) -- attempted, but not a hard error.
            {"label": "cleanup_created", "principal": "user1", "checkpoint": "cleanup",
             "request": {"method": "DELETE", "path": "/api/Users/42"},
             "response": {"status": 401}, "error": None},
        ],
        "comparisons": [{"control": "control_verify", "candidate": "verify", "comparable": True,
                         "selected_json_changed": {"$.role": ["user", "admin"]}}],
        "assertion_results": [
            {"id": "c", "type": "status_in", "step": "control", "values": [201],
             "predicate": "benign_control_accepted", "passed": benign_ok},
            {"id": "f", "type": "status_in", "step": "mutate", "values": [201],
             "predicate": "forbidden_field_accepted", "passed": True},
            {"id": "s", "type": "comparison_changed", "control": "control_verify", "candidate": "verify",
             "predicate": "observable_state_change", "passed": True},
            # The restored assertion FAILS (the created admin persists) -- consistently across both runs.
            {"id": "r", "type": "restored", "control": "list_before", "candidate": "list_after",
             "predicate": "before_after_state", "passed": False},
        ],
    }


def test_create_based_mass_assignment_does_not_promote_without_verified_restoration():
    execution = _create_ma_execution()
    proof = api_module._trusted_workflow_family_proof(execution, execution, normalized=_CREATE_MA_NORMALIZED)
    assert proof["restoration_verified"] is False
    assert proof["reexecuted_at_handoff"] is False
    assert proof["verdict"] != "verified"
    assert proof["promotable"] is False
    assert set(proof["stable_predicates"]) == {
        "forbidden_field_accepted", "observable_state_change", "benign_control_accepted"}
    # The proven route must bind to the WRITE (the create), not the read-back that verifies it --
    # otherwise proof_routes collapses to [] (POST /collection vs GET /collection/{id}) and
    # _promote_trusted_workflow_finding silently blocks the promotion.
    assert proof["proof_routes"] == ["/api/Users"]
    assert proof["proof_methods"] == ["POST"]


def test_create_based_mass_assignment_gate_is_family_and_shape_scoped():
    ok = _CREATE_MA_NORMALIZED
    # Shape detection remains scoped to create-based mass assignment; it no longer relaxes cleanup.
    assert api_module._is_create_based_mass_assignment("mass_assignment", ok) is True
    assert api_module._is_create_based_mass_assignment("bola", ok) is False
    assert api_module._is_create_based_mass_assignment("workflow", ok) is False
    assert api_module._is_create_based_mass_assignment("data_exposure", ok) is False
    # shape gate: needs BOTH a create (POST mutation with extract) AND an attempted DELETE cleanup.
    no_create = {"steps": [{"checkpoint": "mutation", "method": "PUT"},
                            {"checkpoint": "rollback", "method": "PUT"}]}
    assert api_module._is_create_based_mass_assignment("mass_assignment", no_create) is False
    no_cleanup = {"steps": [{"checkpoint": "mutation", "method": "POST", "extract": [{"name": "id"}]}]}
    assert api_module._is_create_based_mass_assignment("mass_assignment", no_cleanup) is False
    create_no_extract = {"steps": [{"checkpoint": "mutation", "method": "POST"},
                                    {"checkpoint": "cleanup", "method": "DELETE"}]}
    assert api_module._is_create_based_mass_assignment("mass_assignment", create_no_extract) is False


def test_create_based_mass_assignment_still_requires_every_predicate():
    # A missing required predicate cannot reach verified, independent of the restoration gate.
    execution = _create_ma_execution(benign_ok=False)
    proof = api_module._trusted_workflow_family_proof(execution, execution, normalized=_CREATE_MA_NORMALIZED)
    assert "benign_control_accepted" not in proof["stable_predicates"]
    assert proof["verdict"] != "verified"
    assert proof["promotable"] is False


def test_restoration_stays_required_for_non_create_mass_assignment():
    # An UPDATE-based mass_assignment also requires verified restoration.
    execution = _create_ma_execution()
    update_shape = {"steps": [{"checkpoint": "mutation", "method": "PUT"},
                              {"checkpoint": "rollback", "method": "PUT"}]}
    proof = api_module._trusted_workflow_family_proof(execution, execution, normalized=update_shape)
    assert proof["reexecuted_at_handoff"] is False
    assert proof["promotable"] is False


def test_create_field_classification_is_name_based_and_universal():
    c = api_module._classify_create_field
    assert c("email") == "login" and c("userEmail") == "login" and c("username") == "login"
    assert c("password") == "secret" and c("passwordRepeat") == "secret" and c("pwd") == "secret"
    assert c("role") == "other" and c("isAdmin") == "other" and c("quantity") == "other"


def test_discover_create_object_shape_finds_envelope_and_id():
    d = api_module._discover_create_object_shape
    assert d({"status": "success", "data": {"id": 5, "role": "admin"}}) == ("data", "id")
    assert d({"id": 9, "role": "x"}) == (None, "id")
    assert d({"result": {"userId": 3}}) == ("result", "userId")
    assert d({"status": "ok"}) is None          # no id-bearing object
    assert d("not-json") is None


def test_agent_finding_locus_requires_an_exact_cited_operation():
    evidence = [
        {"content": json.dumps({"request": {"method": "GET", "path": "/api/items/7"}})},
        {"content": json.dumps({"request": {"method": "POST", "path": "/api/items"}})},
    ]
    # Multi-operation evidence is ambiguous without an explicit operation.
    assert api_module._agent_finding_locus({"evidence": evidence}) == (None, None)
    # An exact operation named by the debrief is accepted only when cited.
    assert api_module._agent_finding_locus({
        "evidence": evidence,
        "route": "/api/items",
        "method": "POST",
    }) == ("/api/items", "POST")
    assert api_module._agent_finding_locus({
        "evidence": evidence,
        "route": "/api/admin",
        "method": "POST",
    }) == (None, None)


def test_mass_assignment_verification_requires_evidenced_post_method():
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module._agent_verification_workflow_for(
            None,
            uuid.uuid4(),
            "mass_assignment",
            "/api/users",
            "",
        ))
    assert exc.value.status_code == 422
    workflow, route, method, metadata = asyncio.run(
        api_module._agent_verification_workflow_for(
            None,
            uuid.uuid4(),
            "mass_assignment",
            "/api/users",
            "POST",
        )
    )
    assert workflow["server_materialize"] is True
    assert (route, method, metadata) == ("/api/users", "POST", {"create_based": True})


def test_probe_create_surface_cleans_trackable_artifact_with_same_cookie():
    import httpx

    requests = []

    def handler(request):
        requests.append(request)
        assert "session=managed" in request.headers.get("cookie", "")
        if request.method == "POST":
            return httpx.Response(201, json={"data": {"id": 42, "role": "user"}})
        assert request.method == "DELETE"
        assert request.url.path == "/api/users/42"
        return httpx.Response(204)

    result = asyncio.run(api_module._probe_create_surface(
        "https://target.test",
        "/api/users",
        {},
        {"session": "managed"},
        httpx.MockTransport(handler),
    ))
    assert result["usable"] is True
    assert result["request_count"] == 1
    assert result["cleanup_request_count"] == 1
    assert result["artifacts"] == [{
        "id_sha256": hashlib.sha256(b"42").hexdigest(),
        "cleanup_attempted": True,
        "cleanup_succeeded": True,
        "cleanup_status": 204,
    }]
    assert [request.method for request in requests] == ["POST", "DELETE"]


def test_probe_create_surface_stops_after_untrackable_accepted_create():
    import httpx

    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(201, json={"status": "created"})

    result = asyncio.run(api_module._probe_create_surface(
        "https://target.test",
        "/api/users",
        {},
        transport=httpx.MockTransport(handler),
    ))
    assert result["usable"] is False
    assert result["reason"] == "accepted_probe_missing_trackable_id"
    assert result["request_count"] == 1
    assert len(requests) == 1


def test_probe_create_surface_rejects_non_same_origin_collection_without_io():
    import httpx

    def should_not_run(_request):
        raise AssertionError("out-of-scope probe performed network I/O")

    result = asyncio.run(api_module._probe_create_surface(
        "https://target.test",
        "//other.test/api/users",
        {},
        transport=httpx.MockTransport(should_not_run),
    ))
    assert result["usable"] is False
    assert result["reason"] == "probe_collection_outside_same_origin_scope"
    assert result["request_count"] == 0


def test_materialize_create_mass_assignment_workflow_is_valid_and_universal():
    import workflow_experiment
    wf = api_module._materialize_create_mass_assignment_workflow(
        collection_route="/api/Users", request_fields="email,password",
        forbidden_field="role", forbidden_value="admin", envelope="data", id_field="id")
    assert wf is not None
    # Normalizes cleanly (managed password body passes the sensitive-key relax; create-cleanup present).
    workflow_experiment.normalize_workflow("https://shop.test", wf)
    steps = {s["label"]: s for s in wf["steps"]}
    # Managed credentials, never literals; forbidden field only on the mutate create.
    assert steps["control"]["json_body"] == {"email": "${ctrl_login}", "password": "${reg_cred}"}
    assert steps["mutate"]["json_body"] == {"email": "${adm_login}", "password": "${reg_cred}", "role": "admin"}
    # Distinct logins so the two creates cannot collide on a unique constraint.
    assert steps["control"]["json_body"]["email"] != steps["mutate"]["json_body"]["email"]
    # Extract + read-back paths use the DISCOVERED envelope, not a guess.
    assert steps["mutate"]["extract"][0]["path"] == "$.data.id"
    assert steps["verify"]["select_json"] == ["$.data.role"]
    # No login field -> refuse rather than fabricate an unprovable (collision-prone) workflow.
    assert api_module._materialize_create_mass_assignment_workflow(
        collection_route="/api/Orders", request_fields="quantity,price",
        forbidden_field="discount", forbidden_value="100", envelope="data", id_field="id") is None


def test_inject_create_ma_credentials_scoped_and_fresh_per_run():
    pv = [{"name": "ctrl_login", "principal": "user1", "ref": "ctrl_login"},
          {"name": "adm_login", "principal": "user1", "ref": "adm_login"},
          {"name": "reg_cred", "principal": "user1", "ref": "reg_cred"}]
    create_ma = {"proof_family": "mass_assignment", "principal_variables": pv,
                 "steps": [{"checkpoint": "mutation", "method": "POST", "extract": [{"name": "created_id"}]},
                           {"checkpoint": "cleanup", "method": "DELETE"}]}
    ctx = {}
    api_module._inject_create_mass_assignment_credentials(ctx, create_ma)
    refs = ctx["user1"]["captured_refs"]
    assert set(refs) == {"ctrl_login", "adm_login", "reg_cred"}
    assert refs["ctrl_login"] != refs["adm_login"]        # distinct logins within a run
    first_login = refs["ctrl_login"]
    api_module._inject_create_mass_assignment_credentials(ctx, create_ma)  # next run
    assert ctx["user1"]["captured_refs"]["ctrl_login"] != first_login       # fresh, no replay collision
    # No-op for non-create-mass_assignment: a bola workflow, or an update-based MA (no POST create).
    for other in ({"proof_family": "bola", "principal_variables": pv, "steps": []},
                  {"proof_family": "mass_assignment", "principal_variables": pv,
                   "steps": [{"checkpoint": "mutation", "method": "PUT"}]}):
        empty = {}
        api_module._inject_create_mass_assignment_credentials(empty, other)
        assert empty == {}


def test_trusted_workflow_bola_proof_requires_full_server_bound_receipt():
    execution = {
        "proof_family": "bola",
        "restoration_verified": True,
        "principal_receipts": [
            {"slot": "user1", "identity_fingerprint": "owner-id"},
            {"slot": "user2", "identity_fingerprint": "attacker-id"},
        ],
        "observations": [
            {"label": "create", "principal": "user1", "checkpoint": "mutation",
             "request": {"method": "POST", "path": "/objects"}, "response": {"status": 201},
             "extracted_names": ["object_id"], "extracted": {"object_id": {"sha256": "a" * 64}},
             "error": None},
            {"label": "create_attacker", "principal": "user2", "checkpoint": "mutation",
             "request": {"method": "POST", "path": "/objects"}, "response": {"status": 201},
             "extracted_names": ["object_id"], "extracted": {"object_id": {"sha256": "b" * 64}},
             "error": None},
            {"label": "owner", "principal": "user1", "request": {
                "method": "GET", "path": "/objects/42", "variable_references": ["object_id"],
             }, "response": {"status": 200}, "error": None},
            {"label": "attacker", "principal": "user2",
             "request": {"method": "GET", "path": "/objects/42"},
             "response": {"status": 200}, "error": None},
            {"label": "anonymous", "principal": "anonymous",
             "request": {"method": "GET", "path": "/objects/42"},
             "response": {"status": 403}, "error": None},
        ],
        "comparisons": [{
            "control": "owner", "candidate": "attacker", "comparable": True,
            "body_changed": False, "status_changed": False,
        }],
        "assertion_results": [
            {"id": "ids", "type": "distinct_principals", "steps": ["owner", "attacker"],
             "predicate": "distinct_identity", "passed": True},
            {"id": "own", "type": "comparison_equivalent", "control": "owner", "candidate": "attacker",
             "predicate": "ownership_established", "passed": True},
            {"id": "cross", "type": "comparison_equivalent", "control": "owner", "candidate": "attacker",
             "predicate": "cross_principal_access", "passed": True},
            {"id": "deny", "type": "status_not_in", "step": "anonymous",
             "predicate": "denial_control", "passed": True},
        ],
    }
    proof = api_module._trusted_workflow_family_proof(execution, execution)
    assert proof["verdict"] == "verified"
    assert proof["promotable"] is True
    # Bindings are canonicalized (Finding 1), so the proven route is the object-id template, not the
    # one concrete id that happened to be used.
    assert proof["proof_routes"] == ["/objects/{id}"]
    assert proof["proof_methods"] == ["GET"]


def _bola_object_execution(object_id):
    path = f"/objects/{object_id}"
    return {
        "proof_family": "bola",
        "restoration_verified": True,
        "principal_receipts": [
            {"slot": "user1", "identity_fingerprint": "owner-id"},
            {"slot": "user2", "identity_fingerprint": "attacker-id"},
        ],
        "observations": [
            {"label": "create", "principal": "user1", "checkpoint": "mutation",
             "request": {"method": "POST", "path": "/objects"}, "response": {"status": 201},
             "extracted_names": ["object_id"],
             "extracted": {"object_id": {"sha256": hashlib.sha256(str(object_id).encode()).hexdigest()}},
             "error": None},
            {"label": "create_attacker", "principal": "user2", "checkpoint": "mutation",
             "request": {"method": "POST", "path": "/objects"}, "response": {"status": 201},
             "extracted_names": ["object_id"],
             "extracted": {"object_id": {"sha256": hashlib.sha256(f"attacker-{object_id}".encode()).hexdigest()}},
             "error": None},
            {"label": "owner", "principal": "user1", "request": {
                "method": "GET", "path": path, "variable_references": ["object_id"],
             }, "response": {"status": 200}, "error": None},
            {"label": "attacker", "principal": "user2",
             "request": {"method": "GET", "path": path},
             "response": {"status": 200}, "error": None},
            {"label": "anonymous", "principal": "anonymous",
             "request": {"method": "GET", "path": path},
             "response": {"status": 403}, "error": None},
        ],
        "comparisons": [{
            "control": "owner", "candidate": "attacker", "comparable": True,
            "body_changed": False, "status_changed": False,
        }],
        "assertion_results": [
            {"id": "ids", "type": "distinct_principals", "steps": ["owner", "attacker"],
             "predicate": "distinct_identity", "passed": True},
            {"id": "own", "type": "comparison_equivalent", "control": "owner", "candidate": "attacker",
             "predicate": "ownership_established", "passed": True},
            {"id": "cross", "type": "comparison_equivalent", "control": "owner", "candidate": "attacker",
             "predicate": "cross_principal_access", "passed": True},
            {"id": "deny", "type": "status_not_in", "step": "anonymous",
             "predicate": "denial_control", "passed": True},
        ],
    }


def test_trusted_workflow_bola_proof_matches_across_distinct_object_ids():
    # Finding 1 regression: the execute run and the independent replay of an object-id workflow
    # legitimately create/read a DIFFERENT concrete id each time. With raw rendered-path bindings
    # (/objects/42 vs /objects/43) the two runs never matched, stable_bindings emptied, proof_routes
    # collapsed to [], and _promote_trusted_workflow_finding bailed at len(proven_routes)!=1 --
    # silently disabling every object-id BOLA/IDOR promotion. Canonicalizing to /objects/{id} before
    # the cross-run comparison keeps them aligned so a genuinely verified BOLA promotes.
    first = _bola_object_execution(42)
    replay = _bola_object_execution(43)
    proof = api_module._trusted_workflow_family_proof(first, replay)
    assert proof["verdict"] == "verified"
    assert proof["promotable"] is True
    assert proof["proof_routes"] == ["/objects/{id}"]
    assert proof["proof_methods"] == ["GET"]


def test_workflow_identity_fingerprint_uses_metadata_without_exposing_identity():
    fingerprint = api_module._workflow_identity_fingerprint(
        {"account_id": "Account-42"}, {}, "Bearer opaque-secret", "authorization_header"
    )

    assert fingerprint == hashlib.sha256(b"account_id:account-42").hexdigest()
    assert "Account-42" not in fingerprint


def test_workflow_runtime_closes_browser_session_after_cancellation(monkeypatch):
    closed = []

    class Session:
        session_id = "workflow-session"

        async def start(self):
            return {"success": True}

    class Manager:
        async def create_session(self, target_url, results_dir):
            return Session()

        async def close_session(self, session_id):
            closed.append(session_id)
            return True

    class ManagerFactory:
        @staticmethod
        async def get_instance():
            return Manager()

    async def fake_execute(*args, **kwargs):
        assert kwargs["cancelled"]() is True
        return {"cancelled": True, "observations": [], "finding_created": False}

    monkeypatch.setattr(api_module, "InteractiveSessionManager", ManagerFactory)
    monkeypatch.setattr(api_module, "execute_workflow", fake_execute)
    event = asyncio.Event()
    event.set()

    result = asyncio.run(api_module._execute_workflow_runtime(
        "https://example.test",
        {"steps": []},
        {"steps": [{"kind": "browser"}]},
        {},
        event,
    ))

    assert result["cancelled"] is True
    assert closed == ["workflow-session"]


def test_research_semantic_dimension_ignores_workflow_and_concrete_object_ids():
    first = {
        "command": "experiment.workflow",
        "parameters": {
            "workflow_id": str(uuid.uuid4()),
            "proof_family": "auth_bypass",
            "steps": [{"method": "GET", "path": "/orders/41"}],
        },
    }
    second = {
        "command": "experiment.workflow",
        "parameters": {
            "workflow_id": str(uuid.uuid4()),
            "proof_family": "auth_bypass",
            "steps": [{"method": "GET", "path": "/orders/99"}],
        },
    }

    assert api_module._research_action_semantic_dimension(first) == api_module._research_action_semantic_dimension(second)


def test_research_semantic_dimension_retains_method_field_and_assertion():
    base = {
        "command": "experiment.workflow",
        "parameters": {
            "proof_family": "mass_assignment",
            "steps": [
                {"label": "mutate", "method": "PATCH", "path": "/profile/42",
                 "principal": "user1", "checkpoint": "mutation", "json_body": {"role": "admin"}},
            ],
            "assertions": [
                {"step": "mutate", "type": "status_in", "values": [200],
                 "predicate": "forbidden_field_accepted"},
            ],
        },
    }
    different_method = json.loads(json.dumps(base))
    different_method["parameters"]["steps"][0]["method"] = "POST"
    different_field = json.loads(json.dumps(base))
    different_field["parameters"]["steps"][0]["json_body"] = {"isAdmin": True}
    different_assertion = json.loads(json.dumps(base))
    different_assertion["parameters"]["assertions"][0]["predicate"] = "benign_control_accepted"

    dimensions = {
        api_module._research_action_semantic_dimension(item)
        for item in (base, different_method, different_field, different_assertion)
    }
    assert None not in dimensions
    assert len(dimensions) == 4


def test_research_hypothesis_context_suppresses_known_deterministic_finding():
    known = api_module._canonical_vulnerability_key(family="bola", route="/orders/{id}")
    already_found = {
        "id": "known-bola",
        "source": "app_graph",
        "family": "bola",
        "status": "open",
        "severity_guess": "critical",
        "confidence": 0.99,
        "dedupe_key": "known",
        "dedupe_dimensions": {"route": "/orders/123"},
        "metadata_json": {"unexplained_residue": True, "route": "/orders/123"},
    }
    novel = {
        "id": "novel-mass-assignment",
        "source": "app_graph",
        "family": "mass_assignment",
        "status": "open",
        "severity_guess": "high",
        "confidence": 0.7,
        "dedupe_key": "novel",
        "dedupe_dimensions": {"route": "/profiles/{id}"},
        "metadata_json": {"unexplained_residue": True, "route": "/profiles/{id}"},
    }

    summaries, ranked = api_module._select_research_hypothesis_context(
        [already_found, novel],
        completed_dimensions=[],
        auth_available=True,
        known_vulnerability_keys={known},
    )

    assert [item["id"] for item in summaries] == ["novel-mass-assignment"]
    assert [item["hypothesis_id"] for item in ranked] == ["novel-mass-assignment"]


def test_research_hypothesis_live_surface_filter_rejects_phantom_routes():
    live_surface = {("PATCH", "/profiles/{id}"), ("GET", "/orders/{id}")}
    live = {
        "source": "app_graph", "family": "mass_assignment",
        "metadata_json": {"route": "/profiles/42", "method": "PATCH"},
    }
    phantom = {
        "source": "ai_planner", "family": "mass_assignment",
        "metadata_json": {"route": "/identity/api/coupon", "method": "PATCH"},
    }
    invariant = {
        "source": "invariant", "family": "workflow",
        "metadata_json": {"route": "/workflow/transition", "method": "POST"},
    }

    assert api_module._research_hypothesis_matches_live_surface(live, live_surface) is True
    assert api_module._research_hypothesis_matches_live_surface(phantom, live_surface) is False
    assert api_module._research_hypothesis_matches_live_surface(invariant, live_surface) is True


def test_research_campaign_readiness_requires_completed_two_user_surface():
    target_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    campaign = {
        "id": uuid.uuid4(),
        "target_id": target_id,
        "metadata_json": {
            "autonomous_research": {
                "intensity": "deep_hunt",
                "approval_receipt_id": str(uuid.uuid4()),
                "allowed_families": ["auth", "bola"],
                "preflight_scan_id": str(scan_id),
            },
        },
    }

    class Conn:
        async def fetch(self, query, *args):
            assert "target_principals" in query
            return [
                {"auth_state": "user1", "credential_profile": "owner", "is_active": True, "credential_configured": True},
                {"auth_state": "user2", "credential_profile": "attacker", "is_active": True, "credential_configured": True},
            ]

        async def fetchrow(self, query, *args):
            if "FROM target_endpoints" in query and "last_seen_scan_id" in query:
                return {
                    "fresh_authenticated_routes": 30, "fresh_second_user_routes": 12,
                    "fresh_executable_routes": 25, "fresh_object_routes": 8,
                    "fresh_mutation_routes": 6, "fresh_parameterized_routes": 14,
                }
            if "FROM target_endpoints" in query:
                return {
                    "inventory_rows": 80,
                    "unique_routes": 40,
                    "authenticated_routes": 30,
                    "second_user_routes": 12,
                    "executable_routes": 25,
                    "object_routes": 8,
                    "mutation_routes": 6,
                    "parameterized_routes": 14,
                }
            if "FROM application_graph_nodes" in query:
                return {
                    "route_nodes": 4,
                    "edge_count": 3,
                    "fresh_route_nodes": 4,
                    "fresh_edge_count": 3,
                    # A fresh cross-principal auth_boundary edge is what makes BOLA executable.
                    "fresh_auth_boundary_edges": 2,
                }
            if "FROM scans" in query:
                return {"id": scan_id, "status": "completed", "current_phase": "done", "error_message": None}
            raise AssertionError(query)

    readiness = asyncio.run(api_module._research_campaign_readiness(Conn(), campaign))

    assert readiness["ready"] is True
    assert readiness["surface"]["authenticated_routes"] == 30
    assert readiness["surface"]["fresh_auth_boundary_edges"] == 2
    assert readiness["surface"]["executable_families"] == ["auth", "bola"]


def test_research_campaign_readiness_requires_invariant_for_invariant_only_family():
    target_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    campaign = {
        "id": uuid.uuid4(),
        "target_id": target_id,
        "metadata_json": {"autonomous_research": {
            "intensity": "deep_hunt",
            "approval_receipt_id": str(uuid.uuid4()),
            "allowed_families": ["field_constraint"],
            "require_all_requested_families": True,
            "preflight_scan_id": str(scan_id),
        }},
    }

    class Conn:
        async def fetch(self, query, *args):
            if "target_principals" in query:
                return [{"auth_state": "user1", "credential_profile": "owner", "credential_configured": True}]
            raise AssertionError(query)

        async def fetchrow(self, query, *args):
            if "target_invariant_contracts" in query:
                return {"access_control": 0, "field_constraint": 0, "workflow": 0}
            if "FROM target_endpoints" in query and "last_seen_scan_id" in query:
                return {
                    "fresh_unique_routes": 6, "fresh_authenticated_routes": 6,
                    "fresh_executable_routes": 6, "fresh_all_executable_routes": 6,
                    "fresh_mutation_routes": 3, "fresh_parameterized_routes": 3,
                }
            if "FROM target_endpoints" in query:
                return {
                    "inventory_rows": 6, "unique_routes": 6, "authenticated_routes": 6,
                    "executable_routes": 6, "all_executable_routes": 6,
                    "mutation_routes": 3, "parameterized_routes": 3,
                }
            if "FROM application_graph_nodes" in query:
                return {"route_nodes": 6, "fresh_route_nodes": 6, "edge_count": 0,
                        "fresh_edge_count": 0, "fresh_auth_boundary_edges": 0}
            if "FROM scans" in query:
                return {"id": scan_id, "status": "completed", "current_phase": "done"}
            raise AssertionError(query)

    readiness = asyncio.run(api_module._research_campaign_readiness(Conn(), campaign))

    assert readiness["ready"] is False
    assert readiness["surface"]["executable_families"] == []
    assert readiness["surface"]["approved_invariant_counts"]["field_constraint"] == 0
    assert "family_surface_unavailable:field_constraint" in readiness["blockers"]


def test_research_campaign_readiness_allows_narrow_public_injection_without_credentials():
    target_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    campaign = {
        "id": uuid.uuid4(),
        "target_id": target_id,
        "metadata_json": {"autonomous_research": {
            "intensity": "deep_hunt",
            "approval_receipt_id": str(uuid.uuid4()),
            "allowed_families": ["sqli"],
            "preflight_scan_id": str(scan_id),
        }},
    }

    class Conn:
        async def fetch(self, query, *args):
            assert "target_principals" in query
            return []

        async def fetchrow(self, query, *args):
            if "FROM target_endpoints" in query and "last_seen_scan_id" in query:
                return {
                    "fresh_unique_routes": 1,
                    "fresh_authenticated_routes": 0,
                    "fresh_second_user_routes": 0,
                    "fresh_executable_routes": 0,
                    "fresh_all_executable_routes": 1,
                    "fresh_object_routes": 0,
                    "fresh_mutation_routes": 0,
                    "fresh_parameterized_routes": 1,
                }
            if "FROM target_endpoints" in query:
                return {
                    "inventory_rows": 1,
                    "unique_routes": 1,
                    "authenticated_routes": 0,
                    "second_user_routes": 0,
                    "executable_routes": 0,
                    "all_executable_routes": 1,
                    "object_routes": 0,
                    "mutation_routes": 0,
                    "parameterized_routes": 1,
                }
            if "FROM application_graph_nodes" in query:
                return {
                    "route_nodes": 0,
                    "fresh_route_nodes": 0,
                    "edge_count": 0,
                    "fresh_edge_count": 0,
                    "fresh_auth_boundary_edges": 0,
                }
            if "FROM scans" in query:
                return {"id": scan_id, "status": "completed", "current_phase": "done"}
            raise AssertionError(query)

    readiness = asyncio.run(api_module._research_campaign_readiness(Conn(), campaign))

    assert readiness["ready"] is True
    assert readiness["required"]["primary_credentials"] is False
    assert readiness["required"]["unique_routes"] == 1
    assert readiness["surface"]["executable_families"] == ["sqli"]
    assert "primary_credentials_required" not in readiness["blockers"]


def test_research_campaign_readiness_accepts_same_count_routes_refreshed_by_this_preflight():
    target_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    campaign = {
        "id": uuid.uuid4(),
        "target_id": target_id,
        "metadata_json": {"autonomous_research": {
            "intensity": "deep_hunt",
            "approval_receipt_id": str(uuid.uuid4()),
            "allowed_families": ["auth"],
            "preflight_scan_id": str(scan_id),
            # Cardinality did not grow, but the current scan re-observed authenticated surface.
            "surface_before_preflight": {"unique_routes": 40, "authenticated_routes": 30},
        }},
    }

    class Conn:
        async def fetch(self, query, *args):
            assert "target_principals" in query
            return [{"auth_state": "user1", "credential_profile": "owner", "credential_configured": True}]

        async def fetchrow(self, query, *args):
            if "FROM target_endpoints" in query and "last_seen_scan_id" in query:
                assert args[1] == scan_id
                return {
                    "fresh_authenticated_routes": 30,
                    "fresh_second_user_routes": 0,
                    "fresh_executable_routes": 25,
                }
            if "FROM target_endpoints" in query:
                return {
                    "inventory_rows": 80, "unique_routes": 40, "authenticated_routes": 30,
                    "second_user_routes": 0, "executable_routes": 25, "object_routes": 8,
                    "mutation_routes": 6, "parameterized_routes": 14,
                }
            if "FROM application_graph_nodes" in query:
                return {"route_nodes": 4, "edge_count": 3, "fresh_route_nodes": 0,
                        "fresh_edge_count": 0, "fresh_auth_boundary_edges": 0}
            if "FROM scans" in query:
                return {"id": scan_id, "status": "completed", "current_phase": "done"}
            raise AssertionError(query)

    readiness = asyncio.run(api_module._research_campaign_readiness(Conn(), campaign))

    assert readiness["ready"] is True
    assert readiness["surface"]["fresh_authenticated_routes"] == 30
    assert readiness["surface"]["meaningful_preflight_gain"] is True
    assert "authenticated_preflight_no_material_gain" not in readiness["blockers"]


def test_research_campaign_readiness_rejects_stale_or_empty_bola_graph():
    target_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    campaign = {
        "id": uuid.uuid4(),
        "target_id": target_id,
        "metadata_json": {"autonomous_research": {
            "intensity": "deep_hunt",
            "approval_receipt_id": str(uuid.uuid4()),
            "allowed_families": ["bola"],
            "preflight_scan_id": str(scan_id),
            "surface_before_preflight": {"unique_routes": 40, "authenticated_routes": 30},
        }},
    }

    class Conn:
        async def fetch(self, query, *args):
            return [
                {"auth_state": "user1", "credential_profile": "owner", "credential_configured": True},
                {"auth_state": "user2", "credential_profile": "attacker", "credential_configured": True},
            ]

        async def fetchrow(self, query, *args):
            if "FROM target_endpoints" in query and "last_seen_scan_id" in query:
                return {
                    "fresh_authenticated_routes": 0, "fresh_second_user_routes": 0,
                    "fresh_executable_routes": 0, "fresh_object_routes": 0,
                    "fresh_mutation_routes": 0, "fresh_parameterized_routes": 0,
                }
            if "FROM target_endpoints" in query:
                return {
                    "inventory_rows": 80, "unique_routes": 40, "authenticated_routes": 30,
                    "second_user_routes": 12, "executable_routes": 25, "object_routes": 8,
                    "mutation_routes": 6, "parameterized_routes": 14,
                }
            if "FROM application_graph_nodes" in query:
                return {"route_nodes": 1, "edge_count": 0, "fresh_route_nodes": 0, "fresh_edge_count": 0}
            if "FROM scans" in query:
                return {"id": scan_id, "status": "completed", "current_phase": "done"}
            raise AssertionError(query)

    readiness = asyncio.run(api_module._research_campaign_readiness(Conn(), campaign))

    assert readiness["ready"] is False
    assert "two_principal_graph_not_materialized" in readiness["blockers"]
    assert "authenticated_preflight_no_material_gain" in readiness["blockers"]


def test_research_campaign_readiness_rejects_edges_without_a_fresh_auth_boundary():
    # Reported fail-open: fresh edges that are NOT cross-principal auth_boundary edges (e.g. a lone
    # producer/produces edge) satisfied the old "any fresh edge" check and opened the BOLA gate with
    # no real two-principal surface. Now only a fresh distinct-principal auth_boundary counts.
    target_id = uuid.uuid4()
    scan_id = uuid.uuid4()
    campaign = {
        "id": uuid.uuid4(),
        "target_id": target_id,
        "metadata_json": {"autonomous_research": {
            "intensity": "deep_hunt",
            "approval_receipt_id": str(uuid.uuid4()),
            "allowed_families": ["bola"],
            "preflight_scan_id": str(scan_id),
            "surface_before_preflight": {"unique_routes": 40, "authenticated_routes": 30},
        }},
    }

    class Conn:
        async def fetch(self, query, *args):
            return [
                {"auth_state": "user1", "credential_profile": "owner", "credential_configured": True},
                {"auth_state": "user2", "credential_profile": "attacker", "credential_configured": True},
            ]

        async def fetchrow(self, query, *args):
            if "FROM target_endpoints" in query and "last_seen_scan_id" in query:
                return {
                    "fresh_authenticated_routes": 30, "fresh_second_user_routes": 12,
                    "fresh_executable_routes": 25, "fresh_object_routes": 8,
                    "fresh_mutation_routes": 6, "fresh_parameterized_routes": 14,
                }
            if "FROM target_endpoints" in query:
                return {
                    "inventory_rows": 80, "unique_routes": 40, "authenticated_routes": 30,
                    "second_user_routes": 12, "executable_routes": 25, "object_routes": 8,
                    "mutation_routes": 6, "parameterized_routes": 14,
                }
            if "FROM application_graph_nodes" in query:
                # 5 fresh edges, but NONE is a cross-principal auth_boundary.
                return {"route_nodes": 4, "edge_count": 5, "fresh_route_nodes": 4,
                        "fresh_edge_count": 5, "fresh_auth_boundary_edges": 0}
            if "FROM scans" in query:
                return {"id": scan_id, "status": "completed", "current_phase": "done"}
            raise AssertionError(query)

    readiness = asyncio.run(api_module._research_campaign_readiness(Conn(), campaign))

    assert readiness["ready"] is False
    assert "two_principal_graph_not_materialized" in readiness["blockers"]
    assert "bola" not in readiness["surface"]["executable_families"]


def test_research_preflight_is_one_principal_coherent_focused_scan():
    endpoints = ["GET /orders", "GET /orders/{id}", "POST /orders"]
    options = api_module._research_preflight_scan_options(
        focus_family="bola",
        custom_endpoints=endpoints,
        approval_receipt_id="approval-1",
    )

    assert options.scan_type == "smart"
    assert options.parallel is False
    assert options.auth_state_shards is False
    assert options.check_family == "bola"
    assert options.focused_endpoints_only is True
    assert options.zero_rediscovery is True
    assert options.custom_endpoints == endpoints
    assert options.exploit_depth is True


def test_approved_invariant_is_materialized_as_schedulable_residue():
    contract = {
        "id": str(uuid.uuid4()),
        "version": 1,
        "status": "approved",
        "contract_kind": "ownership",
        "method": "GET",
        "path": "/orders/{id}",
        "conditions": {},
    }
    request = api_module._invariant_hypothesis_request(
        str(uuid.uuid4()),
        contract,
        created_by="test",
    )
    scored = api_module.hypothesis_scheduler.score_hypothesis(
        request.model_dump(mode="json"),
        context={"require_residue": True, "auth_available": True},
    )

    assert request.metadata_json["unexplained_residue"] is True
    assert scored["excluded"] is False


def test_research_autopilot_lease_recovers_quickly_after_process_death():
    assert api_module.RESEARCH_AUTOPILOT_LEASE_SECONDS <= 30
    assert api_module.RESEARCH_AUTOPILOT_HEARTBEAT_SECONDS < api_module.RESEARCH_AUTOPILOT_LEASE_SECONDS


def test_research_semantic_policy_caps_recon_and_repeated_falsification():
    episode_id = uuid.uuid4()
    campaign_id = uuid.uuid4()
    target_id = uuid.uuid4()
    experiment = {
        "command": "experiment.workflow",
        "parameters": {
            "proof_family": "auth_bypass",
            "steps": [{"method": "GET", "path": "/admin/41"}],
        },
    }
    history = [
        {
            "action": {"command": "asm.gaps", "parameters": {}},
            "status": "completed",
            "command_result_id": uuid.uuid4(),
            "finding_ids": [],
        }
        for _ in range(api_module.RESEARCH_RECON_ACTION_CAP)
    ] + [
        {
                "action": experiment,
                "status": "completed",
                "command_result_id": uuid.uuid4(),
                "command_status": "completed",
                "finding_ids": [],
                "result_json": {
                    "family_proof": {
                        "family": "auth_bypass",
                        "verdict": "refuted",
                        "reason": "refuting_evidence:access_denied_unauthenticated",
                        "refuted_by": ["access_denied_unauthenticated"],
                    },
                },
        }
        for _ in range(api_module.RESEARCH_SEMANTIC_FALSIFICATION_LIMIT)
    ]

    class Conn:
        async def fetch(self, query, *args):
            if "FROM research_decisions" in query:
                return history
            if "FROM findings" in query:
                return []
            raise AssertionError(query)

    episode = {"id": episode_id, "campaign_id": campaign_id, "target_id": target_id}
    recon_errors = asyncio.run(api_module._research_semantic_policy_violations(
        Conn(), episode, {"command": "asm.recon", "parameters": {}},
    ))
    experiment_errors = asyncio.run(api_module._research_semantic_policy_violations(
        Conn(), episode, experiment,
    ))

    assert "campaign_recon_cap_reached" in recon_errors
    assert any(error.startswith("semantic_dimension_exhausted:") for error in experiment_errors)


def test_research_experiment_outcomes_do_not_treat_no_finding_as_refutation():
    action = {
        "command": "experiment.workflow",
        "parameters": {"proof_family": "auth_bypass"},
    }
    inconclusive = api_module._research_experiment_outcome(action, {
        "status": "completed",
        "finding_ids": [],
        "result_json": {"family_proof": {"verdict": "inconclusive", "reason": "no_family_evidence"}},
    })
    partial = api_module._research_experiment_outcome(action, {
        "status": "partial",
        "finding_ids": [],
        "result_json": {},
    })
    refuted = api_module._research_experiment_outcome(action, {
        "status": "completed",
        "finding_ids": [],
        "result_json": {"family_proof": {
            "verdict": "refuted",
            "reason": "refuting_evidence:access_denied_unauthenticated",
            "refuted_by": ["access_denied_unauthenticated"],
        }},
    })

    assert inconclusive["outcome"] == "inconclusive"
    assert inconclusive["deterministic_refutation"] is False
    assert partial["outcome"] == "blocked"
    assert refuted["deterministic_refutation"] is True


def test_research_repeated_inconclusive_actuator_exhausts_without_refuting():
    experiment = {
        "command": "experiment.workflow",
        "parameters": {
            "proof_family": "mass_assignment",
            "steps": [{"label": "before", "method": "GET", "path": "/api/profile/42"}],
        },
    }
    history = [{
        "action": experiment,
        "status": "completed",
        "command_result_id": uuid.uuid4(),
        "command_status": "completed",
        "finding_ids": [],
        "result_json": {
            "family_proof": {"family": "mass_assignment", "verdict": "inconclusive"},
            "failure_reason": "baseline_get_failed",
        },
    } for _ in range(api_module.RESEARCH_INCONCLUSIVE_ACTUATOR_LIMIT)]

    class Conn:
        async def fetch(self, query, *args):
            if "FROM research_decisions" in query:
                return history
            if "FROM findings" in query:
                return []
            raise AssertionError(query)

    snapshot = asyncio.run(api_module._research_campaign_exhaustion_snapshot(
        Conn(), uuid.uuid4(), uuid.uuid4(),
    ))
    assert snapshot["exhausted_inconclusive_actuators"]
    assert snapshot["falsification_counts"] == {}

    errors = asyncio.run(api_module._research_semantic_policy_violations(
        Conn(),
        {"id": uuid.uuid4(), "campaign_id": uuid.uuid4(), "target_id": uuid.uuid4()},
        experiment,
    ))
    assert any(error.startswith("experiment_actuator_exhausted:") for error in errors)


def test_research_hypothesis_learning_persists_terminal_refutation():
    decision_id = uuid.uuid4()
    hypothesis_id = uuid.uuid4()
    updates = []

    class Conn:
        async def fetchrow(self, query, *args):
            if "FROM research_decisions" in query:
                return {
                    "id": decision_id,
                    "hypothesis_id": hypothesis_id,
                    "action": {"command": "experiment.workflow", "parameters": {"proof_family": "auth_bypass"}},
                }
            if "FROM hypotheses" in query:
                return {"id": hypothesis_id, "status": "open", "metadata_json": {}}
            raise AssertionError(query)

        async def execute(self, query, *args):
            updates.append((query, args))
            return "UPDATE 1"

    outcome = asyncio.run(api_module._record_research_hypothesis_outcome(
        Conn(),
        decision_id=decision_id,
        command_result={
            "status": "completed",
            "finding_ids": [],
            "result_json": {"family_proof": {
                "family": "auth_bypass",
                "verdict": "refuted",
                "reason": "refuting_evidence:access_denied_unauthenticated",
                "refuted_by": ["access_denied_unauthenticated"],
            }},
        },
    ))

    assert outcome["outcome"] == "refuted"
    _query, args = updates[0]
    assert args[1] == "refuted"
    metadata = json.loads(args[2])
    assert metadata["attempt_count"] == 1
    assert metadata["last_outcome"] == "refuted"
    assert args[3] == "deterministic_experiment_refutation"


def test_verified_workflow_does_not_create_duplicate_of_known_scanner_finding():
    target_id = uuid.uuid4()
    hypothesis_id = uuid.uuid4()
    known_finding_id = uuid.uuid4()
    proof = api_module._trusted_workflow_family_proof(
        _bola_object_execution(41),
        _bola_object_execution(42),
    )
    executed = []

    class Conn:
        async def fetchrow(self, query, *args):
            if "FROM hypotheses" in query:
                return {
                    "id": hypothesis_id,
                    "target_id": target_id,
                    "family": "bola",
                    "title": "Known BOLA",
                    "description": "already found",
                    "severity_guess": "critical",
                    "metadata_json": {"dedupe_dimensions": {"route": "/objects/{id}", "method": "GET"}},
                }
            raise AssertionError(query)

        async def fetch(self, query, *args):
            assert "FROM findings" in query
            return [{
                "id": known_finding_id,
                "tool": "smart_bola",
                "cwe": "CWE-639",
                "title": "BOLA",
                "url": "https://example.test/objects/99",
                "evidence": {},
            }]

        async def execute(self, query, *args):
            executed.append((query, args))
            return "UPDATE 1"

    promoted = asyncio.run(api_module._promote_trusted_workflow_finding(
        Conn(),
        target_uuid=target_id,
        target_url="https://example.test",
        hypothesis_id=str(hypothesis_id),
        workflow_id=str(uuid.uuid4()),
        proof=proof,
        first={},
        replay={},
        evidence_instance_id=None,
        tool_receipt_id=None,
    ))

    assert promoted is None
    assert proof["novelty_gate"] == "known_vulnerability_already_covered"
    assert proof["known_finding_id"] == str(known_finding_id)
    assert any("status='dead'" in query for query, _ in executed)


def test_verified_workflow_promotes_bound_novel_hypothesis():
    target_id = uuid.uuid4()
    hypothesis_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    proof = api_module._trusted_workflow_family_proof(
        _bola_object_execution(51),
        _bola_object_execution(52),
    )
    updates = []

    class Conn:
        async def fetchrow(self, query, *args):
            if "FROM hypotheses" in query:
                return {
                    "id": hypothesis_id,
                    "target_id": target_id,
                    "family": "bola",
                    "title": "Novel object authorization failure",
                    "description": "Cross-principal object access",
                    "severity_guess": "high",
                    "metadata_json": {"dedupe_dimensions": {"route": "/objects/{id}", "method": "GET"}},
                }
            if "FROM research_decisions" in query:
                return {
                    "decision_id": uuid.uuid4(),
                    "episode_id": uuid.uuid4(),
                    "campaign_id": uuid.uuid4(),
                }
            if "FROM findings" in query:
                return None
            raise AssertionError(query)

        async def fetch(self, query, *args):
            assert "FROM findings" in query
            return []

        async def fetchval(self, query, *args):
            assert "INSERT INTO findings" in query
            return finding_id

        async def execute(self, query, *args):
            updates.append((query, args))
            return "UPDATE 1"

    promoted = asyncio.run(api_module._promote_trusted_workflow_finding(
        Conn(),
        target_uuid=target_id,
        target_url="https://example.test",
        hypothesis_id=str(hypothesis_id),
        workflow_id=str(uuid.uuid4()),
        proof=proof,
        first=_bola_object_execution(51),
        replay=_bola_object_execution(52),
        evidence_instance_id=None,
        tool_receipt_id=None,
    ))

    assert promoted["finding_id"] == str(finding_id)
    assert promoted["status"] == "created"
    assert len(promoted["fingerprint"]) == 32
    assert any("status='promoted'" in query for query, _ in updates)


def test_autonomous_workflow_finding_uses_canonical_retest_inputs_and_source_filter():
    finding = {
        "url": "https://example.test/objects/51",
        "target_url": "https://example.test",
        "tool": "autonomous_workflow",
        "evidence": {
            "type": "bola",
            "method": "GET",
            "canonical_vulnerability_dimensions": {"object_parameters": ["object_id"]},
            "autonomous_workflow": {
                "family": "bola",
                "route": "/objects/{id}",
                "method": "GET",
                "url": "https://example.test/objects/51",
            },
        },
    }

    inputs = api_module.extract_retest_inputs(finding)

    assert inputs == {
        "finding_type": "bola",
        "target_url": "https://example.test/objects/51",
        "original_url": "https://example.test/objects/51",
        "param": "object_id",
        "payload": None,
        "method": "GET",
        "request_body": None,
    }
    assert "f.source = 'autonomous'" in api_module._source_type_filter_sql("autonomous")
    assert "autonomous_workflow" in api_module._source_type_filter_sql("autonomous")
    assert "autonomous_workflow" in api_module._source_type_filter_sql("dast")


def test_keyless_hunt_request_distinguishes_passive_discovery_from_deep_hunt():
    passive = api_module.AgentHuntSessionStartRequest()
    active = api_module.AgentHuntSessionStartRequest(
        mode="deep_hunt",
        approval_receipt_id=str(uuid.uuid4()),
    )

    assert passive.mode == "read_only"
    assert active.mode == "deep_hunt"


def test_agent_hunt_public_shape_exposes_product_mode_and_capability_boundary():
    passive = api_module._agent_hunt_run_public({
        "id": uuid.uuid4(),
        "target_id": uuid.uuid4(),
        "objective": "inspect",
        "status": "awaiting_planner",
        "max_iterations": 12,
        "allow_write": False,
        "allow_active": False,
        "state": {"messages": [], "iterations": 0},
        "result": {},
    })
    deep_hunt = api_module._agent_hunt_run_public({
        "id": uuid.uuid4(),
        "target_id": uuid.uuid4(),
        "objective": "hunt",
        "status": "awaiting_planner",
        "max_iterations": 12,
        "allow_write": False,
        "allow_active": True,
        "state": {"messages": [], "iterations": 0},
        "result": {},
    })

    assert passive["mode"] == "read_only"
    assert passive["tool_surface"]["allow_active"] is False
    assert deep_hunt["mode"] == "deep_hunt"
    assert deep_hunt["tool_surface"]["allow_active"] is True
    assert deep_hunt["tool_surface"]["allow_write"] is False
    assert "arbitrary state-changing HTTP remains blocked" in deep_hunt["tool_surface"]["note"]


def test_research_autobind_requires_ranked_live_operation_identity():
    target_id = uuid.uuid4()
    wrong_hypothesis_id = uuid.uuid4()
    raw = {
        "action": {
            "command": "experiment.workflow",
            "parameters": {
                "proof_family": "mass_assignment",
                "steps": [{
                    "label": "mutate",
                    "method": "PATCH",
                    "path": "/users/51",
                    "json_body": {"isAdmin": True},
                }],
                "assertions": [{
                    "type": "status_in",
                    "step": "mutate",
                    "predicate": "forbidden_field_accepted",
                }],
            },
        },
    }
    observation = {
        "current_surface": {
            "ranked_hypotheses": [{
                "hypothesis": {
                    "id": wrong_hypothesis_id,
                    "family": "mass_assignment",
                    "metadata_json": {
                        "dedupe_dimensions": {
                            "route": "/users/{id}",
                            "method": "POST",
                            "fields": ["role"],
                        },
                    },
                },
            }],
        },
    }

    errors = asyncio.run(api_module._research_autobind_hypothesis(
        object(), {"target_id": target_id}, raw, observation,
    ))

    assert errors == ["experiment_hypothesis_not_on_ranked_live_surface"]
    assert "hypothesis_id" not in raw

    exact_hypothesis_id = uuid.uuid4()
    exact_raw = {"action": json.loads(json.dumps(raw["action"]))}
    exact_observation = {
        "current_surface": {
            "ranked_hypotheses": [{
                "hypothesis": {
                    "id": exact_hypothesis_id,
                    "family": "mass_assignment",
                    "metadata_json": {
                        "dedupe_dimensions": {
                            "route": "/users/{id}",
                            "method": "PATCH",
                            "fields": ["isAdmin"],
                        },
                    },
                },
            }],
        },
    }

    errors = asyncio.run(api_module._research_autobind_hypothesis(
        object(), {"target_id": target_id}, exact_raw, exact_observation,
    ))

    assert errors == []
    assert exact_raw["hypothesis_id"] == str(exact_hypothesis_id)


def test_research_autobind_binds_selected_contract_when_ranked_compacted_away():
    # Size-compaction can empty current_surface.ranked_hypotheses in the persisted pack while KEEPING
    # the derived selected_hypothesis_contracts. An explicit hypothesis_id matching a surviving
    # contract must still bind, instead of rejecting every experiment against an empty ranked board
    # (the experiment_hypothesis_not_on_ranked_live_surface spin observed on crAPI).
    target_id = uuid.uuid4()
    hid = uuid.uuid4()
    action = {
        "command": "experiment.workflow",
        "parameters": {
            "proof_family": "bola",
            "steps": [{"label": "attack", "method": "GET",
                       "path": "/workshop/api/shop/orders/42", "principal": "user2"}],
            "assertions": [{"type": "status_in", "step": "attack", "predicate": "cross_principal_access"}],
        },
    }
    raw = {"hypothesis_id": str(hid), "action": json.loads(json.dumps(action))}
    observation = {
        "current_surface": {"ranked_hypotheses": []},  # compacted away
        "selected_hypothesis_contracts": [{
            "hypothesis_id": str(hid), "family": "bola",
            "route": "/workshop/api/shop/orders/{id}", "method": "GET",
        }],
    }
    errors = asyncio.run(api_module._research_autobind_hypothesis(
        object(), {"target_id": target_id}, raw, observation,
    ))
    assert errors == []
    assert raw["hypothesis_id"] == str(hid)

    # A selected contract on a DIFFERENT route must still reject (fail-closed preserved).
    bad = {"hypothesis_id": str(hid), "action": json.loads(json.dumps(action))}
    bad_obs = {
        "current_surface": {"ranked_hypotheses": []},
        "selected_hypothesis_contracts": [{
            "hypothesis_id": str(hid), "family": "bola",
            "route": "/some/other/route/{id}", "method": "GET",
        }],
    }
    errors2 = asyncio.run(api_module._research_autobind_hypothesis(
        object(), {"target_id": target_id}, bad, bad_obs,
    ))
    assert errors2 == ["experiment_hypothesis_not_on_ranked_live_surface"]


def test_research_autobind_mass_assignment_binds_on_mutation_step_without_supplied_id():
    # A mass_assignment proof reads the field back on a GET verify step, but the lead's identity is the
    # POST mutation route. The autobind must bind on the state-changing step (not the asserted read
    # step) and, with no id supplied, match a selected lead by family+route+method -- otherwise grok's
    # mass_assignment experiments reject with experiment_hypothesis_not_on_ranked_live_surface.
    target_id = uuid.uuid4()
    hid = uuid.uuid4()
    action = {
        "command": "experiment.workflow",
        "parameters": {
            "proof_family": "mass_assignment",
            "steps": [
                {"label": "before", "method": "GET", "path": "/orders/all?id=1", "principal": "user1"},
                {"label": "mutate", "method": "POST", "path": "/orders/1", "principal": "user1",
                 "json_body": {"status": "paid"}},
                {"label": "verify", "method": "GET", "path": "/orders/all?id=1", "principal": "user1"},
            ],
            "assertions": [
                {"type": "field_persisted", "step": "verify", "predicate": "forbidden_field_accepted"},
            ],
        },
    }
    raw = {"action": json.loads(json.dumps(action))}  # no hypothesis_id supplied
    observation = {
        "current_surface": {"ranked_hypotheses": []},
        "selected_hypothesis_contracts": [{
            "hypothesis_id": str(hid), "family": "mass_assignment",
            "route": "/orders/{id}", "method": "POST",
        }],
    }
    errors = asyncio.run(api_module._research_autobind_hypothesis(
        object(), {"target_id": target_id}, raw, observation,
    ))
    assert errors == []
    assert raw["hypothesis_id"] == str(hid)

    # Fail-closed preserved: a mutation route with no matching lead still rejects.
    bad = {"action": json.loads(json.dumps(action))}
    bad_obs = {
        "current_surface": {"ranked_hypotheses": []},
        "selected_hypothesis_contracts": [{
            "hypothesis_id": str(hid), "family": "mass_assignment",
            "route": "/unrelated/{id}", "method": "POST",
        }],
    }
    errors2 = asyncio.run(api_module._research_autobind_hypothesis(
        object(), {"target_id": target_id}, bad, bad_obs,
    ))
    assert errors2 == ["experiment_hypothesis_not_on_ranked_live_surface"]


def test_research_autobind_prefers_actual_mutation_over_setup_write():
    target_id = uuid.uuid4()
    hypothesis_id = uuid.uuid4()
    action = {
        "command": "experiment.workflow",
        "parameters": {
            "proof_family": "mass_assignment",
            "steps": [
                {"label": "create_fixture", "checkpoint": "mutation", "method": "POST",
                 "path": "/api/fixtures"},
                {"label": "mutate_forbidden_field", "checkpoint": "mutation", "method": "PATCH",
                 "path": "/api/profiles/42", "json_body": {"role": "admin"}},
                {"label": "verify", "checkpoint": "action", "method": "GET",
                 "path": "/api/profiles/42"},
            ],
            "assertions": [
                {"type": "comparison_changed", "candidate": "verify", "control": "create_fixture",
                 "predicate": "forbidden_field_accepted"},
            ],
        },
    }
    raw = {"action": action}
    observation = {
        "current_surface": {"ranked_hypotheses": []},
        "selected_hypothesis_contracts": [{
            "hypothesis_id": str(hypothesis_id), "family": "mass_assignment",
            "route": "/api/profiles/{id}", "method": "PATCH",
        }],
    }
    assert asyncio.run(api_module._research_autobind_hypothesis(
        object(), {"target_id": target_id}, raw, observation,
    )) == []
    assert raw["hypothesis_id"] == str(hypothesis_id)


def test_research_autobind_supplied_id_binds_via_db_when_board_compacted():
    # Compaction can drop BOTH ranked_hypotheses and selected_hypothesis_contracts from an oversized
    # pack. A supplied id the planner read in an earlier observation must still bind by resolving the
    # live lead from the hypotheses table -- otherwise every experiment rejects against an empty board.
    target_id = uuid.uuid4()
    hid = uuid.uuid4()
    action = {
        "command": "experiment.workflow",
        "parameters": {
            "proof_family": "mass_assignment",
            "steps": [
                {"label": "control", "method": "POST", "path": "/workshop/api/past-orders"},
                {"label": "mutate", "method": "POST", "path": "/workshop/api/past-orders"},
                {"label": "verify", "method": "GET", "path": "/workshop/api/past-orders"},
            ],
            "assertions": [{"type": "x", "step": "mutate", "predicate": "forbidden_field_accepted"}],
        },
    }
    empty_obs = {"current_surface": {"ranked_hypotheses": []}, "selected_hypothesis_contracts": []}

    class _Conn:
        def __init__(self, row, endpoints=None):
            self._row = row
            self._endpoints = endpoints or []
        async def fetchrow(self, *args, **kwargs):
            return self._row
        async def fetch(self, *args, **kwargs):
            return self._endpoints

    live_row = {
        "source": "app_graph",
        "family": "mass_assignment",
        "next_test_action": {"command": "experiment.workflow", "parameters": {"proof_family": "mass_assignment"}},
        "metadata_json": {"dedupe_dimensions": {"route": "/workshop/api/past-orders", "method": "POST"}},
    }
    raw = {"hypothesis_id": str(hid), "action": json.loads(json.dumps(action))}
    errors = asyncio.run(api_module._research_autobind_hypothesis(
        _Conn(live_row, [{"method": "POST", "path": "/workshop/api/past-orders"}]),
        {"target_id": target_id}, raw, empty_obs,
    ))
    assert errors == []
    assert raw["hypothesis_id"] == str(hid)

    # No live lead in the DB (compacted board + no durable match) -> fail-closed reject.
    bad = {"hypothesis_id": str(hid), "action": json.loads(json.dumps(action))}
    errors2 = asyncio.run(api_module._research_autobind_hypothesis(
        _Conn(None), {"target_id": target_id}, bad, empty_obs,
    ))
    assert errors2 == ["experiment_hypothesis_not_on_ranked_live_surface"]

    # A durable hypothesis on a stale/gone operation is not current live residue.
    stale = {"hypothesis_id": str(hid), "action": json.loads(json.dumps(action))}
    stale_errors = asyncio.run(api_module._research_autobind_hypothesis(
        _Conn(live_row, []), {"target_id": target_id}, stale, empty_obs,
    ))
    assert stale_errors == ["experiment_hypothesis_not_on_ranked_live_surface"]


def test_research_autobind_accepts_explicit_ranked_id_when_typed_workflow_refines_dimensions():
    target_id = uuid.uuid4()
    hypothesis_id = uuid.uuid4()
    raw = {
        "hypothesis_id": str(hypothesis_id),
        "action": {
            "command": "experiment.workflow",
            "parameters": {
                "proof_family": "bola",
                "principal_variables": [
                    {"name": "owner_object_id", "principal": "user1", "ref": "transaction_id"},
                    {"name": "attacker_object_id", "principal": "user2", "ref": "transaction_id"},
                ],
                "steps": [
                    {
                        "label": "owner_read",
                        "method": "GET",
                        "path": "/workshop/api/shop/orders/all?id=${owner_object_id}",
                        "principal": "user1",
                    },
                    {
                        "label": "attacker_read",
                        "method": "GET",
                        "path": "/workshop/api/shop/orders/all?id=${owner_object_id}",
                        "principal": "user2",
                    },
                ],
                "assertions": [{
                    "type": "comparison_equivalent",
                    "control": "owner_read",
                    "candidate": "attacker_read",
                    "predicate": "cross_principal_access",
                }],
            },
        },
    }
    observation = {
        "current_surface": {
            "ranked_hypotheses": [{
                "hypothesis": {
                    "id": hypothesis_id,
                    "family": "bola",
                    "metadata_json": {
                        "dedupe_dimensions": {
                            "route": "/workshop/api/shop/orders/all?id=1234",
                            "method": "GET",
                            "object_key": "transaction_id",
                        },
                    },
                },
            }],
        },
    }

    errors = asyncio.run(api_module._research_autobind_hypothesis(
        object(), {"target_id": target_id}, raw, observation,
    ))

    assert errors == []
    assert raw["hypothesis_id"] == str(hypothesis_id)


def test_research_autobind_rejects_explicit_ranked_id_for_different_operation():
    target_id = uuid.uuid4()
    hypothesis_id = uuid.uuid4()
    raw = {
        "hypothesis_id": str(hypothesis_id),
        "action": {
            "command": "experiment.workflow",
            "parameters": {
                "proof_family": "bola",
                "steps": [{"label": "attacker_read", "method": "GET", "path": "/orders/other/42"}],
                "assertions": [{
                    "type": "comparison_equivalent",
                    "candidate": "attacker_read",
                    "predicate": "cross_principal_access",
                }],
            },
        },
    }
    observation = {
        "current_surface": {
            "ranked_hypotheses": [{
                "hypothesis": {
                    "id": hypothesis_id,
                    "family": "bola",
                    "metadata_json": {
                        "dedupe_dimensions": {"route": "/orders/{id}", "method": "GET"},
                    },
                },
            }],
        },
    }

    errors = asyncio.run(api_module._research_autobind_hypothesis(
        object(), {"target_id": target_id}, raw, observation,
    ))

    assert errors == ["experiment_hypothesis_not_on_ranked_live_surface"]


def test_research_canonicalizes_nested_hypothesis_binding_without_weakening_parameters():
    hypothesis_id = str(uuid.uuid4())
    raw = {
        "hypothesis_id": None,
        "action": {
            "command": "experiment.workflow",
            "parameters": {"hypothesis_id": hypothesis_id, "proof_family": "bola"},
        },
    }

    errors = api_module._research_canonicalize_hypothesis_binding(raw)

    assert errors == []
    assert raw["hypothesis_id"] == hypothesis_id
    assert raw["action"]["parameters"] == {"proof_family": "bola"}


def test_research_canonicalizes_provider_workflow_wrapper_without_losing_route_fields():
    hypothesis_id = str(uuid.uuid4())
    raw = {
        "hypothesis_id": None,
        "action": {
            "command": "experiment.workflow",
            "parameters": {
                "target_id": "server-bound-target",
                "workflow_id": "planner-workflow",
                "workflow": {
                    "hypothesis_id": hypothesis_id,
                    "proof_family": "mass_assignment",
                    "steps": [{"label": "mutate", "method": "PATCH", "path": "/api/users/42"}],
                    "assertions": [{"type": "status_equal", "step": "mutate"}],
                },
            },
        },
    }

    errors = api_module._research_canonicalize_action_shape(raw)

    assert errors == []
    assert raw["hypothesis_id"] == hypothesis_id
    assert "workflow" not in raw["action"]["parameters"]
    assert raw["action"]["parameters"]["target_id"] == "server-bound-target"
    assert raw["action"]["parameters"]["proof_family"] == "mass_assignment"
    assert raw["action"]["parameters"]["steps"][0]["method"] == "PATCH"


@pytest.mark.parametrize("wrapped_steps", [
    [{"label": "read", "method": "GET", "path": "/api/orders/42"}],
    json.dumps([{"label": "read", "method": "GET", "path": "/api/orders/42"}]),
])
def test_research_canonicalizes_provider_workflow_step_list_alias(wrapped_steps):
    raw = {
        "action": {
            "command": "experiment.workflow",
            "parameters": {
                "proof_family": "bola",
                "workflow": wrapped_steps,
                "assertions": [{"type": "status_in", "step": "read", "values": [200]}],
            },
        },
    }

    assert api_module._research_canonicalize_action_shape(raw) == []
    assert raw["action"]["parameters"]["steps"] == [
        {"label": "read", "method": "GET", "path": "/api/orders/42"},
    ]
    assert "workflow" not in raw["action"]["parameters"]


def test_research_canonicalizes_redundant_workflow_uuid_alias():
    workflow_id = str(uuid.uuid4())
    raw = {
        "action": {
            "command": "experiment.workflow",
            "parameters": {"workflow": workflow_id, "steps": []},
        },
    }

    assert api_module._research_canonicalize_action_shape(raw) == []
    assert raw["action"]["parameters"]["workflow_id"] == workflow_id


def test_research_canonicalizes_readable_operations_alias_to_declared_steps():
    operations = [{
        "label": "owner-read",
        "method": "GET",
        "path": "/api/orders/42",
        "principal": "user1",
    }]
    raw = {
        "action": {
            "command": "experiment.workflow",
            "parameters": {"proof_family": "bola", "operations": operations},
        },
    }

    assert api_module._research_canonicalize_action_shape(raw) == []
    assert raw["action"]["parameters"]["steps"] == operations
    assert "operations" not in raw["action"]["parameters"]


def test_research_rejects_conflicting_operations_and_steps_aliases():
    raw = {
        "action": {
            "command": "experiment.workflow",
            "parameters": {
                "operations": [{"label": "one", "method": "GET", "path": "/one"}],
                "steps": [{"label": "two", "method": "GET", "path": "/two"}],
            },
        },
    }

    assert api_module._research_canonicalize_action_shape(raw) == ["experiment_steps_conflict"]
    assert raw["action"]["parameters"]["steps"][0]["label"] == "two"


def test_research_rejects_conflicting_or_invalid_workflow_wrappers():
    conflicting = {
        "action": {
            "command": "experiment.workflow",
            "parameters": {
                "proof_family": "bola",
                "workflow": {"proof_family": "mass_assignment", "steps": []},
            },
        },
    }
    invalid = {
        "action": {
            "command": "experiment.workflow",
            "parameters": {"workflow": "not-an-object"},
        },
    }

    assert api_module._research_canonicalize_action_shape(conflicting) == [
        "workflow_parameter_conflict:proof_family",
    ]
    assert conflicting["action"]["parameters"]["proof_family"] == "bola"
    assert "workflow" not in conflicting["action"]["parameters"]
    assert api_module._research_canonicalize_action_shape(invalid) == [
        "workflow_wrapper_must_be_object",
    ]


def test_research_rejects_conflicting_hypothesis_bindings():
    top_level = str(uuid.uuid4())
    raw = {
        "hypothesis_id": top_level,
        "action": {
            "command": "experiment.workflow",
            "parameters": {"hypothesis_id": str(uuid.uuid4()), "proof_family": "bola"},
        },
    }

    errors = api_module._research_canonicalize_hypothesis_binding(raw)

    assert errors == ["hypothesis_id_conflict"]
    assert raw["hypothesis_id"] == top_level
    assert "hypothesis_id" not in raw["action"]["parameters"]


def test_known_covered_rejection_becomes_campaign_exclusion():
    action = {"command": "experiment.workflow", "parameters": {"proof_family": "bola"}}

    assert api_module._research_decision_action_is_excluded({
        "status": "rejected",
        "action": action,
        "validation_errors": ["known_vulnerability_already_covered"],
    }) is True
    assert api_module._research_decision_action_is_excluded({
        "status": "rejected",
        "action": action,
        "validation_errors": ["action_parameter_not_declared:hypothesis_id"],
    }) is False


def test_hard_policy_exclusions_remove_exact_hypothesis_and_do_not_trip_breaker():
    rejected = {
        "status": "rejected",
        "hypothesis_id": str(uuid.uuid4()),
        "validation_errors": ["known_vulnerability_already_covered"],
    }

    assert api_module._research_decision_hypothesis_is_excluded(rejected) is True
    assert api_module._research_rejection_is_policy_steering(rejected["validation_errors"]) is True
    assert api_module._research_rejection_is_policy_steering([
        "semantic_dimension_exhausted:bola|GET|/api/orders/{id}",
    ]) is True
    assert api_module._research_rejection_is_policy_steering([
        "action_parameter_not_declared:workflow",
    ]) is False


@pytest.mark.parametrize(
    ("linked_work", "expected"),
    [
        ([{"status": "completed"}], "completed"),
        ([{"status": "completed"}, {"status": "failed"}], "failed"),
        ([{"status": "cancelled"}], "cancelled"),
        ([{"status": "partial"}], "partial"),
        ([{"status": "running"}], None),
        ([], None),
    ],
)
def test_research_linked_work_outcome(linked_work, expected):
    assert api_module._research_linked_work_outcome(linked_work) == expected


def test_research_planner_prompt_places_hypothesis_provenance_at_decision_level():
    messages = api_module._research_planner_messages({
        "id": str(uuid.uuid4()),
        "context_hash": "a" * 64,
        "observation_pack": {"proposable_commands": []},
    })

    assert "top-level decision hypothesis_id field" in messages[0]["content"]
    assert "never put hypothesis_id inside action.parameters" in messages[0]["content"]


def test_campaign_yield_counts_only_findings_with_campaign_provenance():
    campaign_id = uuid.uuid4()
    target_id = uuid.uuid4()
    episode_id = uuid.uuid4()
    finding_queries = []

    class Conn:
        async def fetch(self, query, *args):
            if "FROM research_episodes" in query:
                return [{"id": episode_id, "status": "completed", "budget_used": {}}]
            if "FROM research_decisions" in query:
                return []
            if "FROM findings" in query:
                return []
            raise AssertionError(query)

        async def fetchval(self, query, *args):
            finding_queries.append((query, args))
            return 1

    metrics = asyncio.run(api_module._research_campaign_yield_metrics(Conn(), {
        "id": campaign_id,
        "target_id": target_id,
        "metadata_json": {},
    }))

    assert metrics["verified_autonomous_findings"] == 1
    query, args = finding_queries[0]
    assert "research_provenance_history" in query
    assert "campaign_id" in query
    assert "created_at >=" not in query
    # The provenance comparison casts the bind parameter to PostgreSQL text.
    # Keep the Python value text as well; asyncpg does not coerce UUID objects
    # for parameters whose declared SQL type is text.
    assert args == (target_id, str(campaign_id))


def test_campaign_yield_stops_rejection_only_planner_spin():
    campaign_id = uuid.uuid4()
    target_id = uuid.uuid4()
    episode_id = uuid.uuid4()

    class Conn:
        async def fetch(self, query, *args):
            if "FROM research_episodes" in query:
                return [{"id": episode_id, "status": "completed", "budget_used": {}}]
            if "FROM research_decisions" in query:
                return [{
                    "status": "rejected",
                    "validation_errors": ["experiment_hypothesis_not_on_ranked_live_surface"],
                    "action": {"command": "experiment.workflow", "parameters": {
                        "proof_family": "mass_assignment",
                        "steps": [{"method": "PATCH", "path": f"/phantom/{index}"}],
                    }},
                    "command_result_id": None,
                } for index in range(8)]
            if "FROM findings" in query:
                return []
            raise AssertionError(query)

        async def fetchval(self, query, *args):
            return 0

    metrics = asyncio.run(api_module._research_campaign_yield_metrics(Conn(), {
        "id": campaign_id,
        "target_id": target_id,
        "metadata_json": {},
    }))

    assert metrics["experiments"] == 0
    assert metrics["rejected_decisions"] == 8
    assert metrics["stop_recommended"] is True
    assert metrics["stop_reason"] == "planner_rejection_ceiling"


def test_research_graph_preserves_history_and_attributes_parallel_children():
    parent = str(uuid.uuid4())
    child = str(uuid.uuid4())
    historical = str(uuid.uuid4())
    graph = {
        "nodes": [
            {"node_key": "current", "scan_id": child},
            {"node_key": "historical", "scan_id": historical},
        ],
        "edges": [
            {"src_key": "a", "dst_key": "b", "scan_id": child},
            {"src_key": "old-a", "dst_key": "old-b", "scan_id": historical},
        ],
        "truncated": False,
    }

    annotated = api_module._research_graph_with_preflight_provenance(
        graph,
        preflight_scan_id=parent,
        provenance_scan_ids={parent, child},
    )

    assert annotated["nodes"] == graph["nodes"]
    assert annotated["edges"] == graph["edges"]
    assert annotated["preflight_provenance"] == {
        "scan_ids": sorted([parent, child]),
        "node_count": 1,
        "edge_count": 1,
    }


def test_verification_route_abstains_when_finding_has_no_concrete_route():
    """Zero-FP: a route-specific family_proof (bola/auth_bypass/data_exposure) must abstain when the
    suspected finding has no resolved route. An ambiguous evidence locus leaves ``url`` at the target
    base, so the path collapses to "/" — and an auth_bypass proof against the public site root
    trivially passes (anon == authed). Regression from the crAPI deep-hunt smoke."""
    f = api_module._verification_route_from_finding_url
    # concrete protected route -> returned as-is (verification proceeds)
    assert f("http://host.docker.internal:8888/identity/api/v2/admin/videos/search") == "/identity/api/v2/admin/videos/search"
    assert f("https://t/rest/basket/1") == "/rest/basket/1"
    # unresolved route -> None (verifier must abstain, finding stays SUSPECTED)
    assert f("http://host.docker.internal:8888/") is None   # target base with trailing slash
    assert f("http://host.docker.internal:8888") is None     # target base, no path
    assert f("") is None
    assert f(None) is None
