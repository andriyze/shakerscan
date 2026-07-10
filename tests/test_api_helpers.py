"""Unit tests for small helpers in api/api.py.

These cover the env-var coercer, the pagination → COUNT(*) rewriter, and the
JSON-decode helper that have grown enough surface to be worth pinning.
"""

import asyncio
import base64
import io
import json
import os
import sys
import types
import uuid
import zipfile
from datetime import datetime, timedelta, timezone

import pytest


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
    assert by_id["policy-exception-hygiene"]["href"] == "/settings/exceptions"
    assert by_id["policy-exception-hygiene"]["actions"][0]["href"] == "/settings/exceptions?queue_filter=expired"
    assert by_id["asm-coverage-gaps"]["href"] == "/asm?target_id=11111111-1111-4111-8111-111111111111"
    assert by_id["asm-coverage-gaps"]["actions"][0]["label"] == "Improve coverage"
    assert by_id["next-asm-schedule"]["priority"] == "info"
    assert by_id["recent-failed-scans"]["actions"][1]["label"] == "Latest failed scan"
    assert by_id["model-intake-untrusted-signatures"]["samples"][0]["detail"] == "signature status: untrusted_root"
    assert by_id["model-intake-untrusted-signatures"]["actions"][0]["href"] == "/settings/model-intake?remediate=trust"
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
    assert ai_item["href"] == "/settings/ai-gate?remediate=controls"
    assert ai_item["actions"][0]["href"] == "/settings/ai-gate?remediate=controls"
    assert ai_item["actions"][1]["href"] == "/findings?source_type=ai&status=active"
    assert ai_item["samples"][0]["href"] == "/settings/ai-gate?remediate=controls"
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
    assert by_id["ai_gate"]["href"] == "/settings/ai-gate?remediate=controls"
    assert by_id["ai_gate"]["actions"][0]["href"] == "/settings/ai-gate?remediate=controls"
    assert by_id["ai_gate"]["actions"][1]["href"] == "/findings?source_type=ai&status=active"
    assert by_id["model_intake"]["status"] == "critical"
    assert by_id["model_intake"]["href"] == "/settings/model-intake?remediate=trust"
    assert by_id["model_intake"]["actions"][0]["label"] == "Fix trust"
    assert by_id["model_intake"]["actions"][1]["href"] == "/findings?source_type=model_intake&status=active"
    assert by_id["exceptions"]["href"] == "/settings/exceptions?queue_filter=expired"
    assert by_id["exceptions"]["actions"][1]["href"] == "/settings/exceptions?queue_filter=expiring"
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
    assert by_id["exceptions"]["actions"][0]["href"] == "/settings/exceptions?queue_filter=missing_controls"


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
    assert api_module._normalize_schedule_kind("evidence_retention_sweep", {}) == "evidence_retention_sweep"
    assert api_module._normalize_schedule_kind(None, {"kind": "asm_improve"}) == "asm_improve"

    with pytest.raises(ValueError):
        api_module._normalize_schedule_kind("normal_scan", {"kind": "asm_improve"})

    with pytest.raises(ValueError):
        api_module._normalize_schedule_kind("bad_kind", {})


def test_scheduled_retention_sweep_request_defaults_to_dry_run_and_requires_approval_for_execute():
    req = api_module._scheduled_retention_sweep_request({
        "retention_class": "short",
        "older_than_days": 90,
        "limit": 10,
    })
    assert req.dry_run is True
    assert req.retention_class == "short"
    assert req.older_than_days == 90
    assert req.limit == 10

    with pytest.raises(ValueError):
        api_module._scheduled_retention_sweep_request({"dry_run": False})


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


def test_run_due_schedules_runs_retention_sweep_schedule(monkeypatch):
    schedule = _due_schedule()
    schedule["schedule_kind"] = "evidence_retention_sweep"
    schedule["scan_options"] = {
        "retention_class": "short",
        "older_than_days": 90,
        "limit": 10,
    }
    conn = _FakeConn([schedule])
    redis_client = _RecordingRedis()
    sentinel_pool = object()
    monkeypatch.setattr(api_module, "db_pool", sentinel_pool)
    monkeypatch.setattr(api_module, "get_redis", lambda: redis_client)

    asyncio.run(api_module.run_due_schedules(_FakePool(conn)))

    executed_sql = "\n".join(query for query, _args in conn.executes)
    assert "INSERT INTO scans" not in executed_sql
    assert "UPDATE schedules SET last_run_at" in executed_sql
    assert redis_client.rpush_calls == []
    assert redis_client.hset_calls == []
    assert api_module.db_pool is sentinel_pool


def test_run_due_schedules_retries_invalid_retention_sweep_schedule(monkeypatch):
    schedule = _due_schedule()
    schedule["schedule_kind"] = "evidence_retention_sweep"
    schedule["scan_options"] = {"dry_run": False}
    conn = _FakeConn([schedule])
    redis_client = _RecordingRedis()
    monkeypatch.setattr(api_module, "get_redis", lambda: redis_client)

    asyncio.run(api_module.run_due_schedules(_FakePool(conn)))

    executed_sql = "\n".join(query for query, _args in conn.executes)
    assert "INSERT INTO scans" not in executed_sql
    assert "UPDATE schedules SET next_run_at" in executed_sql
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

    assert len(requests) == 1
    req = requests[0]
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


class _SweepConn:
    """Fake conn for the retention-sweep endpoint: durable policy read, blocked
    command_results INSERT capture, and empty evidence/finding fetches."""

    def __init__(self, *, policy_on=False):
        self.policy_on = policy_on
        self.recorded = []

    async def fetchval(self, query, *args):
        if "FROM app_settings" in query:
            return "true" if self.policy_on else None
        return None

    async def fetchrow(self, query, *args):
        if "command_results" in query:
            self.recorded.append({"command": args[0], "status": args[1]})
            return {"id": "cmd-x", "command": args[0], "status": args[1], "created_at": None}
        return None

    async def fetch(self, query, *args):
        return []


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


def test_retention_sweep_execute_requires_approval_when_policy_on(monkeypatch):
    conn = _SweepConn(policy_on=True)
    monkeypatch.setattr(api_module, "db_pool", _pool_for(conn))
    req = api_module.EvidenceRetentionSweepRequest(dry_run=False)

    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(api_module.evidence_retention_sweep(req))

    assert exc.value.status_code == 409
    assert conn.recorded and conn.recorded[0]["command"] == "evidence.retention_sweep"
    assert conn.recorded[0]["status"] == "approval_required"


def test_retention_sweep_dry_run_preview_needs_no_approval(monkeypatch):
    conn = _SweepConn(policy_on=True)
    monkeypatch.setattr(api_module, "db_pool", _pool_for(conn))
    req = api_module.EvidenceRetentionSweepRequest(dry_run=True)

    result = asyncio.run(api_module.evidence_retention_sweep(req))

    assert result["dry_run"] is True
    assert result["execution_enabled"] is False
    assert conn.recorded == []  # preview records nothing and requires no receipt


def test_retention_sweep_dry_run_reports_remote_objects_as_preserved(monkeypatch):
    old = datetime(2025, 1, 1, tzinfo=timezone.utc)
    remote_id = uuid.uuid4()

    class _RemoteSweepConn(_SweepConn):
        async def fetch(self, query, *args):
            return [
                {
                    "id": remote_id,
                    "scan_id": None,
                    "finding_id": None,
                    "object_type": "finding_evidence",
                    "content_sha256": "a" * 64,
                    "size_bytes": 4096,
                    "retention_class": "short",
                    "storage_uri": "s3:evidence_objects/audit-bucket/evidence-objects/aa/" + ("a" * 64) + ".json",
                    "created_at": old,
                }
            ]

    conn = _RemoteSweepConn(policy_on=False)
    monkeypatch.setattr(api_module, "db_pool", _pool_for(conn))

    result = asyncio.run(api_module.evidence_retention_sweep(api_module.EvidenceRetentionSweepRequest(dry_run=True)))

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
    assert result["candidates"][0]["id"] == str(remote_id)
    assert result["candidates"][0]["storage_backend"] == "s3"
    assert result["candidates"][0]["remote_object"] is True


def test_retention_sweep_executes_remote_delete_before_db_delete(monkeypatch):
    old = datetime(2025, 1, 1, tzinfo=timezone.utc)
    remote_id = uuid.uuid4()
    rows = [
        {
            "id": remote_id,
            "scan_id": None,
            "finding_id": None,
            "object_type": "finding_evidence",
            "content_sha256": "a" * 64,
            "size_bytes": 4096,
            "retention_class": "short",
            "storage_uri": "s3:evidence_objects/audit-bucket/evidence-objects/aa/" + ("a" * 64) + ".json",
            "created_at": old,
        }
    ]

    class _RemoteDeleteSweepConn(_SweepConn):
        async def fetch(self, query, *args):
            if "DELETE FROM evidence_objects" in query:
                self.deleted_arg = args[0]
                return [{"id": item} for item in args[0]]
            if "SELECT DISTINCT storage_uri" in query:
                return []  # no other evidence row shares this blob
            return rows

    conn = _RemoteDeleteSweepConn(policy_on=False)
    monkeypatch.setattr(api_module, "db_pool", _pool_for(conn))
    monkeypatch.setattr(api_module, "delete_remote_evidence_object", lambda storage_uri: {
        "storage_uri": storage_uri,
        "storage_backend": "s3",
        "status": "deleted",
        "deleted": True,
        "retryable": False,
    })

    result = asyncio.run(api_module.evidence_retention_sweep(api_module.EvidenceRetentionSweepRequest(dry_run=False)))

    assert result["deleted_count"] == 1
    assert result["remote_objects"]["candidate_count"] == 1
    assert result["remote_objects"]["deleted_count"] == 1
    assert result["remote_objects"]["preserved_count"] == 0
    assert conn.deleted_arg == [remote_id]


def test_retention_sweep_preserves_row_when_remote_delete_fails(monkeypatch):
    old = datetime(2025, 1, 1, tzinfo=timezone.utc)
    remote_id = uuid.uuid4()
    rows = [
        {
            "id": remote_id,
            "scan_id": None,
            "finding_id": None,
            "object_type": "finding_evidence",
            "content_sha256": "a" * 64,
            "size_bytes": 4096,
            "retention_class": "short",
            "storage_uri": "s3:evidence_objects/audit-bucket/evidence-objects/aa/" + ("a" * 64) + ".json",
            "created_at": old,
        }
    ]

    class _RemoteDeleteFailureSweepConn(_SweepConn):
        async def fetch(self, query, *args):
            if "DELETE FROM evidence_objects" in query:
                self.delete_called = True
                return [{"id": item} for item in args[0]]
            if "SELECT DISTINCT storage_uri" in query:
                return []  # no other evidence row shares this blob
            return rows

    conn = _RemoteDeleteFailureSweepConn(policy_on=False)
    conn.delete_called = False
    monkeypatch.setattr(api_module, "db_pool", _pool_for(conn))
    monkeypatch.setattr(api_module, "delete_remote_evidence_object", lambda storage_uri: {
        "storage_uri": storage_uri,
        "storage_backend": "s3",
        "status": "remote_error",
        "deleted": False,
        "retryable": True,
        "error": "HTTPError: 403",
    })

    result = asyncio.run(api_module.evidence_retention_sweep(api_module.EvidenceRetentionSweepRequest(dry_run=False)))

    assert result["deleted_count"] == 0
    assert result["remote_objects"]["failed_count"] == 1
    assert result["remote_objects"]["preserved_count"] == 1
    assert conn.delete_called is False


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
            parameters={"target": "https://app.example.com", "check_family": "sqli", "budget_profile": "fast"},
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
            parameters={"dry_run": False, "older_than_days": 90, "retention_class": "short"},
            execute=True,
            confirmations=["confirm_authorized"],
            approval_receipt_id="r",
        ),
    ))

    assert result["dispatched"] is True
    assert result["operation_id"] == "op-sweep"
    assert captured["body"].dry_run is False
    assert captured["body"].older_than_days == 90
    assert captured["body"].approval_receipt_id == "r"


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

    async def fake_validate(*args, **kwargs):
        assert pool.active == 1
        return {"approval_receipt_id": "r"}

    async def fake_adapter(parameters, approval_receipt_id):
        pool.adapter_saw_no_conn = pool.active == 0
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
        )
    ))

    assert result["dispatched"] is True
    assert pool.adapter_saw_no_conn is True
    assert pool.max_active == 1


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
