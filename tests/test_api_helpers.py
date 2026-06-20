"""Unit tests for small helpers in api/api.py.

These cover the env-var coercer, the pagination → COUNT(*) rewriter, and the
JSON-decode helper that have grown enough surface to be worth pinning.
"""

import asyncio
import os
import sys
import types
import uuid


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

        get = post = patch = put = delete = on_event = _decorator

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
        {"verified": True, "verification_confidence": 0.0, "confidence": 0.95}
    )

    assert fields["last_verification_verdict"] == "exploited"
    assert fields["last_verification_confidence"] == 0.0


def test_scan_time_verification_fields_strong_proof_is_exploited():
    for finding in (
        {"poe": {"proven": True}},
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
        "scan_type": "smart",
        "scan_options": {"budget_profile": "fast"},
        "frequency": "daily",
        "day_of_week": None,
        "time_of_day": "02:00",
        "timezone": "UTC",
        "jitter_minutes": 0,
    }


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
