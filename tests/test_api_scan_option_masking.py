import asyncio
import json
import os
import sys
import types
import uuid

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
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


def test_parallel_parent_rollup_derives_progress_from_shards():
    result = {"status": "running", "progress": 5}
    shards = [
        {"status": "completed", "progress": 100},
        {"status": "running", "progress": 80},
        {"status": "pending", "progress": 0},
    ]

    api_module._attach_parallel_shard_rollup(result, shards)

    assert result["progress"] == 60
    assert result["shard_rollup"] == {
        "total": 3,
        "completed": 1,
        "failed": 0,
        "running": 1,
        "pending": 1,
        "terminal": 1,
        "average_progress": 60,
    }


def test_parallel_parent_rollup_keeps_unfinished_parent_below_complete():
    result = {"status": "running", "progress": 5}
    shards = [{"status": "completed", "progress": 100}]

    api_module._attach_parallel_shard_rollup(result, shards)

    assert result["progress"] == 99


class _FakeAsmRedis:
    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def eval(self, _script, _numkeys, key, amount, cap, _ttl):
        current = int(self.store.get(key) or 0)
        amount = int(amount)
        cap = int(cap)
        if amount <= 0:
            return 0
        if cap <= 0:
            return amount
        if current >= cap:
            return 0
        granted = min(amount, cap - current)
        self.store[key] = current + granted
        return granted


def test_asm_domain_rate_reservation_clamps_remaining_budget():
    r = _FakeAsmRedis()

    assert api_module._reserve_asm_domain_rate(r, "example.com", 5, 10) == 5
    assert api_module._asm_reserved_count(r, "example.com") == 5
    assert api_module._reserve_asm_domain_rate(r, "example.com", 5, 1) == 0


def test_asm_domain_rate_reservation_uses_root_domain_key():
    r = _FakeAsmRedis()

    assert api_module._reserve_asm_domain_rate(r, "example.com", 5, 3) == 3
    assert api_module._reserve_asm_domain_rate(r, "api.example.com", 5, 3) == 3
    assert api_module._asm_reserved_count(r, "example.com") == 3
    assert api_module._asm_reserved_count(r, "api.example.com") == 3


def test_asm_recommendation_empty_inventory_runs_recon():
    rec = api_module._asm_recommendation(
        {"total": 0, "tested": 0, "untested": 0, "stale": 0, "in_progress": 0}
    )

    assert rec["next_action"] == "recon"
    assert "No persistent endpoint inventory" in rec["reason"]


def test_asm_recommendation_claimable_inventory_runs_test():
    rec = api_module._asm_recommendation(
        {"total": 20, "tested": 10, "untested": 5, "stale": 5, "in_progress": 0},
        claimable=10,
    )

    assert rec["next_action"] == "test"
    assert "10 endpoint" in rec["reason"]


def test_asm_recommendation_active_scan_waits_and_reports_blocker():
    rec = api_module._asm_recommendation(
        {"total": 20, "tested": 10, "untested": 10, "stale": 0, "in_progress": 0},
        claimable=10,
        active_scans=1,
    )

    assert rec["next_action"] == "wait"
    assert rec["blockers"][0]["kind"] == "active_scan"


def test_asm_recommendation_auth_missing_is_visible_but_does_not_block_recon():
    rec = api_module._asm_recommendation(
        {"total": 20, "tested": 20, "untested": 0, "stale": 0, "in_progress": 0},
        claimable=0,
        last_attempt_counts={"auth_missing": 2},
    )

    assert rec["next_action"] == "recon"
    assert any(b["kind"] == "auth_missing" for b in rec["blockers"])


def test_asm_check_family_focuses_supported_scanner_flags():
    focused = api_module._apply_asm_check_family({"scan_type": "smart", "xss": True}, "sqli")

    assert focused["sqli"] is True
    assert focused["xss"] is False
    assert focused["asm_check_family"] == "sqli"


def test_asm_check_family_all_keeps_normal_active_mix():
    focused = api_module._apply_asm_check_family({"scan_type": "smart", "sqli": True}, "all")

    assert focused["sqli"] is True
    assert "asm_check_family" not in focused


def test_default_scan_list_hides_shards_and_asm_activity_rows():
    assert api_module._hidden_scan_roles_for_list() == [
        "shard",
        api_module.asm_inventory.ASM_BATCH_ROLE,
        api_module.asm_inventory.ASM_RECON_ROLE,
    ]


def test_scan_list_internal_flags_reveal_requested_implementation_rows():
    assert api_module._hidden_scan_roles_for_list(include_shards=True) == [
        api_module.asm_inventory.ASM_BATCH_ROLE,
        api_module.asm_inventory.ASM_RECON_ROLE,
    ]
    assert api_module._hidden_scan_roles_for_list(include_internal=True) == ["shard"]
    assert api_module._hidden_scan_roles_for_list(include_shards=True, include_internal=True) == []


class _FakeAcquire:
    def __init__(self, conn):
        self.conn = conn

    async def __aenter__(self):
        return self.conn

    async def __aexit__(self, *exc):
        return False


class _FakeAsmPool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return _FakeAcquire(self.conn)


class _RecordingAsmRedis:
    def __init__(self):
        self.rpush_calls = []
        self.hset_calls = []

    def rpush(self, *args):
        self.rpush_calls.append(args)

    def hset(self, *args, **kwargs):
        self.hset_calls.append((args, kwargs))


class _AsmActionConn:
    def __init__(self, *, active=0, target=None, attempts=None):
        self.active = active
        self.target = target or {
            "url": "https://example.test",
            "scan_options": {},
            "asm_config": {},
        }
        self.attempts = attempts or []
        self.executes = []

    async def fetchrow(self, query, *args):
        if "SELECT url, scan_options, asm_config" in query:
            return self.target
        if "SELECT url, scan_options" in query:
            return {"url": self.target["url"], "scan_options": self.target["scan_options"]}
        if "SELECT 1 FROM targets" in query:
            return {"exists": 1}
        if "SELECT asm_config FROM targets" in query:
            return {"asm_config": self.target.get("asm_config")}
        return None

    async def fetchval(self, query, *args):
        if "COUNT(*) FROM scans" in query:
            return self.active
        return 0

    async def fetch(self, query, *args):
        if "last_attempt_status" in query and "GROUP BY" in query:
            return self.attempts
        return []

    async def execute(self, query, *args):
        self.executes.append((query, args))
        return "OK"


def test_asm_improve_queues_recon_when_inventory_is_empty(monkeypatch):
    target_id = str(uuid.uuid4())
    conn = _AsmActionConn()
    redis_client = _RecordingAsmRedis()

    async def fake_coverage(_conn, _target_id):
        return {"total": 0, "tested": 0, "untested": 0, "in_progress": 0, "stale": 0, "gone": 0, "coverage": 0}

    async def fake_claimable(_conn, _target_id, *, stale_days):
        return 0

    monkeypatch.setattr(api_module, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(api_module, "get_redis", lambda: redis_client)
    monkeypatch.setattr(api_module.asm_inventory, "coverage_summary", fake_coverage)
    monkeypatch.setattr(api_module.asm_inventory, "claimable_count", fake_claimable)

    result = asyncio.run(api_module.asm_improve(target_id, api_module.AsmImproveRequest()))

    assert result["action"] == "recon"
    assert result["status"] == "queued"
    queued = json.loads(redis_client.rpush_calls[0][1])
    assert queued["asm_recon"] is True
    assert queued["triggered_by"] == "improve"
    assert "custom_budget" in queued["options"]
    assert any("INSERT INTO scans" in query for query, _args in conn.executes)
    assert any("asm_last_recon_at" in query for query, _args in conn.executes)


def test_asm_improve_queues_claimable_test_batch(monkeypatch):
    target_id = str(uuid.uuid4())
    conn = _AsmActionConn(target={
        "url": "https://example.test",
        "scan_options": json.dumps({"scan_type": "smart", "auth_header": "Bearer token"}),
        "asm_config": json.dumps({"batch_size": 20, "stale_days": 14, "exploit_depth": True}),
    })
    redis_client = _RecordingAsmRedis()

    async def fake_coverage(_conn, _target_id):
        return {"total": 50, "tested": 10, "untested": 40, "in_progress": 0, "stale": 0, "gone": 0, "coverage": 0.2}

    async def fake_claimable(_conn, _target_id, *, stale_days):
        assert stale_days == 14
        return 8

    monkeypatch.setattr(api_module, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(api_module, "get_redis", lambda: redis_client)
    monkeypatch.setattr(api_module.asm_inventory, "coverage_summary", fake_coverage)
    monkeypatch.setattr(api_module.asm_inventory, "claimable_count", fake_claimable)

    result = asyncio.run(api_module.asm_improve(
        target_id,
        api_module.AsmImproveRequest(check_family="sqli"),
    ))

    assert result["action"] == "test"
    assert result["batch_size"] == 8
    assert result["check_family"] == "sqli"
    queued = json.loads(redis_client.rpush_calls[0][1])
    assert queued["type"] == api_module.asm_inventory.EXPLOIT_BATCH_JOB_TYPE
    assert queued["batch_size"] == 8
    assert queued["stale_days"] == 14
    assert queued["exploit_depth"] is True
    assert queued["check_family"] == "sqli"
    assert queued["options"]["auth_header"] == "Bearer token"
    assert queued["options"]["sqli"] is True
    assert queued["options"]["xss"] is False
    assert queued["options"]["asm_check_family"] == "sqli"
    assert any("asm_last_test_at" in query for query, _args in conn.executes)


def test_asm_test_rejects_concurrent_target_work(monkeypatch):
    target_id = str(uuid.uuid4())
    conn = _AsmActionConn(active=1)

    monkeypatch.setattr(api_module, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(api_module, "get_redis", lambda: _RecordingAsmRedis())

    with pytest.raises(api_module.HTTPException) as excinfo:
        asyncio.run(api_module.asm_test(target_id, api_module.AsmTestRequest()))

    assert excinfo.value.status_code == 409


def test_sanitize_scan_options_masks_sensitive_keys():
    options = {
        "scan_type": "smart",
        "auth_header": "Bearer token1",
        "auth_cookies": "session=abc",
        "user2_header": "Bearer token2",
        "user2_cookies": "session=def",
        "auth_headers_json": "{\"X-API-Key\":\"secret\"}",
        "auth_scenario_json": "{\"steps\":[]}",
        "login_password": "password123",
        "ai_api_key": "sk-test",
        "metadata_json": {
            "hf_token": "hf-secret",
            "tokenizer": "keep-tokenizer-name",
            "nested": {"client_secret": "client-secret"},
        },
        "non_sensitive": "keep-me",
    }

    sanitized = api_module._sanitize_scan_options(options)

    assert sanitized["scan_type"] == "smart"
    assert sanitized["non_sensitive"] == "keep-me"
    assert sanitized["auth_header"] == "***"
    assert sanitized["auth_cookies"] == "***"
    assert sanitized["user2_header"] == "***"
    assert sanitized["user2_cookies"] == "***"
    assert sanitized["auth_headers_json"] == "***"
    assert sanitized["auth_scenario_json"] == "***"
    assert sanitized["login_password"] == "***"
    assert sanitized["ai_api_key"] == "***"
    assert sanitized["metadata_json"]["hf_token"] == "***"
    assert sanitized["metadata_json"]["tokenizer"] == "keep-tokenizer-name"
    assert sanitized["metadata_json"]["nested"]["client_secret"] == "***"


def test_sanitize_scan_options_decodes_json_string():
    raw = "{\"scan_type\":\"smart\",\"auth_header\":\"Bearer token\"}"
    sanitized = api_module._sanitize_scan_options(raw)
    assert sanitized["scan_type"] == "smart"
    assert sanitized["auth_header"] == "***"


def _auto_shard_settings(enabled=True, **overrides):
    settings = {
        "auto_sharding_enabled": enabled,
        "auto_sharding_strategy": "auto",
        "auto_sharding_max_shards": 4,
        "auto_sharding_min_workers": 2,
    }
    settings.update(overrides)
    return settings


def _resolve_auto_shard_policy(options):
    scan_type = api_module.normalize_dast_scan_options(options)
    payload = api_module._build_scan_options_payload(options, scan_type)
    enabled, worker_count = api_module._apply_auto_sharding_policy(options, payload, scan_type)
    return scan_type, payload, enabled, worker_count


def test_auto_sharding_setting_disabled_keeps_smart_scan_standalone(monkeypatch):
    monkeypatch.setattr(api_module, "_load_effective_scan_execution_settings", lambda: _auto_shard_settings(False))
    monkeypatch.setattr(api_module, "_running_scan_worker_count_best_effort", lambda: 4)

    _, payload, enabled, worker_count = _resolve_auto_shard_policy(api_module.ScanOptions(scan_type="smart"))

    assert enabled is False
    assert worker_count is None
    assert payload["parallel"] is False
    assert "auto_sharded" not in payload


def test_auto_sharding_uses_family_for_active_scan_when_enabled(monkeypatch):
    monkeypatch.setattr(api_module, "_load_effective_scan_execution_settings", lambda: _auto_shard_settings(True))
    monkeypatch.setattr(api_module, "_running_scan_worker_count_best_effort", lambda: 6)

    _, payload, enabled, worker_count = _resolve_auto_shard_policy(api_module.ScanOptions(scan_type="smart"))

    assert enabled is True
    assert worker_count == 6
    assert payload["parallel"] is True
    assert payload["auto_sharded"] is True
    assert payload["shard_strategy"] == "auto"
    assert payload["shards"] == 3
    assert "broad/SQLi/XSS" in payload["auto_sharding_reason"]


def test_auto_sharding_uses_scope_for_explicit_endpoint_list(monkeypatch):
    monkeypatch.setattr(api_module, "_load_effective_scan_execution_settings", lambda: _auto_shard_settings(True))
    monkeypatch.setattr(api_module, "_running_scan_worker_count_best_effort", lambda: 4)

    _, payload, enabled, _ = _resolve_auto_shard_policy(api_module.ScanOptions(
        scan_type="standard",
        custom_endpoints=["GET /api/users", "POST /api/login", "GET /api/basket"],
    ))

    assert enabled is True
    assert payload["parallel"] is True
    assert payload["shards"] == 4
    assert "explicit endpoints" in payload["auto_sharding_reason"]


def test_explicit_parallel_false_overrides_global_auto_sharding(monkeypatch):
    monkeypatch.setattr(api_module, "_load_effective_scan_execution_settings", lambda: _auto_shard_settings(True))
    monkeypatch.setattr(api_module, "_running_scan_worker_count_best_effort", lambda: 4)

    _, payload, enabled, worker_count = _resolve_auto_shard_policy(api_module.ScanOptions(scan_type="smart", parallel=False))

    assert enabled is False
    assert worker_count is None
    assert payload["parallel"] is False
    assert "auto_sharded" not in payload


def test_explicit_parallel_true_overrides_worker_minimum(monkeypatch):
    monkeypatch.setattr(api_module, "_load_effective_scan_execution_settings", lambda: _auto_shard_settings(True))
    monkeypatch.setattr(api_module, "_running_scan_worker_count_best_effort", lambda: 1)

    _, payload, enabled, worker_count = _resolve_auto_shard_policy(api_module.ScanOptions(scan_type="smart", parallel=True))

    assert enabled is True
    assert worker_count == 1
    assert payload["parallel"] is True
    assert payload["shards"] == "auto"


def test_auto_sharding_skips_when_known_worker_count_is_below_minimum(monkeypatch):
    monkeypatch.setattr(
        api_module,
        "_load_effective_scan_execution_settings",
        lambda: _auto_shard_settings(True, auto_sharding_min_workers=2),
    )
    monkeypatch.setattr(api_module, "_running_scan_worker_count_best_effort", lambda: 1)

    _, payload, enabled, worker_count = _resolve_auto_shard_policy(api_module.ScanOptions(scan_type="smart"))

    assert enabled is False
    assert worker_count == 1
    assert payload["parallel"] is False
    assert "minimum is 2" in payload["auto_sharding_reason"]


def test_normalize_dast_scan_options_keeps_explicit_standard():
    options = api_module.ScanOptions(scan_type="STANDARD", quick=False)

    scan_type = api_module.normalize_dast_scan_options(options)

    assert scan_type == "standard"
    assert options.scan_type == "standard"


def test_normalize_dast_scan_options_maps_legacy_thorough_to_deep():
    options = api_module.ScanOptions(thorough=True)

    scan_type = api_module.normalize_dast_scan_options(options)

    assert scan_type == "deep"
    assert options.scan_type == "deep"


def test_normalize_dast_scan_options_explicit_type_syncs_legacy_flags():
    # Caller sends scan_type='quick' but also passes legacy active=True; the
    # explicit scan_type should win and the legacy flag should be rewritten
    # so downstream worker.py never sees both --quick and --active.
    options = api_module.ScanOptions(scan_type="quick", active=True, thorough=True)

    scan_type = api_module.normalize_dast_scan_options(options)

    assert scan_type == "quick"
    assert options.quick is True
    assert options.active is False
    assert options.thorough is False


def test_scan_options_reject_crlf_in_auth_header():
    # auth_header flows into curl `-H` arguments downstream. CR/LF in the
    # value would let a scan submitter smuggle additional request headers
    # to the scan target.
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as exc:
        api_module.ScanOptions(auth_header="Bearer abc\r\nX-Admin: 1")

    assert "CR or LF" in str(exc.value)


def test_scan_options_reject_crlf_in_user2_cookies():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        api_module.ScanOptions(user2_cookies="session=abc\nfoo=bar")


def test_scan_options_accept_clean_auth_header():
    options = api_module.ScanOptions(auth_header="Bearer eyJ.xyz")
    assert options.auth_header == "Bearer eyJ.xyz"


def test_scan_options_reject_oob_callback_without_scheme():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        api_module.ScanOptions(oob_callback_url="evil.example.com")


def test_scan_options_reject_oob_callback_with_unsafe_scheme():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        api_module.ScanOptions(oob_callback_url="javascript:alert(1)")


def test_scan_options_accept_valid_oob_callback_url():
    options = api_module.ScanOptions(oob_callback_url="https://callback.example.com/hit")
    assert options.oob_callback_url == "https://callback.example.com/hit"


def test_scan_options_normalize_oob_callback_url_strips_whitespace():
    options = api_module.ScanOptions(oob_callback_url="  http://callback.example.com  ")
    assert options.oob_callback_url == "http://callback.example.com"


def test_normalize_dast_scan_options_explicit_smart_sets_legacy_active():
    # An explicit smart/full/aggressive scan implies the legacy active flag.
    options = api_module.ScanOptions(scan_type="smart")

    api_module.normalize_dast_scan_options(options)

    assert options.thorough is True
    assert options.active is True
    assert options.quick is False


def test_normalize_dast_scan_options_rejects_invalid_explicit_type():
    options = api_module.ScanOptions(scan_type="standard-ish")

    with pytest.raises(api_module.HTTPException) as exc:
        api_module.normalize_dast_scan_options(options)

    assert exc.value.status_code == 400
    assert exc.value.detail["error"] == "invalid_scan_type"


def test_build_ai_worker_options_records_production_confirmation():
    target = {
        "id": "target-id",
        "name": "Production bot",
        "target_type": "api_chat",
        "endpoint_url": "https://example.test/chat",
        "method": "POST",
        "headers_template": {},
        "request_template": {"message": "{{prompt}}"},
        "response_path": "$.answer",
        "streaming_mode": "json",
        "rate_limit_rps": None,
        "token_budget": None,
        "request_budget": 3,
        "production_mode": False,
        "metadata_json": {},
    }
    request = api_module.AITargetScanRequest(
        probe_pack="shaker-ai-smoke",
        scan_profile="smoke",
        environment="production",
        confirm_production=True,
    )

    worker_options, storage_options = api_module._build_ai_worker_options(
        target=target,
        credential={"auth_kind": "bearer", "secret": "secret-token", "metadata_json": {}},
        request=request,
    )

    assert storage_options["production_confirmation"]["confirmed"] is True
    assert storage_options["production_confirmation"]["environment"] == "production"
    assert worker_options["ai_target"]["metadata_json"]["production_confirmation"]["probe_pack"] == "shaker-ai-smoke"
    assert worker_options["ai_target"]["credential_ref"]["configured"] is True
    assert "secret-token" not in str(worker_options)


def test_build_ai_worker_options_uses_principal_refs_without_secrets():
    target = {
        "id": "target-id",
        "name": "RAG bot",
        "target_type": "rag",
        "endpoint_url": "https://example.test/rag",
        "method": "POST",
        "headers_template": {},
        "request_template": {"message": "{{prompt}}"},
        "response_path": "$.answer",
        "streaming_mode": "json",
        "rate_limit_rps": None,
        "token_budget": None,
        "request_budget": 3,
        "production_mode": False,
        "metadata_json": {},
    }
    request = api_module.AITargetScanRequest(
        probe_pack="shaker-rag-lite",
        scan_profile="standard",
        environment="staging",
    )
    principal_id = uuid.uuid4()

    worker_options, storage_options = api_module._build_ai_worker_options(
        target=target,
        credential={"auth_kind": "none", "secret": None, "metadata_json": {}},
        request=request,
        principals=[
            {
                "id": principal_id,
                "label": "tenant-a-user",
                "role": "attacker",
                "tenant_id": "tenant-a",
                "auth_kind": "bearer",
                "header_name": "Authorization",
                "secret_value": "principal-secret",
                "metadata_json": {"note": "ok"},
            }
        ],
    )

    principal_refs = worker_options["ai_target"]["principal_refs"]
    assert principal_refs[0]["id"] == str(principal_id)
    assert principal_refs[0]["role"] == "attacker"
    assert principal_refs[0]["credential_configured"] is True
    assert storage_options["ai_principal_roles"] == ["attacker"]
    assert "principal-secret" not in str(worker_options)


def test_build_ai_finding_retest_options_focuses_original_probe():
    target = {
        "id": "target-id",
        "name": "Support bot",
        "target_type": "api_chat",
        "endpoint_url": "https://example.test/chat",
        "method": "POST",
        "headers_template": {},
        "request_template": {"message": "{{prompt}}"},
        "response_path": "$.answer",
        "streaming_mode": "json",
        "rate_limit_rps": None,
        "token_budget": None,
        "request_budget": 3,
        "production_mode": False,
        "metadata_json": {},
    }
    finding_id = uuid.uuid4()

    worker_options, storage_options, replay_plan = api_module._build_ai_finding_retest_scan_options(
        target=target,
        credential={"auth_kind": "none", "secret": None, "metadata_json": {}},
        finding={
            "id": finding_id,
            "evidence": {
                "probe_id": "smoke.prompt-leakage",
                "probe_family": "prompt_leakage",
                "response_excerpt": "leaked",
            },
        },
        original_scan_options={
            "ai_probe_pack": "shaker-ai-smoke",
            "ai_scan_profile": "smoke",
            "ai_environment": "staging",
        },
        request=api_module.AIFindingRetestRequest(mode="same_probe", requested_by="test"),
        verification_id=uuid.uuid4(),
    )

    assert worker_options["ai_focus_probe_ids"] == ["smoke.prompt-leakage"]
    assert worker_options["ai_target"]["metadata_json"]["ai_focus_probe_ids"] == ["smoke.prompt-leakage"]
    assert storage_options["ai_finding_retest"]["mode"] == "same_probe"
    assert replay_plan["finding_id"] == str(finding_id)


def test_deployment_decision_escalates_missing_ai_judging():
    decision = api_module.build_deployment_decision({
        "id": "scan-id",
        "status": "completed",
        "run_kind": "ai_rag",
        "scan_type": "ai_gate",
        "result": {
            "result": {"score": 100, "grade": "A"},
            "findings": [],
            "ai_gate": {
                "decision": {"decision": "allow", "rationale": "No findings", "policy_name": "ai-gate:test"},
                "execution_plan": {
                    "judging_quality_gate": {
                        "judging_required": True,
                        "judging_completed": False,
                        "status": "judging_unavailable",
                    }
                },
            },
        },
    })

    assert decision["product"] == "ai_gate"
    assert decision["decision"] == "needs_review"
    assert decision["required_evidence_missing"][0]["id"] == "semantic_judging"


def test_deployment_decision_reports_model_intake_blockers():
    decision = api_module.build_deployment_decision({
        "id": "scan-id",
        "status": "completed",
        "run_kind": "model_intake",
        "scan_type": "model_intake",
        "result": {
            "result": {"score": 60, "grade": "D", "decision": "block", "decision_reason": "blocked"},
            "findings": [
                {"id": "model_intake:unsafe_serialization", "title": "Unsafe", "severity": "critical", "tool": "model_intake"},
            ],
            "model_intake": {"checks": {"checksum": False, "sbom_dependencies": False}},
        },
    })

    assert decision["product"] == "model_intake"
    assert decision["decision"] == "block"
    assert decision["blocking_findings"][0]["id"] == "model_intake:unsafe_serialization"
    assert {item["id"] for item in decision["required_evidence_missing"]} >= {"checksum", "sbom_dependencies"}


def test_deployment_decision_applies_time_bound_policy_exception():
    future = "2999-01-01T00:00:00Z"
    decision = api_module.build_deployment_decision({
        "id": "scan-id",
        "status": "completed",
        "run_kind": "model_intake",
        "scan_type": "model_intake",
        "options": {"policy_profile": "production"},
        "result": {
            "result": {"score": 50, "grade": "F", "decision": "block", "decision_reason": "blocked"},
            "findings": [
                {"id": "model_intake:unsafe_serialization", "title": "Unsafe", "severity": "critical", "tool": "model_intake"},
            ],
            "policy_exceptions": [
                {
                    "finding_id": "model_intake:unsafe_serialization",
                    "status": "approved",
                    "approved_by": "security",
                    "expires_at": future,
                }
            ],
            "model_intake": {"checks": {"checksum": True}},
        },
    })

    assert decision["decision"] == "needs_approval"
    assert decision["blocking_findings"] == []
    assert decision["applied_exceptions"][0]["id"] == "model_intake:unsafe_serialization"
    assert decision["policy_profile"] == "production"


def test_deployment_decision_ignores_expired_exception():
    decision = api_module.build_deployment_decision({
        "id": "scan-id",
        "status": "completed",
        "run_kind": "model_intake",
        "scan_type": "model_intake",
        "options": {"policy_profile": "production"},
        "result": {
            "result": {"score": 50, "grade": "F", "decision": "block", "decision_reason": "blocked"},
            "findings": [
                {"id": "model_intake:unsafe_serialization", "title": "Unsafe", "severity": "critical", "tool": "model_intake"},
            ],
            "policy_exceptions": [
                {
                    "finding_id": "model_intake:unsafe_serialization",
                    "status": "approved",
                    "approved_by": "security",
                    "expires_at": "2020-01-01T00:00:00Z",
                }
            ],
            "model_intake": {"checks": {"checksum": True}},
        },
    })

    assert decision["decision"] == "block"
    assert decision["blocking_findings"][0]["id"] == "model_intake:unsafe_serialization"


def test_ai_demo_target_detection_uses_structured_metadata_only():
    assert api_module._is_ai_demo_target_row({
        "name": "Honey demo mcp.unsafe.oauth_audience_wildcard.v1",
        "endpoint_url": "https://honey.example/api/v1/mcp/trace",
        "metadata_json": {"shakerscan_demo": True},
    })
    assert api_module._is_ai_demo_target_row({
        "name": "Local Honey calibration mcp.safe.oauth_audience_pkce_rejection.v1 local-honey-1",
        "endpoint_url": "http://host.docker.internal:18080/api/v1/mcp/trace?calibration_run=local-honey-1",
        "metadata_json": {"calibration_run": "local-honey-1"},
    })
    assert not api_module._is_ai_demo_target_row({
        "name": "Honey Production",
        "endpoint_url": "https://example.com/api/chat",
        "metadata_json": {},
    })
    assert not api_module._is_ai_demo_target_row({
        "name": "Calibration audit",
        "endpoint_url": "https://example.com/api/chat",
        "metadata_json": {},
    })


def test_demo_target_url_rewrites_base_and_adds_calibration_query():
    rewritten = api_module._demo_target_url(
        "https://honey.shakerscan.com/api/v1/mcp/trace?existing=1",
        "http://host.docker.internal:18080/",
        "demo-123",
        "mcp.unsafe.oauth_audience_wildcard.v1",
    )

    assert rewritten.startswith("http://host.docker.internal:18080/api/v1/mcp/trace?")
    assert "existing=1" in rewritten
    assert "calibration_run=demo-123" in rewritten
    assert "calibration_scenario=mcp.unsafe.oauth_audience_wildcard.v1" in rewritten


def test_demo_request_template_preserves_mcp_shape_and_injects_prompt():
    template = {"jsonrpc": "2.0", "id": "fixed", "method": "tools/list", "params": {"scenario_id": "x"}}
    rewritten = api_module._demo_request_template_with_prompt(template, "mcp")

    assert rewritten["id"] == "fixed"
    assert rewritten["params"]["scenario_id"] == "x"
    assert rewritten["params"]["prompt"] == "{{prompt}}"
    assert "prompt" not in template["params"]


def test_sanitize_ai_settings_includes_demo_fields():
    settings = api_module._sanitize_ai_settings_response({
        "demo_mode_enabled": True,
        "demo_honey_public_url": "https://honey.example",
        "demo_honey_scanner_url": "http://host.docker.internal:18080",
    })

    assert settings["demo_mode_enabled"] is True
    assert settings["demo_honey_public_url"] == "https://honey.example"
    assert settings["demo_honey_scanner_url"] == "http://host.docker.internal:18080"


def test_sanitize_ai_settings_leaves_demo_urls_empty_by_default():
    settings = api_module._sanitize_ai_settings_response({})

    assert settings["demo_mode_enabled"] is False
    assert settings["demo_honey_public_url"] == ""
    assert settings["demo_honey_scanner_url"] == ""
    assert api_module._normalize_demo_base_url("") == ""


def test_huggingface_model_info_requests_lfs_blob_metadata(monkeypatch):
    captured = {}

    class FakeResponse:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, limit):
            return b'{"siblings":[]}'

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(api_module.urllib.request, "urlopen", fake_urlopen)

    result = api_module._hf_api_model_info("acme/ranker", "abc123", 7)

    assert result == {"siblings": []}
    assert captured["timeout"] == 7
    assert captured["url"] == "https://huggingface.co/api/models/acme/ranker/revision/abc123?blobs=true"


def test_huggingface_model_info_rejects_oversized_payload(monkeypatch):
    class FakeResponse:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, limit):
            return b"x" * limit

    monkeypatch.setattr(api_module, "HF_MODEL_INFO_MAX_BYTES", 10)
    monkeypatch.setattr(api_module.urllib.request, "urlopen", lambda request, timeout: FakeResponse())

    try:
        api_module._hf_api_model_info("acme/ranker", "main", 7)
    except RuntimeError as exc:
        assert "exceeded 10 byte cap" in str(exc)
    else:
        raise AssertionError("expected oversized Hugging Face payload to be rejected")


def test_huggingface_resolver_prefills_hash_license_and_dependency_inventory(monkeypatch):
    model_info = {
        "sha": "abc123",
        "pipeline_tag": "text-generation",
        "library_name": "transformers",
        "tags": ["license:apache-2.0"],
        "cardData": {"base_model": "base/model"},
        "siblings": [
            {
                "rfilename": "vision/vit.safetensors",
                "size": 1024,
                "blobId": "blob-vit",
                "lfs": {"sha256": "e" * 64, "size": 1024},
            },
            {
                "rfilename": "model.safetensors",
                "size": 2048,
                "blobId": "blob-model",
                "lfs": {"sha256": "f" * 64, "size": 2048},
            },
            {"rfilename": "tokenizer.json", "size": 100, "blobId": "blob-tokenizer"},
            {"rfilename": "requirements.txt", "size": 42, "blobId": "blob-reqs"},
        ],
    }
    monkeypatch.setattr(api_module, "_hf_api_model_info", lambda repo_id, revision, timeout_seconds: model_info)

    resolved = api_module._resolve_huggingface_model_intake(
        api_module.ModelIntakeResolveRequest(
            platform="huggingface",
            ref="https://huggingface.co/acme/ranker",
            timeout_seconds=5,
        )
    )

    metadata = resolved["metadata_json"]
    assert resolved["selected_file"]["path"] == "model.safetensors"
    assert resolved["scan_payload"]["expected_sha256"] == "f" * 64
    assert metadata["sha256_source"] == "huggingface_lfs"
    assert metadata["license"] == "apache-2.0"
    assert metadata["tokenizer"][0]["path"] == "tokenizer.json"
    assert metadata["package_dependencies"]["files"][0]["path"] == "requirements.txt"

    resolved_file_url = api_module._resolve_huggingface_model_intake(
        api_module.ModelIntakeResolveRequest(
            platform="huggingface",
            ref="https://huggingface.co/acme/ranker/resolve/abc123/vision/vit.safetensors",
            timeout_seconds=5,
        )
    )
    assert resolved_file_url["selected_file"]["path"] == "vision/vit.safetensors"
    assert resolved_file_url["scan_payload"]["expected_sha256"] == "e" * 64


def test_huggingface_resolver_does_not_emit_scan_payload_without_metadata_or_file(monkeypatch):
    def unavailable_model_info(repo_id, revision, timeout_seconds):
        raise RuntimeError("hub unavailable")

    monkeypatch.setattr(api_module, "_hf_api_model_info", unavailable_model_info)

    resolved = api_module._resolve_huggingface_model_intake(
        api_module.ModelIntakeResolveRequest(
            platform="huggingface",
            ref="https://huggingface.co/acme/ranker",
            timeout_seconds=5,
        )
    )

    assert resolved["scan_payload"] is None
    assert resolved["candidate_files"] == []
    assert any("metadata is required" in warning for warning in resolved["warnings"])


def test_direct_huggingface_scan_request_is_auto_enriched(monkeypatch):
    monkeypatch.setattr(api_module, "_resolve_huggingface_model_intake", lambda request: {
        "scan_payload": {
            "artifact_url": "https://huggingface.co/acme/ranker/resolve/abc123/model.safetensors",
            "name": "Hugging Face: acme/ranker",
            "expected_sha256": "a" * 64,
            "model_card_url": "https://huggingface.co/acme/ranker",
            "metadata_json": {
                "huggingface_repo": "acme/ranker",
                "huggingface_file": "model.safetensors",
                "license": "apache-2.0",
                "sha256": "a" * 64,
            },
        },
    })

    request = api_module.ModelIntakeScanRequest(artifact_url="acme/ranker")
    enriched = asyncio.run(api_module._enrich_model_intake_scan_request(request))

    assert enriched.artifact_url.endswith("/resolve/abc123/model.safetensors")
    assert enriched.expected_sha256 == "a" * 64
    assert enriched.model_card_url == "https://huggingface.co/acme/ranker"
    assert enriched.metadata_json["license"] == "apache-2.0"
