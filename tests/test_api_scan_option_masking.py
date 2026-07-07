import asyncio
import json
import os
import sys
import types
import uuid

import pytest
from pydantic import ValidationError


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


def test_parallel_parent_rollup_adds_shard_contribution_summary():
    result = {"status": "completed", "progress": 100}
    shards = [
        {
            "status": "completed",
            "progress": 100,
            "duration_seconds": 60,
            "result": {
                "active_checks": {
                    "active_worklist_total": 20,
                    "active_endpoints_selected": 2,
                    "active_endpoint_budget": 2,
                    "per_endpoint_telemetry": True,
                    "check_family_scope": {
                        "requested_family": "sqli",
                        "focused_family": "sqli",
                    },
                    "endpoint_attempts": [
                        {"custom_endpoint": "GET /a?id=1", "status": "completed"},
                        {"custom_endpoint": "GET /b?id=1", "status": "partial"},
                    ],
                },
            },
            "options": {
                "custom_endpoints": ["GET /a?id=1", "GET /b?id=1"],
                "asm_check_family": "sqli",
                "custom_budget": {"active_max_seconds": 120, "active_max_endpoints": 2},
            },
        }
    ]

    api_module._attach_parallel_shard_rollup(result, shards)

    shard = result["shards"][0]
    assert "result" not in shard
    assert "options" not in shard
    assert shard["contribution"] == {
        "assigned_endpoints": 2,
        "attempted_endpoints": 2,
        "attempt_statuses": {"completed": 1, "partial": 1},
        "active_worklist_total": 20,
        "active_endpoints_selected": 2,
        "active_endpoint_budget": 2,
        "active_max_seconds": 120,
        "check_family": "sqli",
        "auth_state": "anonymous",
        "per_endpoint_telemetry": True,
    }
    assert result["shard_rollup"]["contribution"] == {
        "assigned_endpoints": 2,
        "attempted_endpoints": 2,
        "active_worklist_total": 20,
        "active_endpoints_selected": 2,
        "active_endpoint_budget": 2,
        "active_max_seconds": 120,
        "duration_seconds": 60,
        "attempt_statuses": {"completed": 1, "partial": 1},
        "by_auth_state": {
            "anonymous": {
                "shards": 1,
                "assigned_endpoints": 2,
                "attempted_endpoints": 2,
                "active_worklist_total": 20,
                "active_endpoints_selected": 2,
                "active_endpoint_budget": 2,
                "active_max_seconds": 120,
                "duration_seconds": 60,
                "telemetry_shards": 1,
            },
        },
        "by_check_family": {
            "sqli": {
                "shards": 1,
                "assigned_endpoints": 2,
                "attempted_endpoints": 2,
                "active_worklist_total": 20,
                "active_endpoints_selected": 2,
                "active_endpoint_budget": 2,
                "active_max_seconds": 120,
                "duration_seconds": 60,
                "telemetry_shards": 1,
            },
        },
        "shards_with_contribution": 1,
        "telemetry_shards": 1,
        "active_budget_utilization": 0.5,
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

    def eval(self, _script, _numkeys, key, amount, cap, _ttl, all_or_nothing="0"):
        current = int(self.store.get(key) or 0)
        amount = int(amount)
        cap = int(cap)
        if amount <= 0:
            return 0
        if cap <= 0:
            return 0
        if current >= cap:
            return 0
        if str(all_or_nothing) == "1" and current + amount > cap:
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


def test_ai_production_scan_requires_explicit_confirmation():
    reason = api_module._ai_production_confirmation_reason
    # production target OR production environment, without confirmation -> refused
    assert reason(True, "staging", False) is not None
    assert reason(False, "production", False) is not None
    # confirmation present -> allowed through
    assert reason(True, "production", True) is None
    # non-production, no confirmation needed
    assert reason(False, "staging", False) is None
    assert reason(False, None, False) is None


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


def test_asm_recommendation_active_scan_blocker_surfaces_scan_id():
    # The blocking scan is usually a hidden ASM batch/recon row; the blocker must
    # carry its id so the UI can link the otherwise-invisible "active (1)" scan.
    rec = api_module._asm_recommendation(
        {"total": 9, "tested": 0, "untested": 0, "stale": 0, "in_progress": 9},
        claimable=0,
        active_scans=1,
        active_scan_ids=["73e93470-aaaa-bbbb-cccc-000000000000"],
    )
    blocker = rec["blockers"][0]
    assert blocker["kind"] == "active_scan"
    assert blocker["scan_id"] == "73e93470-aaaa-bbbb-cccc-000000000000"
    assert blocker["scan_ids"] == ["73e93470-aaaa-bbbb-cccc-000000000000"]


def test_asm_recommendation_active_scan_blocker_omits_id_when_unknown():
    rec = api_module._asm_recommendation(
        {"total": 9, "tested": 0, "untested": 0, "stale": 0, "in_progress": 9},
        claimable=0,
        active_scans=1,
    )
    blocker = rec["blockers"][0]
    assert blocker["kind"] == "active_scan"
    assert "scan_id" not in blocker


def test_asm_recommendation_auth_missing_is_visible_but_does_not_block_recon():
    rec = api_module._asm_recommendation(
        {"total": 20, "tested": 20, "untested": 0, "stale": 0, "in_progress": 0},
        claimable=0,
        last_attempt_counts={"auth_missing": 2},
    )

    assert rec["next_action"] == "recon"
    assert any(b["kind"] == "auth_missing" for b in rec["blockers"])


def test_asm_check_family_focuses_supported_scanner_flags():
    focused = api_module._apply_asm_check_family({"scan_type": "smart", "xss": True}, "sql")

    assert focused["sqli"] is True
    assert focused["xss"] is False
    assert focused["asm_check_family"] == "sqli"


def test_asm_check_family_focuses_auth_without_injection_flags():
    focused = api_module._apply_asm_check_family({"scan_type": "smart", "xss": True, "sqli": True}, "auth")

    assert focused["sqli"] is False
    assert focused["xss"] is False
    assert focused["asm_check_family"] == "auth"


def test_asm_check_family_all_keeps_normal_active_mix():
    focused = api_module._apply_asm_check_family({"scan_type": "smart", "sqli": True}, "all")

    assert focused["sqli"] is True
    assert "asm_check_family" not in focused


def test_asm_check_family_rejects_registered_but_unrunnable_family():
    with pytest.raises(ValueError, match="registered but not runnable"):
        api_module._apply_asm_check_family({"scan_type": "smart"}, "ssrf")


def test_asm_request_validation_rejects_unknown_family_with_allowed_list():
    with pytest.raises(ValidationError, match="allowed families: all, sqli, xss, bola, auth"):
        api_module.AsmImproveRequest(check_family="nosuch")


def test_asm_check_family_registry_endpoint_lists_runnable_and_planned_families():
    result = asyncio.run(api_module.asm_check_families())
    names = {family["name"]: family for family in result["families"]}

    assert result["asm_focus_allowed"] == ["all", "sqli", "xss", "bola", "auth"]
    assert names["sqli"]["runnable"] is True
    assert names["xss"]["runnable"] is True
    assert names["bola"]["runnable"] is True
    assert names["bola"]["requires_credentials"] is True
    assert "resource_id" in names["bola"]["proof_contract"]
    assert names["bola"]["severity_rules"]["critical_requires"] == ["cross_user_data_access"]
    assert names["auth"]["runnable"] is True
    assert names["auth"]["requires_credentials"] is True
    assert names["ssrf"]["risk_level"] == "high"


def test_asm_bola_family_requires_lab_policy_and_two_auth_contexts():
    with pytest.raises(api_module.HTTPException, match="Lab/deep"):
        api_module._enforce_asm_family_preconditions(
            "bola",
            {"scan_type": "smart", "auth_header": "Bearer u1", "user2_header": "Bearer u2"},
            exploit_depth=False,
        )

    with pytest.raises(api_module.HTTPException, match="primary user credentials"):
        api_module._enforce_asm_family_preconditions(
            "bola",
            {"scan_type": "smart", "user2_header": "Bearer u2"},
            exploit_depth=True,
        )

    with pytest.raises(api_module.HTTPException, match="second-user credentials"):
        api_module._enforce_asm_family_preconditions(
            "bola",
            {"scan_type": "smart", "auth_header": "Bearer u1"},
            exploit_depth=True,
        )

    api_module._enforce_asm_family_preconditions(
        "bola",
        {"scan_type": "smart", "auth_header": "Bearer u1", "user2_header": "Bearer u2"},
        exploit_depth=True,
    )


def test_asm_auth_family_requires_primary_credentials_only():
    with pytest.raises(api_module.HTTPException, match="primary user credentials"):
        api_module._enforce_asm_family_preconditions(
            "auth",
            {"scan_type": "smart"},
            exploit_depth=False,
        )

    api_module._enforce_asm_family_preconditions(
        "auth",
        {"scan_type": "smart", "auth_header": "Bearer u1"},
        exploit_depth=False,
    )


def test_post_scans_policy_rejects_bola_without_lab_and_two_users():
    with pytest.raises(api_module.HTTPException, match="Lab/deep"):
        api_module._apply_scan_check_family_policy({
            "scan_type": "smart",
            "check_family": "bola",
            "auth_header": "Bearer u1",
            "user2_header": "Bearer u2",
            "exploit_depth": False,
        })

    with pytest.raises(api_module.HTTPException, match="second-user credentials"):
        api_module._apply_scan_check_family_policy({
            "scan_type": "smart",
            "check_family": "bola",
            "auth_header": "Bearer u1",
            "exploit_depth": True,
        })


def test_post_scans_policy_applies_registry_scanner_options():
    opts, family = api_module._apply_scan_check_family_policy({
        "scan_type": "smart",
        "check_family": "sqli",
        "xss": True,
        "sqli": False,
    })

    assert family == "sqli"
    assert opts["asm_check_family"] == "sqli"
    assert opts["check_family"] == "sqli"
    assert opts["sqli"] is True
    assert opts["xss"] is False


def test_ai_ops_router_full_coverage_is_dry_run_by_default():
    plan = api_module._build_ai_ops_router_plan(
        api_module.AIOpsRouterRequest(
            prompt="Run full coverage on this target",
            target="https://example.test",
        )
    )

    assert plan["intent"] == "run_full_coverage"
    assert plan["dry_run"] is True
    assert plan["requires_confirmation"] is True
    assert plan["missing_inputs"] == []
    assert plan["planned_api_call"] == {
        "method": "POST",
        "path": "/scans",
        "body": {
            "target": "https://example.test",
            "options": {
                "scan_type": "smart",
                "budget_profile": "thorough",
                "parallel": True,
                "shard_strategy": "coverage",
                "exploit_depth": False,
            },
        },
    }
    assert plan["blast_radius"]["active_families"] == ["all"]
    assert plan["authorization_assumption"]


def test_ai_ops_router_scopes_api_budget_raise_to_api_endpoint_filter():
    target_id = str(uuid.uuid4())
    plan = api_module._build_ai_ops_router_plan(
        api_module.AIOpsRouterRequest(
            prompt="Spend more budget on APIs",
            target_id=target_id,
            execute=True,
            confirm_execution=True,
            confirm_authorized=True,
        )
    )

    assert plan["intent"] == "increase_api_endpoint_budget"
    assert plan["dry_run"] is True
    assert plan["missing_inputs"] == []
    assert plan["planned_api_call"] == {
        "method": "POST",
        "path": f"/targets/{target_id}/asm/improve",
        "body": {"endpoint_filter": "api", "batch_size": 100, "exploit_depth": False},
    }
    assert plan["blast_radius"]["rate_cap_changes"] == {
        "global_defaults_changed": False,
        "endpoint_filter": "api",
        "batch_size": 100,
    }
    assert plan["execution_blocked_reason"] == "AI_OPS_ROUTER_EXECUTE_ENABLED is not enabled"


def test_ai_ops_router_bola_requires_auth_context_and_high_risk_confirmation():
    target_id = str(uuid.uuid4())
    plan = api_module._build_ai_ops_router_plan(
        api_module.AIOpsRouterRequest(
            prompt="Only retest BOLA tonight",
            target_id=target_id,
        )
    )

    assert plan["intent"] == "focused_asm_bola"
    assert plan["dry_run"] is True
    assert plan["safety_preset"] == "lab"
    assert plan["blast_radius"]["high_risk_families"] == ["bola"]
    assert plan["missing_inputs"] == ["primary_auth_context", "second_user_auth_context"]
    assert plan["planned_api_call"] == {
        "method": "POST",
        "path": f"/targets/{target_id}/asm/improve",
        "body": {"check_family": "bola", "exploit_depth": True},
    }


def test_ai_ops_router_sqli_focus_does_not_upgrade_to_lab():
    target_id = str(uuid.uuid4())
    plan = api_module._build_ai_ops_router_plan(
        api_module.AIOpsRouterRequest(
            prompt="Only retest SQL injection tonight",
            target_id=target_id,
        )
    )

    assert plan["intent"] == "focused_asm_sqli"
    assert plan["safety_preset"] == "balanced"
    assert plan["blast_radius"]["high_risk_families"] == []
    assert plan["planned_api_call"] == {
        "method": "POST",
        "path": f"/targets/{target_id}/asm/improve",
        "body": {"check_family": "sqli"},
    }


def test_ai_ops_router_auth_focus_requires_primary_auth_context():
    target_id = str(uuid.uuid4())
    plan = api_module._build_ai_ops_router_plan(
        api_module.AIOpsRouterRequest(
            prompt="Retest anonymous access and authentication bypasses",
            target_id=target_id,
        )
    )

    assert plan["intent"] == "focused_asm_auth"
    assert plan["safety_preset"] == "balanced"
    assert plan["missing_inputs"] == ["primary_auth_context"]
    assert plan["blast_radius"]["active_families"] == ["auth"]
    assert plan["planned_api_call"] == {
        "method": "POST",
        "path": f"/targets/{target_id}/asm/improve",
        "body": {"check_family": "auth"},
    }


def test_ai_ops_router_bola_execute_requires_high_risk_confirmation(monkeypatch):
    monkeypatch.setenv("AI_OPS_ROUTER_EXECUTE_ENABLED", "true")
    plan = api_module._build_ai_ops_router_plan(
        api_module.AIOpsRouterRequest(
            prompt="Only retest BOLA tonight",
            target_id=str(uuid.uuid4()),
            auth_context={"has_primary_auth": True, "has_second_user_auth": True},
            execute=True,
            confirm_execution=True,
            confirm_authorized=True,
        )
    )

    assert plan["dry_run"] is True
    assert plan["missing_inputs"] == []
    assert plan["execution_blocked_reason"] == "confirmation_required"


def test_ai_ops_router_execute_requires_feature_flag(monkeypatch):
    monkeypatch.delenv("AI_OPS_ROUTER_EXECUTE_ENABLED", raising=False)
    plan = api_module._build_ai_ops_router_plan(
        api_module.AIOpsRouterRequest(
            prompt="Run full coverage",
            target="https://example.test",
            execute=True,
            confirm_execution=True,
            confirm_authorized=True,
        )
    )

    assert plan["dry_run"] is True
    assert plan["execution_blocked_reason"] == "AI_OPS_ROUTER_EXECUTE_ENABLED is not enabled"


def test_ai_ops_router_execute_full_coverage_when_confirmed(monkeypatch):
    monkeypatch.setenv("AI_OPS_ROUTER_EXECUTE_ENABLED", "true")
    captured = {}

    async def fake_submit_scan(request):
        captured["target"] = request.target
        captured["options"] = request.options.model_dump()
        return {"scan_id": "scan-1", "job_id": "job-1", "status": "queued"}

    monkeypatch.setattr(api_module, "submit_scan", fake_submit_scan)

    result = asyncio.run(
        api_module.ai_ops_route(
            api_module.AIOpsRouterRequest(
                prompt="Run full coverage on this target",
                target="https://example.test",
                execute=True,
                confirm_execution=True,
                confirm_authorized=True,
            )
        )
    )

    assert result["dry_run"] is False
    assert captured["target"] == "https://example.test"
    assert captured["options"]["parallel"] is True
    assert captured["options"]["shard_strategy"] == "coverage"
    assert captured["options"]["exploit_depth"] is False
    assert result["executed"]["scan_id"] == "scan-1"
    assert result["executed"]["ui_link"] == "/scans/scan-1"


def test_ai_ops_router_execute_api_budget_when_confirmed(monkeypatch):
    monkeypatch.setenv("AI_OPS_ROUTER_EXECUTE_ENABLED", "true")
    target_id = str(uuid.uuid4())
    captured = {}

    async def fake_asm_improve(tid, request):
        captured["target_id"] = tid
        captured["request"] = request.model_dump()
        return {
            "scan_id": "scan-api",
            "job_id": "job-api",
            "campaign_id": "campaign-api",
            "status": "queued",
        }

    monkeypatch.setattr(api_module, "asm_improve", fake_asm_improve)

    result = asyncio.run(
        api_module.ai_ops_route(
            api_module.AIOpsRouterRequest(
                prompt="Spend more budget on APIs",
                target_id=target_id,
                execute=True,
                confirm_execution=True,
                confirm_authorized=True,
            )
        )
    )

    assert result["dry_run"] is False
    assert captured["target_id"] == target_id
    assert captured["request"]["endpoint_filter"] == "api"
    assert captured["request"]["batch_size"] == 100
    assert captured["request"]["exploit_depth"] is False
    assert result["executed"]["scan_id"] == "scan-api"
    assert result["executed"]["ui_link"] == "/scans/scan-api"


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
        self.campaign_id = uuid.uuid4()

    async def fetchrow(self, query, *args):
        if "INSERT INTO command_results" in query:
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
        if "SELECT id, url, root_domain, asm_config" in query:
            return {
                "id": args[0] if args else uuid.uuid4(),
                "url": self.target["url"],
                "root_domain": "example.test",
                "asm_config": self.target.get("asm_config"),
                "asm_last_test_at": None,
                "asm_last_recon_at": None,
                "metadata_json": {},
            }
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
        if "INSERT INTO scan_campaigns" in query:
            return self.campaign_id
        return 0

    async def fetch(self, query, *args):
        if "SELECT id FROM scans" in query:
            return [{"id": uuid.uuid4()} for _ in range(self.active)]
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

    async def fake_claimable(_conn, _target_id, *, stale_days, endpoint_filter=None):
        assert endpoint_filter is None
        return 0

    monkeypatch.setattr(api_module, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(api_module, "get_redis", lambda: redis_client)
    monkeypatch.setattr(api_module.asm_inventory, "coverage_summary", fake_coverage)
    monkeypatch.setattr(api_module.asm_inventory, "claimable_count", fake_claimable)

    result = asyncio.run(api_module.asm_improve(target_id, api_module.AsmImproveRequest()))

    assert result["action"] == "recon"
    assert result["status"] == "queued"
    assert result["campaign_id"] == str(conn.campaign_id)
    queued = json.loads(redis_client.rpush_calls[0][1])
    assert queued["asm_recon"] is True
    assert queued["triggered_by"] == "improve"
    assert queued["campaign_id"] == str(conn.campaign_id)
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

    async def fake_claimable(_conn, _target_id, *, stale_days, endpoint_filter=None):
        assert stale_days == 14
        assert endpoint_filter is None
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
    assert result["campaign_id"] == str(conn.campaign_id)
    assert result["batch_size"] == 8
    assert result["check_family"] == "sqli"
    queued = json.loads(redis_client.rpush_calls[0][1])
    assert queued["type"] == api_module.asm_inventory.EXPLOIT_BATCH_JOB_TYPE
    assert queued["batch_size"] == 8
    assert queued["stale_days"] == 14
    assert queued["exploit_depth"] is True
    assert queued["check_family"] == "sqli"
    assert queued["campaign_id"] == str(conn.campaign_id)
    assert queued["options"]["auth_header"] == "Bearer token"
    assert queued["options"]["sqli"] is True
    assert queued["options"]["xss"] is False
    assert queued["options"]["asm_check_family"] == "sqli"
    assert any("asm_last_test_at" in query for query, _args in conn.executes)


def test_asm_improve_can_scope_next_batch_to_api_endpoints(monkeypatch):
    target_id = str(uuid.uuid4())
    conn = _AsmActionConn(target={
        "url": "https://example.test",
        "scan_options": json.dumps({"scan_type": "smart"}),
        "asm_config": json.dumps({"batch_size": 50, "stale_days": 30, "exploit_depth": False}),
    })
    redis_client = _RecordingAsmRedis()

    async def fake_coverage(_conn, _target_id):
        return {"total": 50, "tested": 10, "untested": 40, "in_progress": 0, "stale": 0, "gone": 0, "coverage": 0.2}

    async def fake_claimable(_conn, _target_id, *, stale_days, endpoint_filter=None):
        assert stale_days == 30
        assert endpoint_filter == "api"
        return 12

    monkeypatch.setattr(api_module, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(api_module, "get_redis", lambda: redis_client)
    monkeypatch.setattr(api_module.asm_inventory, "coverage_summary", fake_coverage)
    monkeypatch.setattr(api_module.asm_inventory, "claimable_count", fake_claimable)

    result = asyncio.run(api_module.asm_improve(
        target_id,
        api_module.AsmImproveRequest(batch_size=100, endpoint_filter="apis"),
    ))

    assert result["action"] == "test"
    assert result["batch_size"] == 12
    assert result["endpoint_filter"] == "api"
    queued = json.loads(redis_client.rpush_calls[0][1])
    assert queued["endpoint_filter"] == "api"
    assert queued["options"]["asm_endpoint_filter"] == "api"


def test_asm_improve_endpoint_filter_does_not_queue_when_no_matching_work(monkeypatch):
    target_id = str(uuid.uuid4())
    conn = _AsmActionConn(target={
        "url": "https://example.test",
        "scan_options": json.dumps({"scan_type": "smart"}),
        "asm_config": json.dumps({"batch_size": 50, "stale_days": 30, "exploit_depth": False}),
    })
    redis_client = _RecordingAsmRedis()

    async def fake_coverage(_conn, _target_id):
        return {"total": 50, "tested": 10, "untested": 40, "in_progress": 0, "stale": 0, "gone": 0, "coverage": 0.2}

    async def fake_claimable(_conn, _target_id, *, stale_days, endpoint_filter=None):
        assert stale_days == 30
        assert endpoint_filter == "api"
        return 0

    monkeypatch.setattr(api_module, "db_pool", _FakeAsmPool(conn))
    monkeypatch.setattr(api_module, "get_redis", lambda: redis_client)
    monkeypatch.setattr(api_module.asm_inventory, "coverage_summary", fake_coverage)
    monkeypatch.setattr(api_module.asm_inventory, "claimable_count", fake_claimable)

    result = asyncio.run(api_module.asm_improve(
        target_id,
        api_module.AsmImproveRequest(batch_size=100, endpoint_filter="api"),
    ))

    assert result["action"] == "wait"
    assert result["status"] == "no_claimable_endpoints"
    assert result["endpoint_filter"] == "api"
    assert result["recommendation"]["next_action"] == "wait"
    assert redis_client.rpush_calls == []
    assert not any("INSERT INTO scans" in query for query, _args in conn.executes)


def test_asm_endpoint_filter_rejects_unknown_values():
    with pytest.raises(ValidationError, match="unsupported endpoint_filter"):
        api_module.AsmImproveRequest(endpoint_filter="all-the-things")


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


def test_auto_sharding_defaults_enabled_for_fresh_installs(monkeypatch):
    monkeypatch.delenv("AUTO_SHARDING_ENABLED", raising=False)

    settings = api_module._default_scan_execution_settings()

    assert settings["auto_sharding_enabled"] is True


def test_auto_sharding_env_can_disable_default(monkeypatch):
    monkeypatch.setenv("AUTO_SHARDING_ENABLED", "false")

    settings = api_module._default_scan_execution_settings()

    assert settings["auto_sharding_enabled"] is False


def test_default_asm_enabled_for_new_web_targets(monkeypatch):
    monkeypatch.delenv("DEFAULT_ASM_ENABLED", raising=False)
    monkeypatch.delenv("ASM_DEFAULT_ENABLED", raising=False)
    monkeypatch.setattr(api_module, "get_redis", lambda: (_ for _ in ()).throw(RuntimeError("redis down")))

    assert api_module._default_asm_enabled_for_new_web_target("manual") is True
    assert api_module._default_asm_enabled_for_new_web_target("ai_session") is True


def test_default_asm_enabled_can_be_disabled_and_skips_model_intake(monkeypatch):
    monkeypatch.setenv("DEFAULT_ASM_ENABLED", "false")
    monkeypatch.setattr(api_module, "get_redis", lambda: (_ for _ in ()).throw(RuntimeError("redis down")))

    assert api_module._default_asm_enabled_for_new_web_target("manual") is False
    assert api_module._default_asm_enabled_for_new_web_target("model-intake") is False


class _AutomationSettingsRedis:
    def __init__(self):
        self.store = {}

    def hgetall(self, key):
        return dict(self.store.get(key, {}))

    def hset(self, key, mapping=None, **kwargs):
        data = dict(mapping or {})
        data.update(kwargs)
        self.store.setdefault(key, {}).update(data)
        return len(data)


class _DurableSettingsConn:
    """Fake asyncpg conn backing the durable app_settings key/value store."""

    def __init__(self, durable=None):
        self.store = dict(durable or {})
        self.executes = []

    async def fetchval(self, query, *args):
        if "FROM app_settings" in query:
            return self.store.get(args[0])
        return None

    async def execute(self, query, *args):
        self.executes.append((query, args))
        if "INSERT INTO app_settings" in query:
            self.store[args[0]] = args[1]
        return "OK"


def test_automation_settings_runtime_override_controls_new_target_asm_defaults(monkeypatch):
    redis_client = _AutomationSettingsRedis()
    redis_client.hset(
        api_module.AUTOMATION_SETTINGS_KEY,
        mapping={
            "default_asm_enabled": "false",
            "default_asm_config": json.dumps({"batch_size": 123, "exploit_depth": True}),
        },
    )
    monkeypatch.setattr(api_module, "get_redis", lambda: redis_client)

    cfg = api_module._default_asm_config_for_new_web_target("manual")

    assert api_module._default_asm_enabled_for_new_web_target("manual") is False
    assert cfg["batch_size"] == 123
    assert cfg["exploit_depth"] is False
    assert api_module._default_asm_config_for_new_web_target("model-intake") == {}


def test_update_automation_settings_writes_scan_and_safe_asm_defaults(monkeypatch):
    redis_client = _AutomationSettingsRedis()
    durable_conn = _DurableSettingsConn()
    monkeypatch.setattr(api_module, "get_redis", lambda: redis_client)
    monkeypatch.setattr(api_module, "db_pool", _FakeAsmPool(durable_conn))
    monkeypatch.setattr(api_module, "_running_scan_worker_count_best_effort", lambda: 5)

    result = asyncio.run(api_module.update_automation_settings(
        api_module.AutomationSettingsUpdate(
            auto_sharding_enabled=False,
            auto_sharding_strategy="coverage",
            default_asm_enabled=False,
            default_asm_config={"batch_size": 120, "stale_days": 14, "exploit_depth": True},
            approval_receipts_required_for_state_changing_actions=True,
        )
    ))

    scan_store = redis_client.store[api_module.SCAN_SETTINGS_KEY]
    automation_store = redis_client.store[api_module.AUTOMATION_SETTINGS_KEY]
    stored_asm_config = json.loads(automation_store["default_asm_config"])
    assert scan_store["auto_sharding_enabled"] == "false"
    assert scan_store["auto_sharding_strategy"] == "coverage"
    assert automation_store["default_asm_enabled"] == "false"
    assert automation_store["approval_receipts_required_for_state_changing_actions"] == "true"
    assert stored_asm_config["batch_size"] == 120
    assert stored_asm_config["stale_days"] == 14
    assert stored_asm_config["exploit_depth"] is False
    assert result["settings"]["scan_execution"]["auto_sharding_enabled"] is False
    assert result["settings"]["scan_execution"]["auto_sharding_strategy"] == "coverage"
    assert result["settings"]["default_continuous_asm"]["enabled_for_new_web_targets"] is False
    assert result["settings"]["default_continuous_asm"]["config"]["exploit_depth"] is False
    assert result["settings"]["default_continuous_asm"]["active_depth_confirmation_required"] is True
    assert (
        result["settings"]["safety_boundaries"]["approval_receipts_required_for_state_changing_actions"]
        is True
    )
    # The security flag is persisted durably to Postgres (not just Redis).
    assert durable_conn.store[api_module.APPROVAL_POLICY_SETTING_KEY] == "true"


def test_update_automation_settings_merges_partial_asm_config(monkeypatch):
    redis_client = _AutomationSettingsRedis()
    redis_client.hset(
        api_module.AUTOMATION_SETTINGS_KEY,
        mapping={
            "default_asm_config": json.dumps({
                "batch_size": 40,
                "stale_days": 60,
                "window_start_hour": 2,
                "window_end_hour": 6,
                "window_days": [1, 3],
                "max_requests_per_hour_per_domain": 333,
            }),
        },
    )
    monkeypatch.setattr(api_module, "get_redis", lambda: redis_client)

    result = asyncio.run(api_module.update_automation_settings(
        api_module.AutomationSettingsUpdate(default_asm_config={"batch_size": 100})
    ))

    stored = json.loads(redis_client.store[api_module.AUTOMATION_SETTINGS_KEY]["default_asm_config"])
    assert stored["batch_size"] == 100
    assert stored["stale_days"] == 60
    assert stored["window_start_hour"] == 2
    assert stored["window_end_hour"] == 6
    assert stored["window_days"] == [1, 3]
    assert stored["max_requests_per_hour_per_domain"] == 333
    assert result["settings"]["default_continuous_asm"]["config"]["batch_size"] == 100
    assert result["settings"]["default_continuous_asm"]["config"]["window_days"] == [1, 3]


def test_approval_receipt_policy_defaults_to_compatibility_mode(monkeypatch):
    redis_client = _AutomationSettingsRedis()
    monkeypatch.setattr(api_module, "get_redis", lambda: redis_client)

    response = api_module._sanitize_automation_settings_response()

    assert response["safety_boundaries"]["approval_receipts_required_for_state_changing_actions"] is False
    # No durable row + no Redis flag => compatibility mode => no receipt required.
    conn = _DurableSettingsConn()
    asyncio.run(
        api_module._require_approval_receipt_if_policy_enabled(
            conn, None, action_name="scan.submit:quick"
        )
    )


def test_approval_receipt_policy_blocks_when_enabled_via_redis_fallback(monkeypatch):
    # No durable Postgres row yet => enforcement falls back to the legacy
    # Redis/env view so pre-existing configs keep working.
    redis_client = _AutomationSettingsRedis()
    redis_client.hset(
        api_module.AUTOMATION_SETTINGS_KEY,
        mapping={api_module.APPROVAL_POLICY_SETTING_KEY: "true"},
    )
    monkeypatch.setattr(api_module, "get_redis", lambda: redis_client)

    conn = _DurableSettingsConn()  # durable store empty -> fall back to Redis
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(
            api_module._require_approval_receipt_if_policy_enabled(
                conn, None, action_name="asm.test"
            )
        )

    assert exc.value.status_code == 409
    assert exc.value.detail["error"] == "approval_receipt_required"
    assert exc.value.detail["action"] == "asm.test"


def test_approval_receipt_policy_durable_postgres_is_authoritative(monkeypatch):
    key = api_module.APPROVAL_POLICY_SETTING_KEY

    # Redis says OFF but Postgres says ON => Postgres wins => must block. This is
    # exactly the fail-open case the durable store fixes (a flushed Redis hash
    # can no longer silently disable the policy).
    redis_off = _AutomationSettingsRedis()
    monkeypatch.setattr(api_module, "get_redis", lambda: redis_off)
    conn_on = _DurableSettingsConn(durable={key: "true"})
    with pytest.raises(api_module.HTTPException) as exc:
        asyncio.run(
            api_module._require_approval_receipt_if_policy_enabled(
                conn_on, None, action_name="scan.submit:quick"
            )
        )
    assert exc.value.status_code == 409

    # A provided receipt short-circuits before any policy read.
    asyncio.run(
        api_module._require_approval_receipt_if_policy_enabled(
            conn_on, "receipt-id", action_name="scan.submit:quick"
        )
    )

    # Redis says ON but Postgres says OFF => Postgres wins => must NOT block.
    redis_on = _AutomationSettingsRedis()
    redis_on.hset(api_module.AUTOMATION_SETTINGS_KEY, mapping={key: "true"})
    monkeypatch.setattr(api_module, "get_redis", lambda: redis_on)
    conn_off = _DurableSettingsConn(durable={key: "false"})
    asyncio.run(
        api_module._require_approval_receipt_if_policy_enabled(
            conn_off, None, action_name="scan.submit:quick"
        )
    )


def test_auto_sharding_setting_disabled_keeps_smart_scan_standalone(monkeypatch):
    monkeypatch.setattr(api_module, "_load_effective_scan_execution_settings", lambda: _auto_shard_settings(False))
    monkeypatch.setattr(api_module, "_running_scan_worker_count_best_effort", lambda: 4)

    _, payload, enabled, worker_count = _resolve_auto_shard_policy(api_module.ScanOptions(scan_type="smart"))

    assert enabled is False
    assert worker_count is None
    assert payload["parallel"] is False
    assert "auto_sharded" not in payload


def test_auto_sharding_uses_coverage_for_active_scan_when_enabled(monkeypatch):
    monkeypatch.setattr(api_module, "_load_effective_scan_execution_settings", lambda: _auto_shard_settings(True))
    monkeypatch.setattr(api_module, "_running_scan_worker_count_best_effort", lambda: 6)

    _, payload, enabled, worker_count = _resolve_auto_shard_policy(api_module.ScanOptions(scan_type="smart"))

    assert enabled is True
    assert worker_count == 6
    assert payload["parallel"] is True
    assert payload["auto_sharded"] is True
    assert payload["shard_strategy"] == "coverage"
    assert payload["shards"] == 4
    assert "endpoint coverage" in payload["auto_sharding_reason"]


def test_auto_sharding_honors_explicit_family_strategy(monkeypatch):
    monkeypatch.setattr(
        api_module,
        "_load_effective_scan_execution_settings",
        lambda: _auto_shard_settings(True, auto_sharding_strategy="family"),
    )
    monkeypatch.setattr(api_module, "_running_scan_worker_count_best_effort", lambda: 6)

    _, payload, enabled, worker_count = _resolve_auto_shard_policy(api_module.ScanOptions(scan_type="smart"))

    assert enabled is True
    assert worker_count == 6
    assert payload["parallel"] is True
    assert payload["shard_strategy"] == "family"
    assert payload["shards"] == 3


def test_auto_sharding_uses_scope_for_explicit_endpoint_list(monkeypatch):
    monkeypatch.setattr(api_module, "_load_effective_scan_execution_settings", lambda: _auto_shard_settings(True))
    monkeypatch.setattr(api_module, "_running_scan_worker_count_best_effort", lambda: 4)

    _, payload, enabled, _ = _resolve_auto_shard_policy(api_module.ScanOptions(
        scan_type="standard",
        custom_endpoints=["GET /api/users", "POST /api/login", "GET /api/basket"],
    ))

    assert enabled is True
    assert payload["parallel"] is True
    assert payload["shard_strategy"] == "scope"
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
    assert payload["shard_strategy"] == "coverage"


def test_full_coverage_dynamic_allocation_options_survive_api_payload():
    options = api_module.ScanOptions(
        scan_type="smart",
        parallel=True,
        shard_strategy="coverage",
        coverage_allocation="dynamic",
        coverage_dynamic_batch_size=25,
        coverage_dynamic_max_batches=40,
    )

    scan_type = api_module.normalize_dast_scan_options(options)
    payload = api_module._build_scan_options_payload(options, scan_type)

    assert payload["shard_strategy"] == "coverage"
    assert payload["coverage_allocation"] == "dynamic"
    assert payload["coverage_dynamic_batch_size"] == 25
    assert payload["coverage_dynamic_max_batches"] == 40


def test_coverage_family_strategy_survives_api_payload():
    options = api_module.ScanOptions(
        scan_type="smart",
        parallel=True,
        shard_strategy="coverage_family",
        coverage_allocation="static",
        coverage_max_shards=12,
    )

    scan_type = api_module.normalize_dast_scan_options(options)
    payload = api_module._build_scan_options_payload(options, scan_type)

    assert payload["shard_strategy"] == "coverage_family"
    assert payload["coverage_allocation"] == "static"
    assert payload["coverage_max_shards"] == 12


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


def test_enqueue_finding_retest_creates_campaign(monkeypatch):
    class FakeConn:
        def __init__(self):
            self.executions = []

        async def fetchrow(self, *args, **kwargs):
            return None

        async def execute(self, query, *args):
            self.executions.append((query, args))
            return "INSERT 0 1"

    campaign_id = uuid.uuid4()
    calls = {}

    async def fake_create_campaign(conn, target_id, **kwargs):
        calls["campaign"] = {"target_id": target_id, **kwargs}
        return str(campaign_id)

    monkeypatch.setattr(api_module.asm_inventory, "create_campaign", fake_create_campaign)
    conn = FakeConn()
    finding_id = uuid.uuid4()
    target_id = uuid.uuid4()

    retest_id, job_id = asyncio.run(api_module.enqueue_finding_retest(
        conn,
        {"id": finding_id, "target_id": target_id, "scan_id": None},
        {
            "finding_type": "sqli",
            "target_url": "https://app.test",
            "original_url": "https://app.test/login",
            "method": "POST",
            "param": "email",
        },
        requested_by="tester",
    ))

    assert retest_id
    assert job_id
    assert calls["campaign"]["target_id"] == str(target_id)
    assert calls["campaign"]["mode"] == api_module.asm_inventory.CAMPAIGN_FINDING_RETEST
    insert = next(args for query, args in conn.executions if "INSERT INTO finding_verifications" in query)
    assert insert[-1] == campaign_id


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


# --- Focused check_family auto-sharding policy (locked: this path has regressed) ---

def test_focused_family_runs_direct_without_explicit_parallel(monkeypatch):
    # check_family=sqli, parallel omitted -> NOT auto-sharded into coverage; runs direct.
    monkeypatch.setattr(api_module, "_load_effective_scan_execution_settings", lambda: _auto_shard_settings(True))
    monkeypatch.setattr(api_module, "_running_scan_worker_count_best_effort", lambda: 4)
    _, payload, enabled, _ = _resolve_auto_shard_policy(
        api_module.ScanOptions(scan_type="smart", check_family="sqli")
    )
    assert enabled is False
    assert payload["parallel"] is False


def test_focused_family_explicit_parallel_uses_coverage_family_not_coverage(monkeypatch):
    # parallel:true + check_family=sqli must fan out as coverage_family (single-family
    # lanes), never broad coverage which dilutes/skips the requested family.
    monkeypatch.setattr(api_module, "_load_effective_scan_execution_settings", lambda: _auto_shard_settings(True))
    monkeypatch.setattr(api_module, "_running_scan_worker_count_best_effort", lambda: 4)
    _, payload, enabled, _ = _resolve_auto_shard_policy(
        api_module.ScanOptions(scan_type="smart", check_family="sqli", parallel=True)
    )
    assert enabled is True
    assert payload["parallel"] is True
    assert payload["shard_strategy"] == "coverage_family"


def test_focused_family_explicit_coverage_strategy_redirected_to_coverage_family(monkeypatch):
    # Explicit shard_strategy=coverage + a focused family is redirected so the
    # focused family is not diluted by broad lanes.
    monkeypatch.setattr(api_module, "_load_effective_scan_execution_settings", lambda: _auto_shard_settings(True))
    monkeypatch.setattr(api_module, "_running_scan_worker_count_best_effort", lambda: 4)
    _, payload, _, _ = _resolve_auto_shard_policy(
        api_module.ScanOptions(scan_type="smart", check_family="sqli", parallel=True, shard_strategy="coverage")
    )
    assert payload["shard_strategy"] == "coverage_family"


def test_focused_family_with_endpoint_list_uses_scope_not_coverage(monkeypatch):
    # custom_endpoints partition by scope; each shard still runs the focused family,
    # so this is fine (no dilution) — but it must be scope, not broad coverage.
    monkeypatch.setattr(api_module, "_load_effective_scan_execution_settings", lambda: _auto_shard_settings(True))
    monkeypatch.setattr(api_module, "_running_scan_worker_count_best_effort", lambda: 4)
    _, payload, enabled, _ = _resolve_auto_shard_policy(
        api_module.ScanOptions(
            scan_type="smart", check_family="sqli",
            custom_endpoints=["GET /a?id=1", "GET /b?id=2", "GET /c?id=3"],
        )
    )
    assert enabled is True
    assert payload["shard_strategy"] == "scope"
