"""Profiled sqli.verify runs through admission, the queue and the worker at its useful hold.

Admission reserves the thorough hold, the API waits for the reserved wall, and the worker
re-derives the same hold from the Hunt row, verifies the action digest against it and hands the
process the same wall. A call the remaining ledger cannot fund waits for an operator raise
instead of silently shortening its wall. A call admitted at the registry hold, the only hold
before per-profile holds existed, still dispatches after the upgrade and runs at that hold.

Labelled doubles, and only these: Redis (an in-memory dictionary; the queue hands the job straight
to the worker), the per-call active approval check, and the scanner process (it records the
payload, builds the real enforced plan for it, and reports a successful run without starting
sqlmap; no traffic leaves the test).
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from tests.test_hunt_live_grant_dispatch_postgres import (  # noqa: E402
    DSN, LEDGER, TARGET_URL, FakeRedis, _database,
)

pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")

TARGET_ADDRESS = "203.0.113.10"
PATH = "/item?id=1"


async def _active_hunt(pool, profile, **budget_overrides):
    from hunt.start_contract import HUNT_BUDGET_PROFILES
    from target_authorization import authorize_target

    async with pool.acquire() as conn:
        target = await conn.fetchval("INSERT INTO targets(url) VALUES($1) RETURNING id", TARGET_URL)
        standing = await authorize_target(conn, target, approved_by="alice@example.test")
        budget = {**vars(HUNT_BUDGET_PROFILES[profile]), **budget_overrides}
        allowed = ["sqli.verify"]
        policy = {
            "schema_version": "hunt-policy/v2", "target_kind": "web", "active_testing": True,
            "credential_access": False, "allow_state_changing_http": False, "network_discovery": False,
            "allow_oob_interactions": False, "allow_identity_headers": False, "allow_direct_origin": False,
            "authorization_confirmed": True, "approval_receipt_id": str(standing["approval_receipt_id"]),
            "scope_receipt_id": str(standing["scope_receipt_id"]), "budget_profile": profile,
            "budget": budget, "allowed_capabilities": allowed,
        }
        context = {
            "schema_version": "hunt-context/v2",
            "target": {"id": str(target), "kind": "web", "url": TARGET_URL, "origins": [TARGET_URL],
                       "environment": "production"},
            "authorized_target_addresses": [TARGET_ADDRESS], "credential_refs": [],
            "allowed_capabilities": allowed, "hunt_start_contract": {"resolved_budget": budget},
        }
        row = await conn.fetchrow(
            """INSERT INTO hunt_runs(target_kind,target_id,objective,status,budget_profile,policy_json,
                                     budget_json,budget_used_json,context_pack,created_by,approval_receipt_id)
               VALUES('web',$1,'thorough scanner hold','active',$2,$3::jsonb,$4::jsonb,$5::jsonb,
                      $6::jsonb,'fixture',$7) RETURNING *""",
            target, profile, json.dumps(policy), json.dumps(budget),
            json.dumps({key: 0 for key in LEDGER}), json.dumps(context),
            uuid.UUID(str(standing["approval_receipt_id"])),
        )
    return dict(row), standing


@pytest.fixture
def stack(monkeypatch):
    import agent_tools as worker_agent_tools
    import worker
    from hunt import interaction_router as router

    loop = asyncio.new_event_loop()
    pool, drop = loop.run_until_complete(_database())
    redis = FakeRedis()
    workers: list[asyncio.Task] = []
    waits: list[int] = []
    processes: list[dict] = []
    enqueue_real = router._enqueue_canonical_scanner_capability

    async def enqueue_recorded(**kwargs):
        waits.append(int(kwargs["timeout_ms"]))
        return await enqueue_real(**kwargs)

    def enqueue(_redis, _queue, payload):
        workers.append(asyncio.get_running_loop().create_task(
            worker.process_canonical_scanner_capability_job(payload)
        ))

    async def process(payload, *, heartbeat=None):  # labelled double: the scanner process
        processes.append({key: value for key, value in payload.items() if key != "_cancelled"})
        plan = worker_agent_tools.build_enforced_scanner_plan(
            payload["tool_name"], payload["execution_target"], dict(payload["scanner_options"]),
            reserved_budget=payload["_reserved_budget"], pinned_address=payload["pinned_address"],
            pinned_proxy_url="socks5://127.0.0.1:41000",
            runtime_paths={"sqlmap_output_dir": "/tmp/shakerscan-sqlmap-fixture"},
        )
        processes[-1]["plan_timeout_ms"] = plan.timeout_ms
        processes[-1]["hard_budget"] = plan.hard_budget_dict
        return {
            "status": "success", "error": None, "partial": False, "timed_out": False,
            "elapsed_seconds": 500, "process_enforcement": plan.enforcement_receipt(),
            "settlement": {"mode": "exact", "actual": 432, "observed_minimum": 432,
                           "source": "wire_log"},
            "typed_output": {"parser_status": "parsed", "records": [], "record_count": 0},
        }

    async def approval(*_args, **_kwargs):  # labelled double: the per-call active approval
        return {"scope_receipt_id": stack_state["scope_receipt_id"]}

    stack_state: dict = {}
    monkeypatch.setattr(router, "_pool", lambda: pool)
    monkeypatch.setattr(router, "get_redis", lambda: redis)
    monkeypatch.setattr(router, "enqueue_job", enqueue)
    monkeypatch.setattr(router, "_enqueue_canonical_scanner_capability", enqueue_recorded)
    monkeypatch.setattr(router, "_hunt_redacted_capability_input", lambda _name, values: dict(values))
    monkeypatch.setitem(router._deps, "AGENT_TOOL_QUEUE_NAME", lambda: "agent-tools-fixture")
    monkeypatch.setitem(router._deps, "_validate_approval_receipt_for_action", lambda: approval)
    monkeypatch.setattr(worker, "db_pool", pool)
    monkeypatch.setattr(worker, "get_redis", lambda: redis)
    monkeypatch.setattr(worker, "_execute_agent_scanner_process", process)

    class Stack:
        pass

    environment = Stack()
    environment.pool, environment.loop, environment.router = pool, loop, router
    environment.workers, environment.waits, environment.processes = workers, waits, processes
    environment.state = stack_state
    yield environment
    loop.run_until_complete(drop())
    loop.close()


async def _call(stack, hunt, key):
    from fastapi import HTTPException

    request = stack.router.HuntCapabilityRequest(idempotency_key=key, input={"path": PATH})
    try:
        return await stack.router.execute_hunt_capability(str(hunt["id"]), "sqli.verify", request)
    except HTTPException as exc:
        return exc
    finally:
        if stack.workers:
            await asyncio.gather(*stack.workers)


async def _reservation(pool, hunt, key):
    action_id = uuid.uuid5(uuid.UUID(str(hunt["id"])), f"hunt-capability:{key}")
    async with pool.acquire() as conn:
        action = await conn.fetchrow("SELECT status FROM hunt_actions WHERE id=$1", action_id)
        row = await conn.fetchrow(
            "SELECT * FROM budget_reservations WHERE owner_kind='hunt' AND owner_id=$1 AND action_id=$2",
            str(hunt["id"]), str(action_id))
    def decode(value):
        return json.loads(value) if isinstance(value, str) else dict(value or {})

    return action["status"], dict(row), decode


@pytest.mark.parametrize("profile,wall", [("fast", 1_200), ("balanced", 1_200), ("thorough", 1_200)])
def test_the_hunt_profile_sizes_the_hold_the_wait_and_the_process_wall(stack, profile, wall):
    async def scenario():
        hunt, standing = await _active_hunt(stack.pool, profile)
        stack.state["scope_receipt_id"] = str(standing["scope_receipt_id"])
        result = await _call(stack, hunt, f"{profile}-sqli-0001")
        assert not isinstance(result, Exception), getattr(result, "detail", result)
        assert result["action_result"]["status"] == "success", result
        status, reservation, decode = await _reservation(stack.pool, hunt, f"{profile}-sqli-0001")
        assert status == "completed"
        assert reservation["status"] == "committed"
        requested = decode(reservation["requested_json"])
        assert requested["http_requests"] == 1_800 and requested["tool_wall_seconds"] == wall
        # The API waits for the reserved wall (plus its 30-second margin), counted from enqueue.
        assert stack.waits == [wall * 1_000]
        (process,) = stack.processes
        assert process["timeout_ms"] == wall * 1_000
        assert process["_reserved_budget"]["tool_wall_seconds"] == wall
        assert process["plan_timeout_ms"] == wall * 1_000
        assert process["hard_budget"] == {"http_requests": 1_800, "tool_wall_seconds": wall}

    stack.loop.run_until_complete(scenario())


def test_an_unfunded_useful_hold_waits_for_a_raise_then_dispatches_with_the_same_key(stack):
    """A 500 s total cannot fund a 1,200 s call. No worker starts until the operator raises it;
    retrying the same parked key then reserves and runs the full envelope exactly once."""
    async def scenario():
        from fastapi import HTTPException
        from hunt.budget_amendments import HuntBudgetAmendmentRequest
        from hunt.run_service import HuntRunService
        hunt, standing = await _active_hunt(stack.pool, "thorough", max_duration_seconds=500)
        stack.state["scope_receipt_id"] = str(standing["scope_receipt_id"])
        key = "useful-sqli-0001"
        result = await _call(stack, hunt, key)
        assert isinstance(result, HTTPException)
        assert result.detail["reason_code"] == "budget_insufficient_for_action"
        assert result.detail["shortages"] == {"tool_wall_seconds": 700}
        assert result.detail["permission_request"]["kind"] == "budget.raise"
        assert stack.waits == stack.workers == stack.processes == []
        async with stack.pool.acquire() as conn:
            assert await conn.fetchval("SELECT status FROM hunt_actions WHERE hunt_run_id=$1", hunt["id"]) == "awaiting_permission"
            assert await conn.fetchval("SELECT count(*) FROM budget_reservations WHERE owner_id=$1", str(hunt["id"])) == 0
            used = await conn.fetchval("SELECT budget_used_json FROM hunt_runs WHERE id=$1", hunt["id"])
            assert all(value == 0 for value in json.loads(used).values())
        await HuntRunService(lambda: stack.pool).amend_budget(str(hunt["id"]), HuntBudgetAmendmentRequest(
            limits={"max_duration_seconds": 1_300}, expected_revision=0, operator_confirmed=True,
            idempotency_key="operator-funds-useful-verifier", resume=False,
        ))
        result = await _call(stack, hunt, key)
        assert not isinstance(result, Exception), getattr(result, "detail", result)
        assert result["action_result"]["status"] == "success", result
        status, reservation, decode = await _reservation(stack.pool, hunt, key)
        assert status == "completed" and reservation["status"] == "committed"
        requested = decode(reservation["requested_json"])
        assert requested["http_requests"] == 1_800 and requested["tool_wall_seconds"] == 1_200
        assert stack.waits == [1_200_000]
        (process,) = stack.processes
        assert process["timeout_ms"] == process["plan_timeout_ms"] == 1_200_000
        assert process["hard_budget"] == {"http_requests": 1_800, "tool_wall_seconds": 1_200}

    stack.loop.run_until_complete(scenario())


def test_a_thorough_call_admitted_at_the_registry_hold_still_runs_at_that_hold(stack, monkeypatch):
    """An API that predates per-profile holds admitted every sqli.verify at 900 / 300 s. A worker
    that has them must accept that durable action (digest verified against the registry hold)
    rather than refuse it as a payload that does not match its action."""
    current = stack.router.agent_tools

    class OlderAdmission:  # labelled double: admission as an API without per-profile holds ran it
        def __getattr__(self, name):
            return getattr(current, name)

        @staticmethod
        def hunt_scanner_dispatch_budgets(name, **_context):
            return (current.canonical_hunt_scanner_budget(name),)

    # Only the API side changes; the worker keeps the current module.
    monkeypatch.setattr(stack.router, "agent_tools", OlderAdmission())

    async def scenario():
        hunt, standing = await _active_hunt(stack.pool, "thorough")
        stack.state["scope_receipt_id"] = str(standing["scope_receipt_id"])
        result = await _call(stack, hunt, "legacy-sqli-0001")
        assert not isinstance(result, Exception), getattr(result, "detail", result)
        assert result["action_result"]["status"] == "success", result
        status, reservation, decode = await _reservation(stack.pool, hunt, "legacy-sqli-0001")
        assert status == "completed" and reservation["status"] == "committed"
        assert decode(reservation["requested_json"])["tool_wall_seconds"] == 300
        assert stack.waits == [300_000]
        (process,) = stack.processes
        assert process["timeout_ms"] == 300_000
        assert process["hard_budget"] == {"http_requests": 900, "tool_wall_seconds": 300}

    stack.loop.run_until_complete(scenario())
