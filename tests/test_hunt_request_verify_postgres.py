"""request.verify end to end: the production admission route, enqueue and HTTP worker on one database.

The Hunt calls ``request.verify``; admission checks its input and authority and reserves its hold;
the worker resolves the request, runs the check and settles what it sent; a verified proof becomes
a finding. Labelled doubles, and only these: Redis (an in-memory dictionary; the queue hands the
job straight to the worker), the per-call active approval (the target's standing authorization
answers it), the receipt redaction of the input, and the pinned transport (a fake application
answering in process; no traffic leaves the test).
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import sys
import urllib.parse
import uuid

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from tests.test_hunt_live_grant_dispatch_postgres import FakeRedis, _database  # noqa: E402

DSN = os.environ.get("HUNT_TEST_POSTGRES_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL DSN not configured")

TARGET_URL = "https://app.example.com"
LEDGER = (
    "agent_actions", "active_actions", "http_requests", "tcp_ports_attempted", "browser_actions",
    "state_changing_requests", "tool_wall_seconds", "device_fragility_points", "hosts_attempted",
    "udp_ports_attempted", "oob_interactions", "candidates", "verifications", "verifier_write_requests",
)


async def _hunt(pool, *, state_changing: bool = True):
    from hunt.start_contract import HUNT_BUDGET_PROFILES
    from target_authorization import authorize_target

    async with pool.acquire() as conn:
        target = await conn.fetchval("INSERT INTO targets(url) VALUES($1) RETURNING id", TARGET_URL)
        standing = await authorize_target(conn, target, approved_by="alice@example.test")
        budget = dict(vars(HUNT_BUDGET_PROFILES["fast"]))
        allowed = ["http.request", "request.verify"]
        policy = {
            "schema_version": "hunt-policy/v2", "target_kind": "web", "active_testing": True,
            "credential_access": False, "allow_state_changing_http": state_changing, "network_discovery": False,
            "allow_oob_interactions": False, "allow_identity_headers": False, "allow_direct_origin": False,
            "authorization_confirmed": True, "approval_receipt_id": str(standing["approval_receipt_id"]),
            "scope_receipt_id": str(standing["scope_receipt_id"]), "budget_profile": "fast",
            "budget": budget, "allowed_capabilities": allowed,
        }
        context = {
            "schema_version": "hunt-context/v2",
            "target": {"id": str(target), "kind": "web", "url": TARGET_URL, "origins": [TARGET_URL],
                       "environment": "production"},
            "authorized_target_addresses": ["203.0.113.10"], "credential_refs": [],
            "allowed_capabilities": allowed, "hunt_start_contract": {"resolved_budget": budget},
        }
        row = await conn.fetchrow(
            """INSERT INTO hunt_runs(target_kind,target_id,objective,status,budget_profile,policy_json,
                                     budget_json,budget_used_json,context_pack,created_by,approval_receipt_id)
               VALUES('web',$1,'request.verify','active','fast',$2::jsonb,$3::jsonb,$4::jsonb,$5::jsonb,
                      'fixture',$6) RETURNING *""",
            target, json.dumps(policy), json.dumps(budget), json.dumps({key: 0 for key in LEDGER}),
            json.dumps(context), uuid.UUID(str(standing["approval_receipt_id"])),
        )
    return {**dict(row), "scope_receipt_id": str(standing["scope_receipt_id"])}


class FakeApplication:
    """Labelled double for the pinned transport: an application with an open redirect at /go and a
    reset form that writes the Host header into its answer."""

    sent: list = []

    def __init__(self, *args, **kwargs):
        pass

    async def send(self, request, *, target, timeout_seconds, follow_redirects):
        from runtime.request_replay_executor import ReplayTransportResult

        assert not follow_redirects and target.canonical_host == "app.example.com"
        FakeApplication.sent.append(request)
        parsed = urllib.parse.urlsplit(request.url)
        headers, status, body = {"Content-Type": "application/json"}, 200, b"{}"
        if parsed.path == "/go":
            status = 302
            headers["Location"] = urllib.parse.parse_qs(parsed.query).get("next", ["/"])[0]
        elif parsed.path == "/reset":
            host = next((value for name, value in request.headers if name.lower() == "host"), "app.example.com")
            body = json.dumps({"reset": True, "link": f"https://{host}/r?t=1"}).encode()
        return ReplayTransportResult(
            status_code=status, connected_address="203.0.113.10", final_url=request.url,
            response_headers=headers, response_body=body, elapsed_ms=3,
        )


@pytest.fixture
def stack(monkeypatch):
    import worker
    from hunt import interaction_router as router
    from hunt import request_verification

    loop = asyncio.new_event_loop()
    pool, drop = loop.run_until_complete(_database())
    redis = FakeRedis()
    workers: list[asyncio.Task] = []

    def enqueue(_redis, _queue, payload):
        workers.append(asyncio.get_running_loop().create_task(worker.process_canonical_http_capability_job(payload)))

    scope = {}

    async def approval(*_args, **_kwargs):  # labelled double: the per-call active approval
        return {"scope_receipt_id": scope.get("id")}

    FakeApplication.sent = []
    monkeypatch.setitem(router._deps, "_validate_approval_receipt_for_action", lambda: approval)
    monkeypatch.setattr(router, "_hunt_redacted_capability_input", lambda _name, values: dict(values))
    monkeypatch.setattr(worker, "RESULTS_DIR", Path("/tmp"))
    monkeypatch.setattr(request_verification, "PinnedAiohttpReplayTransport", FakeApplication)
    monkeypatch.setattr(router, "_pool", lambda: pool)
    monkeypatch.setattr(router, "get_redis", lambda: redis)
    monkeypatch.setattr(router, "enqueue_job", enqueue)
    monkeypatch.setitem(router._deps, "AGENT_TOOL_QUEUE_NAME", lambda: "agent-tools-fixture")
    monkeypatch.setattr(worker, "db_pool", pool)
    monkeypatch.setattr(worker, "get_redis", lambda: redis)

    class Stack:
        pass

    environment = Stack()
    environment.pool, environment.loop, environment.router, environment.workers = pool, loop, router, workers
    environment.scope = scope
    yield environment
    loop.run_until_complete(drop())
    loop.close()


async def _call(stack, hunt, key, values):
    from fastapi import HTTPException

    request = stack.router.HuntCapabilityRequest(idempotency_key=key, input=values)
    try:
        return await stack.router.execute_hunt_capability(str(hunt["id"]), "request.verify", request)
    except HTTPException as exc:
        return exc
    finally:
        if stack.workers:
            await asyncio.gather(*stack.workers)


async def _state(pool, hunt, key):
    action_id = uuid.uuid5(uuid.UUID(str(hunt["id"])), f"hunt-capability:{key}")
    async with pool.acquire() as conn:
        action = await conn.fetchrow("SELECT * FROM hunt_actions WHERE id=$1", action_id)
        used = await conn.fetchval("SELECT budget_used_json FROM hunt_runs WHERE id=$1", hunt["id"])
        findings = await conn.fetch("SELECT tool, cwe, url, evidence FROM findings WHERE hunt_run_id=$1", hunt["id"])
    summary = action["result_summary"] if action else None
    return (dict(action) if action else None,
            json.loads(summary) if isinstance(summary, str) else dict(summary or {}),
            json.loads(used) if isinstance(used, str) else dict(used), [dict(row) for row in findings])


def test_a_proven_open_redirect_becomes_a_finding_and_settles_what_it_sent(stack):
    async def scenario():
        hunt = await _hunt(stack.pool)
        stack.scope["id"] = hunt["scope_receipt_id"]
        result = await _call(stack, hunt, "rv-redirect-01", {
            "check": "open_redirect", "method": "GET", "path": "/go", "query": {"next": "/home"},
            "parameter": "next"})
        assert not isinstance(result, Exception), getattr(result, "detail", result)
        action, summary, used, findings = await _state(stack.pool, hunt, "rv-redirect-01")
        assert action["status"] == "completed", summary
        assert summary["verified_finding_ids"], summary
        assert [(row["tool"], row["cwe"]) for row in findings] == [("shakerscan_request_verify", "CWE-601")]
        evidence = findings[0]["evidence"]
        evidence = json.loads(evidence) if isinstance(evidence, str) else evidence
        assert evidence["canonical_capability"] == "request.verify" and evidence["param"] == "next"
        assert used["http_requests"] == len(FakeApplication.sent) == 4  # baseline, probe, repeat, control
        assert int(used.get("state_changing_requests") or 0) == 0
        assert int(used.get("verifier_write_requests") or 0) == 0

    stack.loop.run_until_complete(scenario())


def test_a_writing_check_is_held_and_settled_as_verifier_writes(stack):
    async def scenario():
        hunt = await _hunt(stack.pool)
        stack.scope["id"] = hunt["scope_receipt_id"]
        result = await _call(stack, hunt, "rv-host-01", {
            "check": "host_header_injection", "method": "POST", "path": "/reset",
            "form_body": {"email": "a@example.test"}})
        assert not isinstance(result, Exception), getattr(result, "detail", result)
        action, summary, used, findings = await _state(stack.pool, hunt, "rv-host-01")
        assert action["status"] == "completed", summary
        assert [row["cwe"] for row in findings] == ["CWE-644"]
        sent = len(FakeApplication.sent)
        assert used["verifier_write_requests"] == sent and used["http_requests"] == sent
        assert int(used.get("state_changing_requests") or 0) == 0, "the planner's own write ceiling is untouched"

    stack.loop.run_until_complete(scenario())


def test_a_write_without_the_state_changing_permission_is_refused_before_anything_is_sent(stack):
    async def scenario():
        hunt = await _hunt(stack.pool, state_changing=False)
        stack.scope["id"] = hunt["scope_receipt_id"]
        refused = await _call(stack, hunt, "rv-refused-01", {
            "check": "host_header_injection", "method": "POST", "path": "/reset",
            "form_body": {"email": "a@example.test"}})
        assert getattr(refused, "status_code", None) in {403, 409}, refused
        detail = refused.detail
        assert detail.get("reason_code") == "state_changing_http_not_allowed", detail
        invalid = await _call(stack, hunt, "rv-refused-02", {
            "check": "path_traversal", "method": "GET", "path": "/view"})
        assert getattr(invalid, "status_code", None) == 422 and invalid.detail["reason_code"] == "request_verify_input_invalid"
        _action, _summary, used, findings = await _state(stack.pool, hunt, "rv-refused-02")
        assert FakeApplication.sent == [] and findings == []
        assert int(used.get("http_requests") or 0) == 0

    stack.loop.run_until_complete(scenario())
