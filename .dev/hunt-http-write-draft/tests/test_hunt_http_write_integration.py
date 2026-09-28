"""HTTP write regressions using the actual registry, receipt checker and transport.

The transport fixture is synthetic: these tests do not claim real-TV pairing or
PostgreSQL/Redis end-to-end worker coverage.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace
import uuid

import httpx
import pytest

from capabilities.http import execute_bound_http_request, resolve_hunt_http_origin
from capabilities.inline import HttpRequestExecutionAdapter
from runtime.capability_registry import CAPABILITY_REGISTRY, CapabilityInputContractError
from runtime.hunt_http_contract import require_http_request_authority
from runtime.models import TargetBinding
from scan.authorization import ActionAuthorityDecision, revalidate_action_authority

HOST = "tv.test"
ORIGIN = "http://tv.test:7345"
TARGET_ID = str(uuid.UUID(int=10))
SCOPE_ID = str(uuid.UUID(int=11))
APPROVAL_ID = str(uuid.UUID(int=12))
POLICY = {"active_testing": True, "allow_state_changing_http": True}
BUDGET = {"http_requests": 1, "state_changing_requests": 1,
          "active_actions": 1, "agent_actions": 1, "tool_wall_seconds": 15}


def target():
    return TargetBinding(target_id=TARGET_ID, target_kind="device", canonical_host=HOST,
                         allowed_addresses=("203.0.113.10",), allowed_origins=(ORIGIN,),
                         scope_receipt_id=SCOPE_ID)


def mock_http(monkeypatch, handler):
    original = httpx.AsyncClient

    class Client(original):
        def __init__(self, **kwargs):
            kwargs.pop("transport", None)
            super().__init__(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", Client)


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_real_registry_accepts_workflow_methods(method):
    inputs = {"method": method, "path": "/pairing/start", "json_body": {"device_name": "lab"}}
    assert CAPABILITY_REGISTRY.validate_hunt_input("http.request", inputs) == inputs
    assert "device" in CAPABILITY_REGISTRY.require("http.request").target_kinds


def test_real_registry_rejects_ambiguous_body_before_dispatch():
    with pytest.raises(CapabilityInputContractError):
        CAPABILITY_REGISTRY.validate_hunt_input("http.request", {
            "method": "PUT", "path": "/pairing/start", "json_body": {}, "form_body": {},
        })


def test_authorized_put_reaches_pinned_tv_and_consumes_write_budget(monkeypatch):
    seen = []
    archive = []
    inputs = {"method": "PUT", "path": "/pairing/start", "json_body": {"device_name": "lab"}}
    inputs = CAPABILITY_REGISTRY.validate_hunt_input("http.request", inputs)
    write = require_http_request_authority(inputs, POLICY, requested_budget=BUDGET)

    def handle(request):
        seen.append(request)
        assert request.method == "PUT"
        assert request.url.host == "203.0.113.10"
        assert request.headers["host"] == "tv.test:7345"
        assert json.loads(request.content) == {"device_name": "lab"}
        return httpx.Response(200, json={"status": "pairing_started"})

    mock_http(monkeypatch, handle)

    async def run():
        async def operation():
            return await execute_bound_http_request(
                ORIGIN, inputs, target=target(), allow_write=write,
                transaction_recorder=archive.append,
            )

        async def heartbeat():
            pass

        return await HttpRequestExecutionAdapter(
            specification=CAPABILITY_REGISTRY.require("http.request"),
            operation=operation, requested_budget=BUDGET, redacted_execution={"method": "PUT"},
        ).execute(heartbeat=heartbeat, cancelled=lambda: False)

    result = asyncio.run(run())
    assert result.status == "success"
    assert result.actual_budget["http_requests"] == 1
    assert result.actual_budget["state_changing_requests"] == 1
    assert len(seen) == len(archive) == 1
    assert "lab" not in json.dumps(result.observations)


def test_passive_transport_does_not_send_put(monkeypatch):
    seen = []
    mock_http(monkeypatch, lambda request: seen.append(request) or httpx.Response(200))
    result = asyncio.run(execute_bound_http_request(
        ORIGIN, {"method": "PUT", "path": "/pairing/start", "json_body": {}},
        target=target(), allow_write=False,
    ))
    assert result["needs_approval"] is True
    assert seen == []


@pytest.mark.parametrize("outcome,expected", [
    ({"ok": False, "needs_approval": True, "error": "missing permission"}, 0),
    ({"ok": False, "request": {"method": "PUT"}, "error": "request_error:ReadTimeout"}, 1),
    ({"ok": True, "request": {"method": "PUT"}, "response": {"status": 200}}, 1),
])
def test_write_accounting_distinguishes_pretraffic_and_lost_response(outcome, expected):
    async def run():
        async def operation():
            return outcome

        async def heartbeat():
            pass

        return await HttpRequestExecutionAdapter(
            specification=CAPABILITY_REGISTRY.require("http.request"),
            operation=operation, requested_budget=BUDGET, redacted_execution={},
        ).execute(heartbeat=heartbeat, cancelled=lambda: False)

    result = asyncio.run(run())
    assert result.actual_budget["state_changing_requests"] == expected


def receipt_fixture():
    scope = {"id": SCOPE_ID, "target_id": TARGET_ID, "allowed_hosts": [HOST], "verdict": "allowed"}
    approval = {"id": APPROVAL_ID, "scope_receipt_id": SCOPE_ID, "approved_by": "operator",
                "confirmations": ["confirm_authorized"], "action_name": "target.authorization",
                "risk_tier": "active", "expires_at": None}
    return scope, approval


@pytest.mark.parametrize("condition,expected", [
    ("standing", ActionAuthorityDecision.ALLOWED),
    ("missing", ActionAuthorityDecision.REJECTED_MISSING),
    ("revoked", ActionAuthorityDecision.REJECTED_REVOKED),
    ("expired", ActionAuthorityDecision.REJECTED_EXPIRED),
])
def test_put_does_not_inherit_passive_receipt_shortcut(condition, expected):
    scope, approval = receipt_fixture()
    if condition == "missing":
        approval = None
    elif condition == "revoked":
        approval["status"] = "revoked"
    elif condition == "expired":
        approval["expires_at"] = datetime.now(timezone.utc) - timedelta(minutes=1)
    decision = revalidate_action_authority(
        action=SimpleNamespace(capability_name="http.request", capability_input={"method": "PUT"}),
        target_binding=target(), scope_receipt=scope, approval_receipt=approval,
        scope_receipt_id=SCOPE_ID, approval_receipt_id=APPROVAL_ID,
    )
    assert decision is expected


def test_anonymous_read_remains_available_without_active_receipt():
    scope, _ = receipt_fixture()
    decision = revalidate_action_authority(
        action=SimpleNamespace(capability_name="http.request", capability_input={"method": "GET"}),
        target_binding=target(), scope_receipt=scope, scope_receipt_id=SCOPE_ID,
    )
    assert decision is ActionAuthorityDecision.ALLOWED


def test_alternate_service_reuses_authorized_asset_not_a_new_host():
    alternate = "https://tv.test:8443"
    admitted = resolve_hunt_http_origin(target(), alternate, POLICY)
    assert alternate in admitted.allowed_origins
    with pytest.raises(ValueError):
        resolve_hunt_http_origin(target(), "http://different.test:7345", POLICY)
