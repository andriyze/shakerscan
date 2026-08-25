"""MCP-to-ASGI contract tests using the real Hunt request models and normalizer.

The lightweight MCP unit doubles deliberately prove transport failures. These tests prevent those
doubles from masking drift at the actual FastAPI/Pydantic boundary.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


pytest.importorskip("asyncpg")
pytest.importorskip("fastapi")
from fastapi.testclient import TestClient
from pydantic import ValidationError


ROOT = Path(__file__).resolve().parents[1]
MCP_SPEC = importlib.util.spec_from_file_location(
    "shakerscan_mcp_asgi_contract", ROOT / "scripts" / "shakerscan_mcp.py",
)
assert MCP_SPEC and MCP_SPEC.loader
mcp = importlib.util.module_from_spec(MCP_SPEC)
sys.modules[MCP_SPEC.name] = mcp
MCP_SPEC.loader.exec_module(mcp)

from api import api as api_module  # noqa: E402


class MCPAgainstASGI(mcp.ArsenalClient):
    def __init__(self, http: TestClient):
        super().__init__("http://127.0.0.1:8080")
        self.http = http

    def request_json(self, method, path, payload=None):
        response = self.http.request(method, path, json=payload)
        if response.status_code >= 400:
            raise mcp.MCPError(
                -32002,
                f"ShakerScan API returned HTTP {response.status_code}",
                response.text,
            )
        decoded = response.json()
        assert isinstance(decoded, dict)
        return decoded


@pytest.fixture
def hunt_asgi(monkeypatch):
    captured = []

    async def fake_start(contract):
        captured.append(contract)
        return {
            "hunt_id": f"hunt-{len(captured)}",
            "target_kind": contract.target_kind,
            "target_id": contract.target_id,
            "objective": contract.goal,
            "status": "active",
            "budget_profile": contract.budget_profile,
            "policy": contract.policy.public_dict(),
            "budget": contract.resolved_budget,
            "budget_used": {},
            "capabilities": [],
            "context_pack": {},
        }

    # The product router receives its handler once during application startup.
    # Patch the exact registered endpoint module because the complete-suite
    # runner deliberately exercises both supported import layouts.
    registered_routes = (
        nested
        for route in api_module.app.routes
        for nested in getattr(
            getattr(route, "original_router", None), "routes", (route,)
        )
    )
    start_route = next(
        route
        for route in registered_routes
        if getattr(route, "path", None) == "/hunts"
        and "POST" in (getattr(route, "methods", None) or ())
    )
    monkeypatch.setitem(start_route.endpoint.__globals__, "_start_handler", fake_start)
    http = TestClient(api_module.app)
    return MCPAgainstASGI(http), http, captured


def _mcp_start(**updates):
    payload = {
        "schema_version": "hunt-start/v2",
        "target_id": "target-1",
        "target_kind": "web",
        "goal": "Inspect the exact authorized target.",
        "budget_profile": "fast",
        "policy": {},
    }
    payload.update(updates)
    return payload


@pytest.mark.parametrize(
    "updates",
    [
        {},
        {
            "policy": {
                "active_testing": True,
                "authorization_confirmed": True,
                "approval_receipt_id": "approval-web-1",
            },
        },
        {
            "target_kind": "api",
            "credential_refs": {
                "primary_credential_profile_id": "principal-primary",
                "secondary_credential_profile_id": "principal-secondary",
            },
            "request_collection_ids": ["collection-api-1"],
            "policy": {
                "authorization_confirmed": True,
                "approval_receipt_id": "approval-api-1",
            },
        },
        {
            "target_kind": "network",
            "policy": {
                "active_testing": True,
                "network_discovery": True,
                "authorization_confirmed": True,
                "approval_receipt_id": "approval-network-1",
            },
        },
        {
            "target_kind": "device",
            "credential_refs": {
                "service_credential_profile_id": "device-service",
                "ssh_credential_profile_id": "device-ssh",
            },
            "request_collection_ids": ["collection-device-1"],
            "policy": {
                "authorization_confirmed": True,
                "approval_receipt_id": "approval-device-1",
            },
        },
    ],
    ids=["passive-web", "active-web", "api-principals", "network", "device"],
)
def test_mcp_hunt_start_is_accepted_by_real_asgi_models(hunt_asgi, updates):
    client, _http, captured = hunt_asgi

    result = client.call_tool("shakerscan_hunt_start", _mcp_start(**updates))

    assert result["structuredContent"]["status"] == "active"
    assert len(captured) == 1
    assert captured[0].schema_version == "hunt-start/v2"
    assert captured[0].target_kind == updates.get("target_kind", "web")
    assert captured[0].goal == "Inspect the exact authorized target."


def test_mcp_hunt_start_preserves_explicit_zero_ceilings_at_asgi_boundary(hunt_asgi):
    client, _http, captured = hunt_asgi
    zeroable = {
        "max_active_actions": 0,
        "max_browser_actions": 0,
        "max_state_changing_requests": 0,
        "max_device_fragility_points": 0,
        "max_hosts": 0,
        "max_tcp_ports": 0,
        "max_udp_ports": 0,
        "max_oob_interactions": 0,
    }

    client.call_tool("shakerscan_hunt_start", _mcp_start(budgets=zeroable))

    assert captured[0].budgets == zeroable


@pytest.mark.parametrize(
    "payload",
    [
        _mcp_start(target_kind="database"),
        {key: value for key, value in _mcp_start().items() if key != "policy"},
        _mcp_start(
            credential_refs={"password": "raw-secret-value"},
            policy={
                "authorization_confirmed": True,
                "approval_receipt_id": "approval-1",
            },
        ),
    ],
    ids=["invalid-target-kind", "missing-policy", "raw-secret"],
)
def test_real_hunt_asgi_boundary_rejects_invalid_mcp_shapes(hunt_asgi, payload):
    _client, http, captured = hunt_asgi

    response = http.post("/hunts", json=payload)

    assert response.status_code == 422
    assert not captured
    assert "raw-secret-value" not in response.text


def test_real_capability_request_model_requires_retry_identity():
    accepted = api_module.HuntCapabilityRequest.model_validate({
        "idempotency_key": "mcp-operation-1",
        "input": {},
    })
    assert accepted.idempotency_key == "mcp-operation-1"

    with pytest.raises(ValidationError):
        api_module.HuntCapabilityRequest.model_validate({"input": {}})
