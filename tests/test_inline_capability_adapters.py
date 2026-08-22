from __future__ import annotations

import asyncio
import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from capabilities.inline import (
    HttpRequestExecutionAdapter,
    TlsInspectionExecutionAdapter,
)
from hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import TargetBinding


TARGET = TargetBinding(
    target_id="target-1",
    target_kind="web",
    canonical_host="app.example.test",
    allowed_origins=("https://app.example.test",),
    allowed_addresses=("192.0.2.10",),
    scope_receipt_id="scope-1",
)


def _execute(specification, adapter, requested):
    return asyncio.run(CapabilityExecutor().execute(
        CapabilityExecutionContext(
            specification=specification,
            target=TARGET,
            requested_budget=requested,
        ),
        adapter,
        heartbeat=lambda: asyncio.sleep(0),
        cancelled=lambda: False,
    ))


def test_http_adapter_counts_only_requests_that_reach_execution():
    specification = CAPABILITY_REGISTRY.require("http.request")
    requested = {
        "http_requests": 4,
        "tool_wall_seconds": 15,
        "agent_actions": 1,
    }

    async def operation():
        return {
            "ok": True,
            "request": {"method": "GET", "path": "/account"},
            "response": {"status": 200, "body_sha256": "a" * 64},
            "redirect_chain": [{"status": 302}, {"status": 302}],
            "hops_followed": 2,
        }

    result = _execute(
        specification,
        HttpRequestExecutionAdapter(
            specification=specification,
            operation=operation,
            requested_budget=requested,
            redacted_execution={"method": "GET", "path": "/account"},
        ),
        requested,
    )

    assert result.status == "success"
    assert result.actual_budget["http_requests"] == 3
    assert result.actual_budget["agent_actions"] == 1
    assert result.actual_budget["tool_wall_seconds"] == 1
    assert result.observations[0]["kind"] == "http_observation"


def test_http_adapter_does_not_charge_network_for_scope_block():
    specification = CAPABILITY_REGISTRY.require("http.request")
    requested = {
        "http_requests": 1,
        "tool_wall_seconds": 15,
        "agent_actions": 1,
    }

    async def operation():
        return {"ok": False, "error": "scope: frozen target changed"}

    result = _execute(
        specification,
        HttpRequestExecutionAdapter(
            specification=specification,
            operation=operation,
            requested_budget=requested,
            redacted_execution={"method": "GET", "path": "/"},
        ),
        requested,
    )

    assert result.status == "blocked"
    assert result.actual_budget == {"http_requests": 0, "agent_actions": 1}
    assert result.observations == ()


def test_tls_adapter_returns_typed_observation_and_measured_budget():
    specification = CAPABILITY_REGISTRY.require("tls.inspect")
    requested = {
        "tcp_ports_attempted": 1,
        "tool_wall_seconds": 15,
        "agent_actions": 1,
    }

    async def operation():
        return {
            "ok": True,
            "status": "success",
            "observation": {
                "kind": "tls_protocol",
                "protocol": "TLSv1.3",
            },
            "budget_consumed": {
                "tcp_ports_attempted": 1,
                "tool_wall_seconds": 2,
            },
        }

    result = _execute(
        specification,
        TlsInspectionExecutionAdapter(
            specification=specification,
            operation=operation,
            requested_budget=requested,
            redacted_execution={},
        ),
        requested,
    )

    assert result.status == "success"
    assert result.actual_budget == {
        "tcp_ports_attempted": 1,
        "tool_wall_seconds": 2,
        "agent_actions": 1,
    }
    assert result.observations == ({
        "kind": "tls_protocol", "protocol": "TLSv1.3",
    },)


def test_tls_not_applicable_has_zero_network_consumption():
    specification = CAPABILITY_REGISTRY.require("tls.inspect")
    requested = {
        "tcp_ports_attempted": 1,
        "tool_wall_seconds": 15,
        "agent_actions": 1,
    }

    async def operation():
        return {
            "ok": False,
            "status": "not_applicable",
            "error": "tls inspection requires an HTTPS target",
            "budget_consumed": {
                "tcp_ports_attempted": 0,
                "tool_wall_seconds": 0,
            },
        }

    result = _execute(
        specification,
        TlsInspectionExecutionAdapter(
            specification=specification,
            operation=operation,
            requested_budget=requested,
            redacted_execution={},
        ),
        requested,
    )

    assert result.status == "failed"
    assert result.actual_budget == {
        "tcp_ports_attempted": 0,
        "tool_wall_seconds": 0,
        "agent_actions": 1,
    }
    assert result.observations == ()
