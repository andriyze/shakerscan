from __future__ import annotations

import asyncio
import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from capabilities.inline import (
    AuthSessionExecutionAdapter,
    AuthzVerificationExecutionAdapter,
    ControlPlaneExecutionAdapter,
    DeviceExecutionAdapter,
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

DEVICE_TARGET = TargetBinding(
    target_id="device-1",
    target_kind="device",
    canonical_host="192.0.2.20",
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


def _execute_device(specification, adapter, requested):
    return asyncio.run(CapabilityExecutor().execute(
        CapabilityExecutionContext(
            specification=specification,
            target=DEVICE_TARGET,
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


def test_auth_session_adapter_persists_content_free_measured_observation():
    specification = CAPABILITY_REGISTRY.require("auth.session.establish")
    requested = {"http_requests": 4, "tool_wall_seconds": 45}

    async def operation():
        return {
            "ok": True,
            "status": "success",
            "observation": {
                "kind": "credential_session",
                "lane": "primary",
                "header_names": ["Authorization"],
                "secret_values_visible": False,
            },
            "budget_consumed": {
                "http_requests": 1,
                "tool_wall_seconds": 1,
            },
        }

    result = _execute(
        specification,
        AuthSessionExecutionAdapter(
            specification=specification,
            operation=operation,
            requested_budget=requested,
            redacted_execution={"lane": "primary"},
        ),
        requested,
    )

    assert result.status == "success"
    assert result.actual_budget == {
        "http_requests": 1,
        "tool_wall_seconds": 1,
    }
    assert result.observations == ({
        "kind": "credential_session",
        "lane": "primary",
        "header_names": ["Authorization"],
        "secret_values_visible": False,
    },)


def test_authz_adapter_persists_only_measured_differential_observation():
    specification = CAPABILITY_REGISTRY.require("authz.verify")
    requested = {"http_requests": 4, "tool_wall_seconds": 60}

    async def operation():
        return {
            "ok": True,
            "status": "success",
            "observation": {
                "kind": "authz_differential",
                "proof_state": "inconclusive",
                "principal_contexts_distinct": True,
                "secret_values_visible": False,
            },
            "budget_consumed": {
                "http_requests": 2,
                "tool_wall_seconds": 1,
            },
        }

    result = _execute(
        specification,
        AuthzVerificationExecutionAdapter(
            specification=specification,
            operation=operation,
            requested_budget=requested,
            redacted_execution={"route_count": 1},
        ),
        requested,
    )

    assert result.status == "success"
    assert result.actual_budget == {
        "http_requests": 2,
        "tool_wall_seconds": 1,
    }
    assert result.observations == ({
        "kind": "authz_differential",
        "proof_state": "inconclusive",
        "principal_contexts_distinct": True,
        "secret_values_visible": False,
    },)


class ExpectedControlBlock(Exception):
    pass


def test_collection_control_adapter_returns_a_content_free_observation():
    specification = CAPABILITY_REGISTRY.require("collections.select")
    requested = {"agent_actions": 1, "tool_wall_seconds": 5}

    async def operation():
        return {
            "ok": True,
            "collection_id": "collection-1",
            "selection_id": "selection-1",
            "count": 3,
            "requests": [{"path": "/private"}],
        }

    result = _execute(
        specification,
        ControlPlaneExecutionAdapter(
            specification=specification,
            operation=operation,
            requested_budget=requested,
            redacted_execution={"limit": 3},
            blocked_exceptions=(ExpectedControlBlock,),
        ),
        requested,
    )

    assert result.status == "success"
    assert result.actual_budget == {
        "agent_actions": 1,
        "tool_wall_seconds": 1,
    }
    assert result.observations == ({
        "kind": "request_collection_observation",
        "capability": "collections.select",
        "status": "success",
        "collection_id": "collection-1",
        "selection_id": "selection-1",
        "count": 3,
    },)


def test_collection_control_adapter_refunds_wall_time_for_a_guard_block():
    specification = CAPABILITY_REGISTRY.require("collections.select")
    requested = {"agent_actions": 1, "tool_wall_seconds": 5}

    async def operation():
        raise ExpectedControlBlock("collection changed")

    adapter = ControlPlaneExecutionAdapter(
        specification=specification,
        operation=operation,
        requested_budget=requested,
        redacted_execution={},
        blocked_exceptions=(ExpectedControlBlock,),
    )
    result = _execute(specification, adapter, requested)

    assert result.status == "blocked"
    assert result.actual_budget == {"agent_actions": 1}
    assert isinstance(adapter.blocked_exception, ExpectedControlBlock)


class ExpectedDeviceBlock(Exception):
    pass


def test_device_adapter_refunds_execution_dimensions_for_precondition_block():
    specification = CAPABILITY_REGISTRY.require("device.scan")
    requested = {
        "agent_actions": 1,
        "active_actions": 1,
        "device_fragility_points": 22,
        "tool_wall_seconds": 30,
    }
    state = {"scans_queued": 0, "device_http_requests_used": 0}

    async def operation():
        raise ExpectedDeviceBlock("traffic frozen")

    adapter = DeviceExecutionAdapter(
        specification=specification,
        operation=operation,
        requested_budget=requested,
        redacted_execution={"coverage_profile": "posture"},
        state=state,
        blocked_exceptions=(ExpectedDeviceBlock,),
    )
    result = _execute_device(specification, adapter, requested)

    assert result.status == "blocked"
    assert result.actual_budget == {"agent_actions": 1}
    assert adapter.blocked_exception is not None
    assert result.observations[0]["kind"] == "device_capability"


def test_device_adapter_charges_reserved_queue_envelope_after_acceptance():
    specification = CAPABILITY_REGISTRY.require("device.service.verify")
    requested = {
        "agent_actions": 1,
        "active_actions": 1,
        "tcp_ports_attempted": 1,
        "device_fragility_points": 6,
        "tool_wall_seconds": 30,
    }
    state = {"scans_queued": 0, "device_http_requests_used": 0}

    async def operation():
        state["scans_queued"] = 1
        return {
            "ok": True,
            "queued": {"scan_id": "scan-1", "status": "queued"},
        }

    result = _execute_device(
        specification,
        DeviceExecutionAdapter(
            specification=specification,
            operation=operation,
            requested_budget=requested,
            redacted_execution={"transport": "tcp", "port": 22},
            state=state,
            blocked_exceptions=(ExpectedDeviceBlock,),
        ),
        requested,
    )

    assert result.status == "success"
    assert result.actual_budget == {
        "agent_actions": 1,
        "active_actions": 1,
        "tcp_ports_attempted": 1,
        "device_fragility_points": 6,
        "tool_wall_seconds": 1,
    }
    assert result.observations[0]["queued"]["scan_id"] == "scan-1"


def test_device_adapter_accepts_a_raw_downstream_queue_receipt():
    specification = CAPABILITY_REGISTRY.require(
        "device.ssh.execute_confirmed"
    )
    requested = {
        "active_actions": 1,
        "device_fragility_points": 12,
        "tool_wall_seconds": 30,
    }

    async def operation():
        return {"scan_id": "scan-1", "job_id": "job-1", "status": "queued"}

    result = _execute_device(
        specification,
        DeviceExecutionAdapter(
            specification=specification,
            operation=operation,
            requested_budget=requested,
            redacted_execution={"plan_id": "plan-1"},
            state={},
            blocked_exceptions=(ExpectedDeviceBlock,),
        ),
        requested,
    )

    assert result.status == "success"
    assert result.actual_budget == {
        "active_actions": 1,
        "device_fragility_points": 12,
        "tool_wall_seconds": 1,
    }


def test_device_adapter_preserves_failed_http_attempt_consumption():
    specification = CAPABILITY_REGISTRY.require("device.http.probe")
    requested = {
        "agent_actions": 1,
        "http_requests": 1,
        "device_fragility_points": 1,
        "tool_wall_seconds": 10,
    }
    state = {"scans_queued": 0, "device_http_requests_used": 0}

    async def operation():
        state["device_http_requests_used"] = 1
        raise ExpectedDeviceBlock("transport failed")

    result = _execute_device(
        specification,
        DeviceExecutionAdapter(
            specification=specification,
            operation=operation,
            requested_budget=requested,
            redacted_execution={"method": "GET", "path": "/"},
            state=state,
            blocked_exceptions=(ExpectedDeviceBlock,),
        ),
        requested,
    )

    assert result.status == "blocked"
    assert result.actual_budget == {
        "agent_actions": 1,
        "http_requests": 1,
        "device_fragility_points": 1,
        "tool_wall_seconds": 1,
    }


def test_device_adapter_fault_conservatively_charges_the_full_hold():
    specification = CAPABILITY_REGISTRY.require("device.http.probe")
    requested = {
        "agent_actions": 1,
        "http_requests": 1,
        "device_fragility_points": 1,
        "tool_wall_seconds": 10,
    }
    state = {"scans_queued": 0, "device_http_requests_used": 0}

    async def operation():
        raise RuntimeError("unknown execution state")

    result = _execute_device(
        specification,
        DeviceExecutionAdapter(
            specification=specification,
            operation=operation,
            requested_budget=requested,
            redacted_execution={},
            state=state,
            blocked_exceptions=(ExpectedDeviceBlock,),
        ),
        requested,
    )

    assert result.status == "failed"
    assert result.actual_budget == requested
    assert result.errors == ("adapter_fault:RuntimeError",)
