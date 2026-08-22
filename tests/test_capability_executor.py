from __future__ import annotations

import asyncio

import pytest

from api.hunt.capability_executor import (
    CapabilityAdapterResult,
    CapabilityExecutionContext,
    CapabilityExecutor,
)
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.runtime.models import TargetBinding


def _target() -> TargetBinding:
    return TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
    )


class _Adapter:
    capability_name = "browser.navigate"
    adapter_name = "playwright"
    adapter_version = "1"

    def __init__(self, result: CapabilityAdapterResult | None = None):
        self.called = False
        self.result = result or CapabilityAdapterResult(status="success")

    async def execute(self, *, heartbeat, cancelled):
        self.called = True
        await heartbeat()
        return self.result


def _context() -> CapabilityExecutionContext:
    return CapabilityExecutionContext(
        specification=CAPABILITY_REGISTRY.require("browser.navigate"),
        target=_target(),
        requested_budget={
            "agent_actions": 1,
            "browser_actions": 1,
            "http_requests": 5,
            "tool_wall_seconds": 10,
        },
    )


def test_executor_validates_registry_identity_and_clamps_measured_budget():
    heartbeats = []
    adapter = _Adapter(CapabilityAdapterResult(
        status="partial",
        observations=({"kind": "browser_navigation"},),
        errors=("bounded",),
        actual_budget={
            "browser_actions": 3,
            "http_requests": 2,
            "tool_wall_seconds": 100,
            "unreserved": 99,
        },
        partial=True,
        execution_started=True,
    ))

    async def heartbeat():
        heartbeats.append(True)

    result = asyncio.run(CapabilityExecutor().execute(
        _context(), adapter, heartbeat=heartbeat, cancelled=lambda: False,
    ))

    assert adapter.called
    assert heartbeats == [True]
    assert result.actual_budget == {
        "browser_actions": 1,
        "http_requests": 2,
        "tool_wall_seconds": 10,
        "agent_actions": 1,
    }
    assert "unreserved" not in result.actual_budget


def test_executor_cancellation_is_distinct_and_does_not_start_adapter():
    adapter = _Adapter()

    async def heartbeat():
        raise AssertionError("cancelled execution must not heartbeat")

    result = asyncio.run(CapabilityExecutor().execute(
        _context(), adapter, heartbeat=heartbeat, cancelled=lambda: True,
    ))

    assert result.status == "cancelled"
    assert result.errors == ("cancelled_before_execution",)
    assert result.actual_budget == {"agent_actions": 1}
    assert not adapter.called


def test_executor_adapter_fault_charges_the_complete_uncertain_hold():
    class FaultingAdapter(_Adapter):
        async def execute(self, *, heartbeat, cancelled):
            raise RuntimeError("untrusted detail")

    async def heartbeat():
        return None

    result = asyncio.run(CapabilityExecutor().execute(
        _context(), FaultingAdapter(), heartbeat=heartbeat, cancelled=lambda: False,
    ))

    assert result.status == "failed"
    assert result.execution_started is True
    assert result.actual_budget == dict(_context().requested_budget)
    assert result.errors == ("adapter_fault:RuntimeError",)


def test_executor_rejects_an_adapter_that_does_not_match_registry():
    adapter = _Adapter()
    adapter.adapter_version = "different"

    async def heartbeat():
        return None

    with pytest.raises(ValueError, match="version"):
        asyncio.run(CapabilityExecutor().execute(
            _context(), adapter, heartbeat=heartbeat, cancelled=lambda: False,
        ))
