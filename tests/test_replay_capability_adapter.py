from __future__ import annotations

import asyncio
import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from capabilities.replay import ReplayExecutionAdapter
from hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import TargetBinding
from runtime.request_replay_executor import ReplayTransportResult, replay_reservation_budget
from scanner_tools.request_replay import ReplayAuthorization, build_replay_plan


class Transport:
    def __init__(self):
        self.calls = []

    async def send(
        self, request, *, target, timeout_seconds, follow_redirects,
    ):
        self.calls.append(request.request_id)
        return ReplayTransportResult(
            status_code=200,
            connected_address=target.allowed_addresses[0],
            final_url=request.url,
            response_headers={"Content-Type": "text/plain"},
            response_body=b"ok",
            elapsed_ms=1,
        )


TARGET = TargetBinding(
    target_id="target-1",
    target_kind="web",
    canonical_host="api.example.test",
    allowed_origins=("https://api.example.test",),
    allowed_addresses=("192.0.2.10",),
    scope_receipt_id="scope-1",
)


def _plan():
    return build_replay_plan(
        [{
            "id": "request-1",
            "method": "GET",
            "url": "https://api.example.test/orders?token=wire-secret",
            "headers": {"Authorization": "Bearer header-secret"},
            "body": b"",
        }],
        allowed_origins=TARGET.allowed_origins,
        authorization=ReplayAuthorization(),
    )


def _execute(*, cancelled: bool):
    plan = _plan()
    transport = Transport()
    additional = {"agent_actions": 1, "tool_wall_seconds": 60}
    requested = replay_reservation_budget(plan, additional)
    specification = CAPABILITY_REGISTRY.require("collections.replay_safe")
    adapter = ReplayExecutionAdapter(
        specification=specification,
        execution_kwargs={
            "plan": plan,
            "target": TARGET,
            "owner_kind": "hunt",
            "owner_id": "hunt-1",
            "worker_id": "worker-1",
            "limits": {
                "http_requests": 25,
                "agent_actions": 5,
                "tool_wall_seconds": 300,
            },
            "consumed": {
                "http_requests": 0,
                "agent_actions": 0,
                "tool_wall_seconds": 0,
            },
            "transport": transport,
            "additional_budget": additional,
        },
    )
    result = asyncio.run(CapabilityExecutor().execute(
        CapabilityExecutionContext(
            specification=specification,
            target=TARGET,
            requested_budget=requested,
            adapter_managed_cancellation=True,
        ),
        adapter,
        heartbeat=lambda: asyncio.sleep(0),
        cancelled=lambda: cancelled,
    ))
    return result, adapter, transport


def test_exact_replay_runs_through_shared_executor_without_secret_receipts():
    result, adapter, transport = _execute(cancelled=False)

    assert result.status == "success"
    assert transport.calls == ["request-1"]
    assert adapter.outcome is not None
    assert result.actual_budget["http_requests"] == 1
    assert result.actual_budget["agent_actions"] == 1
    assert result.observations[0]["kind"] == "request_replay"
    assert "wire-secret" not in repr(result)
    assert "header-secret" not in repr(result)


def test_replay_adapter_owns_pre_send_cancellation_and_settlement():
    result, adapter, transport = _execute(cancelled=True)

    assert result.status == "cancelled"
    assert transport.calls == []
    assert adapter.outcome is not None
    assert adapter.outcome.reservation.status == "failed"
    assert result.actual_budget["http_requests"] == 0
    assert result.actual_budget["agent_actions"] == 1
