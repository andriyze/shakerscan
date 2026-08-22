from __future__ import annotations

import asyncio
import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from capabilities.scanner import ScannerExecutionAdapter
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


def _run(adapter: ScannerExecutionAdapter, requested: dict[str, int]):
    return asyncio.run(CapabilityExecutor().execute(
        CapabilityExecutionContext(
            specification=CAPABILITY_REGISTRY.require("templates.scan"),
            target=TARGET,
            requested_budget=requested,
        ),
        adapter,
        heartbeat=lambda: asyncio.sleep(0),
        cancelled=lambda: False,
    ))


def test_scanner_adapter_uses_exact_settlement_and_redacted_execution():
    requested = {
        "http_requests": 4_000,
        "tool_wall_seconds": 300,
        "agent_actions": 1,
        "active_actions": 1,
    }

    async def process_runner(payload, *, heartbeat):
        assert payload["oob_interactsh_token"] == "worker-only-secret"
        await heartbeat()
        return {
            "status": "success",
            "elapsed_seconds": 2,
            "typed_output": {
                "parser": "nuclei-jsonl/v1",
                "records": [{"kind": "template_match", "id": "x"}],
                "errors": [],
            },
            "settlement": {"mode": "exact", "actual": 7},
        }

    adapter = ScannerExecutionAdapter(
        specification=CAPABILITY_REGISTRY.require("templates.scan"),
        process_payload={"oob_interactsh_token": "worker-only-secret"},
        process_runner=process_runner,
        requested_budget=requested,
        redacted_execution={"path": "/account", "severity": "high"},
    )
    result = _run(adapter, requested)

    assert result.status == "success"
    assert result.actual_budget == {
        "http_requests": 7,
        "tool_wall_seconds": 2,
        "agent_actions": 1,
        "active_actions": 1,
    }
    assert result.observations == ({
        "kind": "template_match", "id": "x",
    },)
    assert result.redacted_execution == {
        "path": "/account", "severity": "high",
    }
    assert "worker-only-secret" not in str(result)


def test_scanner_timeout_is_a_partial_executor_outcome():
    requested = {
        "http_requests": 4_000,
        "tool_wall_seconds": 300,
        "agent_actions": 1,
        "active_actions": 1,
    }

    async def process_runner(_payload, *, heartbeat):
        await heartbeat()
        return {
            "status": "timeout",
            "error": "scanner_timeout",
            "elapsed_seconds": 300,
            "timed_out": True,
            "partial": False,
            "typed_output": {
                "parser": "nuclei-jsonl/v1",
                "records": [],
                "errors": [],
            },
            "settlement": {"mode": "conservative"},
        }

    result = _run(ScannerExecutionAdapter(
        specification=CAPABILITY_REGISTRY.require("templates.scan"),
        process_payload={},
        process_runner=process_runner,
        requested_budget=requested,
        redacted_execution={"path": "/"},
    ), requested)

    assert result.status == "partial"
    assert result.partial is True
    assert result.timed_out is True
    assert result.actual_budget == requested
