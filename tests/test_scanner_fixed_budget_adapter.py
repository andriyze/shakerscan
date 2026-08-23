from __future__ import annotations

import asyncio
import importlib.util
import os
from pathlib import Path
import sys


os.environ.pop("SHAKERSCAN_CANONICAL_SCAN_EXECUTION", None)
MODULE_PATH = Path(__file__).parents[1] / "scanner" / "sitecustomize.py"
spec = importlib.util.spec_from_file_location(
    "shakerscan_sitecustomize_budget_test", MODULE_PATH,
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = module
spec.loader.exec_module(module)

from capabilities.scanner import ScannerExecutionAdapter
from runtime.capability_registry import CAPABILITY_REGISTRY


def _adapter(*, requested):
    calls = []

    async def runner(payload, *, heartbeat):
        calls.append(dict(payload))
        await heartbeat()
        return {
            "status": "completed",
            "typed_output": {"records": []},
            "request_settlement": {"mode": "exact", "actual": 1},
        }

    instance = ScannerExecutionAdapter(
        specification=CAPABILITY_REGISTRY.require("templates.scan"),
        process_payload={"tool_name": "nuclei"},
        process_runner=runner,
        requested_budget=requested,
        redacted_execution={
            "schema_version": "scan-external-capability/v1",
            "capability_name": "templates.scan",
        },
    )
    return instance, calls


def test_fixed_external_scan_tool_is_blocked_before_process_when_hold_is_clamped():
    assert module.install_fixed_external_budget_guard() is True
    adapter, calls = _adapter(requested={
        "http_requests": 400,
        "tool_wall_seconds": 30,
    })

    async def heartbeat():
        return None

    result = asyncio.run(adapter.execute(
        heartbeat=heartbeat,
        cancelled=lambda: False,
    ))
    assert result.status == "blocked"
    assert result.execution_started is False
    assert result.actual_budget == {
        "http_requests": 0,
        "tool_wall_seconds": 0,
    }
    assert result.errors == (
        "fixed_external_budget_incomplete:http_requests,tool_wall_seconds",
    )
    assert calls == []


def test_fixed_external_scan_tool_runs_when_complete_profile_is_reserved():
    assert module.install_fixed_external_budget_guard() is True
    adapter, calls = _adapter(requested={
        "http_requests": 4_000,
        "tool_wall_seconds": 300,
    })

    async def heartbeat():
        return None

    result = asyncio.run(adapter.execute(
        heartbeat=heartbeat,
        cancelled=lambda: False,
    ))
    assert result.status == "success"
    assert result.execution_started is True
    assert len(calls) == 1


def test_non_scan_external_execution_is_not_changed_by_the_guard():
    assert module.install_fixed_external_budget_guard() is True
    calls = []

    async def runner(payload, *, heartbeat):
        calls.append(dict(payload))
        return {
            "status": "completed",
            "typed_output": {"records": []},
            "request_settlement": {"mode": "exact", "actual": 1},
        }

    adapter = ScannerExecutionAdapter(
        specification=CAPABILITY_REGISTRY.require("templates.scan"),
        process_payload={"tool_name": "nuclei"},
        process_runner=runner,
        requested_budget={"http_requests": 1, "tool_wall_seconds": 1},
        redacted_execution={
            "schema_version": "hunt-external-capability/v1",
            "capability_name": "templates.scan",
        },
    )

    async def heartbeat():
        return None

    result = asyncio.run(adapter.execute(
        heartbeat=heartbeat,
        cancelled=lambda: False,
    ))
    assert result.status == "success"
    assert len(calls) == 1
