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


def _enforcement(*, hard=None, mode="conservative", method="fixed_conservative_profile"):
    return {
        "schema_version": "external-process-enforcement/v1",
        "tool_name": "nuclei",
        "process_plan_digest": "a" * 64,
        "hard_budget": hard or {
            "http_requests": 4_000,
            "tool_wall_seconds": 300,
        },
        "accounting_mode": mode,
        "proof_method": method,
        "parser_version": "nuclei-jsonl/v1",
    }


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
            "process_enforcement": _enforcement(),
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
    assert result.redacted_execution["path"] == "/account"
    assert result.redacted_execution["severity"] == "high"
    assert result.redacted_execution["process_enforcement"] == _enforcement()
    assert result.redacted_execution["wire_telemetry"] == {
        "schema_version": "external-wire-telemetry/v1",
        "accounting_mode": "exact",
        "actual_http_requests": 7,
        "observed_http_requests_minimum": 0,
        "http_request_upper_bound": 4_000,
        "tcp_attempt_upper_bound": 0,
        "connections_attempted": 0,
        "connections_opened": 0,
        "targets": 0,
        "wall_seconds": 2,
        "limiter_status": "within_ceiling",
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
            "process_enforcement": _enforcement(),
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


def test_scanner_adapter_passes_live_cancellation_to_process_runner():
    requested = {"http_requests": 10, "tool_wall_seconds": 5}
    saw_cancelled = False
    cancellation_checks = 0

    def cancelled():
        nonlocal cancellation_checks
        cancellation_checks += 1
        return cancellation_checks > 1

    async def process_runner(payload, *, heartbeat):
        nonlocal saw_cancelled
        await heartbeat()
        saw_cancelled = bool(payload["_cancelled"]())
        return {
            "status": "cancelled",
            "error": "cancelled",
            "elapsed_seconds": 0,
            "typed_output": {"records": [], "errors": []},
            "settlement": {"source": "not_executed"},
        }

    adapter = ScannerExecutionAdapter(
        specification=CAPABILITY_REGISTRY.require("templates.scan"),
        process_payload={},
        process_runner=process_runner,
        requested_budget=requested,
        redacted_execution={"input": {}},
    )
    result = asyncio.run(adapter.execute(
        heartbeat=lambda: asyncio.sleep(0),
        cancelled=cancelled,
    ))

    assert saw_cancelled is True
    assert result.status == "cancelled"
    assert result.actual_budget == {"tool_wall_seconds": 0}


def test_scanner_adapter_never_reports_success_after_wire_limiter_overrun():
    requested = {
        "http_requests": 4_000,
        "tool_wall_seconds": 300,
    }

    async def process_runner(_payload, *, heartbeat):
        await heartbeat()
        return {
            "status": "success",
            "elapsed_seconds": 3,
            "typed_output": {"records": [], "errors": []},
            "settlement": {"mode": "exact", "actual": 4_001},
            "process_enforcement": _enforcement(),
        }

    result = asyncio.run(ScannerExecutionAdapter(
        specification=CAPABILITY_REGISTRY.require("templates.scan"),
        process_payload={},
        process_runner=process_runner,
        requested_budget=requested,
        redacted_execution={"input": {}},
    ).execute(
        heartbeat=lambda: asyncio.sleep(0),
        cancelled=lambda: False,
    ))

    assert result.status == "failed"
    assert result.actual_budget == requested
    assert result.errors[0].startswith("external_process_contract:")
