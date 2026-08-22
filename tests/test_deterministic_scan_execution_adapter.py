from __future__ import annotations

import asyncio
import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from capabilities.scan import DeterministicScanExecutionAdapter
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


def test_deterministic_scan_adapter_heartbeats_and_settles_measured_usage():
    requested = {
        "http_requests": 20,
        "state_changing_requests": 5,
        "browser_actions": 8,
        "tcp_ports_attempted": 1,
        "hosts_attempted": 10,
        "tool_wall_seconds": 10,
    }
    heartbeat_count = 0

    async def heartbeat():
        nonlocal heartbeat_count
        heartbeat_count += 1

    async def scan_runner():
        await asyncio.sleep(0.035)
        return {
            "findings": [{"id": "one"}],
            "coverage": {"status": "complete"},
            "discovery": {"browser_crawl": {"pages_visited": 2}},
            "tls": {
                "canonical_runtime": {
                    "schema_version": "canonical-tls-runtime/v1",
                    "tcp_ports_attempted": 1,
                },
            },
            "request_budget": {
                "schema_version": "request_meter_v1",
                "mode": "enforce",
                "fully_metered": True,
                "attempted_requests": 4,
                "state_changing_attempted_requests": 1,
            },
            "scan_metadata": {"schema_version": "scan-report/v2"},
        }

    adapter = DeterministicScanExecutionAdapter(
        specification=CAPABILITY_REGISTRY.require("scan.execute"),
        scan_runner=scan_runner,
        requested_budget=requested,
        redacted_execution={"plan_digest": "a" * 64},
        heartbeat_interval_seconds=0.01,
    )
    result = asyncio.run(CapabilityExecutor().execute(
        CapabilityExecutionContext(
            specification=CAPABILITY_REGISTRY.require("scan.execute"),
            target=TARGET,
            requested_budget=requested,
            adapter_managed_cancellation=True,
        ),
        adapter,
        heartbeat=heartbeat,
        cancelled=lambda: False,
    ))

    assert heartbeat_count >= 3
    assert result.status == "success"
    assert result.actual_budget == {
        "http_requests": 4,
        "state_changing_requests": 1,
        "browser_actions": 2,
        "tcp_ports_attempted": 1,
        "hosts_attempted": 1,
        "tool_wall_seconds": 1,
    }
    assert result.observations == ({
        "kind": "deterministic_scan_summary",
        "status": "success",
        "coverage_status": "complete",
        "finding_count": 1,
        "request_meter_exact": True,
    },)
    assert adapter.scan_result["findings"] == [{"id": "one"}]


def test_deterministic_scan_adapter_refunds_proven_preflight_failure():
    requested = {
        "http_requests": 20,
        "hosts_attempted": 10,
        "tool_wall_seconds": 10,
    }

    async def scan_runner():
        return {
            "error": "scanner preflight failed",
            "findings": [],
            "scan_metadata": {
                "preflight_failed": True,
                "schema_version": "scan-report/v2",
            },
        }

    adapter = DeterministicScanExecutionAdapter(
        specification=CAPABILITY_REGISTRY.require("scan.execute"),
        scan_runner=scan_runner,
        requested_budget=requested,
        redacted_execution={},
    )
    result = asyncio.run(CapabilityExecutor().execute(
        CapabilityExecutionContext(
            specification=CAPABILITY_REGISTRY.require("scan.execute"),
            target=TARGET,
            requested_budget=requested,
            adapter_managed_cancellation=True,
        ),
        adapter,
        heartbeat=lambda: asyncio.sleep(0),
        cancelled=lambda: False,
    ))

    assert result.status == "failed"
    assert result.execution_started is False
    assert result.actual_budget == {
        "http_requests": 0,
        "hosts_attempted": 0,
        "tool_wall_seconds": 0,
    }
