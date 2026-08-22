from __future__ import annotations

import asyncio
import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from runtime.models import ScanBudget, ScanPolicy, TargetBinding
from scan.execution import ScanExecutionPlan
from scan.executor import NATIVE_SCAN_STAGES, build_native_scan_execution
from scan.stages import (
    ScanStageCancelled,
    ScanStageContext,
    ScanStageExecutionError,
    ScanStageRunResult,
    execute_scan_stage_graph,
)


def _context(*, active: bool = True):
    plan = ScanExecutionPlan(
        policy=ScanPolicy(
            active_testing=active,
            network_discovery=active,
            approval_receipt_id="approval-1" if active else None,
            scope_receipt_id="scope-1",
        ),
        budget_profile="balanced",
        budget=ScanBudget(1200, 100, 50, 20, 10, 60, 2),
    )
    target = TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("192.0.2.10",),
        allowed_root_domains=("example.test",),
        scope_receipt_id="scope-1",
    )
    execution = build_native_scan_execution(
        plan, {"_canonical_target_binding": target.canonical_dict()},
    )
    return ScanStageContext(
        execution=execution,
        target_url="https://app.example.test",
        options={},
        scan_id="scan-1",
        job_id="job-1",
    )


def test_scheduler_executes_one_fixed_graph_and_keeps_outputs_private():
    context = _context(active=True)
    calls = []
    ticks = iter(float(value) for value in range(100))

    def runner(name):
        async def run(_context):
            calls.append(name)
            return ScanStageRunResult(
                output={"private_secret": f"secret-{name}", "value": name},
                capability_names=(f"capability.{name}",),
            )
        return run

    result = asyncio.run(execute_scan_stage_graph(
        context,
        {name: runner(name) for name in NATIVE_SCAN_STAGES},
        monotonic=lambda: next(ticks),
    ))

    assert calls == list(NATIVE_SCAN_STAGES)
    assert [row["name"] for row in result["stages"]] == list(NATIVE_SCAN_STAGES)
    assert all(row["elapsed_ms"] == 1000 for row in result["stages"])
    assert all(row["output_keys"] == ["private_secret", "value"] for row in result["stages"])
    assert "secret-" not in str(result)
    assert context.output("verify_candidates")["private_secret"] == (
        "secret-verify_candidates"
    )
    assert len(result["history_digest"]) == 64


def test_scheduler_skips_policy_disabled_stages_without_calling_them():
    context = _context(active=False)
    calls = []

    def runner(name):
        async def run(_context):
            calls.append(name)
            return ScanStageRunResult()
        return run

    result = asyncio.run(execute_scan_stage_graph(
        context,
        {name: runner(name) for name in NATIVE_SCAN_STAGES},
    ))

    assert "discover_network" not in calls
    assert "deterministic_active" not in calls
    rows = {row["name"]: row for row in result["stages"]}
    assert rows["discover_network"]["status"] == "skipped"
    assert rows["deterministic_active"]["reason"] == "policy_disabled"


def test_scheduler_fails_closed_on_missing_enabled_runner():
    context = _context(active=True)

    with pytest.raises(ScanStageExecutionError) as failure:
        asyncio.run(execute_scan_stage_graph(context, {}))

    assert failure.value.stage_name == "bind_target"
    assert failure.value.history[0]["status"] == "failed"
    assert failure.value.history[0]["reason"] == "stage_runner_missing"


def test_scheduler_stops_before_traffic_when_cancelled():
    context = _context(active=True)
    calls = []

    async def runner(_context):
        calls.append("traffic")
        return ScanStageRunResult()

    with pytest.raises(ScanStageCancelled) as failure:
        asyncio.run(execute_scan_stage_graph(
            context,
            {name: runner for name in NATIVE_SCAN_STAGES},
            cancel_requested=lambda: True,
        ))

    assert calls == []
    assert failure.value.history[-1]["status"] == "cancelled"


def test_scheduler_records_partial_adapter_outcome_without_stopping_graph():
    context = _context(active=True)

    def runner(name):
        async def run(_context):
            return ScanStageRunResult(
                status="partial" if name == "discover_surface" else "completed",
                reason="one_capability_failed" if name == "discover_surface" else None,
            )
        return run

    result = asyncio.run(execute_scan_stage_graph(
        context,
        {name: runner(name) for name in NATIVE_SCAN_STAGES},
    ))

    assert result["status"] == "partial"
    assert result["stages"][2]["reason"] == "one_capability_failed"


def test_scheduler_never_copies_exception_text_into_public_history():
    context = _context(active=True)

    async def fail(_context):
        raise RuntimeError("https://app.example.test/reset/opaque-secret")

    with pytest.raises(ScanStageExecutionError) as failure:
        asyncio.run(execute_scan_stage_graph(
            context,
            {"bind_target": fail},
        ))

    row = failure.value.history[-1]
    assert row["reason"] == "stage_adapter_error:RuntimeError"
    assert "opaque-secret" not in str(row)


def test_scheduler_checkpoints_each_public_stage_without_private_values():
    context = _context(active=False)
    checkpoints = []

    def runner(name):
        async def run(_context):
            return ScanStageRunResult(
                output={"private_value": f"secret-{name}"},
                capability_names=(f"capability.{name}",),
            )
        return run

    async def checkpoint(row, history_digest):
        checkpoints.append((dict(row), history_digest))

    result = asyncio.run(execute_scan_stage_graph(
        context,
        {name: runner(name) for name in NATIVE_SCAN_STAGES},
        checkpoint=checkpoint,
    ))

    assert len(checkpoints) == len(NATIVE_SCAN_STAGES)
    assert checkpoints[-1][1] == result["history_digest"]
    assert all(len(digest) == 64 for _row, digest in checkpoints)
    assert all("private_value" in row["output_keys"] for row, _digest in checkpoints if row["enabled"])
    assert "secret-" not in str(checkpoints)


def test_scheduler_checkpoints_failure_before_stopping():
    context = _context(active=True)
    checkpoints = []

    async def fail(_context):
        raise RuntimeError("secret failure detail")

    async def checkpoint(row, history_digest):
        checkpoints.append((dict(row), history_digest))

    with pytest.raises(ScanStageExecutionError):
        asyncio.run(execute_scan_stage_graph(
            context,
            {"bind_target": fail},
            checkpoint=checkpoint,
        ))

    assert checkpoints[0][0]["status"] == "failed"
    assert checkpoints[0][0]["reason"] == "stage_adapter_error:RuntimeError"
    assert "secret failure detail" not in str(checkpoints)
