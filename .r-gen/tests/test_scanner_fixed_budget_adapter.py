from __future__ import annotations

import asyncio

from capabilities.scanner import ScannerExecutionAdapter
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import PreparedExecution
from scan.capability_execution import fit_prepared_scan_capability


def _prepared() -> PreparedExecution:
    spec = CAPABILITY_REGISTRY.require("templates.scan")
    return PreparedExecution(
        capability_name=spec.name,
        adapter_name=spec.adapter,
        adapter_version=spec.adapter_version,
        commands=(),
        estimated_budget=dict(spec.budget_cost),
        input_digest="a" * 64,
        redacted_execution={
            "schema_version": "scan-external-capability/v1",
            "capability_name": spec.name,
        },
        parser_version=spec.output_schema,
    )


def _receipt():
    return {
        "schema_version": "external-process-enforcement/v1",
        "tool_name": "nuclei",
        "process_plan_digest": "b" * 64,
        "hard_budget": {
            "http_requests": 4_000,
            "tool_wall_seconds": 300,
        },
        "accounting_mode": "conservative",
        "proof_method": "fixed_conservative_profile",
        "parser_version": "nuclei-jsonl/v1",
    }


def _adapter(*, requested, include_receipt=True):
    calls = []

    async def runner(payload, *, heartbeat):
        calls.append(dict(payload))
        await heartbeat()
        result = {
            "status": "success",
            "typed_output": {"records": []},
            "settlement": {"mode": "exact", "actual": 1},
            "elapsed_seconds": 1,
        }
        if include_receipt:
            result["process_enforcement"] = _receipt()
        return result

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


def test_external_scan_tool_is_bound_to_smaller_immutable_action_hold():
    prepared = fit_prepared_scan_capability(
        _prepared(),
        ledger_limits={"http_requests": 301, "tool_wall_seconds": 60},
    )

    assert dict(prepared.estimated_budget) == {
        "http_requests": 301,
        "tool_wall_seconds": 60,
    }


def test_fixed_external_scan_tool_runs_with_complete_profile_and_proof():
    prepared = fit_prepared_scan_capability(
        _prepared(),
        ledger_limits={"http_requests": 4_000, "tool_wall_seconds": 300},
    )
    adapter, calls = _adapter(requested=dict(prepared.estimated_budget))

    result = asyncio.run(adapter.execute(
        heartbeat=lambda: asyncio.sleep(0),
        cancelled=lambda: False,
    ))

    assert result.status == "success"
    assert calls[0]["_reserved_budget"] == dict(prepared.estimated_budget)
    assert result.redacted_execution["process_enforcement"] == _receipt()


def test_started_process_without_enforcement_proof_fails_and_charges_full_hold():
    requested = {"http_requests": 4_000, "tool_wall_seconds": 300}
    adapter, calls = _adapter(requested=requested, include_receipt=False)

    result = asyncio.run(adapter.execute(
        heartbeat=lambda: asyncio.sleep(0),
        cancelled=lambda: False,
    ))

    assert calls
    assert result.status == "failed"
    assert result.execution_started is True
    assert result.actual_budget == requested
    assert result.errors[0].startswith("external_process_contract:")
