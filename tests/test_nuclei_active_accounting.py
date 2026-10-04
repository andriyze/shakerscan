"""Reserve, build and settle the active Nuclei state-changing budget dimension.

These assert the accounting half of the fix: the planner reserves
``state_changing_requests`` only when state-changing HTTP is authorized, the
argv builder adds a matching hard ceiling and feeds an explicit ``-id`` allowlist
(never the unfiltered ``-tags`` selection), and the adapter settles the dimension
to the requests actually sent -- instead of the former zero, which let active
Nuclei POST credentials while reporting no mutations.
"""

from __future__ import annotations

import asyncio

import pytest

import agent_tools
from capabilities.scanner import ScannerExecutionAdapter
from hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
from runtime.capability_registry import CAPABILITY_REGISTRY
from runtime.models import TargetBinding
from scan.action_plan import batch_profile_shape

TARGET = TargetBinding(
    target_id="target-1",
    target_kind="web",
    canonical_host="app.example.test",
    allowed_origins=("https://app.example.test",),
    allowed_addresses=("192.0.2.10",),
    scope_receipt_id="scope-1",
)

_ACTIVE_IDS = "django-debug-exposure,squid-analysis-report-generator"


def _enforcement(hard):
    return {
        "schema_version": "external-process-enforcement/v1",
        "tool_name": "nuclei",
        "process_plan_digest": "a" * 64,
        "hard_budget": dict(hard),
        "accounting_mode": "conservative",
        "proof_method": "runtime_transport_wall_limiter",
        "parser_version": "nuclei-jsonl/v1",
    }


def _run_nuclei_adapter(*, scanner_options, requested, settlement):
    async def process_runner(payload, *, heartbeat):
        await heartbeat()
        return {
            "status": "success",
            "elapsed_seconds": 10,
            "typed_output": {
                "parser": "nuclei-jsonl/v1",
                "records": [{"kind": "template_match", "id": "x"}],
                "errors": [],
            },
            "settlement": settlement,
            "process_enforcement": _enforcement({
                name: requested[name]
                for name in ("http_requests", "tool_wall_seconds")
            }),
        }

    adapter = ScannerExecutionAdapter(
        specification=CAPABILITY_REGISTRY.require("templates.scan"),
        process_payload={"tool_name": "nuclei", "scanner_options": scanner_options},
        process_runner=process_runner,
        requested_budget=requested,
        redacted_execution={"capability_name": "templates.scan"},
    )
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


def test_active_nuclei_with_non_get_templates_settles_mutations_to_requests_sent():
    requested = {
        "http_requests": 120,
        "state_changing_requests": 120,
        "tool_wall_seconds": 45,
        "agent_actions": 1,
        "active_actions": 1,
    }
    result = _run_nuclei_adapter(
        scanner_options={
            "template_profile": "active",
            "template_ids": _ACTIVE_IDS,
            "nuclei_active_state_changing": True,
        },
        requested=requested,
        settlement={"mode": "exact", "actual": 30},
    )
    assert result.status == "success"
    # The former GET-only settlement charged zero here; now the mutation dimension
    # tracks the requests actually sent (exact wire telemetry: 30), not the hold.
    assert result.actual_budget["state_changing_requests"] == 30
    assert result.actual_budget["http_requests"] == 30


def test_get_only_active_nuclei_settles_no_mutations():
    requested = {
        "http_requests": 120,
        "state_changing_requests": 120,
        "tool_wall_seconds": 45,
        "agent_actions": 1,
        "active_actions": 1,
    }
    result = _run_nuclei_adapter(
        scanner_options={
            "template_profile": "active",
            "template_ids": "squid-analysis-report-generator",
            "nuclei_active_state_changing": False,
        },
        requested=requested,
        settlement={"mode": "exact", "actual": 5},
    )
    assert result.actual_budget["state_changing_requests"] == 0


def test_plan_reserves_state_changing_only_when_authorized():
    _size, authorized = batch_profile_shape(
        "balanced", "templates.active_batch", allow_state_changing_http=True,
    )
    _size, unauthorized = batch_profile_shape(
        "balanced", "templates.active_batch", allow_state_changing_http=False,
    )
    assert authorized.get("state_changing_requests", 0) > 0
    assert authorized["state_changing_requests"] == authorized["http_requests"]
    assert "state_changing_requests" not in unauthorized


def test_active_argv_uses_explicit_id_allowlist_not_tag_filter():
    plan = agent_tools.build_enforced_scanner_plan(
        "nuclei",
        "https://app.example.test/",
        {
            "_batch_attempt": True,
            "template_profile": "active",
            "template_ids": _ACTIVE_IDS,
            "severity": "high,critical",
            "nuclei_active_state_changing": True,
        },
        reserved_budget={
            "http_requests": 120,
            "state_changing_requests": 120,
            "tool_wall_seconds": 45,
        },
    )
    assert "-id" in plan.argv
    assert _ACTIVE_IDS in plan.argv
    assert "-tags" not in plan.argv
    # Authorized + non-GET templates present -> the hard ceiling carries the
    # mutation dimension so the reservation is proven, not merely reserved.
    assert plan.hard_budget_dict.get("state_changing_requests") == 120


def test_get_only_active_argv_has_no_state_changing_ceiling():
    plan = agent_tools.build_enforced_scanner_plan(
        "nuclei",
        "https://app.example.test/",
        {
            "_batch_attempt": True,
            "template_profile": "active",
            "template_ids": "squid-analysis-report-generator",
            "severity": "high,critical",
            "nuclei_active_state_changing": False,
        },
        reserved_budget={
            "http_requests": 120,
            "tool_wall_seconds": 45,
        },
    )
    assert "-id" in plan.argv
    assert "-tags" not in plan.argv
    assert "state_changing_requests" not in plan.hard_budget_dict


def test_malformed_active_allowlist_fails_closed():
    with pytest.raises(agent_tools.AgentToolError):
        agent_tools.build_enforced_scanner_plan(
            "nuclei",
            "https://app.example.test/",
            {
                "_batch_attempt": True,
                "template_profile": "active",
                "template_ids": "ok-id, bad id with spaces",
                "nuclei_active_state_changing": False,
            },
            reserved_budget={"http_requests": 120, "tool_wall_seconds": 45},
        )
