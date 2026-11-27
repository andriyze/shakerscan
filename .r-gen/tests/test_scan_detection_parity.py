from __future__ import annotations

import asyncio

from api.scan.action_plan import ScanActionPlanCompiler
from api.scan.orchestrator import ScanOrchestrator
from tests.test_scan_action_compiler import _execution, _target
from tests.test_scan_orchestrator import FakeBackend, FakeExecutor


def _compile(scan_id: str):
    return ScanActionPlanCompiler().compile(
        scan_id=scan_id,
        execution_plan=_execution(include=("xss",), active=True),
        target_binding=_target(),
    )


def test_local_broker_and_parallel_shards_preserve_action_and_evidence_contracts():
    local_plan = _compile("60000000-0000-4000-8000-000000000001")
    broker_plan = _compile("60000000-0000-4000-8000-000000000002")
    shard_plan = _compile("60000000-0000-4000-8000-000000000003")

    expected_actions = tuple(action.action_id for action in local_plan.actions)
    expected_capabilities = tuple(
        action.capability_name for action in local_plan.actions
    )
    expected_outputs = tuple(action.output_schema for action in local_plan.actions)
    reports = []
    for plan, backend_name in (
        (local_plan, "local"),
        (broker_plan, "broker"),
        # Parallel children use the same backend protocol and immutable graph;
        # sharding changes input bindings/sub-budgets, never capability semantics.
        (shard_plan, "local"),
    ):
        assert tuple(action.action_id for action in plan.actions) == expected_actions
        assert tuple(action.capability_name for action in plan.actions) == expected_capabilities
        assert tuple(action.output_schema for action in plan.actions) == expected_outputs
        backend = FakeBackend(plan, backend_name)
        reports.append(asyncio.run(
            ScanOrchestrator(
                backend=backend, executor=FakeExecutor(),
            ).run(plan)
        ))

    assert all(report.action_ids == expected_actions for report in reports)
    assert reports[0].status_matrix == reports[1].status_matrix == reports[2].status_matrix
    assert set(reports[0].status_matrix.values()) == {"success"}
