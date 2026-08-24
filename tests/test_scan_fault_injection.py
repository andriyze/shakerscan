from __future__ import annotations

import asyncio

import pytest

from api.scan.capability_result import CapabilityResultStatus
from api.scan.execution_backend import ScanExecutionBackendError
from api.scan.orchestrator import ScanOrchestrator
from tests.test_scan_orchestrator import FakeBackend, FakeExecutor, _plan


class _ReservationFaultBackend(FakeBackend):
    async def acquire_action(self, action):
        raise ScanExecutionBackendError(
            f"injected failure before reservation for {action.action_id}"
        )


class _ExecutionFaultExecutor(FakeExecutor):
    def __init__(self, phase: str):
        super().__init__()
        self.phase = phase

    async def execute(self, action, lease, heartbeat):
        self.executed.append(action.action_id)
        await heartbeat()
        raise RuntimeError(f"injected failure {self.phase}")


class _SettledResponseLostBackend(FakeBackend):
    """Persist one terminal result, then lose the worker-facing acknowledgement."""

    def __init__(self, plan, backend_name):
        super().__init__(plan, backend_name)
        self.response_lost = False

    async def settle(self, lease, result):
        settled = await super().settle(lease, result)
        if not self.response_lost:
            self.response_lost = True
            raise ScanExecutionBackendError("injected post-settlement response loss")
        return settled


class _ManifestUploadFaultBackend(FakeBackend):
    async def settle(self, lease, result):
        if result.observation_manifest_ref is not None:
            raise ScanExecutionBackendError("injected manifest upload failure")
        return await super().settle(lease, result)


def test_failure_before_reservation_emits_no_execution_or_terminal_result():
    plan = _plan()
    backend = _ReservationFaultBackend(plan, "local")
    executor = FakeExecutor()

    with pytest.raises(ScanExecutionBackendError, match="before reservation"):
        asyncio.run(ScanOrchestrator(backend=backend, executor=executor).run(plan))

    assert executor.executed == []
    assert backend.results == {}


@pytest.mark.parametrize(
    "phase",
    (
        "after_hold",
        "after_process_start",
        "after_target_response",
        "before_receipt",
    ),
)
def test_uncertain_execution_faults_charge_the_full_hold_and_fail_closed(phase):
    plan = _plan()
    backend = FakeBackend(plan, "local")
    executor = _ExecutionFaultExecutor(phase)

    report = asyncio.run(
        ScanOrchestrator(backend=backend, executor=executor).run(plan)
    )

    first = report.action_results[plan.actions[0].action_id]
    assert first.status is CapabilityResultStatus.FAILED
    assert dict(first.budget_consumed) == dict(plan.actions[0].requested_budget)
    assert report.status_matrix[plan.actions[1].action_id] == "blocked"
    assert report.status_matrix["finalize.report"] == "failed"


@pytest.mark.parametrize("backend_name", ("local", "broker"))
def test_lost_ack_after_terminal_settlement_resumes_without_duplicate_traffic(
    backend_name,
):
    plan = _plan()
    backend = _SettledResponseLostBackend(plan, backend_name)
    first_executor = FakeExecutor()

    with pytest.raises(ScanExecutionBackendError, match="post-settlement"):
        asyncio.run(
            ScanOrchestrator(
                backend=backend, executor=first_executor,
            ).run(plan)
        )
    assert first_executor.executed == [plan.actions[0].action_id]
    assert plan.actions[0].action_id in backend.results

    resumed_executor = FakeExecutor()
    report = asyncio.run(
        ScanOrchestrator(
            backend=backend, executor=resumed_executor,
        ).run(plan)
    )

    assert plan.actions[0].action_id not in resumed_executor.executed
    assert report.status_matrix == {
        action.action_id: "success" for action in plan.actions
    }


def test_manifest_upload_failure_never_reports_the_action_complete():
    plan = _plan()
    backend = _ManifestUploadFaultBackend(plan, "broker")

    with pytest.raises(ScanExecutionBackendError, match="manifest upload"):
        asyncio.run(
            ScanOrchestrator(
                backend=backend, executor=FakeExecutor(),
            ).run(plan)
        )

    assert plan.actions[0].action_id not in backend.results


def test_finalizer_fault_is_a_terminal_failure_not_a_clean_report():
    plan = _plan()
    backend = FakeBackend(plan, "local")
    executor = _ExecutionFaultExecutor("during_finalization")
    # Let the target-facing actions succeed and inject only at finalization.
    original_execute = executor.execute

    async def execute(action, lease, heartbeat):
        if action.action_id == "finalize.report":
            return await original_execute(action, lease, heartbeat)
        return await FakeExecutor.execute(executor, action, lease, heartbeat)

    executor.execute = execute
    report = asyncio.run(
        ScanOrchestrator(backend=backend, executor=executor).run(plan)
    )

    assert report.status_matrix["baseline.http"] == "success"
    assert report.status_matrix["baseline.security_txt"] == "success"
    assert report.status_matrix["finalize.report"] == "failed"
