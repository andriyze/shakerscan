from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from api.runtime.receipts import CapabilityReceipt
from api.scan.execution_backend import ActionLease
from api.scan.worker_action_executor import (
    ReceiptScanActionExecutor,
    WorkerActionExecutionError,
)
from tests.test_scan_orchestrator import SCAN_ID, _plan


def _lease(plan, action):
    return ActionLease(
        lease_id="60000000-0000-4000-8000-000000000001",
        lease_token="abcdefghijklmnopqrstuvwxyz012345",
        scan_id=plan.scan_id,
        plan_digest=plan.plan_digest,
        execution_plan_digest=plan.execution_plan_digest,
        target_binding_digest=plan.target_binding_digest,
        action=action,
        backend="local",
        worker_id="local-worker-1",
        lease_seconds=30,
        attempt=1,
    )


def _receipt(action, *, input_digest=None):
    now = datetime.now(timezone.utc).isoformat()
    return CapabilityReceipt(
        capability_name=action.capability_name,
        adapter_name=str(action.placement["adapter_name"]),
        adapter_version=str(action.placement["adapter_version"]),
        target_id="target-1",
        scan_id=SCAN_ID,
        worker_id="local-worker-1",
        status="success",
        input_digest=input_digest or action.action_digest,
        parser_version="1",
        started_at=now,
        finished_at=now,
        budget_reserved=action.requested_budget,
        budget_consumed={},
        observations=(),
    )


def test_worker_action_executor_accepts_only_exact_lease_bound_receipts():
    plan = _plan()
    action = plan.actions[0]
    heartbeats = []

    async def dispatch(_action, _lease, heartbeat):
        await heartbeat()
        return _receipt(action).public_dict()

    executor = ReceiptScanActionExecutor(
        scan_id=SCAN_ID,
        target_id="target-1",
        worker_id="local-worker-1",
        dispatcher=dispatch,
    )
    receipt = asyncio.run(executor.execute(
        action, _lease(plan, action), lambda: _heartbeat(heartbeats),
    ))
    assert receipt.input_digest == action.action_digest
    assert heartbeats == [True]


async def _heartbeat(calls):
    calls.append(True)


def test_worker_action_executor_rejects_receipt_substitution():
    plan = _plan()
    action = plan.actions[0]

    async def dispatch(_action, _lease, _heartbeat):
        return _receipt(action, input_digest="f" * 64)

    executor = ReceiptScanActionExecutor(
        scan_id=SCAN_ID,
        target_id="target-1",
        worker_id="local-worker-1",
        dispatcher=dispatch,
    )
    with pytest.raises(WorkerActionExecutionError, match="differs"):
        asyncio.run(executor.execute(
            action, _lease(plan, action), lambda: _heartbeat([]),
        ))


def test_worker_action_executor_emits_bounded_nonexecution_receipts():
    plan = _plan()
    action = plan.actions[0]

    async def unused(*_args):
        raise AssertionError("not called")

    executor = ReceiptScanActionExecutor(
        scan_id=SCAN_ID,
        target_id="target-1",
        worker_id="local-worker-1",
        dispatcher=unused,
    )
    skipped = asyncio.run(executor.terminal_without_execution(
        action,
        _lease(plan, action),
        status="skipped",
        reason_code="policy_disabled",
        charge_full_reservation=False,
    ))
    uncertain = asyncio.run(executor.terminal_without_execution(
        action,
        _lease(plan, action),
        status="failed",
        reason_code="adapter_failed",
        charge_full_reservation=True,
    ))

    assert all(amount == 0 for amount in skipped.budget_consumed.values())
    assert dict(uncertain.budget_consumed) == dict(action.requested_budget)
    assert skipped.redacted_execution["execution_started"] is False
