from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from dataclasses import replace

import pytest

from api.runtime.receipts import CapabilityReceipt
from api.scan.execution_backend import ActionLease
from api.scan.worker_action_executor import (
    ReceiptScanActionExecutor,
    WorkerActionExecutionError,
)
from tests.test_scan_orchestrator import SCAN_ID, _plan
from api.scan.action_interruption import action_interrupted


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


def test_lost_credential_authority_blocks_next_action_but_preserves_finalization():
    plan = _plan()
    dispatched, checked = [], []

    async def dispatch(action, *_args):
        dispatched.append(action.action_id)
        return _receipt(action)

    async def check(action):
        checked.append(action.action_id)
        return "authentication_uncertain" if action.action_id == "baseline.security_txt" else None

    executor = ReceiptScanActionExecutor(scan_id=SCAN_ID, target_id="target-1",
        worker_id="local-worker-1", dispatcher=dispatch, credential_check=check)

    async def run():
        return [await executor.execute(action, _lease(plan, action), lambda: _heartbeat([]))
                for action in plan.actions]

    first, blocked, final = asyncio.run(run())
    assert first.status == final.status == "success"
    assert blocked.status == "blocked" and blocked.errors == ("authentication_uncertain",)
    assert all(value == 0 for value in blocked.budget_consumed.values())
    assert blocked.redacted_execution["execution_started"] is False
    assert dispatched == ["baseline.http", "finalize.report"]
    assert checked == ["baseline.http", "baseline.http", "baseline.security_txt"]


@pytest.mark.parametrize("user_cancel", [False, True])
def test_inflight_authority_loss_stops_action_and_preserves_partial_evidence(user_cancel):
    plan = _plan()
    action = plan.actions[0]
    started = False
    revoked_observed = False

    async def check(_action):
        nonlocal revoked_observed
        if started and not revoked_observed:
            revoked_observed = True
            return "authentication_uncertain"
        return None  # A later/out-of-order positive result cannot erase the gap.

    async def dispatch(_action, *_args):
        nonlocal started
        started = True
        async with asyncio.timeout(2):
            while not action_interrupted():
                await asyncio.sleep(0.01)
        return replace(_receipt(action), status="cancelled", errors=("cancelled",),
            observations=({"kind": "completed_fixture_evidence", "count": 1},),
            budget_consumed={"http_requests": 1})

    executor = ReceiptScanActionExecutor(scan_id=SCAN_ID, target_id="target-1", worker_id="local-worker-1",
        dispatcher=dispatch, credential_check=check, user_cancelled=lambda: user_cancel)
    receipt = asyncio.run(executor.execute(action, _lease(plan, action), lambda: _heartbeat([])))
    assert receipt.status == ("cancelled" if user_cancel else "partial")
    assert receipt.observations[0] == {"kind": "completed_fixture_evidence", "count": 1}
    assert receipt.budget_consumed["http_requests"] == 1
    if not user_cancel:
        assert receipt.errors == ("authentication_uncertain",)
        assert receipt.partial and receipt.redacted_execution["identity_interruption"]["observed_at"]
    assert not action_interrupted()


def test_action_interruption_does_not_leak_across_concurrent_tasks():
    from api.scan.action_interruption import ActionInterruption, interruption_scope

    async def run():
        entered = asyncio.Event()
        release = asyncio.Event()

        async def interrupted():
            with interruption_scope(ActionInterruption(reason="authentication_uncertain")):
                entered.set()
                await release.wait()
                assert action_interrupted()

        async def unaffected():
            await entered.wait()
            assert not action_interrupted()
            release.set()

        await asyncio.gather(interrupted(), unaffected())
        assert not action_interrupted()

    asyncio.run(run())
