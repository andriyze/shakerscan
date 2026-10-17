"""A caller cancelled while a helper task unwinds stays cancelled (``stop_task``).

``stop_task`` cancelled a monitor and awaited it, swallowing ``CancelledError``. A cancellation of
the caller that arrived during that await (a user cancel, a worker shutdown) was indistinguishable
from the monitor's own and was swallowed too, so the caller ran on as if nothing had happened.
Unit level: the monitors are fixtures that take a moment to unwind; no database or network.
"""
from __future__ import annotations

import asyncio

import pytest

from api.scan import running_scan_authority, worker_action_executor
from api.scan.authority_deadline import stop_task, stop_tasks
from tests.test_scan_orchestrator import _plan
from tests.test_scan_worker_action_executor_authority import FixtureAuthority, _executor
from tests.test_worker_action_executor import _lease, _receipt


def _slow_helper(unwinding: asyncio.Event, finished: list[str], *, seconds: float = 0.2):
    async def helper(*_args, **_kwargs):
        try:
            await asyncio.sleep(3600)
        finally:
            unwinding.set()
            try:
                await asyncio.sleep(seconds)  # cleanup that takes a moment
            finally:
                finished.append("helper")
    return helper


async def _cancel_when(event: asyncio.Event, task: asyncio.Task) -> None:
    await event.wait()
    task.cancel()


def test_the_callers_cancellation_is_raised_after_the_helper_has_ended():
    async def run():
        unwinding, finished = asyncio.Event(), []
        helper = asyncio.create_task(_slow_helper(unwinding, finished)())
        await asyncio.sleep(0)

        async def caller():
            await stop_task(helper)
            finished.append("caller ran on")

        task = asyncio.create_task(caller())
        canceller = asyncio.create_task(_cancel_when(unwinding, task))
        with pytest.raises(asyncio.CancelledError):
            await task
        await canceller
        assert finished == ["helper"]  # the helper ended; the caller did not run on
        assert helper.done()
    asyncio.run(run())


def test_the_helpers_own_cancellation_is_swallowed_and_its_error_raised():
    async def run():
        unwinding, finished = asyncio.Event(), []
        helper = asyncio.create_task(_slow_helper(unwinding, finished, seconds=0)())
        await asyncio.sleep(0)
        await stop_task(helper)
        assert finished == ["helper"]
        await stop_task(None)

        async def broken():
            try:
                await asyncio.sleep(3600)
            finally:
                raise RuntimeError("monitor failed")
        task = asyncio.create_task(broken())
        await asyncio.sleep(0)
        with pytest.raises(RuntimeError, match="monitor failed"):
            await stop_task(task)
    asyncio.run(run())


def test_every_helper_is_stopped_before_the_callers_cancellation_is_raised():
    async def run():
        unwinding, finished = asyncio.Event(), []
        helpers = [asyncio.create_task(_slow_helper(unwinding, finished, seconds=0.1 * n)()) for n in (1, 2)]
        await asyncio.sleep(0)
        task = asyncio.create_task(stop_tasks(*helpers, None))
        canceller = asyncio.create_task(_cancel_when(unwinding, task))
        with pytest.raises(asyncio.CancelledError):
            await task
        await canceller
        assert finished == ["helper", "helper"] and all(helper.done() for helper in helpers)
    asyncio.run(run())


def test_an_action_cancelled_while_its_authority_monitor_unwinds_is_cancelled(monkeypatch):
    """Entry point: ``ReceiptScanActionExecutor.execute``. The action finished; the worker was
    cancelled while the authorization monitor was being stopped; ``execute`` must not return."""
    unwinding, finished = asyncio.Event(), []
    monkeypatch.setattr(worker_action_executor, "watch_authorization", _slow_helper(unwinding, finished))
    plan = _plan()
    action = plan.actions[0]

    async def dispatch(action, _lease, _heartbeat):
        await asyncio.sleep(0.05)  # the monitor is running
        return _receipt(action)

    async def run():
        task = asyncio.create_task(_executor(dispatch, FixtureAuthority()).execute(
            action, _lease(plan, action), lambda: asyncio.sleep(0)))
        canceller = asyncio.create_task(_cancel_when(unwinding, task))
        with pytest.raises(asyncio.CancelledError):
            await task
        await canceller
        assert finished == ["helper"]
    asyncio.run(run())


def test_a_run_cancelled_while_its_authority_monitor_unwinds_is_cancelled_and_leaves_its_scopes(monkeypatch):
    """Entry point: ``RunningScanAuthority`` (device posture/probe and AI scans)."""
    unwinding, finished = asyncio.Event(), []
    monkeypatch.setattr(running_scan_authority, "watch_authorization", _slow_helper(unwinding, finished))

    async def allowed(_guard, _action):
        return None, 0.0

    monkeypatch.setattr(running_scan_authority, "check_before_start", allowed)
    action = running_scan_authority.RunAuthorityAction("device.scan")

    async def run():
        ran_on = []

        async def scan():
            async with running_scan_authority.RunningScanAuthority(object(), action):
                await asyncio.sleep(0.05)  # the monitor is running
            ran_on.append(True)

        task = asyncio.create_task(scan())
        canceller = asyncio.create_task(_cancel_when(unwinding, task))
        with pytest.raises(asyncio.CancelledError):
            await task
        await canceller
        assert ran_on == [] and finished == ["helper"]
    asyncio.run(run())
