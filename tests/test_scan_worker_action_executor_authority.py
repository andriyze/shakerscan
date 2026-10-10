"""The local executor re-checks target authorization before and while each action runs.

Unit level: the dispatcher and the authority are fixtures (``FixtureAuthority``,
``fixture_dispatch``); nothing here reaches a database or the network. The PostgreSQL
behaviour of the real guard is in ``test_scan_local_revocation_postgres.py``.
"""
from __future__ import annotations

import asyncio
from dataclasses import replace
import time

import pytest

from api.scan.action_interruption import action_interrupted
from api.scan.worker_action_executor import ReceiptScanActionExecutor
from tests.test_scan_orchestrator import SCAN_ID, _plan
from tests.test_worker_action_executor import _lease, _receipt


class FixtureAuthority:
    """Fixture authority: scripted answers for ``check`` and ``poll``."""

    def __init__(self, *, check=None, polls=(), poll_seconds=0.02, unverified_after_seconds=0.2,
                 check_retry_delays=(0.01, 0.01)):
        self.poll_seconds = poll_seconds
        self.unverified_after_seconds = unverified_after_seconds
        self.check_retry_delays = check_retry_delays
        self._check = list(check) if isinstance(check, list) else check
        self._polls = list(polls)
        self.checked: list[str] = []
        self.polled: list[str] = []

    async def check(self, action):
        self.checked.append(action.action_id)
        answer = self._check.pop(0) if isinstance(self._check, list) else self._check
        if isinstance(answer, BaseException):
            raise answer
        return answer

    async def poll(self, action):
        self.polled.append(action.action_id)
        answer = self._polls.pop(0) if self._polls else None
        if isinstance(answer, BaseException):
            raise answer
        return answer


def _executor(dispatch, authority, **kwargs):
    return ReceiptScanActionExecutor(scan_id=SCAN_ID, target_id="target-1", worker_id="local-worker-1",
        dispatcher=dispatch, authority=authority, **kwargs)


def _long_dispatch(calls, *, seconds=5.0):
    """A fixture tool process: runs until its action is interrupted, as the process runner does."""
    async def dispatch(action, _lease, _heartbeat):
        calls.append(action.action_id)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if action_interrupted():
                return replace(_receipt(action), status="cancelled", errors=("cancelled",),
                               budget_consumed={"http_requests": 1})
            await asyncio.sleep(0.01)
        return _receipt(action)
    return dispatch


def test_a_withdrawn_authority_blocks_before_dispatch_without_charging_budget():
    plan = _plan()
    action = plan.actions[0]
    calls = []
    authority = FixtureAuthority(check="authorization_revoked")
    receipt = asyncio.run(_executor(_long_dispatch(calls), authority).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert calls == []
    assert receipt.status == "blocked"
    assert receipt.errors == ("authorization_revoked",)
    assert set(receipt.budget_consumed.values()) == {0}
    assert receipt.redacted_execution["execution_started"] is False


def test_a_check_that_cannot_reach_the_database_retries_then_blocks_as_unverified():
    plan = _plan()
    action = plan.actions[0]
    calls = []
    authority = FixtureAuthority(check=OSError("database unavailable"))
    receipt = asyncio.run(_executor(_long_dispatch(calls), authority).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert calls == [] and receipt.status == "blocked"
    # Unverified, never reported as a revoke that did not happen.
    assert receipt.errors == ("authorization_unverified",)
    assert len(authority.checked) == 3  # the first try and both retries


def test_a_check_that_recovers_within_its_retries_dispatches_normally():
    plan = _plan()
    action = plan.actions[0]
    calls = []
    authority = FixtureAuthority(check=[OSError("blip"), None])
    receipt = asyncio.run(_executor(_long_dispatch(calls, seconds=0.01), authority).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert calls == [action.action_id] and receipt.status == "success"


def test_a_revoke_while_the_action_runs_interrupts_it_and_keeps_partial_output():
    plan = _plan()
    action = plan.actions[0]
    calls = []
    authority = FixtureAuthority(polls=(None, None, "authorization_revoked"))
    started = time.monotonic()
    receipt = asyncio.run(_executor(_long_dispatch(calls), authority).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert time.monotonic() - started < 2.0
    assert calls == [action.action_id]
    assert receipt.status == "partial" and receipt.partial
    assert receipt.errors == ("authorization_revoked",)
    assert receipt.budget_consumed["http_requests"] == 1
    assert receipt.redacted_execution["target_authority_interruption"]["reason_code"] == "authorization_revoked"
    assert receipt.observations[-1]["kind"] == "target_authority_interruption"
    assert "identity_interruption" not in receipt.redacted_execution


def test_expiry_while_the_action_runs_is_reported_as_expired():
    plan = _plan()
    action = plan.actions[0]
    authority = FixtureAuthority(polls=(None, "authorization_expired"))
    receipt = asyncio.run(_executor(_long_dispatch([]), authority).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert receipt.status == "partial" and receipt.errors == ("authorization_expired",)


def test_a_database_blip_shorter_than_the_tolerance_does_not_stop_a_healthy_action():
    plan = _plan()
    action = plan.actions[0]
    # Several consecutive failed polls (about 0.1 s of outage) inside a 0.2 s tolerance.
    blip = FixtureAuthority(polls=(OSError("blip"),) * 5 + (None,))
    receipt = asyncio.run(_executor(_long_dispatch([], seconds=0.5), blip).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert receipt.status == "success" and receipt.errors == ()
    assert len(blip.polled) >= 6


def test_a_longer_outage_interrupts_as_unverified_not_revoked():
    plan = _plan()
    action = plan.actions[0]
    outage = FixtureAuthority(polls=(None,) + (OSError("down"),) * 200)
    started = time.monotonic()
    receipt = asyncio.run(_executor(_long_dispatch([]), outage).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert time.monotonic() - started < 1.5
    assert receipt.status == "partial" and receipt.errors == ("authorization_unverified",)
    assert receipt.redacted_execution["target_authority_interruption"]["reason_code"] == "authorization_unverified"


def test_the_production_tolerance_is_time_based():
    from api.scan.worker_action_executor import AUTHORITY_UNVERIFIED_AFTER_SECONDS
    from api.scan.action_authority_guard import ScanAuthorityGuard
    assert AUTHORITY_UNVERIFIED_AFTER_SECONDS == 10.0
    guard = ScanAuthorityGuard(pool=None, target_binding=None, scope_receipt_id=None, approval_receipt_id=None)
    assert guard.unverified_after_seconds == 10.0 and guard.poll_seconds == 2.0


def test_the_report_finalizer_is_exempt():
    plan = _plan()
    final = plan.actions[-1]
    assert final.action_id == "finalize.report"
    calls = []

    async def dispatch(action, _lease, _heartbeat):
        calls.append(action.action_id)
        return _receipt(action)

    authority = FixtureAuthority(check="authorization_revoked", polls=("authorization_revoked",))
    receipt = asyncio.run(_executor(dispatch, authority).execute(
        final, _lease(plan, final), lambda: asyncio.sleep(0)))
    assert calls == ["finalize.report"] and receipt.status == "success"
    assert authority.checked == [] and authority.polled == []


def test_authority_is_checked_before_credentials_and_a_denial_skips_them():
    plan = _plan()
    action = plan.actions[0]
    order = []

    async def credential_check(_action):
        order.append("credential")
        return None

    class Ordered(FixtureAuthority):
        async def check(self, action):
            order.append("authority")
            return await super().check(action)

    allowed = Ordered()
    asyncio.run(_executor(_long_dispatch([], seconds=0.01), allowed, credential_check=credential_check).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert order[:2] == ["authority", "credential"]

    order.clear()
    denied = Ordered(check="scope_invalid")
    receipt = asyncio.run(_executor(_long_dispatch([]), denied, credential_check=credential_check).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert order == ["authority"] and receipt.errors == ("scope_invalid",)


def test_polling_stops_with_the_action():
    plan = _plan()
    action = plan.actions[0]
    authority = FixtureAuthority(poll_seconds=0.05)

    async def run():
        executor = _executor(_long_dispatch([], seconds=0.26), authority)
        await executor.execute(action, _lease(plan, action), lambda: asyncio.sleep(0))
        settled = len(authority.polled)
        await asyncio.sleep(0.2)
        return settled

    settled = asyncio.run(run())
    assert 3 <= settled <= 6
    assert len(authority.polled) == settled


@pytest.mark.parametrize("reason", ["not-a-reason"])
def test_an_unknown_reason_from_the_check_fails_closed(reason):
    plan = _plan()
    action = plan.actions[0]
    calls = []
    receipt = asyncio.run(_executor(_long_dispatch(calls), FixtureAuthority(check=reason)).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert calls == [] and receipt.status == "blocked"
    assert receipt.errors == ("authorization_unverified",)


class StallingAuthority(FixtureAuthority):
    """Fixture authority whose checks stall: they never answer, or answer only after a delay.

    ``poll_stall``/``check_stall`` is ``None`` for no stall, ``float('inf')`` for a check that
    never returns (a pool acquisition or query left pending), or seconds before the scripted
    answer. Records every check that was cancelled and every check still pending.
    """

    def __init__(self, *, poll_stall=None, check_stall=None, stall_polls_from=0, **kwargs):
        super().__init__(**kwargs)
        self.poll_stall, self.check_stall, self.stall_polls_from = poll_stall, check_stall, stall_polls_from
        self.cancelled: list[str] = []
        self.pending = 0

    async def _stall(self, seconds, kind):
        self.pending += 1
        try:
            await asyncio.sleep(3600 if seconds == float("inf") else seconds)
        except asyncio.CancelledError:
            self.cancelled.append(kind)
            raise
        finally:
            self.pending -= 1

    async def check(self, action):
        if self.check_stall is not None:
            await self._stall(self.check_stall, "check")
        return await super().check(action)

    async def poll(self, action):
        if self.poll_stall is not None and len(self.polled) >= self.stall_polls_from:
            self.polled.append(action.action_id)
            await self._stall(self.poll_stall, "poll")
            answer = self._polls.pop(0) if self._polls else None
            if isinstance(answer, BaseException):
                raise answer
            return answer
        return await super().poll(action)


def _run_with_tasks(coro):
    """Run ``coro``; return its result and the tasks still alive once it finished."""
    async def run():
        result = await coro
        await asyncio.sleep(0)
        return result, [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
    return asyncio.run(run())


def test_a_poll_that_never_returns_interrupts_within_the_tolerance():
    plan = _plan()
    action = plan.actions[0]
    calls = []
    authority = StallingAuthority(poll_stall=float("inf"), poll_seconds=0.05, unverified_after_seconds=0.4)
    started = time.monotonic()
    receipt, alive = _run_with_tasks(_executor(_long_dispatch(calls), authority).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    elapsed = time.monotonic() - started
    # The deadline runs from the pre-dispatch confirmation; the hung poll cannot hold it back.
    assert 0.35 <= elapsed < 0.4 + 0.3
    assert calls == [action.action_id]
    assert receipt.status == "partial" and receipt.errors == ("authorization_unverified",)
    assert receipt.budget_consumed["http_requests"] == 1
    assert receipt.redacted_execution["target_authority_interruption"]["reason_code"] == "authorization_unverified"
    # The stalled poll was cancelled and nothing is left running.
    assert authority.cancelled == ["poll"] and authority.pending == 0
    assert alive == []


def test_the_deadline_runs_from_the_last_confirmation_not_the_first_failure():
    plan = _plan()
    action = plan.actions[0]
    # Two confirmed polls, then every poll fails only after a delay longer than its interval.
    authority = StallingAuthority(poll_stall=0.15, stall_polls_from=2, poll_seconds=0.05,
                                  unverified_after_seconds=0.4,
                                  polls=(None, None) + (OSError("slow failure"),) * 50)
    started = time.monotonic()
    receipt, alive = _run_with_tasks(_executor(_long_dispatch([]), authority).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    elapsed = time.monotonic() - started
    # Last confirmation at about 0.1 s (two 0.05 s intervals), so the stop is due by about
    # 0.5 s; counting from the first slow failure (about 0.25 s) would give about 0.65 s.
    assert elapsed < 0.1 + 0.4 + 0.1
    assert receipt.status == "partial" and receipt.errors == ("authorization_unverified",)
    assert authority.pending == 0 and alive == []


def test_a_slow_but_successful_poll_does_not_interrupt():
    plan = _plan()
    action = plan.actions[0]
    # Each poll answers after 0.1 s: slower than the interval, well inside the tolerance.
    authority = StallingAuthority(poll_stall=0.1, poll_seconds=0.05, unverified_after_seconds=0.4)
    receipt, alive = _run_with_tasks(_executor(_long_dispatch([], seconds=0.8), authority).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert receipt.status == "success" and receipt.errors == ()
    assert len(authority.polled) >= 4 and alive == []


def test_a_pre_dispatch_check_that_never_returns_blocks_within_the_tolerance():
    plan = _plan()
    action = plan.actions[0]
    calls = []
    authority = StallingAuthority(check_stall=float("inf"), unverified_after_seconds=0.3,
                                  check_retry_delays=(0.01, 0.01))
    started = time.monotonic()
    receipt, alive = _run_with_tasks(_executor(_long_dispatch(calls), authority).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert time.monotonic() - started < 0.3 + 0.3
    assert calls == [] and receipt.status == "blocked"
    assert receipt.errors == ("authorization_unverified",)
    assert set(receipt.budget_consumed.values()) == {0}
    assert authority.cancelled == ["check"] and authority.pending == 0 and alive == []


def test_pre_dispatch_retries_stop_at_the_tolerance():
    plan = _plan()
    action = plan.actions[0]
    calls = []
    # Each attempt fails after 0.15 s; four attempts with their delays would take about 1.5 s.
    authority = StallingAuthority(check_stall=0.15, unverified_after_seconds=0.4,
                                  check=OSError("slow failure"), check_retry_delays=(0.2, 0.2, 0.2))
    started = time.monotonic()
    receipt, alive = _run_with_tasks(_executor(_long_dispatch(calls), authority).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert time.monotonic() - started < 0.4 + 0.3
    assert calls == [] and receipt.errors == ("authorization_unverified",)
    # The first attempt failed at 0.15 s; the second started at 0.35 s and was cancelled at the
    # 0.4 s deadline before it answered; no third attempt was made.
    assert len(authority.checked) == 1 and authority.cancelled == ["check"]
    assert authority.pending == 0 and alive == []


def test_a_slow_but_successful_pre_dispatch_check_does_not_make_the_action_unverified():
    plan = _plan()
    action = plan.actions[0]
    # The check before dispatch answers yes after 0.92 s of a 1 s tolerance; polls are healthy.
    authority = StallingAuthority(check_stall=0.92, poll_seconds=0.2, unverified_after_seconds=1.0)
    receipt, alive = _run_with_tasks(_executor(_long_dispatch([], seconds=1.5), authority).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert receipt.status == "success" and receipt.errors == ()
    # The first poll ran at once, before the deadline, instead of after a full interval.
    assert len(authority.polled) >= 5 and alive == []


def test_steady_polls_slower_than_the_interval_keep_a_healthy_action_running():
    plan = _plan()
    action = plan.actions[0]
    # Every poll takes 0.4 s of a 1 s tolerance with a 0.3 s interval. Waiting a full interval
    # after each poll would leave the next one 0.3 s to answer; it starts early enough instead.
    authority = StallingAuthority(poll_stall=0.4, poll_seconds=0.3, unverified_after_seconds=1.0)
    receipt, alive = _run_with_tasks(_executor(_long_dispatch([], seconds=2.5), authority).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert receipt.status == "success" and receipt.errors == ()
    assert authority.pending == 0 and alive == []  # the poll pending at the end was cancelled


def test_unverified_is_declared_only_after_a_poll_was_attempted():
    from api.scan.authority_deadline import watch_authorization
    from api.scan.action_interruption import ActionInterruption

    async def run():
        # The confirmation is already at the deadline when watching starts (a slow check).
        authority = FixtureAuthority(poll_seconds=0.2, unverified_after_seconds=0.5)
        loop = asyncio.get_running_loop()
        signal, stopped, interrupts = ActionInterruption(), asyncio.Event(), []
        task = asyncio.create_task(watch_authorization(
            authority, _plan().actions[0], confirmed_at=loop.time() - 0.5, stopped=stopped,
            signal=signal, on_interrupt=interrupts.append))
        await asyncio.sleep(0.3)
        stopped.set()
        await task
        return authority, interrupts
    authority, interrupts = asyncio.run(run())
    assert interrupts == [] and len(authority.polled) >= 1
