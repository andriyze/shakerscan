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

    def __init__(self, *, check=None, polls=(), poll_seconds=0.02):
        self.poll_seconds = poll_seconds
        self._check = check
        self._polls = list(polls)
        self.checked: list[str] = []
        self.polled: list[str] = []

    async def check(self, action):
        self.checked.append(action.action_id)
        if isinstance(self._check, BaseException):
            raise self._check
        return self._check

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


def test_a_check_that_cannot_decide_fails_closed():
    plan = _plan()
    action = plan.actions[0]
    calls = []
    authority = FixtureAuthority(check=OSError("database unavailable"))
    receipt = asyncio.run(_executor(_long_dispatch(calls), authority).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert calls == [] and receipt.status == "blocked"
    assert receipt.errors == ("authorization_revoked",)


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


def test_one_failed_poll_is_tolerated_and_two_consecutive_interrupt():
    plan = _plan()
    action = plan.actions[0]
    tolerated = FixtureAuthority(polls=(OSError("blip"), None, OSError("blip"), None))
    receipt = asyncio.run(_executor(_long_dispatch([], seconds=0.3), tolerated).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert receipt.status == "success" and len(tolerated.polled) >= 4

    failing = FixtureAuthority(polls=(None, OSError("down"), OSError("down")))
    receipt = asyncio.run(_executor(_long_dispatch([]), failing).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert receipt.status == "partial" and receipt.errors == ("authorization_revoked",)
    assert len(failing.polled) == 3


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
