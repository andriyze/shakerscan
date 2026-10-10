"""A running broker action re-checks its target's authorization through the control plane.

Unit level: the control plane is a fixture request function (``FixtureControlPlane``) and the
dispatcher a fixture tool loop; the executor and ``BrokerActionAuthority`` are the real ones.
The control-plane route over PostgreSQL is in ``test_scan_running_authority_postgres.py``.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
import re
import time

from api.scan.broker_backend import BrokerActionAuthority, BrokerActionHTTPError, BrokerScanExecutionBackend
from tests.test_scan_orchestrator import _plan
from tests.test_scan_worker_action_executor_authority import _executor, _long_dispatch
from tests.test_worker_action_executor import _lease

ROOT = Path(__file__).resolve().parents[1]
BASE = "/fleet/broker/nodes/node-1/leases/lease-1"


class FixtureControlPlane:
    """Fixture request function: scripted answers to the authority endpoint."""

    def __init__(self, answers=(), *, default=None):
        self.answers, self.default = list(answers), default
        self.calls: list[tuple[str, str, dict]] = []

    async def __call__(self, method, path, payload):
        self.calls.append((method, path, dict(payload or {})))
        answer = self.answers.pop(0) if self.answers else self.default
        if isinstance(answer, BaseException):
            raise answer
        if answer == "hang":
            await asyncio.sleep(3600)
        return answer


def _authority(plan, control, **timing):
    backend = BrokerScanExecutionBackend(plan=plan, worker_id="broker:node-1",
                                         job_lease_token="t" * 40, base_path=BASE, request=control)
    timing = {"poll_seconds": 0.05, "unverified_after_seconds": 0.4, "check_retry_delays": (0.01,), **timing}
    return BrokerActionAuthority(lambda: backend, control, **timing)


def test_the_authority_request_names_the_action_and_its_job_lease():
    plan = _plan()
    action = plan.actions[0]
    control = FixtureControlPlane(default={"reason": None})
    assert asyncio.run(_authority(plan, control).check(action)) is None
    method, path, payload = control.calls[0]
    assert (method, path) == ("POST", f"{BASE}/actions/{action.action_id}/authority")
    assert payload == {"job_lease_token": "t" * 40, "worker_id": "broker:node-1", "plan_digest": plan.plan_digest,
                       "action_id": action.action_id, "action_digest": action.action_digest}


def test_a_revoke_on_the_control_plane_stops_the_running_remote_action():
    plan = _plan()
    action = plan.actions[0]
    calls = []
    control = FixtureControlPlane([{"reason": None}, {"reason": None}, {"reason": "authorization_revoked"}])
    authority = _authority(plan, control)
    started = time.monotonic()
    receipt = asyncio.run(_executor(_long_dispatch(calls), authority).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert time.monotonic() - started < 1.0
    assert calls == [action.action_id]
    assert receipt.status == "partial" and receipt.errors == ("authorization_revoked",)
    assert receipt.budget_consumed["http_requests"] == 1
    assert receipt.redacted_execution["target_authority_interruption"]["reason_code"] == "authorization_revoked"
    # Withdrawn for the rest of the Scan: the next action is blocked without asking again.
    asked = len(control.calls)
    later = asyncio.run(_executor(_long_dispatch(calls), authority).execute(
        plan.actions[1], _lease(plan, plan.actions[1]), lambda: asyncio.sleep(0)))
    assert later.status == "blocked" and later.errors == ("authorization_revoked",)
    assert len(control.calls) == asked and calls == [action.action_id]


def test_a_denial_before_dispatch_blocks_the_remote_action_without_traffic():
    plan = _plan()
    action = plan.actions[0]
    calls = []
    control = FixtureControlPlane(default={"reason": "scope_invalid"})
    receipt = asyncio.run(_executor(_long_dispatch(calls), _authority(plan, control)).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert calls == [] and receipt.status == "blocked" and receipt.errors == ("scope_invalid",)
    assert set(receipt.budget_consumed.values()) == {0}


def test_an_unreachable_control_plane_stops_the_action_as_unverified_not_revoked():
    plan = _plan()
    action = plan.actions[0]
    control = FixtureControlPlane([{"reason": None}], default=BrokerActionHTTPError(503, "unavailable"))
    authority = _authority(plan, control)
    started = time.monotonic()
    receipt = asyncio.run(_executor(_long_dispatch([]), authority).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert time.monotonic() - started < 0.4 + 0.3
    assert receipt.status == "partial" and receipt.errors == ("authorization_unverified",)
    assert authority.reason is None  # not withdrawn: the next action is asked again


def test_a_control_plane_that_never_answers_stops_the_action_within_the_tolerance():
    plan = _plan()
    action = plan.actions[0]
    control = FixtureControlPlane([{"reason": None}], default="hang")
    started = time.monotonic()
    receipt = asyncio.run(_executor(_long_dispatch([]), _authority(plan, control)).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert time.monotonic() - started < 0.4 + 0.3
    assert receipt.status == "partial" and receipt.errors == ("authorization_unverified",)


def test_a_brief_control_plane_outage_does_not_stop_a_healthy_action():
    plan = _plan()
    action = plan.actions[0]
    control = FixtureControlPlane([{"reason": None}, *[BrokerActionHTTPError(503, "blip")] * 3],
                                  default={"reason": None})
    receipt = asyncio.run(_executor(_long_dispatch([], seconds=0.6), _authority(plan, control)).execute(
        action, _lease(plan, action), lambda: asyncio.sleep(0)))
    assert receipt.status == "success" and receipt.errors == ()


def test_an_invalid_or_unknown_answer_is_unverified_never_a_revoke():
    plan = _plan()
    action = plan.actions[0]
    for answer in ({"reason": "not-a-reason"}, {"status": "ok"}, None):
        control = FixtureControlPlane(default=answer)
        authority = _authority(plan, control)
        receipt = asyncio.run(_executor(_long_dispatch([]), authority).execute(
            action, _lease(plan, action), lambda: asyncio.sleep(0)))
        assert receipt.status == "blocked" and receipt.errors == ("authorization_unverified",)
        assert authority.reason is None


def test_the_broker_worker_runs_every_round_under_the_authority():
    source = (ROOT / "api" / "broker_worker.py").read_text(encoding="utf-8")
    body = source[source.index("async def _execute_broker_action_plan"):]
    body = body[:re.search(r"\n(?:async )?def ", body).start()]
    assert body.count("ReceiptScanActionExecutor(") == 2
    assert body.count("authority=authority,") == 2
    assert "BrokerActionAuthority(lambda: backend, authority_request)" in body


def test_authority_checks_reuse_the_plan_read_for_the_lease_but_always_check_the_lease(monkeypatch):
    """The frequent authority route reads the plan and job once per plan digest; the lease row
    (status, expiry, worker) and the Scan's current plan digest are read on every call."""
    from datetime import timedelta
    from types import SimpleNamespace

    from fastapi import HTTPException
    from api.fleet_routes import router as fleet
    from tests.test_scan_broker_backend import _plan as broker_plan

    plan = broker_plan()
    action = plan.actions[0]
    lease = {"status": "leased", "lease_expires_at": fleet.utc_now() + timedelta(minutes=5),
             "worker_id": "node-1", "scan_id": plan.scan_id}
    loads = []

    async def lease_row(_conn, **_kwargs):
        return dict(lease)

    class Store:
        async def load_plan(self, _conn, *, scan_id):
            loads.append(scan_id)
            return plan

    stored = {"digest": plan.plan_digest}

    class Conn:
        async def fetchrow(self, _query, *_args):
            return {"status": "running", "target_id": None, "scan_job_payload": "{}"}

        async def fetchval(self, query, *_args):
            assert "scan_action_plan_digest" in query
            return stored["digest"]

    job = SimpleNamespace(scan_id=plan.scan_id, shard=None, target=SimpleNamespace(digest=plan.target_binding_digest),
                          execution_plan=SimpleNamespace(digest=plan.execution_plan_digest))
    monkeypatch.setattr(fleet, "_broker_lease_row", lease_row)
    monkeypatch.setattr(fleet, "PostgresScanActionStore", Store)
    monkeypatch.setattr(fleet.CanonicalScanJob, "from_payload", staticmethod(lambda _raw: job))
    monkeypatch.setattr(fleet, "_pool", lambda: object())
    monkeypatch.setattr(fleet, "_BROKER_PLANS", type(fleet._BROKER_PLANS)())

    async def context(**kwargs):
        return await fleet._broker_action_context(
            Conn(), node_id="node-1", lease_id="lease-1", job_lease_token="t" * 40, worker_id="broker:node-1",
            plan_digest=plan.plan_digest, action_id=action.action_id, action_digest=action.action_digest, **kwargs)

    async def run():
        for _ in range(4):
            _row, bound_plan, bound_job, bound_action, _backend = await context(reuse_plan=True)
            assert bound_plan is plan and bound_job is job and bound_action is action
        assert len(loads) == 1
        await context()  # other routes read the plan every time
        assert len(loads) == 2
        # The Scan's current plan digest no longer matches: the cached plan is dropped and the
        # plan is read afresh (where the full digest check applies).
        stored["digest"] = "f" * 64
        await context(reuse_plan=True)
        assert len(loads) == 3
        stored["digest"] = plan.plan_digest
        lease["status"] = "released"  # a lease that ended is refused even with the plan cached
        try:
            await context(reuse_plan=True)
        except HTTPException as exc:
            return exc.status_code
    assert asyncio.run(run()) == 409


def test_a_withdrawn_heartbeat_is_a_distinct_signal_from_a_lost_lease():
    from api.scan.execution_backend import ActionAuthorityWithdrawn, ActionLeaseLost

    plan = _plan()
    action = plan.actions[0]

    def backend(error):
        async def request(_method, _path, _payload):
            raise error
        return BrokerScanExecutionBackend(plan=plan, worker_id="broker:node-1", job_lease_token="t" * 40,
                                          base_path=BASE, request=request)

    lease = _lease(plan, action)
    lease = type(lease)(**{**lease.__dict__, "backend": "broker", "worker_id": "broker:node-1"})
    withdrawn = backend(BrokerActionHTTPError(409, "authority_withdrawn:authorization_revoked"))
    try:
        asyncio.run(withdrawn.heartbeat(lease))
    except ActionAuthorityWithdrawn as exc:
        assert exc.reason == "authorization_revoked" and not isinstance(exc, ActionLeaseLost)
    else:
        raise AssertionError("a withdrawn heartbeat must raise")
    for error in (BrokerActionHTTPError(409, "broker action lease expired"),
                  BrokerActionHTTPError(409, "authority_withdrawn:not-a-reason"),
                  BrokerActionHTTPError(410, "authority_withdrawn:authorization_revoked")):
        try:
            asyncio.run(backend(error).heartbeat(lease))
        except ActionLeaseLost:
            pass
        else:
            raise AssertionError(f"{error} must stay a lost lease")


def test_a_withdrawn_lease_heartbeat_stops_the_action_and_keeps_its_receipt():
    from dataclasses import replace

    from api.scan.execution_backend import ActionAuthorityWithdrawn

    plan = _plan()
    action = plan.actions[0]
    calls = []
    heartbeats = []

    async def heartbeat():
        heartbeats.append(1)
        raise ActionAuthorityWithdrawn("authorization_revoked")

    # The node's own poll would take 30 s; the lease heartbeat (every 1.7 s) sees the withdrawal.
    control = FixtureControlPlane(default={"reason": None})
    executor = _executor(_long_dispatch(calls), _authority(plan, control, poll_seconds=30.0,
                                                            unverified_after_seconds=60.0))
    started = time.monotonic()
    receipt = asyncio.run(executor.execute(action, replace(_lease(plan, action), lease_seconds=5), heartbeat))
    assert time.monotonic() - started < 3.0 and heartbeats == [1]
    assert receipt.status == "partial" and receipt.errors == ("authorization_revoked",)
    assert receipt.redacted_execution["target_authority_interruption"]["reason_code"] == "authorization_revoked"
    assert receipt.budget_consumed["http_requests"] == 1
