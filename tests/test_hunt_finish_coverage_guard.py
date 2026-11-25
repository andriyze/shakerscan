"""Finishing a web Hunt with open coverage: refused with what is open, or forced with a reason."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import uuid

import pytest

from api.hunt import run_router
from api.hunt.coverage_map import build_coverage
from api.hunt.run_service import HuntRunService

HUNT = uuid.uuid4()


class _Acquire:
    def __init__(self, connection):
        self.connection = connection

    async def __aenter__(self):
        return self.connection

    async def __aexit__(self, *exc):
        return False


class _Pool:
    def __init__(self, connection):
        self.connection = connection
        connection.transaction = lambda **_kw: _Acquire(connection)

    def acquire(self):
        return _Acquire(self.connection)


APPROVAL = uuid.uuid4()
ACTIVE_POLICY = {"allowed_capabilities": ["web.crawl"], "active_testing": True,
                 "approval_receipt_id": str(APPROVAL)}
PASSIVE_POLICY = {"allowed_capabilities": ["web.crawl"], "active_testing": False}


class _Connection:
    """One Hunt row; by default an active web Hunt whose approval is current."""

    def __init__(self, *, created_minutes_ago=5, status="active", target_kind="web",
                 policy=None, approval_status="active", in_flight=False):
        self.status = status
        self.target_kind = target_kind
        self.policy = ACTIVE_POLICY if policy is None else policy
        self.approval_status = approval_status
        self.in_flight = in_flight
        self.created_at = datetime.now(timezone.utc) - timedelta(minutes=created_minutes_ago)
        self.final_debrief = None
        self.completed_at = None

    def row(self):
        return {"id": HUNT, "target_id": uuid.uuid4(), "device_target_id": None,
                "target_kind": self.target_kind, "status": self.status,
                "completed_at": self.completed_at, "final_debrief": self.final_debrief,
                "created_at": self.created_at, "objective": "o", "budget_profile": "balanced",
                "policy_json": json.dumps(self.policy),
                "budget_json": json.dumps({"max_duration_seconds": 5400, "max_http_requests": 10_000}),
                "budget_used_json": json.dumps({"http_requests": 50}), "context_pack": "{}",
                "stop_reason": None, "budget_revision": 0, "updated_at": self.created_at}

    async def fetchrow(self, query, *args):
        if query.startswith("SELECT * FROM hunt_runs"):
            return self.row()
        if "FROM approval_receipts" in query:
            assert args == (str(APPROVAL),)
            return {"status": self.approval_status,
                    "revoked_at": datetime.now(timezone.utc) if self.approval_status == "revoked" else None,
                    "expires_at": None}
        if "FROM hunt_actions" in query:
            return {"actions": self.in_flight, "reservations": False}
        if "UPDATE hunt_runs" in query and "final_debrief=$2" in query:
            self.status = "completed"
            self.completed_at = datetime.now(timezone.utc)
            self.final_debrief = args[1]
            return self.row()
        raise AssertionError(query)

    async def fetchval(self, query, *args):
        assert "FROM hunt_actions" in query
        return self.in_flight

    async def execute(self, query, *args):
        return "UPDATE 0"

    async def fetch(self, query, *args):
        return []


def _reader(report):
    async def read(_conn, row):
        assert row["id"] == HUNT
        return report
    return read


OPEN = build_coverage(actions=[], endpoints=[{"method": "GET", "path": "/search", "param_shape": "q"}],
                      allowed=["web.crawl"])


def _service(connection, report=OPEN):
    return HuntRunService(lambda: _Pool(connection), coverage_reader=_reader(report))


def test_finish_with_open_coverage_and_time_left_is_refused_and_names_what_is_open():
    connection = _Connection()
    with pytest.raises(run_router.HTTPException) as refused:
        asyncio.run(_service(connection).finish(str(HUNT), summary="Done", next_actions=[]))
    assert refused.value.status_code == 409
    assert "coverage is open" in refused.value.detail and "GET /search (q)" in refused.value.detail
    assert connection.status == "active" and connection.final_debrief is None


def test_forced_finish_records_the_reason_and_the_open_coverage_in_the_debrief():
    connection = _Connection()
    with pytest.raises(run_router.HTTPException) as no_reason:
        asyncio.run(_service(connection).finish(str(HUNT), summary="Done", next_actions=[], force=True))
    assert "force_reason" in no_reason.value.detail
    result = asyncio.run(_service(connection).finish(
        str(HUNT), summary="Done", next_actions=[], force=True,
        force_reason="the remaining routes are out of this objective"))
    assert result["status"] == "completed"
    debrief = json.loads(connection.final_debrief)
    assert debrief["coverage"]["forced"] is True
    assert debrief["coverage"]["force_reason"] == "the remaining routes are out of this objective"
    assert debrief["coverage"]["pairs_open"] == OPEN["pairs_open"]
    assert debrief["coverage"]["open_sample"][0].startswith("GET /search")


def test_finish_is_not_held_when_time_is_spent_or_nothing_is_open_and_records_coverage():
    late = _Connection(created_minutes_ago=89)
    asyncio.run(_service(late).finish(str(HUNT), summary="Done", next_actions=[]))
    assert json.loads(late.final_debrief)["coverage"]["forced"] is False
    closed = build_coverage(actions=[{"capability_name": "web.crawl", "status": "completed", "input": "{}"}],
                            endpoints=[], allowed=["web.crawl"])
    done = _Connection()
    asyncio.run(_service(done, closed).finish(str(HUNT), summary="Done", next_actions=[]))
    assert json.loads(done.final_debrief)["coverage"]["pairs_open"] == 0


def test_device_hunts_and_unreadable_coverage_never_hold_a_finish():
    device = _Connection(target_kind="device")
    asyncio.run(_service(device).finish(str(HUNT), summary="Done", next_actions=[]))
    assert "coverage" not in json.loads(device.final_debrief)

    async def broken(_conn, _row):
        raise RuntimeError("database hiccup")

    web = _Connection()
    asyncio.run(HuntRunService(lambda: _Pool(web), coverage_reader=broken).finish(
        str(HUNT), summary="Done", next_actions=[]))
    assert web.status == "completed"


def test_coverage_route_pages_the_report():
    connection = _Connection()
    page = asyncio.run(_service(connection).coverage(str(HUNT), limit=1))
    assert page["hunt_id"] == str(HUNT) and page["returned"] == 1 and page["open"][0]["endpoint"] == "GET /search"
    with pytest.raises(run_router.HTTPException):
        asyncio.run(_service(_Connection(target_kind="device"), None).coverage(str(HUNT)))


def test_finish_request_accepts_force_fields():
    request = run_router.HuntFinishRequest(summary="s", force=True, force_reason="because")
    assert request.force is True and request.force_reason == "because"
    with pytest.raises(Exception):
        run_router.HuntFinishRequest(summary="s", force_reason="x" * 2001)


def test_a_finish_while_the_engine_sweep_runs_is_deferred_with_its_reason():
    from api.hunt import auto_discovery
    auto_discovery._STATE.clear()
    auto_discovery._STATE[str(HUNT)] = {"running": True}
    connection = _Connection()
    with pytest.raises(run_router.HTTPException) as no_reason:
        asyncio.run(_service(connection).finish(str(HUNT), summary="Done", next_actions=[], force=True))
    assert "force_reason" in no_reason.value.detail
    answer = asyncio.run(_service(connection).finish(
        str(HUNT), summary="Done", next_actions=["x"], force=True, force_reason="my part is done here"))
    assert answer["finish_deferred"] is True and answer["status"] == "active"
    assert connection.status == "active" and connection.final_debrief is None
    assert auto_discovery._STATE[str(HUNT)]["deferred_finish"] == {
        "summary": "Done", "next_actions": ["x"], "reason": "my part is done here"}
    # An unforced finish is deferred too: the engine's work never ends early.
    unforced = asyncio.run(_service(connection).finish(str(HUNT), summary="Done", next_actions=[]))
    assert unforced["finish_deferred"] is True
    auto_discovery._STATE.clear()


def test_a_hunt_that_cannot_test_is_not_held_by_open_coverage():
    # Passive (zero authority) or with its approval revoked: it has no checks to close the open
    # pairs with, so the finish completes and records the coverage.
    for connection in (_Connection(policy=PASSIVE_POLICY), _Connection(approval_status="revoked")):
        result = asyncio.run(_service(connection).finish(str(HUNT), summary="Done", next_actions=[]))
        assert result["status"] == "completed" and connection.status == "completed"
        assert json.loads(connection.final_debrief)["coverage"]["pairs_open"] == OPEN["pairs_open"]


def test_a_finish_after_revocation_stops_the_engine_work_and_completes():
    from api.hunt import auto_discovery
    auto_discovery._STATE.clear()
    connection = _Connection(approval_status="revoked")
    stopped = []

    async def scenario():
        async def engine_work():
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                stopped.append(True)
                raise
            finally:
                auto_discovery._STATE[str(HUNT)]["running"] = False

        auto_discovery._STATE[str(HUNT)] = {"running": True}
        task = asyncio.get_running_loop().create_task(engine_work())
        auto_discovery._TASK_BY_HUNT[str(HUNT)] = task
        await asyncio.sleep(0)
        return await _service(connection).finish(str(HUNT), summary="Done", next_actions=[])

    result = asyncio.run(scenario())
    assert stopped == [True]
    assert result["status"] == "completed" and "finish_deferred" not in result
    assert not auto_discovery.sweep_running(str(HUNT))
    auto_discovery._STATE.clear()
    auto_discovery._TASK_BY_HUNT.clear()


def test_a_passive_finish_is_never_deferred():
    from api.hunt import auto_discovery
    auto_discovery._STATE.clear()
    auto_discovery._STATE[str(HUNT)] = {"running": True}
    connection = _Connection(policy=PASSIVE_POLICY)
    result = asyncio.run(_service(connection).finish(str(HUNT), summary="Done", next_actions=[]))
    assert result["status"] == "completed" and "finish_deferred" not in result
    auto_discovery._STATE.clear()
