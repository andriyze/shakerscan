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


class _Connection:
    def __init__(self, *, created_minutes_ago=5, status="active", target_kind="web"):
        self.status = status
        self.target_kind = target_kind
        self.created_at = datetime.now(timezone.utc) - timedelta(minutes=created_minutes_ago)
        self.final_debrief = None
        self.completed_at = None

    def row(self):
        return {"id": HUNT, "target_id": uuid.uuid4(), "device_target_id": None,
                "target_kind": self.target_kind, "status": self.status,
                "completed_at": self.completed_at, "final_debrief": self.final_debrief,
                "created_at": self.created_at, "objective": "o", "budget_profile": "balanced",
                "policy_json": json.dumps({"allowed_capabilities": ["web.crawl"]}),
                "budget_json": json.dumps({"max_duration_seconds": 5400, "max_http_requests": 10_000}),
                "budget_used_json": json.dumps({"http_requests": 50}), "context_pack": "{}",
                "stop_reason": None, "budget_revision": 0, "updated_at": self.created_at}

    async def fetchrow(self, query, *args):
        if query.startswith("SELECT * FROM hunt_runs"):
            return self.row()
        if "FROM hunt_actions" in query:
            return {"actions": False, "reservations": False}
        if "UPDATE hunt_runs" in query and "final_debrief=$2" in query:
            self.status = "completed"
            self.completed_at = datetime.now(timezone.utc)
            self.final_debrief = args[1]
            return self.row()
        raise AssertionError(query)

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
