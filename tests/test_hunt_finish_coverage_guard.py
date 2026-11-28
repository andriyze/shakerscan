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
    connection = _Connection(created_minutes_ago=40)
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
        "summary": "Done", "next_actions": ["x"], "reason": "my part is done here", "forced": True}
    # An unforced finish is deferred too: the engine's work never ends early. It is recorded as
    # unforced, with no reason: the engine never invents either.
    unforced = asyncio.run(_service(connection).finish(str(HUNT), summary="Done", next_actions=[]))
    assert unforced["finish_deferred"] is True
    assert auto_discovery._STATE[str(HUNT)]["deferred_finish"] == {
        "summary": "Done", "next_actions": [], "reason": None, "forced": False}
    auto_discovery._STATE.clear()


def test_an_unforced_finish_while_the_sweep_only_follows_is_held_by_open_coverage():
    # The engine tested what was mapped and waits for the planner: what is open is the planner's,
    # so the finish guard applies; a forced finish with a reason is deferred to the last round.
    from api.hunt import auto_discovery
    auto_discovery._STATE.clear()
    auto_discovery._STATE[str(HUNT)] = {"running": True, "sweep": "following"}
    connection = _Connection()
    with pytest.raises(run_router.HTTPException) as held:
        asyncio.run(_service(connection).finish(str(HUNT), summary="Done", next_actions=[]))
    assert held.value.status_code == 409 and "coverage is open" in held.value.detail
    assert "deferred_finish" not in auto_discovery._STATE[str(HUNT)]
    forced = asyncio.run(_service(connection).finish(
        str(HUNT), summary="Done", next_actions=[], force=True, force_reason="the rest needs a second account"))
    assert forced["finish_deferred"] is True and connection.status == "active"
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


# --- the engine's own deferred finish (review of 2.14.1) -----------------------------------------

# Coverage with a concrete next call the Hunt may send: a planner's forced finish this early is
# refused ("too early"), which is what used to hold the engine's deferred finish for ever.
EARLY = build_coverage(actions=[], endpoints=[{"method": "GET", "path": "/search", "param_shape": "q"}],
                       allowed=["request.verify", "xss.verify", "http.request"])


def test_early_objective_completion_and_the_engines_deferred_finish_keep_the_debrief():
    connection = _Connection(created_minutes_ago=5)
    early = asyncio.run(_service(connection, EARLY).finish(
        str(HUNT), summary="Done", next_actions=[], force=True, force_reason="the objective was answered early"))
    assert early["status"] == "completed"
    assert json.loads(connection.final_debrief)["coverage"]["force_reason"] == "the objective was answered early"
    connection = _Connection(created_minutes_ago=5)
    # The same finish, completed by the engine once its sweep has ended: an unforced planner finish
    # stays unforced in the debrief, marked as the engine's, with no reason nobody gave.
    result = asyncio.run(_service(connection, EARLY).finish(
        str(HUNT), summary="Done", next_actions=[], engine_deferred=True))
    assert result["status"] == "completed" and connection.status == "completed"
    coverage = json.loads(connection.final_debrief)["coverage"]
    assert coverage["engine_deferred"] is True and coverage["forced"] is False and "force_reason" not in coverage
    assert coverage["pairs_open"] == EARLY["pairs_open"]  # what was left open is still recorded


def test_an_engine_deferred_finish_keeps_the_planners_own_force_and_reason_and_waits_for_actions():
    connection = _Connection(created_minutes_ago=5)
    asyncio.run(_service(connection, EARLY).finish(
        str(HUNT), summary="Done", next_actions=[], force=True,
        force_reason="the rest needs a second account", engine_deferred=True))
    coverage = json.loads(connection.final_debrief)["coverage"]
    assert coverage == {**coverage, "engine_deferred": True, "forced": True,
                        "force_reason": "the rest needs a second account"}
    # Actions still settling hold it like any finish (the engine retries).
    busy = _Connection(in_flight=True)
    with pytest.raises(run_router.HTTPException) as held:
        asyncio.run(_service(busy, EARLY).finish(str(HUNT), summary="Done", next_actions=[], engine_deferred=True))
    assert held.value.status_code == 409 and "reserved or running actions" in held.value.detail


def test_no_request_can_claim_to_be_the_engines_finish():
    import inspect

    with pytest.raises(Exception) as refused:
        run_router.HuntFinishRequest(summary="s", engine_deferred=True)
    assert "engine_deferred" in str(refused.value)
    assert "engine_deferred" not in run_router.HuntFinishRequest.model_fields
    seen = {}

    class _Recording:
        async def finish(self, hunt_id, **values):
            seen.update(values)
            return {}

    original = run_router._service
    run_router._service = lambda: _Recording()
    try:
        asyncio.run(run_router.finish_hunt(str(HUNT), run_router.HuntFinishRequest(
            summary="s", force=True, force_reason="a planner's reason")))
    finally:
        run_router._service = original
    assert set(seen) == {"summary", "next_actions", "force", "force_reason"}
    assert inspect.signature(HuntRunService.finish).parameters["engine_deferred"].default is False


def test_the_engine_names_a_deferred_finish_it_could_not_complete(monkeypatch):
    from api.hunt import auto_discovery
    from api.hunt.coverage_map import build_coverage as build
    monkeypatch.setattr(auto_discovery, "DEFERRED_FINISH_ATTEMPTS", 3)
    monkeypatch.setattr(auto_discovery, "DEFERRED_FINISH_RETRY_SECONDS", 0)
    auto_discovery._STATE.clear()
    attempts = []

    async def load_run(_hunt_id):
        return {"id": "h9", "status": "active", "completed_at": None, "target_kind": "web"}

    async def finish(hunt_id, **values):
        attempts.append(values)
        raise run_router.HTTPException(status_code=409, detail="Hunt has reserved or running actions: x")

    async def nothing(*_args, **_kwargs):
        return None

    runner = auto_discovery.DiscoveryRunner("h9", execute=nothing, record=nothing, load_run=load_run, finish=finish)
    auto_discovery.defer_finish("h9", summary="Done", next_actions=["n"], reason=None)
    asyncio.run(runner._finish_deferred())
    assert len(attempts) == 3
    assert attempts[0] == {"summary": "Done", "next_actions": ["n"], "force": False, "force_reason": None,
                           "engine_deferred": True}
    state = auto_discovery.discovery_state("h9")
    assert "still refused after 3 attempts" in state["deferred_finish_failed"]
    assert "reserved or running actions" in state["deferred_finish_failed"]
    assert any(note.startswith("deferred finish failed") for note in state["notes"])
    # The Hunt's coverage state says it (it is what the planner, the UI and the debrief read).
    report = build(actions=[], endpoints=[], discovery=state)
    assert "still refused" in report["discovery"]["deferred_finish_failed"]
    assert "deferred_finish_failed" not in report["discovery"]["steps"]
    # A later finish that goes through clears it.
    attempts.clear()

    async def accepted(hunt_id, **values):
        attempts.append(values)

    runner._finish = accepted
    asyncio.run(runner._finish_deferred())
    assert "deferred_finish_failed" not in auto_discovery.discovery_state("h9")
    auto_discovery._STATE.clear()


class _DurableConnection(_Connection):
    """A Hunt row with its ``notes`` column, and the quiet-period read of the recovery."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.notes: list = []
        self.quiet = True

    def row(self):
        return {**super().row(), "notes": json.dumps(self.notes)}

    async def execute(self, query, *args):
        if "UPDATE hunt_runs SET notes" in query:
            kept = [item for item in self.notes if item.get("kind") != args[2]]
            self.notes = kept + json.loads(args[1])
        return "UPDATE 1"

    async def fetchval(self, query, *args):
        if "make_interval" in query:
            return self.quiet
        return await super().fetchval(query, *args)


def test_a_recorded_finish_survives_an_api_restart_and_is_completed_once_the_hunt_is_quiet():
    from api.hunt import auto_discovery, run_service
    auto_discovery._STATE.clear()
    auto_discovery._STATE[str(HUNT)] = {"running": True}
    connection = _DurableConnection()
    service = _service(connection, EARLY)
    asyncio.run(service.finish(str(HUNT), summary="Done", next_actions=["x"]))
    asyncio.run(service.finish(str(HUNT), summary="Done, really", next_actions=["x"]))  # the latest replaces it
    assert [(note["kind"], note["summary"], note["forced"], note["reason"]) for note in connection.notes] == [
        ("engine_deferred_finish", "Done, really", False, None)]
    assert connection.status == "active"

    # While this process still runs the engine's work nothing is recovered.
    assert asyncio.run(service.recover_deferred_finish(str(HUNT))) is None
    # The API restarts: the sweep and its recorded finish (process memory) are gone.
    auto_discovery._STATE.clear()
    restarted = _service(connection, EARLY)
    # Just recorded: another API process may still be sweeping.
    assert asyncio.run(restarted.recover_deferred_finish(str(HUNT))) is None
    old = (datetime.now(timezone.utc) - timedelta(seconds=run_service.DEFERRED_RECOVERY_QUIET_SECONDS + 5)).isoformat()
    connection.notes[0]["at"] = old
    connection.quiet = False  # an action in flight or just settled
    assert asyncio.run(restarted.recover_deferred_finish(str(HUNT))) is None
    assert connection.status == "active"
    connection.quiet = True
    result = asyncio.run(restarted.recover_deferred_finish(str(HUNT)))
    assert result["status"] == "completed" and connection.status == "completed"
    debrief = json.loads(connection.final_debrief)
    assert debrief["summary"] == "Done, really" and debrief["next_actions"] == ["x"]
    assert debrief["coverage"]["engine_deferred"] is True and debrief["coverage"]["forced"] is False
    # Finished: nothing more to recover.
    assert asyncio.run(restarted.recover_deferred_finish(str(HUNT))) is None


def test_reading_an_open_hunt_with_a_recorded_finish_starts_its_recovery():
    from api.hunt import auto_discovery, run_service
    auto_discovery._STATE.clear()
    connection = _DurableConnection()
    old = (datetime.now(timezone.utc) - timedelta(seconds=run_service.DEFERRED_RECOVERY_QUIET_SECONDS + 5)).isoformat()
    connection.notes = [{"kind": "entries_retracted"},
                        {"kind": "engine_deferred_finish", "summary": "Done", "next_actions": [], "reason":
                         "my part is done here", "forced": True, "at": old}]
    service = _service(connection, EARLY)

    async def scenario():
        service._recover_deferred_in_background(connection.row())
        service._recover_deferred_in_background(connection.row())  # one recovery at a time
        assert len(service._recovering) == 1
        await asyncio.gather(*list(service._recovering.values()))

    asyncio.run(scenario())
    assert connection.status == "completed" and not service._recovering
    coverage = json.loads(connection.final_debrief)["coverage"]
    assert coverage["forced"] is True and coverage["force_reason"] == "my part is done here"

    # A Hunt with no recorded finish, or a finished one, starts nothing.
    plain = _DurableConnection()

    async def untouched():
        service._recover_deferred_in_background(plain.row())
        service._recover_deferred_in_background(connection.row())
        assert not service._recovering

    asyncio.run(untouched())
