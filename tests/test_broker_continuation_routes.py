"""Control-plane retries append at most one successor per settled revision."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import timedelta
from types import SimpleNamespace
import sys

import pytest

try:
    import asyncpg  # noqa: F401 - prefer the real driver in the locked CI environment
except ModuleNotFoundError:
    sys.modules.setdefault("asyncpg", SimpleNamespace(Pool=object))
from api.fleet_routes import router as routes
from api.scan.continuation import root_scan_plan_revision
from api.scan.continuation_rounds import compile_continuation_round, compile_next_continuation
from tests.test_continuation_rounds import _shared_round_fixture, _settle_round_fixture


def test_broker_retries_current_round_next_round_and_cancellation(monkeypatch):
    async def scenario():
        fixture = _shared_round_fixture()
        root = fixture["parent_plan"]
        state = dict(plan=root, revision=root_scan_plan_revision(root), status="running", calls=0)
        lock = asyncio.Lock()
        lock_reads = []

        class Connection:
            @asynccontextmanager
            async def transaction(self):
                async with lock:
                    yield self

            async def fetchrow(self, sql, *_args):
                assert "FOR UPDATE" in sql
                lock_reads.append(lock.locked())
                return {"status": state["status"], "target_id": "70000000-0000-4000-8000-000000000002",
                        "target_url": fixture["target_url"], "options": {}, "scan_job_payload": {}}

            async def fetchval(self, *_args):
                return True

        class Pool:
            @asynccontextmanager
            async def acquire(self):
                yield Connection()

        class ActionStore:
            async def load_continuation_allocation(self, *_args, **_kwargs):
                return fixture["allocation"]

            async def load_plan(self, *_args, **_kwargs):
                assert lock.locked(), "read must follow the scan row lock"
                return state["plan"]

            async def load_plan_revision(self, *_args, **_kwargs):
                return state["revision"]

        async def authenticated(*_args, **_kwargs):
            return None

        async def lease(*_args, **_kwargs):
            return {"status": "leased", "worker_id": "node:container", "scan_id": root.scan_id,
                    "lease_expires_at": routes.utc_now() + timedelta(minutes=5)}

        # The shared compiler is real; only the persistence/lease boundaries are mocked.
        materialized = []

        async def materialize(_conn, *, parent_plan, revision_number, finalize_only=False, persist=True,
                              **_kwargs):
            assert lock.locked()
            state["calls"] += 1
            materialized.append({"finalize_only": finalize_only, "persist": persist})
            fixture["parent_plan"] = parent_plan
            _settle_round_fixture(fixture)
            if finalize_only:
                result = compile_continuation_round(**fixture, revision_number=revision_number,
                                                    include_finalizer=True, finalize_only=True)
            else:
                result = compile_next_continuation(**fixture, revision_number=revision_number)
            if persist:
                state.update(plan=result.plan, revision=result.revision)
            await asyncio.sleep(0)  # Exercise simultaneous parent retries at the lock.
            return result.plan, result.revision, result.options

        monkeypatch.setattr(routes, "_pool", lambda: Pool())
        monkeypatch.setattr(routes, "_broker_authenticated_node", authenticated)
        monkeypatch.setattr(routes, "_broker_lease_row", lease)
        monkeypatch.setattr(routes, "PostgresScanActionStore", ActionStore)
        monkeypatch.setattr(routes, "CanonicalScanJob", SimpleNamespace(from_payload=lambda _raw: SimpleNamespace(
            scan_id=root.scan_id, execution_plan=SimpleNamespace(digest=fixture["allocation"].execution_plan_digest),
            target=SimpleNamespace(digest=fixture["target"].digest, target_id="70000000-0000-4000-8000-000000000002"),
        )))
        monkeypatch.setattr(routes, "_materialize_broker_scan_continuation", materialize)

        async def request(digest, **overrides):
            data = dict(job_lease_token="x" * 32, worker_id="broker:node:container",
                        plan_digest=digest, allocation_digest=fixture["allocation"].allocation_digest)
            data.update(overrides)
            return await routes.continue_broker_scan_action_plan(
                "node", "lease", routes.BrokerScanContinuationRequest(**data), None,
            )

        first, duplicate = await asyncio.gather(request(root.plan_digest), request(root.plan_digest))
        assert first["plan"] == duplicate["plan"]
        assert first["plan_revision"]["revision"] == 1
        assert state["calls"] == 1
        second = await request(state["plan"].plan_digest)
        assert second["plan_revision"]["revision"] == 2
        assert state["calls"] == 2
        with pytest.raises(routes.HTTPException) as stale:
            await request(root.plan_digest)
        assert stale.value.status_code == 409
        with pytest.raises(routes.HTTPException) as wrong_worker:
            await request(state["plan"].plan_digest, worker_id="broker:other")
        assert wrong_worker.value.status_code == 409
        state["status"] = "cancelling"
        with pytest.raises(routes.HTTPException) as cancelled:
            await request(state["plan"].plan_digest)
        assert cancelled.value.status_code == 409
        assert state["calls"] == 2
        # A cancelled Scan's node asks for the finalize-only revision its kept report is built
        # over: compiled, never stored, and the Scan's plan stays frozen.
        frozen = state["plan"]
        kept = await request(frozen.plan_digest, finalize_only=True)
        assert materialized[-1] == {"finalize_only": True, "persist": False}
        assert kept["plan"]["actions"][-1]["action_id"] == "finalize.report"
        assert kept["plan_revision"]["parent_plan_digest"] == frozen.plan_digest
        assert state["plan"] is frozen and kept["time_limit_reached"] is False
        with pytest.raises(routes.HTTPException) as stale_kept:
            await request(root.plan_digest, finalize_only=True)
        assert stale_kept.value.status_code == 409
        assert all(lock_reads)

        # B7: past the Scan's time limit the control plane compiles only the finalizer (stored),
        # whether or not the node asked for it, and says so.
        state["status"] = "running"
        reached = {"value": True}

        async def time_limit_reached(*_args, **_kwargs):
            return reached["value"]

        monkeypatch.setattr(routes, "_broker_scan_time_limit_reached", time_limit_reached)
        terminal = await request(frozen.plan_digest)
        assert materialized[-1] == {"finalize_only": True, "persist": True}
        assert terminal["time_limit_reached"] is True
        assert terminal["plan"]["actions"][-1]["action_id"] == "finalize.report"
    asyncio.run(scenario())


def test_a_node_past_its_limit_asks_for_the_finalizer_and_gets_it_stored(monkeypatch):
    """B7: a node's ``finalize_only`` on a running Scan past its limit stores the terminal
    revision; before the control plane's limit it is refused."""
    async def scenario():
        fixture = _shared_round_fixture()
        root = fixture["parent_plan"]
        state = dict(plan=root, revision=root_scan_plan_revision(root))
        seen = []

        class Connection:
            @asynccontextmanager
            async def transaction(self):
                yield self

            async def fetchrow(self, *_args):
                return {"status": "running", "target_id": "70000000-0000-4000-8000-000000000002",
                        "target_url": fixture["target_url"], "options": {}, "scan_job_payload": {}}

            async def fetchval(self, *_args):
                return True

        class Pool:
            @asynccontextmanager
            async def acquire(self):
                yield Connection()

        class ActionStore:
            async def load_continuation_allocation(self, *_args, **_kwargs):
                return fixture["allocation"]

            async def load_plan(self, *_args, **_kwargs):
                return state["plan"]

            async def load_plan_revision(self, *_args, **_kwargs):
                return state["revision"]

        async def authenticated(*_args, **_kwargs):
            return None

        async def lease(*_args, **_kwargs):
            return {"status": "leased", "worker_id": "node:container", "scan_id": root.scan_id,
                    "lease_expires_at": routes.utc_now() + timedelta(minutes=5)}

        async def materialize(_conn, *, parent_plan, revision_number, finalize_only=False, persist=True, **_kw):
            seen.append((finalize_only, persist))
            fixture["parent_plan"] = parent_plan
            _settle_round_fixture(fixture)
            result = compile_continuation_round(**fixture, revision_number=revision_number,
                                                include_finalizer=True, finalize_only=True)
            return result.plan, result.revision, result.options

        limit = {"reached": False, "tolerances": []}

        async def time_limit(*_args, tolerance_seconds=0.0, **_kwargs):
            limit["tolerances"].append(tolerance_seconds)
            return limit["reached"]

        monkeypatch.setattr(routes, "_pool", lambda: Pool())
        monkeypatch.setattr(routes, "_broker_authenticated_node", authenticated)
        monkeypatch.setattr(routes, "_broker_lease_row", lease)
        monkeypatch.setattr(routes, "PostgresScanActionStore", ActionStore)
        monkeypatch.setattr(routes, "_broker_scan_time_limit_reached", time_limit)
        monkeypatch.setattr(routes, "CanonicalScanJob", SimpleNamespace(from_payload=lambda _raw: SimpleNamespace(
            scan_id=root.scan_id, execution_plan=SimpleNamespace(digest=fixture["allocation"].execution_plan_digest),
            target=SimpleNamespace(digest=fixture["target"].digest, target_id="70000000-0000-4000-8000-000000000002"),
        )))
        monkeypatch.setattr(routes, "_materialize_broker_scan_continuation", materialize)

        def ask():
            return routes.continue_broker_scan_action_plan(
                "node", "lease", routes.BrokerScanContinuationRequest(
                    job_lease_token="x" * 32, worker_id="broker:node:container", plan_digest=root.plan_digest,
                    allocation_digest=fixture["allocation"].allocation_digest, finalize_only=True), None)

        # Review sweep L6: on a running Scan whose limit the control plane has not reached, a
        # node's finalize_only is refused; nothing is compiled or stored.
        with pytest.raises(routes.HTTPException) as early:
            await ask()
        assert early.value.status_code == 409 and seen == []
        assert limit["tolerances"] == [routes.TIME_LIMIT_STOP_GRACE_SECONDS]
        limit["reached"] = True
        response = await ask()
        assert seen == [(True, True)] and response["time_limit_reached"] is True
    asyncio.run(scenario())


def test_the_scan_time_limit_is_measured_from_the_scans_start(monkeypatch):
    from datetime import datetime, timezone

    started = datetime.now(timezone.utc) - timedelta(seconds=700)

    class Connection:
        async def fetchval(self, _sql, _scan_id):
            return started

    class Pool:
        @asynccontextmanager
        async def acquire(self):
            yield Connection()

    monkeypatch.setattr(routes, "_pool", lambda: Pool())
    job = SimpleNamespace(execution_plan=SimpleNamespace(budget=SimpleNamespace(max_duration_seconds=600)),
                          shard=None)
    assert asyncio.run(routes._broker_scan_time_limit_reached(
        None, scan_id="70000000-0000-4000-8000-000000000001", canonical_job=job)) is True
    unlimited = SimpleNamespace(execution_plan=SimpleNamespace(budget=SimpleNamespace(max_duration_seconds=0)),
                                shard=None)
    assert asyncio.run(routes._broker_scan_time_limit_reached(
        None, scan_id="70000000-0000-4000-8000-000000000001", canonical_job=unlimited)) is False
    limit = asyncio.run(routes.lease_time_limit(
        Pool(), scan_id="70000000-0000-4000-8000-000000000001",
        options={"scan_execution_plan": {"budget": {"max_duration_seconds": 600}}}))
    assert limit["max_duration_seconds"] == 600 and 695 <= limit["elapsed_seconds"] <= 710


def test_the_finalize_only_tolerance_covers_only_the_stop_grace(monkeypatch):
    """Review sweep L6: a node's request just before the control plane's limit (the time the
    request took) is within the tolerance; one well before it is not."""
    from datetime import datetime, timezone

    class Connection:
        async def fetchval(self, _sql, _scan_id):
            return state["started"]

    class Pool:
        @asynccontextmanager
        async def acquire(self):
            yield Connection()

    monkeypatch.setattr(routes, "_pool", lambda: Pool())
    job = SimpleNamespace(execution_plan=SimpleNamespace(budget=SimpleNamespace(max_duration_seconds=3600)),
                          shard=None)
    now = datetime.now(timezone.utc)
    from api.scan.scan_deadline import finalization_reserve_seconds
    deadline_offset = 3600 - finalization_reserve_seconds(3600)
    state = {"started": now - timedelta(seconds=deadline_offset - 5)}
    check = routes._broker_scan_time_limit_reached
    scan = "70000000-0000-4000-8000-000000000001"
    assert asyncio.run(check(None, scan_id=scan, canonical_job=job)) is False
    assert asyncio.run(check(None, scan_id=scan, canonical_job=job,
                             tolerance_seconds=routes.TIME_LIMIT_STOP_GRACE_SECONDS)) is True
    state["started"] = now - timedelta(seconds=deadline_offset - 300)
    assert asyncio.run(check(None, scan_id=scan, canonical_job=job,
                             tolerance_seconds=routes.TIME_LIMIT_STOP_GRACE_SECONDS)) is False
