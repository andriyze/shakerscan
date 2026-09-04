"""Control-plane retries append at most one successor per settled revision."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import sys

import pytest

sys.modules.setdefault("asyncpg", SimpleNamespace(Pool=object))
from api.fleet_routes import router as routes
from api.scan.continuation import root_scan_plan_revision
from api.scan.continuation_rounds import compile_next_continuation
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
        async def materialize(_conn, *, parent_plan, revision_number, **_kwargs):
            assert lock.locked()
            state["calls"] += 1
            fixture["parent_plan"] = parent_plan
            _settle_round_fixture(fixture)
            result = compile_next_continuation(**fixture, revision_number=revision_number)
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
        assert all(lock_reads)
    asyncio.run(scenario())
