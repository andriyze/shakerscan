from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import uuid

import pytest

from api.hunt import run_router
from api.hunt.run_service import HuntRunService, public_hunt_run


def _row(**overrides):
    values = {
        "id": uuid.uuid4(),
        "target_kind": "web",
        "target_id": uuid.uuid4(),
        "device_target_id": None,
        "objective": "Inspect the fixture",
        "status": "active",
        "budget_profile": "fast",
        "policy_json": json.dumps({
            "allowed_capabilities": ["collections.inspect"],
        }),
        "budget_json": {"max_http_requests": 10},
        "budget_used_json": "{}",
        "context_pack": {"secret_values_visible_to_planner": False},
        "stop_reason": None,
        "final_debrief": None,
        "created_at": datetime(2026, 8, 25, tzinfo=timezone.utc),
        "updated_at": datetime(2026, 8, 25, tzinfo=timezone.utc),
    }
    values.update(overrides)
    return values


class _Acquire:
    def __init__(self, connection):
        self.connection = connection

    async def __aenter__(self):
        return self.connection

    async def __aexit__(self, *_args):
        return False


class _Pool:
    def __init__(self, connection):
        self.connection = connection

    def acquire(self):
        return _Acquire(self.connection)


def test_public_hunt_projection_is_metadata_only_and_legacy_fail_closed():
    item = public_hunt_run(_row())

    assert item["hunt_id"]
    assert item["target_id"]
    assert item["capabilities"][0]["name"] == "collections.inspect"
    assert item["context_pack"]["secret_values_visible_to_planner"] is False
    assert item["created_at"] == "2026-08-25T00:00:00+00:00"

    legacy = public_hunt_run(_row(policy_json={}))
    assert legacy["capabilities"] == []


def test_hunt_run_service_lists_without_context_or_capability_expansion():
    class Connection:
        async def fetch(self, query, *args):
            assert "target_id=$1 OR device_target_id=$1" in query
            assert "status=$2" in query
            assert "LIMIT $3" in query
            assert args[1:] == ("active", 25)
            return [_row()]

    service = HuntRunService(lambda: _Pool(Connection()))
    result = asyncio.run(service.list(
        target_id=str(uuid.uuid4()), status="active", limit=25
    ))

    assert result["count"] == 1
    assert "context_pack" not in result["hunts"][0]
    assert "capabilities" not in result["hunts"][0]

    with pytest.raises(run_router.HTTPException) as exc:
        asyncio.run(service.list(target_id=None, status="invented", limit=25))
    assert exc.value.status_code == 400


def test_hunt_run_terminal_transitions_are_idempotent_and_state_guarded():
    hunt_id = str(uuid.uuid4())

    class Connection:
        def __init__(self):
            self.status = "active"

        async def fetchrow(self, query, *args):
            if "SET status='completed'" in query:
                self.status = "completed"
                return _row(id=uuid.UUID(hunt_id), status=self.status)
            if "SET status='cancelled'" in query:
                return None
            if query.startswith("SELECT * FROM hunt_runs"):
                return _row(id=uuid.UUID(hunt_id), status=self.status)
            raise AssertionError(query)

    connection = Connection()
    service = HuntRunService(lambda: _Pool(connection))
    finished = asyncio.run(service.finish(
        hunt_id, summary="Done", next_actions=["Review evidence"]
    ))
    cancelled_after_finish = asyncio.run(service.cancel(hunt_id))

    assert finished["status"] == "completed"
    assert cancelled_after_finish["status"] == "completed"


def test_hunt_run_router_owns_only_read_and_terminal_lifecycle_routes():
    paths = {
        (frozenset(route.methods or ()), route.path, route.name)
        for route in run_router.router.routes
    }
    assert paths == {
        (frozenset({"GET"}), "/hunts/{hunt_id}", "get_hunt"),
        (frozenset({"GET"}), "/hunts", "list_hunts"),
        (frozenset({"POST"}), "/hunts/{hunt_id}/finish", "finish_hunt"),
        (frozenset({"POST"}), "/hunts/{hunt_id}/cancel", "cancel_hunt"),
        (frozenset({"POST"}), "/hunts/{hunt_id}/resume", "resume_hunt"),
    }
