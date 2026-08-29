from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import uuid

import pytest

from api.hunt import run_router
from api.hunt.run_service import (
    HuntRunService,
    public_hunt_action,
    public_hunt_action_trace,
    public_hunt_run,
)


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


def test_public_hunt_action_projection_omits_inputs_and_arbitrary_result_content():
    scan_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    action = public_hunt_action({
        "id": uuid.uuid4(),
        "capability_name": "device.inspect",
        "status": "completed",
        "input_summary": {
            "input": {"password": "must-not-leak"},
            "input_digest": "input-digest",
            "idempotency_key_sha256": "idempotency-digest",
        },
        "result_summary": {
            "ok": True,
            "partial": False,
            "timed_out": False,
            "secret": "must-not-leak",
            "observations": [{"message": "must-not-leak"}],
            "budget_consumed": {"agent_actions": 1, "invalid": "hidden"},
            "data": {
                "scan_id": str(scan_id),
                "finding_ids": [str(finding_id), "not-a-uuid"],
            },
        },
        "receipt_id": uuid.uuid4(),
        "started_at": datetime(2026, 8, 25, tzinfo=timezone.utc),
        "completed_at": datetime(2026, 8, 25, tzinfo=timezone.utc),
    })

    serialized = json.dumps(action)
    assert "must-not-leak" not in serialized
    assert action["input_digest"] == "input-digest"
    assert action["result"]["observation_count"] == 1
    assert action["result"]["budget_consumed"] == {"agent_actions": 1}
    assert action["result"]["reference_ids"]["scan_ids"] == [str(scan_id)]
    assert action["result"]["reference_ids"]["finding_ids"] == [str(finding_id)]


def test_public_hunt_action_projects_content_safe_worker_record_count():
    action = public_hunt_action({
        "id": uuid.uuid4(),
        "capability_name": "web.crawl",
        "status": "completed",
        "input_summary": {},
        "result_summary": {
            "status": "success",
            "record_count": 45,
        },
    })

    assert action["result"]["observation_count"] == 45


def test_public_hunt_action_prefers_canonical_worker_observation_count():
    action = public_hunt_action({
        "id": uuid.uuid4(),
        "capability_name": "web.probe",
        "status": "completed",
        "input_summary": {},
        "result_summary": {
            "status": "success",
            "observation_count": 1,
            "record_count": 999,
            "budget_consumed": {"http_requests": 1, "agent_actions": 1},
        },
    })

    assert action["result"]["observation_count"] == 1
    assert action["result"]["budget_consumed"] == {
        "http_requests": 1,
        "agent_actions": 1,
    }


def test_explicit_hunt_trace_preserves_decision_without_secrets_or_hidden_thoughts():
    trace = public_hunt_action_trace({
        "id": uuid.uuid4(),
        "capability_name": "http.request",
        "status": "completed",
        "input_summary": {
            "input": {"method": "POST", "path": "/login", "password": "opaque"},
            "input_digest": "input-digest",
            "idempotency_key_sha256": "key-digest",
        },
        "result_summary": {"ok": True, "secret": "response-secret"},
    })

    assert trace["decision"]["kind"] == "explicit_capability_selection"
    assert trace["decision"]["input"]["path"] == "/login"
    assert trace["decision"]["input"]["password"] == "***"
    assert trace["outcome"]["secret"] == "***"
    assert "opaque" not in json.dumps(trace)
    assert "response-secret" not in json.dumps(trace)


def test_hunt_run_service_get_includes_canonical_action_ledger():
    hunt_id = str(uuid.uuid4())

    class Connection:
        async def fetchrow(self, query, *args):
            assert query.startswith("SELECT * FROM hunt_runs")
            return _row(id=uuid.UUID(hunt_id))

        async def fetch(self, query, *args):
            assert "FROM hunt_actions WHERE hunt_run_id=$1" in query
            assert args == (uuid.UUID(hunt_id),)
            return [{
                "id": uuid.uuid4(),
                "capability_name": "collections.inspect",
                "status": "completed",
                "input_summary": {},
                "result_summary": {},
                "receipt_id": uuid.uuid4(),
                "started_at": datetime(2026, 8, 25, tzinfo=timezone.utc),
                "completed_at": datetime(2026, 8, 25, tzinfo=timezone.utc),
            }]

    service = HuntRunService(lambda: _Pool(Connection()))
    result = asyncio.run(service.get(hunt_id))

    assert len(result["actions"]) == 1
    assert result["actions"][0]["capability_name"] == "collections.inspect"


def test_hunt_record_combines_explicit_trace_debrief_and_redacted_http_archive():
    hunt_id = str(uuid.uuid4())

    class Connection:
        async def fetchrow(self, query, *args):
            if query.startswith("SELECT * FROM hunt_runs"):
                return _row(
                    id=uuid.UUID(hunt_id), status="completed",
                    notes=[{"note": "Review authorization"}],
                    final_debrief={
                        "summary": "Admin token LEAKED_TOKEN_ABC123 exposed",
                        "next_actions": ["mysql -u root -pHunter2"],
                    },
                    context_pack={"ssh_plan": "mysql -u root -pHunter2"},
                )
            if "FROM http_archive_stats" in query:
                return {"attempted": 0, "stored": 0, "failed": 0, "dropped": 0}
            raise AssertionError(query)

        async def fetchval(self, query, *args):
            if query.startswith("SELECT COUNT(*) FROM http_transactions"):
                return 0
            raise AssertionError(query)

        async def fetch(self, query, *args):
            if "FROM hunt_actions WHERE hunt_run_id=$1" in query:
                return [{
                    "id": uuid.uuid4(),
                    "capability_name": "http.request",
                    "status": "completed",
                    "input_summary": {"input": {"method": "GET", "path": "/health"}},
                    "result_summary": {"ok": True},
                    "receipt_id": uuid.uuid4(),
                    "started_at": datetime(2026, 8, 25, tzinfo=timezone.utc),
                    "completed_at": datetime(2026, 8, 25, tzinfo=timezone.utc),
                }]
            if "FROM http_transactions t" in query:
                return []
            if "FROM hunt_actions action" in query:
                return []
            raise AssertionError(query)

    service = HuntRunService(lambda: _Pool(Connection()))
    record = asyncio.run(service.export_record(hunt_id))

    assert record["schema_version"] == "hunt-record/v1"
    assert record["trace_policy"]["kind"] == "explicit_decision_trace"
    assert "hidden_model_chain_of_thought" in record["trace_policy"]["excludes"]
    assert record["decision_trace"][0]["decision"]["input"]["path"] == "/health"
    assert "LEAKED_TOKEN_ABC123" not in json.dumps(record)
    assert "Hunter2" not in json.dumps(record)
    assert "context_pack" not in record["hunt"]
    assert record["trace_policy"]["residual_secret_risk"] is True
    assert record["http_archive"]["fidelity"] == "unavailable"


def test_hunt_run_service_lists_without_context_or_capability_expansion():
    class Connection:
        async def fetchval(self, query, *args):
            # Counted before paging so a client can report "51-100 of 240" rather than
            # only how many rows this page happened to return.
            assert query.startswith("SELECT COUNT(*)")
            assert "LIMIT" not in query
            return 240

        async def fetch(self, query, *args):
            assert "h.target_id=$1 OR h.device_target_id=$1" in query
            assert "h.status=$2" in query
            assert "LEFT JOIN targets t" in query
            assert "LIMIT $3 OFFSET $4" in query
            assert args[1:] == ("active", 25, 50)
            return [_row()]

    service = HuntRunService(lambda: _Pool(Connection()))
    result = asyncio.run(service.list(
        target_id=str(uuid.uuid4()), status="active", limit=25, offset=50,
    ))

    assert result["count"] == 1
    assert result["total"] == 240
    assert result["offset"] == 50
    assert "context_pack" not in result["hunts"][0]
    assert "capabilities" not in result["hunts"][0]

    for kwargs in (
        {"status": "invented"},
        {"target_kind": "invented"},
        {"budget_profile": "invented"},
        {"sort_by": "objective; DROP TABLE"},
    ):
        with pytest.raises(run_router.HTTPException) as exc:
            asyncio.run(service.list(limit=25, **kwargs))
        assert exc.value.status_code == 400, kwargs


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


def test_hunt_run_router_owns_the_complete_public_hunt_lifecycle():
    paths = {
        (frozenset(route.methods or ()), route.path, route.name)
        for route in run_router.router.routes
    }
    assert paths == {
        (frozenset({"POST"}), "/hunts", "start_hunt"),
        (frozenset({"GET"}), "/hunts/contract", "get_hunt_contract"),
        (frozenset({"GET"}), "/hunt/skills", "list_hunt_skills"),
        (frozenset({"GET"}), "/hunt/skills/{skill_id}", "get_hunt_skill"),
        (
            frozenset({"GET"}),
            "/hunts/lifecycle-metrics",
            "get_hunt_lifecycle_metrics",
        ),
        (frozenset({"GET"}), "/hunts/{hunt_id}", "get_hunt"),
        (frozenset({"GET"}), "/hunts/{hunt_id}/record", "export_hunt_record"),
        (frozenset({"GET"}), "/hunts", "list_hunts"),
        (frozenset({"POST"}), "/hunts/{hunt_id}/finish", "finish_hunt"),
        (frozenset({"POST"}), "/hunts/{hunt_id}/cancel", "cancel_hunt"),
        (frozenset({"POST"}), "/hunts/{hunt_id}/resume", "resume_hunt"),
    }
