from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import uuid

import pytest
from fastapi import HTTPException

from api.hunt.run_service import HuntRunService
from api.hunt.skills import (
    bind_skills_to_hunt,
    record_initial_skill_bindings,
    skill_library,
)


SKILL_ID = "skill.web.edge-waf-and-origin-exposure-validation"
ROOT = Path(__file__).resolve().parents[1]


class _Transaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


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


def test_initial_skill_bindings_preserve_requested_and_prerequisite_reasons():
    class Recorder:
        def __init__(self):
            self.calls = []

        async def execute(self, query, *args):
            self.calls.append((query, args))

    library = skill_library()
    specs = library.resolve_for_hunt([SKILL_ID], target_kind="web")
    recorder = Recorder()
    hunt_id = uuid.uuid4()

    asyncio.run(record_initial_skill_bindings(
        recorder,
        hunt_run_id=hunt_id,
        specs=specs,
        requested_skill_ids=[SKILL_ID],
    ))

    assert len(recorder.calls) == len(specs)
    reasons = {args[1]: args[4] for _, args in recorder.calls}
    assert reasons[SKILL_ID] == "Explicitly selected at Hunt start"
    assert set(reasons.values()) <= {
        "Explicitly selected at Hunt start",
        "Required by selected methodology",
    }


class _Connection:
    def __init__(self):
        library = skill_library()
        resolved = library.resolve_for_hunt([SKILL_ID], target_kind="web")
        self.allowed = tuple(sorted({
            capability for spec in resolved for capability in spec.capabilities
        } | {"collections.inspect"}))
        context = dict(bind_skills_to_hunt(
            (), target_kind="web", allowed_capabilities=self.allowed,
            budget=object(), library=library, goal="Inspect the application",
        ).context_section)
        context["target"] = {"technologies": ["Cloudflare"]}
        self.hunt_id = uuid.uuid4()
        self.row = {
            "id": self.hunt_id,
            "target_kind": "web",
            "target_id": uuid.uuid4(),
            "device_target_id": None,
            "objective": "Inspect the application",
            "status": "active",
            "budget_profile": "balanced",
            "policy_json": {"allowed_capabilities": list(self.allowed)},
            "budget_json": {},
            "budget_used_json": {},
            "context_pack": {"skills": context, "target": context["target"]},
            "final_debrief": {},
            "stop_reason": None,
            "created_at": datetime(2026, 8, 29, tzinfo=timezone.utc),
            "updated_at": datetime(2026, 8, 29, tzinfo=timezone.utc),
            "completed_at": None,
        }
        self.events: list[dict] = []

    def transaction(self):
        return _Transaction()

    async def fetchrow(self, query, *args):
        if query.startswith("SELECT * FROM hunt_runs"):
            return self.row
        if "SELECT capability_name FROM hunt_actions" in query:
            return None
        raise AssertionError(query)

    async def fetchval(self, query, *args):
        if "FROM hunt_skill_events" in query and "event_type='read'" in query:
            return any(
                event["skill_id"] == args[1]
                and event["event_type"] == "read"
                and event["body_sha256"] == args[2]
                for event in self.events
            )
        raise AssertionError(query)

    async def fetch(self, query, *args):
        if "FROM hunt_actions WHERE hunt_run_id=$1" in query:
            return []
        if "FROM hunt_skill_events" in query:
            return list(self.events)
        raise AssertionError(query)

    async def execute(self, query, *args):
        if query.startswith("UPDATE hunt_runs SET context_pack"):
            self.row["context_pack"] = json.loads(args[1])
            return "UPDATE 1"
        if "INSERT INTO hunt_skill_events" in query:
            if "'read'" in query:
                event_type = "read"
                skill_id, version, digest, reason = args[1], args[2], args[3], args[4]
                if any(
                    event["skill_id"] == skill_id
                    and event["event_type"] == "read"
                    and event["body_sha256"] == digest
                    for event in self.events
                ):
                    return "INSERT 0 0"
                evidence_refs, action_id = [], None
            else:
                event_type = str(args[2]) if "$3" in query else "bound"
                if event_type == "bound":
                    skill_id, version, digest, reason = args[1], args[2], args[3], args[4]
                    evidence_refs = json.loads(args[5])
                else:
                    skill_id, version, digest, reason = args[1], args[3], args[4], args[5]
                    evidence_refs = json.loads(args[6]) if len(args) > 6 else []
                action_id = args[7] if len(args) > 7 else None
            self.events.append({
                "id": uuid.uuid4(),
                "skill_id": skill_id,
                "event_type": event_type,
                "skill_version": version,
                "body_sha256": digest,
                "reason": reason,
                "evidence_refs": evidence_refs,
                "action_id": action_id,
                "created_at": datetime.now(timezone.utc),
            })
            return "INSERT 0 1"
        raise AssertionError(query)


def test_progressive_methodology_is_compact_read_once_and_never_changes_authority():
    connection = _Connection()
    service = HuntRunService(lambda: _Pool(connection))
    hunt_id = str(connection.hunt_id)

    suggestions = asyncio.run(service.skill_suggestions(hunt_id))
    assert suggestions["methodology_bodies_loaded"] == 0
    assert suggestions["count"] <= 3
    assert suggestions["suggestions"][0]["skill_id"] == SKILL_ID
    assert suggestions["suggestions"][0]["reason"] == "Observed signals: cloudflare"
    assert "description" not in suggestions["suggestions"][0]

    first = asyncio.run(service.read_skill(hunt_id, SKILL_ID))
    second = asyncio.run(service.read_skill(hunt_id, SKILL_ID))
    assert first["methodology"] == second["methodology"]
    assert len([event for event in connection.events if event["event_type"] == "read"]) == 1

    before = list(connection.row["policy_json"]["allowed_capabilities"])
    bound = asyncio.run(service.bind_skill(
        hunt_id, SKILL_ID,
        reason="Cloudflare was observed", evidence_refs=["evidence:edge"],
    ))
    assert connection.row["policy_json"]["allowed_capabilities"] == before
    assert any(item["skill_id"] == SKILL_ID for item in bound["skills"])
    assert bound["context_pack"]["skills"]["selection"]["selection_optional"] is True
    assert len(bound["context_pack"]["skills"]["suggested"]) <= 3

    deferred = asyncio.run(service.record_skill_usage(
        hunt_id, SKILL_ID, state="deferred",
        reason="Direct-origin authority was not granted",
    ))
    assert deferred["skill_activity"][-1]["event_type"] == "deferred"
    assert deferred["skill_activity"][-1]["reason"].startswith("Direct-origin")


def test_runtime_binding_requires_that_exact_methodology_revision_to_be_read():
    connection = _Connection()
    service = HuntRunService(lambda: _Pool(connection))

    with pytest.raises(HTTPException) as exc:
        asyncio.run(service.bind_skill(
            str(connection.hunt_id), SKILL_ID, reason="Cloudflare was observed",
        ))

    assert getattr(exc.value, "status_code", None) == 409
    assert "read endpoint" in str(getattr(exc.value, "detail", ""))
    assert connection.row["context_pack"]["skills"]["bound"] == []


def test_fresh_and_upgraded_databases_persist_methodology_lifecycle_outside_context():
    initial = (ROOT / "db" / "init.sql").read_text(encoding="utf-8")
    migration = (ROOT / "api" / "retest_contract.py").read_text(encoding="utf-8")
    for source in (initial, migration):
        assert "CREATE TABLE IF NOT EXISTS hunt_skill_events" in source or "CREATE TABLE hunt_skill_events" in source
        assert "hunt_run_id UUID NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE" in source
        assert "body_sha256 TEXT NOT NULL" in source
        assert "action_id UUID REFERENCES hunt_actions(id) ON DELETE SET NULL" in source
