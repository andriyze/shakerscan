"""After a rollback from 2.9, this engine reads target instructions a 2.9 engine wrote.

2.9 records a new instruction authority (``target_instruction_delegation``) and an ``origin`` on
instruction writes and saved actions. 2.8.2 validated the stored document against its closed set of
authorities, so ``GET /targets/{id}/skill`` answered 500 for such a target. These rows are shaped as
2.9 writes them (release/2.9.0 ``targets/skill.py`` and ``targets/actions.py``); every one must be
read, and nothing a later engine marks may be read as operator guidance unless an operator wrote
it: an unknown authority reads as ``none`` and any origin other than ``operator`` only demotes.
"""
from __future__ import annotations

import hashlib
import sys
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "api") not in sys.path:
    sys.path.insert(0, str(ROOT / "api"))

from targets import skill as target_skill  # noqa: E402
from targets.actions import public_actions  # noqa: E402
from targets.skill_trust import instruction_trust, planner_snapshot  # noqa: E402

TARGET = uuid.UUID(int=2900)
HUNT = f"hunt:{uuid.UUID(int=2901)}"


def _document(revision: int, *, writer: str, authority: str, origin: str | None, purpose: str = "instructions",
              text: str = "Log in as the support role and map the ticket routes.") -> dict:
    """An instruction document as a 2.9 engine's ``_public`` builds and snapshots it."""
    return {
        "schema_version": "hunt-skill/v2", "skill_id": f"skill.target.{TARGET}", "target_id": str(TARGET),
        "source": "target", "kind": "target_instructions", "title": "Support portal",
        "methodology": text, "version": str(revision),
        "body_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "updated_at": "2026-10-20T10:00:00+00:00", "written_by": writer, "purpose": purpose,
        "instruction_authority": authority, "delegation_revision": 3 if writer.startswith("hunt:") else None,
        "origin": origin,
    }


def _row(saved: dict) -> dict:
    return {"id": TARGET, "metadata_json": {"target_skill": saved}}


def _saved(document: dict, **extra) -> dict:
    record = {key: document[key] for key in ("title", "methodology", "body_sha256", "updated_at", "written_by",
                                             "purpose", "instruction_authority", "delegation_revision", "origin")}
    record.update(revision=int(document["version"]), history=[], operator_snapshot=document,
                  knowledge_snapshot=None)
    record.update(extra)
    return record


def _served(row: dict) -> dict:
    """What GET /targets/{id}/skill answers: the projection, validated by its response model."""
    public = target_skill._public(row)
    return target_skill.TargetSkillResponse.model_validate(public).model_dump()


def test_a_hunt_write_under_2_9_instruction_changes_is_served_and_only_advisory():
    document = _document(4, writer=HUNT, authority="target_instruction_delegation", origin="agent_delegated")
    served = _served(_row(_saved(document)))
    assert served["skill"]["instruction_authority"] == "none"
    assert served["operator_skill"] is None
    assert served["trust"] == "hunt_advisory"
    snapshot = planner_snapshot(target_skill._public(_row(_saved(document))))
    assert snapshot["skill"] is None and snapshot["authority_granted"] is False


def test_an_operator_write_by_2_9_stays_operator_guidance():
    document = _document(5, writer="operator:target-skill-api", authority="operator", origin="operator")
    served = _served(_row(_saved(document)))
    assert served["trust"] == "operator"
    assert served["operator_skill"]["methodology"] == document["methodology"]


def test_unconfirmed_text_carried_by_a_2_9_knowledge_write_is_never_operator_guidance():
    unconfirmed = _document(2, writer=HUNT, authority="target_metadata_delegation", origin="agent_unconfirmed")
    knowledge = _document(6, writer=HUNT, authority="none", origin=None, purpose="knowledge",
                          text="The ticket export endpoint paginates by cursor.")
    saved = _saved(knowledge, operator_snapshot=unconfirmed, knowledge_snapshot=knowledge)
    served = _served(_row(saved))
    assert served["operator_skill"] is None
    assert served["knowledge"]["methodology"] == knowledge["methodology"]
    assert planner_snapshot(target_skill._public(_row(saved)))["skill"] is None


@pytest.mark.parametrize(("authority", "origin"), [
    ("target_instruction_delegation", None),
    ("some_future_authority", None),
    ("operator", "some_future_origin"),
    ("target_metadata_delegation", "agent_unconfirmed"),
])
def test_unknown_values_read_as_the_least_trusted_and_never_as_operator(authority, origin):
    for writer in (HUNT, "operator:target-skill-api", "agent:unknown"):
        document = _document(7, writer=writer, authority=authority, origin=origin)
        served = _served(_row(_saved(document)))  # never a 500
        assert served["skill"]["instruction_authority"] in {"operator", "target_metadata_delegation", "none"}
        if origin is not None or not writer.startswith("operator:"):
            assert served["trust"] in {"hunt_advisory", "unknown_advisory"}, (writer, authority, origin)
            assert served["operator_skill"] is None
        assert instruction_trust({**document, "written_by": writer}) != "operator" or (
            writer.startswith("operator:") and origin in (None, "operator"))


def test_saved_actions_written_by_2_9_are_read_with_their_extra_fields():
    action = {"id": str(uuid.UUID(int=2902)), "target_id": str(TARGET), "name": "Export tickets",
              "instructions": "Call the export route.", "steps": [], "parameters": {}, "revision": 1,
              "body_sha256": "a" * 64, "updated_at": "2026-10-20T10:00:00+00:00", "written_by": HUNT,
              "instruction_authority": "target_instruction_delegation", "delegation_revision": 3,
              "origin": "agent_delegated"}
    row = {"id": TARGET, "metadata_json": {"hunt_actions": {"revision": 1, "actions": [action]}}}
    listed = public_actions(row)
    assert listed["actions"][0]["name"] == "Export tickets" and listed["authority_granted"] is False


def test_an_operator_write_on_this_engine_drops_a_2_9_origin():
    """An operator saving instructions here writes a fresh record: no 2.9 mark carries over."""
    source = Path(target_skill.__file__).read_text(encoding="utf-8")
    body = source[source.index("async def write_target_skill"):]
    body = body[:body.index("\nasync def ")]
    assert "saved = {'revision': current['revision'] + 1," in body
    assert "origin" not in body.split("saved = {'revision'")[1].split("next_row")[0]
