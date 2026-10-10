"""Target instructions and saved actions this engine wrote, and records a later engine may write.

Every stored record must be read (``GET /targets/{id}/skill`` never answers 500 for one), and
nothing may be read as operator guidance unless an operator wrote it or a Hunt wrote it under the
explicit ``instruction_changes`` opt-in: an authority this engine does not know reads as ``none``,
and an origin it does not know only demotes. (2.8.3 reads 2.9 records the same way after a rollback;
its copy of this test asserts the 2.8 reading.)
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


def test_a_hunt_write_under_instruction_changes_is_delegated_guidance():
    document = _document(4, writer=HUNT, authority="target_instruction_delegation", origin="agent_delegated")
    served = _served(_row(_saved(document)))
    assert served["skill"]["instruction_authority"] == "target_instruction_delegation"
    assert served["trust"] == "operator_delegated"
    assert served["operator_skill"]["methodology"] == document["methodology"]
    snapshot = planner_snapshot(target_skill._public(_row(_saved(document))))
    assert snapshot["skill"]["methodology"] == document["methodology"] and snapshot["authority_granted"] is False


def test_an_operator_write_stays_operator_guidance():
    document = _document(5, writer="operator:target-skill-api", authority="operator", origin="operator")
    served = _served(_row(_saved(document)))
    assert served["trust"] == "operator"
    assert served["operator_skill"]["methodology"] == document["methodology"]


def test_unconfirmed_text_carried_by_a_knowledge_write_is_never_operator_guidance():
    unconfirmed = _document(2, writer=HUNT, authority="target_metadata_delegation", origin="agent_unconfirmed")
    knowledge = _document(6, writer=HUNT, authority="none", origin=None, purpose="knowledge",
                          text="The ticket export endpoint paginates by cursor.")
    saved = _saved(knowledge, operator_snapshot=unconfirmed, knowledge_snapshot=knowledge)
    served = _served(_row(saved))
    assert served["operator_skill"] is None
    assert served["unconfirmed_instructions"]["methodology"] == unconfirmed["methodology"]
    assert served["knowledge"]["methodology"] == knowledge["methodology"]
    assert planner_snapshot(target_skill._public(_row(saved)))["skill"] is None


@pytest.mark.parametrize(("authority", "origin"), [
    ("some_future_authority", None),
    ("operator", "some_future_origin"),
    ("target_instruction_delegation", "some_future_origin"),
    ("target_metadata_delegation", "agent_unconfirmed"),
    ("operator", "agent_delegated"),
])
def test_unknown_values_read_as_the_least_trusted_and_never_as_operator(authority, origin):
    for writer in (HUNT, "operator:target-skill-api", "agent:unknown"):
        document = _document(7, writer=writer, authority=authority, origin=origin)
        served = _served(_row(_saved(document)))  # never a 500
        assert served["skill"]["instruction_authority"] in {
            "operator", "target_instruction_delegation", "target_metadata_delegation", "none"}
        assert served["skill"]["origin"] in {None, "operator", "agent_delegated", "agent_unconfirmed"}
        if origin is not None or not writer.startswith("operator:"):
            assert served["trust"] in {"hunt_advisory", "unknown_advisory", "agent_unconfirmed"}, (
                writer, authority, origin)
            assert served["operator_skill"] is None
        assert instruction_trust({**document, "written_by": writer}) != "operator" or (
            writer.startswith("operator:") and origin in (None, "operator"))


def test_saved_actions_are_read_with_extra_fields_and_unknown_marks_demote():
    from targets.skill_trust import action_trust
    action = {"id": str(uuid.UUID(int=2902)), "target_id": str(TARGET), "name": "Export tickets",
              "instructions": "Call the export route.", "steps": [], "parameters": {}, "revision": 1,
              "body_sha256": "a" * 64, "updated_at": "2026-10-20T10:00:00+00:00", "written_by": HUNT,
              "instruction_authority": "target_instruction_delegation", "delegation_revision": 3,
              "origin": "agent_delegated", "a_later_field": True}
    row = {"id": TARGET, "metadata_json": {"hunt_actions": {"revision": 1, "actions": [action]}}}
    listed = public_actions(row)
    assert listed["actions"][0]["name"] == "Export tickets" and listed["authority_granted"] is False
    assert action_trust(action) == "operator_delegated"
    assert action_trust({**action, "origin": "some_future_origin"}) == "agent_unconfirmed"
    assert action_trust({**action, "written_by": "operator:x", "origin": "agent_delegated"}) == "agent_unconfirmed"


def test_an_operator_write_records_its_own_origin_and_drops_earlier_marks():
    """An operator saving instructions writes a fresh record: no earlier mark carries over."""
    source = Path(target_skill.__file__).read_text(encoding="utf-8")
    body = source[source.index("async def write_target_skill"):]
    body = body[:body.index("\nasync def ")]
    assert "saved = {'revision': current['revision'] + 1," in body
    assert "saved['origin'] = 'operator' if operator else 'agent_delegated'" in body
