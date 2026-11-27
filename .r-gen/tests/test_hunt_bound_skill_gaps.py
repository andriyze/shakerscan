"""Bound methodologies expose capability gaps without changing execution authority."""

import asyncio
from copy import deepcopy
import json

import pytest

from api.hunt.run_service import HuntRunService
from api.hunt.skills import bind_skills_to_hunt, load_skill_library, skill_context_section
from tests.test_hunt_skill_lifecycle import _Connection, _Pool, SKILL_ID


@pytest.fixture(scope="module")
def library():
    return load_skill_library()


def requirements(library, skill_id):
    return list(dict.fromkeys(
        name for spec in library.resolve_for_hunt([skill_id], target_kind="web")
        for name in spec.capabilities
    ))


@pytest.mark.parametrize("mode", ["complete", "narrow", "empty"])
def test_start_context_reports_exact_gaps_for_each_bound_skill(library, mode):
    needed = requirements(library, SKILL_ID)
    allowed = {"complete": tuple(needed), "narrow": ("http.request",), "empty": ()}[mode]
    budget = object()
    bound = bind_skills_to_hunt(
        [SKILL_ID], target_kind="web", allowed_capabilities=allowed,
        budget=budget, library=library,
    )
    assert bound.allowed_capabilities is allowed
    assert bound.budget is budget
    rows = bound.context_section["bound"]
    assert rows
    for row in rows:
        expected = [name for name in requirements(library, row["skill_id"]) if name not in allowed]
        assert row["withheld_capabilities"] == expected
        assert row["requested"] is (row["skill_id"] == SKILL_ID)
        assert "methodology" not in row and "techniques" not in row
    assert json.loads(json.dumps(rows)) == rows


def test_bound_gap_includes_a_missing_prerequisite_capability(library):
    spec = next(spec for spec in library.bindable(target_kind="web")
                if set(requirements(library, spec.skill_id)) - set(spec.capabilities))
    bound = bind_skills_to_hunt(
        [spec.skill_id], target_kind="web", allowed_capabilities=spec.capabilities,
        budget=None, library=library,
    )
    row = next(row for row in bound.context_section["bound"] if row["skill_id"] == spec.skill_id)
    expected = [name for name in requirements(library, spec.skill_id) if name not in spec.capabilities]
    assert expected and row["withheld_capabilities"] == expected


def test_bound_and_suggested_gaps_share_one_capability_snapshot(library):
    allowed = ("http.request",)
    specs = library.resolve_for_hunt([SKILL_ID], target_kind="web")
    args = dict(specs=specs, requested=[SKILL_ID], library=library,
                target_kind="web", goal="Investigate GraphQL JWT and Cloudflare WAF")
    expected = skill_context_section(**args, allowed_capabilities=allowed)
    assert expected["suggested"]
    assert skill_context_section(**args, allowed_capabilities=iter(allowed)) == expected
    assert next(row for row in expected["bound"] if row["skill_id"] == SKILL_ID)["withheld_capabilities"]


def test_one_shot_skill_selection_keeps_explicit_and_prerequisite_labels(library):
    args = dict(target_kind="web", allowed_capabilities=("http.request",),
                budget=None, library=library)
    expected = bind_skills_to_hunt([SKILL_ID], **args)
    actual = bind_skills_to_hunt(iter([SKILL_ID]), **args)
    assert actual.context_section == expected.context_section


def test_planner_instruction_classifies_unavailable_techniques_as_coverage_gaps(library):
    section = skill_context_section((), requested=(), library=library, allowed_capabilities=())
    instruction = section["selection"]["instruction"]
    assert "withheld_capabilities" in instruction
    assert "coverage gaps" in instruction
    assert "never findings or clean results" in instruction


@pytest.mark.parametrize("allowed", [("http.request",), ()])
def test_mid_run_binding_persists_gaps_and_unbind_refresh_preserves_them(allowed):
    connection = _Connection()
    connection.row["policy_json"]["allowed_capabilities"] = list(allowed)
    connection.row["budget_json"] = {"max_http_requests": 40}
    connection.row["budget_used_json"] = {"http_requests": 3}
    before = {key: deepcopy(connection.row[key]) for key in
              ("policy_json", "budget_json", "budget_used_json", "status")}
    service = HuntRunService(lambda: _Pool(connection))
    hunt_id = str(connection.hunt_id)
    library = load_skill_library()
    other = "skill.web.http-baselining-replay-and-differential-analysis"
    for skill_id in (SKILL_ID, other):
        asyncio.run(service.read_skill(hunt_id, skill_id))
        response = asyncio.run(service.bind_skill(hunt_id, skill_id))
        for row in response["skills"]:
            assert row["withheld_capabilities"] == [
                name for name in requirements(library, row["skill_id"]) if name not in allowed
            ]
        assert response["skills"] == response["context_pack"]["skills"]["bound"]
        # The metadata is durable, not attached only to the immediate response.
        assert all("withheld_capabilities" in row for row in connection.row["context_pack"]["skills"]["bound"])
    response = asyncio.run(service.unbind_skill(hunt_id, SKILL_ID))
    assert [row["skill_id"] for row in response["skills"]] == [other]
    assert response["skills"][0]["withheld_capabilities"] == [
        name for name in requirements(library, other) if name not in allowed
    ]
    assert {key: connection.row[key] for key in before} == before
    assert not response["actions"]  # Selecting methodology did not execute anything.


def test_rebinding_existing_revision_refreshes_old_context_without_duplicate_events():
    connection = _Connection()
    service = HuntRunService(lambda: _Pool(connection))
    hunt_id = str(connection.hunt_id)
    asyncio.run(service.read_skill(hunt_id, SKILL_ID))
    asyncio.run(service.bind_skill(hunt_id, SKILL_ID))
    for row in connection.row["context_pack"]["skills"]["bound"]:
        row.pop("withheld_capabilities", None)
    events = deepcopy(connection.events)
    result = asyncio.run(service.bind_skill(hunt_id, SKILL_ID))
    assert all(row["withheld_capabilities"] == [] for row in result["skills"])
    assert connection.events == events


def test_a_bound_skills_gap_does_not_contaminate_other_bound_methodologies(library):
    complete = "skill.web.http-baselining-replay-and-differential-analysis"
    allowed = tuple(requirements(library, complete))
    assert set(requirements(library, SKILL_ID)) - set(allowed)
    context = bind_skills_to_hunt(
        [complete, SKILL_ID], target_kind="web", allowed_capabilities=allowed,
        budget=None, library=library,
    ).context_section
    rows = {row["skill_id"]: row for row in context["bound"]}
    assert rows[complete]["withheld_capabilities"] == []
    assert rows[SKILL_ID]["withheld_capabilities"] == [
        name for name in requirements(library, SKILL_ID) if name not in allowed
    ]
