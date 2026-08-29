"""The Hunt skill library must never advertise authority or work it cannot deliver."""

import pytest

from api.hunt.skills import (
    MAX_SKILLS_PER_HUNT,
    SKILL_BUDGET_DIMENSIONS,
    HuntSkillError,
    HuntSkillLibrary,
    build_skill_spec,
    load_skill_library,
)
from api.hunt.start_contract import MAX_SKILLS
from api.runtime.capability_registry import CAPABILITY_REGISTRY


@pytest.fixture(scope="module")
def library():
    return load_skill_library()


def _spec(**overrides):
    base = {
        "id": "skill.web.example",
        "name": "example",
        "title": "Example",
        "description": "An example skill.",
        "version": "1.0.0",
        "kind": "specialist",
        "phase": "active_testing",
        "risk": "medium",
        "support": "supported",
        "target_kinds": ["web"],
        "capabilities": ["http.request"],
    }
    base.update(overrides)
    return base


def test_the_shipped_library_loads(library):
    assert len(library) >= 30


def test_every_declared_capability_is_real_and_planner_visible(library):
    """A skill naming a capability the planner cannot call would advertise dead work."""
    for spec in library.list():
        for name in (*spec.capabilities, *spec.optional_capabilities):
            assert CAPABILITY_REGISTRY.require(name).planner_visible, (
                f"{spec.skill_id} names non-planner capability {name}"
            )


def test_support_level_matches_the_declared_gap(library):
    for spec in library.list():
        if spec.support == "supported":
            assert not spec.missing_capabilities
            assert spec.capabilities
        elif spec.support == "partial":
            assert spec.missing_capabilities


def test_only_supported_skills_are_bindable(library):
    for spec in library.list():
        assert spec.bindable is (spec.support == "supported")


def test_no_skill_can_reach_shell_or_planner_supplied_argv(library):
    """AI-Native rule 3. The upstream library offers a shell adapter; ShakerScan does not."""
    for spec in library.list():
        names = {*spec.capabilities, *spec.optional_capabilities}
        assert not any("shell" in name for name in names), spec.skill_id
        assert "shell.allowlisted" not in spec.missing_capabilities, (
            f"{spec.skill_id} still treats shell as a missing requirement rather than a "
            "capability ShakerScan refuses to have"
        )


def test_declared_budgets_are_real_hunt_dimensions(library):
    for spec in library.list():
        for name, amount in spec.budget.items():
            assert name in SKILL_BUDGET_DIMENSIONS
            assert amount > 0


def test_the_request_boundary_and_the_library_agree_on_the_cap():
    assert MAX_SKILLS == MAX_SKILLS_PER_HUNT


def test_a_partial_skill_cannot_be_bound_to_a_hunt(library):
    partial = next(s for s in library.list(support="partial"))
    with pytest.raises(HuntSkillError, match="cannot be bound"):
        library.resolve_for_hunt([partial.skill_id], target_kind="web")


def test_a_reference_skill_cannot_be_bound_to_a_hunt(library):
    reference = next(iter(library.list(support="reference")), None)
    if reference is None:
        pytest.skip("no reference skills in the shipped library")
    with pytest.raises(HuntSkillError, match="cannot be bound"):
        library.resolve_for_hunt([reference.skill_id], target_kind="web")


def test_prerequisites_are_expanded_rather_than_demanded(library):
    """25 of 30 skills need the baselining skill; making the operator name it teaches
    nothing and would be pasted from a template every time."""
    dependent = next(
        s for s in library.bindable(target_kind="web") if s.requires_skills
    )
    resolved = library.resolve_for_hunt([dependent.skill_id], target_kind="web")
    resolved_ids = {item.skill_id for item in resolved}
    assert dependent.skill_id in resolved_ids
    for required in dependent.requires_skills:
        assert required in resolved_ids


def test_binding_more_skills_than_the_cap_is_refused(library):
    bindable = [s.skill_id for s in library.bindable(target_kind="web")]
    with pytest.raises(HuntSkillError, match="at most"):
        library.resolve_for_hunt(bindable[: MAX_SKILLS_PER_HUNT + 1], target_kind="web")


def test_a_skill_cannot_be_bound_to_the_wrong_target_kind(library):
    web_skill = library.bindable(target_kind="web")[0]
    with pytest.raises(HuntSkillError, match="does not support target kind"):
        library.resolve_for_hunt([web_skill.skill_id], target_kind="device")


def test_an_unknown_skill_is_refused(library):
    with pytest.raises(HuntSkillError, match="unknown skill"):
        library.resolve_for_hunt(["skill.web.does-not-exist"], target_kind="web")


def test_budget_ceilings_take_the_most_permissive_bound_value(library):
    """Two skills in one hunt must not starve each other; the run profile still caps them."""
    specs = library.resolve_for_hunt(
        [s.skill_id for s in library.bindable(target_kind="web")[:2]], target_kind="web"
    )
    ceilings = HuntSkillLibrary.budget_ceilings(specs)
    for name, amount in ceilings.items():
        assert amount == max(
            spec.budget.get(name, 0) for spec in specs
        )


def test_the_allowlist_is_a_union_the_caller_then_intersects(library):
    """The library reports what the skills want. Narrowing happens against the policy
    allowlist at start, so a skill can lose a capability but never gain one."""
    specs = library.resolve_for_hunt(
        [library.bindable(target_kind="web")[0].skill_id], target_kind="web"
    )
    allowlist = set(HuntSkillLibrary.capability_allowlist(specs))
    for spec in specs:
        assert set(spec.capabilities) <= allowlist


# --- declaration validation -------------------------------------------------------------

def test_an_unknown_capability_is_rejected_at_load():
    with pytest.raises(HuntSkillError, match="unknown capability"):
        build_skill_spec(_spec(capabilities=["http.nope"]), path="x.md", body="")


def test_a_server_only_capability_is_rejected_at_load():
    server_only = next(
        s.name for s in CAPABILITY_REGISTRY.list() if not s.planner_visible
    )
    with pytest.raises(HuntSkillError, match="not planner-visible"):
        build_skill_spec(_spec(capabilities=[server_only]), path="x.md", body="")


def test_claiming_support_while_something_is_missing_is_rejected():
    with pytest.raises(HuntSkillError, match="still missing"):
        build_skill_spec(
            _spec(missing_capabilities=["oob.allocate"]), path="x.md", body=""
        )


def test_a_bindable_skill_must_name_a_capability():
    with pytest.raises(HuntSkillError, match="at least one capability"):
        build_skill_spec(_spec(capabilities=[]), path="x.md", body="")


def test_a_budget_dimension_outside_the_skill_subset_is_rejected():
    with pytest.raises(HuntSkillError, match="not a skill ceiling"):
        build_skill_spec(
            _spec(budget={"max_tcp_ports": 100}), path="x.md", body=""
        )


def test_a_deferred_technique_must_say_what_it_needs():
    with pytest.raises(HuntSkillError, match="what it requires"):
        build_skill_spec(
            _spec(deferred_techniques=[{"technique": "smuggling"}]), path="x.md", body=""
        )


def test_a_skill_cannot_require_one_that_is_not_bindable():
    unbindable = _spec(
        id="skill.web.gap", name="gap", support="partial",
        missing_capabilities=["oob.allocate"],
    )
    dependent = _spec(id="skill.web.dependent", requires_skills=["skill.web.gap"])
    with pytest.raises(HuntSkillError, match="not bindable"):
        HuntSkillLibrary([
            build_skill_spec(unbindable, path="a.md", body=""),
            build_skill_spec(dependent, path="b.md", body=""),
        ])
