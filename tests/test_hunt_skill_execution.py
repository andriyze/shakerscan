"""Suggestion execution metadata describes requirements without changing Hunt authority."""

import pytest

from api.hunt.skills import load_skill_library


GOAL = "Validate Cloudflare WAF and direct origin exposure"
EDGE = "skill.web.edge-waf-and-origin-exposure-validation"


@pytest.fixture(scope="module")
def library():
    return load_skill_library()


def required_capabilities(library, skill_id):
    return tuple(dict.fromkeys(
        name
        for spec in library.resolve_for_hunt([skill_id], target_kind="web")
        for name in spec.capabilities
    ))


@pytest.mark.parametrize("authority", ["catalog", "complete", "narrow", "empty"])
def test_execution_metadata_matches_the_supplied_authority(library, authority):
    required = required_capabilities(library, EDGE)
    allowed = {
        "catalog": None,
        "complete": required,
        "narrow": ("http.request",),
        "empty": (),
    }[authority]
    suggestion = library.suggest(
        goal=GOAL, target_kind="web", allowed_capabilities=allowed,
    )[0]
    missing = [] if allowed is None else [name for name in required if name not in allowed]
    assert suggestion["skill_id"] == EDGE
    assert suggestion["auto_bound"] is False
    assert suggestion["execution"] == {
        "fully_executable": not missing,
        "unavailable_capabilities": missing,
    }
    assert "methodology" not in suggestion
    assert "capabilities" not in suggestion


@pytest.mark.parametrize("narrow", [False, True])
def test_generator_authority_matches_reusable_authority_for_every_suggestion(library, narrow):
    allowed = ("http.request",) if narrow else tuple(dict.fromkeys(
        name for spec in library.list() for name in spec.capabilities
    ))
    args = {"goal": "Investigate GraphQL JWT and Cloudflare WAF", "target_kind": "web"}
    reusable = library.suggest(**args, allowed_capabilities=allowed)
    assert len(reusable) > 1, "exercise reuse across multiple ranked suggestions"
    one_shot = library.suggest(**args, allowed_capabilities=iter(allowed))
    assert one_shot == reusable


def test_prerequisite_gaps_are_reported_without_hiding_the_methodology(library):
    # Find a real shipped methodology with a capability supplied only by a prerequisite.
    spec = next(spec for spec in library.bindable(target_kind="web")
                if set(required_capabilities(library, spec.skill_id)) - set(spec.capabilities))
    required = required_capabilities(library, spec.skill_id)
    missing = [name for name in required if name not in spec.capabilities]
    suggestion = library.suggest(
        goal=spec.title,
        target_kind="web",
        allowed_capabilities=spec.capabilities,
        exclude=(other.skill_id for other in library.list() if other.skill_id != spec.skill_id),
    )[0]
    assert suggestion["skill_id"] == spec.skill_id
    assert suggestion["execution"] == {
        "fully_executable": False,
        "unavailable_capabilities": missing,
    }
