"""The environment a target was admitted under reaches every later admission of it.

Recheck finding N01 on PR #162. The admission resolver classifies each DNS answer under a
deployment policy for a given environment, but two of its callers never said which environment
they meant and so fell back to production: Hunt's context-pack builder and the broker's
dispatch-time DNS revalidation. On a deployment that refuses private ranges, a Lab target that
was admitted correctly at Scan creation was then refused when Hunt seeded its session or when
the broker revalidated the name at dispatch. Same target, same policy, different verdicts.

The controls themselves stay: restricted classes are still never admitted, and a deployment
that refuses private ranges still refuses them for a production target. What changes is that
each caller now carries the target's own environment to the resolver instead of assuming the
strictest one.

Finding N02, from the same recheck: an IPv4-mapped IPv6 form of a restricted address, such as
``::ffff:169.254.169.254``, is classified as the IPv4 address it names.
"""
from __future__ import annotations

import ast
import asyncio
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

import action_scope  # noqa: E402
from tests.api_sources import definition_source  # noqa: E402


# ---------------------------------------------------------------- the two callers that fell back


def _calls_of(source: str, callee: str) -> list[ast.Call]:
    tree = ast.parse(source)
    found: list[ast.Call] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if name == callee:
                found.append(node)
    return found


def _keyword_names(call: ast.Call) -> set[str]:
    return {kw.arg for kw in call.keywords if kw.arg}


def test_every_hunt_context_pack_site_names_the_targets_environment():
    """The web and device context-pack builders each pass the stored target's environment."""
    source = (ROOT / "api" / "api.py").read_text(encoding="utf-8")
    calls = _calls_of(source, "_resolve_agent_target_addresses")
    assert len(calls) == 2, "expected the web and device Hunt context-pack sites"
    for call in calls:
        assert "environment" in _keyword_names(call), (
            f"line {call.lineno}: Hunt freezes the target's addresses without saying which "
            f"environment it was admitted under, so the resolver assumes production and a "
            f"refusing deployment rejects a Lab target Scan creation had admitted"
        )


def test_the_web_hunt_site_derives_it_the_same_way_authorization_does():
    """Not `metadata.environment` read by hand: the shared resolver, which also reads a cohort."""
    source = (ROOT / "api" / "api.py").read_text(encoding="utf-8")
    start = source.index('"schema_version": "hunt-context/v2"')
    web_site = source[start:start + 1500]
    assert web_site.count('target_authorization.effective_target_environment(') == 2, (
        "the context pack's environment and the admission environment must come from the one "
        "resolver authorization uses, or a target stored as a Lab cohort admits as production"
    )
    assert '.get("environment")\n                        or "unknown"' not in web_site


def test_the_device_hunt_site_reads_the_device_rows_environment():
    source = (ROOT / "api" / "api.py").read_text(encoding="utf-8")
    assert "device_class, environment, is_active FROM device_targets WHERE id=$1" in source, (
        "the device Hunt site must select the device's environment to pass it on"
    )
    assert 'environment=str(device["environment"] or "production")' in source


def test_hunt_session_seeding_carries_the_stored_environment():
    seed = definition_source("_agent_seed_state")
    assert "effective_target_environment(" in seed, (
        "_agent_seed_state freezes addresses without the target's environment"
    )
    assert "target_url, environment=target_environment," in seed


def test_the_hunt_wrapper_forwards_the_environment_it_is_given(monkeypatch):
    """Behavioral: the wrapper hands the environment to the fleet resolver unchanged."""
    from agent_routes import router as agent_router
    import fleet_routes.router as fleet_router

    seen: dict = {}

    async def resolver(url, *, subject, environment="production"):
        seen.update(url=url, subject=subject, environment=environment)
        return ["192.168.1.50"]

    monkeypatch.setattr(fleet_router, "_resolve_runtime_target_addresses", resolver)
    monkeypatch.setattr(agent_router._fleet_routes, "_resolve_runtime_target_addresses", resolver)

    result = asyncio.run(
        agent_router._resolve_agent_target_addresses("http://192.168.1.50", environment="lab")
    )
    assert result == ["192.168.1.50"]
    assert seen["environment"] == "lab"
    assert seen["subject"] == "Hunt target"

    asyncio.run(agent_router._resolve_agent_target_addresses("http://192.168.1.50"))
    assert seen["environment"] == "production", "no environment given: the strict reading"


def test_broker_revalidation_judges_answers_under_the_admitted_environment():
    source = (ROOT / "api" / "fleet_routes" / "router.py").read_text(encoding="utf-8")
    start = source.index('subject="broker Scan target"')
    call = source[start - 200:start + 200]
    assert 'environment=_binding_environment_from_options(row["options"])' in call, (
        "the broker revalidates DNS under production regardless of the environment the Scan "
        "was admitted under, so a refusing deployment refuses a correctly admitted Lab scan "
        "at dispatch"
    )


def test_the_binding_environment_comes_from_the_frozen_guard():
    """Behavioral, on the helper the broker call uses."""
    import fleet_routes.router as fleet_router

    read = fleet_router._binding_environment_from_options
    assert read({"runtime_scope_guard": {"environment": "lab"}}) == "lab"
    assert read('{"runtime_scope_guard": {"environment": "Staging"}}') == "staging"
    # what the guard writes when it does not know, and when there is no guard at all
    assert read({"runtime_scope_guard": {"environment": "unknown"}}) == "production"
    assert read({"runtime_scope_guard": {}}) == "production"
    assert read({}) == "production"
    assert read(None) == "production"
    assert read("not json") == "production"


# ------------------------------------------------- the same verdict at admission and revalidation


def _admit(address, environment, allow_private=None):
    return action_scope._ip_scope_block_reason(
        address, environment, allow_private_networks=allow_private,
    ) is None


@pytest.mark.parametrize("address", ["192.168.1.50", "10.0.0.7", "127.0.0.1"])
def test_a_lab_target_is_admitted_the_same_way_on_a_refusing_deployment(address):
    """What N01 broke: creation admitted under Lab; Hunt and the broker judged under production."""
    at_creation = _admit(address, "lab", allow_private=False)
    at_hunt_seed = _admit(address, "lab", allow_private=False)
    at_dispatch = _admit(address, "lab", allow_private=False)
    assert at_creation is at_hunt_seed is at_dispatch is True
    assert _admit(address, "production", allow_private=False) is False, (
        "the control is retained: a refusing deployment still refuses a production target"
    )


# ------------------------------------------------------------------ N02: IPv4-mapped IPv6 forms


@pytest.mark.parametrize("address", [
    "::ffff:255.255.255.255",
    "::ffff:169.254.169.254",
    "::ffff:224.0.0.1",
    "::ffff:0.0.0.0",
])
@pytest.mark.parametrize("environment", ["production", "lab"])
def test_an_ipv4_mapped_restricted_address_is_refused(address, environment):
    assert action_scope._ip_scope_block_reason(
        address, environment, allow_private_networks=True,
    ) == "loopback_or_private_range"


def test_an_ipv4_mapped_ordinary_private_address_follows_the_same_policy_as_its_ipv4_form():
    """The mapping normalizes; it neither loosens nor tightens the operator's own network."""
    for environment in ("production", "lab"):
        assert _admit("::ffff:192.168.1.50", environment) is _admit("192.168.1.50", environment)
    assert _admit("::ffff:192.168.1.50", "production", allow_private=False) is False
    assert _admit("::ffff:192.168.1.50", "lab", allow_private=False) is True
