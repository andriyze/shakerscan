"""Operator evidence selects useful knowledge without pretending unsupported work ran."""
from __future__ import annotations

import asyncio
import copy

import pytest

from api.hunt.run_service import HuntRunService, _skill_signal_values
from api.hunt.skills import bind_skills_to_hunt, load_skill_library
from tests.test_hunt_skill_lifecycle import _Connection, _Pool

GRAPHQL = "skill.web.graphql-security-testing"
JWT = "skill.web.session-cookie-token-and-jwt-testing"


@pytest.fixture(scope="module")
def library():
    return load_skill_library()


def test_graphql_signal_selects_partial_graphql_methodology_with_honest_gaps(library):
    suggestion = library.suggest(goal="Investigate", target_kind="web", signals=["graphql"])[0]
    assert suggestion["skill_id"] == GRAPHQL
    assert suggestion["execution"]["fully_executable"] is False
    assert "graphql.execute" in suggestion["execution"]["missing_capabilities"]
    assert suggestion["auto_bound"] is False
    assert "methodology" not in suggestion


@pytest.mark.parametrize("kind", ["web", "api", "device", "network"])
def test_partial_methodology_preserves_the_existing_authority_and_budget(library, kind):
    allowed, budget = ("http.request",), object()
    bound = bind_skills_to_hunt([GRAPHQL], target_kind=kind, allowed_capabilities=allowed,
                               budget=budget, library=library)
    entry = next(row for row in bound.context_section["bound"] if row["skill_id"] == GRAPHQL)
    assert entry["support"] == "partial"
    assert entry["missing_capabilities"] == ["graphql.execute"]
    assert "authz.verify" in entry["withheld_capabilities"]
    assert "graphql.execute" not in entry["withheld_capabilities"]
    assert bound.allowed_capabilities is allowed and bound.budget is budget


@pytest.mark.parametrize("kind", ["device", "network"])
def test_web_methodology_is_suggested_for_observed_interface_not_asset_label(library, kind):
    assert library.suggest(goal="Investigate", target_kind=kind) == ()
    suggestion = library.suggest(goal="Investigate", target_kind=kind, signals=["graphql"])[0]
    assert suggestion["skill_id"] == GRAPHQL
    assert kind in library.require(GRAPHQL).catalog_entry()["target_kinds"]


@pytest.mark.parametrize("kind", ["device", "network"])
def test_read_and_bind_paths_accept_interface_methodology_without_new_authority(kind):
    conn = _Connection()
    conn.row["target_kind"] = kind
    before = copy.deepcopy(conn.row["policy_json"])
    service = HuntRunService(lambda: _Pool(conn))
    hunt_id = str(conn.hunt_id)
    payload = asyncio.run(service.read_skill(hunt_id, GRAPHQL))
    assert payload["support"] == "partial" and payload["methodology"]
    result = asyncio.run(service.bind_skill(hunt_id, GRAPHQL, reason="Observed GraphQL interface"))
    row = next(row for row in result["skills"] if row["skill_id"] == GRAPHQL)
    assert row["missing_capabilities"] == ["graphql.execute"]
    assert conn.row["policy_json"] == before


def test_service_observations_produce_compact_routing_signals_not_raw_origins():
    signals = _skill_signal_values({"services": [
        {"service_name": "mqtt", "product": "mosquitto", "web_origin": "https://secret.example:8443"},
    ]})
    assert signals == ("mqtt", "mosquitto", "http")
    assert "secret.example" not in str(signals)


def test_fresh_operator_signal_is_not_discarded_by_full_old_context():
    conn = _Connection()
    conn.row["context_pack"]["target"] = {"technologies": [f"old{i}" for i in range(20)],
                                           "frameworks": [f"stale{i}" for i in range(20)]}
    before = copy.deepcopy(conn.row["policy_json"])
    service = HuntRunService(lambda: _Pool(conn))
    result = asyncio.run(service.skill_suggestions(str(conn.hunt_id), signals=["jwt"]))
    assert result["signals_considered"] == 40
    assert result["suggestions"][0]["skill_id"] == JWT
    assert result["methodology_bodies_loaded"] == 0
    assert result["advisory_only"] is True
    assert conn.row["policy_json"] == before


def test_duplicate_signal_case_does_not_spend_context_twice():
    conn = _Connection()
    conn.row["context_pack"]["target"] = {"technologies": ["JWT"]}
    result = asyncio.run(HuntRunService(lambda: _Pool(conn)).skill_suggestions(
        str(conn.hunt_id), signals=["jwt", "JWT"]))
    assert result["signals_considered"] == 1


def test_current_operator_direction_outweighs_an_old_relevant_technology():
    conn = _Connection()  # Retained Cloudflare evidence.
    result = asyncio.run(HuntRunService(lambda: _Pool(conn)).skill_suggestions(
        str(conn.hunt_id), signals=["jwt"]))
    assert result["suggestions"][0]["skill_id"] == JWT


def test_previous_suggestions_are_not_reinterpreted_as_observations():
    signals = _skill_signal_values({"skills": {"target": {"technologies": ["Cloudflare"]}},
                                  "target": {"technologies": ["JWT"]}})
    assert signals == ("JWT",)
