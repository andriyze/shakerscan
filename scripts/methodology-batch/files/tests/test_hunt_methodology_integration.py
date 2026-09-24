"""Shipped investigation knowledge must use the actual Hunt execution contract."""
from __future__ import annotations

import asyncio
import copy
import hashlib
from pathlib import Path

import pytest

from api.hunt.run_service import HuntRunService
from api.hunt.skills import bind_skills_to_hunt, load_skill_library
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from scripts.check_hunt_methodologies import check
from tests.test_hunt_skill_lifecycle import _Connection, _Pool

ROOT = Path(__file__).resolve().parents[1]
NATIVE = "skill.network.service-protocol-and-device-investigation"


@pytest.fixture(scope="module")
def library():
    return load_skill_library()


def test_shipped_guidance_has_no_missing_references_or_retired_execution_contracts():
    assert check(ROOT) == []


@pytest.mark.parametrize("retired", ["../schemas/action.schema.json", "**Allowed adapters**",
                                     "this skill cannot be bound to a hunt yet"])
def test_integration_check_detects_regressions(tmp_path, retired):
    path = tmp_path / "skills" / "web" / "sample.md"
    path.parent.mkdir(parents=True)
    path.write_text(retired)
    assert any("retired execution instruction" in error for error in check(tmp_path))


def test_integration_check_detects_a_missing_relative_reference(tmp_path):
    path = tmp_path / "skills" / "web" / "sample.md"
    path.parent.mkdir(parents=True)
    path.write_text("[runtime](core/missing.md)")
    assert any("missing local reference" in error for error in check(tmp_path))


def test_every_delivered_body_matches_its_declared_revision_and_real_operations(library):
    assert library.catalog_status == "ready"
    for spec in library.list():
        payload = spec.public(include_body=True)
        body = payload["methodology"]
        assert hashlib.sha256(body.encode()).hexdigest() == payload["body_sha256"]
        for name in (*spec.capabilities, *spec.optional_capabilities):
            capability = CAPABILITY_REGISTRY.require(name)
            assert capability.planner_visible and capability.hunt_executor
        assert "../schemas/" not in body
        assert "this skill cannot be bound" not in body
        if "## ShakerScan execution contract" in body:
            for heading in ("Core security hypotheses", "Agent workflow", "Technique modules",
                            "Focused test matrix", "False-positive controls"):
                assert f"## {heading}" in body, (spec.skill_id, heading)
            assert "coverage gaps" in body
            assert "## Results and handoff" in body


@pytest.mark.parametrize("kind", ["device", "network"])
@pytest.mark.parametrize("signal", ["mqtt", "mosquitto", "ssh", "smb", "snmp", "upnp", "dlna"])
def test_protocol_signals_select_native_methodology_without_inventing_http(library, kind, signal):
    result = library.suggest(goal="Investigate", target_kind=kind, signals=[signal],
                             allowed_capabilities=())
    assert result[0]["skill_id"] == NATIVE
    assert result[0]["auto_bound"] is False
    assert result[0]["execution"]["fully_executable"] is False
    assert result[0]["execution"]["missing_capabilities"] == ["protocol.exchange"]


@pytest.mark.parametrize("kind", ["device", "network"])
def test_protocol_binding_does_not_change_authority_or_budget(library, kind):
    allowed, budget = ("http.request",), object()
    bound = bind_skills_to_hunt([NATIVE], target_kind=kind, allowed_capabilities=allowed,
                               budget=budget, library=library)
    row = bound.context_section["bound"][0]
    assert row["withheld_capabilities"] == ["ports.discover", "service.fingerprint"]
    assert row["missing_capabilities"] == ["protocol.exchange"]
    assert bound.allowed_capabilities is allowed and bound.budget is budget


@pytest.mark.parametrize("kind", ["device", "network"])
def test_priority_signal_alone_can_select_web_interface_methodology(library, kind):
    result = library.suggest(goal="Investigate", target_kind=kind,
                             priority_signals=iter(["graphql"]))
    assert result[0]["skill_id"] == "skill.web.graphql-security-testing"


@pytest.mark.parametrize("kind", ["device", "network"])
def test_protocol_selection_read_bind_and_web_pivot_through_run_service(kind):
    conn = _Connection()
    conn.row["target_kind"] = kind
    conn.row["context_pack"]["target"] = {"services": [{"service_name": "mqtt"}]}
    before = copy.deepcopy(conn.row["policy_json"])
    service = HuntRunService(lambda: _Pool(conn))
    hunt_id = str(conn.hunt_id)
    suggestions = asyncio.run(service.skill_suggestions(hunt_id, signals=["mqtt"]))
    assert suggestions["suggestions"][0]["skill_id"] == NATIVE
    payload = asyncio.run(service.read_skill(hunt_id, NATIVE))
    assert "Protocol hypotheses" in payload["methodology"]
    bound = asyncio.run(service.bind_skill(hunt_id, NATIVE, reason="Observed broker"))
    assert any(row["skill_id"] == NATIVE for row in bound["skills"])
    pivot = asyncio.run(service.skill_suggestions(hunt_id, signals=["graphql"]))
    assert pivot["suggestions"][0]["skill_id"] == "skill.web.graphql-security-testing"
    assert conn.row["policy_json"] == before


def test_installer_downloads_native_methodology_and_current_core_guides():
    from scripts.generate_install_manifest import installer_paths
    paths = installer_paths((ROOT / "install/index.sh").read_text())
    assert "skills/web/32-service-protocol-and-device-investigation.md" in paths
    assert {path.relative_to(ROOT).as_posix() for path in (ROOT / "skills/web/core").glob("*.md")} <= set(paths)
