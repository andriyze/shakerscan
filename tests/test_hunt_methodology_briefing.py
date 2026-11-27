"""The briefing names the methodologies the mapped surface calls for (1 skill read in 305 lab Hunts)."""
from __future__ import annotations

from api.hunt import methodology_briefing as mb
from api.hunt.briefing import bound_briefing


def test_mapped_routes_and_inputs_become_signals_a_rare_surface_first():
    rows = [{"path": "/graphql", "param_shape": "", "content_type": "application/json"},
            *[{"path": f"/api/items/{n}", "param_shape": "sort", "content_type": None} for n in range(30)],
            {"path": "/api/fetch", "param_shape": "url&format", "content_type": None},
            {"path": "/upload", "param_shape": "", "content_type": "multipart/form-data"}]
    signals = mb.surface_signals(rows)
    assert signals[:2] == ["sql injection", "file upload"] or "graphql" in signals[:4]
    assert {"graphql", "ssrf", "file upload", "idor", "sql injection"} <= set(signals)


def test_a_graphql_surface_puts_the_graphql_methodology_and_its_steps_in_the_briefing():
    section = mb.build_section(hunt_id="h1", signals=["graphql"], objective="", target_kind="web",
                               allowed_capabilities=None)
    top = section["methodologies"][0]
    assert top["skill_id"] == "skill.web.graphql-security-testing"
    assert any("resolver arguments" in step for step in top["steps"])
    assert top["read"] == "POST /hunts/h1/skills/skill.web.graphql-security-testing/read"
    assert len(section["methodologies"]) <= mb.MAX_SKILLS


def test_the_checklist_is_the_workflow_steps_and_the_evidence_lines():
    body = ("## Agent workflow\n\n### 1. Map it\n\n- x\n\n### 2. Prove it\n\n## Evidence required for a finding\n\n"
            "- the request\n- the control\n\n## Next\n")
    assert mb.checklist(body) == {"steps": ["1. Map it", "2. Prove it"], "evidence": ["the request", "the control"]}


def test_the_methodology_gives_way_first_when_the_briefing_is_too_large():
    briefing = {"methodology": {"methodologies": [
        {"skill_id": "a", "evidence": ["x" * 400] * 4}, {"skill_id": "b", "evidence": ["y" * 400]}]},
        "objective": {"text": "o"}, "trimmed": []}
    small = bound_briefing(briefing, limit=600)
    assert all(not entry.get("evidence") for entry in small["methodology"]["methodologies"])
    assert len(small["methodology"]["methodologies"]) == 2  # the evidence was enough
    long = {"methodology": {"methodologies": [
        {"skill_id": "a", "steps": ["s" * 300] * 2}, {"skill_id": "b", "steps": ["t" * 300] * 2}]},
        "objective": {"text": "o"}, "trimmed": []}
    assert len(bound_briefing(long, limit=900)["methodology"]["methodologies"]) == 1
