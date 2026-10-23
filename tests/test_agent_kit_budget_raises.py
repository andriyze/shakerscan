"""An agent never raises its own Hunt budget; a person does, by approving the budget.raise request.

Live: told by the Hunt skill to post a budget amendment "when the operator asks", an agent read
its launch instruction as that request and raised its own state-changing ceiling from 20 to 41
while its budget.raise request was still pending. The agent kit (the skills, AGENTS.md, the MCP
server's tool descriptions and instructions, and the hints the engine returns to agents) must never
tell an agent to post a budget amendment or to set ``operator_confirmed``. The route itself stays:
the Hunt page uses it.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# What an agent reads: its skills and repository notes, the MCP server it calls, and the engine's
# own agent-facing hint texts (start warnings, refusal recovery, permission request texts).
AGENT_KIT = (
    "AGENTS.md", "llms.txt", *sorted(str(path.relative_to(ROOT)) for path in (ROOT / "skills").rglob("*.md")),
    "scripts/shakerscan_mcp.py", "api/hunt/start_guidance.py", "api/hunt/permission_admission.py",
    "api/hunt/permission_store.py", "api/hunt/briefing.py", "api/hunt/permission_reasons.py",
)


def _sentences(text: str):
    sentences = []
    for paragraph in re.split(r"\n\s*\n|\n(?=#)", text):
        flat = " ".join(paragraph.split())
        sentences.extend(part for part in re.split(r"(?<=[.!?])\s+(?=[A-Z`*(#])", flat) if part)
    return sentences


def _instructions(relative: str):
    """Sentences that would have an agent post an amendment or confirm one."""
    found = []
    for sentence in _sentences((ROOT / relative).read_text(encoding="utf-8")):
        lowered = sentence.lower()
        posts = "budget-amendments" in sentence and re.search(r"\bpost\b", lowered)
        # A record field that says a text was not confirmed (``"operator_confirmed": False``) is data.
        confirms = re.search(r"operator_confirmed(?![\"']\s*:\s*False)", sentence)
        if (posts or confirms) and "never" not in lowered:
            found.append(sentence)
    return found


@pytest.mark.parametrize("relative", AGENT_KIT)
def test_the_agent_kit_never_tells_an_agent_to_post_a_budget_amendment(relative):
    assert _instructions(relative) == [], relative


def test_the_hunt_skill_says_a_person_raises_a_budget_and_the_agent_names_the_request():
    text = " ".join((ROOT / "skills/hunt/SKILL.md").read_text(encoding="utf-8").split())
    assert "When the operator asks for more budget, use `POST" not in text
    assert "an agent never does" in text
    assert "Never call `POST /hunts/{hunt_id}/budget-amendments`" in text
    assert "shakerscan approve <permission_request_id>" in text
    agents = " ".join((ROOT / "AGENTS.md").read_text(encoding="utf-8").split())
    assert "An operator extends a Hunt via `/hunts/{id}/budget-amendments`" not in agents
    assert "never calls `POST /hunts/{id}/budget-amendments`" in agents


def test_the_check_recognises_an_instruction_to_post_an_amendment(tmp_path, monkeypatch):
    import sys
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)
    (tmp_path / "kit.md").write_text(
        "When the operator asks for more budget, use `POST /hunts/{hunt_id}/budget-amendments` with the "
        "current revision and `operator_confirmed: true`. Never call `POST /hunts/{id}/budget-amendments`.",
        encoding="utf-8")
    assert len(_instructions("kit.md")) == 1
