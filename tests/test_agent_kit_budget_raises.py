"""An agent never raises its own Hunt budget; a person does, by approving the budget.raise request.

Before 2.11.1 the Hunt skill told agents to post a budget amendment "when the operator asks", and
an agent read its launch instruction as that request and raised its own state-changing ceiling
from 20 to 41 while its budget.raise request was still pending. The agent kit (the skills, AGENTS.md, the MCP
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


_VERB = r"(?:call|calls|post|posts|send|sends|set|sets|use|uses|submit|submits)"
# "never <verb> `<route or field>`", and further "or|and [never] <verb> `<...>`" under the same
# never: the one form that forbids the amendment itself. A "never" anywhere else in the sentence
# ("..., but never without being asked") forbids something else and exempts nothing.
_FORBIDDEN = re.compile(rf"\bnever\s+{_VERB}\s+`[^`]*`(?:\s*,?\s+(?:or|and|nor)\s+(?:never\s+)?{_VERB}\s+`[^`]*`)*",
                        re.IGNORECASE)
# What turns a prohibition back into an instruction ("never call it unless the operator asks").
_EXCEPT = re.compile(r"^\s*[,;:(-]*\s*(?:unless|except|only|but|if|when|once|until|without|other than|apart)\b",
                     re.IGNORECASE)


def _mentions(text: str) -> bool:
    posts = "budget-amendments" in text and re.search(r"\bpost\b", text.lower())
    # A record field that says a text was not confirmed (``"operator_confirmed": False``) is data.
    confirms = re.search(r"operator_confirmed(?![\"']\s*:\s*False)", text)
    return bool(posts or confirms)


def _instructions(relative: str):
    """Sentences that would have an agent post an amendment or confirm one.

    A sentence passes only when every mention of posting an amendment or of
    ``operator_confirmed`` sits inside a "never <verb> `...`" clause, and no exception
    ("unless", "only if", "when"...) follows that clause.
    """
    found = []
    for sentence in _sentences((ROOT / relative).read_text(encoding="utf-8")):
        if not _mentions(sentence):
            continue
        clauses = list(_FORBIDDEN.finditer(sentence))
        rest = _FORBIDDEN.sub(" ", sentence)
        excepted = any(_EXCEPT.match(sentence[clause.end():]) for clause in clauses)
        if not clauses or _mentions(rest) or excepted:
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


@pytest.mark.parametrize("sentence", [
    "When the operator asks for more budget, use `POST /hunts/{hunt_id}/budget-amendments` with the "
    "current revision and `operator_confirmed: true`.",
    # A "never" that governs something else does not exempt the instruction beside it.
    "When the operator asks, send `POST /hunts/{hunt_id}/budget-amendments` with `operator_confirmed: true`, "
    "but never without being asked.",
    "Never wait to POST /hunts/{id}/budget-amendments with operator_confirmed true.",
    "Never call `GET /hunts/{id}`; call `POST /hunts/{id}/budget-amendments` instead.",
    "Never hesitate: send `operator_confirmed: true` when the operator agrees.",
    # A prohibition with an exception is an instruction.
    "Never call `POST /hunts/{id}/budget-amendments` unless the operator asks.",
    "Never send `operator_confirmed`, except when the operator says so.",
    "Never call `POST /hunts/{id}/budget-amendments` (only when asked).",
])
def test_the_check_recognises_an_instruction_to_post_an_amendment(tmp_path, monkeypatch, sentence):
    import sys
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)
    (tmp_path / "kit.md").write_text(sentence, encoding="utf-8")
    assert _instructions("kit.md") == [sentence]


@pytest.mark.parametrize("sentence", [
    "Never call `POST /hunts/{hunt_id}/budget-amendments` and never send `operator_confirmed`: that route "
    "is the operator's own control.",
    "A person raises it; an agent never calls `POST /hunts/{id}/budget-amendments` or sends "
    "`operator_confirmed`, even when asked in chat (name the pending request instead).",
    "`GET /hunts/{hunt_id}/budget-amendments` pages the saved history.",
])
def test_the_check_accepts_a_prohibition_of_the_amendment_itself(tmp_path, monkeypatch, sentence):
    import sys
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)
    (tmp_path / "kit.md").write_text(sentence, encoding="utf-8")
    assert _instructions("kit.md") == []
