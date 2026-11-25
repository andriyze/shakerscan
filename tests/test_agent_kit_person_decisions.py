"""The agent kit never tells an agent to make a person's decision itself.

Every API call in AGENTS.md, .claude/commands and skills that records a person's decision
(scripts/person_decision_routes.py) must be one the kit hands to the person: the lines just above
it say the person (or a named human reviewer or release manager) runs it.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, "scripts")
import person_decision_routes as routes  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
KIT = [ROOT / "AGENTS.md", *sorted((ROOT / ".claude").rglob("*.md")), *sorted((ROOT / "skills").rglob("*.md"))]
METHOD = r"(GET|POST|PUT|PATCH|DELETE)"
CALLS = (
    # shakerscan api [--option value] METHOD PATH ['BODY']
    re.compile(r"shakerscan api(?: --[a-z-]+(?: \S+)?)* " + METHOD + r" \"?([^\s\"']+)\"?(?: '([^']*)')?"),
    # curl ... -X METHOD "$API_BASE/path" (either order of -X and the URL on one line)
    re.compile(r"curl\b[^\n]*?-X " + METHOD + r"[^\n]*?\"?\$\{?API_[A-Z]+\}?([^\s\"']+)"),
    # ```http blocks: METHOD /path
    re.compile(r"^" + METHOD + r" (/\S*)$"),
)
HANDED_OVER = re.compile(r"\b(person|reviewer|release manager)\b[^\n]*\bruns?\b", re.IGNORECASE)


def kit_calls():
    for path in KIT:
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines):
            for pattern in CALLS:
                for found in pattern.finditer(line.strip()):
                    method, route = found.group(1), found.group(2)
                    body = found.group(3) if pattern.groups >= 3 else None
                    yield path.relative_to(ROOT), number, lines, method, route, body


def test_the_kit_hands_every_person_decision_to_the_person():
    offenders = []
    checked = 0
    for where, number, lines, method, route, body in kit_calls():
        checked += 1
        if routes.match(method, route, body) is None:
            continue
        context = "\n".join(lines[max(0, number - 5):number + 1])
        if not HANDED_OVER.search(context):
            offenders.append(f"{where}:{number + 1}: {method} {route}")
    assert checked > 50
    assert offenders == []


def test_the_kit_never_has_the_agent_sign_in_the_persons_name():
    for path in KIT:
        text = path.read_text(encoding="utf-8")
        assert "Use the user's name in `approved_by`" not in text, path
        assert '"approved_by":"{user name}"' not in text, path
