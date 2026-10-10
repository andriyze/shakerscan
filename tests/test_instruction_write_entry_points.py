"""Every path that can write a target's instructions or saved actions, inventoried.

Static checks over the source: an agent reaches a write only through the Hunt capability route,
where instruction_changes gates it (tests/test_saved_action_proposals_postgres.py and
tests/test_instruction_proposals_postgres.py exercise those paths against PostgreSQL). A new caller
of a write function, a new MCP route or an unreserved generic metadata key fails here until it is
reviewed and added to the inventory.
"""
from __future__ import annotations

import ast
from pathlib import Path
import re
import sys

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import shakerscan_mcp  # noqa: E402

WRITERS = ("write_target_skill", "write_target_action", "confirm_unconfirmed_instructions")
# Every call site of a write function, with who reaches it.
EXPECTED_CALLERS = {
    ("api/targets/skill.py", "create_target_skill"): "operator route POST /targets/{id}/skill",
    ("api/targets/skill.py", "update_target_skill"): "operator route PUT /targets/{id}/skill",
    ("api/targets/skill.py", "delete_target_skill"): "operator route DELETE /targets/{id}/skill",
    ("api/targets/skill.py", "confirm_unconfirmed_instructions"): "operator confirm (same text, digest-bound)",
    ("api/targets/skill.py", "confirm_target_skill"): "operator route POST /targets/{id}/skill/confirm",
    ("api/targets/actions.py", "create_target_action"): "operator route POST /targets/{id}/actions",
    ("api/targets/actions.py", "update_target_action"): "operator route PUT /targets/{id}/actions/{action}",
    ("api/targets/actions.py", "delete_target_action"): "operator route DELETE /targets/{id}/actions/{action}",
    ("api/targets/instruction_proposals.py", "accept_proposal"): "operator accept of an instruction proposal",
    ("api/targets/instruction_proposals.py", "_accept_action"): "operator accept of a saved-action proposal",
    ("api/hunt/asset_actions.py", "_perform_asset_action"): "Hunt capability, gated by instruction_changes",
}


def _callers() -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for path in sorted((ROOT / "api").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for function in ast.walk(tree):
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(function):
                if isinstance(node, ast.Call):
                    name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
                    if name in WRITERS and function.name != name:
                        found.add((str(path.relative_to(ROOT)), function.name))
    return found


def test_every_instruction_and_saved_action_write_path_is_inventoried():
    assert _callers() == set(EXPECTED_CALLERS)


def test_the_hunt_path_calls_the_saved_action_write_only_with_the_checked_delegation():
    source = (ROOT / "api/hunt/asset_actions.py").read_text(encoding="utf-8")
    branch = source[source.index("if name.startswith('targets.actions.')"):source.index("if name.startswith('targets.skill.')")]
    assert "require_hunt_delegation(conn, run, name, values)" in branch
    assert "delegation=delegation" in branch and "source=f\"hunt:{run['id']}\"" in branch
    # Only the specific instruction refusal becomes a proposal; every other refusal propagates.
    assert "detail.get('reason_code') != 'instruction_changes_not_delegated'" in branch and "raise" in branch


def test_mcp_exposes_no_direct_route_to_instructions_saved_actions_or_their_review():
    """Agents connected over MCP reach target writes only through the Hunt capability route."""
    pattern = re.compile(r"/targets/|instruction-proposals|hunt-authority|/skill/confirm")
    for tool in shakerscan_mcp.HUNT_TOOLS:
        assert not pattern.search(tool.path_template), tool.name
    source = (ROOT / "scripts/shakerscan_mcp.py").read_text(encoding="utf-8")
    assert "instruction-proposals" not in source and "/skill/confirm" not in source
    capability = next(tool for tool in shakerscan_mcp.HUNT_TOOLS if tool.name == "shakerscan_hunt_capability")
    assert capability.path_template == "/hunts/{hunt_id}/capabilities/{capability_name}"


def test_the_runtime_cli_decides_proposals_only_after_a_keypress():
    source = (ROOT / "scripts/v2_cli.py").read_text(encoding="utf-8")
    review = source[source.index("def _run_knowledge_review"):]
    assert "terminal.require(" in review and "with terminal.keypresses()" in review
    for function in ("_review_one", "_review_unconfirmed"):
        body = source[source.index(f"def {function}"):]
        body = body[:body.index("\ndef ", 1)]
        assert "terminal.key(" in body
        posts = [match.start() for match in re.finditer(r'send\("POST"|_decide_proposal\(', body)]
        assert posts and body.index("terminal.key(") < min(posts)


@pytest.mark.parametrize("key", ["target_skill", "hunt_actions", "hunt_authority"])
def test_generic_metadata_writes_cannot_carry_instructions_actions_or_permissions(key):
    sys.path.insert(0, str(ROOT / "api"))
    from targets.router import TargetUpdate
    from devices.router import DeviceTargetCreate, DeviceTargetUpdate
    with pytest.raises(ValidationError):
        TargetUpdate(metadata_json={key: {}})
    with pytest.raises(ValidationError):
        DeviceTargetUpdate(metadata_json={key: {}})
    with pytest.raises(ValidationError):
        DeviceTargetCreate(name="d", primary_locator="d.example.test", metadata_json={key: {}})
