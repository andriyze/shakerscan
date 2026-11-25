"""tools/list describes every tool and every argument, and marks remote command execution.

Read against the engine's own Arsenal catalogue and Hunt start contract, as an agent's MCP host
receives them.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location("shakerscan_mcp_descriptions", ROOT / "scripts" / "shakerscan_mcp.py")
mcp = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mcp
SPEC.loader.exec_module(mcp)

from api.command_arsenal import describe_commands  # noqa: E402
from api.hunt.start_contract import hunt_start_public_contract  # noqa: E402


class EngineContracts(mcp.ArsenalClient):
    def __init__(self, *, drift=None):
        super().__init__("http://127.0.0.1:8080")
        self.drift = drift

    def request_json(self, method, path, payload=None):
        if path.startswith("/arsenal/commands"):
            catalog = json.loads(json.dumps(describe_commands(), default=str))
            for command in catalog["commands"]:
                if command.get("name") == self.drift:
                    command["risk_tier"] = "credential"
            return catalog
        if path.startswith("/hunts/contract"):
            return json.loads(json.dumps(hunt_start_public_contract(), default=str))
        raise AssertionError(path)

    def serves_route(self, method, path):
        return True


@pytest.fixture(scope="module")
def tools():
    return {tool["name"]: tool for tool in EngineContracts().list_tools()}


def test_every_argument_of_every_tool_is_described(tools):
    missing = {
        name: [key for key, schema in tool["inputSchema"].get("properties", {}).items()
               if not str(schema.get("description") or "").strip()]
        for name, tool in tools.items()
    }
    assert {name: keys for name, keys in missing.items() if keys} == {}


def test_finish_and_cancel_say_what_they_do(tools):
    finish = tools["shakerscan_hunt_finish"]["description"]
    cancel = tools["shakerscan_hunt_cancel"]["description"]
    assert "debrief" in finish and "in_flight_actions" in finish and "409" in finish
    assert "cancelled_scan_ids" in cancel and "shakerscan_hunt_finish" in cancel
    assert len(finish) > 200 and len(cancel) > 200


def test_ssh_exec_is_marked_as_remote_command_execution(tools):
    ssh = tools["shakerscan_hunt_ssh_exec"]
    assert ssh["annotations"]["destructiveHint"] is True
    assert ssh["annotations"]["openWorldHint"] is True
    assert ssh["annotations"]["readOnlyHint"] is False
    assert "remote command execution" in ssh["description"]


def test_one_drifted_arsenal_command_drops_only_its_tool(capsys):
    names = {tool["name"] for tool in EngineContracts(drift="asm.gaps").list_tools()}
    assert "shakerscan_asm_gaps" not in names and "shakerscan_targets" in names
    assert "shakerscan_asm_gaps left out of tools/list" in capsys.readouterr().err


def test_the_mcp_guide_lists_every_tool(tools):
    guide = (ROOT / "docs" / "mcp.md").read_text(encoding="utf-8")
    assert [name for name in tools if f"`{name}`" not in guide] == []
    assert "arbitrary shell is never exposed" not in guide
