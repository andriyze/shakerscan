"""The MCP tool and the Hunt CLI offer exactly the query kinds the engine accepts.

``POST /hunts/{id}/query`` accepts ``endpoint_groups`` (the grouped route frontier) and
``service_intelligence``, but neither client listed them: the MCP adapter rejected both before
they reached the server and ``shakerscan hunt query`` refused them, while the client docs said
"all query kinds". Both sets are now pinned to the server's in each direction, so a kind added to
or removed from the engine fails here until the clients follow.
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("shakerscan_mcp_query_kinds", ROOT / "scripts" / "shakerscan_mcp.py")
mcp = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mcp
SPEC.loader.exec_module(mcp)
sys.path.insert(0, str(ROOT / "scripts"))
import v2_cli  # noqa: E402


def _server_kinds() -> set[str]:
    source = (ROOT / "api" / "hunt" / "interaction_router.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ClassDef) and node.name == "HuntQueryRequest":
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and getattr(stmt.target, "id", "") == "kind":
                    return {
                        element.value for element in stmt.annotation.slice.elts
                        if isinstance(element, ast.Constant) and isinstance(element.value, str)
                    }
    raise AssertionError("HuntQueryRequest.kind must declare its accepted values")


def _cli_kinds() -> set[str]:
    def subparser(parser: argparse.ArgumentParser, name: str) -> argparse.ArgumentParser:
        action = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
        return action.choices[name]

    query = subparser(subparser(v2_cli.build_parser(), "hunt"), "query")
    (kind,) = [action for action in query._actions if action.dest == "kind"]
    return set(kind.choices)


def test_the_server_still_declares_the_kinds_this_pin_was_written_for():
    assert {"endpoint_groups", "service_intelligence", "hypotheses", "graph_edges"} <= _server_kinds()


def test_the_mcp_query_tool_offers_exactly_the_server_kinds():
    enum = mcp.HUNT_TOOL_BY_NAME["shakerscan_hunt_query"].properties["kind"]["enum"]
    assert len(enum) == len(set(enum))
    assert set(enum) == _server_kinds()


def test_the_hunt_cli_offers_exactly_the_server_kinds():
    assert _cli_kinds() == _server_kinds()
