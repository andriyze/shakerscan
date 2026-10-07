"""The client advertises only what the connected instance serves, and the kit points agents at
routes that answer.

Soak 2026-10-07 (defect 13): against an Enterprise gateway ``shakerscan_public_check`` was listed,
counted by ``doctor`` and described as available, but every call got 403; the agent kit told
agents to read ``GET /openapi.json``, which the gateway also refuses. The adapter now probes the
route with a request the engine rejects before doing any work (415, wrong media type) and lists
the tool only when the instance serves it. Unit fixtures: the HTTP layer is scripted.
"""

from __future__ import annotations

import importlib.util
import io
import re
import sys
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("shakerscan_mcp_routes", ROOT / "scripts" / "shakerscan_mcp.py")
mcp = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mcp
SPEC.loader.exec_module(mcp)


class Opener:
    """Answers the public-check probe with one status and records what was sent."""

    def __init__(self, status):
        self.status = status
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        if isinstance(self.status, BaseException):
            raise self.status
        raise urllib.error.HTTPError(request.full_url, self.status, "x", {}, io.BytesIO(b'{"detail":"x"}'))


class Instance(mcp.ArsenalClient):
    """A catalogue and Hunt contract that list nothing beyond the fixed Arsenal tools."""

    def __init__(self, probe_status):
        super().__init__("http://127.0.0.1:8080")
        self.opener = Opener(probe_status)

    def catalog(self):
        return {tool.command: {"status": "read_only", "risk_tier": "read_only", "method": "GET"} for tool in mcp.TOOLS}

    def hunt_contract(self):
        return {}


@pytest.fixture(autouse=True)
def _no_hunt_tools(monkeypatch):
    monkeypatch.setattr(mcp, "_hunt_tools", lambda contract: ())


@pytest.mark.parametrize(("status", "listed"), [
    (415, True),   # the engine serves the route and refused the probe before any work
    (422, True),
    (403, False),  # an Enterprise gateway that keeps the route closed
    (404, False),  # an engine without the route
    (401, False),
    (405, False),
    (502, False),
    (urllib.error.URLError("refused"), False),
])
def test_public_check_is_listed_only_when_the_instance_serves_it(status, listed):
    instance = Instance(status)
    names = {tool["name"] for tool in instance.list_tools()}
    assert ("shakerscan_public_check" in names) is listed
    (probe,) = instance.opener.requests
    assert (probe.get_method(), probe.full_url) == ("POST", "http://127.0.0.1:8080/public/check")
    # Not JSON and no body: the engine answers 415 before it runs a check.
    assert "json" not in (probe.get_header("Content-type") or "").lower()
    assert not probe.data


def test_initialize_does_not_promise_posture_checks():
    server = mcp.MCPServer(mcp.ArsenalClient("http://127.0.0.1:8080"))
    text = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})["result"]["instructions"]
    assert not text.startswith("Posture checks")
    assert "tools/list" in text


def _paragraphs(path: Path):
    return [block for block in re.split(r"\n\s*\n", path.read_text(encoding="utf-8")) if "openapi.json" in block]


@pytest.mark.parametrize("relative", ["AGENTS.md", "skills/hunt/SKILL.md", "skills/shakerscan/SKILL.md"])
def test_the_agent_kit_says_where_openapi_is_refused(relative):
    for block in _paragraphs(ROOT / relative):
        assert "Enterprise" in block, f"{relative}: tells agents to read /openapi.json unqualified:\n{block}"
