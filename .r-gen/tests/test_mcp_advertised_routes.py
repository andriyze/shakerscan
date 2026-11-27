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
import json
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


ENGINE_415 = {"error": {"code": "unsupported_media_type", "message": "Use application/json encoded as UTF-8."}}


class Page(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Opener:
    """Answers the public-check probe with one status and body and records what was sent."""

    def __init__(self, status, body=None):
        self.status = status
        self.body = {"detail": "x"} if body is None else body
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        if isinstance(self.status, BaseException):
            raise self.status
        if self.status == 200:
            return Page(b"<html>sign in</html>")
        raise urllib.error.HTTPError(request.full_url, self.status, "x", {"Location": "/sso"},
                                     io.BytesIO(json.dumps(self.body).encode()))


class Instance(mcp.ArsenalClient):
    """A catalogue and Hunt contract that list nothing beyond the fixed Arsenal tools."""

    def __init__(self, probe_status, body=None):
        super().__init__("http://127.0.0.1:8080")
        self.opener = Opener(probe_status, body)

    def catalog(self):
        return {tool.command: {"status": "read_only", "risk_tier": "read_only", "method": "GET"} for tool in mcp.TOOLS}

    def hunt_contract(self):
        return {}


@pytest.fixture(autouse=True)
def _no_hunt_tools(monkeypatch):
    monkeypatch.setattr(mcp, "_hunt_tools", lambda contract: ())


@pytest.mark.parametrize(("status", "body", "listed"), [
    (415, ENGINE_415, True),   # the engine serves the route and refused the probe before any work
    (415, None, False),        # a 415 that is not the engine's own answer
    (422, None, False),
    (400, None, False),        # a gateway or WAF refusing the probe itself
    (429, None, False),        # a gateway's rate limit says nothing about the route
    (302, None, False),        # a redirect, e.g. to a sign-in page
    (307, None, False),
    (200, None, False),        # a soft page answering every path
    (403, None, False),        # an Enterprise gateway that keeps the route closed
    (404, None, False),        # an engine without the route
    (401, None, False),
    (405, None, False),
    (502, None, False),
    (503, {"error": {"code": "service_unavailable", "message": "not installed"}}, False),  # no engine
    (urllib.error.URLError("refused"), None, False),
])
def test_public_check_is_listed_only_when_the_instance_serves_it(status, body, listed):
    instance = Instance(status, body)
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
