"""A long Hunt capability never outlives the agent's MCP request.

Soak 2026-10-07 (defect 12): ``web.content_discover`` (~60-75 s) and ``ports.discover`` top_1000
(120 s) ran longer than the agent's MCP request timeout (OpenCode and the MCP SDK default to
60 s), so the agent received ``-32001 Request timed out`` while the action kept running and then
had to guess whether to retry. The adapter now (1) sizes the capability request from the
server's own wall time in the Hunt manifest, (2) sends MCP progress while it waits so a client
that resets its timeout on progress keeps waiting, and (3) for a client that sent no progress
token, returns ``outcome: running`` with the idempotency key before a 60 s client timeout, so the
agent collects the result by calling again with the same key and input. Unit fixtures: the HTTP
layer is scripted, not a live instance.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("shakerscan_mcp_long", ROOT / "scripts" / "shakerscan_mcp.py")
mcp = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mcp
SPEC.loader.exec_module(mcp)

HUNT = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
PATH = f"/hunts/{HUNT}/capabilities/web.content_discover"


def _action(status):
    return {"hunt_id": HUNT, "capability": "web.content_discover", "action_id": "act-1",
            "action_result": {"status": status}}


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class SlowEngine:
    """The engine behind the opener: the first POST runs for ``first_seconds``; every POST
    records the timeout the adapter allowed it, and replays answer the current state."""

    def __init__(self, answers, *, first_seconds=0.0, wall=75):
        self.answers = list(answers)
        self.first_seconds = first_seconds
        self.wall = wall
        self.posts = []

    def open(self, request, timeout):
        path = request.full_url.removeprefix("http://127.0.0.1:8080")
        if request.get_method() == "GET":
            assert path == f"/hunts/{HUNT}"
            body = {"hunt_id": HUNT, "status": "active", "capabilities": [{
                "name": "web.content_discover", "input_schema": {"type": "object"},
                "budget_cost": {"http_requests": 220, "tool_wall_seconds": self.wall},
            }]}
            return Response(json.dumps(body).encode())
        assert path == PATH
        self.posts.append((json.loads(request.data), timeout))
        if len(self.posts) == 1 and self.first_seconds:
            time.sleep(self.first_seconds)
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        return Response(json.dumps(answer).encode())


def _client(engine, **kwargs):
    client = mcp.ArsenalClient("http://127.0.0.1:8080", poll_seconds=0.01, **kwargs)
    client.opener = engine
    return client


ARGUMENTS = {"hunt_id": HUNT, "capability_name": "web.content_discover", "input": {}, "idempotency_key": "key-long-1"}


def test_a_client_without_progress_gets_running_and_the_key_before_its_timeout():
    engine = SlowEngine([_action("running")])
    client = _client(engine, call_seconds=0.2)
    started = time.monotonic()
    result = client.call_tool("shakerscan_hunt_capability", dict(ARGUMENTS))
    assert time.monotonic() - started < 2
    assert result["isError"] is False
    structured = result["structuredContent"]
    assert structured["outcome"] == "running"
    assert structured["mcp_idempotency_key"] == "key-long-1"
    assert "same idempotency_key" in structured["continue"]
    assert all(body == {"idempotency_key": "key-long-1", "input": {}} for body, _ in engine.posts)
    # Calling again with the same key collects the settled action; nothing new is started.
    engine.answers = [_action("success")]
    again = client.call_tool("shakerscan_hunt_capability", dict(ARGUMENTS))["structuredContent"]
    assert again["action_result"]["status"] == "success" and "outcome" not in again


def test_the_capability_request_is_sized_from_the_server_wall_time():
    engine = SlowEngine([_action("success")], wall=120)
    server = mcp.MCPServer(_client(engine))
    server.notify = lambda message: None
    server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "shakerscan_hunt_capability", "arguments": dict(ARGUMENTS), "_meta": {"progressToken": "p1"},
    }})
    (_, timeout), = engine.posts
    assert timeout == 120 + mcp.CAPABILITY_TIMEOUT_MARGIN_SECONDS, "not the 20 s default request timeout"


def test_progress_keeps_a_waiting_client_alive_until_the_action_settles(monkeypatch):
    monkeypatch.setattr(mcp, "HEARTBEAT_SECONDS", 0.02)
    engine = SlowEngine([_action("running"), _action("running"), _action("success")], first_seconds=0.2)
    server = mcp.MCPServer(_client(engine, call_seconds=0.05))
    sent = []
    server.notify = sent.append
    response = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
        "name": "shakerscan_hunt_capability", "arguments": dict(ARGUMENTS), "_meta": {"progressToken": "tok"},
    }})
    assert response["result"]["structuredContent"]["action_result"]["status"] == "success"
    beats = [m for m in sent if m.get("method") == "notifications/progress"]
    assert len(beats) >= 2 and all(m["params"]["progressToken"] == "tok" for m in beats)
    assert [m["params"]["progress"] for m in beats] == sorted({m["params"]["progress"] for m in beats})


def test_the_tool_tells_the_agent_how_to_collect_a_running_action():
    description = mcp.HUNT_TOOL_BY_NAME["shakerscan_hunt_capability"].description
    assert "outcome" in description and "running" in description
    assert "same idempotency_key" in description and "never runs it twice" in description


@pytest.mark.parametrize("seconds", ["0", "-5", "nan"])
def test_the_call_bound_stays_below_a_60_second_client_timeout(monkeypatch, seconds):
    client = mcp.ArsenalClient("http://127.0.0.1:8080", call_seconds=float(seconds))
    assert 1.0 <= client.call_seconds <= 55.0
    assert mcp.ArsenalClient("http://127.0.0.1:8080").call_seconds < 60
