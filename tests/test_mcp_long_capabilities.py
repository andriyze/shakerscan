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
    """The engine behind the opener. Like the real one, it answers the first POST only when the
    action is done (``first_seconds`` of work): a request that gives up sooner times out with
    no answer. A replay of the same key answers at once with the action's current state. Every
    POST records the timeout the adapter allowed it."""

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
            if timeout < self.first_seconds:
                time.sleep(timeout)
                raise TimeoutError("timed out")  # the socket read gave up; the action runs on
            time.sleep(self.first_seconds)
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        return Response(json.dumps(answer).encode())


def _client(engine, **kwargs):
    client = mcp.ArsenalClient("http://127.0.0.1:8080", poll_seconds=0.01, **kwargs)
    client.opener = engine
    return client


ARGUMENTS = {"hunt_id": HUNT, "capability_name": "web.content_discover", "input": {}, "idempotency_key": "key-long-1"}


def test_a_client_without_progress_gets_running_and_the_key_before_its_timeout():
    # The first POST blocks for the whole action (5 s here, 60-120 s live), past the call's wait.
    engine = SlowEngine([_action("running")], first_seconds=5.0)
    client = _client(engine, call_seconds=1.0)
    started = time.monotonic()
    result = client.call_tool("shakerscan_hunt_capability", dict(ARGUMENTS))
    assert time.monotonic() - started < 2
    assert result["isError"] is False
    structured = result["structuredContent"]
    assert structured["outcome"] == "running"
    assert structured["mcp_idempotency_key"] == "key-long-1"
    # The key is in the text the agent reads, not only in a field it may never look at.
    assert "idempotency_key key-long-1" in structured["continue"]
    assert "key-long-1" in result["content"][0]["text"]
    # The first POST gave up before the wait did, so a replay could still learn the state.
    assert engine.posts[0][1] < 1.0 and len(engine.posts) >= 2
    assert all(body == {"idempotency_key": "key-long-1", "input": {}} for body, _ in engine.posts)
    # Calling again with the same key collects the settled action; nothing new is started.
    engine.answers = [_action("success")]
    again = client.call_tool("shakerscan_hunt_capability", dict(ARGUMENTS))["structuredContent"]
    assert again["action_result"]["status"] == "success" and "outcome" not in again


def test_the_first_post_leaves_the_default_call_wait_room_for_a_replay():
    # ports.discover top_1000 runs 120 s; the default wait is 45 s for a client without progress.
    engine = SlowEngine([_action("success")], wall=120)
    _client(engine).call_tool("shakerscan_hunt_capability", dict(ARGUMENTS))
    (_, timeout), = engine.posts
    assert timeout == mcp.DEFAULT_CALL_SECONDS - mcp.SETTLE_RESERVE_SECONDS


def test_an_answer_that_never_arrives_names_the_key_in_the_message():
    class Silent(SlowEngine):
        def open(self, request, timeout):
            if request.get_method() == "GET":
                return super().open(request, timeout)
            self.posts.append((json.loads(request.data), timeout))
            raise TimeoutError("timed out")

    client = _client(Silent([_action("running")]), call_seconds=1.0)
    with pytest.raises(mcp.MCPError) as unknown:
        client.call_tool("shakerscan_hunt_capability", dict(ARGUMENTS))
    assert unknown.value.data["outcome"] == "unknown"
    assert "not confirmed" in unknown.value.message and "key-long-1" in unknown.value.message


@pytest.mark.parametrize("wall,expected", [
    (75, 75 + mcp.CAPABILITY_TIMEOUT_MARGIN_SECONDS),
    # A longer action: the request ends a settle reserve before the call's progress hold does.
    (1_200, mcp.DEFAULT_ACTION_WAIT_SECONDS - mcp.SETTLE_RESERVE_SECONDS),
])
def test_the_capability_request_is_sized_from_the_server_wall_time(wall, expected):
    engine = SlowEngine([_action("success")], wall=wall)
    server = mcp.MCPServer(_client(engine))
    server.notify = lambda message: None
    server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "shakerscan_hunt_capability", "arguments": dict(ARGUMENTS), "_meta": {"progressToken": "p1"},
    }})
    (_, timeout), = engine.posts
    assert timeout == expected, "not the 20 s default request timeout"


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


# --- A long verifier never holds the agent's step ---------------------------------------------
#
# A client that sends a progress token was kept in the call (with progress every 10 s) for up to
# 900 s, and OpenCode starts nothing else while a call of its step is open, so a Hunt did nothing
# else while a verifier ran its whole wall. A progress client is now held at most
# DEFAULT_ACTION_WAIT_SECONDS; a longer action answers outcome=running with its key, the agent
# works on, and shakerscan_hunt_get lists what it has not collected yet.

VERIFY = dict(ARGUMENTS, capability_name="sqli.verify", input={"path": "/reports?filter=x"},
              idempotency_key="key-verify-1")
VERIFY_PATH = f"/hunts/{HUNT}/capabilities/sqli.verify"


class VerifierEngine(SlowEngine):
    """A 1,200 s verifier: its first POST would block for the whole run (here first_seconds), a
    replay answers its current state. Every POST that reached the engine is recorded by path."""

    def __init__(self, **kwargs):
        super().__init__([_action("running")], **kwargs)
        self.state = "running"

    def open(self, request, timeout):
        path = request.full_url.removeprefix("http://127.0.0.1:8080")
        if request.get_method() == "GET":
            body = {"hunt_id": HUNT, "status": "active", "capabilities": [
                {"name": "sqli.verify", "input_schema": {"type": "object"},
                 "budget_cost": {"http_requests": 900, "tool_wall_seconds": 300}},
                {"name": "web.probe", "input_schema": {"type": "object"},
                 "budget_cost": {"http_requests": 4, "tool_wall_seconds": 30}},
            ]}
            return Response(json.dumps(body).encode())
        self.posts.append((path, json.loads(request.data), timeout))
        if path.endswith("/web.probe"):
            return Response(json.dumps({**_action("success"), "capability": "web.probe"}).encode())
        if len([p for p in self.posts if p[0] == VERIFY_PATH]) == 1:
            if timeout < self.first_seconds:
                time.sleep(timeout)
                raise TimeoutError("timed out")
        answer = {**_action(self.state), "capability": "sqli.verify", "action_id": "act-verify"}
        return Response(json.dumps(answer).encode())


def _progress_call(server, arguments, request_id):
    return server.handle({"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {
        "name": "shakerscan_hunt_capability", "arguments": dict(arguments),
        "_meta": {"progressToken": f"p{request_id}"},
    }})["result"]["structuredContent"]


def test_a_progress_client_is_answered_running_within_the_hold_and_collects_later(monkeypatch):
    monkeypatch.setattr(mcp, "HEARTBEAT_SECONDS", 0.05)
    engine = VerifierEngine(first_seconds=30.0)
    client = _client(engine, action_wait_seconds=1.0)
    server = mcp.MCPServer(client)
    server.notify = lambda message: None
    started = time.monotonic()
    first = _progress_call(server, VERIFY, 1)
    assert time.monotonic() - started < 2.0, "held past the progress hold"
    assert first["outcome"] == "running" and first["mcp_idempotency_key"] == "key-verify-1"
    assert "idempotency_key key-verify-1" in first["continue"]
    # The agent works on: another capability is answered meanwhile.
    other = _progress_call(server, dict(ARGUMENTS, capability_name="web.probe", input={},
                                        idempotency_key="key-probe-1"), 2)
    assert other["action_result"]["status"] == "success"
    # The Hunt view lists what is still to collect, with what to call it with.
    hunt = server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
        "name": "shakerscan_hunt_get", "arguments": {"hunt_id": HUNT}}})["result"]["structuredContent"]
    assert hunt["mcp_uncollected_actions"] == [{
        "capability_name": "sqli.verify", "idempotency_key": "key-verify-1", "action_id": "act-verify",
        "input": {"path": "/reports?filter=x"},
    }]
    # The verifier finishes; the same key collects it, and nothing is run twice: every POST to
    # the verifier carried the one key and the one input.
    engine.state = "success"
    collected = _progress_call(server, VERIFY, 4)
    assert collected["action_result"]["status"] == "success" and "outcome" not in collected
    bodies = [body for path, body, _ in engine.posts if path == VERIFY_PATH]
    assert bodies and all(body == {"idempotency_key": "key-verify-1", "input": {"path": "/reports?filter=x"}}
                          for body in bodies)
    hunt = server.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
        "name": "shakerscan_hunt_get", "arguments": {"hunt_id": HUNT}}})["result"]["structuredContent"]
    assert "mcp_uncollected_actions" not in hunt


def test_the_default_progress_hold_ends_well_before_a_verifier_wall():
    # sqli.verify holds 1,200 s and xss.verify 480 s; a crawl or content discovery takes 75 s.
    assert 75 + mcp.CAPABILITY_TIMEOUT_MARGIN_SECONDS + mcp.SETTLE_RESERVE_SECONDS <= mcp.DEFAULT_ACTION_WAIT_SECONDS
    assert mcp.DEFAULT_ACTION_WAIT_SECONDS <= 120
    assert mcp.ArsenalClient("http://127.0.0.1:8080").action_wait_seconds == mcp.DEFAULT_ACTION_WAIT_SECONDS


def test_the_uncollected_list_is_bounded_and_keeps_no_large_input():
    client = mcp.ArsenalClient("http://127.0.0.1:8080")
    running = _action("running")
    for index in range(mcp.MAX_UNCOLLECTED_ACTIONS + 5):
        client._note_capability_answer(HUNT, "http.request", {
            "idempotency_key": f"key-{index:04d}", "input": {"path": "/", "pad": "x" * (3_000 if index == 12 else 1)},
        }, running)
    listed = client.uncollected_actions(HUNT)
    assert len(listed) == mcp.MAX_UNCOLLECTED_ACTIONS
    assert listed[0]["idempotency_key"] == "key-0005"  # the oldest are dropped first
    (large,) = [item for item in listed if item["idempotency_key"] == "key-0012"]
    assert "input" not in large and len(large["input_sha256"]) == 64
    client._note_capability_answer(HUNT, "http.request", {"idempotency_key": "key-0010", "input": {}},
                                   _action("success"))
    assert all(item["idempotency_key"] != "key-0010" for item in client.uncollected_actions(HUNT))
    assert client.uncollected_actions("another-hunt") == []


def test_the_tool_says_a_hunt_runs_at_most_two_long_actions():
    description = mcp.HUNT_TOOL_BY_NAME["shakerscan_hunt_capability"].description
    assert "at most two long actions" in description and "long_actions_in_flight" in description
