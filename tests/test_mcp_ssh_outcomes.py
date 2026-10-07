"""An SSH command reported as "refused" provably did not run.

The engine opens the SSH event stream by accepting the action, before anything runs, and reports
any later failure as an ``error`` event, including a 500 after the command ran and its output was
streamed. The adapter used to call every such event "refused", which tells the agent the command
never ran and invites sending it again. Now only an HTTP refusal before the stream opened, or a
refusal for an action the engine never recorded, is "refused"; any other failure is an unknown
outcome that names the action to inspect and never suggests re-sending the command. Unit
fixtures: the HTTP layer is scripted, not a live instance.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import types
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("shakerscan_mcp_ssh_outcomes", ROOT / "scripts" / "shakerscan_mcp.py")
mcp = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mcp
SPEC.loader.exec_module(mcp)
sys.path.insert(0, str(ROOT / "scripts"))

HUNT = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
ACTION = "12345678-1234-4234-8234-123456789abc"
BASE = "http://127.0.0.1:8080"
OUTPUT = f"/hunts/{HUNT}/ssh/actions/{ACTION}/output"


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Stream:
    def __init__(self, events):
        self.lines = []
        for name, value in events:
            self.lines += [f"event: {name}\n".encode(), f"data: {json.dumps(value)}\n".encode(), b"\n"]
        self.headers = types.SimpleNamespace(get_content_type=lambda: "text/event-stream")

    def readline(self, limit):
        return self.lines.pop(0) if self.lines else b""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _http_error(url, status, body):
    return urllib.error.HTTPError(url, status, "x", {}, io.BytesIO(json.dumps(body).encode()))


class Engine:
    """The Hunt manifest, one scripted answer for /ssh/exec and one for the action's output."""

    def __init__(self, exec_answer, output_answer=None):
        self.exec_answer = exec_answer
        self.output_answer = output_answer
        self.seen = []

    def open(self, request, timeout):
        path = request.full_url.removeprefix(BASE)
        self.seen.append((request.get_method(), path))
        if path == f"/hunts/{HUNT}":
            return Response(json.dumps({"hunt_id": HUNT, "status": "active", "capabilities": [
                {"name": "ssh.exec", "input_schema": {"type": "object"}}]}).encode())
        if path == f"/hunts/{HUNT}/ssh/exec":
            if isinstance(self.exec_answer, tuple):
                raise _http_error(request.full_url, *self.exec_answer)
            return Stream(self.exec_answer)
        assert path == OUTPUT, path
        if isinstance(self.output_answer, tuple):
            raise _http_error(request.full_url, *self.output_answer)
        return Response(json.dumps(self.output_answer).encode())


def _run(engine):
    client = mcp.ArsenalClient(BASE)
    client.opener = engine
    with pytest.raises(mcp.MCPError) as failed:
        client.call_tool("shakerscan_hunt_ssh_exec", {
            "hunt_id": HUNT, "input": {"command": "rm -rf /tmp/x"}, "idempotency_key": "key-ssh-0001",
        })
    return failed.value


ACCEPTED = ("accepted", {"hunt_id": HUNT, "action_id": ACTION})
NOT_RECORDED = (404, {"detail": "SSH action not found in this Hunt"})


def test_a_failure_after_the_command_streamed_output_is_unknown_and_never_resent():
    engine = Engine([ACCEPTED, ("output", {"stdout": "removed"}), ("error", {"status_code": 500, "detail": "RuntimeError"})])
    error = _run(engine)
    assert error.data["outcome"] == "unknown" and error.data["action_id"] == ACTION
    assert "refused" not in error.message
    assert ACTION in error.message and "do not send the command again" in error.message
    assert "idempotency_key" not in error.message, "an uncertain command is never re-sent"
    assert engine.seen.count(("POST", f"/hunts/{HUNT}/ssh/exec")) == 1


def test_a_refusal_for_an_action_the_engine_never_recorded_is_refused_with_its_reason():
    reason = "Session is disconnected. Reconnect with ssh.exec without session_id"
    engine = Engine([ACCEPTED, ("error", {"status_code": 409, "detail": reason})], NOT_RECORDED)
    error = _run(engine)
    assert error.data["outcome"] == "refused" and error.data["http_status"] == 409
    assert "did not run" in error.message and "HTTP 409" in error.message and reason in error.message


@pytest.mark.parametrize("output", [
    {"status": "failed", "output_available": False},   # recorded: it may have run
    (404, {"detail": "Not Found"}),                     # a gateway's 404 is not the engine's answer
    (403, {"detail": "route closed"}),
])
def test_a_refusal_after_acceptance_is_unknown_unless_the_engine_says_it_recorded_nothing(output):
    engine = Engine([ACCEPTED, ("error", {"status_code": 409, "detail": "Hunt is cancelled"})], output)
    error = _run(engine)
    assert error.data["outcome"] == "unknown"
    assert "HTTP 409: Hunt is cancelled" in error.message and ACTION in error.message


def test_an_http_refusal_before_the_stream_opened_is_refused():
    error = _run(Engine((422, {"detail": "Invalid SSH capability request"})))
    assert error.data["outcome"] == "refused"
    assert "HTTP 422: Invalid SSH capability request" in error.message


def test_a_retry_later_answer_before_the_stream_names_the_key():
    error = _run(Engine((429, {"detail": "slow down"})))
    assert error.data["outcome"] == "retry_later" and "key-ssh-0001" in error.message


@pytest.mark.parametrize("answer", [
    (502, {"detail": "bad gateway"}),
    [ACCEPTED, ("output", {"stdout": "partial"})],  # the stream ended without a result
])
def test_a_lost_answer_is_unknown(answer):
    error = _run(Engine(answer))
    assert error.data["outcome"] == "unknown"
    assert "do not send the command again" in error.message


def test_the_not_recorded_answer_is_the_engines_own_text():
    source = (ROOT / "api" / "hunt" / "ssh_stream.py").read_text(encoding="utf-8")
    assert f"raise HTTPException(404, '{mcp.SSH_ACTION_NOT_RECORDED}')" in source
