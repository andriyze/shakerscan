"""The MCP adapter as a real process: a parked action, the wait, the person's grant, the resume.

``scripts/shakerscan_mcp.py`` runs as the agent's MCP server does (JSON-RPC lines on stdin and
stdout) against a stub instance (``tests/hunt_permission_stub.py``, a unit fixture: real HTTP,
scripted routes). The grant is made the way a person makes it on a local open-source engine:
``shakerscan approve`` in a pseudo-terminal, answering y. The framing tests (D9) use the same
process with no instance at all.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tests.hunt_permission_stub import HUNT, REQUEST, TITLE, StubInstance
from tests.test_hunt_terminal_approval import Session, _environment

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "scripts" / "shakerscan_mcp.py"
KEY = "agent-key-crawl-0001"


class Adapter:
    def __init__(self, url: str) -> None:
        env = {key: value for key, value in os.environ.items() if not key.startswith("SHAKERSCAN_")}
        env.update({"SHAKERSCAN_API_URL": url, "SHAKERSCAN_MCP_ACTION_WAIT_SECONDS": "5"})
        self.proc = subprocess.Popen(
            [sys.executable, str(ADAPTER)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env, cwd=str(ROOT),
        )
        self.next_id = 0

    def call(self, name: str, arguments: dict) -> dict:
        self.next_id += 1
        self.proc.stdin.write((json.dumps({"jsonrpc": "2.0", "id": self.next_id, "method": "tools/call",
                                           "params": {"name": name, "arguments": arguments}}) + "\n").encode())
        self.proc.stdin.flush()
        answer = json.loads(self.proc.stdout.readline())
        assert answer["id"] == self.next_id
        return answer

    def close(self) -> None:
        self.proc.stdin.close()
        assert self.proc.wait(timeout=30) == 0


def _crawl(adapter: Adapter) -> dict:
    return adapter.call("shakerscan_hunt_capability", {
        "hunt_id": HUNT, "capability_name": "web.crawl", "input": {}, "idempotency_key": KEY,
    })


def test_awaiting_permission_then_wait_then_the_persons_grant_then_the_same_key_resumes(tmp_path):
    with StubInstance() as stub:
        adapter = Adapter(stub.url)
        try:
            refused = _crawl(adapter)
            data = refused["error"]["data"]
            assert data["outcome"] == "awaiting_permission"
            assert data["permission_request_id"] == REQUEST and data["mcp_idempotency_key"] == KEY
            assert f"shakerscan approve {REQUEST}" in refused["error"]["message"]

            waiting = adapter.call("shakerscan_hunt_permission_wait",
                                   {"hunt_id": HUNT, "request_id": REQUEST, "wait_seconds": 1})
            assert waiting["result"]["structuredContent"]["outcome"] == "still_pending"
            assert f"shakerscan approve {REQUEST}" in waiting["result"]["structuredContent"]["next"]

            # The person, in their own terminal, on a local engine: a y/N confirmation.
            person = Session(["approve", "--url", stub.url, REQUEST], _environment(tmp_path))
            person.expect(TITLE)
            person.expect("[y/N]")
            person.type("y\n")
            code, out, err = person.finish()
            assert code == 0, (out, err)

            granted = adapter.call("shakerscan_hunt_permission_wait",
                                   {"hunt_id": HUNT, "request_id": REQUEST, "wait_seconds": 5})
            assert granted["result"]["structuredContent"]["outcome"] == "granted"

            resumed = _crawl(adapter)["result"]["structuredContent"]
            assert resumed["action_result"] == {"action_id": stub.request["action_id"], "status": "completed"}
            assert resumed["mcp_idempotency_key"] == KEY
            again = _crawl(adapter)["result"]["structuredContent"]
            assert again["idempotent_replay"] is True, "the same key replays; the action never runs twice"
        finally:
            adapter.close()
    posts = [body for method, path, body in stub.seen if method == "POST" and path.endswith("/capabilities/web.crawl")]
    assert {body["idempotency_key"] for body in posts} == {KEY}
    decisions = [body for method, path, body in stub.seen if path.endswith("/decision")]
    assert [(body["decided_by"], body["decision_via"]) for body in decisions] == [("local-operator", "local_confirm")], (
        "the one decision came from the person's terminal, never from an MCP tool"
    )


def _frames(lines: list[bytes]) -> list[dict]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("SHAKERSCAN_")}
    result = subprocess.run([sys.executable, str(ADAPTER)], input=b"".join(lines), capture_output=True,
                            env=env, cwd=str(ROOT), timeout=60)
    assert result.returncode == 0, result.stderr
    return [json.loads(line) for line in result.stdout.splitlines()]


def test_framing_answers_requests_only_and_refuses_ids_it_cannot_echo():
    """D9: a request without an id gets no answer; an object id is refused; one oversized line,
    one error."""
    ping = {"jsonrpc": "2.0", "method": "ping"}
    frames = _frames([
        json.dumps(ping).encode() + b"\n",                                   # no id: a notification
        json.dumps({**ping, "id": {"nested": 1}}).encode() + b"\n",        # object id
        json.dumps({**ping, "id": [1]}).encode() + b"\n",                  # array id
        b'{"jsonrpc":"2.0","id":9,"method":"ping","pad":"' + b"x" * 300_000 + b'"}\n',  # oversized
        json.dumps({**ping, "id": 7}).encode() + b"\n",
        json.dumps({**ping, "id": "s-1"}).encode() + b"\n",
    ])
    assert [frame.get("id") for frame in frames] == [None, None, None, 7, "s-1"], frames
    assert [frame["error"]["code"] for frame in frames[:3]] == [-32600, -32600, -32700]
    assert "string or an integer" in frames[0]["error"]["message"]
    assert frames[3]["result"] == {} and frames[4]["result"] == {}
