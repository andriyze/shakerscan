"""A Hunt capability whose answer is lost is settled by replay, not handed back as "unknown".

The engine runs a Hunt capability synchronously inside its request; a crawl or content
discovery takes minutes. Driving a Hunt from client 0.7.2 against an Enterprise gateway, the MCP
adapter gave up after its 20-second request timeout and the Hunt CLI after the gateway's
30-second one, each reporting an unknown outcome while the engine finished the work; finishing
the Hunt then failed with 409 because the action was still running. The engine answers a replay
of the same key and input with the action's current state and never starts it twice, so both
now replay until the action is final, within a bounded wait.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("shakerscan_mcp_settle", ROOT / "scripts" / "shakerscan_mcp.py")
mcp = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mcp
SPEC.loader.exec_module(mcp)
sys.path.insert(0, str(ROOT / "scripts"))
import v2_cli  # noqa: E402

HUNT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
PATH = f"/hunts/{HUNT}/capabilities/web.crawl"


def _action(status):
    return {"hunt_id": HUNT, "capability": "web.crawl", "action_id": "a1",
            "action_result": {"status": status, "budget_consumed": {}}}


class ScriptedHunt(mcp.ArsenalClient):
    """The Hunt manifest, then scripted answers for each POST of the capability."""

    def __init__(self, answers, *, wait=5.0):
        super().__init__("http://127.0.0.1:8080", action_wait_seconds=wait, poll_seconds=0.01)
        self.answers = list(answers)
        self.posts = []

    def request_json(self, method, path, payload=None):
        if method == "GET" and path == f"/hunts/{HUNT}":
            return {"hunt_id": HUNT, "status": "active",
                    "capabilities": [{"name": "web.crawl", "input_schema": {"type": "object"}}]}
        assert method == "POST" and path == PATH
        self.posts.append(dict(payload))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def _call(client):
    return client.call_tool("shakerscan_hunt_capability", {
        "hunt_id": HUNT, "capability_name": "web.crawl", "input": {}, "idempotency_key": "key-mcp-1",
    })


@pytest.mark.parametrize("lost", [
    mcp.MCPError(-32001, "ShakerScan API is unavailable", "timed out"),
    mcp.MCPError(-32002, "ShakerScan API returned HTTP 502", "engine unavailable"),
    mcp.MCPError(-32002, "ShakerScan API returned HTTP 504", ""),
])
def test_mcp_settles_a_lost_answer_by_replaying_the_same_key(lost):
    client = ScriptedHunt([lost, _action("running"), _action("running"), _action("success")])
    result = _call(client)["structuredContent"]
    assert result["action_result"]["status"] == "success"
    assert len(client.posts) == 4
    assert all(p == {"idempotency_key": "key-mcp-1", "input": {}} for p in client.posts), (
        "a replay must carry the same key and unchanged input, never a new key"
    )


def test_mcp_settles_an_in_flight_first_answer():
    client = ScriptedHunt([_action("running"), _action("success")])
    assert _call(client)["structuredContent"]["action_result"]["status"] == "success"


def test_mcp_never_replays_a_definite_refusal():
    client = ScriptedHunt([mcp.MCPError(
        -32002, "ShakerScan API returned HTTP 409: budget exhausted", '{"detail": "budget exhausted"}',
        http_status=409,
    )])
    with pytest.raises(mcp.MCPError) as refused:
        _call(client)
    assert len(client.posts) == 1
    # A definite answer is reported as one, with its reason, and keeps the recovery identity.
    assert refused.value.data["outcome"] == "refused"
    assert "HTTP 409: budget exhausted" in refused.value.message
    assert refused.value.data["mcp_idempotency_key"] == "key-mcp-1"


def test_mcp_wait_is_bounded_and_keeps_the_recovery_identity():
    client = ScriptedHunt([mcp.MCPError(-32001, "unavailable")] + [_action("running")] * 1000, wait=0.05)
    with pytest.raises(mcp.MCPError) as unsettled:
        _call(client)
    assert unsettled.value.message == "Hunt capability response was not confirmed"
    assert unsettled.value.data["mcp_idempotency_key"] == "key-mcp-1"
    assert "same key" in unsettled.value.data["recovery"]


class ScriptedApi:
    def __init__(self, answers):
        self.answers, self.posts = list(answers), []

    def post(self, path, body):
        assert path == PATH
        self.posts.append(dict(body))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def test_cli_settles_a_gateway_502_and_a_timeout(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_HUNT_ACTION_WAIT_SECONDS", "5")
    api = ScriptedApi([
        v2_cli.CliError("engine unavailable", error_type="api_error", http_status=502),
        v2_cli.CliError("did not answer", error_type="network_error"),
        _action("running"),
        _action("success"),
    ])
    body = {"idempotency_key": "k-1", "input": {}}
    result = v2_cli._settled_capability(api, PATH, body, poll_seconds=0.01)
    assert result["action_result"]["status"] == "success"
    assert api.posts == [body] * 4


def test_cli_never_replays_a_definite_refusal(monkeypatch):
    api = ScriptedApi([v2_cli.CliError("conflict", error_type="api_error", http_status=409)])
    with pytest.raises(v2_cli.CliError):
        v2_cli._settled_capability(api, PATH, {"idempotency_key": "k", "input": {}}, poll_seconds=0.01)
    assert len(api.posts) == 1


def test_cli_read_timeout_is_a_network_error_not_a_traceback(monkeypatch):
    class Opener:
        def open(self, request, timeout):
            raise TimeoutError("timed out")

    monkeypatch.setattr(v2_cli, "_opener", lambda: Opener())
    client = v2_cli.ApiClient("http://127.0.0.1:8080", timeout=1)
    with pytest.raises(v2_cli.CliError) as failed:
        client.post("/hunts", {})
    assert failed.value.error_type == "network_error"
