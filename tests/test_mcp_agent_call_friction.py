"""Hunt calls an agent got wrong and could not recover from, because the adapter refused them
without saying how to succeed.

An evaluation round of the Hunt over MCP showed three repeated refusals:

- capability calls with short caller keys ("ws-ch0", "login-a") refused for the server's 8-character
  minimum before they ran (nine calls in one round);
- ``Unknown input.conditions fields: path, principal`` on knowledge.record, which named what was wrong
  but not what is accepted, so three Hunts gave up recording a negative result;
- ``HTTP 422: invalid_workflow`` from a candidate verification, with the workflow's actual violation
  dropped from the message the agent reads.

Unit fixtures: the HTTP layer is scripted, not a live instance.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("shakerscan_mcp_friction", ROOT / "scripts" / "shakerscan_mcp.py")
mcp = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mcp
SPEC.loader.exec_module(mcp)

HUNT = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
CONDITIONS_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {"method": {"type": "string"}, "route": {"type": "string"}, "as_principal": {"type": "string"}},
}
CAPABILITIES = [
    {"name": "http.request", "input_schema": {"type": "object"}},
    {"name": "knowledge.record", "input_schema": {
        "type": "object", "additionalProperties": False, "required": ["kind", "title"],
        "properties": {"kind": {"type": "string"}, "title": {"type": "string"}, "conditions": CONDITIONS_SCHEMA},
    }},
]


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Engine:
    def __init__(self):
        self.posts = []

    def open(self, request, timeout):
        path = request.full_url.removeprefix("http://127.0.0.1:8080")
        if request.get_method() == "GET":
            assert path == f"/hunts/{HUNT}"
            return Response(json.dumps({"hunt_id": HUNT, "status": "active", "capabilities": CAPABILITIES}).encode())
        self.posts.append((path, json.loads(request.data)))
        return Response(json.dumps({"hunt_id": HUNT, "action_id": "a-1", "action_result": {"status": "success"}}).encode())


def _client(engine):
    client = mcp.ArsenalClient("http://127.0.0.1:8080", poll_seconds=0.01)
    client.opener = engine
    return client


def _call(client, key, capability="http.request", payload=None):
    arguments = {"hunt_id": HUNT, "capability_name": capability, "input": payload or {"method": "GET", "path": "/"}}
    if key is not None:
        arguments["idempotency_key"] = key
    return client.call_tool("shakerscan_hunt_capability", arguments)


def test_a_short_caller_key_runs_and_always_reaches_the_server_as_the_same_key():
    engine = Engine()
    client = _client(engine)
    first = _call(client, "ws-ch0")
    again = _call(client, "ws-ch0")
    assert first["isError"] is False
    sent = [body["idempotency_key"] for _path, body in engine.posts]
    assert sent == ["mcp-key-ws-ch0", "mcp-key-ws-ch0"]
    assert len(sent[0]) >= mcp.SERVER_IDEMPOTENCY_MIN_LENGTH
    # The key the answer returns, sent back, is the same server key (a retry never forks).
    returned = first["structuredContent"]["mcp_idempotency_key"]
    _call(client, returned)
    assert engine.posts[-1][1]["idempotency_key"] == "mcp-key-ws-ch0"
    assert again["isError"] is False


def test_a_long_enough_key_is_sent_unchanged_and_the_pattern_still_applies():
    engine = Engine()
    client = _client(engine)
    _call(client, "agent-key-0001")
    assert engine.posts[0][1]["idempotency_key"] == "agent-key-0001"
    with pytest.raises(mcp.MCPError, match="idempotency_key has an invalid value"):
        _call(client, "-bad")
    assert mcp.server_idempotency_key(mcp.server_idempotency_key("k")) == mcp.server_idempotency_key("k")


def test_the_start_key_accepts_short_keys():
    assert mcp.START_IDEMPOTENCY_KEY_PROPERTY["minLength"] == 1
    assert mcp.server_idempotency_key("s1") == "mcp-key-s1"


def test_unknown_nested_fields_name_the_accepted_fields():
    engine = Engine()
    with pytest.raises(mcp.MCPError) as raised:
        _call(_client(engine), "neg-result-0001", "knowledge.record",
              {"kind": "negative_result", "title": "t", "conditions": {"path": "/x", "principal": "anonymous"}})
    message = raised.value.message
    assert "Unknown input.conditions fields: path, principal" in message
    assert "input.conditions accepts: as_principal, method, route" in message
    assert engine.posts == []


def test_an_invalid_workflow_refusal_carries_its_violation():
    body = json.dumps({"detail": {"error": "invalid_workflow", "target_traffic_sent": False,
                                  "violation": "step 1 route must be a path on the target origin"}})
    assert mcp._refusal_reason(body) == "invalid_workflow: step 1 route must be a path on the target origin"
    # A refusal with its own message keeps it.
    coded = json.dumps({"detail": {"error": "invalid_workflow", "message": "No credential fills user1",
                                   "violation": "x", "code": "hunt_credential_refused"}})
    assert mcp._refusal_reason(coded) == "No credential fills user1 (hunt_credential_refused)"
    assert mcp._refusal_reason(json.dumps({"detail": {"error": "invalid_workflow"}})) == "invalid_workflow"


def test_an_earlier_hunts_action_is_refused_with_how_to_cite_evidence_instead():
    import asyncio
    spec = importlib.util.spec_from_file_location("candidate_evidence_friction", ROOT / "api" / "hunt" / "candidate_evidence.py")
    evidence = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(evidence)
    CandidateEvidenceError, resolve_candidate_evidence = evidence.CandidateEvidenceError, evidence.resolve_candidate_evidence

    class NoRows:
        async def fetch(self, *_args):
            return []   # the action belongs to another Hunt: nothing of this Hunt matches

    run = {"id": HUNT, "target_id": "dddddddd-dddd-4ddd-8ddd-dddddddddddd"}
    with pytest.raises(CandidateEvidenceError) as raised:
        asyncio.run(resolve_candidate_evidence(
            NoRows(), run=run, references=["70ed7ea1-3ba4-5eb2-9393-804fc7872a1d"]))
    assert "repeat that request in this Hunt and cite the new action" in str(raised.value)
    assert raised.value.references == ["70ed7ea1-3ba4-5eb2-9393-804fc7872a1d"]
