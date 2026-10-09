"""MCP side of Hunt permission requests: the agent waits, and never decides.

* A refused grantable action answers ``outcome: awaiting_permission`` with the request id and the
  server's title, and tells the agent to have the user run ``shakerscan approve`` (D34: the
  reason code reaches the agent on every refusal).
* A capability outside the manifest goes to the server, which says what is missing (D31), instead
  of the adapter's opaque local "Capability is not allowed by this Hunt manifest".
* ``shakerscan_hunt_permission_wait`` long-polls; no MCP tool can approve, deny or revoke.
* Bounds the agent passes to the start tool are sent as ``proposed_allow`` (one pending request
  for the person), never as the person's own ``allow``.

Unit fixtures: the HTTP layer is the scripted opener from test_mcp_refusal_reasons.
"""
from __future__ import annotations

import json

import pytest

from tests.test_mcp_refusal_reasons import HUNT, HUNT_RECORD, _client, mcp

REQUEST = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
PARKED = {"detail": {
    "code": "permission_required", "error": "budget_exhausted:http_requests", "reason_code": "budget_exhausted",
    "message": "The Hunt's max_http_requests limit (500) does not cover this action.",
    "action_id": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    "permission_request": {"id": REQUEST, "kind": "budget.raise", "status": "pending",
                           "title": "Raise max_http_requests for this Hunt", "expires_at": "2026-10-09T00:00:00Z"},
}}


def _capability(client, name="web.crawl"):
    return client.call_tool("shakerscan_hunt_capability", {
        "hunt_id": HUNT, "capability_name": name, "input": {}, "idempotency_key": "key-permission-1",
    })


def test_a_parked_action_answers_awaiting_permission_with_the_request_and_server_text():
    client = _client({("GET", f"/hunts/{HUNT}"): HUNT_RECORD,
                      ("POST", f"/hunts/{HUNT}/capabilities/web.crawl"): (409, PARKED)})
    with pytest.raises(mcp.MCPError) as waiting:
        _capability(client)
    data = waiting.value.data
    assert data["outcome"] == "awaiting_permission"
    assert data["permission_request_id"] == REQUEST and data["reason_code"] == "budget_exhausted"
    assert data["mcp_idempotency_key"] == "key-permission-1"
    message = waiting.value.message
    assert f"shakerscan approve {REQUEST}" in message and "Raise max_http_requests for this Hunt" in message
    assert "same idempotency key" in message and "shakerscan_hunt_permission_wait" in message


def test_a_refusal_keeps_its_reason_code_for_the_agent():
    body = {"detail": {"error": "hunt_credential_refused", "reason_code": "credential_not_attached",
                       "message": "The credential selected for this slot is no longer attached.",
                       "slot": "primary"}}
    client = _client({("GET", f"/hunts/{HUNT}"): HUNT_RECORD,
                      ("POST", f"/hunts/{HUNT}/capabilities/web.crawl"): (403, body)})
    with pytest.raises(mcp.MCPError) as refused:
        _capability(client)
    assert refused.value.data["outcome"] == "refused"
    assert refused.value.data["reason_code"] == "credential_not_attached"
    assert refused.value.data["slot"] == "primary"


def test_a_capability_outside_the_manifest_is_answered_by_the_server_not_the_adapter():
    body = {"detail": {"error": "capability_requires_active_testing", "reason_code": "capability_requires_active_testing",
                       "message": "xss.verify needs active testing, which this Hunt was started without."}}
    client = _client({("GET", f"/hunts/{HUNT}"): HUNT_RECORD,
                      ("POST", f"/hunts/{HUNT}/capabilities/xss.verify"): (403, body)})
    with pytest.raises(mcp.MCPError) as refused:
        _capability(client, "xss.verify")
    assert "not allowed by this Hunt manifest" not in refused.value.message
    assert refused.value.data["reason_code"] == "capability_requires_active_testing"
    assert ("POST", f"/hunts/{HUNT}/capabilities/xss.verify") in client.opener.seen


def test_the_wait_tool_long_polls_and_reports_the_decision():
    path = f"/hunts/{HUNT}/permission-requests/{REQUEST}"
    pending = {"id": REQUEST, "status": "pending", "title": "Raise max_http_requests for this Hunt"}
    client = _client({("GET", f"{path}?wait_seconds=2"): pending,
                      ("GET", f"{path}?wait_seconds=1"): {**pending, "status": "granted"}})
    result = client.call_tool("shakerscan_hunt_permission_wait", {
        "hunt_id": HUNT, "request_id": REQUEST, "wait_seconds": 2,
    })["structuredContent"]
    assert result["outcome"] == "granted"
    assert "same idempotency_key" in result["next"]


def test_the_wait_tool_never_floods_an_engine_that_answers_at_once():
    """L1: an answer that comes back before its hold is followed by a pause, never by a burst of
    wait_seconds=0 reads (the CLI's wait sent 79-86 of them in its last second)."""
    path = f"/hunts/{HUNT}/permission-requests/{REQUEST}"
    pending = {"id": REQUEST, "status": "pending", "title": "Raise max_http_requests for this Hunt"}
    client = _client({("GET", f"{path}?wait_seconds={seconds}"): pending for seconds in range(0, 5)})
    result = client.call_tool("shakerscan_hunt_permission_wait", {
        "hunt_id": HUNT, "request_id": REQUEST, "wait_seconds": 3,
    })["structuredContent"]
    reads = [seen for seen in client.opener.seen if seen[1].startswith(f"{path}?")]
    assert result["outcome"] == "still_pending"
    holds = [int(path_.rsplit("=", 1)[1]) for _method, path_ in reads]
    assert holds[0] == 3 and 0 not in holds and len(holds) <= 3, holds


def test_no_mcp_tool_can_decide_or_revoke_a_permission():
    for tool in mcp.HUNT_TOOLS:
        assert "/decision" not in tool.path_template and "/revoke" not in tool.path_template, tool.name
        assert not ("permission" in tool.name and tool.method != "GET"), tool.name
    wait = mcp.HUNT_TOOL_BY_NAME["shakerscan_hunt_permission_wait"]
    assert wait.method == "GET" and wait.read_only


def test_start_bounds_from_the_agent_are_a_proposal_for_the_person():
    contract = {
        "schema_version": "hunt-start/v2", "target_kinds": ["web"], "policy_fields": ["active_testing"],
        "credential_ref_fields": [], "budget_profiles": {"fast": {"max_http_requests": 500}},
        "budget_dimensions": [{"name": "max_http_requests", "minimum": 1}], "limits": {"allow": 32},
        "allow_bounds": {"grammar": ["budget.raise:<N>x"]},
    }
    tool = mcp._hunt_start_tool(contract)
    assert "allow" in tool.properties and "approve" in tool.properties["allow"]["description"]
    sent = []

    class Client(mcp.ArsenalClient):
        def hunt_contract(self):
            return contract

        def request_json(self, method, path, payload=None):
            sent.append((method, path, payload))
            return {"hunt_id": HUNT, "status": "active", "capabilities": []}

    Client("http://127.0.0.1:8080").call_tool("shakerscan_hunt_start", {
        "schema_version": "hunt-start/v2", "target_id": "t1", "target_kind": "web", "goal": "g",
        "budget_profile": "fast", "policy": {}, "allow": ["budget.raise:2x"],
    })
    (_method, path, payload), = sent
    assert path == "/hunts" and payload["proposed_allow"] == ["budget.raise:2x"] and "allow" not in payload
    json.dumps(payload)
