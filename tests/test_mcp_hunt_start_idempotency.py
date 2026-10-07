"""The MCP Hunt start carries an idempotency key, like REST and the CLI.

Regression for soak defect D8 (2026-10-07): ``shakerscan_hunt_start`` had no idempotency key, so
two identical MCP starts created two Hunts (87c0ddee and ccb0f3a1) while ``POST /hunts`` and
``shakerscan hunt start --idempotency-key`` replay the first. The tool now sends one
``Idempotency-Key`` per start, generated when the caller gives none, and returns it.
"""
from __future__ import annotations

import io
import json
import urllib.error

import pytest

from tests.test_read_only_mcp import _hunt_contract, mcp

START = {
    "schema_version": "hunt-start/v2",
    "target_id": "target-1",
    "target_kind": "web",
    "goal": "Inspect the authorized web target.",
    "budget_profile": "fast",
    "policy": {},
}


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class Opener:
    """Answers the real ``request_json`` transport; records what reached the API."""

    def __init__(self, *, fail_start=None):
        self.starts = []
        self.fail_start = fail_start
        self.hunts = {}
        self.other_keys = []

    def open(self, request, timeout=None):
        path = request.full_url.removeprefix("http://127.0.0.1:8080")
        if path == "/hunts/contract":
            return _Response(json.dumps(_hunt_contract()).encode())
        if path.endswith("/cancel"):
            self.other_keys.append(request.get_header("Idempotency-key"))
            return _Response(json.dumps({"hunt_id": "hunt-1", "status": "cancelled"}).encode())
        assert (request.get_method(), path) == ("POST", "/hunts")
        key = request.get_header("Idempotency-key")
        self.starts.append({"key": key, "body": json.loads(request.data)})
        if self.fail_start is not None:
            raise self.fail_start
        # The server's Idempotency-Key contract: the same key answers the Hunt it started.
        hunt_id = self.hunts.setdefault(key, f"hunt-{len(self.hunts) + 1}")
        return _Response(json.dumps({"hunt_id": hunt_id, "status": "active"}).encode())


def _client(opener):
    client = mcp.ArsenalClient("http://127.0.0.1:8080")
    client.opener = opener
    return client


def test_start_tool_offers_an_idempotency_key():
    tool = mcp._hunt_start_tool(_hunt_contract())
    schema = tool.properties["idempotency_key"]
    assert schema["type"] == "string"
    assert (schema["minLength"], schema["maxLength"]) == (8, 200)
    assert "idempotency_key" not in tool.required


def test_a_start_without_a_key_sends_and_returns_a_generated_one():
    opener = Opener()
    result = _client(opener).call_tool("shakerscan_hunt_start", dict(START))["structuredContent"]

    (start,) = opener.starts
    assert start["key"].startswith("mcp-") and len(start["key"]) == 36
    assert "idempotency_key" not in start["body"]  # a header, never part of the contract body
    assert result["mcp_idempotency_key"] == start["key"]
    assert result["mcp_generated_idempotency_key"] is True


def test_a_retried_start_with_the_returned_key_does_not_start_a_second_hunt():
    opener = Opener()
    client = _client(opener)
    first = client.call_tool("shakerscan_hunt_start", {**START, "idempotency_key": "agent-start-0001"})
    again = client.call_tool("shakerscan_hunt_start", {**START, "idempotency_key": "agent-start-0001"})

    assert [item["key"] for item in opener.starts] == ["agent-start-0001", "agent-start-0001"]
    assert first["structuredContent"]["hunt_id"] == again["structuredContent"]["hunt_id"]
    assert again["structuredContent"]["mcp_generated_idempotency_key"] is False


def test_an_unconfirmed_start_names_the_key_to_retry_with():
    opener = Opener(fail_start=urllib.error.URLError("connection reset"))
    with pytest.raises(mcp.MCPError) as exc:
        _client(opener).call_tool("shakerscan_hunt_start", dict(START))
    key = opener.starts[0]["key"]
    assert key in exc.value.message and "never a new key" in exc.value.message
    assert exc.value.data["outcome"] == "unknown"
    assert exc.value.data["mcp_idempotency_key"] == key


def test_a_refused_start_is_reported_as_the_refusal():
    refusal = urllib.error.HTTPError(
        "http://127.0.0.1:8080/hunts", 422, "Unprocessable", {},
        io.BytesIO(b'{"detail": "target is not authorized"}'),
    )
    with pytest.raises(mcp.MCPError) as exc:
        _client(Opener(fail_start=refusal)).call_tool("shakerscan_hunt_start", dict(START))
    assert exc.value.http_status == 422
    assert "target is not authorized" in exc.value.message


def test_the_start_key_is_not_sent_by_the_next_tool():
    opener = Opener()
    client = _client(opener)
    client.call_tool("shakerscan_hunt_start", dict(START))
    client.call_tool("shakerscan_hunt_cancel", {"hunt_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})
    assert opener.other_keys == [None]
