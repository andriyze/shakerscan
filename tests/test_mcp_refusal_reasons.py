"""A definite server refusal reaches the agent with its status and the server's reason.

Soak 2026-10-07 (defect 2): the MCP adapter re-caught every capability error and reported it as
"Hunt capability response was not confirmed" (outcome unknown), and every other tool said only
"ShakerScan API returned HTTP 4xx" with the reason in ``error.data``, which agents do not show.
Models then retried blindly or misdiagnosed: a 422 budget-profile ceiling was read as "the target
does not exist" and a 403 capability-policy refusal as "verification disabled". A 4xx with a
reason is a definite answer; only a lost answer (timeout, connection loss, gateway 502-504) is an
unknown outcome. Unit fixtures: the HTTP layer is a scripted opener, not a live instance.
"""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("shakerscan_mcp_refusals", ROOT / "scripts" / "shakerscan_mcp.py")
mcp = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mcp
SPEC.loader.exec_module(mcp)

HUNT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
CAPABILITY_PATH = f"/hunts/{HUNT}/capabilities/web.crawl"


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class ScriptedOpener:
    """Answers (method, path) with a JSON document, an HTTP error, or a transport failure."""

    def __init__(self, answers):
        self.answers = answers
        self.seen = []

    def open(self, request, timeout):
        path = request.full_url.removeprefix("http://127.0.0.1:8080")
        self.seen.append((request.get_method(), path))
        answer = self.answers[(request.get_method(), path)]
        if isinstance(answer, list):
            answer = answer.pop(0) if len(answer) > 1 else answer[0]
        if isinstance(answer, BaseException):
            raise answer
        if isinstance(answer, tuple):
            status, body = answer
            raise urllib.error.HTTPError(request.full_url, status, "refused", {}, io.BytesIO(json.dumps(body).encode()))
        return Response(json.dumps(answer).encode())


def _client(answers, **kwargs):
    client = mcp.ArsenalClient("http://127.0.0.1:8080", poll_seconds=0.01, action_wait_seconds=0.2, **kwargs)
    client.opener = ScriptedOpener(answers)
    return client


HUNT_RECORD = {
    "hunt_id": HUNT, "status": "active",
    "capabilities": [{"name": "web.crawl", "input_schema": {"type": "object"}}],
}


def _call_capability(client):
    return client.call_tool("shakerscan_hunt_capability", {
        "hunt_id": HUNT, "capability_name": "web.crawl", "input": {}, "idempotency_key": "key-refusal-1",
    })


@pytest.mark.parametrize(("status", "body", "reason"), [
    (403, {"detail": "capability web.crawl is outside this Hunt's policy"}, "outside this Hunt's policy"),
    (409, {"detail": {"code": "hunt_budget_exhausted", "message": "http_requests budget is exhausted"}},
     "http_requests budget is exhausted"),
    (422, {"detail": [{"loc": ["body", "input", "max_pages"], "msg": "must be at most 50",
                       "input": "SECRET-INPUT"}]}, "input.max_pages: must be at most 50"),
])
def test_capability_refusal_names_status_and_reason_not_an_unknown_outcome(status, body, reason):
    client = _client({("GET", f"/hunts/{HUNT}"): HUNT_RECORD, ("POST", CAPABILITY_PATH): (status, body)})
    with pytest.raises(mcp.MCPError) as refused:
        _call_capability(client)
    error = refused.value
    assert "not confirmed" not in error.message
    assert f"HTTP {status}" in error.message and reason in error.message
    assert error.data["outcome"] == "refused"
    assert error.data["http_status"] == status
    assert reason in error.data["detail"]
    assert error.data["mcp_idempotency_key"] == "key-refusal-1"
    # A definite refusal is never replayed, and a request input echoed in a 422 is never shown.
    assert client.opener.seen.count(("POST", CAPABILITY_PATH)) == 1
    assert "SECRET-INPUT" not in error.message + json.dumps(error.data)
    wire = mcp._error_response(7, error)["error"]
    assert reason in wire["message"] and wire["data"]["http_status"] == status


def test_a_lost_answer_is_still_reported_as_unknown_with_its_recovery_identity():
    lost = urllib.error.URLError(TimeoutError("timed out"))
    client = _client({("GET", f"/hunts/{HUNT}"): HUNT_RECORD, ("POST", CAPABILITY_PATH): lost})
    with pytest.raises(mcp.MCPError) as unknown:
        _call_capability(client)
    assert unknown.value.message.startswith("Hunt capability response was not confirmed")
    assert "key-refusal-1" in unknown.value.message
    assert unknown.value.data["outcome"] == "unknown"
    assert unknown.value.data["mcp_idempotency_key"] == "key-refusal-1"


def test_every_other_tool_puts_the_server_reason_in_the_message():
    reason = "budget profile fast allows at most 100 max_tcp_ports"
    client = _client({
        ("GET", "/hunts/contract"): (503, {"detail": "unused"}),
        ("POST", f"/hunts/{HUNT}/candidates"): (409, {"detail": f"Hunt is budget_exhausted; {reason}"}),
    })
    with pytest.raises(mcp.MCPError) as refused:
        client.call_tool("shakerscan_hunt_candidate", {
            "hunt_id": HUNT, "family": "ssh", "locus": {"port": 22}, "title": "t", "claim": "c",
            "evidence_refs": ["e1"],
        })
    assert refused.value.message == f"ShakerScan API returned HTTP 409: Hunt is budget_exhausted; {reason}"
    assert refused.value.http_status == 409
    assert json.loads(refused.value.data)["detail"].endswith(reason), "error.data keeps the body"


def test_a_body_without_a_reason_keeps_the_bare_status():
    client = _client({("POST", f"/hunts/{HUNT}/cancel"): (404, ["not json"])})
    with pytest.raises(mcp.MCPError) as refused:
        client.call_tool("shakerscan_hunt_cancel", {"hunt_id": HUNT})
    assert refused.value.message == "ShakerScan API returned HTTP 404"


def test_reason_text_is_bounded_and_single_line():
    long = "line one\nline two\x1b[31m " + "x" * 5_000
    reason = mcp._refusal_reason(json.dumps({"detail": long}))
    assert "\n" not in reason and "\x1b" not in reason
    assert len(reason) <= mcp.MAX_REASON_CHARS


@pytest.mark.parametrize("status", [408, 425, 429])
def test_a_retry_later_status_is_not_a_refusal_and_names_the_key_to_retry_with(status):
    # The broker treats the same statuses as retryable: "not now" is not "no".
    body = {"detail": "Device HTTP requests must be spaced at least one second apart"}

    class RetryLater(ScriptedOpener):
        def open(self, request, timeout):
            path = request.full_url.removeprefix("http://127.0.0.1:8080")
            if request.get_method() == "GET":
                return super().open(request, timeout)
            self.seen.append(("POST", path))
            raise urllib.error.HTTPError(request.full_url, status, "slow down", {"Retry-After": "3"},
                                         io.BytesIO(json.dumps(body).encode()))

    client = _client({})
    client.opener = RetryLater({("GET", f"/hunts/{HUNT}"): HUNT_RECORD})
    with pytest.raises(mcp.MCPError) as later:
        _call_capability(client)
    error = later.value
    assert error.data["outcome"] == "retry_later"
    assert "refused" not in error.message
    assert f"HTTP {status}" in error.message and "spaced at least one second apart" in error.message
    assert "key-refusal-1" in error.message and "Wait 3 s" in error.message
    assert error.data["retry_after_seconds"] == 3 and "new key" in error.data["recovery"]
    assert client.opener.seen.count(("POST", CAPABILITY_PATH)) == 1


def test_other_tools_mark_a_retry_later_status_in_the_message():
    client = _client({("POST", f"/hunts/{HUNT}/cancel"): (429, {"detail": "rate limited"})})
    with pytest.raises(mcp.MCPError) as later:
        client.call_tool("shakerscan_hunt_cancel", {"hunt_id": HUNT})
    assert later.value.message == "ShakerScan API returned HTTP 429: rate limited (retryable: wait and try again)"
