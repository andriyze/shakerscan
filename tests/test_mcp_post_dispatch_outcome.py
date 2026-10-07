"""A 4xx after the server reported an action dispatched is an unknown outcome, not a refusal.

The MCP adapter labelled every non-retryable 4xx "refused" (``data.outcome = "refused"``,
recovery "replaying the same key returns the same answer"). A capability whose first answer
was the action in flight (``action_result.status: running``) and whose settling replay was
then answered 409 -- the Hunt finished while the action ran -- was reported as refused, so the
agent concluded nothing had run. Once the server has reported dispatch (``execution_started``
or the action's state), a later 4xx is reported as unknown with the action id and the
idempotency key to recover with. A 4xx before dispatch stays a definite refusal. Unit
fixtures: the HTTP layer is a scripted opener, not a live instance.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "shakerscan_mcp_post_dispatch", ROOT / "scripts" / "shakerscan_mcp.py",
)
mcp = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mcp
SPEC.loader.exec_module(mcp)

from tests.test_mcp_refusal_reasons import (  # noqa: E402
    CAPABILITY_PATH, HUNT, HUNT_RECORD, ScriptedOpener,
)

ACTION_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
KEY = "key-dispatch-1"


def _client(answers):
    client = mcp.ArsenalClient(
        "http://127.0.0.1:8080", poll_seconds=0.01, action_wait_seconds=0.5,
    )
    client.opener = ScriptedOpener(answers)
    return client


def _call(client):
    return client.call_tool("shakerscan_hunt_capability", {
        "hunt_id": HUNT, "capability_name": "web.crawl", "input": {}, "idempotency_key": KEY,
    })


def _running(**extra):
    return {
        "hunt_id": HUNT, "capability": "web.crawl", "action_id": ACTION_ID,
        "action_result": {"status": "running", **extra},
    }


@pytest.mark.parametrize("first", [
    _running(),
    {**_running(), "action_result": {"status": "queued"}},
    _running(execution_started=True),
])
def test_a_4xx_while_settling_a_dispatched_action_is_unknown_not_refused(first):
    client = _client({
        ("GET", f"/hunts/{HUNT}"): HUNT_RECORD,
        ("POST", CAPABILITY_PATH): [first, (409, {"detail": "Hunt is completed"})],
    })
    with pytest.raises(mcp.MCPError) as failure:
        _call(client)
    data = failure.value.data
    assert data["outcome"] == "unknown"
    assert data["indeterminate"] is True
    assert data["action_id"] == ACTION_ID
    assert data["mcp_idempotency_key"] == KEY
    assert data["http_status"] == 409
    assert data["detail"] == "Hunt is completed"
    message = failure.value.message
    assert "refused" not in message
    assert ACTION_ID in message and f"idempotency_key {KEY}" in message
    assert "HTTP 409: Hunt is completed" in message


def test_a_4xx_whose_body_reports_execution_started_is_unknown():
    client = _client({
        ("GET", f"/hunts/{HUNT}"): HUNT_RECORD,
        ("POST", CAPABILITY_PATH): (422, {"detail": {
            "error": "capability output rejected", "action_id": ACTION_ID,
            "execution_started": True,
        }}),
    })
    with pytest.raises(mcp.MCPError) as failure:
        _call(client)
    assert failure.value.data["outcome"] == "unknown"
    assert failure.value.data["action_id"] == ACTION_ID
    assert failure.value.data["execution_started"] is True


@pytest.mark.parametrize("answer", [
    (422, {"detail": "HTTP service origin must be on the Hunt's exact target host"}),
    # The server stating the action never ran is a refusal, even with an action id.
    (409, {"detail": {"error": "budget_exhausted:agent_actions", "action_id": ACTION_ID,
                      "execution_started": False}}),
])
def test_a_refusal_before_dispatch_stays_refused(answer):
    client = _client({
        ("GET", f"/hunts/{HUNT}"): HUNT_RECORD,
        ("POST", CAPABILITY_PATH): answer,
    })
    with pytest.raises(mcp.MCPError) as failure:
        _call(client)
    assert failure.value.data["outcome"] == "refused"
    assert "was refused" in failure.value.message


def test_the_client_runs_the_same_adapter():
    # The client vendors scripts/shakerscan_mcp.py at build time; a checkout loads it in place.
    sys.path.insert(0, str(ROOT / "client" / "src"))
    try:
        from shakerscan import _vendored
    finally:
        sys.path.pop(0)
    vendored = _vendored.load("_mcp")
    assert Path(vendored.__file__).resolve() == (ROOT / "scripts" / "shakerscan_mcp.py").resolve()
    assert vendored._dispatch_evidence(_running()) == {
        "action_id": ACTION_ID, "action_status": "running",
    }
