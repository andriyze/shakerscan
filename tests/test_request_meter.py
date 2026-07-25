import asyncio
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import common
from scanner_tools.request_meter import (
    RequestBudgetExceeded,
    configure_request_meter,
    install_async_client_metering,
)


def teardown_function():
    configure_request_meter(limit=None, target_host=None, mode="off")


def test_request_meter_tracks_attempt_completion_retry_and_rejection():
    meter = configure_request_meter(
        limit=2,
        target_host="app.test",
        mode="enforce",
        planned=5,
        reserved=2,
    )

    assert meter.before_request(phase="probe", url="https://app.test/a") is True
    meter.record_completion(phase="probe", url="https://app.test/a", status_code=200)
    assert meter.before_request(phase="probe", url="https://app.test/b", retry=True) is True
    meter.record_completion(phase="probe", url="https://app.test/b", status_code=500)
    with pytest.raises(RequestBudgetExceeded):
        meter.before_request(phase="probe", url="https://app.test/c")

    snapshot = meter.snapshot()
    assert snapshot["planned_requests"] == 5
    assert snapshot["reserved_requests"] == 2
    assert snapshot["attempted_requests"] == 2
    assert snapshot["completed_requests"] == 2
    assert snapshot["retried_requests"] == 1
    assert snapshot["rejected_requests"] == 1
    assert snapshot["successful_requests"] == 1
    assert snapshot["adapter_usage"] == {
        "probe": {
            "attempted": 2,
            "completed": 2,
            "retried": 1,
            "rejected": 1,
            "successful": 1,
        }
    }


def test_request_meter_ignores_other_hosts():
    meter = configure_request_meter(
        limit=1, target_host="app.test", mode="enforce", planned=1, reserved=1
    )

    assert meter.before_request(phase="provider", url="https://provider.test/v1") is False
    assert meter.snapshot()["attempted_requests"] == 0


def test_httpx_hook_enforces_target_budget():
    meter = configure_request_meter(
        limit=1, target_host="app.test", mode="enforce", planned=1, reserved=1
    )
    install_async_client_metering()

    async def run_requests():
        transport = httpx.MockTransport(lambda request: httpx.Response(200, request=request))
        async with httpx.AsyncClient(transport=transport) as client:
            response = await client.get("https://app.test/one")
            assert response.status_code == 200
            with pytest.raises(RequestBudgetExceeded):
                await client.get("https://app.test/two")

    asyncio.run(run_requests())
    assert meter.snapshot()["attempted_requests"] == 1
    assert meter.snapshot()["completed_requests"] == 1
    assert meter.snapshot()["rejected_requests"] == 1


def test_unmetered_network_tool_fails_closed_only_in_enforce_mode():
    meter = configure_request_meter(
        limit=10, target_host="app.test", mode="enforce", planned=10, reserved=10
    )
    out, error, rc = asyncio.run(common.run([
        "nuclei", "-u", "https://app.test",
    ]))

    assert out == ""
    assert rc == 75
    assert "unmetered network tool" in error
    assert meter.snapshot()["rejected_requests"] == 1


def test_enforcing_curl_disables_hidden_redirect_requests(monkeypatch):
    captured = {}
    configure_request_meter(
        limit=1, target_host="app.test", mode="enforce", planned=1, reserved=1
    )

    class FakeProcess:
        returncode = 0

        async def communicate(self, input=None):
            return b"ok", b""

    async def fake_exec(*cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return FakeProcess()

    monkeypatch.setattr(common.asyncio, "create_subprocess_exec", fake_exec)
    out, error, rc = asyncio.run(common.run([
        "curl", "-sS", "-L", "--max-redirs", "5", "https://app.test/start",
    ]))

    assert (out, error, rc) == ("ok", "", 0)
    assert "-L" not in captured["cmd"]
    assert "--max-redirs" not in captured["cmd"]
