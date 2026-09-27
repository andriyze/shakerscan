"""Scheme inference chooses reachability only within admitted Scan origins."""

from __future__ import annotations

import pytest
import os
import sys
import asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from runtime.models import TargetBinding  # noqa: E402
from scan import origin_selection  # noqa: E402
from capabilities.inline import ScanOriginSelectionExecutionAdapter  # noqa: E402
from runtime.capability_registry import CAPABILITY_REGISTRY  # noqa: E402


def _target(port: str = "") -> TargetBinding:
    origins = (f"https://app.example.test{port}", f"http://app.example.test{port}")
    return TargetBinding(
        target_id="target-1", target_kind="web", canonical_host="app.example.test",
        allowed_origins=origins, inferred_origins=origins,
        allowed_addresses=("192.0.2.10",), allowed_root_domains=("example.test",),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("https_works", "expected", "attempts"),
    [
        (True, "https://app.example.test", 1),
        (False, "http://app.example.test", 2),
    ],
)
async def test_origin_selection_uses_measured_reachability(
    monkeypatch, https_works, expected, attempts,
):
    calls = []

    async def request(origin, args, *, target, **kwargs):
        calls.append(origin)
        assert origin in target.inferred_origins
        assert args == {"method": "GET", "path": "/", "follow_redirects": False}
        if origin.startswith("https://") and not https_works:
            return {"ok": False, "request": {"origin": origin}, "error": "request_error:ConnectError"}
        return {"ok": True, "request": {"origin": origin}, "response": {"status": 404}}

    monkeypatch.setattr(origin_selection, "execute_bound_http_request", request)
    result = await origin_selection.select_inferred_scan_origin(target=_target())
    assert result["observation"]["selected_origin"] == expected
    assert result["budget_consumed"]["http_requests"] == attempts
    assert len(calls) == attempts
    assert origin_selection.selected_origin_from_observations(
        (result["observation"],), _target(),
    ) == expected


@pytest.mark.asyncio
async def test_origin_selection_keeps_failed_attempts_and_no_false_clean_result(monkeypatch):
    async def request(origin, args, *, target, **kwargs):
        return {"ok": False, "request": {"origin": origin}, "error": "request_error:ConnectError"}

    monkeypatch.setattr(origin_selection, "execute_bound_http_request", request)
    result = await origin_selection.select_inferred_scan_origin(target=_target())
    assert result["status"] == "failed"
    assert result["observation"]["selected_origin"] is None
    assert result["budget_consumed"]["http_requests"] == 2
    assert len(result["observation"]["attempts"]) == 2


@pytest.mark.asyncio
async def test_explicit_port_80_on_scheme_inferred_target_selects_http(monkeypatch):
    target = TargetBinding(
        target_id="target-1", target_kind="web", canonical_host="app.example.test",
        allowed_origins=("https://app.example.test:80", "http://app.example.test"),
        inferred_origins=("https://app.example.test:80", "http://app.example.test"),
        allowed_addresses=("192.0.2.10",), allowed_root_domains=("example.test",),
    )

    async def request(origin, _args, *, target, **_kwargs):
        if origin.startswith("https://"):
            return {"ok": False, "request": {"origin": origin}, "error": "request_error:TLSFailure"}
        return {"ok": True, "request": {"origin": origin}, "response": {"status": 200}}

    monkeypatch.setattr(origin_selection, "execute_bound_http_request", request)
    result = await origin_selection.select_inferred_scan_origin(target=target)
    assert result["observation"]["selected_origin"] == "http://app.example.test"


def test_selected_origin_must_remain_in_the_frozen_binding():
    observation = ({"kind": "origin_selection_observation", "selected_origin": "https://evil.test"},)
    assert origin_selection.selected_origin_from_observations(observation, _target()) is None


@pytest.mark.asyncio
async def test_origin_selection_cancellation_stops_pending_probe():
    stopped = asyncio.Event()
    cancelled = False

    async def operation():
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    adapter = ScanOriginSelectionExecutionAdapter(
        specification=CAPABILITY_REGISTRY.require("scan.origin_select"),
        operation=operation,
        requested_budget={"http_requests": 2, "tool_wall_seconds": 20},
        redacted_execution={},
    )

    async def heartbeat():
        return None

    async def run():
        return await adapter.execute(heartbeat=heartbeat, cancelled=lambda: cancelled)

    task = asyncio.create_task(run())
    await asyncio.sleep(0.01)
    cancelled = True
    result = await task
    assert result.status == "cancelled"
    assert stopped.is_set()
