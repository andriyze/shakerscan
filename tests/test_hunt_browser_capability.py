from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
import sys
import types

import pytest

from api.capabilities.browser import (
    BrowserCapabilityInputError,
    BrowserNavigateAdapter,
)
from api.hunt.capability_reservations import (
    DURABLE_BROWSER_HUNT_CAPABILITIES,
    terminalize_hunt_capability,
)
from api.runtime.budget_reservations import DurableBudgetReservation
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.runtime.models import TargetBinding


NOW = datetime(2026, 8, 22, 17, 0, tzinfo=timezone.utc)


def _target(
    *,
    origins: tuple[str, ...] = ("https://app.example.test",),
    addresses: tuple[str, ...] = ("192.0.2.10",),
) -> TargetBinding:
    return TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=origins,
        allowed_addresses=addresses,
        allowed_root_domains=("example.test",),
    )


def test_browser_registry_and_durable_set_are_explicit_and_bounded():
    assert DURABLE_BROWSER_HUNT_CAPABILITIES == {"browser.navigate"}
    spec = CAPABILITY_REGISTRY.require("browser.navigate")
    assert spec.execution_kind == "browser"
    assert spec.risk_tier == "passive"
    assert spec.adapter == "playwright"
    assert spec.requires_active_approval is False
    assert spec.placement_requirements == {
        "network_reachability": True,
        "browser_runtime": "playwright",
        "agent_tool_worker": True,
        "runtime_target_binding": True,
    }
    assert spec.budget_cost == {
        "browser_actions": 1,
        "http_requests": 50,
        "tool_wall_seconds": 30,
    }


def test_browser_prepare_freezes_origin_address_digest_and_budget():
    prepared = BrowserNavigateAdapter.prepare(
        target=_target(),
        base_url="https://app.example.test",
        args={
            "path": "/reports?page=2&view=full",
            "timeout_ms": 5_100,
            "max_requests": 7,
        },
    )
    repeated = BrowserNavigateAdapter.prepare(
        target=_target(),
        base_url="https://app.example.test",
        args={
            "path": "/reports?page=2&view=full",
            "timeout_ms": 5_100,
            "max_requests": 7,
        },
    )

    assert prepared.input_digest == repeated.input_digest
    assert prepared.pinned_address == "192.0.2.10"
    assert prepared.estimated_budget == {
        "browser_actions": 1,
        "http_requests": 7,
        "tool_wall_seconds": 6,
    }
    assert "page=2" not in str(prepared.redacted_execution)
    assert "page" in prepared.redacted_execution["path"]


@pytest.mark.parametrize("path", [
    "https://evil.example/", "//evil.example/", "/path#fragment", "/bad\\path",
])
def test_browser_prepare_rejects_paths_that_can_escape_or_hide_scope(path):
    with pytest.raises(BrowserCapabilityInputError):
        BrowserNavigateAdapter.prepare(
            target=_target(),
            base_url="https://app.example.test",
            args={"path": path},
        )


def test_browser_prepare_requires_a_frozen_runtime_address():
    with pytest.raises(BrowserCapabilityInputError, match="frozen"):
        BrowserNavigateAdapter.prepare(
            target=_target(addresses=()),
            base_url="https://app.example.test",
            args={"path": "/"},
        )


@pytest.mark.parametrize("args", [
    {"path": 7},
    {"wait_until": True},
    {"timeout_ms": "5000"},
    {"max_requests": True},
    {"headers": {"authorization": "secret"}},
])
def test_browser_prepare_rejects_untyped_or_unregistered_input(args):
    with pytest.raises(BrowserCapabilityInputError):
        BrowserNavigateAdapter.prepare(
            target=_target(),
            base_url="https://app.example.test",
            args=args,
        )


@pytest.mark.parametrize("path", [
    "/?token=worker-only",
    "/?access_token=worker-only",
    "/?session=worker-only",
    "/?q=Bearer%20worker-only",
    "/?q=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature",
])
def test_browser_prepare_rejects_raw_secrets_before_queue_admission(path):
    with pytest.raises(BrowserCapabilityInputError, match="managed credential"):
        BrowserNavigateAdapter.prepare(
            target=_target(),
            base_url="https://app.example.test",
            args={"path": path},
        )


def test_browser_execution_blocks_cross_origin_and_writes_and_redacts_evidence(monkeypatch):
    blocked_routes = []

    class FakeRequest:
        def __init__(self, method, url):
            self.method = method
            self.url = url

    class FakeRoute:
        def __init__(self, request):
            self.request = request

        async def abort(self, reason):
            blocked_routes.append((self.request.method, self.request.url, reason))

        async def continue_(self):
            return None

    class FakeResponse:
        def __init__(self, method, url, status=200):
            self.url = url
            self.status = status
            self.request = FakeRequest(method, url)
            self.headers = {"content-type": "text/html; charset=utf-8"}

    class FakePage:
        def __init__(self):
            self.url = "about:blank"
            self.route_handler = None
            self.response_handler = None

        async def route(self, _pattern, handler):
            self.route_handler = handler

        def on(self, _event, handler):
            self.response_handler = handler

        async def goto(self, url, **_kwargs):
            attempts = [
                FakeRequest("GET", url),
                FakeRequest("GET", "https://evil.example/track?secret=outside"),
                FakeRequest("POST", "https://app.example.test/mutate?csrf=hidden"),
                FakeRequest("GET", "https://app.example.test/data?token=inside"),
            ]
            for request in attempts:
                await self.route_handler(FakeRoute(request))
                if request.method == "GET" and request.url.startswith(
                    "https://app.example.test"
                ):
                    await self.response_handler(FakeResponse(request.method, request.url))
            self.url = url
            return FakeResponse("GET", url)

    page = FakePage()

    class FakeContext:
        async def add_init_script(self, _script):
            return None

        async def new_page(self):
            return page

        async def close(self):
            return None

    class FakeBrowser:
        async def new_context(self, **_kwargs):
            return FakeContext()

        async def close(self):
            return None

    class FakeChromium:
        async def launch(self, **_kwargs):
            return FakeBrowser()

    class FakePlaywright:
        chromium = FakeChromium()

        async def stop(self):
            return None

    class FakeStarter:
        async def start(self):
            return FakePlaywright()

    async_api = types.ModuleType("playwright.async_api")
    async_api.TimeoutError = type("FakePlaywrightTimeout", (Exception,), {})
    async_api.async_playwright = lambda: FakeStarter()
    package = types.ModuleType("playwright")
    package.async_api = async_api
    monkeypatch.setitem(sys.modules, "playwright", package)
    monkeypatch.setitem(sys.modules, "playwright.async_api", async_api)

    prepared = BrowserNavigateAdapter.prepare(
        target=_target(),
        base_url="https://app.example.test",
        args={"path": "/start?page=2", "max_requests": 10},
    )
    heartbeats = []

    async def heartbeat():
        heartbeats.append(True)

    result = asyncio.run(BrowserNavigateAdapter(prepared).execute(
        heartbeat=heartbeat,
        cancelled=lambda: False,
    ))

    assert result.status == "partial"
    assert result.actual_budget["http_requests"] == 2
    assert heartbeats == [True]
    assert {item[0] for item in blocked_routes} == {"GET", "POST"}
    serialized = str(result.observations) + str(result.redacted_execution)
    for secret in ("page=2", "outside", "hidden", "inside"):
        assert secret not in serialized
    assert any(
        item.get("reason") == "cross_origin" for item in result.observations
    )
    assert any(
        item.get("reason") == "state_changing_method"
        for item in result.observations
    )


def test_cancelled_browser_terminal_is_distinct_and_preserves_measured_usage():
    requested = DurableBudgetReservation.request(
        owner_kind="hunt",
        owner_id="hunt-1",
        capability_name="browser.navigate",
        amounts={
            "agent_actions": 1,
            "browser_actions": 1,
            "http_requests": 5,
            "tool_wall_seconds": 10,
        },
        reservation_id="reservation-1",
        now=NOW,
    )
    running = requested.reserve(now=NOW, lease_seconds=90).start(
        worker_id="worker:test", now=NOW, lease_seconds=90,
    )
    terminal, receipt = terminalize_hunt_capability(
        running,
        action_digest="a" * 64,
        capability_name="browser.navigate",
        adapter_name="playwright",
        adapter_version="1",
        target_id="target-1",
        target_kind="web",
        capability_input={"path": "/safe"},
        action_status="cancelled",
        actual_budget={
            "agent_actions": 1,
            "browser_actions": 1,
            "http_requests": 2,
            "tool_wall_seconds": 1,
        },
        worker_id="worker:test",
        started_at=NOW.isoformat(),
        finished_at=NOW.isoformat(),
        receipt_id="receipt-1",
        result={"error": "cancelled"},
    )

    assert terminal.status == "failed"
    assert terminal.failure_reason == "capability_cancelled"
    assert terminal.actual["http_requests"] == 2
    assert receipt.status == "cancelled"
    assert receipt.budget_reservation_state == "failed"


def test_browser_queue_and_worker_rebuild_authority_and_settle_atomically():
    root = Path(__file__).resolve().parents[1]
    api_source = (root / "api" / "api.py").read_text()
    worker_source = (root / "api" / "worker.py").read_text()

    enqueue_start = api_source.index(
        "async def _enqueue_canonical_browser_capability("
    )
    enqueue_end = api_source.index(
        "\n\nasync def _enqueue_canonical_scanner_capability(", enqueue_start
    )
    enqueue = api_source[enqueue_start:enqueue_end]
    assert '"hunt_id"' in enqueue
    assert '"action_id"' in enqueue
    assert '"budget_reservation_id"' in enqueue
    assert '"action_digest"' in enqueue
    assert '"expected_input_digest"' in enqueue
    assert '"expected_budget"' in enqueue
    assert '"target"' not in enqueue
    assert "allowed_addresses" not in enqueue

    route_start = api_source.index("async def execute_hunt_capability(")
    route_end = api_source.index(
        '\n\n@app.post("/hunts/{hunt_id}/shell-plans', route_start
    )
    route = api_source[route_start:route_end]
    assert route.index("create_requested") < route.index(
        "await _enqueue_canonical_browser_capability("
    )

    worker_start = worker_source.index(
        "async def process_canonical_browser_capability_job("
    )
    worker_end = worker_source.index(
        "\n\nasync def process_canonical_network_capability_job(", worker_start
    )
    worker = worker_source[worker_start:worker_end]
    assert 'context = _worker_json_object(run["context_pack"])' in worker
    assert 'hunt_policy = _worker_json_object(run["policy_json"])' in worker
    assert "BrowserNavigateAdapter.prepare(" in worker
    assert "hunt_capability_action_digest(" in worker
    assert worker.index("stored.record.start(") < worker.index(
        "CapabilityExecutor()"
    )
    assert "heartbeat_reservation" in worker
    assert "terminalize_hunt_capability(" in worker
    assert "persist_terminal(" in worker
    assert "receipt_input = dict(execution.redacted_execution)" in worker
    assert "raw_target" not in worker
    assert "raw_policy" not in worker
    assert "elif job_type == 'canonical_browser_capability':" in worker_source
