from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
import sys
import types

import pytest

from api.capabilities.browser import (
    BrowserCapabilityInputError,
    BrowserInteractAdapter,
    BrowserNavigateAdapter,
    _observation_url,
    _redacted_path,
    _validate_read_only_interaction,
    browser_capability_adapter,
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
    assert DURABLE_BROWSER_HUNT_CAPABILITIES == {
        "browser.interact", "browser.navigate",
    }
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
    interaction = CAPABILITY_REGISTRY.require("browser.interact")
    assert interaction.execution_kind == "browser"
    assert interaction.risk_tier == "passive"
    assert interaction.adapter == "playwright"
    assert interaction.requires_active_approval is False
    assert interaction.placement_requirements == spec.placement_requirements
    assert interaction.budget_cost == {
        "browser_actions": 2,
        "http_requests": 50,
        "tool_wall_seconds": 30,
    }
    assert browser_capability_adapter("browser.navigate") is BrowserNavigateAdapter
    assert browser_capability_adapter("browser.interact") is BrowserInteractAdapter


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
    assert prepared.redacted_execution["address_policy"] == {
        "schema_version": "frozen-target-address-policy/v1",
        "family_preference": "ipv4_first",
        "admitted_address_count": 1,
        "fallback_attempt_limit": 1,
        "no_runtime_resolution": True,
    }


def test_browser_prepare_address_selection_is_stable_across_dns_order():
    first = BrowserNavigateAdapter.prepare(
        target=_target(addresses=("192.0.2.20", "2001:db8::1", "192.0.2.10")),
        base_url="https://app.example.test",
        args={"path": "/"},
    )
    repeated = BrowserNavigateAdapter.prepare(
        target=_target(addresses=("192.0.2.10", "192.0.2.20", "2001:db8::1")),
        base_url="https://app.example.test",
        args={"path": "/"},
    )

    assert first.pinned_address == repeated.pinned_address == "192.0.2.10"


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


def test_browser_public_paths_redact_opaque_secret_segments():
    secret = "AbCdEf0123456789AbCdEf0123456789"
    relative = f"/reset/{secret}?page=2"
    observed = f"https://app.example.test/reset/{secret}?page=2"

    assert secret not in _redacted_path(relative)
    assert secret not in _observation_url(observed)
    assert "/reset/<redacted>" in _redacted_path(relative)
    assert "page=%3Credacted%3E" in _redacted_path(relative)


def test_browser_interaction_prepare_is_deterministic_bounded_and_redacted():
    args = {
        "path": "/reports?view=summary",
        "selector": "#report-tabs [role='tab']",
        "timeout_ms": 6_100,
        "max_requests": 8,
        "settle_ms": 250,
    }
    prepared = BrowserInteractAdapter.prepare(
        target=_target(), base_url="https://app.example.test", args=args,
    )
    repeated = BrowserInteractAdapter.prepare(
        target=_target(), base_url="https://app.example.test", args=args,
    )

    assert prepared.input_digest == repeated.input_digest
    assert prepared.estimated_budget == {
        "browser_actions": 2,
        "http_requests": 8,
        "tool_wall_seconds": 7,
    }
    assert prepared.selector_digest == repeated.selector_digest
    redacted = str(prepared.redacted_execution)
    assert prepared.selector not in redacted
    assert "summary" not in redacted
    assert prepared.selector_digest in redacted


@pytest.mark.parametrize("args", [
    {},
    {"selector": "text=Delete account"},
    {"selector": "xpath=//button"},
    {"selector": "button >> text=Open"},
    {"selector": "[data-token='Bearer worker-only']"},
    {"selector": "#tab", "settle_ms": True},
    {"selector": "#tab", "settle_ms": 2001},
])
def test_browser_interaction_prepare_rejects_unbounded_or_secret_input(args):
    with pytest.raises(BrowserCapabilityInputError):
        BrowserInteractAdapter.prepare(
            target=_target(), base_url="https://app.example.test", args=args,
        )


@pytest.mark.parametrize("element", [
    {
        "tag": "a", "href": "https://evil.example/report", "semantics": "Read",
        "target": "", "download": False,
    },
    {
        "tag": "a", "href": "https://app.example.test/logout", "semantics": "Log out",
        "target": "", "download": False,
    },
    {
        "tag": "button", "role": "", "type": "submit", "semantics": "Continue",
        "target": "", "download": False,
    },
    {
        "tag": "a", "href": "https://app.example.test/report?token=worker-only",
        "semantics": "Read", "target": "", "download": False,
    },
    {
        "tag": "a", "href": "https://app.example.test/report", "semantics": "Read",
        "target": "_blank", "download": False,
    },
])
def test_browser_interaction_rejects_cross_origin_mutating_or_secret_elements(element):
    prepared = BrowserInteractAdapter.prepare(
        target=_target(),
        base_url="https://app.example.test",
        args={"selector": "#safe"},
    )
    with pytest.raises(BrowserCapabilityInputError):
        _validate_read_only_interaction(prepared, element)


def test_browser_interaction_click_is_context_guarded_and_content_free(monkeypatch):
    class FakePinnedProxy:
        def __init__(self, **_kwargs):
            self.socket_factory = types.SimpleNamespace(policy_receipt={
                "schema_version": "frozen-target-address-policy/v1",
            })
            self.address_attempts = {"192.0.2.10": 1}
            self.address_connections = {"192.0.2.10": 1}
            self.proxy_url = "socks5://127.0.0.1:41000"

        async def start(self): return self
        async def close(self): return None

    monkeypatch.setattr(
        "api.capabilities.browser.PinnedSocksProxy", FakePinnedProxy,
    )
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
            self.headers = {"content-type": "text/html"}

    class FakeLocator:
        async def count(self):
            return 1

        async def evaluate(self, _script):
            return {
                "tag": "a",
                "role": "",
                "type": "",
                "href": "https://app.example.test/report?view=public",
                "target": "",
                "download": False,
                "semantics": "Read report private-label",
            }

        async def click(self, **_kwargs):
            attempts = [
                FakeRequest("GET", "https://app.example.test/report?view=public"),
                FakeRequest("POST", "https://app.example.test/mutate?csrf=hidden"),
                FakeRequest("GET", "https://evil.example/track?secret=outside"),
            ]
            for request in attempts:
                await page.route_handler(FakeRoute(request))
                if request.method == "GET" and request.url.startswith(
                    "https://app.example.test"
                ):
                    await page.response_handler(FakeResponse(request.method, request.url))
            page.url = "https://app.example.test/report?view=public"

    class FakePage:
        def __init__(self):
            self.url = "about:blank"
            self.route_handler = None
            self.response_handler = None

        async def goto(self, url, **_kwargs):
            request = FakeRequest("GET", url)
            await self.route_handler(FakeRoute(request))
            await self.response_handler(FakeResponse("GET", url))
            self.url = url
            return FakeResponse("GET", url)

        def locator(self, selector):
            assert selector == "#report-link"
            return FakeLocator()

    page = FakePage()

    class FakeContext:
        async def route(self, _pattern, handler):
            page.route_handler = handler

        def on(self, _event, handler):
            page.response_handler = handler

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

    prepared = BrowserInteractAdapter.prepare(
        target=_target(),
        base_url="https://app.example.test",
        args={
            "path": "/start?view=summary",
            "selector": "#report-link",
            "max_requests": 10,
            "settle_ms": 0,
        },
    )
    heartbeats = []

    async def heartbeat():
        heartbeats.append(True)

    result = asyncio.run(BrowserInteractAdapter(prepared).execute(
        heartbeat=heartbeat, cancelled=lambda: False,
    ))

    assert result.status == "partial"
    assert result.actual_budget["browser_actions"] == 2
    assert result.actual_budget["http_requests"] == 2
    assert heartbeats == [True]
    assert {item[0] for item in blocked_routes} == {"GET", "POST"}
    serialized = str(result.observations) + str(result.redacted_execution)
    for content in (
        "private-label", "view=summary", "view=public", "hidden", "outside",
        "#report-link",
    ):
        assert content not in serialized
    interaction = next(
        item for item in result.observations
        if item.get("kind") == "browser_interaction"
    )
    assert interaction["element_kind"] == "same_origin_link"
    assert interaction["selector_sha256"] == prepared.selector_digest


def test_browser_execution_blocks_cross_origin_and_writes_and_redacts_evidence(monkeypatch):
    class FakePinnedProxy:
        def __init__(self, **_kwargs):
            self.socket_factory = types.SimpleNamespace(policy_receipt={
                "schema_version": "frozen-target-address-policy/v1",
            })
            self.address_attempts = {"192.0.2.10": 1}
            self.address_connections = {"192.0.2.10": 1}
            self.proxy_url = "socks5://127.0.0.1:41000"

        async def start(self): return self
        async def close(self): return None

    monkeypatch.setattr(
        "api.capabilities.browser.PinnedSocksProxy", FakePinnedProxy,
    )
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
        async def route(self, _pattern, handler):
            page.route_handler = handler

        def on(self, _event, handler):
            page.response_handler = handler

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
    transport = next(
        item for item in result.observations
        if item.get("kind") == "browser_target_transport"
    )
    assert transport["address_connections"] == {"192.0.2.10": 1}


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
    assert "browser_capability_adapter(capability_name)" in worker
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
