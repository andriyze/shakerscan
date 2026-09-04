"""Behavioral tests of replay, session confinement, and partial evidence.

The transport is a double; these do not replace a real Chromium acceptance run.
"""
import asyncio
from contextlib import asynccontextmanager
import json
import sys
from types import ModuleType, SimpleNamespace

import pytest

from api.capabilities.browser import BrowserInteractAdapter, BrowserNavigateAdapter, BrowserCapabilityInputError
from api.capabilities.browser_steps import browser_steps, validate_fill
from tests.test_hunt_browser_capability import _target


@pytest.mark.parametrize("args", [
    {"steps": []}, {"steps": [{"action": "click", "selector": "a"}] * 9},
    {"selector": "a", "steps": [{"selector": "b"}]},
    {"steps": [{"action": "submit", "selector": "form"}]},
    {"steps": [{"action": "fill", "selector": "input"}]},
    {"steps": [{"action": "fill", "selector": "input", "value": "a\nb"}]},
    {"steps": [{"action": "click", "selector": "a", "value": "x"}]},
])
def test_replay_input_is_typed_and_bounded(args):
    with pytest.raises(ValueError):
        browser_steps(args)


@pytest.mark.parametrize("element", [
    {"tag": "input", "type": "password"},
    {"tag": "input", "type": "text", "semantics": "one time OTP"},
    {"tag": "input", "type": "file"}, {"tag": "button", "type": "submit"},
])
def test_replay_cannot_fill_secret_or_non_text_controls(element):
    with pytest.raises(ValueError):
        validate_fill(element)


def test_fragment_session_and_each_step_participate_in_preparation():
    args = {"path": "/#/reports", "session_ref": "11111111-1111-4111-8111-111111111111",
            "steps": [{"action": "fill", "selector": "#search", "value": "report"},
                      {"action": "click", "selector": "#tab"}]}
    first = BrowserInteractAdapter.prepare(target=_target(), base_url="https://app.example.test", args=args)
    assert first.url.endswith("/#/reports")
    assert first.estimated_budget["browser_actions"] == 3
    assert first.session_ref == args["session_ref"]
    changed = dict(args, steps=[dict(args["steps"][0], value="different"), args["steps"][1]])
    second = BrowserInteractAdapter.prepare(target=_target(), base_url="https://app.example.test", args=changed)
    assert first.input_digest != second.input_digest
    with pytest.raises(BrowserCapabilityInputError):
        BrowserNavigateAdapter.prepare(target=_target(), base_url="https://app.example.test", args={"session_ref": "raw-cookie"})


@pytest.mark.parametrize("failure", [None, "missing", "unsafe", "timeout"])
def test_replay_retains_steps_confines_credentials_and_closes_context(monkeypatch, failure):
    import api.capabilities.browser as module
    continued, aborted, operations, cookies, lifecycle = [], [], [], [], []
    timeout = type("BrowserTimeout", (Exception,), {})

    class Proxy:
        def __init__(self, **kwargs):
            assert kwargs["pinned_addresses"] == ("192.0.2.10",)
            self.socket_factory = SimpleNamespace(policy_receipt={})
            self.address_attempts, self.address_connections = {}, {}
            self.proxy_url = "socks5://127.0.0.1:1234"
        async def start(self): return self
        async def close(self): lifecycle.append("proxy_closed")

    class Route:
        def __init__(self, method, url):
            self.request = SimpleNamespace(method=method, url=url, headers={})
        async def continue_(self, **kwargs): continued.append((self.request.url, kwargs))
        async def abort(self, reason): aborted.append(self.request.url)

    class Locator:
        def __init__(self, selector): self.selector = selector
        async def count(self): return 0 if self.selector == "#tab" and failure == "missing" else 1
        async def evaluate(self, script):
            if self.selector == "#search":
                return {"tag": "input", "type": "search", "semantics": "Search"}
            return {"tag": "button", "type": "button", "role": "tab",
                    "semantics": "Delete" if failure == "unsafe" else "Reports"}
        async def fill(self, value, **kwargs): operations.append((self.selector, value))
        async def click(self, **kwargs):
            if failure == "timeout": raise timeout()
            operations.append((self.selector, "click"))
            for method, url in [("GET", "https://app.example.test/report"),
                                ("POST", "https://app.example.test/update"),
                                ("GET", "https://other.example.test/exfil")]:
                await page.route_handler(Route(method, url))

    class Page:
        url = "about:blank"
        async def goto(self, url, **kwargs):
            self.url = url
            await self.route_handler(Route("GET", url))
            return SimpleNamespace(status=200)
        def locator(self, selector): return Locator(selector)
        async def evaluate(self, script):
            assert "textContent" not in script
            return {"total": 1, "controls": [{"selector": "a:nth-of-type(1)", "tag": "a",
                "href": "https://app.example.test/report?view=PRIVATE_VALUE",
                "text": "PRIVATE_TEXT", "value": "PRIVATE_VALUE"}]}
    page = Page()

    class Context:
        async def add_cookies(self, items): cookies.extend(items)
        async def add_init_script(self, script): pass
        async def route(self, pattern, handler): page.route_handler = handler
        def on(self, event, handler): pass
        async def new_page(self): return page
        async def close(self): lifecycle.append("context_closed")
    class Browser:
        async def new_context(self, **kwargs): return Context()
        async def close(self): lifecycle.append("browser_closed")
    class Chromium:
        async def launch(self, **kwargs): return Browser()
    class Playwright:
        chromium = Chromium()
        async def stop(self): lifecycle.append("playwright_stopped")
    class Starter:
        async def start(self): return Playwright()
    async_api = ModuleType("playwright.async_api")
    async_api.async_playwright, async_api.TimeoutError = lambda: Starter(), timeout
    monkeypatch.setitem(sys.modules, "playwright.async_api", async_api)
    monkeypatch.setattr(module, "PinnedSocksProxy", Proxy)

    @asynccontextmanager
    async def session():
        lifecycle.append("session_opened")
        try: yield {"Authorization": "Bearer WORKER_SECRET", "Cookie": "sid=COOKIE_SECRET"}
        finally: lifecycle.append("session_closed")
    async def heartbeat(): pass
    prepared = BrowserInteractAdapter.prepare(target=_target(), base_url="https://app.example.test",
        args={"path": "/#/reports", "session_ref": "11111111-1111-4111-8111-111111111111", "settle_ms": 0,
              "steps": [{"action": "fill", "selector": "#search", "value": "test query"},
                        {"action": "click", "selector": "#tab"}]})
    result = asyncio.run(BrowserInteractAdapter(prepared, session_loader=session).execute(heartbeat=heartbeat, cancelled=lambda: False))
    assert result.status == "partial"
    interactions = [x for x in result.observations if x["kind"] == "browser_interaction"]
    assert len(interactions) == (2 if failure is None else 1)
    assert result.actual_budget["browser_actions"] == (2 if failure in {"missing", "unsafe"} else 3)
    assert cookies[0]["url"] == "https://app.example.test"
    assert cookies[0]["httpOnly"] is True
    assert all(url.startswith("https://app.example.test/") for url, _ in continued)
    assert all(options["headers"]["authorization"] == "Bearer WORKER_SECRET" for _, options in continued)
    if failure is None:
        assert len(aborted) == 2
        surface = next(x for x in result.observations if x["kind"] == "browser_surface")
        assert surface["untrusted_data"] is True
        assert surface["controls"][0]["selector"] == "a:nth-of-type(1)"
    serialized = json.dumps(result.observations) + json.dumps(result.redacted_execution)
    for value in ("WORKER_SECRET", "COOKIE_SECRET", "PRIVATE_TEXT", "PRIVATE_VALUE", "test query"):
        assert value not in serialized
    assert lifecycle == ["session_opened", "context_closed", "browser_closed", "playwright_stopped", "proxy_closed", "session_closed"]
