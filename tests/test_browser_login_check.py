"""Functional login orchestration with synthetic, offline browser/transport doubles."""
from __future__ import annotations

import asyncio
from dataclasses import replace
import importlib.util
from pathlib import Path
import sys
import traceback
from types import SimpleNamespace

import pytest

_SOURCE = Path(__file__).resolve().parents[1] / "api/capabilities/browser_login.py"
_SPEC = importlib.util.spec_from_file_location("browser_login_check", _SOURCE)
assert _SPEC is not None and _SPEC.loader is not None
bl = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = bl
_SPEC.loader.exec_module(bl)
ORIGIN = "https://login-fixture.test"
SECRET = "SYNTHETIC_PRIVATE_PASSWORD"
SPEC = bl.BrowserLoginWorkflow(
    origin=ORIGIN, login_url=ORIGIN + "/login", submit_url=ORIGIN + "/session",
    check_url=ORIGIN + "/account", username_selector="#username",
    password_selector="#password", submit_selector="#sign-in",
    authenticated_selector="#private-account", rejected_selector="#login-error",
    challenge_selector="#mfa", timeout_ms=200,
)
VALUES = bl.BrowserLoginValues("synthetic-user", SECRET)


class Route:
    def __init__(self, url, method="GET"):
        self.request = SimpleNamespace(url=url, method=method)
        self.response = None
        self.aborted = False

    async def fulfill(self, **response):
        self.response = response

    async def abort(self, reason):
        self.aborted = True


class Locator:
    def __init__(self, page, selector):
        assert selector.startswith("css=")
        self.page, self.selector = page, selector[4:]

    async def is_visible(self):
        flags = self.page.browser.flags
        if self.selector == SPEC.challenge_selector:
            return bool(flags.get("mfa"))
        if self.selector == SPEC.rejected_selector:
            return bool(flags.get("rejected"))
        if self.selector == SPEC.authenticated_selector:
            return bool(flags.get("public_marker") or self.page.browser.authenticated)
        return True

    async def fill(self, value):
        if self.page.browser.flags.get("cancel"):
            raise asyncio.CancelledError()
        self.page.browser.values.append(value)

    async def click(self):
        route = await self.page.browser.send(SPEC.submit_url, "POST")
        if route.response and route.response["status"] == 200:
            self.page.browser.authenticated = True
        if self.page.browser.flags.get("double_submit"):
            second = await self.page.browser.send(SPEC.submit_url, "POST")
            assert second.aborted


class Page:
    def __init__(self, browser):
        self.browser = browser
        self.url = "about:blank"

    def locator(self, selector):
        return Locator(self, selector)

    async def goto(self, url, **kwargs):
        self.url = url
        route = await self.browser.send(url)
        if route.aborted:
            raise RuntimeError(SECRET)
        if url == SPEC.check_url and self.browser.flags.get("expires"):
            self.browser.authenticated = False
            self.browser.flags["rejected"] = True


class Browser:
    def __init__(self, **flags):
        self.flags = flags
        self.values, self.calls = [], []
        self.closed = False
        self.authenticated = False
        self.page = Page(self)

    async def new_context(self, **options):
        assert options == {"service_workers": "block", "accept_downloads": False}
        return self

    async def new_page(self):
        return self.page

    async def route(self, pattern, handler):
        self.handler = handler

    async def route_web_socket(self, pattern, handler):
        self.websocket_handler = handler

    def set_default_timeout(self, value):
        pass

    async def close(self):
        self.closed = True
        if self.flags.get("close_error"):
            raise RuntimeError(SECRET)

    async def send(self, url, method="GET"):
        route = Route(url, method)
        await self.handler(route)
        return route

    async def transport(self, request, phase):
        self.calls.append((request.method, request.url, phase))
        if self.flags.get("transport_error"):
            raise RuntimeError(SECRET)
        if self.flags.get("slow_transport"):
            await asyncio.sleep(1)
        if self.flags.get("oversized"):
            return bl.BrowserLoginResponse(200, {}, b"x" * (SPEC.max_response_bytes + 1))
        status = 401 if self.flags.get("bad_password") and request.method == "POST" else 200
        return bl.BrowserLoginResponse(status, {"Content-Length": "10"}, b"synthetic")


def execute(browser, spec=SPEC, values=VALUES):
    async def scenario():
        async with bl.authenticated_browser_page(
            browser, workflow=spec, values=values, transport=browser.transport,
        ) as (page, receipt):
            return receipt
    return asyncio.run(scenario())


def test_success_observes_login_and_rechecks_protected_page_without_exporting_secrets():
    browser = Browser()
    receipt = execute(browser)
    assert receipt["authentication_verified"] is True
    assert receipt["login_submissions"] == 1
    assert receipt["login_response_status"] == 200
    assert receipt["responses_received"] == receipt["requests_routed"] == 3
    assert receipt["verification_basis"] == "operator_dom_assertion"
    assert browser.values == [VALUES.username, VALUES.password]
    assert [phase for _, _, phase in browser.calls] == ["load", "login", "verify"]
    assert SECRET not in repr(receipt) + repr(VALUES)
    assert browser.closed


@pytest.mark.parametrize("change", [
    {"origin": "https://user:secret@login-fixture.test"},
    {"login_url": "https://other.test/login"}, {"submit_url": ORIGIN + "/session#fragment"},
    {"check_url": ORIGIN + "\\other"}, {"login_url": ORIGIN + "/login\n"},
    {"username_selector": "css=#name >> text=secret"}, {"password_selector": ""},
    {"authenticated_selector": "#login-error"}, {"timeout_ms": True},
    {"timeout_ms": 0}, {"max_requests": 2}, {"max_response_bytes": 0},
])
def test_invalid_workflow_fails_before_any_browser_or_network_work(change):
    browser = Browser()
    with pytest.raises(bl.BrowserLoginError, match="invalid_workflow"):
        execute(browser, replace(SPEC, **change))
    assert not browser.calls
    assert not browser.values


@pytest.mark.parametrize("flags, reason", [
    ({"mfa": True}, "requires_user_action"),
    ({"bad_password": True}, "authentication_rejected"),
    ({"public_marker": True}, "ambiguous_success_assertion"),
    ({"transport_error": True}, "transport_failed"),
    ({"oversized": True}, "transport_failed"),
    ({"expires": True}, "authentication_rejected"),
])
def test_failure_outcomes_close_context_and_do_not_leak_private_diagnostics(flags, reason):
    browser = Browser(**flags)
    with pytest.raises(bl.BrowserLoginError, match=reason) as caught:
        execute(browser)
    assert browser.closed
    assert SECRET not in "".join(traceback.format_exception(caught.value))
    assert not caught.value.receipt["authentication_verified"]
    assert sum(method == "POST" for method, _, _ in browser.calls) <= 1


def test_slow_transport_is_bounded():
    browser = Browser(slow_transport=True)
    with pytest.raises(bl.BrowserLoginError):
        execute(browser)
    assert browser.closed


@pytest.mark.parametrize("close_error", [False, True])
def test_cancellation_remains_cancellation_even_when_context_close_fails(close_error):
    browser = Browser(cancel=True, close_error=close_error)
    with pytest.raises(asyncio.CancelledError):
        execute(browser)
    assert browser.closed


def test_normal_cleanup_error_is_visible_and_sanitized():
    browser = Browser(close_error=True)
    with pytest.raises(bl.BrowserLoginError, match="browser_cleanup_failed") as caught:
        execute(browser)
    assert SECRET not in "".join(traceback.format_exception(caught.value))


def test_only_one_login_submission_is_ever_forwarded():
    browser = Browser(double_submit=True)
    receipt = execute(browser)
    assert receipt["login_submissions"] == 1
    assert receipt["requests_blocked"] == 1


def test_authenticated_context_allows_read_only_checks_not_further_form_submissions():
    browser = Browser()
    async def scenario():
        async with bl.authenticated_browser_page(
            browser, workflow=SPEC, values=VALUES, transport=browser.transport,
        ) as (page, receipt):
            for url, method in [
                (SPEC.submit_url, "POST"), (ORIGIN + "/delete", "DELETE"),
                ("https://other.test/", "GET"), ("http://login-fixture.test/", "GET"),
                (ORIGIN + ":8443/", "GET"),
            ]:
                assert (await browser.send(url, method)).aborted
            await page.goto(ORIGIN + "/help")
            assert browser.calls[-1][-1] == "read_only"
            browser.authenticated = False
            browser.flags["rejected"] = True
            assert await bl.browser_authentication_state(page, SPEC) == "authentication_rejected"
    asyncio.run(scenario())
    assert browser.closed


def test_request_ceiling_applies_after_login_as_well():
    browser = Browser()
    async def scenario():
        async with bl.authenticated_browser_page(
            browser, workflow=replace(SPEC, max_requests=3), values=VALUES,
            transport=browser.transport,
        ):
            assert (await browser.send(ORIGIN + "/one-more")).aborted
    asyncio.run(scenario())
    assert len(browser.calls) == 3


@pytest.mark.parametrize("values", [
    bl.BrowserLoginValues("", SECRET), bl.BrowserLoginValues("name", ""),
    bl.BrowserLoginValues(None, SECRET), bl.BrowserLoginValues("name", b"not-text"),
    bl.BrowserLoginValues("name", "x" * 4097), bl.BrowserLoginValues("name", "x\x00y"),
])
def test_invalid_credentials_are_never_filled(values):
    browser = Browser()
    with pytest.raises(bl.BrowserLoginError, match="invalid_workflow"):
        execute(browser, values=values)
    assert browser.values == browser.calls == []


def test_login_marker_without_an_observed_submission_is_not_authentication():
    browser = Browser()
    original = Locator.click
    async def no_network_click(self):
        self.page.browser.authenticated = True
    Locator.click = no_network_click
    try:
        with pytest.raises(bl.BrowserLoginError, match="login_submission_not_observed"):
            execute(browser)
    finally:
        Locator.click = original
    assert not any(method == "POST" for method, _, _ in browser.calls)


def test_websockets_cannot_open_an_uncontrolled_transport():
    browser = Browser()
    socket = SimpleNamespace(closed=False)
    async def close():
        socket.closed = True
    socket.close = close
    async def scenario():
        async with bl.authenticated_browser_page(
            browser, workflow=SPEC, values=VALUES, transport=browser.transport,
        ):
            await browser.websocket_handler(socket)
    asyncio.run(scenario())
    assert socket.closed


def test_read_only_checks_have_per_request_timeout_not_an_expired_login_deadline():
    browser = Browser()
    async def scenario():
        async with bl.authenticated_browser_page(
            browser, workflow=SPEC, values=VALUES, transport=browser.transport,
        ) as (page, _):
            await asyncio.sleep(SPEC.timeout_ms / 1000 + 0.01)
            await page.goto(ORIGIN + "/help")
            assert browser.calls[-1][-1] == "read_only"
    asyncio.run(scenario())


def test_failure_receipt_preserves_cleanup_failure_without_replacing_primary_error():
    browser = Browser(transport_error=True, close_error=True)
    with pytest.raises(bl.BrowserLoginError, match="transport_failed") as caught:
        execute(browser)
    assert caught.value.receipt["cleanup_failed"] is True


def test_contexts_do_not_reuse_authenticated_state_across_principals():
    first = Browser()
    second = Browser(bad_password=True)
    assert execute(first)["authentication_verified"] is True
    with pytest.raises(bl.BrowserLoginError, match="authentication_rejected"):
        execute(second, values=bl.BrowserLoginValues("other-principal", "other-password"))
    assert second.values == ["other-principal", "other-password"]
    assert not second.authenticated


@pytest.mark.parametrize("headers", [
    {"Location": "https://outside.test/private"},
    {"Location": "//outside.test/private"},
    {"Location": "http://login-fixture.test/private"},
    {"Location": ORIGIN + ":8443/private"},
    {"Location": "/account", "location": "https://outside.test/private"},
    {"Location": "\\\\outside.test/private"},
    {"Location": "\nhttps://outside.test/private"},
    {},
])
def test_unapproved_or_ambiguous_redirects_never_reach_the_browser(headers):
    browser = Browser()
    async def transport(request, phase):
        return bl.BrowserLoginResponse(302, headers, b"")
    browser.transport = transport
    with pytest.raises(bl.BrowserLoginError, match="transport_failed"):
        execute(browser)
    assert browser.values == []
    assert browser.closed


@pytest.mark.parametrize("status", [307, 308])
def test_preserving_redirect_cannot_repeat_the_login_post(status):
    browser = Browser()
    original = browser.transport
    async def transport(request, phase):
        if request.method == "POST":
            return bl.BrowserLoginResponse(status, {"Location": "/session"}, b"")
        return await original(request, phase)
    browser.transport = transport
    with pytest.raises(bl.BrowserLoginError) as caught:
        execute(browser)
    assert not caught.value.receipt["authentication_verified"]
    assert caught.value.receipt["login_submissions"] == 1
    assert browser.closed
