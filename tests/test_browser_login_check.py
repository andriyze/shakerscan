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
            return bool(flags.get("rejected") or (
                self.page.url == SPEC.check_url and not self.page.browser.authenticated
                and not flags.get("protected_public_marker") and not flags.get("anonymous_unknown")
            ))
        if self.selector == SPEC.authenticated_selector:
            return bool(flags.get("public_marker") or self.page.browser.authenticated or (
                flags.get("protected_public_marker") and self.page.url == SPEC.check_url
            ))
        return True

    async def fill(self, value):
        if self.page.browser.flags.get("cancel"):
            raise asyncio.CancelledError()
        self.page.browser.values.append(value)

    async def wait_for(self, **kwargs):
        if self.page.browser.flags.get("qa_assertion_missing") or not await self.is_visible():
            raise RuntimeError(SECRET)

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
        if url == SPEC.check_url and self.browser.authenticated and self.browser.flags.get("expires"):
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
    assert receipt["responses_received"] == receipt["requests_routed"] == 5
    assert receipt["anonymous_check_verified"] is True
    assert receipt["qa_completed"] is True
    assert receipt["context_closed"] is True
    assert receipt["verification_basis"] == "operator_dom_assertion"
    assert browser.values == [VALUES.username, VALUES.password]
    assert [phase for _, _, phase in browser.calls] == [
        "anonymous", "load", "login", "verify", "read_only",
    ]
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
    with pytest.raises(bl.BrowserLoginError, match="authentication_rejected"):
        asyncio.run(scenario())
    assert browser.closed


def test_request_ceiling_applies_after_login_as_well():
    browser = Browser()
    async def scenario():
        async with bl.authenticated_browser_page(
            browser, workflow=replace(SPEC, max_requests=4), values=VALUES,
            transport=browser.transport,
        ):
            assert (await browser.send(ORIGIN + "/one-more")).aborted
    with pytest.raises(bl.BrowserLoginError, match="request_limit_reached"):
        asyncio.run(scenario())
    assert len(browser.calls) == 4


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


def test_public_protected_marker_fails_before_filling_credentials():
    browser = Browser(protected_public_marker=True)
    with pytest.raises(bl.BrowserLoginError, match="ambiguous_success_assertion"):
        execute(browser)
    assert browser.values == []
    assert not any(method == "POST" for method, _, _ in browser.calls)
    assert browser.closed


def test_missing_anonymous_negative_signal_is_not_accepted():
    browser = Browser(anonymous_unknown=True)
    with pytest.raises(bl.BrowserLoginError, match="anonymous_verification_incomplete"):
        execute(browser)
    assert browser.values == []
    assert browser.closed


def test_live_receipt_is_read_only_and_tracks_post_login_requests():
    browser = Browser()
    async def scenario():
        async with bl.authenticated_browser_page(
            browser, workflow=SPEC, values=VALUES, transport=browser.transport,
        ) as (page, receipt):
            before = receipt["requests_routed"]
            await page.goto(ORIGIN + "/help")
            assert receipt["requests_routed"] == before + 1
            with pytest.raises(TypeError):
                receipt["authentication_verified"] = False
        assert receipt["status"] == "completed"
        assert receipt["context_closed"] is True
        assert receipt["qa_completed"] is True
        assert receipt["requests_routed"] == len(browser.calls)
    asyncio.run(scenario())


def test_post_login_transport_failure_cannot_finish_with_success():
    browser = Browser()
    async def scenario():
        with pytest.raises(bl.BrowserLoginError, match="transport_failed") as caught:
            async with bl.authenticated_browser_page(
                browser, workflow=SPEC, values=VALUES, transport=browser.transport,
            ) as (_, receipt):
                browser.flags["transport_error"] = True
                assert (await browser.send(ORIGIN + "/help")).aborted
                assert receipt["authentication_verified"] is False
        assert not receipt["authentication_verified"]
        assert caught.value.receipt["status"] == "transport_failed"
        assert receipt["context_closed"] is True
    asyncio.run(scenario())


def test_expiry_after_login_is_detected_at_context_exit():
    browser = Browser()
    async def scenario():
        with pytest.raises(bl.BrowserLoginError, match="authentication_rejected"):
            async with bl.authenticated_browser_page(
                browser, workflow=SPEC, values=VALUES, transport=browser.transport,
            ) as (_, receipt):
                browser.authenticated = False
                browser.flags["rejected"] = True
        assert not receipt["authentication_verified"]
        assert receipt["qa_completed"] is False
    asyncio.run(scenario())
    assert browser.closed


@pytest.mark.parametrize("headers", [
    {"Content-Type": "text/html\r\nX-Secret: private"},
    {"content-type": "text/html", "Content-Type": "text/plain"},
    {"bad name": "value"}, {"X-Example": None}, {"X-Example": "a\x00b"},
    {"X-Example": "x" * 65_537}, {str(i): "value" for i in range(129)},
])
def test_malformed_transport_headers_fail_before_browser_fulfillment(headers):
    browser = Browser()
    async def transport(request, phase):
        return bl.BrowserLoginResponse(200, headers, b"synthetic")
    browser.transport = transport
    with pytest.raises(bl.BrowserLoginError, match="transport_failed"):
        execute(browser)
    assert browser.values == []
    assert browser.closed


@pytest.mark.parametrize("password", ["\ud800", "\u20ac" * 2_000], ids=["surrogate", "byte-limit"])
def test_private_values_must_fit_the_utf8_byte_contract(password):
    browser = Browser()
    with pytest.raises(bl.BrowserLoginError, match="invalid_workflow"):
        execute(browser, values=bl.BrowserLoginValues("name", password))
    assert browser.values == browser.calls == []


def test_post_login_browser_error_is_sanitized_and_invalidates_receipt():
    browser = Browser()
    async def scenario():
        with pytest.raises(bl.BrowserLoginError, match="browser_check_failed") as caught:
            async with bl.authenticated_browser_page(
                browser, workflow=SPEC, values=VALUES, transport=browser.transport,
            ) as (_, receipt):
                raise RuntimeError(SECRET)
        assert SECRET not in "".join(traceback.format_exception(caught.value))
        assert not receipt["authentication_verified"]
        assert receipt["context_closed"] is True
    asyncio.run(scenario())


def test_background_transport_failure_is_settled_before_success():
    browser = Browser()
    original = browser.transport
    async def transport(request, phase):
        if request.url.endswith("/late"):
            await asyncio.sleep(0.02)
            raise RuntimeError(SECRET)
        return await original(request, phase)
    browser.transport = transport
    async def scenario():
        with pytest.raises(bl.BrowserLoginError, match="transport_failed"):
            async with bl.authenticated_browser_page(
                browser, workflow=SPEC, values=VALUES, transport=browser.transport,
            ) as (_, receipt):
                task = asyncio.create_task(browser.send(ORIGIN + "/late"))
                await asyncio.sleep(0)
        await task
        assert receipt["requests_in_flight"] == 0
        assert not receipt["authentication_verified"]
    asyncio.run(scenario())


def test_fixed_qa_deadline_is_enforced_without_changing_login_timeout():
    browser = Browser()
    async def scenario():
        with pytest.raises(bl.BrowserLoginError, match="browser_check_timed_out"):
            async with bl.authenticated_browser_page(
                browser, workflow=replace(SPEC, qa_timeout_ms=100),
                values=VALUES, transport=browser.transport,
            ) as (_, receipt):
                await asyncio.sleep(1)
        assert not receipt["authentication_verified"]
        assert receipt["context_closed"] is True
    asyncio.run(scenario())


@pytest.mark.parametrize("ceiling", [True, 0, 99, 120001, "1000"])
def test_qa_timeout_is_validated_before_browser_work(ceiling):
    browser = Browser()
    with pytest.raises(bl.BrowserLoginError, match="invalid_workflow"):
        execute(browser, spec=replace(SPEC, qa_timeout_ms=ceiling))
    assert browser.calls == []


def test_anonymous_redirect_to_exact_login_form_is_a_negative_control(monkeypatch):
    original = Page.goto
    async def redirect_anonymous(self, url, **kwargs):
        await original(self, url, **kwargs)
        if url == SPEC.check_url and not self.browser.authenticated:
            self.url = SPEC.login_url
    monkeypatch.setattr(Page, "goto", redirect_anonymous)
    browser = Browser()
    assert execute(browser)["anonymous_check_verified"] is True


def test_first_transport_failure_blocks_later_admissions():
    browser = Browser()
    async def scenario():
        with pytest.raises(bl.BrowserLoginError, match="transport_failed"):
            async with bl.authenticated_browser_page(
                browser, workflow=SPEC, values=VALUES, transport=browser.transport,
            ):
                browser.flags["transport_error"] = True
                assert (await browser.send(ORIGIN + "/help")).aborted
                count = len(browser.calls)
                browser.flags["transport_error"] = False
                assert (await browser.send(ORIGIN + "/later")).aborted
                assert len(browser.calls) == count
    asyncio.run(scenario())


def test_success_waits_for_admitted_background_response():
    browser = Browser()
    original = browser.transport
    async def transport(request, phase):
        if request.url.endswith("/late"):
            await asyncio.sleep(0.02)
        return await original(request, phase)
    browser.transport = transport
    async def scenario():
        async with bl.authenticated_browser_page(
            browser, workflow=SPEC, values=VALUES, transport=browser.transport,
        ) as (_, receipt):
            task = asyncio.create_task(browser.send(ORIGIN + "/late"))
            await asyncio.sleep(0)
            assert receipt["requests_in_flight"] == 1
        assert task.done()
        assert receipt["requests_in_flight"] == 0
        assert receipt["responses_received"] == receipt["requests_routed"] == 6
        assert receipt["qa_completed"] is True
    asyncio.run(scenario())


@pytest.mark.parametrize("close_error", [False, True])
def test_post_login_cancellation_invalidates_live_receipt(close_error):
    browser = Browser(close_error=close_error)
    async def scenario():
        with pytest.raises(asyncio.CancelledError) as caught:
            async with bl.authenticated_browser_page(
                browser, workflow=SPEC, values=VALUES, transport=browser.transport,
            ) as (_, receipt):
                raise asyncio.CancelledError()
        assert receipt["status"] == "cancelled"
        assert not receipt["authentication_verified"]
        assert receipt["cleanup_failed"] is close_error
        if close_error:
            assert any("cleanup failed" in note for note in caught.value.__notes__)
    asyncio.run(scenario())


def test_hop_headers_and_connection_nominations_do_not_reach_chromium():
    assert bl._response_headers({
        "Content-Type": "text/html", "Connection": "X-Hop, keep-alive", "X-Hop": "private",
        "Keep-Alive": "timeout=5", "Content-Length": "123", "Transfer-Encoding": "chunked",
    }) == {"content-type": "text/html"}


def test_fixed_qa_wrapper_returns_only_finalized_content_free_results():
    browser = Browser()
    result = asyncio.run(bl.run_browser_login_checks(
        browser, workflow=SPEC, values=VALUES, transport=browser.transport,
        checks=(bl.BrowserReadOnlyCheck(ORIGIN + "/help", "#help"),
                bl.BrowserReadOnlyCheck(SPEC.check_url, SPEC.authenticated_selector)),
    ))
    assert result["status"] == "completed"
    assert result["qa_completed"] is True
    assert result["context_closed"] is True
    assert result["checks_requested"] == result["checks_completed"] == 2
    assert result["checks"] == [{"index": 0, "status": "passed"}, {"index": 1, "status": "passed"}]
    assert result["requests_routed"] == len(browser.calls) == 7
    assert SECRET not in repr(result)
    assert ORIGIN not in repr(result)
    assert "#help" not in repr(result)
    assert browser.closed


@pytest.mark.parametrize("checks", [
    [None], "not-a-plan", [bl.BrowserReadOnlyCheck("https://outside.test/", "#help")],
    [bl.BrowserReadOnlyCheck(ORIGIN + "/help", "css=#help >> text=private")],
    [bl.BrowserReadOnlyCheck(ORIGIN + "/help", "")],
    [bl.BrowserReadOnlyCheck(ORIGIN + "/help", "#help")] * 21,
])
def test_fixed_qa_plan_is_validated_before_login(checks):
    browser = Browser()
    with pytest.raises(bl.BrowserLoginError, match="invalid_qa_plan"):
        asyncio.run(bl.run_browser_login_checks(
            browser, workflow=SPEC, values=VALUES, transport=browser.transport, checks=checks,
        ))
    assert browser.calls == browser.values == []


def test_fixed_qa_failure_retains_partial_results_but_not_browser_diagnostics():
    browser = Browser(qa_assertion_missing=True)
    with pytest.raises(bl.BrowserLoginError, match="browser_check_failed") as caught:
        asyncio.run(bl.run_browser_login_checks(
            browser, workflow=SPEC, values=VALUES, transport=browser.transport,
            checks=(bl.BrowserReadOnlyCheck(ORIGIN + "/help", "#help"),),
        ))
    assert caught.value.receipt["checks_completed"] == 0
    assert caught.value.receipt["checks"] == [{"index": 0, "status": "incomplete"}]
    assert not caught.value.receipt["qa_completed"]
    assert not caught.value.receipt["authentication_verified"]
    assert SECRET not in "".join(traceback.format_exception(caught.value))
    assert browser.closed


def test_fixed_qa_authentication_only_still_performs_final_session_check():
    browser = Browser()
    result = asyncio.run(bl.run_browser_login_checks(
        browser, workflow=SPEC, values=VALUES, transport=browser.transport,
    ))
    assert result["checks"] == []
    assert result["requests_routed"] == 5
    assert result["status"] == "completed"


def test_request_started_during_final_dom_lookup_is_settled(monkeypatch):
    browser = Browser()
    original_transport = browser.transport
    original_visible = Locator.is_visible
    tasks = []
    async def transport(request, phase):
        if request.url.endswith("/late"):
            await asyncio.sleep(0.02)
            raise RuntimeError(SECRET)
        return await original_transport(request, phase)
    async def visible(self):
        if (self.selector == SPEC.authenticated_selector and browser.calls
                and browser.calls[-1][-1] == "read_only" and not tasks):
            tasks.append(asyncio.create_task(browser.send(ORIGIN + "/late")))
            await asyncio.sleep(0)
        return await original_visible(self)
    monkeypatch.setattr(Locator, "is_visible", visible)
    browser.transport = transport
    async def scenario():
        with pytest.raises(bl.BrowserLoginError, match="transport_failed"):
            async with bl.authenticated_browser_page(
                browser, workflow=SPEC, values=VALUES, transport=browser.transport,
            ) as (_, receipt):
                pass
        assert tasks and all(task.done() for task in tasks)
        assert not receipt["qa_completed"]
        assert not receipt["authentication_verified"]
        assert receipt["requests_in_flight"] == 0
    asyncio.run(scenario())
