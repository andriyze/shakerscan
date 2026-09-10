"""Operator-authored login and read-only QA in an isolated browser context.

This is an internal helper, not a registered Scan/Hunt capability. ``transport``
MUST reuse the caller's target binding, credential authority, approval, budget and
pinned HTTP executor. Browser requests are fulfilled, never continued directly.
No credential store, planner, attack dispatcher, or public endpoint is added here.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Awaitable, Callable, Mapping
from urllib.parse import urljoin, urlsplit, urlunsplit

try:
    from scanner_tools.browser_profile import _origin
except ModuleNotFoundError:
    from scanner.scanner_tools.browser_profile import _origin


@dataclass(frozen=True, repr=False)
class BrowserLoginValues:
    username: str = field(repr=False)
    password: str = field(repr=False)

    def __repr__(self) -> str:
        return "BrowserLoginValues(values_visible=False)"


@dataclass(frozen=True, repr=False)
class BrowserLoginWorkflow:
    origin: str
    login_url: str
    submit_url: str
    check_url: str
    username_selector: str
    password_selector: str
    submit_selector: str
    authenticated_selector: str
    rejected_selector: str
    challenge_selector: str | None = None
    timeout_ms: int = 30_000
    max_requests: int = 64
    max_response_bytes: int = 2 * 1024 * 1024

    def __repr__(self) -> str:
        return "BrowserLoginWorkflow(operator_defined=True, values_visible=False)"


@dataclass(frozen=True, repr=False)
class BrowserLoginResponse:
    status: int
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)

    def __repr__(self) -> str:
        return f"BrowserLoginResponse(status={self.status}, values_visible=False)"


class BrowserLoginError(ValueError):
    def __init__(self, reason: str, receipt: Mapping[str, Any]):
        super().__init__(reason)
        self.receipt = dict(receipt)


BrowserLoginTransport = Callable[[Any, str], Awaitable[BrowserLoginResponse]]


def _url(value: str, origin: str, *, fragment: bool = True) -> str:
    if not isinstance(value, str) or len(value) > 2_000 or "\\" in value:
        raise ValueError("invalid workflow URL")
    if _origin(value) != origin:
        raise ValueError("workflow URL differs from origin")
    parts = urlsplit(value)
    if not fragment and parts.fragment:
        raise ValueError("submit URL has a fragment")
    return urlunsplit((parts.scheme.lower(), urlsplit(origin).netloc,
                      parts.path or "/", parts.query, parts.fragment))


def _validate(workflow: BrowserLoginWorkflow, values: BrowserLoginValues) -> str:
    origin = _origin(workflow.origin)
    if workflow.origin.rstrip("/") != origin or urlsplit(origin).port == 0:
        raise ValueError("origin must be canonical")
    for value in (workflow.login_url, workflow.check_url):
        if _url(value, origin) != value:
            raise ValueError("workflow URL must be canonical")
    if _url(workflow.submit_url, origin, fragment=False) != workflow.submit_url:
        raise ValueError("submit URL must be canonical")
    selectors = [workflow.username_selector, workflow.password_selector,
                 workflow.submit_selector, workflow.authenticated_selector,
                 workflow.rejected_selector]
    if workflow.challenge_selector is not None:
        selectors.append(workflow.challenge_selector)
    for selector in selectors:
        if (not isinstance(selector, str) or not selector.strip() or len(selector) > 300
                or ">>" in selector or any(ord(c) < 32 or ord(c) == 127 for c in selector)):
            raise ValueError("invalid CSS selector")
    if len(set(selectors)) != len(selectors):
        raise ValueError("workflow selectors must be distinct")
    for value in (values.username, values.password):
        if not isinstance(value, str) or not value or len(value) > 4_096 or "\x00" in value:
            raise ValueError("invalid private login values")
    for value, minimum, maximum in (
        (workflow.timeout_ms, 100, 120_000), (workflow.max_requests, 3, 500),
        (workflow.max_response_bytes, 1_024, 8 * 1024 * 1024),
    ):
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError("invalid browser login ceiling")
    return origin


async def browser_authentication_state(page: Any, workflow: BrowserLoginWorkflow) -> str:
    """Observe operator-defined DOM assertions; never infer from a cookie or HTTP 200.

    Callers can use this after a read-only protected-page navigation to detect
    session expiry. It does not navigate, reauthenticate, or retry credentials.
    """
    try:
        if _origin(page.url) != _origin(workflow.origin):
            return "out_of_scope"
        if workflow.challenge_selector and await page.locator("css=" + workflow.challenge_selector).is_visible():
            return "requires_user_action"
        if await page.locator("css=" + workflow.rejected_selector).is_visible():
            return "authentication_rejected"
        if await page.locator("css=" + workflow.authenticated_selector).is_visible():
            return "authenticated"
        return "unknown"
    except Exception:
        return "verification_unavailable"


@asynccontextmanager
async def authenticated_browser_page(
    browser: Any, *, workflow: BrowserLoginWorkflow,
    values: BrowserLoginValues, transport: BrowserLoginTransport,
) -> AsyncIterator[tuple[Any, Mapping[str, Any]]]:
    """Yield a verified functional-test page; close its private context on exit.

    One explicit POST is permitted only during submission. All later browsing
    permits only GET/HEAD/OPTIONS. The transport must fail closed on expired or
    revoked authority and count actual wire use; route admissions are not a wire
    log. Credentials and browser state never appear in the receipt or on disk.
    The caller must not add routing handlers or otherwise alter this context.
    """
    receipt: dict[str, Any] = {
        "schema_version": "browser-login-check/v1", "status": "not_started",
        "authentication_verified": False, "verification_basis": "operator_dom_assertion",
        "requests_routed": 0, "requests_blocked": 0, "login_submissions": 0, "login_response_status": None,
        "responses_received": 0, "cleanup_failed": False,
        "secret_values_visible": False,
    }

    def fail(reason: str) -> BrowserLoginError:
        receipt.update(status=reason, authentication_verified=False)
        return BrowserLoginError(reason, receipt)

    try:
        origin = _validate(workflow, values)
        if not callable(transport):
            raise ValueError("authorized transport is required")
    except Exception:
        raise fail("invalid_workflow") from None

    phase = "load"
    context = None
    transport_failed = False
    budget_exhausted = False
    started = asyncio.get_running_loop().time()

    async def route_request(route: Any) -> None:
        nonlocal transport_failed, budget_exhausted
        request = route.request
        try:
            url = _url(request.url, origin, fragment=False)
            method = request.method
            write = method == "POST"
            allowed = method in {"GET", "HEAD", "OPTIONS"} or (
                write and phase == "login" and url == workflow.submit_url
                and receipt["login_submissions"] == 0
            )
            if not allowed:
                raise ValueError("request is not part of this login or read-only check")
            if receipt["requests_routed"] >= workflow.max_requests:
                budget_exhausted = True
                raise ValueError("local request ceiling reached")
        except Exception:
            receipt["requests_blocked"] += 1
            await route.abort("blockedbyclient")
            return
        # No await before reservation: concurrent requests cannot claim the same
        # single login slot. The transport also enforces the durable reservation.
        receipt["requests_routed"] += 1
        if write:
            receipt["login_submissions"] += 1
        try:
            remaining = workflow.timeout_ms / 1000
            if phase != "read_only":
                remaining -= asyncio.get_running_loop().time() - started
            response = await asyncio.wait_for(transport(request, phase), timeout=max(0, remaining))
            if (not isinstance(response, BrowserLoginResponse)
                    or type(response.status) is not int or not 200 <= response.status <= 599
                    or not isinstance(response.body, bytes)
                    or len(response.body) > workflow.max_response_bytes):
                raise ValueError("invalid private transport response")
            receipt["responses_received"] += 1
            if write:
                receipt["login_response_status"] = response.status
            headers = {name: value for name, value in response.headers.items()
                       if name.lower() not in {"content-length", "transfer-encoding", "connection"}}
            locations = [value for name, value in headers.items() if name.lower() == "location"]
            if locations:
                if (len(locations) != 1 or not isinstance(locations[0], str)
                        or any(ord(c) <= 0x20 or ord(c) == 127 for c in locations[0])
                        or "\\" in locations[0]):
                    raise ValueError("invalid redirect location")
                _url(urljoin(url, locations[0]), origin)
            if response.status in {301, 302, 303, 307, 308}:
                if not locations or (write and response.status in {307, 308}):
                    # A preserving redirect would re-submit credentials, while
                    # this helper admits exactly one login POST, never a retry.
                    raise ValueError("unsupported login redirect")
            # Reject off-origin Location before Chromium sees the response,
            # independently of redirect interception in the browser build.
            await route.fulfill(status=response.status, headers=headers, body=response.body)
        except Exception:
            transport_failed = True
            await route.abort("failed")

    async def deny_websocket(route: Any) -> None:
        receipt["requests_blocked"] += 1
        await route.close()

    async def close_context() -> None:
        try:
            await asyncio.wait_for(context.close(), timeout=5)
        except BaseException:
            receipt["cleanup_failed"] = True
            raise

    async def verify(page: Any) -> None:
        while True:
            state = await browser_authentication_state(page, workflow)
            if state in {"requires_user_action", "authentication_rejected", "out_of_scope"}:
                raise fail(state)
            if state == "verification_unavailable" or transport_failed or budget_exhausted:
                raise fail("verification_incomplete")
            status = receipt["login_response_status"]
            if status is not None and status >= 400:
                raise fail("authentication_rejected")
            if state == "authenticated":
                return
            await asyncio.sleep(0.05)

    try:
        async with asyncio.timeout(workflow.timeout_ms / 1000):
            context = await browser.new_context(service_workers="block", accept_downloads=False)
            await context.route("**/*", route_request)
            await context.route_web_socket("**/*", deny_websocket)
            context.set_default_timeout(workflow.timeout_ms)
            page = await context.new_page()
            await page.goto(workflow.login_url, wait_until="domcontentloaded")
            if await page.locator("css=" + workflow.authenticated_selector).is_visible():
                raise fail("ambiguous_success_assertion")
            if workflow.challenge_selector and await page.locator("css=" + workflow.challenge_selector).is_visible():
                raise fail("requires_user_action")
            if _origin(page.url) != origin or transport_failed or budget_exhausted:
                raise fail("login_page_unavailable")
            await page.locator("css=" + workflow.username_selector).fill(values.username)
            await page.locator("css=" + workflow.password_selector).fill(values.password)
            phase = "login"
            await page.locator("css=" + workflow.submit_selector).click()
            await verify(page)
            phase = "verify"
            if receipt["login_submissions"] != 1 or receipt["login_response_status"] is None:
                raise fail("login_submission_not_observed")
            # Fresh navigation checks that the protected view survives the login
            # UI transition, for cookie- and browser-storage-backed applications.
            await page.goto(workflow.check_url, wait_until="domcontentloaded")
            await verify(page)
        phase = "read_only"
        receipt.update(status="authenticated", authentication_verified=True)
    except BaseException as error:
        if context is not None:
            try:
                await close_context()
            except Exception:
                pass
        if isinstance(error, BrowserLoginError):
            error.receipt = dict(receipt)
            raise
        if isinstance(error, asyncio.CancelledError):
            if receipt["cleanup_failed"]:
                error.add_note("Private browser context cleanup failed; worker teardown is required.")
            raise
        if not isinstance(error, Exception):
            raise
        reason = "request_limit_reached" if budget_exhausted else (
            "transport_failed" if transport_failed else (
                "login_timed_out" if isinstance(error, TimeoutError) else "browser_login_failed"
            )
        )
        raise fail(reason) from None

    try:
        yield page, dict(receipt)
    except BaseException:
        try:
            await close_context()
        except Exception:
            pass
        raise
    else:
        try:
            await close_context()
        except Exception:
            raise fail("browser_cleanup_failed") from None
