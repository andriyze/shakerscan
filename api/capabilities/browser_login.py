"""Operator-authored login and read-only QA in an isolated browser context.

This is an internal helper, not a registered Scan/Hunt capability. ``transport``
MUST reuse the caller's target binding, credential authority, approval, budget and
pinned HTTP executor. Browser requests are fulfilled, never continued directly.
No credential store, planner, attack dispatcher, or public endpoint is added here.
"""
from __future__ import annotations

import asyncio
import re
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from types import MappingProxyType
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
    qa_timeout_ms: int = 60_000

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


def _validate_selector(selector: str) -> None:
    if (not isinstance(selector, str) or not selector.strip() or len(selector) > 300
            or ">>" in selector or any(ord(c) < 32 or ord(c) == 127 for c in selector)):
        raise ValueError("invalid CSS selector")


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
        _validate_selector(selector)
    if len(set(selectors)) != len(selectors):
        raise ValueError("workflow selectors must be distinct")
    for value in (values.username, values.password):
        if (not isinstance(value, str) or not value or len(value) > 4_096
                or "\x00" in value or len(value.encode("utf-8")) > 4_096):
            raise ValueError("invalid private login values")
    for value, minimum, maximum in (
        (workflow.timeout_ms, 100, 120_000), (workflow.max_requests, 3, 500),
        (workflow.max_response_bytes, 1_024, 8 * 1024 * 1024),
        (workflow.qa_timeout_ms, 100, 120_000),
    ):
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError("invalid browser login ceiling")
    return origin


def _response_headers(values: Mapping[str, str]) -> dict[str, str]:
    """Validate a bounded header map before handing it to Chromium.

    Duplicate field names (including differently cased Set-Cookie) cannot be
    represented faithfully by this interface and must not be silently folded.
    """
    if not isinstance(values, Mapping) or len(values) > 128:
        raise ValueError("invalid private response headers")
    result: dict[str, str] = {}
    total = 0
    for name, value in values.items():
        if (not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,120}", name)
                or not isinstance(value, str) or len(value) > 65_536
                or any((ord(c) < 32 and c != "\t") or ord(c) == 127 for c in value)):
            raise ValueError("invalid private response headers")
        lowered = name.lower()
        if lowered in result:
            raise ValueError("ambiguous private response headers")
        total += len(name) + len(value.encode("latin-1"))
        if total > 65_536:
            raise ValueError("private response headers exceeded limit")
        result[lowered] = value
    connection_fields = {name.strip().lower() for name in result.get("connection", "").split(",")}
    for name in connection_fields | {
        "content-length", "transfer-encoding", "connection", "keep-alive",
        "proxy-authenticate", "proxy-authorization", "te", "trailer", "upgrade",
    }:
        result.pop(name, None)
    return result


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
    The receipt is a live read-only view. Only normal context exit after a final
    protected-page verification and cleanup sets ``qa_completed`` to true.
    """
    receipt: dict[str, Any] = {
        "schema_version": "browser-login-check/v1", "status": "not_started",
        "authentication_verified": False, "verification_basis": "operator_dom_assertion",
        "requests_routed": 0, "requests_blocked": 0, "login_submissions": 0, "login_response_status": None,
        "responses_received": 0, "requests_in_flight": 0, "cleanup_failed": False,
        "anonymous_check_verified": False, "qa_completed": False, "context_closed": False,
        "secret_values_visible": False,
    }

    def fail(reason: str) -> BrowserLoginError:
        receipt.update(status=reason, authentication_verified=False, qa_completed=False)
        return BrowserLoginError(reason, receipt)

    try:
        origin = _validate(workflow, values)
        if not callable(transport):
            raise ValueError("authorized transport is required")
    except Exception:
        raise fail("invalid_workflow") from None

    phase = "load"
    context = None
    fatal_reason: str | None = None
    idle = asyncio.Event()
    idle.set()
    started = asyncio.get_running_loop().time()

    def fault(reason: str) -> None:
        nonlocal fatal_reason
        fatal_reason = fatal_reason or reason
        receipt.update(status=fatal_reason, authentication_verified=False, qa_completed=False)

    def check_health() -> None:
        if fatal_reason:
            raise fail(fatal_reason)

    async def abort(route: Any, reason: str) -> None:
        try:
            await route.abort(reason)
        except Exception:
            fault("browser_route_failed")

    async def route_request(route: Any) -> None:
        request = route.request
        try:
            if fatal_reason or phase == "closed":
                raise ValueError("browser check no longer admits requests")
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
                fault("request_limit_reached")
                raise ValueError("local request ceiling reached")
        except Exception:
            receipt["requests_blocked"] += 1
            await abort(route, "blockedbyclient")
            return
        # No await before reservation: concurrent requests cannot claim the same
        # single login slot. The transport also enforces the durable reservation.
        receipt["requests_routed"] += 1
        receipt["requests_in_flight"] += 1
        idle.clear()
        if write:
            receipt["login_submissions"] += 1
        try:
            remaining = workflow.timeout_ms / 1000
            if phase != "read_only":
                remaining -= asyncio.get_running_loop().time() - started
            response = await asyncio.wait_for(transport(request, phase), timeout=max(0, remaining))
            check_health()
            if (not isinstance(response, BrowserLoginResponse)
                    or type(response.status) is not int or not 200 <= response.status <= 599
                    or not isinstance(response.body, bytes)
                    or len(response.body) > workflow.max_response_bytes):
                raise ValueError("invalid private transport response")
            headers = _response_headers(response.headers)
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
            receipt["responses_received"] += 1
            if write:
                receipt["login_response_status"] = response.status
            await route.fulfill(status=response.status, headers=headers, body=response.body)
        except asyncio.CancelledError:
            fault("transport_cancelled")
            raise
        except Exception:
            fault("transport_failed")
            await abort(route, "failed")
        finally:
            receipt["requests_in_flight"] -= 1
            if receipt["requests_in_flight"] == 0:
                idle.set()

    async def deny_websocket(route: Any) -> None:
        receipt["requests_blocked"] += 1
        try:
            await route.close()
        except Exception:
            fault("browser_route_failed")

    async def close_context() -> None:
        nonlocal phase
        phase = "closed"
        try:
            await asyncio.wait_for(context.close(), timeout=5)
            receipt["context_closed"] = True
        except BaseException:
            receipt["cleanup_failed"] = True
            raise

    async def verify(page: Any) -> None:
        while True:
            await idle.wait()
            check_health()
            state = await browser_authentication_state(page, workflow)
            if state in {"requires_user_action", "authentication_rejected", "out_of_scope"}:
                raise fail(state)
            if state == "verification_unavailable":
                raise fail("verification_incomplete")
            status = receipt["login_response_status"]
            if status is not None and status >= 400:
                raise fail("authentication_rejected")
            if state == "authenticated":
                # DOM lookups await the browser and can admit a new background
                # request. Settle that work as well before returning success.
                await idle.wait()
                check_health()
                return
            await asyncio.sleep(0.05)

    async def anonymous_control(page: Any) -> None:
        """Check the same protected assertion without submitting credentials."""
        await page.goto(workflow.check_url, wait_until="domcontentloaded")
        while True:
            await idle.wait()
            check_health()
            state = await browser_authentication_state(page, workflow)
            if state == "authenticated":
                raise fail("ambiguous_success_assertion")
            if state in {"requires_user_action", "out_of_scope", "verification_unavailable"}:
                raise fail(state)
            if state == "authentication_rejected":
                break
            # A protected page may redirect anonymous users to the login form.
            if (_url(page.url, origin) == workflow.login_url
                    and await page.locator("css=" + workflow.username_selector).is_visible()
                    and await page.locator("css=" + workflow.password_selector).is_visible()):
                break
            await asyncio.sleep(0.05)
        receipt["anonymous_check_verified"] = True

    async def close_after_error(error: BaseException) -> None:
        if context is not None:
            try:
                await close_context()
            except BaseException:
                # Retain the primary error, particularly caller cancellation.
                # close_context recorded a fixed cleanup flag, never diagnostics.
                pass
        if receipt["cleanup_failed"] and isinstance(error, asyncio.CancelledError):
            error.add_note("Private browser context cleanup failed; worker teardown is required.")

    try:
        async with asyncio.timeout(workflow.timeout_ms / 1000):
            context = await browser.new_context(service_workers="block", accept_downloads=False)
            await context.route("**/*", route_request)
            await context.route_web_socket("**/*", deny_websocket)
            context.set_default_timeout(workflow.timeout_ms)
            page = await context.new_page()
            phase = "anonymous"
            await anonymous_control(page)
            phase = "load"
            await page.goto(workflow.login_url, wait_until="domcontentloaded")
            if await page.locator("css=" + workflow.authenticated_selector).is_visible():
                raise fail("ambiguous_success_assertion")
            if workflow.challenge_selector and await page.locator("css=" + workflow.challenge_selector).is_visible():
                raise fail("requires_user_action")
            check_health()
            if _origin(page.url) != origin:
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
        error_phase = phase
        await close_after_error(error)
        if isinstance(error, BrowserLoginError):
            error.receipt = dict(receipt)
            raise
        if isinstance(error, asyncio.CancelledError):
            receipt.update(status="cancelled", authentication_verified=False)
            raise
        if not isinstance(error, Exception):
            raise
        reason = fatal_reason or (
            "anonymous_verification_incomplete" if error_phase == "anonymous" else
            "login_timed_out" if isinstance(error, TimeoutError) else "browser_login_failed"
        )
        raise fail(reason) from None

    try:
        async with asyncio.timeout(workflow.qa_timeout_ms / 1000):
            yield page, MappingProxyType(receipt)
            # Settle admitted work, then recheck the protected view. A successful
            # login is not successful QA when the session or transport later fails.
            await idle.wait()
            check_health()
            await page.goto(workflow.check_url, wait_until="domcontentloaded")
            await verify(page)
    except BaseException as error:
        receipt.update(authentication_verified=False, qa_completed=False)
        await close_after_error(error)
        if isinstance(error, BrowserLoginError):
            error.receipt = dict(receipt)
            raise
        if isinstance(error, asyncio.CancelledError):
            receipt["status"] = "cancelled"
            raise
        if not isinstance(error, Exception):
            raise
        raise fail(fatal_reason or (
            "browser_check_timed_out" if isinstance(error, TimeoutError) else "browser_check_failed"
        )) from None
    else:
        try:
            await close_context()
        except asyncio.CancelledError:
            receipt.update(status="cancelled", authentication_verified=False)
            raise
        except Exception:
            raise fail("browser_cleanup_failed") from None
        check_health()
        receipt.update(status="completed", qa_completed=True)


@dataclass(frozen=True, repr=False)
class BrowserReadOnlyCheck:
    """One operator-authored GET navigation and visible-element assertion."""

    url: str
    visible_selector: str

    def __repr__(self) -> str:
        return "BrowserReadOnlyCheck(operator_defined=True, values_visible=False)"


async def run_browser_login_checks(
    browser: Any, *, workflow: BrowserLoginWorkflow, values: BrowserLoginValues,
    transport: BrowserLoginTransport, checks: tuple[BrowserReadOnlyCheck, ...] = (),
) -> dict[str, Any]:
    """Run bounded functional checks without giving the caller a live page.

    This internal wrapper consumes the same caller-owned authority/transport as
    authenticated_browser_page. It does not resolve secrets or publish a session.
    Only check indices/statuses and the finalized content-free receipt are returned.
    """
    try:
        origin = _validate(workflow, values)
        if not isinstance(checks, (tuple, list)) or len(checks) > 20:
            raise ValueError("invalid read-only QA plan")
        selected = tuple(checks)
        for check in selected:
            if not isinstance(check, BrowserReadOnlyCheck) or _url(check.url, origin) != check.url:
                raise ValueError("invalid read-only QA navigation")
            _validate_selector(check.visible_selector)
    except Exception:
        raise BrowserLoginError("invalid_qa_plan", {
            "schema_version": "browser-login-check/v1", "status": "invalid_qa_plan",
            "authentication_verified": False, "qa_completed": False,
            "secret_values_visible": False,
        }) from None

    results: list[dict[str, Any]] = []
    try:
        async with authenticated_browser_page(
            browser, workflow=workflow, values=values, transport=transport,
        ) as (page, receipt):
            for index, check in enumerate(selected):
                results.append({"index": index, "status": "incomplete"})
                await page.goto(check.url, wait_until="domcontentloaded")
                await page.locator("css=" + check.visible_selector).wait_for(
                    state="visible", timeout=workflow.timeout_ms,
                )
                results[-1]["status"] = "passed"
        # A copy is safe only now: final session verification and close completed.
        return {**dict(receipt), "checks_requested": len(selected),
                "checks_completed": len(results), "checks": results}
    except BrowserLoginError as error:
        error.receipt.update(checks_requested=len(selected), checks=results,
                             checks_completed=sum(item["status"] == "passed" for item in results))
        raise
