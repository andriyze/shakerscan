"""Offline failure-path tests for private browser-state materialization.

The fake models disk writes and browser failures, not successful authentication.
A separate opt-in Chromium suite exercises the actual browser implementation.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
import shutil
import sys
import traceback
from types import ModuleType, SimpleNamespace

import pytest

from scanner.scanner_tools import browser_profile as bp

SECRET = "synthetic-private-value"
# Non-sensitive filler for the simulated on-disk browser-state files. The files' presence is what
# these fixtures reproduce; their content is never asserted. Keeping SECRET out of the file-write
# (storage) sinks avoids a clear-text-storage false positive while SECRET still flows through the
# error/receipt paths the leak assertions actually check.
STATE_MARKER = "partial-state-present"
ORIGIN = "https://browser-fixture.test"


def seed(kind="local_storage", **changes):
    result = {"schema_version": bp.BROWSER_STORAGE_SCHEMA, "kind": kind, "value": SECRET}
    if kind == "local_storage":
        result["key"] = "auth.token"
    else:
        result["value"] = "session=" + SECRET
    result.update(changes)
    return result


class Route:
    def __init__(self, url=ORIGIN + "/", method="GET", navigation=True):
        self.request = SimpleNamespace(
            url=url, method=method, is_navigation_request=lambda: navigation,
        )
        self.fulfilled = None
        self.aborted = None

    async def fulfill(self, **kwargs):
        self.fulfilled = kwargs

    async def abort(self, reason):
        self.aborted = reason


class FakeContext:
    def __init__(self, errors):
        self.errors = errors
        self.page = FakePage(self)
        self.pages = [self.page]
        self.handler = None
        self.closed = False
        self.jar = []

    async def route(self, pattern, handler):
        assert pattern == "**/*"
        self.handler = handler

    async def new_page(self):
        return self.page

    async def add_cookies(self, cookies):
        self.jar = [] if self.errors.get("drop_cookies") else cookies
        (self.profile / "private-cookie-state").write_text(STATE_MARKER)
        if self.errors.get("add_cookies"):
            raise RuntimeError(SECRET)

    async def cookies(self, url):
        return self.jar

    async def close(self):
        self.closed = True
        if self.errors.get("close"):
            raise RuntimeError(SECRET)


class FakePage:
    def __init__(self, context):
        self.context = context
        self.handler = None

    async def route(self, pattern, handler):
        # Compatibility with the exact old implementation, for red/green tests.
        self.handler = handler

    async def goto(self, url, **kwargs):
        handler = self.context.handler or self.handler
        assert handler is not None
        routed = Route(url)
        await handler(routed)
        assert routed.fulfilled is not None
        self.context.bootstrap = routed

    async def evaluate(self, expression, arguments):
        (self.context.profile / "private-storage-state").write_text(arguments[1])
        error = self.context.errors.get("evaluate")
        if error == "cancel":
            raise asyncio.CancelledError()
        if error:
            raise RuntimeError(SECRET)
        return not self.context.errors.get("drop_storage")


@pytest.fixture
def browser(monkeypatch, tmp_path):
    errors = {}
    context = FakeContext(errors)
    state = SimpleNamespace(context=context, errors=errors, launches=[])

    async def launch(path, **kwargs):
        state.launches.append(kwargs)
        context.profile = Path(path)
        if errors.get("launch"):
            (context.profile / "private-partial-state").write_text(STATE_MARKER)
            raise RuntimeError(SECRET)
        return context

    class Manager:
        async def __aenter__(self):
            return SimpleNamespace(chromium=SimpleNamespace(launch_persistent_context=launch))

        async def __aexit__(self, *args):
            return False

    package = ModuleType("playwright")
    package.__path__ = []
    api = ModuleType("playwright.async_api")
    api.async_playwright = Manager
    monkeypatch.setitem(sys.modules, "playwright", package)
    monkeypatch.setitem(sys.modules, "playwright.async_api", api)
    executable = tmp_path / "chromium-fixture"
    executable.write_text("not executed: browser is a fake")
    state.kwargs = {
        "user_data_dir": str(tmp_path / "private-profile"),
        "target_origin": ORIGIN,
        "seed": seed(),
        "chromium_path": str(executable),
        "proxy_url": "socks5://127.0.0.1:9050",
    }
    return state


def run(browser, **changes):
    return asyncio.run(bp.seed_browser_profile(**{**browser.kwargs, **changes}))


@pytest.mark.parametrize("bad", [None, 7, True, b"private", {"value": SECRET}, [SECRET], "\ud800"])
def test_non_text_or_invalid_unicode_secret_is_rejected(bad):
    with pytest.raises(bp.BrowserProfileError):
        bp.normalize_browser_storage_seed(seed(value=bad))


@pytest.mark.parametrize("bad", [7, True, ["auth.token"]])
def test_storage_key_must_be_text(bad):
    with pytest.raises(bp.BrowserProfileError):
        bp.normalize_browser_storage_seed(seed(key=bad))


@pytest.mark.parametrize("origin", [
    "https://user:private@browser-fixture.test/", "https://browser-fixture.test:bad/",
    "https://browser-fixture.test\n/", " https://browser-fixture.test/", "file:///private",
])
def test_invalid_origin_fails_before_profile_creation(browser, origin):
    with pytest.raises(bp.BrowserProfileError):
        run(browser, target_origin=origin)
    assert not Path(browser.kwargs["user_data_dir"]).exists()
    assert not browser.launches


@pytest.mark.parametrize("origin, expected", [
    ("HTTPS://BROWSER-FIXTURE.TEST:443/login", ORIGIN),
    ("http://browser-fixture.test:80/path", "http://browser-fixture.test"),
    ("http://[::1]:8080/path", "http://[::1]:8080"),
    ("https://b\u00fccher.test/", "https://xn--bcher-kva.test"),
])
def test_origin_matches_browser_canonicalization(origin, expected):
    assert bp._origin(origin) == expected


def test_invalid_seed_does_not_leave_an_empty_profile(browser):
    with pytest.raises(bp.BrowserProfileError):
        run(browser, seed={})
    assert not Path(browser.kwargs["user_data_dir"]).exists()


def test_missing_executable_does_not_create_profile(browser, tmp_path):
    with pytest.raises(bp.BrowserProfileError):
        run(browser, chromium_path=str(tmp_path / "missing-browser"))
    assert not Path(browser.kwargs["user_data_dir"]).exists()
    assert not browser.launches


@pytest.mark.parametrize("attribute", ["Domain=outside.test", "Path=/other", "Secure", "HttpOnly"])
def test_set_cookie_attributes_are_not_silently_ignored(attribute):
    with pytest.raises(bp.BrowserProfileError):
        bp._cookies("session=opaque; " + attribute, origin=ORIGIN)


def test_empty_cookie_value_is_not_silently_lost():
    cookies = bp._cookies("session=opaque; marker=", origin=ORIGIN)
    assert [(item["name"], item["value"]) for item in cookies] == [
        ("marker", ""), ("session", "opaque"),
    ]


@pytest.mark.parametrize("header", ["session=x\n", "session=x\r\nextra=y", "session=x\t", "session=x\x7f"])
def test_cookie_controls_fail_closed(header):
    with pytest.raises(bp.BrowserProfileError):
        bp._cookies(header, origin=ORIGIN)


@pytest.mark.parametrize("failure", ["launch", "evaluate", "close", "add_cookies"])
def test_browser_failure_scrubs_diagnostic_and_removes_private_profile(browser, failure):
    browser.errors[failure] = True
    selected_seed = seed("cookie_header") if failure == "add_cookies" else seed()
    with pytest.raises(bp.BrowserProfileError) as caught:
        run(browser, seed=selected_seed)
    assert SECRET not in "".join(traceback.format_exception(caught.value))
    assert not Path(browser.kwargs["user_data_dir"]).exists()
    if failure != "launch":
        assert browser.context.closed


def test_cancellation_is_preserved_and_removes_partial_private_state(browser):
    browser.errors["evaluate"] = "cancel"
    with pytest.raises(asyncio.CancelledError):
        run(browser)
    assert browser.context.closed
    assert not Path(browser.kwargs["user_data_dir"]).exists()


def test_close_error_does_not_replace_cancellation(browser):
    browser.errors.update(evaluate="cancel", close=True)
    with pytest.raises(asyncio.CancelledError):
        run(browser)
    assert browser.context.closed
    assert not Path(browser.kwargs["user_data_dir"]).exists()


@pytest.mark.parametrize("failure, kind", [("drop_storage", "local_storage"), ("drop_cookies", "cookie_header")])
def test_silent_storage_drop_does_not_report_success(browser, failure, kind):
    browser.errors[failure] = True
    with pytest.raises(bp.BrowserProfileError):
        run(browser, seed=seed(kind))
    assert not Path(browser.kwargs["user_data_dir"]).exists()


@pytest.mark.parametrize("kind", ["local_storage", "cookie_header"])
def test_success_has_private_profile_and_does_not_claim_authenticated(browser, kind):
    receipt = run(browser, seed=seed(kind))
    assert receipt["seeded_items"] == 1
    assert receipt["storage_seed_verified"] is True
    assert receipt["authentication_verified"] is False
    assert receipt["secret_values_visible"] is False
    assert receipt["target_requests"] == 0
    assert SECRET not in repr(receipt)
    assert Path(browser.kwargs["user_data_dir"]).stat().st_mode & 0o777 == 0o700
    assert browser.launches[0]["service_workers"] == "block"
    assert browser.launches[0]["proxy"] == {"server": "socks5://127.0.0.1:9050"}
    assert SECRET not in repr(browser.launches)
    assert browser.context.closed


@pytest.mark.parametrize("kind", ["local_storage", "cookie_header"])
def test_bootstrap_context_never_forwards_unexpected_requests(browser, kind):
    run(browser, seed=seed(kind))
    handler = browser.context.handler
    assert handler is not None
    for route in [
        Route("https://outside.test/"), Route(ORIGIN + "/login", "POST"),
        Route(ORIGIN + "/", "POST"), Route(ORIGIN + "/", navigation=False),
        Route(ORIGIN.replace("https", "http") + "/"),
        Route(ORIGIN + ":8443/"),
    ]:
        asyncio.run(handler(route))
        assert route.aborted == "blockedbyclient"
        assert route.fulfilled is None
    exact = Route()
    asyncio.run(handler(exact))
    if kind == "local_storage":
        assert exact.fulfilled is not None
        assert "default-src 'none'" in exact.fulfilled["headers"]["Content-Security-Policy"]
    else:
        assert exact.aborted == "blockedbyclient"


def test_preexisting_profile_is_not_removed(browser):
    profile = Path(browser.kwargs["user_data_dir"])
    profile.mkdir()
    marker = profile / "keep"
    marker.write_text("belongs to someone else")
    with pytest.raises(bp.BrowserProfileError):
        run(browser)
    assert marker.read_text() == "belongs to someone else"


def test_dangling_symlink_is_not_followed_or_removed(browser, tmp_path):
    profile = Path(browser.kwargs["user_data_dir"])
    target = tmp_path / "do-not-create"
    profile.symlink_to(target, target_is_directory=True)
    with pytest.raises(bp.BrowserProfileError):
        run(browser)
    assert profile.is_symlink()
    assert not target.exists()


def test_cleanup_failure_is_reported_without_secret_exception(browser, monkeypatch):
    browser.errors["evaluate"] = True

    def fail_cleanup(path):
        raise OSError(SECRET)

    monkeypatch.setattr(shutil, "rmtree", fail_cleanup)
    with pytest.raises(bp.BrowserProfileError, match="cleanup failed") as caught:
        run(browser)
    assert SECRET not in "".join(traceback.format_exception(caught.value))
