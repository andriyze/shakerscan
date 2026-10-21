"""Browser contexts that carry session headers reach only the target's origin.

Playwright's ``extra_http_headers`` (and ``set_extra_http_headers``) add the headers to every
request a page makes: an image or script from another origin, and every redirect hop, including
one to another origin, which no route handler sees. A context carrying session headers is
therefore confined at the network layer: its proxy admits only the bound origins, so the headers
(attached natively) can never leave for another origin.

Two loopback servers, in a real headless Chromium: the target on ``127.0.0.1`` and another
origin on ``localhost`` (a different port). The target's page loads an image and a fetch from the
other origin, and has same-origin and cross-origin redirects for navigations and for fetches. The
target receives the header on its own requests (same-origin redirects included); the other origin
receives nothing, and the refusals are recorded. Each browser entry point that carries session
headers is run.
"""
from __future__ import annotations

import asyncio
import contextlib
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import threading

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scanner"))
sys.path.insert(0, str(ROOT / "api"))

playwright_api = pytest.importorskip("playwright.async_api")

SECRET = "fixture-session-header-not-a-real-credential"


@contextmanager
def _servers():
    hits: list[tuple[str, str, str]] = []  # (server, path, every header value joined)
    ports: dict[str, int] = {}

    def handler(name: str):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def _reply(self, status: int, body: bytes = b"", content_type: str = "text/html", location: str = ""):
                self.send_response(status)
                if location:
                    self.send_header("Location", location)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802
                hits.append((name, self.path.split("?", 1)[0], "\n".join(self.headers.values())))
                other = f"http://localhost:{ports['other']}"
                if name == "other":
                    self._reply(200, b"other", "text/plain")
                    return
                path = self.path.split("?", 1)[0]
                if path in ("/", "/index.html"):
                    page = (
                        f'<html><body><h1>target</h1><img src="{other}/img.png">'
                        f'<script src="/app.js"></script>'
                        f'<script>fetch("/api/same"); fetch("/api/cross").catch(() => 0);'
                        f'fetch("{other}/xhr", {{mode: "no-cors"}}).catch(() => 0);</script></body></html>'
                    )
                    self._reply(200, page.encode())
                elif path == "/api/same":
                    self._reply(302, location="/api/final")
                elif path == "/api/cross":
                    self._reply(302, location=f"{other}/xhr-redirected")
                elif path == "/nav-same":
                    self._reply(302, location="/landed")
                elif path == "/nav-cross":
                    self._reply(302, location=f"{other}/nav-landed")
                elif path == "/app.js":
                    self._reply(200, b"window.appLoaded = true;", "application/javascript")
                else:
                    self._reply(200, b"<html><body>ok</body></html>")

            do_HEAD = do_GET

        return Handler

    try:
        other = ThreadingHTTPServer(("127.0.0.1", 0), handler("other"))
        target = ThreadingHTTPServer(("127.0.0.1", 0), handler("target"))
    except PermissionError:
        pytest.skip("test sandbox does not permit a loopback listener")
    ports["other"] = other.server_port
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (other, target)]
    for thread in threads:
        thread.start()
    try:
        yield f"http://127.0.0.1:{target.server_port}", hits
    finally:
        for server in (other, target):
            server.shutdown()
            server.server_close()


def _with_secret(hits, server: str) -> list[str]:
    return [path for name, path, values in hits if name == server and SECRET in values]


def _assert_contained(hits) -> None:
    # The other origin is refused at the context's proxy: nothing reaches it, header or not.
    assert [hit for hit in hits if hit[0] == "other"] == [], hits


REFUSED = "session_cross_origin_refused"
NAV_REFUSED = "session_navigation_redirect_refused"
LNA_BLOCK = "private_network_subresource_blocked"


class _Session:
    """Unit fixture standing in for an authenticated scan session."""

    def export_session(self) -> dict:
        return {"headers": {"X-API-Key": SECRET}, "cookies": {}}


def test_confined_context_sends_headers_to_the_target_origin_only():
    from scanner_tools.credential_redirects import confined_session_context

    async def drive(target: str) -> dict:
        async with playwright_api.async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            try:
                context, events = await confined_session_context(browser, [target], {"X-API-Key": SECRET})
                page = await context.new_page()
                await page.goto(target + "/", wait_until="networkidle")
                assert await page.evaluate("window.appLoaded") is True
                await page.goto(target + "/nav-same", wait_until="networkidle")
                assert page.url.endswith("/landed")
                # The hop is refused at the proxy (a plain-HTTP refusal is the proxy's 403).
                with contextlib.suppress(playwright_api.Error):
                    response = await page.goto(target + "/nav-cross", wait_until="networkidle")
                    assert response is None or response.status == 403
                await context.close()
                return events.as_dict()
            finally:
                await browser.close()

    with _servers() as (target, hits):
        recorded = asyncio.run(drive(target))
    _assert_contained(hits)
    secret_paths = _with_secret(hits, "target")
    # Same-origin redirects keep the header natively, for navigations and subresources.
    for path in ("/", "/app.js", "/api/same", "/api/final", "/nav-same", "/landed", "/nav-cross"):
        assert path in secret_paths, (path, hits)
    assert recorded["counts"][REFUSED] >= 3  # the image, the fetch, the redirect hops
    assert recorded["counts"][NAV_REFUSED] == 1
    assert LNA_BLOCK not in recorded["counts"]


def test_xss_browser_proof_keeps_its_headers_on_the_target():
    from scanner_tools import proof_of_exploit

    async def drive(target: str) -> list:
        try:
            return [(await proof_of_exploit.prove_xss_headless(
                start, "q", "x", headers={"X-API-Key": SECRET})).to_dict()
                for start in (f"{target}/", f"{target}/nav-cross")]
        finally:
            # The proof keeps one browser per event loop; close it with this loop.
            browser, playwright = proof_of_exploit._browser_instance, proof_of_exploit._playwright_instance
            proof_of_exploit._browser_instance = proof_of_exploit._playwright_instance = None
            if browser is not None:
                await browser.close()
            if playwright is not None:
                await playwright.stop()

    with _servers() as (target, hits):
        page, redirected = asyncio.run(drive(target))
    _assert_contained(hits)
    assert "/" in _with_secret(hits, "target")
    assert REFUSED in page["coverage_reasons"]
    assert NAV_REFUSED in redirected["coverage_reasons"]


@pytest.mark.parametrize("crawl", ["browser_fetch", "interactive_browser_crawl"])
def test_authenticated_browser_crawl_keeps_its_headers_on_the_target(crawl, tmp_path):
    from scanner_tools import http_scanner

    results = []
    with _servers() as (target, hits):
        for start in (f"{target}/", f"{target}/nav-cross"):
            if crawl == "browser_fetch":
                results.append(asyncio.run(http_scanner.browser_fetch(
                    start, screenshot_dir=str(tmp_path), auth_session=_Session())))
            else:
                results.append(asyncio.run(http_scanner.interactive_browser_crawl(
                    start, auth_session=_Session(), max_pages=2, screenshot_dir=str(tmp_path),
                )))
    _assert_contained(hits)
    assert "/" in _with_secret(hits, "target")
    assert REFUSED in results[1]["session_headers"]["reasons"]
    with _servers() as (target, hits):
        anonymous = asyncio.run(http_scanner.browser_fetch(f"{target}/nav-same", screenshot_dir=str(tmp_path)))
    assert "session_headers" not in anonymous  # a context without session headers is not confined


def test_interactive_session_set_auth_confines_the_session(tmp_path):
    import session_manager

    async def drive(target: str):
        session = session_manager.InteractiveSession("fixture-session", f"{target}/", results_dir=tmp_path)
        try:
            started = await session.start()
            assert started["success"], started
            result = await session.action({"action": "set_auth", "data": {"auth_header": f"Bearer {SECRET}"}})
            assert result["success"], result
            await session.action({"action": "navigate", "data": {"url": f"{target}/"}})
            await asyncio.sleep(0.5)
            redirected = await session.action({"action": "navigate", "data": {"url": f"{target}/nav-cross"}})
            return redirected, await session.get_state()
        finally:
            await session.close()

    with _servers() as (target, hits):
        redirected, state = asyncio.run(drive(target))
    # Before set_auth the session is an ordinary one and may load the other origin's image;
    # with the header it is confined, and the other origin never sees the header.
    assert _with_secret(hits, "other") == [], hits
    assert "/" in _with_secret(hits, "target")
    assert redirected.get("coverage_reasons") and NAV_REFUSED in redirected["coverage_reasons"], redirected
    assert REFUSED in state["session_header_coverage"]["default"]["reasons"]


def test_ai_widget_target_keeps_its_headers_on_its_origins():
    from ai_gate.targets.widget_playwright import WidgetPlaywrightConversationTarget

    async def drive(target: str):
        widget = WidgetPlaywrightConversationTarget(f"{target}/", {
            "endpoint_url": f"{target}/", "headers_template": {"X-API-Key": SECRET},
            # The widget page redirects to the other origin: refused at the context's proxy.
            "metadata_json": {"widget_manifest": {
                "input_selector": "#q", "response_selector": "#a", "entry_url": f"{target}/nav-cross",
            }},
        })
        try:
            with contextlib.suppress(Exception):
                await widget._ensure_browser()
            return widget.session_header_coverage()
        finally:
            await widget.close()

    with _servers() as (target, hits):
        recorded = asyncio.run(drive(target))
    _assert_contained(hits)
    assert "/nav-cross" in _with_secret(hits, "target")
    assert NAV_REFUSED in recorded["reasons"]


def test_bound_origins_include_the_same_host_https_upgrade():
    from scanner_tools.credential_redirects import bound_origins

    assert bound_origins(["http://app.example/"]) == {("http", "app.example", 80), ("https", "app.example", 443)}
    assert bound_origins(["http://app.example:8080/"]) == {("http", "app.example", 8080)}
    assert bound_origins(["https://app.example/"]) == {("https", "app.example", 443)}


def test_scan_coverage_lists_the_reasons_without_changing_its_status():
    from scanner_tools.credential_redirects import add_session_header_reasons
    sys.path.insert(0, str(ROOT))
    from api.scan.explanation import _REASON_LABELS

    coverage = {"status": "complete", "grade_reliable": True, "issues": []}
    add_session_header_reasons(coverage, {"reasons": [REFUSED, NAV_REFUSED], "counts": {REFUSED: 2, NAV_REFUSED: 1}})
    assert coverage["status"] == "complete" and coverage["grade_reliable"] is True
    assert coverage["reasons"] == [REFUSED, NAV_REFUSED]
    assert coverage["browser_session_headers"] == {REFUSED: 2, NAV_REFUSED: 1}
    for reason in (REFUSED, NAV_REFUSED, LNA_BLOCK, "session_header_withheld_from_headless"):
        assert reason in _REASON_LABELS


def test_scanner_report_coverage_carries_the_browser_session_reasons():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "shaker_scanner_main_session_headers", str(ROOT / "scanner" / "scanner.py"))
    scanner_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scanner_mod)
    report = {"http": {"browser_session_headers": {"reasons": [REFUSED], "counts": {REFUSED: 1}}}}
    coverage = {"status": "complete", "grade_reliable": True, "issues": [], "reasons": ["existing"]}
    scanner_mod.apply_browser_session_header_coverage(report, coverage)
    assert coverage["reasons"] == ["existing", REFUSED]
    assert coverage["status"] == "complete" and coverage["grade_reliable"] is True
    assert coverage["browser_session_headers"] == {REFUSED: 1}
    # A dalfox run that withheld the session from its headless browser is listed the same way.
    report["session_header_coverage"] = {"reasons": ["session_header_withheld_from_headless"],
                                         "counts": {"session_header_withheld_from_headless": 2}}
    scanner_mod.apply_browser_session_header_coverage(report, coverage)
    assert "session_header_withheld_from_headless" in coverage["reasons"]
    # The http block records what the browser fetch reported.
    source = (ROOT / "scanner" / "scanner.py").read_text()
    assert '"browser_session_headers": (' in source


def test_ai_widget_basic_auth_answers_only_the_endpoint_origin():
    import base64
    from ai_gate.targets.widget_playwright import WidgetPlaywrightConversationTarget

    seen: list[tuple[str, str, str | None]] = []
    ports: dict[str, int] = {}

    def handler(name: str):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):  # noqa: N802
                seen.append((name, self.path, self.headers.get("Authorization")))
                if not self.headers.get("Authorization"):
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="fixture"')
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                # A navigation to another origin that challenges too (a navigation, so Local
                # Network Access does not stop it first).
                body = (f'<html>widget<script>setTimeout(() => location = '
                        f'"http://127.0.0.1:{ports["other"]}/next", 100)</script></html>').encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return Handler

    endpoint = ThreadingHTTPServer(("127.0.0.1", 0), handler("endpoint"))
    other = ThreadingHTTPServer(("127.0.0.1", 0), handler("other"))
    ports["other"] = other.server_port
    for server in (endpoint, other):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{endpoint.server_port}"

    async def drive():
        widget = WidgetPlaywrightConversationTarget(f"{target}/", {
            "endpoint_url": f"{target}/",
            "credential": {"auth_kind": "basic_auth", "secret": "fixture-user:fixture-pass"},
            "metadata_json": {"widget_manifest": {"input_selector": "#q", "response_selector": "#a"}},
        })
        try:
            await widget._ensure_browser()
            await widget._page.wait_for_load_state("load")
            await widget._page.wait_for_timeout(1000)
        finally:
            await widget.close()

    try:
        asyncio.run(drive())
    finally:
        for server in (endpoint, other):
            server.shutdown()
            server.server_close()
    expected = "Basic " + base64.b64encode(b"fixture-user:fixture-pass").decode()
    assert ("endpoint", "/", expected) in seen
    # The credential is a header too, so the widget's context reaches its origins only: the other
    # origin is refused at the proxy, and Chromium's credentials answer the endpoint's origin only.
    assert [hit for hit in seen if hit[0] == "other" and hit[2]] == []
