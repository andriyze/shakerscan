"""Browser contexts send session headers only to the target's origin.

Playwright's ``extra_http_headers`` (and ``set_extra_http_headers``) add the headers to every
request a page makes: an image or script from another origin, and every redirect hop, including
one to another origin. A Scan authenticated with an API-key or bearer header therefore handed it
to any origin the target's page loaded or redirected to.

Two loopback servers, in a real headless Chromium: the target on ``127.0.0.1`` and another
origin on ``localhost`` (a different port). The target's page loads an image and a fetch from the
other origin, and has same-origin and cross-origin redirects for navigations and for fetches. The
target receives the header on its own requests (a same-origin fetch redirect included); the
other origin never receives it. Each browser entry point that carries session headers is run.
"""
from __future__ import annotations

import asyncio
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
    assert [hit for hit in hits if hit[0] == "other"], ("the page never reached the other origin", hits)
    assert _with_secret(hits, "other") == []


class _Session:
    """Unit fixture standing in for an authenticated scan session."""

    def export_session(self) -> dict:
        return {"headers": {"X-API-Key": SECRET}, "cookies": {}}


def test_bound_context_sends_headers_to_the_target_origin_only():
    from scanner_tools.credential_redirects import bind_session_headers

    async def drive(target: str) -> None:
        async with playwright_api.async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            try:
                context = await browser.new_context()
                await bind_session_headers(context, [target], {"X-API-Key": SECRET})
                page = await context.new_page()
                await page.goto(target + "/", wait_until="networkidle")
                assert await page.evaluate("window.appLoaded") is True
                await page.goto(target + "/nav-same", wait_until="networkidle")
                assert page.url.endswith("/landed")
                await page.goto(target + "/nav-cross", wait_until="networkidle")
                assert "/nav-landed" in page.url
            finally:
                await browser.close()

    with _servers() as (target, hits):
        asyncio.run(drive(target))
    _assert_contained(hits)
    secret_paths = _with_secret(hits, "target")
    for path in ("/", "/app.js", "/api/same", "/api/final", "/nav-same", "/nav-cross"):
        assert path in secret_paths, (path, hits)


def test_xss_browser_proof_keeps_its_headers_on_the_target():
    from scanner_tools import proof_of_exploit

    async def drive(target: str) -> None:
        try:
            for start in (f"{target}/", f"{target}/nav-cross"):
                await proof_of_exploit.prove_xss_headless(start, "q", "x", headers={"X-API-Key": SECRET})
        finally:
            # The proof keeps one browser per event loop; close it with this loop.
            browser, playwright = proof_of_exploit._browser_instance, proof_of_exploit._playwright_instance
            proof_of_exploit._browser_instance = proof_of_exploit._playwright_instance = None
            if browser is not None:
                await browser.close()
            if playwright is not None:
                await playwright.stop()

    with _servers() as (target, hits):
        asyncio.run(drive(target))
    _assert_contained(hits)
    assert "/" in _with_secret(hits, "target")


@pytest.mark.parametrize("crawl", ["browser_fetch", "interactive_browser_crawl"])
def test_authenticated_browser_crawl_keeps_its_headers_on_the_target(crawl, tmp_path):
    from scanner_tools import http_scanner

    with _servers() as (target, hits):
        for start in (f"{target}/", f"{target}/nav-cross"):
            if crawl == "browser_fetch":
                asyncio.run(http_scanner.browser_fetch(start, screenshot_dir=str(tmp_path), auth_session=_Session()))
            else:
                asyncio.run(http_scanner.interactive_browser_crawl(
                    start, auth_session=_Session(), max_pages=2, screenshot_dir=str(tmp_path),
                ))
    _assert_contained(hits)
    assert "/" in _with_secret(hits, "target")


def test_interactive_session_set_auth_keeps_the_header_on_the_target(tmp_path):
    import session_manager

    async def drive(target: str) -> None:
        session = session_manager.InteractiveSession("fixture-session", f"{target}/", results_dir=tmp_path)
        try:
            started = await session.start()
            assert started["success"], started
            result = await session.action({"action": "set_auth", "data": {"auth_header": f"Bearer {SECRET}"}})
            assert result["success"], result
            await session.action({"action": "navigate", "data": {"url": f"{target}/"}})
            await asyncio.sleep(0.5)
            await session.action({"action": "navigate", "data": {"url": f"{target}/nav-cross"}})
        finally:
            await session.close()

    with _servers() as (target, hits):
        asyncio.run(drive(target))
    _assert_contained(hits)
    assert "/" in _with_secret(hits, "target")


def test_ai_widget_target_keeps_its_headers_on_the_endpoint_origin():
    from ai_gate.targets.widget_playwright import WidgetPlaywrightConversationTarget

    async def drive(target: str) -> None:
        widget = WidgetPlaywrightConversationTarget(f"{target}/", {
            "endpoint_url": f"{target}/", "headers_template": {"X-API-Key": SECRET},
            # The widget page redirects to the other origin: its next hop must not carry the header.
            "metadata_json": {"widget_manifest": {
                "input_selector": "#q", "response_selector": "#a", "entry_url": f"{target}/nav-cross",
            }},
        })
        try:
            await widget._ensure_browser()
            await widget._page.wait_for_load_state("load")
            await widget._page.wait_for_timeout(500)
        finally:
            await widget.close()

    with _servers() as (target, hits):
        asyncio.run(drive(target))
    _assert_contained(hits)
    assert "/nav-cross" in _with_secret(hits, "target")


def test_bound_origins_include_the_same_host_https_upgrade():
    from scanner_tools.credential_redirects import bound_origins

    assert bound_origins(["http://app.example/"]) == {("http", "app.example", 80), ("https", "app.example", 443)}
    assert bound_origins(["http://app.example:8080/"]) == {("http", "app.example", 8080)}
    assert bound_origins(["https://app.example/"]) == {("https", "app.example", 443)}


# --- the two costs of keeping headers on the origin are recorded, never silent ---------------

NAV_DROP = "session_header_dropped_on_navigation_redirect"
LNA_BLOCK = "private_network_subresource_blocked"


def test_bound_context_records_a_navigation_redirect_and_a_blocked_private_subresource():
    from scanner_tools.credential_redirects import bind_session_headers

    async def drive(target: str) -> dict:
        async with playwright_api.async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            try:
                context = await browser.new_context()
                events = await bind_session_headers(context, [target], {"X-API-Key": SECRET})
                page = await context.new_page()
                await page.goto(target + "/nav-same", wait_until="load")
                assert events.as_dict()["reasons"] == [NAV_DROP]
                await page.goto(target + "/", wait_until="load")
                await page.wait_for_timeout(500)
                return events.as_dict()
            finally:
                await browser.close()

    with _servers() as (target, _hits):
        recorded = asyncio.run(drive(target))
    assert recorded["reasons"] == sorted([NAV_DROP, LNA_BLOCK])
    assert recorded["counts"][NAV_DROP] == 1
    assert recorded["counts"][LNA_BLOCK] >= 2  # the image and the fetch from the other origin


def test_authenticated_browser_fetch_reports_the_navigation_redirect(tmp_path):
    from scanner_tools import http_scanner

    with _servers() as (target, _hits):
        redirected = asyncio.run(http_scanner.browser_fetch(
            f"{target}/nav-same", screenshot_dir=str(tmp_path), auth_session=_Session()))
        page = asyncio.run(http_scanner.browser_fetch(
            f"{target}/", screenshot_dir=str(tmp_path), auth_session=_Session()))
    assert NAV_DROP in redirected["session_headers"]["reasons"]
    # The crawl's own guard refuses other origins first (and reports them); nothing is
    # claimed for a request that never reached Chromium's check.
    assert page["interaction_safety"]["cross_origin_requests_blocked"] >= 1
    assert LNA_BLOCK not in page["session_headers"]["reasons"]
    anonymous = None
    with _servers() as (target, _hits):
        anonymous = asyncio.run(http_scanner.browser_fetch(f"{target}/nav-same", screenshot_dir=str(tmp_path)))
    assert "session_headers" not in anonymous


def test_interactive_crawl_reports_the_navigation_redirect(tmp_path):
    from scanner_tools import http_scanner

    with _servers() as (target, _hits):
        crawl = asyncio.run(http_scanner.interactive_browser_crawl(
            f"{target}/nav-same", auth_session=_Session(), max_pages=1, screenshot_dir=str(tmp_path)))
    assert NAV_DROP in crawl["session_headers"]["reasons"]


def test_xss_proof_result_reports_both_reasons():
    from scanner_tools import proof_of_exploit

    async def drive(target: str):
        try:
            redirected = await proof_of_exploit.prove_xss_headless(
                f"{target}/nav-same", "q", "x", headers={"X-API-Key": SECRET})
            page = await proof_of_exploit.prove_xss_headless(
                f"{target}/", "q", "x", headers={"X-API-Key": SECRET})
            return redirected.to_dict(), page.to_dict()
        finally:
            browser, playwright = proof_of_exploit._browser_instance, proof_of_exploit._playwright_instance
            proof_of_exploit._browser_instance = proof_of_exploit._playwright_instance = None
            if browser is not None:
                await browser.close()
            if playwright is not None:
                await playwright.stop()

    with _servers() as (target, _hits):
        redirected, page = asyncio.run(drive(target))
    assert NAV_DROP in redirected["coverage_reasons"]
    assert LNA_BLOCK in page["coverage_reasons"]


def test_interactive_session_navigation_reports_the_redirect(tmp_path):
    import session_manager

    async def drive(target: str):
        session = session_manager.InteractiveSession("fixture-session-2", f"{target}/", results_dir=tmp_path)
        try:
            assert (await session.start())["success"]
            assert (await session.action({"action": "set_auth", "data": {"auth_header": f"Bearer {SECRET}"}}))["success"]
            return await session.action({"action": "navigate", "data": {"url": f"{target}/nav-same"}})
        finally:
            await session.close()

    with _servers() as (target, _hits):
        result = asyncio.run(drive(target))
    assert NAV_DROP in result["coverage_reasons"], result


def test_ai_widget_records_the_navigation_redirect():
    from ai_gate.targets.widget_playwright import WidgetPlaywrightConversationTarget

    async def drive(target: str):
        widget = WidgetPlaywrightConversationTarget(f"{target}/", {
            "endpoint_url": f"{target}/", "headers_template": {"X-API-Key": SECRET},
            "metadata_json": {"widget_manifest": {
                "input_selector": "#q", "response_selector": "#a", "entry_url": f"{target}/nav-same",
            }},
        })
        try:
            await widget._ensure_browser()
            await widget._page.wait_for_load_state("load")
            return widget.session_header_coverage()
        finally:
            await widget.close()

    with _servers() as (target, _hits):
        recorded = asyncio.run(drive(target))
    assert NAV_DROP in recorded["reasons"]


def test_scan_coverage_lists_the_reasons_without_changing_its_status():
    from scanner_tools.credential_redirects import add_session_header_reasons
    sys.path.insert(0, str(ROOT))
    from api.scan.explanation import _reason_label

    coverage = {"status": "complete", "grade_reliable": True, "issues": []}
    add_session_header_reasons(coverage, {"reasons": [NAV_DROP, LNA_BLOCK], "counts": {NAV_DROP: 2, LNA_BLOCK: 3}})
    assert coverage["status"] == "complete" and coverage["grade_reliable"] is True
    assert coverage["reasons"] == [LNA_BLOCK, NAV_DROP]
    assert coverage["browser_session_headers"] == {NAV_DROP: 2, LNA_BLOCK: 3}
    for reason in (NAV_DROP, LNA_BLOCK):
        label = _reason_label(reason)
        assert label and ("session" in label.lower() or "private" in label.lower()), label


def test_scanner_report_coverage_carries_the_browser_session_reasons():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "shaker_scanner_main_session_headers", str(ROOT / "scanner" / "scanner.py"))
    scanner_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scanner_mod)
    report = {"http": {"browser_session_headers": {"reasons": [NAV_DROP], "counts": {NAV_DROP: 1}}}}
    coverage = {"status": "complete", "grade_reliable": True, "issues": [], "reasons": ["existing"]}
    scanner_mod.apply_browser_session_header_coverage(report, coverage)
    assert coverage["reasons"] == ["existing", NAV_DROP]
    assert coverage["status"] == "complete" and coverage["grade_reliable"] is True
    assert coverage["browser_session_headers"] == {NAV_DROP: 1}
    # The http block records what the browser fetch reported.
    source = (ROOT / "scanner" / "scanner.py").read_text()
    assert '"browser_session_headers": (' in source
