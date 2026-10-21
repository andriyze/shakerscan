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
