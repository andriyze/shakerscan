"""A retest's destination guard holds in a real headless Chromium.

Two local servers: the in-scope one (127.0.0.1) and an off-scope one reached as ``localhost``.
Every way a page can send traffic -- a redirect (also after an in-scope hop), meta refresh, a
script navigation, an image, fetch, a beacon, a WebSocket -- must never reach the off-scope
server, and each refused host is recorded. An in-scope login flow (form POST, 302 with a cookie)
still works. Both the proof contexts (``proof_of_exploit``) and the AI verification session
(``session_manager``) open their contexts with ``guarded_context_options``.
"""
from __future__ import annotations

import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import threading
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scanner"))
sys.path.insert(0, str(ROOT / "api"))

playwright_api = pytest.importorskip("playwright.async_api")

from scanner_tools.destination_guard import destination_guard, guarded_context_options  # noqa: E402

OFF_HITS: list[str] = []


class OffScope(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        OFF_HITS.append(self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"off")

    do_POST = do_GET


def _servers():
    off = ThreadingHTTPServer(("127.0.0.1", 0), OffScope)
    off_url = f"http://localhost:{off.server_address[1]}"

    class InScope(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _html(self, body):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body.encode())

        def do_GET(self):
            path = self.path
            if path == "/redir":
                self.send_response(302)
                self.send_header("Location", off_url + "/hit-redirect")
                self.end_headers()
            elif path == "/chain":  # an in-scope hop, then off scope
                self.send_response(302)
                self.send_header("Location", "/redir")
                self.end_headers()
            elif path == "/meta":
                self._html(f'<meta http-equiv="refresh" content="0;url={off_url}/hit-meta">')
            elif path == "/js":
                port = urlsplit(off_url).port
                self._html(f'''<img src="{off_url}/hit-img"><script>
                  fetch("{off_url}/hit-fetch").catch(() => {{}});
                  try {{ new WebSocket("ws://localhost:{port}/hit-ws"); }} catch (e) {{}}
                  navigator.sendBeacon("{off_url}/hit-beacon");
                  setTimeout(() => location = "{off_url}/hit-jsnav", 300);</script>''')
            elif path == "/home":
                self._html("home cookie=" + (self.headers.get("Cookie") or "none"))
            else:
                self._html("in scope")

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(302)
            self.send_header("Location", "/home")
            self.send_header("Set-Cookie", "sid=42; Path=/")
            self.end_headers()

    on = ThreadingHTTPServer(("127.0.0.1", 0), InScope)
    for server in (on, off):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    return on, off, f"http://127.0.0.1:{on.server_address[1]}"


def _allowed(url: str) -> bool:
    return urlsplit(url).hostname == "127.0.0.1"


async def _launch(pw):
    try:
        return await pw.chromium.launch(headless=True, args=["--no-sandbox"])
    except Exception as exc:  # the Playwright browser is not installed on this host
        pytest.skip(f"Chromium for Playwright is not installed: {type(exc).__name__}")


@pytest.mark.parametrize("paths", [("/redir",), ("/chain",), ("/meta",), ("/js",)],
                         ids=["302", "302-after-in-scope-hop", "meta-refresh", "script-img-fetch-beacon-ws"])
def test_no_page_traffic_reaches_an_off_scope_host(paths):
    on, off, on_url = _servers()

    async def run():
        OFF_HITS.clear()
        async with playwright_api.async_playwright() as pw:
            browser = await _launch(pw)
            try:
                with destination_guard(_allowed) as guard:
                    context = await browser.new_context(**await guarded_context_options())
                    page = await context.new_page()
                    for path in paths:
                        try:
                            await page.goto(on_url + path, wait_until="load", timeout=5000)
                        except Exception:
                            pass  # a refused navigation fails the goto
                        await page.wait_for_timeout(1200)
                    await context.close()
                    return list(guard.refused)
            finally:
                await browser.close()
    try:
        refused = asyncio.run(run())
    finally:
        on.shutdown()
        off.shutdown()
    assert OFF_HITS == []
    assert "localhost" in refused


def test_an_in_scope_login_redirect_with_a_cookie_still_works():
    on, off, on_url = _servers()

    async def run():
        async with playwright_api.async_playwright() as pw:
            browser = await _launch(pw)
            try:
                with destination_guard(_allowed) as guard:
                    context = await browser.new_context(**await guarded_context_options())
                    page = await context.new_page()
                    await page.goto(on_url + "/x")
                    await page.set_content(f'<form method=post action="{on_url}/login"><input name=u value=a></form>')
                    await page.evaluate("document.forms[0].submit()")
                    await page.wait_for_url(on_url + "/home", timeout=5000)
                    body = await page.content()
                    await context.close()
                    return page.url, body, list(guard.refused)
            finally:
                await browser.close()
    try:
        url, body, refused = asyncio.run(run())
    finally:
        on.shutdown()
        off.shutdown()
    assert url == on_url + "/home" and "sid=42" in body and refused == []


def test_the_proof_and_session_browser_contexts_open_through_the_guard():
    proof = (ROOT / "scanner" / "scanner_tools" / "proof_of_exploit.py").read_text(encoding="utf-8")
    assert proof.count("new_context(") == proof.count("guarded_context_options()") == 2
    session = (ROOT / "api" / "session_manager.py").read_text(encoding="utf-8")
    assert "**await guarded_context_options()" in session


def test_without_a_guard_contexts_are_unchanged():
    assert asyncio.run(guarded_context_options()) == {}
