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
        protocol_version = "HTTP/1.1"  # keep-alive, so a proxy that reused connections would show it

        def log_message(self, *_args):
            pass

        def end_headers(self):
            if not getattr(self, "_has_length", False):
                self.send_header("Content-Length", "0")
            self._has_length = False
            super().end_headers()

        def _html(self, body):
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self._has_length = True
            self.end_headers()
            self.wfile.write(data)

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


def test_webrtc_sends_no_udp_under_the_guard():
    import socket
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(0.1)
    stun_port = udp.getsockname()[1]
    on, off, on_url = _servers()

    async def run(guarded: bool):
        async with playwright_api.async_playwright() as pw:
            browser = await _launch(pw)
            try:
                with destination_guard(_allowed if guarded else None):
                    context = await browser.new_context()
                    page = await context.new_page()
                    await page.goto(on_url + "/x")
                    await page.evaluate(f"""() => {{ try {{
                        const pc = new RTCPeerConnection({{iceServers: [{{urls: "stun:localhost:{stun_port}"}}]}});
                        pc.createDataChannel("x"); pc.createOffer().then(o => pc.setLocalDescription(o));
                    }} catch (e) {{}} }}""")
                    await page.wait_for_timeout(1500)
                    await context.close()
            finally:
                await browser.close()

    def packets():
        count = 0
        try:
            while True:
                udp.recvfrom(2048)
                count += 1
        except OSError:
            return count
    try:
        asyncio.run(run(guarded=False))
        unguarded = packets()
        asyncio.run(run(guarded=True))
        guarded = packets()
    finally:
        udp.close()
        on.shutdown()
        off.shutdown()
    assert unguarded > 0  # the fixture does send STUN without the guard
    assert guarded == 0


def test_a_plain_http_connection_cannot_carry_a_second_request_to_another_host():
    """Keep-alive: after the first (allowed) request the proxy closes the client connection, so a
    second request on it -- here to an off-scope host -- is never relayed anywhere."""
    on, off, on_url = _servers()
    off_port = off.server_address[1]

    async def run():
        OFF_HITS.clear()
        with destination_guard(_allowed) as guard:
            options = await guarded_context_options()
            proxy_port = int(options["proxy"]["server"].rsplit(":", 1)[1])
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            first = f"GET {on_url}/x HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n"
            second = (f"GET http://localhost:{off_port}/hit-keepalive HTTP/1.1\r\nHost: localhost\r\n"
                      "Connection: keep-alive\r\n\r\n")
            writer.write((first + second).encode())
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), timeout=5)
            writer.close()
            refused = await asyncio.wait_for(_refused_direct(proxy_port, off_port), timeout=5)
            return response, refused, list(guard.refused)
    try:
        response, direct, refused = asyncio.run(run())
    finally:
        on.shutdown()
        off.shutdown()
    assert response.startswith(b"HTTP/1.0 200") or response.startswith(b"HTTP/1.1 200")
    assert response.count(b"HTTP/1.") == 1  # one response; the connection then ended
    assert OFF_HITS == []
    assert direct.startswith(b"HTTP/1.1 403") and "localhost" in refused


async def _refused_direct(proxy_port: int, off_port: int) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(f"GET http://localhost:{off_port}/hit-direct HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
    await writer.drain()
    data = await reader.read()
    writer.close()
    return data


def test_a_proxy_failure_is_recorded_as_an_incident():
    async def run():
        with destination_guard(lambda url: True) as guard:
            options = await guarded_context_options()
            proxy_port = int(options["proxy"]["server"].rsplit(":", 1)[1])
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            # An allowed host on a port nothing listens on.
            writer.write(b"GET http://127.0.0.1:9/x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.read(), timeout=5)
            writer.close()
            await asyncio.sleep(0.1)
            return list(guard.incidents)
    incidents = asyncio.run(run())
    assert incidents and incidents[0].startswith("127.0.0.1:")


def test_a_context_opened_without_the_options_is_still_guarded():
    """Any browser code reached during a replay (form login, discovery, browser capabilities...)
    gets the guarded context: ``enforce_on_playwright`` wraps Playwright itself."""
    on, off, on_url = _servers()

    async def run():
        OFF_HITS.clear()
        async with playwright_api.async_playwright() as pw:
            browser = await _launch(pw)
            try:
                with destination_guard(_allowed) as guard:
                    context = await browser.new_context()  # no guarded options passed
                    page = await context.new_page()
                    try:
                        await page.goto(on_url + "/chain", timeout=5000)
                    except Exception:
                        pass
                    await page.wait_for_timeout(800)
                    has_rtc = await page.evaluate("typeof RTCPeerConnection")
                    await context.close()
                    return list(guard.refused), has_rtc
            finally:
                await browser.close()
    try:
        refused, has_rtc = asyncio.run(run())
    finally:
        on.shutdown()
        off.shutdown()
    assert OFF_HITS == [] and "localhost" in refused and has_rtc == "undefined"


def test_every_browser_entry_point_in_the_engine_is_one_the_guard_wraps():
    """Browser code anywhere in the engine opens Chromium through ``launch``,
    ``launch_persistent_context`` or ``new_context`` -- the three methods
    ``enforce_on_playwright`` wraps -- never through a path it does not (CDP, another engine)."""
    import re
    sources = [*sorted((ROOT / "api").rglob("*.py")), *sorted((ROOT / "scanner").rglob("*.py"))]
    browser_modules = []
    for path in sources:
        text = path.read_text(encoding="utf-8", errors="replace")
        if re.search(r"new_context\(|launch_persistent_context\(|chromium\.launch\(", text):
            browser_modules.append(path.relative_to(ROOT).as_posix())
            assert not re.search(r"connect_over_cdp|\.connect\(|firefox\.|webkit\.", text), path
    assert {"scanner/scanner_tools/proof_of_exploit.py", "api/session_manager.py",
            "scanner/scanner_tools/form_login.py", "scanner/scanner_tools/http_scanner.py",
            "scanner/scanner_tools/discovery.py", "scanner/scanner_tools/browser_profile.py",
            "api/capabilities/browser.py"} <= set(browser_modules)
    guard = (ROOT / "scanner" / "scanner_tools" / "destination_guard.py").read_text(encoding="utf-8")
    for wrapped in ("Browser.new_context =", "BrowserType.launch_persistent_context =", "BrowserType.launch ="):
        assert wrapped in guard
    assert "enforce_on_playwright()" in guard.split("def destination_guard", 1)[1]


def test_the_proof_and_session_browser_contexts_open_through_the_guard():
    proof = (ROOT / "scanner" / "scanner_tools" / "proof_of_exploit.py").read_text(encoding="utf-8")
    assert proof.count("new_context(") == proof.count("guarded_context_options()") == 2
    session = (ROOT / "api" / "session_manager.py").read_text(encoding="utf-8")
    assert "**await guarded_context_options()" in session


def test_without_a_guard_contexts_are_unchanged():
    assert asyncio.run(guarded_context_options()) == {}
