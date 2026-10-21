"""What a session-header browser route must not do, and what it must say it did not do.

Real headless Chromium against loopback servers:

- a response too large to hand to the page is refused, the browser survives, and the refusal is
  recorded (``session_header_response_too_large``);
- a stream (``EventSource``) is not buffered: it reaches the page as it arrives, without the
  session header, and the withholding is recorded (``session_header_withheld_from_stream``);
- a cross-origin request between two bound origins gets the CORS preflight the page's own
  request needs, and the response's CORS headers are checked, as a browser would
  (``cors_preflight_refused``);
- Local Network Access is granted only where destinations are confined (the destination guard);
  an unconfined context keeps Chromium's refusal and records it.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import threading
import time
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scanner"))

playwright_api = pytest.importorskip("playwright.async_api")

from scanner_tools.credential_redirects import bind_session_headers  # noqa: E402

SECRET = "fixture-session-header-not-a-real-credential"
BIG = 200 * 1024 * 1024
CHUNK = b"\0" * (1024 * 1024)


def _handler(name: str, hits: list, ports: dict, *, cors: str = "none"):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def _send(self, status, body=b"", content_type="text/html", extra=()):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for key, value in extra:
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _cors(self):
            origin = self.headers.get("Origin") or ""
            return [("Access-Control-Allow-Origin", origin)] if cors in {"allow", "preflight-refused"} and origin else []

        def do_OPTIONS(self):  # noqa: N802
            hits.append((name, "OPTIONS", self.path, self.headers.get("X-API-Key"),
                         self.headers.get("Access-Control-Request-Headers") or ""))
            if cors == "allow":
                self._send(204, extra=[*self._cors(), ("Access-Control-Allow-Methods", "PUT, GET"),
                                       ("Access-Control-Allow-Headers", "x-page-header")])
            else:
                self._send(403, b"no")

        def do_PUT(self):  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            hits.append((name, "PUT", self.path, self.headers.get("X-API-Key"), ""))
            self._send(200, b"put-ok", "text/plain", self._cors())

        def do_GET(self):  # noqa: N802
            hits.append((name, "GET", self.path, self.headers.get("X-API-Key"), ""))
            other = f"http://127.0.0.1:{ports.get('other', 0)}"
            self.path = self.path.split("?", 1)[0]
            if self.path == "/big":
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(BIG))
                self.end_headers()
                try:
                    for _ in range(BIG // len(CHUNK)):
                        self.wfile.write(CHUNK)
                except OSError:
                    pass
            elif self.path == "/events":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                try:
                    for index in range(6):
                        self.wfile.write(f"data: {index}\n\n".encode())
                        self.wfile.flush()
                        time.sleep(0.5)
                except OSError:
                    pass
            elif self.path == "/big-page":
                self._send(200, b"<html><script>window.big = fetch('/big').then(r => r.arrayBuffer())"
                                b".then(b => 'got ' + b.byteLength, e => 'failed');</script>ok</html>")
            elif self.path == "/stream-page":
                self._send(200, b"<html><script>window.events = [];"
                                b"new EventSource('/events').onmessage = e => events.push([e.data, Date.now()]);"
                                b"</script>ok</html>")
            elif self.path == "/cors-page":
                self._send(200, (
                    "<html><script>window.put = fetch('" + other + "/item', {method: 'PUT', body: 'x',"
                    " headers: {'X-Page-Header': '1'}}).then(r => r.text(), e => 'failed');"
                    "window.plain = fetch('" + other + "/plain').then(r => r.text(), e => 'failed');"
                    "</script>ok</html>").encode())
            elif self.path == "/spa":
                self._send(200, (
                    f'<html><script src="{other}/bundle.js"></script><script>'
                    f"window.api = fetch('{other}/api/data').then(r => r.text(), e => 'failed');"
                    "</script>spa</html>").encode())
            elif self.path == "/bundle.js":
                self._send(200, b"window.bundle = true;", "application/javascript", self._cors() or [("Access-Control-Allow-Origin", "*")])
            elif self.path == "/api/data":
                self._send(200, b"data-ok", "text/plain", [("Access-Control-Allow-Origin", "*")])
            elif self.path == "/plain":
                self._send(200, b"plain-ok", "text/plain", self._cors() if cors == "allow" else [])
            else:
                self._send(200, b"<html>ok</html>")

    return Handler


@contextmanager
def _pair(cors: str = "none"):
    hits: list = []
    ports: dict = {}
    try:
        page = ThreadingHTTPServer(("127.0.0.1", 0), _handler("page", hits, ports, cors=cors))
        other = ThreadingHTTPServer(("127.0.0.1", 0), _handler("other", hits, ports, cors=cors))
    except PermissionError:
        pytest.skip("test sandbox does not permit a loopback listener")
    ports["other"] = other.server_port
    for server in (page, other):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{page.server_port}", f"http://127.0.0.1:{other.server_port}", hits
    finally:
        for server in (page, other):
            server.shutdown()
            server.server_close()


async def _browser(playwright):
    return await playwright.chromium.launch()


def test_an_oversized_response_is_refused_and_the_browser_survives():
    async def drive(page_origin: str):
        async with playwright_api.async_playwright() as playwright:
            browser = await _browser(playwright)
            try:
                context = await browser.new_context()
                events = await bind_session_headers(context, [page_origin], {"X-API-Key": SECRET})
                page = await context.new_page()
                await page.goto(page_origin + "/big-page", wait_until="load")
                outcome = await page.evaluate("window.big")
                assert await page.evaluate("1 + 1") == 2
                await context.close()
                later = await browser.new_context()  # the shared browser still works
                second = await later.new_page()
                await second.goto(page_origin + "/", wait_until="load")
                await later.close()
                return outcome, events.as_dict()
            finally:
                await browser.close()

    with _pair() as (page_origin, _other, _hits):
        outcome, recorded = asyncio.run(drive(page_origin))
    assert outcome == "failed"
    assert recorded["counts"]["session_header_response_too_large"] == 1


def test_a_stream_arrives_progressively_without_the_session_header():
    async def drive(page_origin: str):
        async with playwright_api.async_playwright() as playwright:
            browser = await _browser(playwright)
            try:
                context = await browser.new_context()
                events = await bind_session_headers(context, [page_origin], {"X-API-Key": SECRET})
                page = await context.new_page()
                await page.goto(page_origin + "/stream-page", wait_until="load")
                await page.wait_for_timeout(1600)
                early = await page.evaluate("window.events.length")
                return early, events.as_dict()
            finally:
                await browser.close()

    with _pair() as (page_origin, _other, hits):
        early, recorded = asyncio.run(drive(page_origin))
    assert early >= 2  # delivered while the stream is still open
    assert [hit for hit in hits if hit[2] == "/events" and hit[3]] == []
    assert ("page", "GET", "/stream-page", SECRET, "") in hits
    assert recorded["counts"]["session_header_withheld_from_stream"] >= 1


@pytest.mark.parametrize("cors", ["preflight-refused", "allow"])
def test_cross_origin_requests_between_bound_origins_follow_cors(cors):
    async def drive(page_origin: str, other_origin: str):
        async with playwright_api.async_playwright() as playwright:
            browser = await _browser(playwright)
            try:
                context = await browser.new_context(permissions=["local-network-access"])
                events = await bind_session_headers(context, [page_origin, other_origin], {"X-API-Key": SECRET})
                page = await context.new_page()
                await page.goto(page_origin + "/cors-page", wait_until="load")
                return await page.evaluate("window.put"), await page.evaluate("window.plain"), events.as_dict()
            finally:
                await browser.close()

    with _pair(cors) as (page_origin, other_origin, hits):
        put, plain, recorded = asyncio.run(drive(page_origin, other_origin))
    preflights = [hit for hit in hits if hit[1] == "OPTIONS"]
    assert preflights and all(hit[3] is None for hit in preflights)  # a preflight carries no session
    assert all(hit[4].lower() == "x-page-header" for hit in preflights)  # the page's own header only
    if cors == "allow":
        assert put == "put-ok" and plain == "plain-ok"
        assert ("other", "PUT", "/item", SECRET, "") in hits
    else:
        assert put == "failed" and [hit for hit in hits if hit[1] == "PUT"] == []
        assert recorded["counts"]["cors_preflight_refused"] == 1
        # The simple GET is sent, but without Access-Control-Allow-Origin the page cannot read it.
        assert plain == "failed"


def test_local_network_access_is_granted_only_under_the_destination_guard():
    from scanner_tools import proof_of_exploit
    from scanner_tools.destination_guard import destination_guard

    async def drive(page_origin: str, guarded: bool):
        try:
            if guarded:
                with destination_guard(lambda url: urlsplit(url).hostname == "127.0.0.1"):
                    proof = await proof_of_exploit.prove_xss_headless(
                        f"{page_origin}/spa", "q", "x", headers={"X-API-Key": SECRET})
            else:
                proof = await proof_of_exploit.prove_xss_headless(
                    f"{page_origin}/spa", "q", "x", headers={"X-API-Key": SECRET})
            return proof.to_dict()
        finally:
            browser, playwright = proof_of_exploit._browser_instance, proof_of_exploit._playwright_instance
            proof_of_exploit._browser_instance = proof_of_exploit._playwright_instance = None
            if browser is not None:
                await browser.close()
            if playwright is not None:
                await playwright.stop()

    with _pair() as (page_origin, _other, hits):
        guarded = asyncio.run(drive(page_origin, True))
        guarded_hits = list(hits)
        hits.clear()
        unguarded = asyncio.run(drive(page_origin, False))
    # The internal SPA (app and API on two loopback origins) loads under the guard ...
    assert ("other", "GET", "/bundle.js", None, "") in guarded_hits
    assert ("other", "GET", "/api/data", None, "") in guarded_hits
    assert "private_network_subresource_blocked" not in (guarded.get("coverage_reasons") or [])
    # ... and outside it Chromium still refuses, and the proof says so.
    assert "private_network_subresource_blocked" in unguarded["coverage_reasons"]
