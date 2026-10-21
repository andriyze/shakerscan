"""Edges of the network confinement of header-carrying browser contexts.

Real headless Chromium against loopback servers (and a UDP listener):

- WebRTC sends no UDP from a confined context or from the pinned Scan/Hunt browser;
- a refused plain-HTTP request is a network error to the page, never a 403 "from" the other
  origin, and the crawler records no such endpoint;
- the caller's own context permissions and extra headers are kept;
- closing a confined context closes its open tunnels;
- the pinned proxy admits its bound origin's scheme only;
- a retest's destination guard still applies inside a confined context, and a bound host's
  other ports are not admitted.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sys
import threading
import time
import urllib.parse

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scanner"))
sys.path.append(str(ROOT / "api"))

playwright_api = pytest.importorskip("playwright.async_api")

from scanner_tools.credential_redirects import _admits, bound_origins, confined_session_context  # noqa: E402

SECRET = "fixture-session-header-not-a-real-credential"
RTC_SCRIPT = """(async (port) => {
  const pc = new RTCPeerConnection({iceServers: [{urls: 'stun:127.0.0.1:' + port}]});
  pc.createDataChannel('x');
  await pc.setLocalDescription(await pc.createOffer());
  await new Promise(r => setTimeout(r, 1500));
  return 'ran';
})"""


@contextmanager
def _udp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.2)
    packets: list = []
    stop = threading.Event()

    def listen():
        while not stop.is_set():
            try:
                packets.append(sock.recvfrom(2048)[0])
            except (socket.timeout, OSError):
                continue

    thread = threading.Thread(target=listen, daemon=True)
    thread.start()
    try:
        yield sock.getsockname()[1], packets
    finally:
        stop.set()
        thread.join(1)
        sock.close()


@contextmanager
def _servers():
    hits: list = []
    ports: dict = {}

    def handler(name):
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_GET(self):  # noqa: N802
                hits.append((name, self.path, self.headers.get("X-API-Key"), self.headers.get("X-Caller")))
                if self.path == "/nav-cross":
                    self.send_response(302)
                    self.send_header("Location", f"http://localhost:{ports['other']}/landed")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path == "/endless":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    try:
                        while True:
                            self.wfile.write(b"9\r\ndata: x\n\n\r\n")
                            self.wfile.flush()
                            time.sleep(0.2)
                    except OSError:
                        hits.append((name, "stream-closed", None, None))
                    return
                body = b"<html><body>ok<script>window.es = new EventSource('/endless')</script></body></html>" \
                    if self.path == "/streaming-page" else b"<html><body>ok</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return Handler

    target = ThreadingHTTPServer(("127.0.0.1", 0), handler("target"))
    other = ThreadingHTTPServer(("127.0.0.1", 0), handler("other"))
    ports["other"] = other.server_port
    for server in (target, other):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{target.server_port}", hits
    finally:
        for server in (target, other):
            server.shutdown()
            server.server_close()


async def _browser(playwright):
    return await playwright.chromium.launch()


def test_webrtc_sends_no_udp_from_a_confined_context():
    async def drive(target: str, port: int, confined: bool):
        async with playwright_api.async_playwright() as playwright:
            browser = await _browser(playwright)
            try:
                if confined:
                    context, _events = await confined_session_context(browser, [target], {"X-API-Key": SECRET})
                else:
                    context = await browser.new_context()
                page = await context.new_page()
                await page.goto(target + "/")
                try:
                    return await page.evaluate(RTC_SCRIPT, port)
                except playwright_api.Error:
                    return "blocked"
            finally:
                await browser.close()

    with _servers() as (target, _hits):
        with _udp_listener() as (port, plain_packets):
            assert asyncio.run(drive(target, port, False)) == "ran"
        with _udp_listener() as (port, confined_packets):
            asyncio.run(drive(target, port, True))
    assert plain_packets  # the probe works: an unconfined page reaches the UDP listener
    assert confined_packets == []


def test_webrtc_sends_no_udp_from_the_pinned_scan_browser():
    from api.capabilities import browser
    from api.runtime.models import TargetBinding

    host = "target.fixture.invalid"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):  # noqa: N802
            body = (f"<html><body><script>({RTC_SCRIPT})({self.server.udp_port})</script>ok</body></html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://{host}:{server.server_port}"
    target = TargetBinding("fixture", "web", host, (origin,), ("127.0.0.1",), "scope")
    prepared = browser.BrowserNavigateAdapter.prepare(
        target=target, base_url=origin, args={"path": "/", "max_requests": 4, "wait_until": "load"})

    async def heartbeat():
        return None

    async def drive():
        result = await browser._execute_browser_action(
            prepared, heartbeat=heartbeat, cancelled=lambda: False, trusted_headers={"X-API-Key": SECRET})
        await asyncio.sleep(1.5)
        return result

    try:
        with _udp_listener() as (port, packets):
            server.udp_port = port
            asyncio.run(drive())
    finally:
        server.shutdown()
        server.server_close()
    assert packets == []


def test_a_refused_plain_http_request_is_a_network_error_not_a_403(tmp_path):
    from scanner_tools import http_scanner

    class _Session:
        def export_session(self):
            return {"headers": {"X-API-Key": SECRET}, "cookies": {}}

    async def drive(target: str):
        async with playwright_api.async_playwright() as playwright:
            browser = await _browser(playwright)
            try:
                context, _events = await confined_session_context(browser, [target], {"X-API-Key": SECRET})
                page = await context.new_page()
                statuses = []
                page.on("response", lambda response: statuses.append((response.url, response.status)))
                with pytest.raises(playwright_api.Error):
                    await page.goto(target + "/nav-cross")
                return statuses
            finally:
                await browser.close()

    with _servers() as (target, hits):
        statuses = asyncio.run(drive(target))
        crawl = asyncio.run(http_scanner.browser_fetch(f"{target}/nav-cross", screenshot_dir=str(tmp_path),
                                                       auth_session=_Session()))
    assert [status for url, status in statuses if "localhost" in url] == []
    assert [hit for hit in hits if hit[0] == "other"] == []
    other = f"localhost:{urllib.parse.urlsplit(target).port}"
    recorded = json.dumps({key: crawl.get(key) for key in ("captured_requests", "api_endpoints", "page_urls")})
    assert "localhost" not in recorded and other not in recorded
    assert "403" not in str(crawl.get("status") or "")


def test_caller_permissions_and_headers_are_kept():
    async def drive(target: str):
        async with playwright_api.async_playwright() as playwright:
            browser = await _browser(playwright)
            try:
                context, _events = await confined_session_context(
                    browser, [target], {"X-API-Key": SECRET},
                    permissions=["geolocation"], extra_http_headers={"X-Caller": "kept"})
                page = await context.new_page()
                await page.goto(target + "/")
                return await page.evaluate(
                    "navigator.permissions.query({name: 'geolocation'}).then(p => p.state)")
            finally:
                await browser.close()

    with _servers() as (target, hits):
        state = asyncio.run(drive(target))
    assert state == "granted"
    assert ("target", "/", SECRET, "kept") in hits


def test_closing_a_session_closes_its_tunnels(tmp_path):
    import session_manager

    async def drive(target: str):
        session = session_manager.InteractiveSession("fixture-close", f"{target}/", results_dir=tmp_path)
        assert (await session.start())["success"]
        assert (await session.action({"action": "set_auth", "data": {"auth_header": f"Bearer {SECRET}"}}))["success"]
        await session.action({"action": "navigate", "data": {"url": f"{target}/streaming-page"}})
        await asyncio.sleep(1.0)  # the event stream is open through the context's proxy
        await session.close()
        await asyncio.sleep(0.5)
        return [task for task in asyncio.all_tasks()
                if "GuardProxy" in repr(task.get_coro()) or "_pump" in repr(task.get_coro())]

    with _servers() as (target, hits):
        lingering = asyncio.run(drive(target))
        time.sleep(0.5)
    assert lingering == []
    assert ("target", "stream-closed", None, None) in hits


def test_the_pinned_proxy_admits_its_bound_scheme_only():
    from pinned_socks_proxy import PinnedSocksProxy
    from tests.test_pinned_socks_proxy import _socks_connect

    async def scenario(scheme, first_bytes):
        received: list = []

        async def upstream(reader, writer):
            data = await reader.read(64)
            received.append(data)
            writer.close()

        server = await asyncio.start_server(upstream, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with PinnedSocksProxy(hostname="app.fixture.invalid", pinned_address="127.0.0.1",
                                    port=port, scheme=scheme) as proxy:
            reader, writer, code = await _socks_connect(proxy.proxy_url, "app.fixture.invalid", port)
            writer.write(first_bytes)
            await writer.drain()
            await asyncio.sleep(0.3)
            writer.close()
            receipt = proxy.receipt()
        server.close()
        return code, received, receipt

    tls_hello = b"\x16\x03\x01\x00\x05hello"
    plaintext = b"GET / HTTP/1.1\r\nHost: app\r\nX-API-Key: " + SECRET.encode() + b"\r\n\r\n"
    _code, received, receipt = asyncio.run(scenario("https", plaintext))
    assert received in ([], [b""]) and receipt["scheme_mismatch_refused"] == 1
    _code, received, _receipt = asyncio.run(scenario("https", tls_hello))
    assert received and received[0].startswith(b"\x16")
    _code, received, receipt = asyncio.run(scenario("http", tls_hello))
    assert received in ([], [b""]) and receipt["scheme_mismatch_refused"] == 1
    _code, received, _receipt = asyncio.run(scenario(None, plaintext))  # no scheme bound: unchanged
    assert received and received[0].startswith(b"GET ")


def test_a_retest_guard_still_applies_inside_a_confined_context():
    from scanner_tools.destination_guard import destination_guard

    async def drive(target: str):
        async with playwright_api.async_playwright() as playwright:
            browser = await _browser(playwright)
            try:
                with destination_guard(lambda url: False) as guard:
                    context, _events = await confined_session_context(browser, [target], {"X-API-Key": SECRET})
                    page = await context.new_page()
                    with pytest.raises(playwright_api.Error):
                        await page.goto(target + "/")
                    return list(guard.refused)
            finally:
                await browser.close()

    with _servers() as (target, hits):
        refused = asyncio.run(drive(target))
    assert hits == []  # the bound origin itself is refused when the retest guard refuses it
    assert refused and refused[0] == "127.0.0.1"


def test_a_bound_hosts_other_ports_are_not_admitted():
    origins = frozenset(bound_origins(["https://app.example:8443/", "http://api.example/"]))
    assert _admits(origins, "https://app.example:8443/")
    assert not _admits(origins, "https://app.example:9443/")  # a CONNECT to another port
    assert not _admits(origins, "https://app.example/")
    assert _admits(origins, "https://api.example:443/")  # the http origin's https upgrade
    assert _admits(origins, "https://api.example:80/")  # a tunnel to the http origin's own port
    assert not _admits(origins, "https://api.example:8080/")


def test_closing_the_guard_proxy_ends_its_open_tunnels():
    from scanner_tools.destination_guard import DestinationGuard, GuardProxy

    async def scenario():
        closed = asyncio.Event()

        async def endless(reader, writer):
            try:
                while True:
                    writer.write(b"x" * 1024)
                    await writer.drain()
                    await asyncio.sleep(0.05)
            except (ConnectionError, OSError):
                closed.set()

        upstream = await asyncio.start_server(endless, "127.0.0.1", 0)
        port = upstream.sockets[0].getsockname()[1]
        proxy = GuardProxy(DestinationGuard(lambda url: True), close_on_refusal=True)
        proxy_url = await proxy.start()
        reader, writer = await asyncio.open_connection("127.0.0.1", urllib.parse.urlsplit(proxy_url).port)
        writer.write(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
        await writer.drain()
        await reader.readuntil(b"\r\n\r\n")
        await reader.read(1024)  # the tunnel is carrying data
        proxy.close()
        await asyncio.wait_for(closed.wait(), timeout=3)
        await asyncio.sleep(0.1)
        lingering = [task for task in asyncio.all_tasks() if "_pump" in repr(task.get_coro())
                     or "GuardProxy" in repr(task.get_coro())]
        writer.close()
        upstream.close()
        return lingering

    assert asyncio.run(scenario()) == []
