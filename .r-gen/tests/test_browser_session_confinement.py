"""A header-carrying browser context behaves like a plain one, except that it reaches only its
bound origins.

The session headers are the context's own extra headers and its traffic goes through a proxy that
admits only the bound origins (``credential_redirects.confined_session_context``). Real headless
Chromium against loopback servers, each case compared with a plain context where the question is
whether the browser's own behaviour survived:

- 300 MB responses, chunked and with a Content-Length, are delivered as in a plain context and the
  engine's memory stays bounded;
- an EventSource and a fetch stream reader receive data while it is still being sent;
- nine CORS cases (simple, preflighted, refused preflight, credentials with ``*``, credentials
  without and with Access-Control-Allow-Credentials, no-cors opaque, a same-origin redirect to a
  cross-origin response) give the page exactly what an unconfined context with the same session
  headers gives it, request for request. (A custom session header makes a cross-origin request
  non-simple in any Chromium, so between two bound origins it is preflighted, as it always was;
  a context without the header is compared where it is the question: a single origin.)
- a bound origin's 302 to another origin, over HTTP and over HTTPS, reaches nothing there: the
  header never leaves the machine;
- an internal application on two bound loopback origins loads its bundle and its API.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import resource
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scanner"))

playwright_api = pytest.importorskip("playwright.async_api")

from scanner_tools.credential_redirects import confined_session_context  # noqa: E402

SECRET = "fixture-session-header-not-a-real-credential"
BIG = 300 * 1024 * 1024
CHUNK = b"\0" * (1024 * 1024)


def _handler(name: str, hits: list, ports: dict):
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

        def _origin(self):
            # Rebuilt from its parts (a literal scheme and loopback host, a numeric port), so a
            # response header never carries request text; every page here is on loopback.
            match = re.fullmatch(r"(https?)://(127\.0\.0\.1|localhost):(\d{1,5})", self.headers.get("Origin") or "")
            if not match:
                return ""
            scheme = "https" if match.group(1) == "https" else "http"
            host = "localhost" if match.group(2) == "localhost" else "127.0.0.1"
            return f"{scheme}://{host}:{int(match.group(3))}"

        def do_OPTIONS(self):  # noqa: N802
            hits.append((name, "OPTIONS", self.path, self.headers.get("X-API-Key")))
            if self.path.startswith("/put-refused"):
                self._send(403, b"no")
                return
            self._send(204, extra=[("Access-Control-Allow-Origin", self._origin()),
                                   ("Access-Control-Allow-Methods", "PUT, GET"),
                                   ("Access-Control-Allow-Headers", "x-page-header, x-api-key")])

        def do_PUT(self):  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            hits.append((name, "PUT", self.path, self.headers.get("X-API-Key")))
            self._send(200, b"put-ok", "text/plain", [("Access-Control-Allow-Origin", self._origin())])

        def do_GET(self):  # noqa: N802
            path = self.path.split("?", 1)[0]
            hits.append((name, "GET", path, self.headers.get("X-API-Key")))
            other = f"http://127.0.0.1:{ports.get('other', 0)}"
            origin = self._origin()
            if path in {"/big-length", "/big-chunked"}:
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Access-Control-Allow-Origin", "*")
                if path == "/big-length":
                    self.send_header("Content-Length", str(BIG))
                else:
                    self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                try:
                    for _ in range(BIG // len(CHUNK)):
                        if path == "/big-length":
                            self.wfile.write(CHUNK)
                        else:
                            self.wfile.write(b"%x\r\n%s\r\n" % (len(CHUNK), CHUNK))
                    if path == "/big-chunked":
                        self.wfile.write(b"0\r\n\r\n")
                except OSError:
                    pass
            elif path in {"/events", "/stream"}:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream" if path == "/events" else "text/plain")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                try:
                    for index in range(6):
                        data = f"data: {index}\n\n".encode()
                        self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
                        self.wfile.flush()
                        time.sleep(0.5)
                    self.wfile.write(b"0\r\n\r\n")
                except OSError:
                    pass
            elif path == "/page":
                self._send(200, b"<html>ok</html>")
            elif path == "/redir":
                self._send(302, extra=[("Location", f"{other}/simple-none")])
            elif path == "/simple-acao":
                self._send(200, b"simple-acao", "text/plain", [("Access-Control-Allow-Origin", origin)])
            elif path == "/simple-none" or path == "/opaque":
                self._send(200, b"no-acao", "text/plain")
            elif path == "/cred-star":
                self._send(200, b"cred-star", "text/plain", [("Access-Control-Allow-Origin", "*")])
            elif path == "/cred-noacac":
                self._send(200, b"cred-noacac", "text/plain", [("Access-Control-Allow-Origin", origin)])
            elif path == "/cred-ok":
                self._send(200, b"cred-ok", "text/plain", [("Access-Control-Allow-Origin", origin),
                                                          ("Access-Control-Allow-Credentials", "true")])
            elif path == "/spa":
                self._send(200, (f'<html><script src="{other}/bundle.js"></script><script>'
                                 f"window.api = fetch('{other}/api/data').then(r => r.text(), e => 'failed');"
                                 "</script>spa</html>").encode())
            elif path == "/bundle.js":
                self._send(200, b"window.bundle = true;", "application/javascript")
            elif path == "/api/data":
                self._send(200, b"data-ok", "text/plain", [("Access-Control-Allow-Origin", origin)])
            else:
                self._send(200, b"<html>ok</html>")

    return Handler


@contextmanager
def _pair():
    hits: list = []
    ports: dict = {}
    try:
        page = ThreadingHTTPServer(("127.0.0.1", 0), _handler("page", hits, ports))
        other = ThreadingHTTPServer(("127.0.0.1", 0), _handler("other", hits, ports))
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


async def _context(browser, confined: bool, origins: list[str], *, headers: bool = True, **options):
    """The confined context, or the same browser context with the same session headers but no
    confinement (what Chromium does with these headers anywhere)."""
    if not confined:
        extra = {"extra_http_headers": {"X-API-Key": SECRET}} if headers else {}
        return await browser.new_context(**options, **extra), None
    return await confined_session_context(browser, origins, {"X-API-Key": SECRET}, **options)


def _rss_bytes() -> int:
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return usage if sys.platform == "darwin" else usage * 1024


@pytest.mark.parametrize("path", ["/big-length", "/big-chunked"])
def test_large_responses_behave_as_in_a_plain_context(path):
    async def drive(page_origin: str, confined: bool):
        async with playwright_api.async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            try:
                context, _events = await _context(browser, confined, [page_origin])
                page = await context.new_page()
                await page.goto(page_origin + "/page")
                return await page.evaluate(
                    f"fetch('{path}').then(r => r.arrayBuffer()).then(b => b.byteLength, e => 'failed')")
            finally:
                await browser.close()

    with _pair() as (page_origin, _other, _hits):
        plain = asyncio.run(drive(page_origin, False))
        before = _rss_bytes()
        confined = asyncio.run(drive(page_origin, True))
        grown = _rss_bytes() - before
    assert confined == plain == BIG
    assert grown < 100 * 1024 * 1024  # the proxy streams; nothing is held in this process


def test_streams_arrive_while_they_are_sent():
    script = """
      window.events = []; window.chunks = [];
      new EventSource('/events').onmessage = e => events.push(e.data);
      fetch('/stream').then(async r => { const reader = r.body.getReader();
        for (;;) { const {done, value} = await reader.read(); if (done) break; chunks.push(value.length); } });
    """

    async def drive(page_origin: str):
        async with playwright_api.async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            try:
                context, _events = await _context(browser, True, [page_origin])
                page = await context.new_page()
                await page.goto(page_origin + "/page")
                await page.evaluate(script)
                await page.wait_for_timeout(1600)
                return await page.evaluate("[window.events.length, window.chunks.length]")
            finally:
                await browser.close()

    with _pair() as (page_origin, _other, hits):
        events, chunks = asyncio.run(drive(page_origin))
    assert events >= 2 and chunks >= 2  # delivered while both streams are still open
    assert ("page", "GET", "/events", SECRET) in hits  # the session header, natively


CORS_SCRIPT = """(async () => {
  const other = OTHER;
  const read = async (promise) => { try { const r = await promise;
      return r.type === 'opaque' ? 'opaque:' + r.status : r.status + ':' + await r.text(); }
    catch (e) { return 'failed'; } };
  return {
    simple_acao: await read(fetch(other + '/simple-acao')),
    simple_none: await read(fetch(other + '/simple-none')),
    preflight_ok: await read(fetch(other + '/put', {method: 'PUT', body: 'x', headers: {'X-Page-Header': '1'}})),
    preflight_refused: await read(fetch(other + '/put-refused', {method: 'PUT', body: 'x', headers: {'X-Page-Header': '1'}})),
    credentials_star: await read(fetch(other + '/cred-star', {credentials: 'include'})),
    credentials_no_acac: await read(fetch(other + '/cred-noacac', {credentials: 'include'})),
    credentials_ok: await read(fetch(other + '/cred-ok', {credentials: 'include'})),
    no_cors_opaque: await read(fetch(other + '/opaque', {mode: 'no-cors'})),
    redirect_to_cross_origin: await read(fetch('/redir')),
  };
})()"""


def test_cors_gives_the_page_what_a_plain_context_gives_it():
    async def drive(page_origin: str, other_origin: str, confined: bool):
        async with playwright_api.async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            try:
                context, _events = await _context(browser, confined, [page_origin, other_origin])
                page = await context.new_page()
                await page.goto(page_origin + "/page")
                return await page.evaluate(CORS_SCRIPT.replace("OTHER", json.dumps(other_origin)))
            finally:
                await browser.close()

    with _pair() as (page_origin, other_origin, hits):
        plain = asyncio.run(drive(page_origin, other_origin, False))
        plain_requests = [(name, method, path) for name, method, path, _key in hits]
        hits.clear()
        confined = asyncio.run(drive(page_origin, other_origin, True))
        confined_requests = [(name, method, path) for name, method, path, _key in hits]
    assert len(plain) == 9
    assert confined == plain
    assert confined_requests == plain_requests  # the same preflights, the same requests
    assert plain["preflight_refused"] == "failed" and plain["simple_acao"] == "200:simple-acao"
    assert plain["no_cors_opaque"] == "opaque:0"
    assert ("other", "PUT", "/put-refused") not in confined_requests  # a refused preflight stops it


def _tls_server(hits: list, name: str, cert: Path, key: Path):
    """A TLS listener that records every accepted connection and answers each request."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    ports = {"self": listener.getsockname()[1]}

    def serve():
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            hits.append((name, "connection"))
            try:
                with tls.wrap_socket(conn, server_side=True) as secure:
                    request = secure.recv(65536).decode(errors="ignore")
                    hits.append((name, request.split("\r\n", 1)[0], SECRET in request))
                    location = ports.get("location")
                    if location and " /go " in request:
                        secure.sendall(f"HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n"
                                       "Connection: close\r\n\r\n".encode())
                    else:
                        secure.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            except (OSError, ssl.SSLError):
                pass

    threading.Thread(target=serve, daemon=True).start()
    return listener, ports


@pytest.mark.parametrize("scheme", ["http", "https"])
def test_a_redirect_to_another_origin_never_carries_the_header_out(scheme, tmp_path):
    hits: list = []
    if scheme == "https":
        if shutil.which("openssl") is None:
            pytest.skip("openssl is required to make a test certificate")
        cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj",
                        "/CN=localhost", "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
        target, target_ports = _tls_server(hits, "target", cert, key)
        other, _other_ports = _tls_server(hits, "other", cert, key)
        target_ports["location"] = f"https://localhost:{other.getsockname()[1]}/landed"
        start = f"https://127.0.0.1:{target.getsockname()[1]}/go"
    else:
        ports: dict = {}
        server_hits: list = []
        target = ThreadingHTTPServer(("127.0.0.1", 0), _handler("target", server_hits, ports))
        other = ThreadingHTTPServer(("127.0.0.1", 0), _handler("other", server_hits, ports))
        ports["other"] = other.server_port
        for server in (target, other):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        start = f"http://127.0.0.1:{target.server_port}/redir"

    async def drive():
        async with playwright_api.async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            try:
                context, events = await confined_session_context(
                    browser, [start], {"X-API-Key": SECRET}, ignore_https_errors=True)
                page = await context.new_page()
                try:
                    await page.goto(start, wait_until="load", timeout=10000)
                except playwright_api.Error:
                    pass
                return events.as_dict()
            finally:
                await browser.close()

    try:
        recorded = asyncio.run(drive())
    finally:
        if scheme == "https":
            target.close()
            other.close()
        else:
            for server in (target, other):
                server.shutdown()
                server.server_close()
    if scheme == "https":
        assert ("target", "GET /go HTTP/1.1", True) in hits  # the bound origin has the header
        assert [hit for hit in hits if hit[0] == "other"] == []  # CONNECT refused: no connection at all
    else:
        assert ("target", "GET", "/redir", SECRET) in server_hits
        assert [hit for hit in server_hits if hit[0] == "other"] == []
    assert recorded["counts"]["session_cross_origin_refused"] >= 1
    assert recorded["counts"]["session_navigation_redirect_refused"] == 1


def test_an_internal_application_on_two_bound_origins_loads():
    async def drive(page_origin: str, other_origin: str):
        async with playwright_api.async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            try:
                context, events = await confined_session_context(browser, [page_origin, other_origin],
                                                                 {"X-API-Key": SECRET})
                page = await context.new_page()
                await page.goto(page_origin + "/spa", wait_until="load")
                return await page.evaluate("(async () => [window.bundle === true, await window.api])()"), events.as_dict()
            finally:
                await browser.close()

    with _pair() as (page_origin, other_origin, hits):
        (bundle, api), recorded = asyncio.run(drive(page_origin, other_origin))
    assert bundle is True and api == "data-ok"
    assert ("other", "GET", "/bundle.js", SECRET) in hits and ("other", "GET", "/api/data", SECRET) in hits
    assert recorded["reasons"] == []
