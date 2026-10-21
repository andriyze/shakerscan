"""The V2 browser capability sends trusted headers only to the bound origin, through the pin.

The capability's browser reaches the network only through the job's pinned SOCKS proxy, which
admits the target's hostname and its pinned addresses on the target's port. That still leaves
one other origin: the pinned address written as a host (``http://127.0.0.1:<port>`` for a target
``http://target.fixture.invalid:<port>``). A route that continued a same-origin request with the
trusted headers carried them into every redirect hop, so a redirect to that address received
them. Here a real Chromium drives the capability against a loopback server reached as
``target.fixture.invalid`` (resolvable only through the pin, so a request that bypassed the
proxy would fail) and as ``127.0.0.1``.
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
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pytest.importorskip("playwright.async_api")

from api.capabilities import browser  # noqa: E402
from api.runtime.models import TargetBinding  # noqa: E402

SECRET = "fixture-trusted-header-not-a-real-credential"
HOST = "target.fixture.invalid"
NAV_REFUSED = "session_navigation_redirect_refused"


@contextmanager
def _server():
    hits: list[tuple[str, str, str | None]] = []  # Host, path, X-API-Key
    ports: dict[str, int] = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _reply(self, status, body=b"", location=""):
            self.send_response(status)
            if location:
                self.send_header("Location", location)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            hits.append((self.headers.get("Host") or "", self.path, self.headers.get("X-API-Key")))
            address = f"http://127.0.0.1:{ports['port']}"
            if self.path == "/page":
                # Scripts hold the load event, so the action waits for their redirects.
                self._reply(200, (
                    '<html><body>page<script src="/api/same"></script>'
                    '<script src="/api/cross"></script></body></html>').encode())
            elif self.path == "/nav-cross":
                self._reply(302, location=f"{address}/landed")
            elif self.path == "/nav-same":
                self._reply(302, location="/landed")
            elif self.path == "/api/same":
                self._reply(302, location="/api/final")
            elif self.path == "/api/cross":
                self._reply(302, location=f"{address}/xhr-landed")
            else:
                self._reply(200, b"<html><body>ok</body></html>")

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    except PermissionError:
        pytest.skip("test sandbox does not permit a loopback listener")
    ports["port"] = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, hits
    finally:
        server.shutdown()
        server.server_close()


def _run(port: int, path: str):
    origin = f"http://{HOST}:{port}"
    target = TargetBinding("fixture", "web", HOST, (origin,), ("127.0.0.1",), "scope")
    prepared = browser.BrowserNavigateAdapter.prepare(
        target=target, base_url=origin, args={"path": path, "max_requests": 8},
    )

    async def heartbeat():
        return None

    return asyncio.run(browser._execute_browser_action(
        prepared, heartbeat=heartbeat, cancelled=lambda: False, trusted_headers={"X-API-Key": SECRET},
    ))


def _to_address(hits):
    return [(host, path, key) for host, path, key in hits if host.startswith("127.0.0.1")]


def test_a_redirect_to_the_pinned_address_as_another_origin_carries_no_trusted_header():
    with _server() as (port, hits):
        _run(port, "/nav-cross")
    # The hop to the address is refused at the pinned proxy (a hostname target is reached by
    # its hostname only); whatever reaches the server under that name carries no header.
    assert [hit for hit in _to_address(hits) if hit[2]] == []
    assert (f"{HOST}:{port}", "/nav-cross", SECRET) in hits


def test_subresource_redirects_keep_the_header_on_the_origin_only():
    with _server() as (port, hits):
        result = _run(port, "/page")
    assert result.status == "success", result
    assert [hit for hit in _to_address(hits) if hit[2]] == []
    assert (f"{HOST}:{port}", "/page", SECRET) in hits
    assert (f"{HOST}:{port}", "/api/final", SECRET) in hits


def test_a_same_origin_redirect_keeps_the_header_and_a_refused_hop_is_recorded():
    with _server() as (port, hits):
        same = _run(port, "/nav-same")
    assert same.status == "success", same
    assert (f"{HOST}:{port}", "/landed", SECRET) in hits  # Chromium carries it within the origin
    with _server() as (port, hits):
        cross = _run(port, "/nav-cross")
    coverage = [row for row in cross.observations if row.get("kind") == "browser_session_header_coverage"]
    assert coverage, cross.observations
    assert "session_cross_origin_refused" in coverage[0]["reasons"]
    assert "session_navigation_redirect_refused" in coverage[0]["reasons"]


def test_scan_coverage_reads_the_browser_session_reasons():
    from api.scan.finalizer import browser_session_header_reasons

    observations = {
        "web.browser_crawl:1": ({"kind": "browser_navigation"},
                                {"kind": "browser_session_header_coverage", "reasons": [NAV_REFUSED],
                                 "counts": {NAV_REFUSED: 1}}),
        "web.probe:1": ({"kind": "http_response"},),
    }
    assert browser_session_header_reasons(observations) == {NAV_REFUSED}
    assert browser_session_header_reasons({}) == set()
