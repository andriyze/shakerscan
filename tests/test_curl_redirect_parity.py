"""A session-carrying ``curl -L`` run hop by hop behaves exactly like ``curl -L`` on its origin.

The scanner's runner follows the redirects of a curl request that carries a custom session
header itself, one hop at a time, so it can stop at another origin. On the target's own origin
the result must be what real curl prints and does: the same bytes on stdout (header blocks of
every hop for ``-i``, ``-I`` and ``-D -``, empty-body redirects included), the same exit status
(47 past ``--max-redirs``), the same requests on the wire (a body dropped after 301/302/303 even
with ``-X``, kept after 307/308), and the same cookie engine (cookies set during the redirect
are sent on the next hop and written to the ``-c`` jar).

Each case runs real curl directly and through ``common.run`` against one loopback server whose
responses do not depend on time, and compares stdout, exit status, the server's view of every
request and the jar files.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import http.server
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import common  # noqa: E402
from scanner_tools.request_meter import configure_request_meter  # noqa: E402

SESSION = ["-H", "X-API-Key: fixture-key-not-a-real-credential"]
pytestmark = pytest.mark.skipif(shutil.which("curl") is None, reason="curl is required")


@contextmanager
def _server():
    seen: list[tuple[str, str, str, str]] = []  # method, path, body, cookie

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def version_string(self):
            return "fixture"

        def date_time_string(self, timestamp=None):
            return "Tue, 20 Oct 2026 00:00:00 GMT"

        def log_message(self, *_args):
            pass

        def _any(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode() if length else ""
            path = self.path
            seen.append((self.command, path, body, self.headers.get("Cookie") or ""))
            routes = {
                "/empty": (302, "/final", b"", []),
                "/body": (302, "/final", b"moved here", []),
                "/chain": (301, "/empty", b"", []),
                "/see": (303, "/final", b"", []),
                "/temp": (307, "/final", b"", []),
                "/perm": (308, "/final", b"", []),
                "/multi": (300, "/final", b"", []),
                "/setc": (302, "/final", b"", ["sid=abc123; Path=/"]),
                "/loop": (302, "/loop2", b"", []),
                "/loop2": (302, "/loop3", b"", []),
                "/loop3": (302, "/final", b"", []),
            }
            status, location, payload, cookies = routes.get(path, (200, "", f"final {self.command}".encode(), []))
            self.send_response(status)
            if location:
                self.send_header("Location", location)
            for cookie in cookies:
                self.send_header("Set-Cookie", cookie)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        do_GET = do_POST = do_PUT = do_HEAD = _any

    try:
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    except PermissionError:
        pytest.skip("test sandbox does not permit a loopback listener")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", seen
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(autouse=True)
def _plain_environment(monkeypatch):
    for name in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "*")
    configure_request_meter(limit=None, target_host=None, mode="off")


def _both(args: list[str], path: str, tmp_path: Path, jar_args: tuple[str, ...] = ()):
    """(real curl, runner) results: stdout, exit status, the server's requests and the jar."""
    results = []
    for mode in ("curl", "runner"):
        jar = tmp_path / f"{mode}.jar"
        if jar.exists():
            jar.unlink()
        extra = [arg.replace("JAR", str(jar)) for arg in jar_args]
        with _server() as (origin, seen):
            argv = ["curl", "-sS", "-L", *args, *extra, *SESSION, origin + path]
            if mode == "curl":
                done = subprocess.run(argv, capture_output=True, timeout=20)
                # As the runner reads it: bytes decoded, then stripped (no newline translation).
                out, rc = done.stdout.decode(errors="ignore").strip(), done.returncode
            else:
                out, _err, rc = asyncio.run(common.run(argv, timeout=20))
            out = out.replace(origin, "ORIGIN")  # each run has its own port
            requests = [(method, p, body, cookie) for method, p, body, cookie in seen]
        jar_text = jar.read_text() if jar.exists() else None
        results.append((out, rc, requests, jar_text))
    return results


@pytest.mark.parametrize("args", [["-i"], ["-I"], ["-D", "-"], ["-i", "-w", "\n%{http_code} %{url_effective}"], []])
@pytest.mark.parametrize("path", ["/empty", "/body", "/chain", "/multi"])
def test_followed_output_is_byte_identical_to_curl(args, path, tmp_path):
    real, runner = _both(args, path, tmp_path)
    assert runner == real


@pytest.mark.parametrize("path", ["/empty", "/see", "/temp", "/perm"])
@pytest.mark.parametrize("args", [["-X", "POST", "-d", "password=hunter2"], ["-d", "password=hunter2"],
                                  ["-X", "PUT", "--data-raw", "x=1", "-i"]])
def test_request_bodies_follow_curl_rules(args, path, tmp_path):
    real, runner = _both(args, path, tmp_path)
    assert runner[2] == real[2]
    assert runner == real


@pytest.mark.parametrize("jar_args", [("-c", "JAR"), ("-b", "JAR", "-c", "JAR"), ("-b", "pre=1", "-c", "JAR"),
                                      ("-b", "pre=1",), ("-b", "JAR")])
def test_cookie_engine_matches_curl(jar_args, tmp_path):
    real, runner = _both(["-i"], "/setc", tmp_path, jar_args)
    assert runner[2] == real[2]
    assert runner[3] == real[3]
    assert runner == real


@pytest.mark.parametrize("limit", ["0", "1", "2", "3"])
def test_max_redirs_matches_curl(limit, tmp_path):
    real, runner = _both(["-i", "--max-redirs", limit], "/loop", tmp_path)
    assert runner == real


@contextmanager
def _lf_only_server():
    """A server that ends its header lines with a bare LF (curl prints them as received)."""
    import socket

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(16)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            with conn:
                request = conn.recv(65536).decode(errors="ignore")
                path = request.split(" ", 2)[1] if " " in request else "/"
                if path == "/lf":
                    conn.sendall(b"HTTP/1.1 302 Found\nLocation: /final\nContent-Length: 0\nConnection: close\n\n")
                else:
                    conn.sendall(b"HTTP/1.1 200 OK\nContent-Length: 2\nConnection: close\n\nok")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{listener.getsockname()[1]}"
    finally:
        stop.set()
        listener.close()


@pytest.mark.parametrize("args", [["-i"], ["-I"], ["-D", "-"]])
def test_lf_only_header_blocks_match_curl(args):
    with _lf_only_server() as origin:
        argv = ["curl", "-sS", "-L", *args, *SESSION, origin + "/lf"]
        done = subprocess.run(argv, capture_output=True, timeout=20)
        real = (done.stdout.decode(errors="ignore").strip(), done.returncode)
        out, _err, rc = asyncio.run(common.run(argv, timeout=20))
    assert (out, rc) == real
