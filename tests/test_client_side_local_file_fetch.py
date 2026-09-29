"""A scanned page must not be able to point the JS scanners at the scanner's own files."""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

from scanner_tools import client_side

LOCAL_SECRET = "ghp_" + "L" * 36


@contextmanager
def _serve_page(html: str, scripts: dict[str, str]):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = (scripts.get(self.path) if self.path in scripts else html).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def test_js_secret_scan_ignores_file_scheme_script_sources(tmp_path):
    local_file = tmp_path / "environ"
    local_file.write_text(f"SCANNER_TOKEN={LOCAL_SECRET}\n")
    html = f'<html><script src="file://{local_file}#.js"></script><script src="/app.js"></script></html>'
    with _serve_page(html, {"/app.js": "console.log('bundle');"}) as origin:
        result = asyncio.run(client_side.test_js_secrets(f"{origin}/", safe_mode=True))

    assert result["secrets_found"] == []
    assert result["vulnerable"] is False


def test_fetch_helper_only_opens_web_urls(tmp_path):
    local_file = tmp_path / "hostname"
    local_file.write_text("scanner-host\n")
    assert asyncio.run(client_side._fetch_url(f"file://{local_file}")) == ""
    with _serve_page("<html>ok</html>", {}) as origin:
        assert asyncio.run(client_side._fetch_url(f"{origin}/")) == "<html>ok</html>"
