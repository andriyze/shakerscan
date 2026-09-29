"""API-process connectivity checks must not follow a target's redirect off its origin."""

from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

import pytest

import ai_assurance
from ai_targets import router as ai_router
from redirect_policy import is_same_origin_redirect


@contextmanager
def _http_server(routes):
    """Serve ``routes`` (path -> (status, headers, body)) and record every request seen."""
    seen: list[dict[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def _answer(self):
            seen.append({"path": self.path, "authorization": self.headers.get("Authorization", "")})
            status, headers, body = routes.get(self.path, (404, {}, b"missing"))
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_OPTIONS = _answer

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", seen
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize(
    ("current", "redirect", "expected"),
    [
        ("https://ai.example/chat", "/chat/", True),
        ("https://ai.example/chat", "https://AI.example:443/v2", True),
        ("http://ai.example/chat", "https://ai.example/chat", True),
        ("http://ai.example:8080/chat", "https://ai.example/chat", False),
        ("https://ai.example/chat", "http://ai.example/chat", False),
        ("https://ai.example/chat", "https://ai.example:8443/chat", False),
        ("https://ai.example/chat", "http://169.254.169.254/latest/meta-data/", False),
        ("https://ai.example/chat", "https://ai.example.attacker.test/chat", False),
        ("https://ai.example/chat", "//internal-service/chat", False),
        ("https://ai.example/chat", "file:///etc/passwd", False),
    ],
)
def test_same_origin_redirect_decision(current, redirect, expected):
    assert is_same_origin_redirect(current, redirect) is expected


def test_mcp_metadata_fetch_reports_but_does_not_follow_cross_origin_redirect():
    with _http_server({"/internal": (200, {}, b'{"secret": "internal"}')}) as (internal, internal_seen):
        routes = {"/mcp": (302, {"Location": f"{internal}/internal"}, b"")}
        with _http_server(routes) as (target, target_seen):
            result = ai_assurance._fetch_url_metadata(
                f"{target}/mcp", headers={"Authorization": "Bearer operator-configured"},
            )

    assert result["status_code"] == 302
    assert "internal" not in result["body_excerpt"]
    assert [item["path"] for item in target_seen] == ["/mcp"]
    assert internal_seen == []


def test_mcp_metadata_fetch_still_follows_same_origin_redirect():
    routes = {
        "/mcp": (307, {"Location": "/mcp/"}, b""),
        "/mcp/": (200, {"Content-Type": "application/json"}, b'{"ok": true}'),
    }
    with _http_server(routes) as (target, seen):
        result = ai_assurance._fetch_url_metadata(f"{target}/mcp")

    assert result["status_code"] == 200
    assert result["json"] == {"ok": True}
    assert [item["path"] for item in seen] == ["/mcp", "/mcp/"]


def test_ai_connectivity_probe_does_not_carry_headers_across_origins():
    with _http_server({"/collect": (200, {}, b'{"reply": "leaked"}')}) as (other, other_seen):
        routes = {"/chat": (302, {"Location": f"{other}/collect"}, b"")}
        with _http_server(routes) as (target, target_seen):
            result = ai_router._run_ai_target_connectivity_probe(
                {
                    "target_type": "api_chat",
                    "method": "GET",
                    "endpoint_url": f"{target}/chat",
                    "headers_template": {"Authorization": "Bearer operator-configured"},
                    "request_template": {},
                    "response_path": "reply",
                },
                prompt="connectivity check",
                timeout_seconds=5,
            )

    assert result["status_code"] == 302
    assert result["ok"] is False
    assert target_seen and target_seen[0]["authorization"] == "Bearer operator-configured"
    assert other_seen == []
