import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from scanner.scanner_tools.http_scanner import (
    _BROWSER_SAFE_INTERACTION_SELECTORS,
    _browser_capture_request_is_safe,
    _browser_capture_response_header,
    _browser_capture_url,
    _browser_interaction_element_is_safe,
    _browser_interaction_method_allowed,
    _browser_navigation_url_is_safe,
    _guard_browser_interaction_request,
    browser_fetch,
)
from scanner.scanner_tools.request_meter import (
    configure_request_meter,
    install_async_client_metering,
)


def test_passive_browser_interactions_allow_only_read_only_methods():
    assert _browser_interaction_method_allowed("GET")
    assert _browser_interaction_method_allowed("head")
    assert _browser_interaction_method_allowed("OPTIONS")
    for method in ("POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE", ""):
        assert not _browser_interaction_method_allowed(method)


def test_passive_browser_capture_keeps_shape_without_values_or_cross_origin():
    safe_url = _browser_capture_url(
        "https://app.example.test/api/items?token=secret&view=public#private"
    )
    assert safe_url == "https://app.example.test/api/items?token=&view="
    assert _browser_capture_request_is_safe(
        url=safe_url,
        method="GET",
        allowed_origin="https://app.example.test:443",
    )
    assert not _browser_capture_request_is_safe(
        url=safe_url,
        method="POST",
        allowed_origin="https://app.example.test:443",
    )
    assert _browser_capture_response_header(
        "set-cookie", "session=secret-value; Secure; HttpOnly; SameSite=Lax",
    ) == "session=<redacted>; Secure; HttpOnly; SameSite=Lax"
    assert _browser_capture_response_header(
        "x-session-token", "secret-value",
    ) == "<redacted>"
    assert not _browser_capture_request_is_safe(
        url="https://cdn.example.test/api/items",
        method="GET",
        allowed_origin="https://app.example.test:443",
    )


def test_passive_browser_selectors_exclude_generic_action_controls():
    selectors = " ".join(_BROWSER_SAFE_INTERACTION_SELECTORS)
    assert 'button[type="button"]' not in selectors
    assert '[role="button"]' not in selectors
    assert ".MuiButton-root" not in selectors
    assert ".ant-btn" not in selectors
    assert "card" not in selectors.lower()
    assert "clickable-row" not in selectors


def test_passive_browser_element_filter_fails_closed_and_rejects_actions():
    assert _browser_interaction_element_is_safe("Overview", "/overview")
    assert _browser_interaction_element_is_safe("Runtime details", "/runtime")
    assert not _browser_interaction_element_is_safe()
    assert not _browser_interaction_element_is_safe("Start model review")
    assert not _browser_interaction_element_is_safe("Save settings")
    assert not _browser_interaction_element_is_safe("Delete target")
    assert not _browser_interaction_element_is_safe("Manage", "deleteAccount")
    assert not _browser_interaction_element_is_safe("Manage", "delete_all")
    assert not _browser_interaction_element_is_safe("", "", "", "", "", "")
    assert not _browser_navigation_url_is_safe("https://app.example.test/logoutUser")
    assert not _browser_navigation_url_is_safe("https://app.example.test/account/delete_all")
    assert _browser_navigation_url_is_safe("https://app.example.test/reports/create")


def test_passive_browser_route_aborts_mutations_and_redacts_query_values():
    class Route:
        aborted = None
        continued = False

        async def abort(self, reason):
            self.aborted = reason

        async def continue_(self):
            self.continued = True

    class Request:
        method = "POST"
        url = "https://app.example.test/api/start?token=secret#fragment"

    route = Route()
    guard = {"active": False, "blocked_count": 0, "blocked_samples": []}
    asyncio.run(_guard_browser_interaction_request(route, Request(), guard))

    assert route.aborted == "blockedbyclient"
    assert not route.continued
    assert guard["blocked_count"] == 1
    assert guard["blocked_samples"] == [
        {"method": "POST", "url": "https://app.example.test/api/start"}
    ]


def test_passive_browser_route_allows_navigation_get():
    class Route:
        aborted = None
        continued = False

        async def abort(self, reason):
            self.aborted = reason

        async def continue_(self):
            self.continued = True

    class Request:
        method = "GET"
        url = "https://app.example.test/overview"

    route = Route()
    asyncio.run(_guard_browser_interaction_request(
        route,
        Request(),
        {"active": True, "blocked_count": 0, "blocked_samples": []},
    ))
    assert route.continued
    assert route.aborted is None


def test_passive_browser_route_aborts_cross_origin_get_and_redacts_sample():
    class Route:
        aborted = None

        async def abort(self, reason):
            self.aborted = reason

        async def continue_(self):
            raise AssertionError("cross-origin request must not continue")

    class Request:
        method = "GET"
        url = "https://cdn.example.test/track?secret=private"

    route = Route()
    guard = {
        "allowed_origin": "https://app.example.test:443",
        "blocked_count": 0,
        "blocked_samples": [],
        "cross_origin_blocked_count": 0,
        "cross_origin_blocked_samples": [],
    }
    asyncio.run(_guard_browser_interaction_request(route, Request(), guard))

    assert route.aborted == "blockedbyclient"
    assert guard["cross_origin_blocked_count"] == 1
    assert guard["cross_origin_blocked_samples"] == [{
        "method": "GET",
        "url": "https://cdn.example.test/track",
    }]


def test_browser_fetch_blocks_state_change_from_semantic_tab(tmp_path):
    pytest.importorskip("playwright.async_api")
    class CrossOriginHandler(BaseHTTPRequestHandler):
        get_count = 0

        def do_GET(self):
            type(self).get_count += 1
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_args):
            return

    cross_server = ThreadingHTTPServer(("127.0.0.1", 0), CrossOriginHandler)
    cross_thread = threading.Thread(target=cross_server.serve_forever, daemon=True)
    cross_thread.start()

    class Handler(BaseHTTPRequestHandler):
        post_count = 0

        def do_GET(self):
            body = f"""<!doctype html><html><head><title>Safe fixture</title></head>
            <body><button role=\"tab\" onclick=\"
              fetch('/safe?token=secret-value');
              fetch('/mutate?token=secret-value',{{method:'POST'}});
              fetch('http://127.0.0.1:{cross_server.server_port}/track?token=secret-value');
            \">Overview</button>
            <a href=\"/second\">Details</a></body></html>""".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            type(self).post_count += 1
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        configure_request_meter(
            limit=100,
            target_host="127.0.0.1",
            mode="enforce",
            planned=100,
            reserved=100,
        )
        install_async_client_metering()
        result = asyncio.run(browser_fetch(
            f"http://127.0.0.1:{server.server_port}/",
            screenshot_dir=str(tmp_path),
            max_pages=1,
        ))
    finally:
        configure_request_meter(limit=None, target_host=None, mode="off")
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        cross_server.shutdown()
        cross_thread.join(timeout=5)
        cross_server.server_close()

    assert Handler.post_count == 0
    assert CrossOriginHandler.get_count == 0
    safety = result["interaction_safety"]
    assert safety["unsafe_methods_blocked"] >= 1
    assert safety["cross_origin_requests_blocked"] >= 1
    assert safety["blocked_request_samples"][0]["method"] == "POST"
    assert "?" not in safety["blocked_request_samples"][0]["url"]
    assert all(req["method"] in {"GET", "HEAD", "OPTIONS"} for req in result["captured_requests"])
    assert all(
        req["url"].startswith(f"http://127.0.0.1:{server.server_port}/")
        for req in result["captured_requests"]
    )
    assert "secret-value" not in json.dumps(result)
