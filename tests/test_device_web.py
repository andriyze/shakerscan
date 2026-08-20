import asyncio
import os
import sys
import time


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import device_postman, device_web  # noqa: E402


class _Reader:
    def __init__(self):
        self.remaining = b""

    async def readuntil(self, _separator):
        return b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

    async def readexactly(self, count):
        data, self.remaining = self.remaining[:count], self.remaining[count:]
        return data

    async def readline(self):
        return b"0\r\n"

    async def read(self, _limit):
        return b""


class _Writer:
    def __init__(self):
        self.data = b""

    def write(self, data):
        self.data += data

    async def drain(self):
        return None

    def close(self):
        return None

    async def wait_closed(self):
        return None


def test_device_web_connects_to_pinned_address_with_registered_host_and_sni(monkeypatch):
    calls = []
    writers = []

    async def fake_open_connection(host, port, **kwargs):
        writer = _Writer()
        calls.append((host, port, kwargs.get("server_hostname")))
        writers.append(writer)
        return _Reader(), writer

    monkeypatch.setattr(device_web.asyncio, "open_connection", fake_open_connection)
    result = asyncio.run(device_web.run_pinned_device_web_scan({
        "origin": "https://tv.example.test:8443",
        "connect_address": "192.0.2.10",
        "port": 8443,
        "host_header": "tv.example.test:8443",
    }, profile="quick"))

    assert calls == [
        ("192.0.2.10", 8443, "tv.example.test"),
        ("192.0.2.10", 8443, "tv.example.test"),
    ]
    assert b"Host: tv.example.test:8443\r\n" in writers[1].data
    assert result["http"]["remote_ip"] == "192.0.2.10"
    assert result["scan_metadata"]["pinned_destination"] is True


def test_device_web_cancellation_interrupts_an_inflight_request(monkeypatch):
    async def slow_request(**_kwargs):
        await asyncio.sleep(30)
        return {}

    checks = 0

    async def cancelled():
        nonlocal checks
        checks += 1
        return checks >= 2

    monkeypatch.setattr(device_web, "_request", slow_request)
    result = asyncio.run(device_web.run_pinned_device_web_scan({
        "origin": "http://tv.example.test:8008",
        "connect_address": "192.0.2.10",
        "port": 8008,
        "host_header": "tv.example.test:8008",
    }, profile="quick", cancel_check=cancelled))
    assert result["error"] == "Cancelled by user"


def test_device_web_finishes_content_length_response_without_waiting_for_server_close(monkeypatch):
    class KeepAliveReader:
        async def readuntil(self, _separator):
            return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\n"

        async def readexactly(self, count):
            assert count == 2
            return b"OK"

    async def fake_open_connection(*_args, **_kwargs):
        return KeepAliveReader(), _Writer()

    monkeypatch.setattr(device_web.asyncio, "open_connection", fake_open_connection)
    result = asyncio.run(device_web.run_pinned_device_web_scan({
        "origin": "https://192.0.2.10:3001",
        "connect_address": "192.0.2.10",
        "port": 3001,
    }, profile="quick"))
    assert result["http"]["status_code"] == 200
    assert result["device_web"]["observations"][0]["body_bytes"] == 2


def test_public_response_headers_redact_redirect_secrets_and_auth_challenges():
    public = device_web._public_response_headers({
        "location": "https://device.test/callback?token=secret-token",
        "www-authenticate": 'Digest realm="device", nonce="secret-nonce"',
        "set-cookie": "session=secret-cookie; Secure",
    })

    assert "secret-token" not in public["location"]
    assert "%3Credacted%3E" in public["location"]
    # auth-challenge scheme stays visible for reasoning, secrets do not
    assert public["www-authenticate"] == "<redacted>"
    assert public["set-cookie"] == "<redacted>"


def test_chunked_response_never_reads_a_device_controlled_huge_chunk():
    class HugeChunkReader:
        requested = []

        async def readuntil(self, _separator):
            return b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"

        async def readline(self):
            return b"ffffffff\r\n"

        async def readexactly(self, count):
            self.requested.append(count)
            return b"x" * count

    reader = HugeChunkReader()
    status, _headers, body, truncated = asyncio.run(device_web._read_response(reader, 1.0))
    assert status == 200
    assert reader.requested == [device_web.MAX_RESPONSE_BYTES + 1]
    assert len(body) == device_web.MAX_RESPONSE_BYTES
    assert truncated is True


def test_device_management_header_findings_are_contextual_and_deduplicable():
    findings = device_web._security_header_findings(
        origin="https://tv.example.lan:8443",
        response_url="https://tv.example.lan:8443/admin",
        status=200,
        headers={
            "content-type": "text/html; charset=utf-8",
            "set-cookie": "session=secret; Path=/",
        },
        protected_access=True,
    )
    titles = {finding["title"] for finding in findings}

    assert "Device HTTPS management interface does not declare HSTS" in titles
    assert "Device management page has no Content Security Policy" in titles
    assert "Device management page lacks framing protection" in titles
    assert "Authenticated device response lacks private cache controls" in titles
    assert "Device management cookie lacks protective attributes" in titles
    assert all("secret" not in str(finding) for finding in findings)


def test_hsts_is_not_recommended_for_literal_ip_device_origin():
    findings = device_web._security_header_findings(
        origin="https://192.0.2.10",
        response_url="https://192.0.2.10/",
        status=200,
        headers={"content-type": "application/json"},
        protected_access=False,
    )

    assert not any("HSTS" in finding["title"] for finding in findings)
    assert not any("Content Security Policy" in finding["title"] for finding in findings)


def test_invalid_credentials_on_public_root_are_attempted_not_accepted(monkeypatch):
    async def public_response(**_kwargs):
        return {
            "status": 200,
            "headers": {"content-type": "application/json"},
            "body": b"{}",
            "truncated": False,
            "elapsed_ms": 1,
        }

    monkeypatch.setattr(device_web, "_request", public_response)
    result = asyncio.run(device_web.run_pinned_device_web_scan({
        "origin": "http://tv.example.test:8008",
        "connect_address": "192.0.2.10",
        "port": 8008,
        "host_header": "tv.example.test:8008",
    }, profile="quick", credential={
        "auth_kind": "web_authorization_header",
        "secret": "Bearer invalid",
    }))

    assert result["device_web"]["credentials_attempted"] is True
    assert result["device_web"]["authentication_succeeded"] is False
    assert result["device_web"]["protected_access_evidence"]["verified"] is False
    assert not any(
        finding["title"] == "Authenticated device response lacks private cache controls"
        for finding in result["findings"]
    )


def test_anonymous_denial_then_credentialed_access_proves_authentication(monkeypatch):
    async def protected_response(**kwargs):
        authenticated = bool(kwargs.get("headers", {}).get("Authorization"))
        return {
            "status": 200 if authenticated else 401,
            "headers": {"content-type": "application/json"},
            "body": b"{}" if authenticated else b"denied",
            "truncated": False,
            "elapsed_ms": 1,
        }

    monkeypatch.setattr(device_web, "_request", protected_response)
    result = asyncio.run(device_web.run_pinned_device_web_scan({
        "origin": "http://tv.example.test:8008",
        "connect_address": "192.0.2.10",
        "port": 8008,
        "host_header": "tv.example.test:8008",
    }, profile="quick", credential={
        "auth_kind": "web_authorization_header",
        "secret": "Bearer valid",
    }))

    evidence = result["device_web"]["protected_access_evidence"]
    assert result["device_web"]["authentication_succeeded"] is True
    assert evidence == {
        "verified": True,
        "anonymous_status": 401,
        "credentialed_status": 200,
        "anonymous_denial_kind": "status",
    }
    assert any(
        finding["title"] == "Authenticated device response lacks private cache controls"
        for finding in result["findings"]
    )


def test_classify_discovered_device_path_matches_management_tokens():
    assert device_web.classify_discovered_device_path("/admin.html")
    assert device_web.classify_discovered_device_path("/api/status")
    assert device_web.classify_discovered_device_path("/setup.cgi")
    assert not device_web.classify_discovered_device_path("/favicon.ico")
    assert not device_web.classify_discovered_device_path("/assets/logo.png")
    assert not device_web.classify_discovered_device_path("")


def test_dir_discovery_findings_require_sensitive_200(monkeypatch):
    findings = device_web._dir_discovery_findings(
        origin="http://tv.example.test:8080",
        discovery={"tool": device_web.DIR_DISCOVERY_TOOL, "wordlist": "/app/wordlists/common.txt",
                   "discovered": [
                       {"path": "/admin", "status": 200, "length": 512},
                       {"path": "/admin", "status": 401, "length": 0},
                       {"path": "/images", "status": 200, "length": 90},
                   ]},
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "info"
    assert "cwe" not in finding
    assert finding["tool"] == device_web.DIR_DISCOVERY_TOOL
    assert finding["evidence"]["path"] == "/admin"
    assert finding["evidence"]["authentication_assessed"] is False
    assert finding["fingerprint"]


def test_dir_discovery_parser_accepts_normal_ffuf_input_objects_and_skips_bad_rows():
    parsed = device_web._parse_dir_discovery_results({
        "results": [
            {"input": {"FUZZ": "admin"}, "status": 200, "length": 512},
            {"input": {"FUZZ": "api/status"}, "status": "204", "length": "0"},
            {"input": {"FUZZ": "broken"}, "status": "not-a-status", "length": 1},
        ]
    })
    assert parsed == [
        {"path": "/admin", "status": 200, "length": 512},
        {"path": "/api/status", "status": 204, "length": 0},
    ]


def test_dir_discovery_reports_missing_ffuf_distinct_from_zero_results(monkeypatch):
    import asyncio as _asyncio

    async def missing_binary(*_args, **_kwargs):
        raise FileNotFoundError("ffuf")

    monkeypatch.setattr(device_web.asyncio, "create_subprocess_exec", missing_binary)
    result = _asyncio.run(device_web.run_device_dir_discovery(
        connect_address="192.0.2.10",
        hostname="tv.example.test",
        port=8080,
    ))

    assert result["status"] == "unavailable"
    assert result["error"] == "ffuf_not_installed"
    assert result["discovered"] == []


def test_dir_discovery_is_thorough_and_cleartext_only(monkeypatch):
    import asyncio as _asyncio

    calls = {}

    async def fake_dir_discovery(**kwargs):
        calls["kwargs"] = kwargs
        return {"tool": device_web.DIR_DISCOVERY_TOOL, "wordlist": "w",
                "discovered": [{"path": "/admin", "status": 200, "length": 10}]}

    async def public_response(**_kwargs):
        return {
            "status": 200,
            "headers": {"content-type": "text/html"},
            "body": b"<html></html>",
            "truncated": False,
            "elapsed_ms": 1,
        }

    monkeypatch.setattr(device_web, "run_device_dir_discovery", fake_dir_discovery)
    monkeypatch.setattr(device_web, "_request", public_response)

    async def fake_tls(*_a, **_k):
        return None

    monkeypatch.setattr(device_web, "_assess_tls_trust", fake_tls)

    async def run(profile, scheme):
        port = 8080 if scheme == "http" else 8443
        return await device_web.run_pinned_device_web_scan({
            "origin": f"{scheme}://tv.example.test:{port}",
            "connect_address": "192.0.2.10",
            "port": port,
            "host_header": f"tv.example.test:{port}",
        }, profile=profile, credential=None, cancel_check=None)

    # deep + http -> discovery runs in the production web profile.
    result = _asyncio.run(run("deep", "http"))
    assert calls["kwargs"]["hostname"] == "tv.example.test"
    assert any(f["tool"] == device_web.DIR_DISCOVERY_TOOL for f in result["findings"])
    assert result["device_web"]["dir_discovery"]["discovered"][0]["path"] == "/admin"
    assert any(o.get("source") == device_web.DIR_DISCOVERY_TOOL for o in result["device_web"]["observations"])

    # standard profile or https origin -> discovery never invoked
    calls.clear()
    _asyncio.run(run("standard", "http"))
    assert calls == {}
    _asyncio.run(run("thorough", "https"))
    assert calls == {}


def test_dir_discovery_reserves_shared_device_web_request_budget(monkeypatch):
    import asyncio as _asyncio

    calls = []

    async def fake_dir_discovery(**kwargs):
        calls.append(kwargs)
        return {"tool": device_web.DIR_DISCOVERY_TOOL, "status": "completed", "discovered": []}

    async def public_response(**_kwargs):
        return {"status": 200, "headers": {}, "body": b"ok", "truncated": False, "elapsed_ms": 1}

    monkeypatch.setattr(device_web, "run_device_dir_discovery", fake_dir_discovery)
    monkeypatch.setattr(device_web, "_request", public_response)
    result = _asyncio.run(device_web.run_pinned_device_web_scan({
        "origin": "http://tv.example.test:8080",
        "connect_address": "192.0.2.10",
        "port": 8080,
        "host_header": "tv.example.test:8080",
    }, profile="deep", request_budget=10))

    assert calls == []
    assert result["device_web"]["dir_discovery"]["status"] == "budget_limited"
    assert result["device_web"]["request_budget"]["limit"] == 10


def test_imported_request_replay_caps_and_time_budgets_per_profile():
    assert device_web.IMPORTED_REQUEST_LIMITS == {"quick": 50, "standard": 500, "deep": 2000}
    assert device_web.IMPORTED_REQUEST_TIME_BUDGETS == {"quick": 60.0, "standard": 300.0, "deep": 900.0}


def test_imported_replay_enforces_quick_profile_request_limit(monkeypatch):
    async def fake_request(**_kwargs):
        return {"status": 200, "headers": {}, "body": b"ok", "truncated": False, "elapsed_ms": 1.0}

    async def trusted_tls(**_kwargs):
        return {"trusted": True, "verification_error": None}

    monkeypatch.setattr(device_web, "_request", fake_request)
    monkeypatch.setattr(device_web, "_assess_tls_trust", trusted_tls)
    collection = {"info": {"name": "Pinned"}, "item": [
        {"name": str(index), "request": {"method": "GET", "url": f"https://192.0.2.10:3001/api/{index}"}}
        for index in range(60)
    ]}
    payload, _summary = device_postman.validate_and_summarize(collection)
    result = asyncio.run(device_web.run_pinned_device_web_scan(
        {"origin": "https://192.0.2.10:3001", "connect_address": "192.0.2.10", "port": 3001},
        profile="quick",
        request_collections=[{"collection_id": "c1", "name": "Pinned", "payload": payload}],
        default_origin=True,
    ))

    imported = result["device_web"]["imported_requests"]
    assert imported["request_limit"] == 50
    assert imported["time_budget_seconds"] == 60.0
    assert imported["executed"] == 50
    assert imported["skipped"] == 10
    assert any(item["reason"] == "profile_request_limit" for item in imported["skipped_requests"])


def test_imported_replay_reports_deep_profile_limits_without_truncation(monkeypatch):
    async def fake_request(**_kwargs):
        return {"status": 200, "headers": {}, "body": b"ok", "truncated": False, "elapsed_ms": 1.0}

    async def trusted_tls(**_kwargs):
        return {"trusted": True, "verification_error": None}

    monkeypatch.setattr(device_web, "_request", fake_request)
    monkeypatch.setattr(device_web, "_assess_tls_trust", trusted_tls)
    collection = {"info": {"name": "Deep"}, "item": [
        {"name": "Status", "request": {"method": "GET", "url": "https://192.0.2.10:8443/api/status"}},
    ]}
    payload, _summary = device_postman.validate_and_summarize(collection)
    result = asyncio.run(device_web.run_pinned_device_web_scan(
        {"origin": "https://192.0.2.10:8443", "connect_address": "192.0.2.10", "port": 8443},
        profile="deep",
        request_collections=[{"collection_id": "c1", "name": "Deep", "payload": payload}],
        default_origin=True,
    ))

    imported = result["device_web"]["imported_requests"]
    assert imported["request_limit"] == 2000
    assert imported["time_budget_seconds"] == 900.0
    assert imported["executed"] == 1


def test_imported_replay_time_budget_skips_remaining_requests():
    collection = {"info": {"name": "Budget"}, "item": [
        {"name": str(index), "request": {"method": "GET", "url": f"https://192.0.2.10:3001/api/{index}"}}
        for index in range(3)
    ]}
    payload, _summary = device_postman.validate_and_summarize(collection)
    result, findings = asyncio.run(device_web._run_imported_requests(
        origin_info={"origin": "https://192.0.2.10:3001", "connect_address": "192.0.2.10"},
        request_collections=[{"collection_id": "c1", "name": "Budget", "payload": payload}],
        profile="deep",
        allow_state_changing_requests=False,
        default_origin=True,
        base_headers=None,
        tls_assessment=None,
        allow_untrusted_tls_credentials=False,
        deadline=time.monotonic() - 1,
        cancel_check=None,
    ))

    assert result["executed"] == 0
    assert result["wire_attempts"] == 0
    assert result["skipped"] == 3
    assert [item["reason"] for item in result["skipped_requests"]] == ["profile_time_budget"] * 3
    assert findings == []
