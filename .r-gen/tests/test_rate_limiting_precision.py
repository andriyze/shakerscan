import asyncio

from scanner.scanner_tools import critical_checks


async def _no_spa(*args, **kwargs):
    return {"is_spa_catch_all": False}


def _http(status: int, headers: str, body: str) -> str:
    return (
        f"HTTP/1.1 {status} Test\r\n"
        f"{headers}\r\n"
        "\r\n"
        f"{body}"
        f"__SHAKERSCAN_META__{status}__SHAKERSCAN_META__"
    )


def _payload(command: list[str]) -> str:
    return command[command.index("-d") + 1] if "-d" in command else ""


def test_rate_limiting_skips_method_not_allowed_auth_guess(monkeypatch):
    calls = {"count": 0}

    async def fake_run(*args, **kwargs):
        calls["count"] += 1
        return (
            _http(
                405,
                "Content-Type: application/json\r\nX-RateLimit-Limit: 100",
                '{"detail":"Method Not Allowed"}',
            ),
            "",
            0,
        )

    monkeypatch.setattr(critical_checks, "detect_spa_catch_all", _no_spa)
    monkeypatch.setattr(critical_checks, "run", fake_run)

    result = asyncio.run(
        critical_checks.test_rate_limiting(
            "https://example.test",
            sensitive_endpoints=["https://example.test/api/login"],
            requests_per_second=3,
        )
    )

    assert result["vulnerable"] is False
    assert result["vulnerable_endpoints"] == []
    assert calls["count"] == 1
    assert result["evidence"][0]["message"] == "Auth endpoint not confirmed (status_405)"


def test_rate_limiting_flags_confirmed_json_login_without_throttle(monkeypatch):
    async def fake_run(*args, **kwargs):
        return (
            _http(200, "Content-Type: application/json", '{"success":false}'),
            "",
            0,
        )

    monkeypatch.setattr(critical_checks, "detect_spa_catch_all", _no_spa)
    monkeypatch.setattr(critical_checks, "run", fake_run)

    result = asyncio.run(
        critical_checks.test_rate_limiting(
            "https://example.test",
            sensitive_endpoints=["https://example.test/login"],
            requests_per_second=3,
        )
    )

    assert result["vulnerable"] is True
    assert result["vulnerable_endpoints"][0]["requests_processed"] == 3
    assert result["vulnerable_endpoints"][0]["rate_limit_detected"] is False


def test_rate_limiting_confirms_custom_auth_endpoint_by_response_shape(monkeypatch):
    calls = {"shape": 0, "burst": 0}

    async def fake_run(command, *args, **kwargs):
        payload = _payload(command)
        if "shakerscan-shape-probe" in payload:
            calls["shape"] += 1
            return (
                _http(400, "Content-Type: application/json", '{"code":"E2","faults":["A"]}'),
                "",
                0,
            )
        calls["burst"] += 1
        return (_http(401, "Content-Type: application/json", '{"code":"E1"}'), "", 0)

    monkeypatch.setattr(critical_checks, "detect_spa_catch_all", _no_spa)
    monkeypatch.setattr(critical_checks, "run", fake_run)

    result = asyncio.run(
        critical_checks.test_rate_limiting(
            "https://example.test",
            sensitive_endpoints=["https://example.test/sign-on"],
            requests_per_second=3,
        )
    )

    assert result["vulnerable"] is True
    assert result["vulnerable_endpoints"][0]["endpoint"] == "https://example.test/sign-on"
    assert result["vulnerable_endpoints"][0]["requests_processed"] == 3
    assert calls == {"shape": 1, "burst": 3}


def test_rate_limiting_skips_custom_auth_endpoint_without_response_shape_diff(monkeypatch):
    calls = {"count": 0}

    async def fake_run(command, *args, **kwargs):
        calls["count"] += 1
        return (_http(401, "Content-Type: application/json", '{"code":"E1"}'), "", 0)

    monkeypatch.setattr(critical_checks, "detect_spa_catch_all", _no_spa)
    monkeypatch.setattr(critical_checks, "run", fake_run)

    result = asyncio.run(
        critical_checks.test_rate_limiting(
            "https://example.test",
            sensitive_endpoints=["https://example.test/sign-on"],
            requests_per_second=3,
        )
    )

    assert result["vulnerable"] is False
    assert result["vulnerable_endpoints"] == []
    assert calls["count"] == 2
    assert result["evidence"][0]["message"] == "Auth endpoint not confirmed (json_not_auth_like)"


def test_rate_limiting_skips_spa_shell_login_guess(monkeypatch):
    async def fake_run(*args, **kwargs):
        body = '<html><div id="root"></div><script src="/_next/static/app.js"></script></html>'
        return (_http(200, "Content-Type: text/html", body), "", 0)

    monkeypatch.setattr(critical_checks, "detect_spa_catch_all", _no_spa)
    monkeypatch.setattr(critical_checks, "run", fake_run)

    result = asyncio.run(
        critical_checks.test_rate_limiting(
            "https://example.test",
            sensitive_endpoints=["https://example.test/login"],
            requests_per_second=3,
        )
    )

    assert result["vulnerable"] is False
    assert result["vulnerable_endpoints"] == []
    assert result["evidence"][0]["message"] == "Auth endpoint not confirmed (spa_shell)"


def test_2fa_rate_limit_skips_method_not_allowed_verify_guess(monkeypatch):
    calls_by_endpoint = {}

    async def fake_run(command, *args, **kwargs):
        endpoint = command[-1]
        calls_by_endpoint[endpoint] = calls_by_endpoint.get(endpoint, 0) + 1
        if endpoint.endswith("/login"):
            return ("<html>login</html>", "", 0)
        if endpoint.endswith(("/dashboard", "/account", "/profile")):
            return ("not found\n---HTTP_CODE---404", "", 0)
        if endpoint.endswith("/api/2fa/verify"):
            return (_http(404, "Content-Type: application/json", '{"detail":"Not Found"}'), "", 0)
        if endpoint.endswith("/api/auth/2fa"):
            return (
                _http(
                    405,
                    "Content-Type: application/json\r\nX-RateLimit-Limit: 100",
                    '{"detail":"Method Not Allowed"}',
                ),
                "",
                0,
            )
        return ("", "", 1)

    monkeypatch.setattr(critical_checks, "detect_spa_catch_all", _no_spa)
    monkeypatch.setattr(critical_checks, "run", fake_run)

    result = asyncio.run(critical_checks.test_2fa_bypass("https://example.test"))

    assert result["vulnerable"] is False
    assert result["bypass_methods_detected"] == []
    assert calls_by_endpoint["https://example.test/api/auth/2fa"] == 1
    assert any(
        e.get("message") == "2FA verification endpoint not confirmed (status_405)"
        for e in result["evidence"]
    )


def test_2fa_rate_limit_flags_confirmed_verify_endpoint(monkeypatch):
    async def fake_run(command, *args, **kwargs):
        endpoint = command[-1]
        if endpoint.endswith("/login"):
            return ("<html>login</html>", "", 0)
        if endpoint.endswith(("/dashboard", "/account", "/profile")):
            return ("not found\n---HTTP_CODE---404", "", 0)
        if endpoint.endswith("/api/2fa/verify"):
            return (
                _http(
                    200,
                    "Content-Type: application/json",
                    '{"verified":false,"predictable_bypass":true}',
                ),
                "",
                0,
            )
        if endpoint.endswith("/api/auth/2fa"):
            return (_http(404, "Content-Type: application/json", '{"detail":"Not Found"}'), "", 0)
        return ("", "", 1)

    monkeypatch.setattr(critical_checks, "detect_spa_catch_all", _no_spa)
    monkeypatch.setattr(critical_checks, "run", fake_run)

    result = asyncio.run(critical_checks.test_2fa_bypass("https://example.test"))

    assert result["vulnerable"] is True
    no_limit = [
        item
        for item in result["bypass_methods_detected"]
        if item.get("method") == "no_rate_limiting"
    ]
    assert len(no_limit) == 1
    assert no_limit[0]["endpoint"] == "https://example.test/api/2fa/verify"
    assert no_limit[0]["requests_processed"] == 10


def test_2fa_rate_limit_confirms_custom_json_shape(monkeypatch):
    calls_by_endpoint = {}

    async def fake_run(command, *args, **kwargs):
        endpoint = command[-1]
        calls_by_endpoint[endpoint] = calls_by_endpoint.get(endpoint, 0) + 1
        if endpoint.endswith("/login"):
            return ("<html>login</html>", "", 0)
        if endpoint.endswith(("/dashboard", "/account", "/profile")):
            return ("not found\n---HTTP_CODE---404", "", 0)
        if endpoint.endswith("/api/2fa/verify"):
            if "shakerscan-shape-probe" in _payload(command):
                return (
                    _http(400, "Content-Type: application/json", '{"code":"E2","faults":["A"]}'),
                    "",
                    0,
                )
            return (_http(401, "Content-Type: application/json", '{"code":"E1"}'), "", 0)
        if endpoint.endswith("/api/auth/2fa"):
            return (_http(404, "Content-Type: application/json", '{"detail":"Not Found"}'), "", 0)
        return ("", "", 1)

    monkeypatch.setattr(critical_checks, "detect_spa_catch_all", _no_spa)
    monkeypatch.setattr(critical_checks, "run", fake_run)

    result = asyncio.run(critical_checks.test_2fa_bypass("https://example.test"))

    assert result["vulnerable"] is True
    no_limit = [
        item
        for item in result["bypass_methods_detected"]
        if item.get("method") == "no_rate_limiting"
    ]
    assert len(no_limit) == 1
    assert no_limit[0]["endpoint"] == "https://example.test/api/2fa/verify"
    assert no_limit[0]["requests_processed"] == 10
    assert calls_by_endpoint["https://example.test/api/2fa/verify"] == 11


def test_2fa_rate_limit_skips_custom_json_without_shape_diff(monkeypatch):
    async def fake_run(command, *args, **kwargs):
        endpoint = command[-1]
        if endpoint.endswith("/login"):
            return ("<html>login</html>", "", 0)
        if endpoint.endswith(("/dashboard", "/account", "/profile")):
            return ("not found\n---HTTP_CODE---404", "", 0)
        if endpoint.endswith(("/api/2fa/verify", "/api/auth/2fa")):
            return (_http(401, "Content-Type: application/json", '{"code":"E1"}'), "", 0)
        return ("", "", 1)

    monkeypatch.setattr(critical_checks, "detect_spa_catch_all", _no_spa)
    monkeypatch.setattr(critical_checks, "run", fake_run)

    result = asyncio.run(critical_checks.test_2fa_bypass("https://example.test"))

    assert result["vulnerable"] is False
    assert result["bypass_methods_detected"] == []
    assert any(
        e.get("message") == "2FA verification endpoint not confirmed (json_not_2fa_like)"
        for e in result["evidence"]
    )
