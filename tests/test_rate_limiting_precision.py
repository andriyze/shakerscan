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
