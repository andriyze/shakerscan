import asyncio

from scanner.scanner_tools import critical_checks


async def _no_sleep(*args, **kwargs):
    return None


def _auth_http(status: int, headers: str, body: str) -> str:
    return (
        f"HTTP/1.1 {status} Test\r\n"
        f"{headers}\r\n"
        "\r\n"
        f"{body}"
        f"__SHAKERSCAN_AUTH__{status}__SHAKERSCAN_AUTH__"
    )


def test_default_credentials_skips_generic_user_endpoints(monkeypatch):
    calls = {"count": 0}

    async def fake_run(*args, **kwargs):
        calls["count"] += 1
        raise AssertionError("generic user endpoints should not receive credential probes")

    monkeypatch.setattr(critical_checks.asyncio, "sleep", _no_sleep)
    monkeypatch.setattr(critical_checks, "run", fake_run)

    result = asyncio.run(
        critical_checks.test_default_credentials(
            "https://example.test",
            login_endpoints=[
                "https://example.test/api/Users",
                "https://example.test/api/v1/users",
                "https://example.test/api/auth/register",
            ],
        )
    )

    assert result["vulnerable"] is False
    assert result["tested_endpoints"] == 0
    assert result["tested_combinations"] == 0
    assert result["skipped_non_login_endpoints"] == 3
    assert calls["count"] == 0


def test_default_credentials_tests_login_shaped_endpoints(monkeypatch):
    calls = {"count": 0}

    async def fake_run(command, *args, **kwargs):
        calls["count"] += 1
        return (
            _auth_http(
                200,
                "Content-Type: application/json",
                '{"success":true,"token":"test-token"}',
            ),
            "",
            0,
        )

    monkeypatch.setattr(critical_checks.asyncio, "sleep", _no_sleep)
    monkeypatch.setattr(critical_checks, "run", fake_run)

    result = asyncio.run(
        critical_checks.test_default_credentials(
            "https://example.test",
            login_endpoints=["https://example.test/rest/v2/auth/login"],
        )
    )

    assert result["vulnerable"] is True
    assert result["tested_endpoints"] == 1
    assert result["tested_combinations"] == 1
    assert result["vulnerable_endpoints"][0]["endpoint"] == "https://example.test/rest/v2/auth/login"
    assert result["vulnerable_endpoints"][0]["auth_method"] == "json"
    assert calls["count"] == 1
