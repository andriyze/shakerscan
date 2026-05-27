import asyncio

from scanner.scanner_tools import phase4_checks


async def _no_sleep(*args, **kwargs):
    return None


def _http(status: int, headers: str, body: str) -> str:
    return (
        f"HTTP/1.1 {status} Test\r\n"
        f"{headers}\r\n"
        "\r\n"
        f"{body}"
    )


def test_phase4_api_security_verifies_sensitive_json_api_response(monkeypatch):
    async def fake_run(command, *args, **kwargs):
        url = command[-1]
        if "-I" in command:
            return ("HTTP/1.1 404 Not Found\r\n\r\n", "", 0)
        if url.endswith("/rest/memories/"):
            return (
                _http(
                    200,
                    "Content-Type: application/json",
                    (
                        '{"data":[{"User":{"email":"admin@example.test",'
                        '"password":"9283f1b2e9669749081963be0462e466",'
                        '"role":"admin","deluxeToken":"abc","totpSecret":"JBSWY3DPEHPK3PXP"}}]}'
                    ),
                ),
                "",
                0,
            )
        return (_http(200, "Content-Type: text/html", "<html><body>home</body></html>"), "", 0)

    monkeypatch.setattr(phase4_checks.asyncio, "sleep", _no_sleep)
    monkeypatch.setattr(phase4_checks, "run", fake_run)

    result = asyncio.run(
        phase4_checks.test_api_security(
            "https://example.test",
            discovered_urls=["https://example.test/rest/memories/"],
        )
    )

    exposure = result["excessive_data_exposure"][0]
    assert result["vulnerable"] is True
    assert exposure["verified"] is True
    assert exposure["type"] == "api_sensitive_data"
    assert exposure["url"] == "https://example.test/rest/memories/"
    assert "password" in exposure["sensitive_markers"]
    assert "token" in exposure["sensitive_markers"]
    assert "secret" in exposure["sensitive_markers"]
    assert exposure["response_hash16"]


def test_phase4_api_security_does_not_report_html_contact_data_as_verified(monkeypatch):
    async def fake_run(command, *args, **kwargs):
        if "-I" in command:
            return ("HTTP/1.1 404 Not Found\r\n\r\n", "", 0)
        return (
            _http(
                200,
                "Content-Type: text/html",
                "<html><body>Call 555-555-1212 or email support@example.test</body></html>",
            ),
            "",
            0,
        )

    monkeypatch.setattr(phase4_checks.asyncio, "sleep", _no_sleep)
    monkeypatch.setattr(phase4_checks, "run", fake_run)

    result = asyncio.run(
        phase4_checks.test_api_security(
            "https://example.test",
            discovered_urls=["https://example.test/rest/contact"],
        )
    )

    assert result["vulnerable"] is False
    assert not any(exposure.get("verified") for exposure in result["excessive_data_exposure"])
