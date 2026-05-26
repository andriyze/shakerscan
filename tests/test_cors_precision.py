import asyncio

from scanner.scanner_tools import discovery, proof_of_exploit
from scanner.scanner_tools.finding_validator import validate_cors


def test_cors_wildcard_without_credentials_is_not_reported_as_vulnerable(monkeypatch):
    async def fake_run(cmd, timeout=30):
        return "HTTP/1.1 200 OK\nAccess-Control-Allow-Origin: *\n\n", "", 0

    monkeypatch.setattr(discovery, "run", fake_run)

    result = asyncio.run(discovery.check_cors("https://example.test"))

    assert result["vulnerable"] is False
    assert result["issues"] == []
    assert "Wildcard CORS without credentials" in result["weak_issues"]


def test_cors_reflection_with_credentials_is_reported(monkeypatch):
    async def fake_run(cmd, timeout=30):
        origin = next(value.split(":", 1)[1].strip() for value in cmd if value.startswith("Origin:"))
        return (
            "HTTP/1.1 200 OK\n"
            f"Access-Control-Allow-Origin: {origin}\n"
            "Access-Control-Allow-Credentials: true\n\n",
            "",
            0,
        )

    monkeypatch.setattr(discovery, "run", fake_run)

    result = asyncio.run(discovery.check_cors("https://example.test"))

    assert result["vulnerable"] is True
    assert "Reflects arbitrary Origin with credentials: https://evil.com" in result["issues"]
    assert "Allows null Origin with credentials" in result["issues"]


def test_cors_validator_does_not_verify_browser_blocked_wildcard_credentials():
    result = validate_cors({
        "evidence": {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        }
    })

    assert result.verified is False
    assert result.downgrade_to == "info"
    assert result.confidence < 0.5


def test_cors_poe_requires_credentials_with_reflected_origin(monkeypatch):
    async def fake_fetch(url, headers=None, timeout=10, follow_redirects=False):
        return {
            "status_code": 200,
            "headers": {
                "access-control-allow-origin": headers["Origin"],
            },
        }

    monkeypatch.setattr(proof_of_exploit, "fetch_with_capture", fake_fetch)

    proof = asyncio.run(proof_of_exploit.prove_cors("https://example.test/api/data"))

    assert proof.proven is False
    assert proof.evidence_type == "origin_reflection_without_credentials"


def test_cors_poe_confirms_reflected_origin_with_credentials(monkeypatch):
    async def fake_fetch(url, headers=None, timeout=10, follow_redirects=False):
        return {
            "status_code": 200,
            "headers": {
                "access-control-allow-origin": headers["Origin"],
                "access-control-allow-credentials": "true",
            },
        }

    monkeypatch.setattr(proof_of_exploit, "fetch_with_capture", fake_fetch)

    proof = asyncio.run(proof_of_exploit.prove_cors("https://example.test/api/data"))

    assert proof.proven is True
    assert proof.evidence_type == "origin_reflection_with_credentials"
