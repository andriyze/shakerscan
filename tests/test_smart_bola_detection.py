"""Regression tests for smart BOLA/IDOR heuristics."""

import asyncio
import json
from urllib.parse import parse_qs, urlsplit

from scanner.scanner_tools.access_control_checks import smart_bola_test


def _fake_http_response(url: str, status_code: int, body: str) -> dict:
    return {
        "status_code": status_code,
        "headers": {"content-type": "application/json"},
        "body": body,
        "final_url": url,
        "elapsed_ms": 1.0,
        "error": None,
    }


def test_smart_bola_skips_operational_rate_limit_endpoint(monkeypatch):
    async def should_not_fetch(*args, **kwargs):
        raise AssertionError("Operational endpoint should be skipped before fetch")

    monkeypatch.setattr(
        "scanner.scanner_tools.proof_of_exploit.fetch_with_capture",
        should_not_fetch,
    )

    results = asyncio.run(
        smart_bola_test(
            base_url="https://example.com",
            discovered_urls=["https://example.com/api/rate-limit/?id=2"],
            max_endpoints=10,
            timeout=1,
        )
    )

    assert not results["vulnerable"]
    assert results["findings"] == []
    assert results["endpoints_analyzed"] == 0


def test_smart_bola_flags_unauthenticated_resource_access_once(monkeypatch):
    async def fake_fetch(url, **kwargs):
        path_parts = [part for part in urlsplit(url).path.split("/") if part]
        resource_id = path_parts[-1] if path_parts else "1"
        body = json.dumps(
            {
                "user_id": int(resource_id),
                "email": f"user{resource_id}@example.com",
                "role": "user",
            }
        )
        return _fake_http_response(url, 200, body)

    monkeypatch.setattr(
        "scanner.scanner_tools.proof_of_exploit.fetch_with_capture",
        fake_fetch,
    )

    results = asyncio.run(
        smart_bola_test(
            base_url="https://example.com",
            discovered_urls=["https://example.com/api/users/2"],
            max_endpoints=10,
            timeout=1,
        )
    )

    unauth_findings = [f for f in results["findings"] if "Unauthenticated access" in f.get("title", "")]
    assert results["vulnerable"]
    assert len(unauth_findings) == 1
    assert unauth_findings[0]["evidence"]["successful_count"] >= 2


def test_smart_bola_skips_when_id_parameter_is_ignored(monkeypatch):
    async def fake_fetch(url, **kwargs):
        _ = parse_qs(urlsplit(url).query).get("id", ["1"])[0]
        # Constant payload regardless requested ID.
        body = json.dumps(
            {
                "user_id": 1,
                "email": "current-user@example.com",
            }
        )
        return _fake_http_response(url, 200, body)

    monkeypatch.setattr(
        "scanner.scanner_tools.proof_of_exploit.fetch_with_capture",
        fake_fetch,
    )

    results = asyncio.run(
        smart_bola_test(
            base_url="https://example.com",
            discovered_urls=["https://example.com/api/users?id=7"],
            max_endpoints=10,
            timeout=1,
        )
    )

    assert not results["vulnerable"]
    assert results["findings"] == []
