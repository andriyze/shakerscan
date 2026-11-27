"""Regression tests for focused auth/access-control endpoint telemetry."""

import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace

_SCANNER_DIR = Path(__file__).resolve().parents[1] / "scanner"
if str(_SCANNER_DIR) not in sys.path:
    sys.path.insert(0, str(_SCANNER_DIR))

from scanner_tools.access_control_checks import smart_auth_access_test  # noqa: E402


def _session(token: str = "u1") -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(headers={"Authorization": f"Bearer {token}"}, cookies={}),
        state=SimpleNamespace(cookies_received={}),
    )


def _response(status_code: int, body: str) -> dict:
    return {"status_code": status_code, "body": body, "headers": {}, "error": None}


def test_smart_auth_flags_equivalent_anonymous_user_specific_response(monkeypatch):
    user_body = json.dumps({
        "user_id": "u1",
        "email": "alice@shakerscan.dev",
        "role": "customer",
    })

    async def fake_fetch(url, *, method="GET", headers=None, timeout=10):
        return _response(200, user_body)

    monkeypatch.setattr("scanner_tools.access_control_checks._fetch_auth_access_probe", fake_fetch)

    result = asyncio.run(
        smart_auth_access_test(
            "https://app.test",
            [{"url": "/api/me", "method": "GET"}],
            auth_session=_session(),
            max_endpoints=5,
        )
    )

    assert result["vulnerable"] is True
    assert len(result["findings"]) == 1
    assert result["findings"][0]["tool"] == "smart_auth"
    assert result["anonymous_accessible"] == 1
    assert result["endpoint_attempts"] == [
        {
            "custom_endpoint": "GET /api/me",
            "family": "auth",
            "method": "GET",
            "url": "https://app.test/api/me",
            "param_count": 1,
            "attempted_params_count": 1,
            "completed_params_count": 1,
            "status": "completed",
        }
    ]


def test_smart_auth_records_protected_endpoint_without_finding(monkeypatch):
    async def fake_fetch(url, *, method="GET", headers=None, timeout=10):
        if headers and headers.get("Authorization"):
            return _response(200, json.dumps({"email": "alice@shakerscan.dev"}))
        return _response(401, json.dumps({"error": "unauthorized"}))

    monkeypatch.setattr("scanner_tools.access_control_checks._fetch_auth_access_probe", fake_fetch)

    result = asyncio.run(
        smart_auth_access_test(
            "https://app.test",
            [{"url": "/api/me", "method": "GET"}],
            auth_session=_session(),
        )
    )

    assert result["vulnerable"] is False
    assert result["findings"] == []
    assert result["auth_required"] == 1
    assert result["endpoint_attempts"][0]["status"] == "completed"


def test_smart_auth_skips_mutating_methods_as_partial_telemetry(monkeypatch):
    async def should_not_fetch(*args, **kwargs):
        raise AssertionError("mutating auth probe should not issue requests")

    monkeypatch.setattr("scanner_tools.access_control_checks._fetch_auth_access_probe", should_not_fetch)

    result = asyncio.run(
        smart_auth_access_test(
            "https://app.test",
            [{"url": "/api/me", "method": "POST", "body_params": ["name"]}],
            auth_session=_session(),
        )
    )

    assert result["findings"] == []
    assert result["skipped"] == 1
    assert result["endpoint_attempts"][0]["family"] == "auth"
    assert result["endpoint_attempts"][0]["status"] == "skipped"
    assert result["endpoint_attempts"][0]["skip_reason"] == "unsafe_method_not_tested"


def test_smart_auth_preserves_custom_endpoint_string_identity(monkeypatch):
    async def fake_fetch(url, *, method="GET", headers=None, timeout=10):
        return _response(401 if not headers else 200, "{}")

    monkeypatch.setattr("scanner_tools.access_control_checks._fetch_auth_access_probe", fake_fetch)

    result = asyncio.run(
        smart_auth_access_test(
            "https://app.test",
            ["GET /api/orders?orderId=1"],
            auth_session=_session(),
        )
    )

    assert result["endpoint_attempts"][0]["custom_endpoint"] == "GET /api/orders?orderId=1"
    assert result["endpoint_attempts"][0]["url"] == "https://app.test/api/orders?orderId=1"
