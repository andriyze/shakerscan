"""Session-cookie posture survives the receipt masking path (names and flags, never values)."""

from __future__ import annotations

import httpx

from api.capabilities.http import cookie_metadata
from api.runtime.receipts import key_is_sensitive, redact_receipt_value
from tests.test_scan_finalizer import _baseline_cookie_report


def _stored(cookies):
    """What a stored baseline observation holds after the receipt redaction."""
    observation = {
        "kind": "http_observation",
        "request": {"method": "GET", "origin": "https://app.example.test", "path": "/"},
        "response": {"status": 200, "security_headers": {}, "set_cookie_metadata": cookies},
    }
    return redact_receipt_value(observation)["response"]["set_cookie_metadata"]


def test_cookie_names_and_flags_survive_the_receipt_redaction_and_still_produce_findings():
    response = httpx.Response(200, headers=[
        ("set-cookie", "sessionid=7c1e0f9a2b3d4c5e6f708192a3b4c5d6; Path=/"),
        ("set-cookie", "theme=dark; Path=/"),
    ])
    recorded = [cookie_metadata(value) for value in response.headers.get_list("set-cookie")]
    stored = _stored(recorded)
    assert stored == [
        {"name": "sessionid", "secure": False, "httponly": False, "samesite": None},
        {"name": "theme", "secure": False, "httponly": False, "samesite": None},
    ]
    assert "7c1e0f9a" not in repr(stored)
    findings = _baseline_cookie_report("https://app.example.test", stored)
    assert sorted(f["title"] for f in findings) == [
        "Session cookie without HttpOnly flag", "Session cookie without Secure flag",
    ]
    assert all(f["evidence"]["cookie_name"] == "sessionid" for f in findings)


def test_anything_but_value_free_cookie_posture_is_still_masked():
    assert _stored([{"name": "sid", "value": "abc", "secure": True}]) == "***"
    assert _stored("sid=abc") == "***"
    assert _stored([{"name": "sid=abc; x", "secure": True}]) == "***"
    assert _stored([{"name": "sid", "secure": "yes"}]) == "***"
    assert key_is_sensitive("set_cookie_metadata") is True
    assert key_is_sensitive("cookie") is True
    assert redact_receipt_value({"cookie_flags": {"secure": True, "httponly": False, "samesite": "lax"}}) == {
        "cookie_flags": {"secure": True, "httponly": False, "samesite": "lax"},
    }
    assert redact_receipt_value({"cookie_flags": {"value": "x"}}) == {"cookie_flags": "***"}


def test_cookie_attributes_are_read_from_the_attribute_list_not_the_value():
    assert cookie_metadata("sid=secure-httponly-samesite=strict; Path=/") == {
        "name": "sid", "secure": False, "httponly": False, "samesite": None,
    }
    assert cookie_metadata("sid=1; Secure; HttpOnly; SameSite=Strict") == {
        "name": "sid", "secure": True, "httponly": True, "samesite": "strict",
    }
    assert cookie_metadata("=nameless; Secure") is None
