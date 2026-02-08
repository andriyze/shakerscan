"""
Unit tests for AI verifier safety and redaction helpers.
"""

import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from ai_verifier import (  # noqa: E402
    _redact_object_for_ai,
    _redact_text_for_ai,
    _redact_url_for_ai,
    _resolve_and_validate_step_url,
)


class TestAiVerifierUrlSafety:
    def test_allows_same_origin_relative_step(self):
        resolved, error = _resolve_and_validate_step_url("/search?q=test", "https://app.example.com")
        assert error is None
        assert resolved == "https://app.example.com/search?q=test"

    def test_allows_same_origin_absolute_step(self):
        resolved, error = _resolve_and_validate_step_url(
            "https://app.example.com/api/v1/users?id=1",
            "https://app.example.com",
        )
        assert error is None
        assert resolved == "https://app.example.com/api/v1/users?id=1"

    def test_blocks_cross_origin_host(self):
        resolved, error = _resolve_and_validate_step_url(
            "https://evil.example.net/collect",
            "https://app.example.com",
        )
        assert resolved is None
        assert error is not None
        assert "cross-origin" in error.lower()

    def test_blocks_cross_origin_scheme(self):
        resolved, error = _resolve_and_validate_step_url(
            "http://app.example.com/login",
            "https://app.example.com",
        )
        assert resolved is None
        assert error is not None
        assert "cross-origin" in error.lower()

    def test_blocks_cross_origin_port(self):
        resolved, error = _resolve_and_validate_step_url(
            "https://app.example.com:8443/admin",
            "https://app.example.com",
        )
        assert resolved is None
        assert error is not None
        assert "cross-origin" in error.lower()


class TestAiVerifierRedaction:
    def test_redacts_sensitive_query_values(self):
        url = "https://app.example.com/callback?token=abc123456789&next=/home"
        redacted = _redact_url_for_ai(url)
        assert "token=%5BREDACTED%5D" in redacted
        assert "next=%2Fhome" in redacted

    def test_redacts_text_with_secret_patterns(self):
        text = 'api_key=sk_test_1234567890abcdef user_email=alice@example.com'
        redacted = _redact_text_for_ai(text)
        assert redacted != text
        assert "REDACTED" in redacted

    def test_redacts_nested_sensitive_keys(self):
        obj = {
            "request": {
                "headers": {"Authorization": "Bearer secret-token", "X-Test": "ok"},
                "password": "supersecret",
            },
            "note": "contact alice@example.com",
        }
        redacted = _redact_object_for_ai(obj)
        assert redacted["request"]["headers"]["Authorization"] == "[REDACTED]"
        assert redacted["request"]["password"] == "[REDACTED]"
        assert "REDACTED" in redacted["note"]
