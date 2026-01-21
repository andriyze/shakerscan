"""
Unit tests for default credential detection helpers.

Tests the AuthResponse parser and validators to ensure they correctly
identify successful authentication vs. false positives (like 404 pages
with "token" in routing state).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools.critical_checks import (
    AuthResponse,
    _is_valid_form_auth_success,
    _is_valid_json_auth_success,
    _parse_auth_response,
)


class TestParseAuthResponse:
    """Tests for _parse_auth_response."""

    def test_parse_json_success(self):
        """Parse a valid JSON auth response with 200 status."""
        raw = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"access_token": "abc123"}'
            "__SHAKERSCAN_AUTH__200__SHAKERSCAN_AUTH__"
        )
        resp = _parse_auth_response(raw)
        assert resp.status_code == 200
        assert resp.is_json
        assert "access_token" in resp.body

    def test_parse_404_html(self):
        """Parse a 404 HTML error page."""
        raw = (
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<html><body>Not found</body></html>"
            "__SHAKERSCAN_AUTH__404__SHAKERSCAN_AUTH__"
        )
        resp = _parse_auth_response(raw)
        assert resp.status_code == 404
        assert not resp.is_json
        assert "Not found" in resp.body

    def test_parse_redirect_with_cookie(self):
        """Parse a redirect response with session cookie."""
        raw = (
            "HTTP/1.1 302 Found\r\n"
            "Location: /dashboard\r\n"
            "Set-Cookie: session_id=abc123; Path=/; HttpOnly\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            ""
            "__SHAKERSCAN_AUTH__302__SHAKERSCAN_AUTH__"
        )
        resp = _parse_auth_response(raw)
        assert resp.status_code == 302
        assert resp.location == "/dashboard"
        assert len(resp.set_cookies) == 1
        assert resp.has_session_cookie

    def test_parse_empty_response(self):
        """Parse empty input gracefully."""
        resp = _parse_auth_response("")
        assert resp.status_code is None
        assert resp.body == ""
        assert not resp.is_json

    def test_parse_response_with_lf_separator(self):
        """Parse response using LF-only line endings."""
        raw = (
            "HTTP/1.1 200 OK\n"
            "Content-Type: application/json\n"
            "\n"
            '{"token": "xyz"}'
            "__SHAKERSCAN_AUTH__200__SHAKERSCAN_AUTH__"
        )
        resp = _parse_auth_response(raw)
        assert resp.status_code == 200
        assert resp.is_json


class TestJsonAuthValidation:
    """Tests for _is_valid_json_auth_success."""

    def test_rejects_404_with_token_in_html(self):
        """
        The original false positive case - Next.js 404 with 'token' in routing state.

        This is the exact bug we're fixing: a 404 page that happens to contain
        the string "token" in its Next.js routing state JSON.
        """
        resp = AuthResponse(
            status_code=404,
            content_type="text/html",
            location=None,
            set_cookies=[],
            body='<html>"c":["","token"]</html>',
            is_json=False,
        )
        is_success, reason = _is_valid_json_auth_success(resp)
        assert not is_success
        assert reason == "status_404"

    def test_rejects_html_for_json_auth(self):
        """HTML response should be rejected even with 200 status."""
        resp = AuthResponse(
            status_code=200,
            content_type="text/html",
            location=None,
            set_cookies=[],
            body="<html>token</html>",
            is_json=False,
        )
        is_success, reason = _is_valid_json_auth_success(resp)
        assert not is_success
        assert reason == "not_json_content_type"

    def test_rejects_json_without_token_field(self):
        """Valid JSON but no token field."""
        resp = AuthResponse(
            status_code=200,
            content_type="application/json",
            location=None,
            set_cookies=[],
            body='{"message": "hello"}',
            is_json=True,
        )
        is_success, reason = _is_valid_json_auth_success(resp)
        assert not is_success
        assert reason == "no_token_or_success_field"

    def test_rejects_json_with_empty_token(self):
        """JSON with token field that is empty/null."""
        resp = AuthResponse(
            status_code=200,
            content_type="application/json",
            location=None,
            set_cookies=[],
            body='{"token": ""}',
            is_json=True,
        )
        is_success, reason = _is_valid_json_auth_success(resp)
        assert not is_success
        assert reason == "no_token_or_success_field"

    def test_rejects_invalid_json(self):
        """Invalid JSON should be rejected."""
        resp = AuthResponse(
            status_code=200,
            content_type="application/json",
            location=None,
            set_cookies=[],
            body="not valid json",
            is_json=True,
        )
        is_success, reason = _is_valid_json_auth_success(resp)
        assert not is_success
        assert reason == "invalid_json"

    def test_rejects_json_array(self):
        """JSON array (not object) should be rejected."""
        resp = AuthResponse(
            status_code=200,
            content_type="application/json",
            location=None,
            set_cookies=[],
            body='["token", "value"]',
            is_json=True,
        )
        is_success, reason = _is_valid_json_auth_success(resp)
        assert not is_success
        assert reason == "json_not_object"

    def test_accepts_valid_token_response(self):
        """Valid JSON with access_token field."""
        resp = AuthResponse(
            status_code=200,
            content_type="application/json",
            location=None,
            set_cookies=[],
            body='{"access_token": "eyJhbGciOiJIUzI1NiIs..."}',
            is_json=True,
        )
        is_success, reason = _is_valid_json_auth_success(resp)
        assert is_success
        assert reason == "json_auth_success"

    def test_accepts_success_true_response(self):
        """Valid JSON with success: true."""
        resp = AuthResponse(
            status_code=200,
            content_type="application/json",
            location=None,
            set_cookies=[],
            body='{"success": true, "user": "admin"}',
            is_json=True,
        )
        is_success, reason = _is_valid_json_auth_success(resp)
        assert is_success
        assert reason == "json_auth_success"

    def test_accepts_jwt_field(self):
        """Valid JSON with jwt field."""
        resp = AuthResponse(
            status_code=200,
            content_type="application/json",
            location=None,
            set_cookies=[],
            body='{"jwt": "eyJhbGciOiJIUzI1NiIs...", "user_id": 1}',
            is_json=True,
        )
        is_success, reason = _is_valid_json_auth_success(resp)
        assert is_success

    def test_accepts_authenticated_true(self):
        """Valid JSON with authenticated: true."""
        resp = AuthResponse(
            status_code=200,
            content_type="application/json",
            location=None,
            set_cookies=[],
            body='{"authenticated": true}',
            is_json=True,
        )
        is_success, reason = _is_valid_json_auth_success(resp)
        assert is_success

    def test_rejects_500_error(self):
        """Server error should be rejected."""
        resp = AuthResponse(
            status_code=500,
            content_type="application/json",
            location=None,
            set_cookies=[],
            body='{"error": "Internal server error"}',
            is_json=True,
        )
        is_success, reason = _is_valid_json_auth_success(resp)
        assert not is_success
        assert reason == "status_500"


class TestFormAuthValidation:
    """Tests for _is_valid_form_auth_success."""

    def test_accepts_redirect_to_dashboard(self):
        """Redirect to dashboard indicates successful login."""
        resp = AuthResponse(
            status_code=302,
            content_type="text/html",
            location="/dashboard",
            set_cookies=[],
            body="",
            is_json=False,
        )
        is_success, reason = _is_valid_form_auth_success(resp, "/login")
        assert is_success
        assert reason == "form_auth_success"

    def test_rejects_redirect_back_to_login(self):
        """Redirect back to login indicates failed login."""
        resp = AuthResponse(
            status_code=302,
            content_type="text/html",
            location="/login?error=1",
            set_cookies=[],
            body="",
            is_json=False,
        )
        is_success, reason = _is_valid_form_auth_success(resp, "/login")
        assert not is_success
        assert reason == "no_redirect_or_session"

    def test_rejects_redirect_to_signin(self):
        """Redirect to signin page indicates failed login."""
        resp = AuthResponse(
            status_code=302,
            content_type="text/html",
            location="/signin?retry=true",
            set_cookies=[],
            body="",
            is_json=False,
        )
        is_success, reason = _is_valid_form_auth_success(resp, "/login")
        assert not is_success

    def test_accepts_session_cookie(self):
        """Session cookie indicates successful login."""
        resp = AuthResponse(
            status_code=200,
            content_type="text/html",
            location=None,
            set_cookies=["session_id=abc123; Path=/; HttpOnly"],
            body="Welcome!",
            is_json=False,
        )
        is_success, reason = _is_valid_form_auth_success(resp, "/login")
        assert is_success
        assert reason == "form_auth_success"

    def test_accepts_jwt_cookie(self):
        """JWT cookie indicates successful login."""
        resp = AuthResponse(
            status_code=200,
            content_type="text/html",
            location=None,
            set_cookies=["jwt=eyJhbGciOi...; Path=/; HttpOnly; Secure"],
            body="Dashboard",
            is_json=False,
        )
        is_success, reason = _is_valid_form_auth_success(resp, "/login")
        assert is_success

    def test_rejects_error_in_body(self):
        """Error message in body indicates failed login."""
        resp = AuthResponse(
            status_code=200,
            content_type="text/html",
            location=None,
            set_cookies=["session_id=abc123"],
            body="Invalid username or password",
            is_json=False,
        )
        is_success, reason = _is_valid_form_auth_success(resp, "/login")
        assert not is_success
        assert reason == "error_signal_found"

    def test_rejects_404_error(self):
        """404 status code should be rejected."""
        resp = AuthResponse(
            status_code=404,
            content_type="text/html",
            location=None,
            set_cookies=[],
            body="Page not found",
            is_json=False,
        )
        is_success, reason = _is_valid_form_auth_success(resp, "/login")
        assert not is_success
        assert reason == "status_404"

    def test_rejects_forbidden(self):
        """403 status code should be rejected."""
        resp = AuthResponse(
            status_code=403,
            content_type="text/html",
            location=None,
            set_cookies=[],
            body="Access denied",
            is_json=False,
        )
        is_success, reason = _is_valid_form_auth_success(resp, "/login")
        assert not is_success
        assert reason == "status_403"

    def test_rejects_login_failed_message(self):
        """Login failed message should be rejected."""
        resp = AuthResponse(
            status_code=200,
            content_type="text/html",
            location=None,
            set_cookies=["session=xyz"],
            body="<html><body>Authentication failed. Please try again.</body></html>",
            is_json=False,
        )
        is_success, reason = _is_valid_form_auth_success(resp, "/login")
        assert not is_success
        assert reason == "error_signal_found"

    def test_rejects_no_indicators(self):
        """No redirect and no session cookie should be rejected."""
        resp = AuthResponse(
            status_code=200,
            content_type="text/html",
            location=None,
            set_cookies=[],
            body="<html>Some generic page</html>",
            is_json=False,
        )
        is_success, reason = _is_valid_form_auth_success(resp, "/login")
        assert not is_success
        assert reason == "no_redirect_or_session"


class TestHasSessionCookie:
    """Tests for AuthResponse.has_session_cookie property."""

    def test_detects_session_cookie(self):
        resp = AuthResponse(
            status_code=200,
            content_type="",
            location=None,
            set_cookies=["PHPSESSID=abc123; path=/"],
            body="",
            is_json=False,
        )
        assert resp.has_session_cookie

    def test_detects_auth_cookie(self):
        resp = AuthResponse(
            status_code=200,
            content_type="",
            location=None,
            set_cookies=["auth_token=xyz; HttpOnly"],
            body="",
            is_json=False,
        )
        assert resp.has_session_cookie

    def test_ignores_tracking_cookie(self):
        """Tracking cookies should not count as session cookies."""
        resp = AuthResponse(
            status_code=200,
            content_type="",
            location=None,
            set_cookies=["_ga=GA1.2.123456789; path=/"],
            body="",
            is_json=False,
        )
        assert not resp.has_session_cookie

    def test_detects_jwt_cookie(self):
        resp = AuthResponse(
            status_code=200,
            content_type="",
            location=None,
            set_cookies=["jwt=eyJ...; Secure"],
            body="",
            is_json=False,
        )
        assert resp.has_session_cookie

    def test_ignores_csrf_token(self):
        """CSRF/XSRF tokens should NOT count as session cookies (false positive fix)."""
        resp = AuthResponse(
            status_code=200,
            content_type="",
            location=None,
            set_cookies=["XSRF-TOKEN=abc123; Path=/"],
            body="",
            is_json=False,
        )
        assert not resp.has_session_cookie

    def test_ignores_csrf_cookie(self):
        """_csrf cookie should NOT count as session cookie."""
        resp = AuthResponse(
            status_code=200,
            content_type="",
            location=None,
            set_cookies=["_csrf=xyz789; HttpOnly"],
            body="",
            is_json=False,
        )
        assert not resp.has_session_cookie

    def test_ignores_cookie_without_equals(self):
        """Malformed cookie without = should be ignored."""
        resp = AuthResponse(
            status_code=200,
            content_type="",
            location=None,
            set_cookies=["malformed_cookie"],
            body="",
            is_json=False,
        )
        assert not resp.has_session_cookie

    def test_parses_cookie_name_only(self):
        """Should only check cookie NAME, not value or attributes like Path=/auth."""
        resp = AuthResponse(
            status_code=200,
            content_type="",
            location=None,
            set_cookies=["tracking=123; Path=/auth; HttpOnly"],
            body="",
            is_json=False,
        )
        # "auth" appears in Path attribute, not cookie name
        assert not resp.has_session_cookie


class TestJsonFallback:
    """Tests for JSON body fallback when content-type is missing/wrong."""

    def test_accepts_json_with_text_plain_content_type(self):
        """JSON body with text/plain content-type should be accepted."""
        resp = AuthResponse(
            status_code=200,
            content_type="text/plain",
            location=None,
            set_cookies=[],
            body='{"access_token": "abc123"}',
            is_json=False,  # Not JSON content-type
        )
        is_success, reason = _is_valid_json_auth_success(resp)
        assert is_success
        assert reason == "json_auth_success"

    def test_accepts_json_with_no_content_type(self):
        """JSON body with no content-type should be accepted."""
        resp = AuthResponse(
            status_code=200,
            content_type="",
            location=None,
            set_cookies=[],
            body='{"token": "xyz789"}',
            is_json=False,
        )
        is_success, reason = _is_valid_json_auth_success(resp)
        assert is_success

    def test_rejects_html_that_starts_with_bracket(self):
        """HTML that happens to start with < should not be treated as JSON."""
        resp = AuthResponse(
            status_code=200,
            content_type="text/html",
            location=None,
            set_cookies=[],
            body="<html>token</html>",
            is_json=False,
        )
        is_success, reason = _is_valid_json_auth_success(resp)
        assert not is_success
        assert reason == "not_json_content_type"


class TestParse100Continue:
    """Tests for HTTP 100 Continue handling in response parsing."""

    def test_parses_100_continue_response(self):
        """Should skip 100 Continue and parse final headers."""
        raw = (
            "HTTP/1.1 100 Continue\r\n"
            "\r\n"
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Set-Cookie: session=abc; HttpOnly\r\n"
            "\r\n"
            '{"token": "xyz"}'
            "__SHAKERSCAN_AUTH__200__SHAKERSCAN_AUTH__"
        )
        resp = _parse_auth_response(raw)
        assert resp.status_code == 200
        assert resp.is_json
        assert resp.has_session_cookie
        assert '{"token": "xyz"}' in resp.body

    def test_parses_multiple_100_continue(self):
        """Should handle multiple 100 Continue responses."""
        raw = (
            "HTTP/1.1 100 Continue\r\n"
            "\r\n"
            "HTTP/1.1 100 Continue\r\n"
            "\r\n"
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"success": true}'
            "__SHAKERSCAN_AUTH__200__SHAKERSCAN_AUTH__"
        )
        resp = _parse_auth_response(raw)
        assert resp.status_code == 200
        assert resp.is_json


class TestLoginPathUsage:
    """Tests for login_path parameter usage in form auth validation."""

    def test_accepts_redirect_to_login_success(self):
        """Redirect to /login-success should be accepted (different from /login)."""
        resp = AuthResponse(
            status_code=302,
            content_type="text/html",
            location="/login-success",
            set_cookies=[],
            body="",
            is_json=False,
        )
        is_success, reason = _is_valid_form_auth_success(resp, "/login")
        assert is_success

    def test_rejects_redirect_to_same_login_path(self):
        """Redirect back to exact same login path should be rejected."""
        resp = AuthResponse(
            status_code=302,
            content_type="text/html",
            location="/login",
            set_cookies=[],
            body="",
            is_json=False,
        )
        is_success, reason = _is_valid_form_auth_success(resp, "/login")
        assert not is_success

    def test_accepts_redirect_to_different_path(self):
        """Redirect to any different path should be accepted."""
        resp = AuthResponse(
            status_code=302,
            content_type="text/html",
            location="/user/profile",
            set_cookies=[],
            body="",
            is_json=False,
        )
        is_success, reason = _is_valid_form_auth_success(resp, "/auth/login")
        assert is_success

    def test_handles_full_url_login_path(self):
        """Should handle full URL as login_path."""
        resp = AuthResponse(
            status_code=302,
            content_type="text/html",
            location="/dashboard",
            set_cookies=[],
            body="",
            is_json=False,
        )
        is_success, reason = _is_valid_form_auth_success(resp, "https://example.com/login")
        assert is_success


class TestIntegration:
    """Integration tests combining parsing and validation."""

    def test_full_flow_json_success(self):
        """Test full flow: parse raw response and validate JSON auth."""
        raw = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Cache-Control: no-cache\r\n"
            "\r\n"
            '{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "expires_in": 3600}'
            "__SHAKERSCAN_AUTH__200__SHAKERSCAN_AUTH__"
        )
        resp = _parse_auth_response(raw)
        is_success, reason = _is_valid_json_auth_success(resp)
        assert is_success
        assert reason == "json_auth_success"

    def test_full_flow_nextjs_404_false_positive(self):
        """Test the original false positive case end-to-end."""
        # Simulating a Next.js 404 page with routing state containing "token"
        raw = (
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "X-Powered-By: Next.js\r\n"
            "\r\n"
            '<!DOCTYPE html><html><head></head><body>'
            '<script id="__NEXT_DATA__" type="application/json">'
            '{"page":"/_error","query":{},"buildId":"abc123",'
            '"runtimeConfig":{},"nextExport":false,'
            '"autoExport":false,"isFallback":false,'
            '"dynamicIds":[],"err":{"name":"Error","message":"Not found"}'
            ',"gsp":false,"gip":false,"appGip":false,'
            '"locale":"en","locales":[],"defaultLocale":"en",'
            '"scriptLoader":[],"isPreview":false,"rsc":"c":["","token"]}'
            '</script></body></html>'
            "__SHAKERSCAN_AUTH__404__SHAKERSCAN_AUTH__"
        )
        resp = _parse_auth_response(raw)

        # Verify parsing
        assert resp.status_code == 404
        assert not resp.is_json
        assert "token" in resp.body  # The string "token" IS present

        # But validation correctly rejects it
        is_success, reason = _is_valid_json_auth_success(resp)
        assert not is_success
        assert reason == "status_404"

    def test_full_flow_form_redirect_success(self):
        """Test full flow: parse raw response and validate form auth with redirect."""
        raw = (
            "HTTP/1.1 302 Found\r\n"
            "Location: /admin/dashboard\r\n"
            "Set-Cookie: session=abc123; Path=/; HttpOnly; Secure\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<html><head><meta http-equiv='refresh' content='0;url=/admin/dashboard'></head></html>"
            "__SHAKERSCAN_AUTH__302__SHAKERSCAN_AUTH__"
        )
        resp = _parse_auth_response(raw)
        is_success, reason = _is_valid_form_auth_success(resp, "/admin/login")
        assert is_success
        assert reason == "form_auth_success"

    def test_csrf_cookie_does_not_cause_false_positive(self):
        """CSRF cookie alone should not indicate successful auth."""
        raw = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Set-Cookie: XSRF-TOKEN=abc123; Path=/\r\n"
            "\r\n"
            "<html>Login page</html>"
            "__SHAKERSCAN_AUTH__200__SHAKERSCAN_AUTH__"
        )
        resp = _parse_auth_response(raw)
        is_success, reason = _is_valid_form_auth_success(resp, "/login")
        assert not is_success
        assert reason == "no_redirect_or_session"

    def test_100_continue_with_json_auth(self):
        """Full flow with 100 Continue followed by JSON auth success."""
        raw = (
            "HTTP/1.1 100 Continue\r\n"
            "\r\n"
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"access_token": "eyJhbG..."}'
            "__SHAKERSCAN_AUTH__200__SHAKERSCAN_AUTH__"
        )
        resp = _parse_auth_response(raw)
        is_success, reason = _is_valid_json_auth_success(resp)
        assert is_success
