"""
Unit tests for discovery path_exists helper.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools.discovery import (
    _BASELINE_SIGNATURE_CACHE,
    build_response_signature,
    get_baseline_signature,
    path_exists,
)


class DummyResponse:
    def __init__(self, status_code: int, headers: dict[str, str], text: str, history: list | None = None):
        self.status_code = status_code
        self.headers = headers
        self.text = text
        self.history = history or []


class DummyClient:
    def __init__(self, response: DummyResponse):
        self.response = response
        self.calls = 0

    async def get(self, _url: str, timeout: float | None = None) -> DummyResponse:
        _ = timeout
        self.calls += 1
        return self.response


class TestPathExists:
    def test_soft_404_baseline_match(self):
        baseline = build_response_signature(
            status=200,
            content_type="text/html",
            body="<html><body>Not found</body></html>",
            redirect_status=None,
            redirect_location="",
        )

        exists, reason, protected = path_exists(
            status=200,
            content_type="text/html",
            body="<html><body>Not found</body></html>",
            redirect_status=None,
            redirect_location="",
            allow="",
            www_auth="",
            target_url="https://example.com/does-not-exist",
            baseline_signature=baseline,
            require_api_style=True,
        )

        assert not exists
        assert reason == "baseline_match"
        assert not protected

    def test_login_redirect_detected(self):
        exists, reason, protected = path_exists(
            status=200,
            content_type="text/html",
            body="<html><body>Login</body></html>",
            redirect_status=302,
            redirect_location="/login?next=%2Fadmin",
            allow="",
            www_auth="",
            target_url="https://example.com/admin",
            baseline_signature=None,
            require_api_style=True,
        )

        assert exists
        assert reason == "login_redirect"
        assert protected

    def test_json_404_rejected(self):
        exists, reason, protected = path_exists(
            status=404,
            content_type="application/json",
            body='{"error":"not found"}',
            redirect_status=None,
            redirect_location="",
            allow="",
            www_auth="",
            target_url="https://example.com/api/missing",
            baseline_signature=None,
            require_api_style=True,
        )

        assert not exists
        assert reason == "status_404"
        assert not protected

    def test_json_error_accepted(self):
        exists, reason, protected = path_exists(
            status=400,
            content_type="application/json",
            body='{"error":"bad request"}',
            redirect_status=None,
            redirect_location="",
            allow="",
            www_auth="",
            target_url="https://example.com/api/search",
            baseline_signature=None,
            require_api_style=True,
        )

        assert exists
        assert reason == "api_error"
        assert not protected

    def test_www_auth_accepted(self):
        exists, reason, protected = path_exists(
            status=401,
            content_type="text/html",
            body="<html><body>Auth required</body></html>",
            redirect_status=None,
            redirect_location="",
            allow="",
            www_auth='Basic realm="private"',
            target_url="https://example.com/api/secure",
            baseline_signature=None,
            require_api_style=True,
        )

        assert exists
        assert reason == "auth_required"
        assert protected

    def test_html_success_rejected_for_api(self):
        exists, reason, protected = path_exists(
            status=200,
            content_type="text/html",
            body="<html><body>Welcome</body></html>",
            redirect_status=None,
            redirect_location="",
            allow="",
            www_auth="",
            target_url="https://example.com/api/home",
            baseline_signature=None,
            require_api_style=True,
        )

        assert not exists
        assert reason == "html_success"
        assert not protected

    @pytest.mark.asyncio
    async def test_get_baseline_signature_cached(self):
        _BASELINE_SIGNATURE_CACHE.clear()
        response = DummyResponse(
            status_code=404,
            headers={"content-type": "text/html"},
            text="<html><body>Not found</body></html>",
        )
        client = DummyClient(response)
        base_url = "https://example.invalid"

        sig_first = await get_baseline_signature(base_url, client, timeout=1.0)
        sig_second = await get_baseline_signature(base_url, client, timeout=1.0)

        assert sig_first == sig_second
        assert client.calls == 1
