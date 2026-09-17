"""A bearer token must never leave the origin the operator pointed at.

The token-carrying clients checked ``https://`` on the *initial* URL and then followed
redirects with urllib's default behaviour, so a 302 from an otherwise-trusted endpoint
forwarded the Authorization header to another origin -- including a downgrade to plain
HTTP. The MCP adapter already refused redirects; the API, V2 and scan transports did not.

These tests pin the contract for every one of them: an authenticated request does not
follow a redirect, and the redirect is surfaced as an error rather than being reported
as a successful empty response.
"""
from __future__ import annotations

import email.message
import io
import os
import sys
import urllib.error
import urllib.request

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import api_cli  # noqa: E402
import scan_cli  # noqa: E402
import v2_cli  # noqa: E402

TOKEN = "dummy-token-never-a-real-credential"
FIRST = "https://first.example"


class _Recorder(urllib.request.BaseHandler):
    """Answers the first hop with a redirect and records every hop's Authorization."""

    handler_order = 100

    def __init__(self, destination: str) -> None:
        self.destination = destination
        self.hops: list[tuple[str, str | None]] = []

    def https_open(self, req):  # noqa: ANN001
        return self._open(req)

    def http_open(self, req):  # noqa: ANN001
        return self._open(req)

    def _open(self, req):  # noqa: ANN001
        self.hops.append((req.full_url, req.get_header("Authorization")))
        if req.full_url.startswith(FIRST):
            headers = email.message.Message()
            headers["Location"] = self.destination
            return urllib.error.HTTPError(req.full_url, 302, "Found", headers, io.BytesIO(b""))
        headers = email.message.Message()
        headers["Content-Type"] = "application/json"
        return urllib.request.addinfourl(io.BytesIO(b'{"ok": true}'), headers, req.full_url, 200)

    @property
    def leaked_to(self) -> list[str]:
        return [url for url, auth in self.hops if not url.startswith(FIRST) and auth]


@pytest.fixture
def recorder(monkeypatch):
    """Route every transport through the recorder, whichever opener path it takes."""
    made: list[_Recorder] = []
    real_build_opener = urllib.request.build_opener

    def install(destination: str) -> _Recorder:
        rec = _Recorder(destination)
        made.append(rec)

        def build_opener(*handlers):  # noqa: ANN001
            return real_build_opener(*handlers, rec)

        monkeypatch.setattr(urllib.request, "build_opener", build_opener)
        # A transport that still calls the bare urlopen must be observed too.
        monkeypatch.setattr(
            urllib.request, "urlopen",
            lambda req, timeout=None: real_build_opener(rec).open(req, timeout=timeout),
        )
        return rec

    yield install


DESTINATIONS = [
    pytest.param("https://second.example/x", id="cross-origin-https"),
    pytest.param("http://second.example/x", id="downgrade-to-plaintext-http"),
]


@pytest.mark.parametrize("destination", DESTINATIONS)
def test_api_cli_does_not_forward_the_token_through_a_redirect(recorder, destination):
    rec = recorder(destination)
    request = api_cli.build_request("GET", "/health", None, api_url=FIRST, token=TOKEN)
    with pytest.raises(api_cli.ApiCliError) as excinfo:
        api_cli.call(request)
    assert rec.leaked_to == [], f"token forwarded to {rec.leaked_to}"
    assert "redirect" in str(excinfo.value).lower()


@pytest.mark.parametrize("destination", DESTINATIONS)
def test_v2_cli_does_not_forward_the_token_through_a_redirect(recorder, destination):
    rec = recorder(destination)
    client = v2_cli.ApiClient(FIRST, api_token=TOKEN)
    with pytest.raises(Exception):
        client.request("GET", "/health")
    assert rec.leaked_to == [], f"token forwarded to {rec.leaked_to}"


@pytest.mark.parametrize("destination", DESTINATIONS)
def test_scan_cli_does_not_forward_the_token_through_a_redirect(recorder, destination, monkeypatch):
    rec = recorder(destination)
    monkeypatch.setenv("SHAKERSCAN_API_TOKEN", TOKEN)
    monkeypatch.delenv("SHAKERSCAN_API_TOKEN_FILE", raising=False)
    with pytest.raises(Exception):
        scan_cli._request_json(FIRST + "/health")
    assert rec.leaked_to == [], f"token forwarded to {rec.leaked_to}"


def test_a_redirect_is_never_reported_as_a_successful_response():
    """A 3xx that slipped through must not render as success with an empty body."""
    for status in (301, 302, 303, 307, 308):
        _text, code = api_cli.render(status, "")
        assert code != 0, f"HTTP {status} rendered as success"
