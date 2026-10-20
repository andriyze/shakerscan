"""A bearer token must never leave the origin the operator pointed at.

The token-carrying clients checked ``https://`` on the *initial* URL and then followed
redirects with urllib's default behaviour, so a 302 from an otherwise-trusted endpoint
forwarded the Authorization header to another origin -- including a downgrade to plain
HTTP. The MCP adapter already refused redirects; the API, V2 and scan transports did not,
and later the ``shakerscan record`` capture client did not either.

These tests pin the contract for every one of them: an authenticated request does not
follow a redirect, and the redirect is surfaced as an error rather than being reported
as a successful empty response.
"""
from __future__ import annotations

import ast
import email.message
import io
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
sys.path.insert(0, str(ROOT / "client" / "src"))
sys.path.insert(0, str(ROOT / "client"))

import api_cli  # noqa: E402
import hatch_build  # noqa: E402
import scan_cli  # noqa: E402
import v2_cli  # noqa: E402
from shakerscan import record  # noqa: E402
from shakerscan._capture import UploadError  # noqa: E402

TOKEN = "dummy-token-never-a-real-credential"
FIRST = "https://first.example"


class _Recorder(urllib.request.BaseHandler):
    """Answers the first hop with a redirect and records every hop's Authorization."""

    handler_order = 100

    def __init__(self, destination: str, status: int = 302) -> None:
        self.destination = destination
        self.status = status
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
            return urllib.error.HTTPError(req.full_url, self.status, "Redirect", headers, io.BytesIO(b""))
        headers = email.message.Message()
        headers["Content-Type"] = "application/json"
        response = urllib.request.addinfourl(io.BytesIO(b'{"ok": true}'), headers, req.full_url, 200)
        response.msg = "OK"  # urllib reads it: a followed redirect then fails on the leak, not here
        return response

    @property
    def leaked_to(self) -> list[str]:
        return [url for url, auth in self.hops if not url.startswith(FIRST) and auth]


@pytest.fixture
def recorder(monkeypatch):
    """Route every transport through the recorder, whichever opener path it takes."""
    made: list[_Recorder] = []
    real_build_opener = urllib.request.build_opener

    def install(destination: str, status: int = 302) -> _Recorder:
        rec = _Recorder(destination, status)
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


@pytest.mark.parametrize("method", ["POST", "GET"])
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("destination", DESTINATIONS)
def test_record_client_does_not_forward_the_token_through_a_redirect(recorder, destination, status, method):
    """`shakerscan record` posts every capture create, batch and close with the bearer token."""
    rec = recorder(destination, status)
    client = record.ApiClient(FIRST, TOKEN)
    with pytest.raises(UploadError) as excinfo:
        client.request(method, "/request-collections/captures", {"target_url": "https://app.example.test"})
    assert rec.leaked_to == [], f"token forwarded to {rec.leaked_to}"
    assert excinfo.value.status == status and not excinfo.value.retryable
    refused = destination.rsplit("/", 1)[0]
    assert "redirect" in str(excinfo.value) and refused in str(excinfo.value)


def _client_transport_sources() -> list[Path]:
    """The client package and the runtime scripts it vendors: every token-carrying client path."""
    package = sorted((ROOT / "client" / "src" / "shakerscan").glob("*.py"))
    return package + [ROOT / "scripts" / name for name in sorted(hatch_build.VENDORED)]


def test_every_client_opener_refuses_redirects():
    """A transport added later must not fall back to urllib's redirect-following default."""
    unguarded = []
    for path in _client_transport_sources():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), str(path))):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            if name == "urlopen":
                unguarded.append(f"{path.relative_to(ROOT)}:{node.lineno} urlopen")
            elif name == "build_opener" and not any(
                isinstance(arg, ast.Call) and getattr(arg.func, "id", None) == "_NoRedirect" for arg in node.args
            ):
                unguarded.append(f"{path.relative_to(ROOT)}:{node.lineno} build_opener without _NoRedirect()")
    assert not unguarded, unguarded


def test_a_redirect_is_never_reported_as_a_successful_response():
    """A 3xx that slipped through must not render as success with an empty body."""
    for status in (301, 302, 303, 307, 308):
        _text, code = api_cli.render(status, "")
        assert code != 0, f"HTTP {status} rendered as success"
