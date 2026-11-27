"""A certificate from a private CA is a supported deployment: every client says how to trust it."""

from __future__ import annotations

import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client" / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import api_cli  # noqa: E402
import scan_cli  # noqa: E402
import v2_cli  # noqa: E402
from shakerscan import cli  # noqa: E402
from shakerscan._vendored import load  # noqa: E402

UNTRUSTED = ssl.SSLCertVerificationError(
    1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate in "
    "certificate chain (_ssl.c:1000)",
)


class _Refusing:
    def open(self, request, timeout=None):  # noqa: ANN001, ARG002
        raise urllib.error.URLError(UNTRUSTED)


def test_connect_link_names_ssl_cert_file_for_an_untrusted_certificate():
    with pytest.raises(cli.ClientError) as caught:
        cli.fetch_connect_link("https://scanner.example.com/_enterprise/connect/abc", opener=_Refusing())
    assert "SSL_CERT_FILE" in str(caught.value)
    assert "certificate verify failed" in str(caught.value)


def test_connect_link_gives_no_certificate_hint_for_other_failures():
    class Refused:
        def open(self, request, timeout=None):  # noqa: ANN001, ARG002
            raise urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))

    with pytest.raises(cli.ClientError) as caught:
        cli.fetch_connect_link("https://scanner.example.com/_enterprise/connect/abc", opener=Refused())
    assert "SSL_CERT_FILE" not in str(caught.value)


def test_doctor_names_ssl_cert_file_for_an_untrusted_certificate(monkeypatch, capsys):
    for name in (cli.ENV_URL, cli.ENV_TOKEN, cli.ENV_TOKEN_FILE):
        monkeypatch.delenv(name, raising=False)
    mcp = load("_mcp")

    class Untrusted:
        def __init__(self, base_url, *, timeout_seconds, api_token):
            pass

        def request_json(self, method, path, payload=None):
            raise mcp.MCPError(-32001, "ShakerScan API is unavailable", f"<urlopen error {UNTRUSTED}>")

        def list_tools(self):
            raise mcp.MCPError(-32001, "ShakerScan API is unavailable", f"<urlopen error {UNTRUSTED}>")

    monkeypatch.setattr(mcp, "ArsenalClient", Untrusted)
    assert cli.main(["doctor", "--url", "https://scanner.example.com"]) == 1
    assert "SSL_CERT_FILE" in capsys.readouterr().out


def test_scan_cli_names_ssl_cert_file_for_an_untrusted_certificate(monkeypatch):
    monkeypatch.setattr(scan_cli, "_opener", lambda: _Refusing())
    with pytest.raises(scan_cli.ScanCliError) as caught:
        scan_cli._request_json("https://scanner.example.com/scan/contracts")
    assert "SSL_CERT_FILE" in str(caught.value)


def test_api_cli_names_ssl_cert_file_for_an_untrusted_certificate():
    request = urllib.request.Request("https://scanner.example.com/health")
    with pytest.raises(api_cli.ApiCliError) as caught:
        api_cli.call(request, opener=_Refusing())
    assert "SSL_CERT_FILE" in str(caught.value)


def test_hunt_cli_names_ssl_cert_file_for_an_untrusted_certificate(monkeypatch):
    monkeypatch.setattr(v2_cli, "_opener", lambda: _Refusing())
    client = v2_cli.ApiClient("https://scanner.example.com")
    with pytest.raises(v2_cli.CliError) as caught:
        client.request("GET", "/hunts/contract")
    assert "SSL_CERT_FILE" in str(caught.value)


def test_mcp_adapter_error_names_ssl_cert_file_for_an_untrusted_certificate(monkeypatch):
    mcp = load("_mcp")
    monkeypatch.setattr(mcp.urllib.request, "urlopen", lambda *a, **k: _Refusing().open(None))
    monkeypatch.setattr(mcp.urllib.request, "build_opener", lambda *a, **k: _Refusing())
    client = mcp.ArsenalClient("https://scanner.example.com", timeout_seconds=1, api_token=None)
    with pytest.raises(mcp.MCPError) as caught:
        client.request_json("GET", "/health")
    assert "SSL_CERT_FILE" in str(caught.value.data)


def test_doctor_prints_the_certificate_hint_once_per_line(monkeypatch, capsys):
    """E1-N1: the MCP adapter already appends the hint to its reason; doctor must not add it again."""
    for name in (cli.ENV_URL, cli.ENV_TOKEN, cli.ENV_TOKEN_FILE):
        monkeypatch.delenv(name, raising=False)
    mcp = load("_mcp")
    monkeypatch.setattr(mcp.urllib.request, "urlopen", lambda *a, **k: _Refusing().open(None))
    monkeypatch.setattr(mcp.urllib.request, "build_opener", lambda *a, **k: _Refusing())
    assert cli.main(["doctor", "--url", "https://scanner.example.com"]) == 1
    lines = [line for line in capsys.readouterr().out.splitlines() if "SSL_CERT_FILE" in line]
    assert lines, "doctor names SSL_CERT_FILE"
    for line in lines:
        assert line.count("SSL_CERT_FILE") == 1, line
        assert line.count("Hint:") == 1, line


def test_certificate_hint_is_not_appended_twice():
    import redirect_hint

    once = redirect_hint.with_certificate_hint(f"unavailable: {UNTRUSTED}", UNTRUSTED)
    assert redirect_hint.with_certificate_hint(f"api: {once}", once).count("Hint:") == 1
