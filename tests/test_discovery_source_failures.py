"""A discovery source that fails is never read as "no subdomains exist".

crt.sh often answers 502/503/429, times out, or returns its HTML error page with status 200. The
client used to turn every one of those into an empty list, so a failed query showed as "No
certificates found in CT logs" and a discovery run reported zero subdomains. Now the client retries
and then raises, the CT check reports a failed source, discovery lists it in ``source_errors``, and
a run where no source answered fails with the reasons. All fixtures; no network.
"""

from __future__ import annotations

import asyncio

import pytest

from api import discovery_outcome, target_resolution
from scanner.scanner_tools import ct_monitor, subdomain_discovery


@pytest.fixture(autouse=True)
def _no_waits(monkeypatch):
    async def instant(_seconds):
        return None
    monkeypatch.setattr(ct_monitor.asyncio, "sleep", instant)


def _fetch_raising(errors, calls):
    def fetch(url, timeout):
        calls.append(url)
        error = errors[min(len(calls) - 1, len(errors) - 1)]
        if isinstance(error, Exception):
            raise error
        return error
    return fetch


@pytest.mark.parametrize("reason", ["HTTP 503", "HTTP 502", "HTTP 429", "unreachable (timeout)",
                                    "unexpected non-JSON answer"])
def test_a_failing_crtsh_raises_after_retries_instead_of_returning_nothing(monkeypatch, reason):
    calls: list[str] = []
    monkeypatch.setattr(ct_monitor, "_crtsh_fetch", _fetch_raising([ct_monitor.CTQueryError(reason)], calls))
    with pytest.raises(ct_monitor.CTQueryError, match=reason.split()[0]):
        asyncio.run(ct_monitor._query_crtsh("%.example.com"))
    assert len(calls) == ct_monitor.CRTSH_ATTEMPTS


def test_a_client_error_is_not_retried(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(ct_monitor, "_crtsh_fetch", _fetch_raising([ct_monitor.CTQueryError("HTTP 404")], calls))
    with pytest.raises(ct_monitor.CTQueryError):
        asyncio.run(ct_monitor._query_crtsh("example.com"))
    assert len(calls) == 1


def test_a_transient_failure_then_an_answer_succeeds(monkeypatch):
    calls: list[str] = []
    answer = [{"id": 1, "name_value": "a.example.com", "common_name": "a.example.com"}]
    monkeypatch.setattr(ct_monitor, "_crtsh_fetch",
                        _fetch_raising([ct_monitor.CTQueryError("HTTP 503"), answer], calls))
    assert asyncio.run(ct_monitor._query_crtsh("%.example.com")) == answer
    assert len(calls) == 2


def test_the_html_error_page_with_status_200_is_a_failure(monkeypatch):
    class Response:
        def __init__(self, body):
            self.body = body.encode()
        def read(self):
            return self.body
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False
    monkeypatch.setattr(ct_monitor, "urlopen", lambda req, timeout: Response("<html>Bad Gateway</html>"))
    with pytest.raises(ct_monitor.CTQueryError, match="non-JSON"):
        ct_monitor._crtsh_fetch("https://crt.sh/?q=x&output=json", 5)
    monkeypatch.setattr(ct_monitor, "urlopen", lambda req, timeout: Response("[]"))
    assert ct_monitor._crtsh_fetch("https://crt.sh/?q=x&output=json", 5) == []


def test_the_ct_check_reports_a_failed_source_not_no_certificates(monkeypatch):
    async def failing(*_args, **_kwargs):
        raise ct_monitor.CTQueryError("crt.sh HTTP 503")
    monkeypatch.setattr(ct_monitor, "_query_crtsh", failing)
    result = asyncio.run(ct_monitor.check_certificate_transparency("example.com", safe_mode=False))
    assert result["source_status"] == "error"
    assert "HTTP 503" in result["error"] and "incomplete" in result["error"]
    assert "No certificates found" not in str(result)


def test_an_empty_answer_is_a_real_empty_answer_not_an_error(monkeypatch):
    async def empty(*_args, **_kwargs):
        return []
    monkeypatch.setattr(ct_monitor, "_query_crtsh", empty)
    result = asyncio.run(ct_monitor.check_certificate_transparency("example.com", safe_mode=False))
    assert result["source_status"] == "ok"
    assert "error" not in result
    assert result["note"] == "No certificates found in CT logs"


def test_the_ct_monitor_does_not_report_no_new_certificates_on_failure(monkeypatch):
    async def failing(*_args, **_kwargs):
        raise ct_monitor.CTQueryError("crt.sh HTTP 502")
    monkeypatch.setattr(ct_monitor, "_query_crtsh", failing)
    result = asyncio.run(ct_monitor.monitor_ct_for_domain("example.com"))
    assert result["alert_level"] == "unknown"
    assert "HTTP 502" in result["error"]


def _discover(monkeypatch, *, crtsh, subfinder, gungnir_available=False):
    async def ct(domain, **_kwargs):
        return crtsh
    async def sub(domain):
        return subfinder
    async def available():
        return gungnir_available
    monkeypatch.setattr(subdomain_discovery, "check_certificate_transparency", ct)
    monkeypatch.setattr(subdomain_discovery, "subfinder_scan", sub)
    monkeypatch.setattr(subdomain_discovery, "check_gungnir_available", available)
    return asyncio.run(subdomain_discovery.discover_subdomains("example.com"))


def test_discovery_lists_the_failed_source_and_keeps_what_others_found(monkeypatch):
    result = _discover(monkeypatch,
                       crtsh={"source_status": "error", "error": "crt.sh HTTP 503; results are incomplete"},
                       subfinder={"subdomains": ["a.example.com"]})
    assert result["source_errors"] == {"crtsh": "crt.sh HTTP 503; results are incomplete"}
    assert "subfinder" in result["sources_answered"]
    assert "gungnir" not in result["source_errors"]  # not installed is not a failure
    assert discovery_outcome.failed_run_message(result) is None


def test_a_run_where_no_source_answered_fails_with_the_reasons(monkeypatch):
    result = _discover(monkeypatch,
                       crtsh={"source_status": "error", "error": "crt.sh HTTP 503"},
                       subfinder={"subdomains": [], "error": "subfinder: all providers failed"})
    message = discovery_outcome.failed_run_message(result)
    assert message and "crt.sh: crt.sh HTTP 503" in message and "subfinder" in message
    assert "try again later" in message


def test_a_run_where_every_source_answered_none_is_a_real_zero(monkeypatch):
    result = _discover(monkeypatch,
                       crtsh={"source_status": "ok", "note": "No certificates found in CT logs",
                              "subdomain_discovery": {"subdomains": []}},
                       subfinder={"subdomains": []})
    assert result["source_errors"] == {}
    assert discovery_outcome.failed_run_message(result) is None


def test_the_public_run_carries_source_errors_and_hides_none_for_old_ct_rows():
    row = {"id": "r", "status": "completed",
           "sources_used": {"crtsh": {"error": "crt.sh HTTP 503"}, "dns_resolution": {"added": 0},
                            "source_errors": {"crtsh": "crt.sh HTTP 503"}}}
    public = target_resolution.public_discovery_run(row)
    assert public["source_errors"] == {"crtsh": "crt.sh HTTP 503"}
    assert public["resolution"] == {"added": 0}
    old = target_resolution.public_discovery_run(
        {"id": "o", "sources_used": {"crtsh": {"error": "No certificates found in CT logs"},
                                     "subfinder": {"error": "subfinder timed out"}}})
    assert old["source_errors"] == {"subfinder": "subfinder timed out"}


@pytest.mark.parametrize("crtsh", ["fails", "has_no_certificates"])
def test_discovery_with_the_real_ct_check_never_crashes(monkeypatch, crtsh):
    # The real CT check (not a stand-in): it returns before analysing certificates, with no
    # subdomain_discovery, when crt.sh fails and when it has nothing for the domain.
    async def query(*_args, **_kwargs):
        if crtsh == "fails":
            raise ct_monitor.CTQueryError("crt.sh unreachable (connection refused)")
        return []
    async def sub(domain):
        return {"subdomains": ["a.example.com"]}
    async def available():
        return False
    monkeypatch.setattr(ct_monitor, "_query_crtsh", query)
    monkeypatch.setattr(subdomain_discovery, "subfinder_scan", sub)
    monkeypatch.setattr(subdomain_discovery, "check_gungnir_available", available)
    result = asyncio.run(subdomain_discovery.discover_subdomains("example.com"))
    assert result["subdomains"] == ["a.example.com"]
    if crtsh == "fails":
        assert "connection refused" in result["source_errors"]["crtsh"]
        assert "crtsh" not in result["sources_answered"]
    else:
        assert result["source_errors"] == {} and "crtsh" in result["sources_answered"]
