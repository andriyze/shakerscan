"""Broken function-level authorization (BFLA) on sensitive collection endpoints.

A collection like /api/Users that denies anonymous callers but returns bulk
cross-principal records to any authenticated user is broken function-level
authorization. These pin the anon-vs-authed differential detector and its
precision guards (own-record-only and HTML-shell responses must NOT fire).
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import access_control_checks as acc  # noqa: E402
from scanner_tools import proof_of_exploit as poe  # noqa: E402


class _Cfg:
    def __init__(self, headers):
        self.headers = headers
        self.cookies = {}


class _Session:
    def __init__(self, headers):
        self.config = _Cfg(headers)


BULK_USERS = (
    '{"status":"success","data":['
    '{"id":1,"email":"admin@juice-sh.op","role":"admin"},'
    '{"id":2,"email":"jim@juice-sh.op","role":"customer"},'
    '{"id":3,"email":"bob@juice-sh.op","role":"customer"}]}'
)


def _router(auth_body, auth_status=200, anon_status=401, anon_body="Unauthorized",
            auth_ct="application/json", anon_ct="text/html", match_path="/api/Users"):
    """Fake fetch_with_capture: auth requests carry an Authorization header. Only
    the ``match_path`` collection returns the (vulnerable) bulk body; every other
    probed path returns 401 for both principals (realistic — not every model
    collection leaks)."""
    async def fake_fetch(url, method="GET", data=None, headers=None, timeout=15, **kwargs):
        is_auth = bool(headers and any(k.lower() == "authorization" for k in headers))
        if match_path not in url:
            return {"status_code": 401, "headers": {"content-type": "text/html"},
                    "body": "Unauthorized", "final_url": url, "elapsed_ms": 1.0, "error": None}
        if is_auth:
            return {"status_code": auth_status, "headers": {"content-type": auth_ct},
                    "body": auth_body, "final_url": url, "elapsed_ms": 1.0, "error": None}
        return {"status_code": anon_status, "headers": {"content-type": anon_ct},
                "body": anon_body, "final_url": url, "elapsed_ms": 1.0, "error": None}
    return fake_fetch


def _run(monkeypatch, fake_fetch, urls=("/api/Users",)):
    monkeypatch.setattr(poe, "fetch_with_capture", fake_fetch)
    return asyncio.run(acc.check_collection_authz(
        "http://t", discovered_urls=list(urls),
        auth_session=_Session({"Authorization": "Bearer x"}),
        timeout=5, max_endpoints=10))


def test_bfla_detected_anon_denied_authed_bulk(monkeypatch):
    res = _run(monkeypatch, _router(BULK_USERS))
    assert res["vulnerable"] is True
    assert len(res["findings"]) == 1
    f = res["findings"][0]
    assert f["verified"] is True
    assert f["severity"] == "high"
    assert f["tool"] == "bfla"
    assert f["type"] == "bfla"
    assert "/api/Users" in f["title"]
    assert f["evidence"]["privileged_record_present"] is True
    assert f["evidence"]["distinct_identities"] >= 2
    assert f["evidence"]["anonymous_status"] == 401


def test_no_finding_when_only_own_record(monkeypatch):
    # Authenticated response is a single record for the caller (1 email, no admin)
    # -> "my own data", not BFLA. Must NOT fire.
    own = '{"data":{"id":9,"email":"me@t.io","role":"customer"}}'
    res = _run(monkeypatch, _router(own))
    assert res["vulnerable"] is False
    assert res["findings"] == []


def test_no_finding_when_authed_is_html_shell(monkeypatch):
    # Authed 200 but the body is the SPA shell (not JSON PII) -> content
    # validation rejects it, no finding.
    res = _run(monkeypatch, _router("<!doctype html><html><body>app</body></html>",
                                    auth_ct="text/html"))
    assert res["vulnerable"] is False
    assert res["findings"] == []


def test_no_finding_when_anon_also_gets_data_but_is_public_catalog(monkeypatch):
    # If anonymous ALSO returns the same bulk JSON, and it validates as sensitive,
    # this detector defers (anon exposure is forced-browsing's job); it only fires
    # on the authz DIFFERENTIAL. Here anon returns the bulk data too -> no BFLA.
    res = _run(monkeypatch, _router(BULK_USERS, anon_status=200,
                                    anon_body=BULK_USERS, anon_ct="application/json"))
    assert res["vulnerable"] is False


def test_skipped_without_auth_session():
    res = asyncio.run(acc.check_collection_authz(
        "http://t", discovered_urls=["/api/Users"], auth_session=None))
    assert res["vulnerable"] is False
    assert res["skipped_reason"] == "no_auth_session"


def test_non_collection_urls_are_ignored(monkeypatch):
    # /metrics is excluded; /assets/app.js isn't a collection -> nothing tested
    # from discovered_urls (rest_api_models wordlist still probed, but the fake
    # returns 401 for those too since no auth-bulk match beyond /api/Users here).
    res = _run(monkeypatch, _router("Unauthorized", auth_status=401),
               urls=("/metrics", "/assets/app.js", "/main.css"))
    assert res["vulnerable"] is False
