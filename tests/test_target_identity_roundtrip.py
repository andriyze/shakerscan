"""One identity for a target's authorization and its withdrawal, owned by the instance.

`shakerscan targets authorize <url with a path>` registered the URL's origin (the API keeps a web
target by host and non-default port), and `targets unauthorize` with the same URL compared paths
and found nothing. The client now asks the instance which target a URL names (``GET
/targets/lookup``, the identity ``POST /targets`` registers by), and against an instance without
that route compares by the same identity. The instance here is a unit fixture built on the API's
own normaliser and canonical key; the lookup route runs against a recorded connection.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
import sys
import urllib.parse

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "client" / "src"))

from api.target_dedupe import canonical_target_key  # noqa: E402
from api.targets import router as targets_router  # noqa: E402
from api.targets.router import _lookup_keys, normalize_target_url  # noqa: E402
from shakerscan import decisions  # noqa: E402

TARGET = "1a2b3c4d-1111-4222-8333-444455556666"


class _TargetsInstance:
    """A unit fixture instance with the engine's own target identity: POST /targets registers a
    URL as its origin (the API's normalize_target_url and canonical key), GET /targets/lookup
    finds it by the same identity, GET /targets lists it."""

    def __init__(self, *, lookup=True):
        self.lookup, self.rows, self.requests = lookup, {}, []

    def request(self, method, path, payload=None):
        self.requests.append((method, path))
        route, _, query = path.partition("?")
        if method == "POST" and route == "/targets":
            url, _note = normalize_target_url(payload["url"])
            key = canonical_target_key(url)
            row = self.rows.setdefault(key, {"id": TARGET, "url": url, "name": ""})
            return {**row, "status": "created"}
        if method == "GET" and route == "/targets/lookup":
            if not self.lookup:
                error = RuntimeError("Target not found")
                error.http_status = 400  # an older engine reads "lookup" as a malformed target id
                raise error
            url, _note = normalize_target_url(urllib.parse.parse_qs(query)["url"][0])
            for key in _lookup_keys(url):
                if key in self.rows:
                    return {"target": self.rows[key], "normalized_url": url}
            return {"target": None, "normalized_url": url}
        if method == "GET" and route == "/targets":
            return {"targets": list(self.rows.values()), "total": len(self.rows)}
        raise AssertionError((method, path))


@pytest.mark.parametrize("lookup", [True, False], ids=["lookup", "older-instance"])
@pytest.mark.parametrize("named,again", [
    ("https://app.example.com/admin/login?next=1", "https://app.example.com/admin/login?next=1"),
    ("app.example.com/admin", "http://APP.example.com:80/other"),
    ("https://app.example.com:8443/x", "app.example.com:8443"),
    ("https://[2606:4700:4700::1111]/dns", "https://[2606:4700:4700::1111]"),
])
def test_a_target_authorized_by_a_url_with_a_path_is_found_again_by_it(lookup, named, again):
    """`targets authorize <url with path>` registered the origin; `unauthorize` with the same
    URL compared paths and found nothing. Both now use the identity the instance registers by."""
    instance = _TargetsInstance(lookup=lookup)
    created = decisions.find_target(instance, decisions.checked_target(named), create=True)
    found = decisions.find_target(instance, decisions.checked_target(again), create=False)
    assert found["id"] == created["id"] == TARGET
    assert (("GET", "/targets/lookup?" + urllib.parse.urlencode({"url": decisions.target_url(again)}))
            in instance.requests)


def test_a_url_no_target_is_registered_for_is_said_so():
    instance = _TargetsInstance()
    decisions.find_target(instance, "https://app.example.com", create=True)
    with pytest.raises(decisions.DecisionError, match="no target is registered"):
        decisions.find_target(instance, "https://other.example.com/app", create=False)
    with pytest.raises(decisions.DecisionError, match="no target is registered"):
        decisions.find_target(instance, "https://app.example.com:8443", create=False)


class _LookupConn:
    """Recorded connection (unit fixture): the targets table as rows keyed by canonical_key."""

    def __init__(self, rows):
        self.rows, self.asked = rows, []

    async def fetchrow(self, query, keys):
        self.asked.append(list(keys))
        for key in keys:
            if key in self.rows:
                return self.rows[key]
        return None


def _lookup(monkeypatch, rows, url):
    conn = _LookupConn(rows)

    @asynccontextmanager
    async def acquire():
        yield conn

    class _Pool:
        def acquire(self):
            return acquire()

    monkeypatch.setattr(targets_router, "_pool_provider", lambda: _Pool())
    return asyncio.run(targets_router.lookup_target(url)), conn


def test_the_lookup_route_answers_by_the_registered_identity(monkeypatch):
    row = {"id": TARGET, "url": "https://app.example.com", "name": "app", "is_active": True}
    rows = {canonical_target_key("https://app.example.com"): row}
    for url in ("https://app.example.com/admin?x=1#f", "http://APP.example.com", "app.example.com/x"):
        answer, conn = _lookup(monkeypatch, rows, url)
        assert answer["target"] == {"id": TARGET, "url": "https://app.example.com", "name": "app", "is_active": True}
    # Another port is another target; the www twin is asked after the name itself.
    answer, conn = _lookup(monkeypatch, rows, "https://app.example.com:8443/")
    assert answer["target"] is None and conn.asked == [["web:app.example.com:8443", "web:www.app.example.com:8443"]]
    answer, conn = _lookup(monkeypatch, {canonical_target_key("https://www.example.com"): row}, "https://example.com")
    assert answer["target"]["id"] == TARGET and conn.asked == [["web:example.com", "web:www.example.com"]]
    # An address has no twin.
    _answer, conn = _lookup(monkeypatch, {}, "https://[2606:4700:4700::1111]/x")
    assert conn.asked == [["web:2606:4700:4700::1111"]]


def test_the_lookup_route_refuses_what_is_no_target_url(monkeypatch):
    from fastapi import HTTPException

    for url in ("ftp://app.example.com", "https://[not-an-address]"):
        with pytest.raises(HTTPException) as refused:
            _lookup(monkeypatch, {}, url)
        assert refused.value.status_code == 400
