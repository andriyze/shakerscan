"""Target scoping of GET /findings: domain, search and source filters."""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager

import pytest

import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *a, **k: None))

if "fastapi" not in sys.modules:
    fastapi_mod = types.ModuleType("fastapi")

    class _FakeFastAPI:
        def __init__(self, *a, **k):
            pass

        def add_middleware(self, *a, **k):
            return None

        def _decorator(self, *a, **k):
            def wrapper(fn):
                return fn
            return wrapper

        get = post = patch = put = delete = on_event = _decorator

    fastapi_mod.FastAPI = _FakeFastAPI
    fastapi_mod.Header = lambda default=None, **k: default
    fastapi_mod.HTTPException = type("_HTTPExc", (Exception,), {})
    fastapi_mod.Query = lambda default=None, **k: default
    fastapi_mod.Request = type("_Req", (), {"__init__": lambda self, **k: None})
    sys.modules["fastapi"] = fastapi_mod
    cors_mod = types.ModuleType("fastapi.middleware.cors")
    cors_mod.CORSMiddleware = type("_CORS", (), {})
    sys.modules["fastapi.middleware"] = types.ModuleType("fastapi.middleware")
    sys.modules["fastapi.middleware.cors"] = cors_mod
    responses_mod = types.ModuleType("fastapi.responses")
    responses_mod.Response = type("_Resp", (), {"__init__": lambda self, **k: None})
    sys.modules["fastapi.responses"] = responses_mod

from tests.api_import_stubs import install_fastapi_exception_stubs  # noqa: E402

install_fastapi_exception_stubs()
import api as api_module  # noqa: E402

findings_router = sys.modules["finding_routes.router"]
from capabilities import exposure_probe  # noqa: E402
from finding_routes.list_filters import parse_choice_list  # noqa: E402
from finding_routes.remediation import finding_remediation  # noqa: E402



class HTTPException(Exception):
    """Stands in for fastapi's, which the import stubs replace with one that takes no arguments."""

    def __init__(self, status_code=None, detail=None, headers=None):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class _Request:
    def __init__(self, **params):
        self.query_params = params


class _Conn:
    def __init__(self, rows):
        self.rows = rows
        self.queries: list[tuple[str, tuple]] = []

    async def fetch(self, query, *args):
        self.queries.append((query, args))
        return [dict(row) for row in self.rows]

    async def fetchval(self, query, *args):
        return len(self.rows)


def _list(monkeypatch, rows, **params):
    conn = _Conn(rows)

    class _Pool:
        @asynccontextmanager
        async def acquire(self):
            yield conn

    monkeypatch.setattr(findings_router, "_pool", lambda: _Pool())
    monkeypatch.setattr(findings_router, "HTTPException", HTTPException)
    defaults = dict(severity=None, status=None, source_type=None, target_id=None, ai_target_id=None,
                    device_target_id=None, scan_id=None, hunt_id=None, root_domain=None,
                    verification_verdict=None, verification_mode=None, verified_only=False,
                    proof_state=None, driven_by=None, research_campaign_id=None, search=None,
                    seen_within_days=None, not_seen_within_days=None, first_seen_within_days=None,
                    resolved_within_days=None, sort_by=None, sort_order="desc",
                    include_candidates=False, limit=100, offset=0, include_details=False)
    defaults.update(params)
    request = _Request(**{key: value for key, value in params.items() if value not in (None, False)})
    result = asyncio.run(findings_router.list_findings(request, **defaults))
    return result, conn


from finding_routes.list_filters import host_in_domain_sql  # noqa: E402


def test_a_domain_filter_matches_ai_and_device_hosts_exactly(monkeypatch):
    _, conn = _list(monkeypatch, [], root_domain="example.com")
    query, args = conn.queries[0]
    assert "t.root_domain = $1" in query
    assert host_in_domain_sql("ait.endpoint_url", "$1") in query
    assert host_in_domain_sql("dt.primary_locator", "$1") in query
    # The substring match that let example.com select notexample.com is gone.
    assert "LIKE '%' || LOWER($1) || '%'" not in query
    assert args[0] == "example.com"


def test_host_matching_is_exact_or_subdomain_and_avoids_like_wildcards():
    sql = host_in_domain_sql("col", "$1")
    assert "LIKE" not in sql
    assert "= LOWER($1)" in sql and "right(" in sql and "'.' || LOWER($1)" in sql


def test_search_covers_target_and_device_names(monkeypatch):
    _, conn = _list(monkeypatch, [], search="lab-router")
    query, args = conn.queries[0]
    for column in ("t.name", "dt.name", "dt.primary_locator", "ait.name", "f.title"):
        assert f"{column} ILIKE $1" in query, column
    assert args[0] == "%lab-router%"


def test_hunt_findings_belong_to_the_hunt_source_and_not_to_dast(monkeypatch):
    _, conn = _list(monkeypatch, [], source_type="deep_hunt")
    assert "f.source IN ('autonomous', 'deep_hunt')" in conn.queries[0][0]
    _, conn = _list(monkeypatch, [], source_type="dast")
    assert "'deep_hunt'" in conn.queries[0][0].split("NOT IN", 1)[1]
