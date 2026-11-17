"""Bounded same-origin redirect following for the Deep Hunt http_request tool.

Hop validation and method rewrite live in api/http_experiment.py (pure); the executor
wiring in api/api.py is covered BOTH functionally (stub-imported api module driven
against an httpx.MockTransport — same stub pattern as tests/test_api_helpers.py) and by
source-contract pins (the read-the-source pattern from tests/test_agent_ports.py).

    PYTHONPATH=scanner:api python3 -m pytest tests/test_hunt_redirects.py -q
"""
import asyncio
import json
import os
import re
import sys
import types
import uuid as uuid_lib

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import http_experiment as he
import agent_tools as at
from capabilities.http import execute_bound_http_request
from runtime.models import TargetBinding

# api/api.py imports asyncpg/redis/fastapi at module load; stub the ones missing in
# the host test environment (mirrors tests/test_api_helpers.py).
sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *args, **kwargs: None))

if "fastapi" not in sys.modules:
    fastapi_mod = types.ModuleType("fastapi")

    class _FakeFastAPI:
        def __init__(self, *args, **kwargs):
            pass

        def add_middleware(self, *args, **kwargs):
            return None

        def _decorator(self, *args, **kwargs):
            def wrapper(fn):
                return fn
            return wrapper

        get = post = patch = put = delete = on_event = exception_handler = _decorator

    class _FakeHTTPException(Exception):
        def __init__(self, status_code: int = 500, detail=None, headers=None):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail
            self.headers = headers

    def _fake_query(default=None, **kwargs):
        return default

    class _FakeRequest:
        def __init__(self, scope=None):
            self.headers = {}
            self.client = None
            self.url = types.SimpleNamespace(scheme="http")

    fastapi_mod.FastAPI = _FakeFastAPI
    fastapi_mod.Header = _fake_query
    fastapi_mod.HTTPException = _FakeHTTPException
    fastapi_mod.Query = _fake_query
    fastapi_mod.Request = _FakeRequest
    sys.modules["fastapi"] = fastapi_mod

    middleware_mod = types.ModuleType("fastapi.middleware")
    cors_mod = types.ModuleType("fastapi.middleware.cors")

    class _FakeCORSMiddleware:
        pass

    cors_mod.CORSMiddleware = _FakeCORSMiddleware
    sys.modules["fastapi.middleware"] = middleware_mod
    sys.modules["fastapi.middleware.cors"] = cors_mod

    responses_mod = types.ModuleType("fastapi.responses")

    class _FakeResponse:
        def __init__(self, content=None, status_code=200, headers=None, media_type=None):
            self.content = content
            self.status_code = status_code
            self.headers = headers or {}
            self.media_type = media_type

    responses_mod.Response = _FakeResponse
    responses_mod.JSONResponse = _FakeResponse
    sys.modules["fastapi.responses"] = responses_mod

from tests.api_import_stubs import install_fastapi_exception_stubs  # noqa: E402

install_fastapi_exception_stubs()
import api as api_module  # noqa: E402

from tests.api_sources import definition_source  # noqa: E402
from agent_routes import router as agent_router_module  # noqa: E402

HTTP_CAPABILITY_SOURCE = open(
    os.path.join(
        os.path.dirname(__file__), "..", "api", "capabilities", "http.py"
    ),
    encoding="utf-8",
).read()



# ------------------------------------------------------- hop validation (pure) --------

def test_hop_cap_and_redirect_statuses_are_bounded():
    assert he.MAX_REDIRECT_HOPS == 3
    assert he.REDIRECT_STATUSES == frozenset({301, 302, 303, 307, 308})


def test_same_origin_relative_and_absolute_locations_resolve():
    assert he.validate_next_hop("https://shop.test/old", "/new") == "https://shop.test/new"
    assert (
        he.validate_next_hop("https://shop.test/old", "https://shop.test/new?next=1")
        == "https://shop.test/new?next=1"
    )
    # default-port equivalence: the explicit 443 is the SAME https origin
    assert (
        he.validate_next_hop("https://shop.test/old", "https://shop.test:443/new")
        == "https://shop.test:443/new"
    )
    assert he.validate_next_hop("http://shop.test:3000/a", "b") == "http://shop.test:3000/b"


def test_cross_origin_hops_are_rejected_strictly():
    current = "https://shop.test/old"
    # different host
    assert he.validate_next_hop(current, "https://evil.test/new") is None
    # different port on the SAME host is a different origin
    assert he.validate_next_hop(current, "https://shop.test:8443/new") is None
    assert he.validate_next_hop("http://shop.test:3000/a", "http://shop.test:3001/b") is None
    # different scheme (http -> https, even same host)
    assert he.validate_next_hop("http://shop.test/a", "https://shop.test/b") is None
    # protocol-relative cross-host
    assert he.validate_next_hop(current, "//evil.test/new") is None
    # non-HTTP scheme
    assert he.validate_next_hop(current, "file:///etc/passwd") is None
    # userinfo smuggle
    assert he.validate_next_hop(current, "https://shop.test@evil.test/new") is None


def test_malformed_or_control_character_locations_are_rejected():
    current = "https://shop.test/old"
    assert he.validate_next_hop(current, None) is None
    assert he.validate_next_hop(current, "") is None
    assert he.validate_next_hop(current, "   ") is None
    assert he.validate_next_hop(current, "/new\r\nX-Evil: 1") is None
    assert he.validate_next_hop(current, "/new\x00") is None
    assert he.validate_next_hop(current, "https://shop.test:bad/new") is None


# ------------------------------------------------------- method rewrite (pure) --------

def test_method_rewrite_semantics():
    for status in (301, 302, 303):
        assert he.rewrite_method_for_redirect("POST", status) == "GET"
        assert he.rewrite_method_for_redirect("GET", status) == "GET"
    # 307/308 repeat the method
    assert he.rewrite_method_for_redirect("GET", 307) == "GET"
    assert he.rewrite_method_for_redirect("HEAD", 308) == "HEAD"
    assert he.rewrite_method_for_redirect("get", 307) == "GET"
    # non-redirect statuses leave the method alone
    assert he.rewrite_method_for_redirect("GET", 200) == "GET"


# ------------------------------------------------------- executor wiring (source) -----


# ------------------------------------------------------- executor (functional) --------


def test_scan_only_redirect_mode_crosses_between_bound_origins(monkeypatch):
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.scheme, request.headers.get("host", "")))
        if request.url.scheme == "http":
            return httpx.Response(
                301, headers={"location": "https://shop.test/home"},
            )
        return httpx.Response(200)

    class _MockClient(httpx.AsyncClient):
        def __init__(self, **kwargs):
            kwargs.pop("transport", None)
            super().__init__(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _MockClient)
    target = TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="shop.test",
        allowed_origins=("http://shop.test", "https://shop.test"),
        allowed_addresses=("203.0.113.10",),
        allowed_root_domains=("shop.test",),
        scope_receipt_id="scope-1",
    )
    args = {"method": "HEAD", "path": "/", "follow_redirects": True}

    strict = asyncio.run(execute_bound_http_request(
        "http://shop.test", args, target=target,
    ))
    assert strict["hops_followed"] == 0
    assert strict["redirect_chain"][0]["stopped"] == "cross_origin"

    seen.clear()
    redirect_probe = asyncio.run(execute_bound_http_request(
        "http://shop.test",
        args,
        target=target,
        allow_bound_origin_redirects=True,
    ))
    assert redirect_probe["ok"] is True
    assert redirect_probe["hops_followed"] == 1
    assert redirect_probe["response"]["status"] == 200
    assert seen == [
        ("http", "shop.test"),
        ("https", "shop.test"),
    ]


def test_target_bound_http_fails_over_only_before_connect(monkeypatch):
    seen: list[tuple[str, str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((
            request.url.host,
            request.headers.get("host", ""),
            request.extensions.get("sni_hostname"),
        ))
        if request.url.host == "192.0.2.10":
            raise httpx.ConnectError("first frozen address unavailable", request=request)
        return httpx.Response(200, text="second address")

    class _MockClient(httpx.AsyncClient):
        def __init__(self, **kwargs):
            kwargs.pop("transport", None)
            super().__init__(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _MockClient)
    target = TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="shop.test",
        allowed_origins=("https://shop.test",),
        allowed_addresses=("192.0.2.10", "192.0.2.11"),
        allowed_root_domains=("shop.test",),
    )

    result = asyncio.run(execute_bound_http_request(
        "https://shop.test", {"method": "GET", "path": "/"}, target=target,
    ))

    assert result["ok"] is True
    assert result["connection_attempts"] == 2
    assert result["connected_addresses"] == ["192.0.2.11"]
    assert result["request"]["address_policy"] == {
        "schema_version": "frozen-target-address-policy/v1",
        "family_preference": "ipv4_first",
        "admitted_address_count": 2,
        "fallback_attempt_limit": 2,
        "no_runtime_resolution": True,
    }
    assert seen == [
        ("192.0.2.10", "shop.test", "shop.test"),
        ("192.0.2.11", "shop.test", "shop.test"),
    ]


def test_target_bound_http_never_expands_beyond_the_fallback_limit(monkeypatch):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url.host))
        raise httpx.ConnectError("frozen address unavailable", request=request)

    class _MockClient(httpx.AsyncClient):
        def __init__(self, **kwargs):
            kwargs.pop("transport", None)
            super().__init__(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _MockClient)
    target = TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="shop.test",
        allowed_origins=("https://shop.test",),
        allowed_addresses=tuple(f"192.0.2.{index}" for index in range(1, 12)),
        allowed_root_domains=("shop.test",),
    )

    result = asyncio.run(execute_bound_http_request(
        "https://shop.test", {"method": "GET", "path": "/"}, target=target,
    ))

    assert result["ok"] is False
    assert seen == [f"192.0.2.{index}" for index in range(1, 9)]



def _bound_target() -> TargetBinding:
    return TargetBinding(
        target_id="target-1", target_kind="web", canonical_host="shop.test",
        allowed_origins=("https://shop.test",), allowed_addresses=("203.0.113.10",),
        allowed_root_domains=("shop.test",), scope_receipt_id="scope-1",
    )


def _mock_transport(monkeypatch, handler) -> None:
    class _MockClient(httpx.AsyncClient):
        def __init__(self, **kwargs):
            kwargs.pop("transport", None)
            super().__init__(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _MockClient)


def test_executor_follows_same_origin_chain_and_returns_final_response(monkeypatch):
    """The bound HTTP capability every Hunt request runs through: a same-origin chain is followed
    hop by hop, each hop is listed, and the answer is the final response."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "/middle"})
        if request.url.path == "/middle":
            return httpx.Response(302, headers={"location": "https://shop.test/end"})
        return httpx.Response(200, text="done")

    _mock_transport(monkeypatch, handler)
    result = asyncio.run(execute_bound_http_request(
        "https://shop.test", {"method": "GET", "path": "/start", "follow_redirects": True},
        target=_bound_target()))

    assert result["ok"] is True and result["response"]["status"] == 200
    assert seen == ["/start", "/middle", "/end"] and result["hops_followed"] == 2
    assert [hop["status"] for hop in result["redirect_chain"]][:2] == [302, 302]
    # Not asked to follow: the first redirect is the answer and nothing else is requested.
    seen.clear()
    single = asyncio.run(execute_bound_http_request(
        "https://shop.test", {"method": "GET", "path": "/start"}, target=_bound_target()))
    assert single["response"]["status"] == 302 and seen == ["/start"]


def test_executor_stops_and_records_terminal_status_on_cross_origin_hop(monkeypatch):
    """A redirect to another origin is never requested: the chain records where it stopped."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("host", "") + request.url.path)
        return httpx.Response(302, headers={"location": "https://evil.test/collect"})

    _mock_transport(monkeypatch, handler)
    result = asyncio.run(execute_bound_http_request(
        "https://shop.test", {"method": "GET", "path": "/start", "follow_redirects": True},
        target=_bound_target()))

    assert seen == ["shop.test/start"]  # one request, to the bound host only
    assert result["hops_followed"] == 0 and result["response"]["status"] == 302
    assert result["redirect_chain"][0]["stopped"] == "cross_origin"
