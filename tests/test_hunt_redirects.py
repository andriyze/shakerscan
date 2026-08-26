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


def _run_http_request(monkeypatch, handler, args, *, allow_write=False):
    """Drive the real executor against an httpx.MockTransport (no live server).

    The executor constructs its own AsyncClient; patching the constructor on the shared
    httpx module injects the mock transport. Receipt recording runs against an
    unconnected db_pool and safely settles at receipt_id=None (its try/except is
    load-bearing, same as in the other unit-tested executor paths).
    """
    class _MockClient(httpx.AsyncClient):
        def __init__(self, **kwargs):
            kwargs.pop("transport", None)
            super().__init__(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _MockClient)
    return asyncio.run(api_module._agent_tool_http_request(
        uuid_lib.UUID(int=1),
        "https://shop.test",
        args,
        created_by="test",
        allow_write=allow_write,
        authorized_addresses=["203.0.113.10"],
    ))


def _executor_source() -> str:
    return definition_source("_agent_tool_http_request") + HTTP_CAPABILITY_SOURCE


def _apply_reply_source() -> str:
    return definition_source("_agent_apply_reply")


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


# ------------------------------------------------------- tool schema surface ----------

def test_http_request_schema_declares_follow_redirects_as_read_only_option():
    schema = next(s for s in at.AGENT_TOOL_SCHEMAS if s["name"] == "http_request")
    prop = schema["parameters"]["properties"].get("follow_redirects")
    assert prop is not None and prop["type"] == "boolean"
    assert "GET/HEAD/OPTIONS" in prop["description"]
    assert "3" in prop["description"]  # bounded hop cap is part of the contract


# ------------------------------------------------------- executor wiring (source) -----

def test_executor_defaults_follow_redirects_off_and_rejects_write_methods():
    executor = _executor_source()
    # default false: only an explicit JSON true enables following
    assert 'args.get("follow_redirects") is True' in executor
    # read-only enforcement: writes may never opt into redirect replay
    assert 'method not in {"GET", "HEAD", "OPTIONS"}' in executor
    assert "follow_redirects is only permitted for read methods" in executor


def test_executor_enforces_same_origin_per_hop_with_bounded_cap():
    executor = _executor_source()
    # every hop validates the Location BEFORE the next request is built
    assert "next_url = validate_next_hop(current_url, location)" in executor
    # hard hop cap
    assert "hops_followed >= MAX_REDIRECT_HOPS" in executor
    assert 'follow_redirects=False' in executor  # httpx never follows on its own
    # method rewrite + body/query drop for the semantic hop
    assert "current_method = rewrite_method_for_redirect(" in executor
    assert "current_query = None" in executor
    assert "current_json_body = None" in executor
    # a rejected hop stops the chain and records the terminal status
    assert '"stopped": "cross_origin"' in executor
    assert '"stopped": "max_hops"' in executor


def test_executor_returns_chain_and_records_it_in_the_receipt():
    executor = _executor_source()
    assert re.search(
        r'"redirect_chain": (?:\w+\.)?_redact_agent_payload\(redirect_chain\)'
        r" if redirect_chain else \[\]",
        executor,
    )
    assert '"hops_followed": hops_followed' in executor
    # receipts must durably record the chain
    assert re.search(
        r'"redirect_chain": (?:\w+\.)?_redact_agent_payload\(redirect_chain\)'
        r" if redirect_chain else \[\],",
        executor,
    )
    # request view surfaces the option
    assert '"follow_redirects": follow_redirects,' in executor


def test_reply_loop_charges_each_followed_hop_as_a_request_unit():
    loop = _apply_reply_source()
    # hops are clamped to the fixed cap before charging (defense in depth)
    assert "min(MAX_REDIRECT_HOPS, int(result.get(\"hops_followed\") or 0))" in loop
    # 1 + hops actually followed, on both the unit and the wire counters
    assert '+ hops_followed' in loop
    assert 'state["request_units_used"] = int(state["request_units_used"] or 0) + hops_followed' in loop
    assert 'state["wire_requests_reserved"] = int(' in loop
    # the charge is observable in the episode event log
    assert '"redirect_hops_charged": hops_followed' in loop


# ------------------------------------------------------- executor (functional) --------

def test_executor_follows_same_origin_chain_and_returns_final_response(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/old":
            return httpx.Response(302, headers={"location": "/login"})
        if request.url.path == "/login":
            return httpx.Response(301, headers={"location": "https://shop.test/home"})
        if request.url.path == "/home":
            return httpx.Response(200, text="final page")
        return httpx.Response(404)

    result = _run_http_request(
        monkeypatch, handler,
        {"method": "GET", "path": "/old", "follow_redirects": True},
    )
    assert result["ok"] is True
    assert result["hops_followed"] == 2
    assert result["redirect_chain"] == [
        {"status": 302, "location": "/login", "followed": True},
        {"status": 301, "location": "https://shop.test/home", "followed": True},
    ]
    assert result["response"]["status"] == 200
    assert "final page" in result["response"]["body_sample"]
    assert result["request"]["follow_redirects"] is True


def test_executor_stops_and_records_terminal_status_on_cross_origin_hop(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/old"
        return httpx.Response(302, headers={"location": "https://evil.test/x"})

    result = _run_http_request(
        monkeypatch, handler,
        {"method": "GET", "path": "/old", "follow_redirects": True},
    )
    assert result["ok"] is True
    assert result["hops_followed"] == 0
    assert result["redirect_chain"] == [
        {"status": 302, "location": "https://evil.test/x", "followed": False, "stopped": "cross_origin"},
    ]
    # the rejected 302 IS the terminal response the planner sees
    assert result["response"]["status"] == 302


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


def test_executor_caps_the_chain_at_three_hops(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": request.url.path + "x"})

    result = _run_http_request(
        monkeypatch, handler,
        {"method": "GET", "path": "/a", "follow_redirects": True},
    )
    assert result["ok"] is True
    assert result["hops_followed"] == 3
    assert len(result["redirect_chain"]) == 4  # 3 followed + 1 refused terminal hop
    assert result["redirect_chain"][-1] == {
        "status": 302, "location": "/axxxx", "followed": False, "stopped": "max_hops",
    }
    assert result["response"]["status"] == 302


def test_executor_default_does_not_follow_redirects(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "/login"})

    result = _run_http_request(monkeypatch, handler, {"method": "GET", "path": "/old"})
    assert result["ok"] is True
    assert result["response"]["status"] == 302
    assert "redirect_chain" not in result
    assert "hops_followed" not in result
    assert result["request"]["follow_redirects"] is False


def test_executor_rejects_follow_redirects_on_write_methods(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not run
        raise AssertionError("write-method redirect request must never reach the wire")

    result = _run_http_request(
        monkeypatch, handler,
        {"method": "POST", "path": "/old", "follow_redirects": True, "json_body": {"a": 1}},
        allow_write=True,
    )
    assert result["ok"] is False
    assert "read methods" in result["error"]


def test_executor_rewrites_method_and_drops_query_on_semantic_redirects(monkeypatch):
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, str(request.url)))
        if request.url.path == "/old":
            return httpx.Response(302, headers={"location": "/login"})
        if request.url.path == "/probe":
            return httpx.Response(307, headers={"location": "/probe-final"})
        return httpx.Response(200, text="done")

    # 301/302/303 -> GET on the next hop; the original query is not replayed
    result = _run_http_request(
        monkeypatch, handler,
        {"method": "OPTIONS", "path": "/old", "query": {"q": "1"}, "follow_redirects": True},
    )
    assert result["ok"] is True and result["hops_followed"] == 1
    assert [method for method, _url in seen] == ["OPTIONS", "GET"]
    assert "q=1" not in seen[1][1]

    # 307/308 repeat the method (reads only)
    seen.clear()
    result = _run_http_request(
        monkeypatch, handler,
        {"method": "HEAD", "path": "/probe", "follow_redirects": True},
    )
    assert result["ok"] is True and result["hops_followed"] == 1
    assert [method for method, _url in seen] == ["HEAD", "HEAD"]


def test_reply_loop_charges_one_unit_plus_each_followed_hop(monkeypatch):
    state = api_module._agent_new_state("redirect budget test", [], [])
    state["wire_request_budget_limit"] = 100
    state["action_budget_limit"] = 12
    state["request_budget_limit"] = 12
    state["active_action_budget_limit"] = 4

    async def fake_execute_agent_tool(*_args, **_kwargs):
        return {
            "ok": True,
            "request": {"method": "GET", "path": "/old", "follow_redirects": True},
            "response": {"status": 200, "body_sample": "done"},
            "provenance": "tool",
            "redirect_chain": [
                {"status": 302, "location": "/login", "followed": True},
                {"status": 301, "location": "/home", "followed": True},
            ],
            "hops_followed": 2,
        }

    monkeypatch.setattr(api_module, "_execute_agent_tool", fake_execute_agent_tool)
    monkeypatch.setattr(agent_router_module, "_execute_agent_tool", fake_execute_agent_tool)
    reply = json.dumps({"tool_calls": [{
        "name": "http_request",
        "arguments": {"method": "GET", "path": "/old", "follow_redirects": True},
    }]})
    outcome = asyncio.run(api_module._agent_apply_reply(
        state,
        reply,
        target_uuid=uuid_lib.uuid4(),
        target_url="https://shop.test",
        created_by="test",
        allow_write=False,
        allow_active=False,
        approval_receipt_id=None,
        hypothesis_id=None,
        iteration=0,
        max_iterations=4,
    ))

    assert outcome["stop"] is False
    # 1 invocation unit + 2 followed hops, on both the episode and wire counters
    assert state["request_units_used"] == 3
    assert state["wire_requests_reserved"] == 3
    assert state["wire_requests_actual_confirmed"] == 3
    assert state["wire_requests_observed_minimum"] == 3
    assert any(
        event.get("redirect_hops_charged") == 2 for event in state["events"]
    )
    # the hop counter cannot be inflated past the fixed cap by a rogue result
    async def rogue_execute_agent_tool(*_args, **_kwargs):
        return {"ok": True, "request": {"method": "GET", "path": "/x"}, "hops_followed": 99}

    monkeypatch.setattr(api_module, "_execute_agent_tool", rogue_execute_agent_tool)
    monkeypatch.setattr(agent_router_module, "_execute_agent_tool", rogue_execute_agent_tool)
    state = api_module._agent_new_state("clamped budget test", [], [])
    state["wire_request_budget_limit"] = 100
    state["action_budget_limit"] = 12
    state["request_budget_limit"] = 12
    state["active_action_budget_limit"] = 4
    asyncio.run(api_module._agent_apply_reply(
        state,
        json.dumps({"tool_calls": [{"name": "http_request", "arguments": {"method": "GET", "path": "/x"}}]}),
        target_uuid=uuid_lib.uuid4(),
        target_url="https://shop.test",
        created_by="test",
        allow_write=False,
        allow_active=False,
        approval_receipt_id=None,
        hypothesis_id=None,
        iteration=0,
        max_iterations=4,
    ))
    assert state["request_units_used"] == 1 + he.MAX_REDIRECT_HOPS
