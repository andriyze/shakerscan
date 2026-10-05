"""The browser XSS proof must test the request the candidate came from.

Three ways it used to test something else: an authenticated candidate was replayed without
its session (rendering a login or 401 page), a nested JSON field was sent as a literal dotted
key the target ignores, and a 401/403 page was recorded as a completed negative result.
"""
from __future__ import annotations

import asyncio
import json
import sys
import types

import pytest

from api.agent_tools import _injection_body
from api.capabilities.browser import (
    BrowserCapabilityInputError,
    XSSBrowserProofAdapter,
)
from api.runtime.models import TargetBinding
from api.runtime.request_shape import json_field_leaf_name, nested_json_body


TARGET = TargetBinding(
    target_id="10000000-0000-4000-8000-000000000001",
    target_kind="web",
    canonical_host="app.example.test",
    allowed_origins=("https://app.example.test",),
    allowed_addresses=("192.0.2.10",),
    allowed_root_domains=("example.test",),
    scope_receipt_id="10000000-0000-4000-8000-000000000002",
)
SECRET = "Bearer shakerscan-test-secret-value"


def _install_fake_browser(monkeypatch, *, requires_auth: bool):
    """A page that renders the reflected payload only for an authenticated request."""
    seen: dict[str, object] = {"headers": [], "cookies": [], "requests": []}

    class FakePinnedProxy:
        def __init__(self, **_kwargs):
            self.socket_factory = types.SimpleNamespace(policy_receipt={
                "schema_version": "frozen-target-address-policy/v1",
            })
            self.address_attempts = {"192.0.2.10": 1}
            self.address_connections = {"192.0.2.10": 1}
            self.proxy_url = "socks5://127.0.0.1:41000"

        async def start(self): return self
        async def close(self): return None

    monkeypatch.setattr("api.capabilities.browser.PinnedSocksProxy", FakePinnedProxy)

    class FakeRequest:
        def __init__(self, method, url):
            self.method, self.url, self.headers = method, url, {"user-agent": "x"}

    class FakeRoute:
        def __init__(self, request, page): self.request, self.page = request, page
        async def abort(self, _reason): return None

        async def continue_(self, **kwargs):
            headers = dict(kwargs.get("headers") or {})
            seen["headers"].append(headers)
            seen["requests"].append(kwargs)
            self.page.authenticated = headers.get("authorization") == SECRET

    class FakeResponse:
        def __init__(self, method, url, status):
            self.url, self.status = url, status
            self.request = FakeRequest(method, url)
            self.headers = {"content-type": "text/html"}

    class FakeConsole:
        def __init__(self, text): self.type, self.text = "log", text

    class FakePage:
        def __init__(self):
            self.url = "about:blank"
            self.authenticated = False
            self.console_handler = None
            self.marker = None

        def on(self, event, handler):
            if event == "console":
                self.console_handler = handler

        async def goto(self, url, **_kwargs):
            await self.route_handler(FakeRoute(FakeRequest("GET", url), self))
            allowed = self.authenticated or not requires_auth
            status = 200 if allowed else 401
            await self.response_handler(FakeResponse("GET", url, status))
            if allowed and self.console_handler is not None:
                self.console_handler(FakeConsole(self.marker))
            self.url = url
            return FakeResponse("GET", url, status)

        async def get_attribute(self, *_args):
            allowed = self.authenticated or not requires_auth
            return self.marker if allowed else None

        async def evaluate(self, *_args): return None
        async def screenshot(self, **_kwargs): return b"png"

    page = FakePage()

    class FakeContext:
        async def route(self, _pattern, handler): page.route_handler = handler
        def on(self, event, handler):
            if event == "response":
                page.response_handler = handler
        async def add_init_script(self, _script): return None
        async def add_cookies(self, cookies): seen["cookies"].extend(cookies)
        async def new_page(self): return page
        async def close(self): return None

    class FakeBrowser:
        version = "fake/1"
        async def new_context(self, **_kwargs): return FakeContext()
        async def close(self): return None

    class FakeChromium:
        async def launch(self, **_kwargs): return FakeBrowser()

    class FakePlaywright:
        chromium = FakeChromium()
        async def stop(self): return None

    class FakeStarter:
        async def start(self): return FakePlaywright()

    module = types.ModuleType("playwright.async_api")
    module.TimeoutError = type("FakeTimeout", (Exception,), {})
    module.async_playwright = lambda: FakeStarter()
    package = types.ModuleType("playwright")
    package.async_api = module
    monkeypatch.setitem(sys.modules, "playwright", package)
    monkeypatch.setitem(sys.modules, "playwright.async_api", module)
    return page, seen


def _query_proof():
    return XSSBrowserProofAdapter.prepare(
        target=TARGET,
        execution_url="https://app.example.test/account/search?q=seed",
        candidate_id="c0deadbeefcafe01", parameter_name="q",
    )


async def _noop():
    return None


def _proof(result):
    return next(item for item in result.observations if item.get("kind") == "xss_browser_proof")


def test_authenticated_candidate_is_proven_with_its_session(monkeypatch):
    prepared = _query_proof()
    page, seen = _install_fake_browser(monkeypatch, requires_auth=True)
    page.marker = prepared.marker

    result = asyncio.run(XSSBrowserProofAdapter(
        prepared, trusted_headers={"Authorization": SECRET, "Cookie": "sid=abc123"},
    ).execute(heartbeat=_noop, cancelled=lambda: False))

    assert result.status == "success"
    assert _proof(result)["proof_state"] == "verified"
    assert [item["name"] for item in seen["cookies"]] == ["sid"]
    # The header travels on target traffic only; no value reaches the receipt material.
    rendered = json.dumps({
        "observations": result.observations,
        "redacted_execution": result.redacted_execution,
        "errors": result.errors,
    }, default=str)
    assert SECRET not in rendered and "abc123" not in rendered
    assert SECRET not in repr(prepared) and SECRET not in prepared.input_digest


def test_auth_refusal_is_an_inconclusive_attempt_not_a_negative_result(monkeypatch):
    prepared = _query_proof()
    page, _seen = _install_fake_browser(monkeypatch, requires_auth=True)
    page.marker = prepared.marker

    result = asyncio.run(XSSBrowserProofAdapter(prepared).execute(
        heartbeat=_noop, cancelled=lambda: False,
    ))

    # A 401 page is not the route under test: partial, so batch and Hunt coverage do not
    # count it as examined, and never verified.
    assert result.status == "partial"
    assert result.partial is True
    assert "authentication_required:401" in result.errors
    proof = _proof(result)
    assert proof["proof_state"] == "not_proven"
    assert proof["inconclusive_reason"] == "authentication_required"


def test_public_negative_result_is_still_a_completed_attempt(monkeypatch):
    prepared = _query_proof()
    page, _seen = _install_fake_browser(monkeypatch, requires_auth=False)
    page.marker = "a-marker-that-never-fires"

    result = asyncio.run(XSSBrowserProofAdapter(prepared).execute(
        heartbeat=_noop, cancelled=lambda: False,
    ))

    assert result.status == "success"
    assert _proof(result)["proof_state"] == "not_proven"
    assert "inconclusive_reason" not in _proof(result)


def test_json_body_proof_nests_dotted_fields():
    prepared = XSSBrowserProofAdapter.prepare(
        target=TARGET,
        execution_url="https://app.example.test/api/profile",
        candidate_id="c0deadbeefcafe02", parameter_name="profile.name",
        method="PUT", content_type="application/json",
        body_field_names=("profile.name", "profile.bio", "password"),
    )

    document = json.loads(prepared.body)
    assert set(document) == {"password", "profile"}
    assert document["profile"]["bio"] == "shakerscan"
    assert prepared.marker in document["profile"]["name"]
    assert "profile.name" not in document


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH"])
def test_authenticated_body_proof_preserves_session_headers_and_exact_override(monkeypatch, method):
    prepared = XSSBrowserProofAdapter.prepare(
        target=TARGET, execution_url="https://app.example.test/api/profile",
        candidate_id="c0deadbeefcafe02", parameter_name="profile.name",
        method=method, content_type="application/json",
        body_field_names=("profile.name", "profile.bio"),
    )
    page, seen = _install_fake_browser(monkeypatch, requires_auth=True)
    page.marker = prepared.marker
    result = asyncio.run(XSSBrowserProofAdapter(prepared, trusted_headers={
        "Authorization": SECRET, "Cookie": "sid=abc123", "X-Api-Key": "api-key-secret",
        "Content-Type": "text/plain",
    }).execute(heartbeat=_noop, cancelled=lambda: False))

    assert result.status == "success"
    assert _proof(result)["proof_state"] == "verified"
    request = seen["requests"][0]
    assert request["method"] == method
    assert request["post_data"] == prepared.body
    assert request["headers"]["authorization"] == SECRET
    assert request["headers"]["x-api-key"] == "api-key-secret"
    assert request["headers"]["content-type"] == "application/json"
    assert "cookie" not in request["headers"]
    assert seen["cookies"][0]["value"] == "abc123"
    assert result.actual_budget["http_requests"] == 1
    assert result.actual_budget["state_changing_requests"] == 1
    receipt = json.dumps(result.__dict__, default=str)
    assert all(secret not in receipt for secret in (SECRET, "abc123", "api-key-secret"))


def test_json_body_proof_refuses_a_container_field():
    with pytest.raises(BrowserCapabilityInputError, match="container"):
        XSSBrowserProofAdapter.prepare(
            target=TARGET,
            execution_url="https://app.example.test/api/profile",
            candidate_id="c0deadbeefcafe03", parameter_name="profile",
            method="PUT", content_type="application/json",
            body_field_names=("profile", "profile.name"),
        )


@pytest.mark.parametrize(("names", "expected"), [
    # Discovery/surface convention: nested objects list leaves only; an array of objects
    # is a parent plus children.
    (["profile.name", "profile.bio"], {"profile": {"name": "x", "bio": "x"}}),
    (["items", "items.id", "name"], {"items": [{"id": "x"}], "name": "x"}),
    # Imported collections list every container and mark arrays explicitly, so a parent
    # plus children is an object there.
    (["profile", "profile.name", "tags[]", "items[]", "items[].id"],
     {"profile": {"name": "x"}, "tags": ["x"], "items": [{"id": "x"}]}),
    # Exact replay paths index arrays numerically.
    (["items.0.id", "items.1.id", "count"], {"items": [{"id": "x"}], "count": "x"}),
])
def test_nested_json_body_rebuilds_each_flattening_convention(names, expected):
    assert nested_json_body(names, placeholder="x") == expected


def test_nested_json_body_places_values_at_exact_fields():
    assert nested_json_body(
        ["a.b", "a.c", "d"], placeholder="x", values={"a.c": "PAYLOAD"},
    ) == {"a": {"b": "x", "c": "PAYLOAD"}, "d": "x"}
    assert json_field_leaf_name("items[].id") == "id"
    assert json_field_leaf_name("items.0.id") == "id"
    assert json_field_leaf_name("q") == "q"


def test_discovery_tools_receive_the_nested_body_and_leaf_field_names():
    method, body, fields = _injection_body({
        "injection_field": "profile.name",
        "body_field_names": ["profile.name", "profile.bio", "password"],
        "method": "PUT", "content_type": "application/json",
    })

    assert method == "PUT"
    assert json.loads(body) == {
        "password": "shakerscan",
        "profile": {"bio": "shakerscan", "name": "shakerscan"},
    }
    assert fields == ["name", "bio", "password"]


def test_discovery_form_bodies_keep_literal_field_names():
    _method, body, fields = _injection_body({
        "injection_field": "user.name",
        "body_field_names": ["user.name", "q"],
        "method": "POST", "content_type": "application/x-www-form-urlencoded",
    })

    assert body == "user.name=shakerscan&q=shakerscan"
    assert fields == ["user.name", "q"]
