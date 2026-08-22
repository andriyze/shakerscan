from __future__ import annotations

import os
import sys
import types

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools.request_replay import (
    MAX_BODY_BYTES,
    ReplayAuthorization,
    RequestReplayError,
    bind_replay_credential_headers,
    build_replay_plan,
    build_selected_replay_plan,
)


def _request(method="GET", url="https://api.example.test/items/1?token=secret"):
    return {
        "id": "req-1",
        "name": "Exact request",
        "folder": "Orders",
        "method": method,
        "url": url,
        "headers": {
            "Authorization": "Bearer top-secret",
            "Cookie": "session=secret-cookie",
            "Content-Type": "application/json",
            "Host": "attacker.test",
            "Content-Length": "999999",
        },
        "body": b'{"password":"secret-body"}',
        "body_mode": "application/json",
        "auth_type": "captured",
        "has_sensitive_material": True,
        "unresolved_variables": [],
        "error": None,
    }


def test_safe_replay_preserves_wire_semantics_but_public_view_redacts_values():
    plan = build_replay_plan(
        [_request()], allowed_origins=["https://api.example.test"], limit=1
    )
    wire = plan.wire_requests()[0]
    public = plan.public_dict()
    rendered = repr(public).lower()

    assert wire["method"] == "GET"
    assert wire["url"].endswith("/items/1?token=secret")
    assert wire["headers"]["Authorization"] == "Bearer top-secret"
    assert wire["headers"]["Cookie"] == "session=secret-cookie"
    assert wire["body"] == b'{"password":"secret-body"}'
    assert "Host" not in wire["headers"]
    assert "Content-Length" not in wire["headers"]

    assert public["request_count"] == 1
    assert public["secret_values_visible"] is False
    assert "top-secret" not in rendered
    assert "secret-cookie" not in rendered
    assert "secret-body" not in rendered
    assert "token=secret" not in rendered
    assert public["requests"][0]["header_names"] == [
        "Authorization", "Cookie", "Content-Type"
    ]
    assert len(public["input_digest"]) == 64


def test_state_changing_replay_requires_active_policy_and_bound_approval():
    request = _request(method="POST")
    with pytest.raises(RequestReplayError, match="active_testing"):
        build_replay_plan([request], allowed_origins=["https://api.example.test"])
    with pytest.raises(RequestReplayError, match="not enabled"):
        build_replay_plan(
            [request],
            allowed_origins=["https://api.example.test"],
            authorization=ReplayAuthorization(active_testing=True),
        )
    with pytest.raises(RequestReplayError, match="approval"):
        build_replay_plan(
            [request],
            allowed_origins=["https://api.example.test"],
            authorization=ReplayAuthorization(
                active_testing=True, allow_state_changing_http=True
            ),
        )

    plan = build_replay_plan(
        [request],
        allowed_origins=["https://api.example.test"],
        authorization=ReplayAuthorization(
            active_testing=True,
            allow_state_changing_http=True,
            approval_receipt_id="approval-1",
        ),
    )
    assert plan.public_dict()["authorization"] == {
        "active_testing": True,
        "allow_state_changing_http": True,
        "approval_bound": True,
    }
    assert "approval-1" not in repr(plan.public_dict())


def test_origin_binding_and_relative_request_resolution_fail_closed():
    with pytest.raises(RequestReplayError, match="outside"):
        build_replay_plan(
            [_request(url="https://evil.test/items/1")],
            allowed_origins=["https://api.example.test"],
        )
    with pytest.raises(RequestReplayError, match="default origin"):
        build_replay_plan(
            [_request(url="/items/1")],
            allowed_origins=["https://api.example.test", "https://api.example.test:8443"],
        )

    plan = build_replay_plan(
        [_request(url="/items/1?token=secret")],
        allowed_origins=["https://api.example.test", "https://api.example.test:8443"],
        default_origin="https://api.example.test:8443",
    )
    assert plan.wire_requests()[0]["url"] == "https://api.example.test:8443/items/1?token=secret"


def test_replay_rejects_unresolved_imports_header_injection_and_oversized_body():
    unresolved = _request()
    unresolved["unresolved_variables"] = ["baseUrl"]
    with pytest.raises(RequestReplayError, match="unresolved variables"):
        build_replay_plan([unresolved], allowed_origins=["https://api.example.test"])

    injected = _request()
    injected["headers"] = {"X-Test": "ok\r\nHost: evil.test"}
    with pytest.raises(RequestReplayError, match="control characters"):
        build_replay_plan([injected], allowed_origins=["https://api.example.test"])

    oversized = _request()
    oversized["body"] = b"x" * (MAX_BODY_BYTES + 1)
    with pytest.raises(RequestReplayError, match="body exceeds"):
        build_replay_plan([oversized], allowed_origins=["https://api.example.test"])


def test_replay_plan_is_bounded_and_request_ids_are_unambiguous():
    with pytest.raises(RequestReplayError, match="limit"):
        build_replay_plan(
            [_request()], allowed_origins=["https://api.example.test"], limit=2_001
        )
    with pytest.raises(RequestReplayError, match="unique"):
        build_replay_plan(
            [_request(), _request(url="https://api.example.test/items/2")],
            allowed_origins=["https://api.example.test"],
            limit=2,
        )


def test_selected_collection_rows_feed_exact_replay_plan_without_public_secrets(monkeypatch):
    module = types.ModuleType("scanner_tools.request_collections")
    module.select_requests = lambda payload, selector: payload["selected"]
    monkeypatch.setitem(sys.modules, "scanner_tools.request_collections", module)
    selector = types.SimpleNamespace(limit=1)

    plan = build_selected_replay_plan(
        {"selected": [_request()]},
        selector,
        allowed_origins=["https://api.example.test"],
    )
    assert plan.wire_requests()[0]["headers"]["Authorization"] == "Bearer top-secret"
    assert "top-secret" not in repr(plan.public_dict()).lower()


def test_managed_principal_replaces_captured_auth_without_public_values():
    plan = build_replay_plan(
        [_request()], allowed_origins=["https://api.example.test"], limit=1,
    )
    bound = bind_replay_credential_headers(
        plan,
        {"X-API-Key": "managed-secret"},
        auth_kind="api_key_header",
    )

    wire = bound.wire_requests()[0]
    assert "Authorization" not in wire["headers"]
    assert "Cookie" not in wire["headers"]
    assert wire["headers"]["X-API-Key"] == "managed-secret"
    assert wire["headers"]["Content-Type"] == "application/json"
    assert wire["auth_type"] == "managed:api_key_header"
    public = repr(bound.public_dict())
    assert "managed-secret" not in public
    assert bound.public_dict()["requests"][0]["has_sensitive_material"] is True


def test_managed_principal_header_validation_fails_closed():
    plan = build_replay_plan(
        [_request()], allowed_origins=["https://api.example.test"], limit=1,
    )
    with pytest.raises(RequestReplayError, match="control characters"):
        bind_replay_credential_headers(
            plan, {"Authorization": "Bearer ok\r\nX-Evil: value"}, auth_kind="bearer_token",
        )
