from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import capabilities.authz as authz  # noqa: E402
from capabilities.http import WorkerPrivateHTTPResponse  # noqa: E402
from runtime.models import TargetBinding  # noqa: E402


TARGET = TargetBinding(
    target_id="target-1",
    target_kind="web",
    canonical_host="app.example.test",
    allowed_origins=("https://app.example.test",),
    allowed_addresses=("192.0.2.10",),
    scope_receipt_id="scope-1",
)


def test_target_bound_authz_capability_emits_content_free_verified_proof(
    monkeypatch,
):
    calls = []

    async def request(origin, args, **kwargs):
        calls.append((origin, dict(args), kwargs))
        assert origin == "https://app.example.test"
        assert args["method"] == "GET"
        assert kwargs["allow_write"] is False
        principal = kwargs["principal_slot"]
        path = args["path"]
        if path == "/api/orders":
            body = (
                [{"id": 101, "email": "owner@example.test", "amount": 25}]
                if principal == "primary"
                else [{"id": 202, "email": "attacker@example.test", "amount": 10}]
            )
        else:
            assert path == "/api/orders/101"
            body = {"id": 101, "email": "owner@example.test", "amount": 25}
        encoded = json.dumps(body).encode()
        kwargs["private_response_sink"](WorkerPrivateHTTPResponse(
            status_code=200,
            final_url=origin + path,
            _body=encoded,
            _headers={"content-type": "application/json"},
            _cookies={},
        ))
        return {
            "ok": True,
            "request": {"method": "GET", "path": path},
            "response": {"status": 200},
        }

    monkeypatch.setattr(authz, "execute_bound_http_request", request)
    result = asyncio.run(authz.verify_target_bound_object_authorization(
        "https://app.example.test",
        ["/api/orders"],
        target=TARGET,
        primary_headers={"Authorization": "Bearer owner-private"},
        secondary_headers={"Authorization": "Bearer attacker-private"},
    ))

    observation = result["observation"]
    assert len(calls) == 4
    assert observation["kind"] == "authz_differential"
    assert observation["proof_state"] == "verified"
    assert observation["consumer_url"] == (
        "https://app.example.test/api/orders/<owner-object>"
    )
    assert observation["producer_url"] == (
        "https://app.example.test/api/orders"
    )
    assert observation["resource_id_sha256"] == hashlib.sha256(b"101").hexdigest()
    assert observation["object_absent_from_secondary_listing"] is True
    assert observation["responses_equivalent"] is True
    assert observation["secret_values_visible"] is False
    serialized = json.dumps(result)
    assert "owner-private" not in serialized
    assert "attacker-private" not in serialized
    assert '"requested_object_id"' not in serialized
    assert result["budget_consumed"] == {
        "http_requests": 4,
        "tool_wall_seconds": 1,
    }


def test_authz_capability_rejects_same_principal_without_traffic(monkeypatch):
    async def unexpected_request(*_args, **_kwargs):
        raise AssertionError("same-principal proof reached the network")

    monkeypatch.setattr(authz, "execute_bound_http_request", unexpected_request)
    result = asyncio.run(authz.verify_target_bound_object_authorization(
        "https://app.example.test",
        ["/api/orders"],
        target=TARGET,
        primary_headers={"Cookie": "session=same-private"},
        secondary_headers={"Cookie": "session=same-private"},
    ))

    assert result["observation"]["proof_state"] == "inconclusive"
    assert result["observation"]["reason"] == "principal_contexts_not_distinct"
    assert result["budget_consumed"] == {
        "http_requests": 0,
        "tool_wall_seconds": 0,
    }


def test_authz_capability_discards_routes_outside_frozen_target(monkeypatch):
    async def unexpected_request(*_args, **_kwargs):
        raise AssertionError("out-of-scope authz route reached the network")

    monkeypatch.setattr(authz, "execute_bound_http_request", unexpected_request)
    result = asyncio.run(authz.verify_target_bound_object_authorization(
        "https://app.example.test",
        ["https://evil.example/api/orders"],
        target=TARGET,
        primary_headers={"Authorization": "Bearer owner-private"},
        secondary_headers={"Authorization": "Bearer attacker-private"},
    ))

    assert result["observation"]["reason"] == "no_target_bound_routes"
    assert result["budget_consumed"] == {
        "http_requests": 0,
        "tool_wall_seconds": 0,
    }


def test_authz_capability_fails_closed_on_runtime_scope_rejection(monkeypatch):
    async def rejected_request(_origin, args, **_kwargs):
        return {
            "ok": False,
            "request": {"method": "GET", "path": args["path"]},
            "error": "scope: destination changed after admission",
        }

    monkeypatch.setattr(authz, "execute_bound_http_request", rejected_request)
    with pytest.raises(
        authz.AuthzVerificationContractError,
        match="left its frozen target",
    ):
        asyncio.run(authz.verify_target_bound_object_authorization(
            "https://app.example.test",
            ["/api/orders"],
            target=TARGET,
            primary_headers={"Authorization": "Bearer owner-private"},
            secondary_headers={"Authorization": "Bearer attacker-private"},
        ))
