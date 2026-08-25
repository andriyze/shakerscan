from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from capabilities.auth import (  # noqa: E402
    TargetBoundSessionCredential,
    establish_target_bound_http_session,
)
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


def _private_response(
    status: int,
    *,
    body: str = "",
    headers=None,
    cookies=None,
    final_url: str = "https://app.example.test/login",
):
    return WorkerPrivateHTTPResponse(
        status_code=status,
        final_url=final_url,
        _body=body.encode(),
        _headers=dict(headers or {}),
        _cookies=dict(cookies or {}),
    )


def test_target_bound_form_login_returns_only_worker_private_session_headers():
    calls = []
    password = "form-worker-private-password"

    async def request_executor(origin, args, **kwargs):
        calls.append((origin, args, kwargs))
        if args["method"] == "GET":
            kwargs["private_response_sink"](_private_response(
                200,
                body=(
                    '<form action="/session" method="post">'
                    '<input type="hidden" name="csrf" value="nonce">'
                    '<input type="email" name="email">'
                    '<input type="password" name="password">'
                    "</form>"
                ),
                cookies={"prelogin": "one"},
            ))
        else:
            kwargs["private_response_sink"](_private_response(
                302,
                headers={"location": "/account"},
                cookies={"session": "worker-private-cookie"},
                final_url="https://app.example.test/session",
            ))
        return {
            "ok": True,
            "request": {"method": args["method"], "path": args["path"]},
            "response": {"status": 200},
        }

    session = asyncio.run(establish_target_bound_http_session(
        TargetBoundSessionCredential(
            lane="primary",
            auth_kind="form_login",
            endpoint_url="/login",
            binding_digest="a" * 64,
            username="operator@example.test",
            secret=password,
        ),
        target=TARGET,
        request_executor=request_executor,
    ))

    assert session.established is True
    assert session.headers() == {
        "Cookie": "prelogin=one; session=worker-private-cookie",
    }
    assert len(calls) == 2
    assert calls[1][1]["form_body"] == {
        "csrf": "nonce",
        "email": "operator@example.test",
        "password": password,
    }
    assert calls[1][2]["allow_write"] is True
    public = session.execution_result()
    assert password not in json.dumps(public)
    assert "worker-private-cookie" not in json.dumps(public)
    assert public["observation"]["cookie_names"] == ["prelogin", "session"]
    assert public["budget_consumed"]["http_requests"] == 2
    assert password not in repr(session)


def test_target_bound_oauth_exchange_extracts_token_without_public_exposure():
    calls = []
    client_secret = "oauth-worker-private-client-secret"
    access_token = "oauth-worker-private-access-token"

    async def request_executor(origin, args, **kwargs):
        calls.append((origin, args, kwargs))
        kwargs["private_response_sink"](_private_response(
            200,
            body=json.dumps({
                "access_token": access_token,
                "token_type": "Bearer",
            }),
            headers={"content-type": "application/json"},
            final_url="https://app.example.test/oauth/token",
        ))
        return {
            "ok": True,
            "request": {"method": args["method"], "path": args["path"]},
            "response": {"status": 200},
        }

    session = asyncio.run(establish_target_bound_http_session(
        TargetBoundSessionCredential(
            lane="primary",
            auth_kind="oauth_client_credentials",
            endpoint_url="/oauth/token?tenant=blue",
            binding_digest="b" * 64,
            client_id="scanner-client",
            secret=client_secret,
            scopes=("read", "profile"),
        ),
        target=TARGET,
        request_executor=request_executor,
    ))

    assert session.headers() == {"Authorization": f"Bearer {access_token}"}
    assert calls[0][1]["form_body"] == {
        "grant_type": "client_credentials",
        "client_id": "scanner-client",
        "client_secret": client_secret,
        "scope": "read profile",
    }
    assert calls[0][2]["allow_write"] is True
    public = session.execution_result()
    serialized = json.dumps(public)
    assert client_secret not in serialized
    assert access_token not in serialized
    assert public["observation"]["endpoint_path"] == (
        "/oauth/token?<redacted-query>"
    )
    assert public["observation"]["header_names"] == ["Authorization"]


def test_oauth_session_records_bounded_lifecycle_and_evidence_receipt():
    established_at = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)

    async def request_executor(_origin, _args, **kwargs):
        kwargs["private_response_sink"](_private_response(
            200,
            body=json.dumps({
                "access_token": "worker-private-token",
                "token_type": "Bearer",
                "expires_in": 600,
            }),
        ))
        return {"ok": True, "request": {"method": "POST"}, "response": {"status": 200}}

    session = asyncio.run(establish_target_bound_http_session(
        TargetBoundSessionCredential(
            lane="primary",
            auth_kind="oauth_client_credentials",
            endpoint_url="/oauth/token",
            binding_digest="e" * 64,
            client_id="scanner-client",
            secret="worker-private-secret",
            profile_id="00000000-0000-4000-8000-000000000001",
            profile_version=7,
            principal="service-account",
            compatible_capabilities=("auth.session.establish", "http.request"),
        ),
        target=TARGET,
        request_executor=request_executor,
        now=established_at,
    ))

    assert session.established is True
    assert session.expires_at == established_at + timedelta(seconds=600)
    assert session.refresh_after == established_at + timedelta(seconds=540)
    assert session.profile_version == 7
    public = session.execution_result()["observation"]
    assert public["session_ref"] == session.session_ref
    assert public["principal"] == "service-account"
    assert public["evidence_receipt_digest"] == session.evidence_receipt_digest
    assert len(public["evidence_receipt_digest"]) == 64


def test_resource_owner_exchange_requires_explicit_profile_authorization():
    try:
        asyncio.run(establish_target_bound_http_session(
            TargetBoundSessionCredential(
                lane="primary",
                auth_kind="oauth_password",
                endpoint_url="/oauth/token",
                binding_digest="f" * 64,
                username="operator",
                secret="worker-private-password",
                client_id="scanner-client",
            ),
            target=TARGET,
        ))
    except ValueError as exc:
        assert "explicit profile authorization" in str(exc)
    else:
        raise AssertionError("OAuth password flow was accepted without explicit authority")


def test_form_login_reports_unsupported_additional_factor_before_submission():
    calls = []

    async def request_executor(_origin, args, **kwargs):
        calls.append(args)
        kwargs["private_response_sink"](_private_response(
            200,
            body=(
                '<form action="/session" method="post">'
                '<input type="text" name="username">'
                '<input type="password" name="password">'
                '<input type="text" name="totp_code">'
                "</form>"
            ),
        ))
        return {"ok": True, "request": {"method": "GET"}, "response": {"status": 200}}

    session = asyncio.run(establish_target_bound_http_session(
        TargetBoundSessionCredential(
            lane="primary",
            auth_kind="form_login",
            endpoint_url="/login",
            binding_digest="1" * 64,
            username="operator",
            secret="worker-private-password",
        ),
        target=TARGET,
        request_executor=request_executor,
    ))

    assert session.established is False
    assert session.error == (
        "target login form requires an unsupported additional factor"
    )
    assert len(calls) == 1


def test_form_action_outside_frozen_target_fails_before_credential_submission():
    calls = []

    async def request_executor(origin, args, **kwargs):
        calls.append((origin, args, kwargs))
        kwargs["private_response_sink"](_private_response(
            200,
            body=(
                '<form action="https://evil.example/steal" method="post">'
                '<input type="text" name="username">'
                '<input type="password" name="password">'
                "</form>"
            ),
        ))
        return {
            "ok": True,
            "request": {"method": args["method"], "path": args["path"]},
            "response": {"status": 200},
        }

    session = asyncio.run(establish_target_bound_http_session(
        TargetBoundSessionCredential(
            lane="primary",
            auth_kind="form_login",
            endpoint_url="/login",
            binding_digest="c" * 64,
            username="operator",
            secret="never-submit-cross-origin",
        ),
        target=TARGET,
        request_executor=request_executor,
    ))

    assert session.established is False
    assert session.error == "session endpoint is outside the frozen target binding"
    assert len(calls) == 1
    assert calls[0][1]["method"] == "GET"


def test_prelogin_cookie_alone_is_not_treated_as_authenticated_identity():
    async def request_executor(_origin, args, **kwargs):
        if args["method"] == "GET":
            kwargs["private_response_sink"](_private_response(
                200,
                body=(
                    '<form action="/session" method="post">'
                    '<input type="text" name="username">'
                    '<input type="password" name="password">'
                    "</form>"
                ),
                cookies={"prelogin": "anonymous-session"},
            ))
        else:
            kwargs["private_response_sink"](_private_response(
                302,
                headers={"location": "/login?error=invalid"},
                final_url="https://app.example.test/session",
            ))
        return {
            "ok": True,
            "request": {"method": args["method"], "path": args["path"]},
            "response": {"status": 200},
        }

    session = asyncio.run(establish_target_bound_http_session(
        TargetBoundSessionCredential(
            lane="primary",
            auth_kind="form_login",
            endpoint_url="/login",
            binding_digest="d" * 64,
            username="operator",
            secret="invalid-password",
        ),
        target=TARGET,
        request_executor=request_executor,
    ))

    assert session.established is False
    assert session.headers() == {}
    assert session.error == "session exchange produced no usable identity"


def test_worker_private_http_response_repr_hides_body_headers_and_cookies():
    response = _private_response(
        200,
        body="response-worker-private-token",
        headers={"authorization": "Bearer response-worker-private-header"},
        cookies={"session": "response-worker-private-cookie"},
    )

    rendered = repr(response)
    assert "response-worker-private-token" not in rendered
    assert "response-worker-private-header" not in rendered
    assert "response-worker-private-cookie" not in rendered
    assert "authorization" in rendered
    assert "session" in rendered
